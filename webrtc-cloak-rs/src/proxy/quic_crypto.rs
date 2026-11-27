//! 零加密开销 `quinn-proto` 自定义加密层（No-op Crypto Backend）。
//!
//! 安全性前提：内层 `quinn-proto` 状态机产生的全部 QUIC 报文始终封装在外层 WebRTC-Cloak 的
//! DTLS 1.3 PFS + Dual-SSRC AEAD SRTP 加密隧道内部，绝不直接暴露于公网。
//! 因此内层 QUIC 无需再次执行 TLS 1.3 握手与二次 AEAD 加密：
//! - 彻底消除 `rustls` / `ring` 依赖（保持全 16 架构纯 Rust 零 C/ASM 交叉编译）；
//! - `PacketKey::tag_len() == 0` 且 `HeaderKey::sample_size() == 0`，每包节省 16B AEAD Tag 开销；
//! - 仍通过 1-RTT 极简 `CRYPTO` 帧完整交换双方真实 `TransportParameters`（流控窗口、MTU、Datagram 等）。

use bytes::BytesMut;
use hmac::{Hmac, KeyInit, Mac};
use quinn_proto::crypto::{
    AeadKey, ClientConfig as CryptoClientConfig, CryptoError, ExportKeyingMaterialError,
    HandshakeTokenKey, HeaderKey, HmacKey, KeyPair, Keys, PacketKey,
    ServerConfig as CryptoServerConfig, Session, UnsupportedVersion,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{
    AckFrequencyConfig, ClientConfig, ConnectError, ConnectionId, EndpointConfig, IdleTimeout,
    ServerConfig, Side, TransportConfig, TransportError, TransportErrorCode, VarInt,
    DEFAULT_SUPPORTED_VERSIONS,
};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;

const MSG_CLIENT_HELLO: u8 = 0x01;
const MSG_SERVER_HELLO: u8 = 0x02;
const MSG_SERVER_PARAMS: u8 = 0x03;
const MSG_CLIENT_FINISHED: u8 = 0x04;

/// 默认单流接收窗口（8 MiB，对齐高 BDP 跨洋链路）。
pub const DEFAULT_STREAM_RECV_WINDOW: u32 = 8 * 1024 * 1024;
/// 默认连接级接收窗口（20 MiB）。
pub const DEFAULT_CONN_RECV_WINDOW: u32 = 20 * 1024 * 1024;
/// 默认连接级发送窗口（16 MiB）。
pub const DEFAULT_CONN_SEND_WINDOW: u64 = 16 * 1024 * 1024;
/// 默认单连接最大并发双向流数。
pub const DEFAULT_MAX_BIDI_STREAMS: u32 = 1024;
/// 默认 QUIC 空闲超时（秒）：设为 0（禁用内层机械空闲超时）。
///
/// 活体检测由外层 WebRTC-Cloak 的 RFC 7675 45s 同意超时与 `on_outer_flow_closed` 级联回收承担，
/// 彻底消除内层每 10s 固定无抖动 QUIC PING/ACK 周期信标指纹。
pub const DEFAULT_QUIC_IDLE_TIMEOUT_SECS: u64 = 0;
/// 内嵌代理默认内层 QUIC MTU（1200B）：封装 38B SRTP 头/Tag 与 0..=31B 随机填充后，
/// 外层线包落在 ~1238..1269B，与外挂 Hy2 / WebRTC 视频载荷自然对齐，避免 1452..1459B 8B 窄峰指纹。
pub const DEFAULT_PROXY_INNER_MTU: u16 = 1200;
/// 内层 QUIC ACK 聚合阈值（每收到 9 个含数据报文回 1 个 ACK，降低 ~4.5x 上行微小 ACK 溢出至视频 SSRC）。
const PROXY_ACK_ELICITING_THRESHOLD: u32 = 8;
/// 内层 QUIC 最大 ACK 延迟（毫秒），低流量交互场景保持低延迟响应。
const PROXY_MAX_ACK_DELAY_MS: u64 = 12;
/// 内层 QUIC 乱序容忍阈值，减少跨洋 ECMP 轻微乱序触发的多余即时 ACK。
const PROXY_ACK_REORDERING_THRESHOLD: u32 = 4;

// ============================================================================
// No-op PacketKey & HeaderKey（零加密、零 Tag、零包头混淆）
// ============================================================================

struct NoopPacketKey;

impl PacketKey for NoopPacketKey {
    #[inline]
    fn encrypt(&self, _packet: u64, _buf: &mut [u8], _header_len: usize) {}

    #[inline]
    fn decrypt(
        &self,
        _packet: u64,
        _header: &[u8],
        _payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    #[inline]
    fn tag_len(&self) -> usize {
        0
    }

    #[inline]
    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    #[inline]
    fn integrity_limit(&self) -> u64 {
        u64::MAX
    }
}

struct NoopHeaderKey;

impl HeaderKey for NoopHeaderKey {
    #[inline]
    fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    #[inline]
    fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    #[inline]
    fn sample_size(&self) -> usize {
        0
    }
}

#[inline]
fn noop_keys() -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(NoopHeaderKey),
            remote: Box::new(NoopHeaderKey),
        },
        packet: KeyPair {
            local: Box::new(NoopPacketKey),
            remote: Box::new(NoopPacketKey),
        },
    }
}

#[inline]
fn noop_packet_key_pair() -> KeyPair<Box<dyn PacketKey>> {
    KeyPair {
        local: Box::new(NoopPacketKey),
        remote: Box::new(NoopPacketKey),
    }
}

// ============================================================================
// 纯 Rust HmacKey & HandshakeTokenKey（供 EndpointConfig / ServerConfig 使用）
// ============================================================================

type HmacSha256 = Hmac<Sha256>;

pub struct Sha256HmacKey {
    key: [u8; 32],
}

impl Sha256HmacKey {
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        crate::protocol::fill_random(&mut key);
        Self { key }
    }
}

impl HmacKey for Sha256HmacKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(&self.key).expect("32B HMAC key valid");
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        let n = signature_out.len().min(tag.len());
        signature_out[..n].copy_from_slice(&tag[..n]);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut expected = [0u8; 32];
        self.sign(data, &mut expected);
        if signature.len() == 32 && bool::from(expected.ct_eq(signature)) {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}

struct MacTokenAead {
    key: [u8; 32],
}

impl AeadKey for MacTokenAead {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(&self.key).map_err(|_| CryptoError)?;
        mac.update(additional_data);
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        data.extend_from_slice(&tag[..16]);
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        if data.len() < 16 {
            return Err(CryptoError);
        }
        let split = data.len() - 16;
        let (msg, tag) = data.split_at_mut(split);
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(&self.key).map_err(|_| CryptoError)?;
        mac.update(additional_data);
        mac.update(msg);
        let expected = mac.finalize().into_bytes();
        if bool::from(expected[..16].ct_eq(tag)) {
            Ok(msg)
        } else {
            Err(CryptoError)
        }
    }
}

pub struct Sha256TokenKey {
    secret: [u8; 32],
}

impl Sha256TokenKey {
    pub fn random() -> Self {
        let mut secret = [0u8; 32];
        crate::protocol::fill_random(&mut secret);
        Self { secret }
    }
}

impl HandshakeTokenKey for Sha256TokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn AeadKey> {
        let mut h = Sha256::new();
        h.update(self.secret);
        h.update(random_bytes);
        let derived: [u8; 32] = h.finalize().into();
        Box::new(MacTokenAead { key: derived })
    }
}

// ============================================================================
// 1-RTT 无 TLS 握手状态机（仅交换 TransportParameters）
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum HandshakeStage {
    // Client stages
    ClientSendHello,
    ClientWaitServerHello,
    ClientUpgradeToHandshake,
    ClientWaitServerParams,
    ClientSendFinished,
    // Server stages
    ServerWaitClientHello,
    ServerSendHello,
    ServerSendParams,
    ServerWaitClientFinished,
    // Shared terminal stage
    Done,
}

struct NoopSession {
    side: Side,
    stage: HandshakeStage,
    local_params: TransportParameters,
    peer_params: Option<TransportParameters>,
    rx_buf: Vec<u8>,
    handshaking: bool,
}

impl NoopSession {
    fn new(side: Side, local_params: TransportParameters) -> Self {
        let stage = match side {
            Side::Client => HandshakeStage::ClientSendHello,
            Side::Server => HandshakeStage::ServerWaitClientHello,
        };
        Self {
            side,
            stage,
            local_params,
            peer_params: None,
            rx_buf: Vec::with_capacity(256),
            handshaking: true,
        }
    }

    fn encode_params_msg(tag: u8, params: &TransportParameters, out: &mut Vec<u8>) {
        let mut encoded = Vec::with_capacity(128);
        params.write(&mut encoded);
        let len = encoded.len().min(u16::MAX as usize) as u16;
        out.push(tag);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&encoded[..len as usize]);
    }

    fn crypto_err(msg: &'static str) -> TransportError {
        TransportError {
            code: TransportErrorCode::crypto(0x50),
            frame: None,
            reason: msg.into(),
        }
    }
}

impl Session for NoopSession {
    fn initial_keys(&self, _dst_cid: &ConnectionId, _side: Side) -> Keys {
        noop_keys()
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.peer_params.map(|_| Box::new(()) as Box<dyn Any>)
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if buf.is_empty() {
            return Ok(false);
        }
        self.rx_buf.extend_from_slice(buf);
        let mut handshake_data_ready = false;

        loop {
            if self.rx_buf.is_empty() {
                break;
            }
            match self.stage {
                HandshakeStage::ServerWaitClientHello => {
                    if self.rx_buf[0] != MSG_CLIENT_HELLO {
                        return Err(Self::crypto_err("expected client hello"));
                    }
                    if self.rx_buf.len() < 3 {
                        break;
                    }
                    let plen = u16::from_be_bytes([self.rx_buf[1], self.rx_buf[2]]) as usize;
                    if self.rx_buf.len() < 3 + plen {
                        break;
                    }
                    let mut slice = &self.rx_buf[3..3 + plen];
                    let tp = TransportParameters::read(self.side, &mut slice)
                        .map_err(|_| Self::crypto_err("invalid client transport parameters"))?;
                    self.rx_buf.drain(..3 + plen);
                    self.peer_params = Some(tp);
                    self.stage = HandshakeStage::ServerSendHello;
                    handshake_data_ready = true;
                }
                HandshakeStage::ClientWaitServerHello => {
                    if self.rx_buf[0] != MSG_SERVER_HELLO {
                        return Err(Self::crypto_err("expected server hello"));
                    }
                    self.rx_buf.drain(..1);
                    self.stage = HandshakeStage::ClientUpgradeToHandshake;
                }
                HandshakeStage::ClientWaitServerParams => {
                    if self.rx_buf[0] != MSG_SERVER_PARAMS {
                        return Err(Self::crypto_err("expected server params"));
                    }
                    if self.rx_buf.len() < 3 {
                        break;
                    }
                    let plen = u16::from_be_bytes([self.rx_buf[1], self.rx_buf[2]]) as usize;
                    if self.rx_buf.len() < 3 + plen {
                        break;
                    }
                    let mut slice = &self.rx_buf[3..3 + plen];
                    let tp = TransportParameters::read(self.side, &mut slice)
                        .map_err(|_| Self::crypto_err("invalid server transport parameters"))?;
                    self.rx_buf.drain(..3 + plen);
                    self.peer_params = Some(tp);
                    self.stage = HandshakeStage::ClientSendFinished;
                    handshake_data_ready = true;
                }
                HandshakeStage::ServerWaitClientFinished => {
                    if self.rx_buf[0] != MSG_CLIENT_FINISHED {
                        return Err(Self::crypto_err("expected client finished"));
                    }
                    self.rx_buf.drain(..1);
                    self.stage = HandshakeStage::Done;
                    self.handshaking = false;
                }
                HandshakeStage::Done => {
                    self.rx_buf.clear();
                    break;
                }
                _ => break,
            }
        }
        let _ = self.side;
        Ok(handshake_data_ready)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(self.peer_params)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        match self.stage {
            HandshakeStage::ClientSendHello => {
                Self::encode_params_msg(MSG_CLIENT_HELLO, &self.local_params, buf);
                self.stage = HandshakeStage::ClientWaitServerHello;
                None
            }
            HandshakeStage::ClientUpgradeToHandshake => {
                self.stage = HandshakeStage::ClientWaitServerParams;
                Some(noop_keys())
            }
            HandshakeStage::ClientSendFinished => {
                buf.push(MSG_CLIENT_FINISHED);
                self.stage = HandshakeStage::Done;
                self.handshaking = false;
                Some(noop_keys())
            }
            HandshakeStage::ServerSendHello => {
                buf.push(MSG_SERVER_HELLO);
                self.stage = HandshakeStage::ServerSendParams;
                Some(noop_keys())
            }
            HandshakeStage::ServerSendParams => {
                Self::encode_params_msg(MSG_SERVER_PARAMS, &self.local_params, buf);
                self.stage = HandshakeStage::ServerWaitClientFinished;
                Some(noop_keys())
            }
            _ => None,
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        Some(noop_packet_key_pair())
    }

    fn is_valid_retry(
        &self,
        _orig_dst_cid: &ConnectionId,
        _header: &[u8],
        _payload: &[u8],
    ) -> bool {
        true
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        output.fill(0);
        Ok(())
    }
}

pub struct NoopClientCrypto;

impl CryptoClientConfig for NoopClientCrypto {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        if !DEFAULT_SUPPORTED_VERSIONS.contains(&version) {
            return Err(ConnectError::UnsupportedVersion);
        }
        Ok(Box::new(NoopSession::new(Side::Client, *params)))
    }
}

pub struct NoopServerCrypto;

impl CryptoServerConfig for NoopServerCrypto {
    fn initial_keys(
        &self,
        version: u32,
        _dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        if !DEFAULT_SUPPORTED_VERSIONS.contains(&version) {
            return Err(UnsupportedVersion);
        }
        Ok(noop_keys())
    }

    fn retry_tag(&self, _version: u32, _orig_dst_cid: &ConnectionId, _packet: &[u8]) -> [u8; 16] {
        [0u8; 16]
    }

    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        Box::new(NoopSession::new(Side::Server, *params))
    }
}

// ============================================================================
// Quinn Endpoint / Client / Server / Transport 构建辅助
// ============================================================================

/// 按外层 WAN MTU、外层 IP+UDP 包头及可选 `--proxy-mtu` 覆盖推导安全的内层 QUIC MTU（防外层分片）。
///
/// 默认收敛至 `DEFAULT_PROXY_INNER_MTU (1200B)`，保证外层 SRTP 线包自然落在 ~1238..1269B 且保留完整
/// `0..=31B` 随机填充；用户显式指定 `--proxy-mtu` 时放宽至物理安全上限（防分片）。
pub fn compute_inner_quic_mtu(
    wan_mtu: usize,
    outer_hdr_len: usize,
    override_mtu: Option<u16>,
) -> u16 {
    let max_safe = if wan_mtu == 0 {
        1420usize
    } else {
        let srtp_overhead = crate::constants::SRTP_DATA_MIN_WIRE_LEN + 8;
        wan_mtu
            .saturating_sub(outer_hdr_len + srtp_overhead)
            .clamp(1200, 1420)
    } as u16;
    match override_mtu {
        Some(m) if m > 0 => m.clamp(1200, max_safe),
        _ => DEFAULT_PROXY_INNER_MTU.min(max_safe),
    }
}

pub fn build_endpoint_config(inner_mtu: u16) -> EndpointConfig {
    let mut cfg = EndpointConfig::new(Arc::new(Sha256HmacKey::random()));
    let _ = cfg.max_udp_payload_size(inner_mtu.max(1200));
    cfg.grease_quic_bit(false);
    cfg
}

pub fn build_transport_config(
    inner_mtu: u16,
    brutal_factory: Arc<super::brutal::BrutalConfig>,
    idle_timeout_secs: u64,
    keepalive_secs: Option<u64>,
) -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    let mtu = inner_mtu.max(1200);
    tc.initial_mtu(mtu);
    tc.min_mtu(1200);
    tc.mtu_discovery_config(None);
    tc.enable_segmentation_offload(false);
    tc.max_concurrent_bidi_streams(VarInt::from_u32(DEFAULT_MAX_BIDI_STREAMS));
    tc.max_concurrent_uni_streams(VarInt::from_u32(16));
    tc.stream_receive_window(VarInt::from_u32(DEFAULT_STREAM_RECV_WINDOW));
    tc.receive_window(VarInt::from_u32(DEFAULT_CONN_RECV_WINDOW));
    tc.send_window(DEFAULT_CONN_SEND_WINDOW);
    tc.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    tc.datagram_send_buffer_size(2 * 1024 * 1024);
    tc.congestion_controller_factory(brutal_factory);
    tc.initial_rtt(Duration::from_millis(80));
    let mut ack_cfg = AckFrequencyConfig::default();
    ack_cfg
        .ack_eliciting_threshold(VarInt::from_u32(PROXY_ACK_ELICITING_THRESHOLD))
        .max_ack_delay(Some(Duration::from_millis(PROXY_MAX_ACK_DELAY_MS)))
        .reordering_threshold(VarInt::from_u32(PROXY_ACK_REORDERING_THRESHOLD));
    tc.ack_frequency_config(Some(ack_cfg));
    if idle_timeout_secs > 0 {
        if let Ok(t) = IdleTimeout::try_from(Duration::from_secs(idle_timeout_secs)) {
            tc.max_idle_timeout(Some(t));
        }
    } else {
        tc.max_idle_timeout(None);
    }
    if let Some(ka) = keepalive_secs.filter(|&s| s > 0) {
        tc.keep_alive_interval(Some(Duration::from_secs(ka)));
    }
    Arc::new(tc)
}

pub fn build_quic_client_config(transport: Arc<TransportConfig>) -> ClientConfig {
    let mut cfg = ClientConfig::new(Arc::new(NoopClientCrypto));
    cfg.transport_config(transport);
    cfg
}

pub fn build_quic_server_config(transport: Arc<TransportConfig>) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::new(
        Arc::new(NoopServerCrypto),
        Arc::new(Sha256TokenKey::random()),
    );
    cfg.transport_config(transport);
    cfg.migration(false);
    Arc::new(cfg)
}
