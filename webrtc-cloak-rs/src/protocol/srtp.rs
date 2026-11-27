//! 会话密钥派生与双 SSRC SRTP 加解密及防重放状态机。

use super::{
    fill_random, CipherSuite, SrtpFrame, BASE64_ALPHABET, RTCP_CNAME_LEN, RTP_V2_BITS, RTP_V2_MASK,
};
use crate::constants::{
    DEFAULT_WAN_MTU, IPV4_UDP_HDR_LEN, MAX_INNER_UDP_LEN, MIN_WIRE_UDP_MTU, RTP_AUDIO_PT,
    RTP_FIXED_HDR_LEN, RTP_FULL_HDR_LEN, RTP_V2_EXT_BYTE, RTP_VIDEO_PT, SRTP_DATA_PREFIX_LEN,
    SRTP_HANDOVER_MAGIC, SRTP_PATH_CHALLENGE_MAGIC, SRTP_PROBE_MAGIC_LEN, SRTP_REVERSE_CTRL_MAGIC,
    SRTP_REVERSE_DATA_MAGIC, SRTP_TAG_LEN,
};
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Nonce as GcmNonce, Tag as GcmTag};
use blake2::digest::consts::{U16, U64};
use blake2::Blake2bMac;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce, Tag as ChaTag};
use hmac::{KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};
use std::time::Instant;
use subtle::ConstantTimeEq;

/// IPv4 单个 UDP 报文理论最大负载长度（65535 - 28 字节）。
const MAX_IPV4_UDP_PAYLOAD: usize = 65_507;
/// 加密 Nonce 方向域标识：客户端 -> 服务端。
const DIR_C2S: u8 = 0;
/// 加密 Nonce 方向域标识：服务端 -> 客户端。
const DIR_S2C: u8 = 1;
/// 双 SSRC 音频流正交 AEAD Nonce 域掩码位。
const NONCE_DOMAIN_AUDIO_BIT: u8 = 0x40;
/// 解封 SRTP 时允许的最大 RTP 头部长度（字节），防止越界构造。
const RTP_MAX_HDR_LEN: usize = 64;
/// RTP 次字节 Marker 位（`M=1` 表示视频帧尾或音频 talkspurt 起始）。
const RTP_MARKER_BIT: u8 = 0x80;
/// RFC 8285 One-Byte Header 魔数高字节（0xBE）。
const RTP_ONE_BYTE_EXT_MAGIC_HI: u8 = 0xBE;
/// RFC 8285 One-Byte Header 魔数低字节（0xDE）。
const RTP_ONE_BYTE_EXT_MAGIC_LO: u8 = 0xDE;
/// RFC 8285 ssrc-audio-level 扩展元素头字节（ID=1, L=0 即 1 字节值）。
const RTP_AUDIO_LEVEL_EXT_ID_LEN: u8 = 0x10;
/// RFC 8285 abs-send-time 扩展元素头字节（ID=2, L=2 即 3 字节 6.18 定点时钟）。
const RTP_ABS_SEND_TIME_EXT_ID_LEN: u8 = 0x22;
/// RFC 8285 transport-wide-cc 扩展元素头字节（ID=3, L=1 即 2 字节值）。
const RTP_TWCC_EXT_ID_LEN: u8 = 0x31;
/// RFC 8285 sdes:mid 扩展元素头字节（ID=4, L=0 即 1 字节字符）。
const RTP_MID_EXT_ID_LEN: u8 = 0x40;
/// RFC 3550 RTP 填充标志位（P=1，使首字节呈 0xB0 与 0x90 混合，贴合 Chrome BWE 分布）。
const RTP_PADDING_FLAG_BIT: u8 = 0x20;
/// 带内控制帧加密区前缀长度（2B 控制魔数 + 2B 控制负载长度）。
const SRTP_CTRL_PREFIX_LEN: usize = 4;
/// 反向隧道多路复用数据帧加密区前缀长度（2B 魔数 `0xFFFB` + 2B 负载长度 + 4B `flow_id`）。
const SRTP_REV_DATA_PREFIX_LEN: usize = 8;
/// 带内控制帧允许携带的最大负载字节数。
const SRTP_MAX_CTRL_PAYLOAD_LEN: usize = 1460;
/// 触发小范围随机填充的大包有效负载阈值（字节），避免接近 MTU 时浪费空间。
const SRTP_PAD_LARGE_PKT_THRESHOLD: usize = 1340;
/// 大包允许的最大随机填充字节数（0..=7B）。
const SRTP_PAD_LARGE_MAX: usize = 7;
/// 常规包允许的最大随机填充字节数（0..=63B，打破 1200B QUIC 形成的 32B 矩形窄箱）。
const SRTP_PAD_NORMAL_MAX: usize = 63;
/// 溢入视频 SSRC (`PT=96`) 的微小包（如高频 QUIC ACK）触发真实视频分片展宽的明文长度阈值（字节）。
const SRTP_PAD_TINY_VIDEO_THRESHOLD: usize = 160;
/// 溢入视频 SSRC 的微小包最大展宽上限（字节，用于无 MTU 限制时估算 headroom）。
const SRTP_PAD_TINY_VIDEO_MAX: usize = 1040;
/// SRTP 48 位扩展序列号硬上限（触及前强制轮换密钥，杜绝 Nonce 回绕）。
const MAX_SRTP_EXT_SEQ: u64 = 0xFFFF_FFFF_FF00;
/// SRTCP 31 位索引硬上限（触及前强制轮换密钥，杜绝 Nonce 回绕）。
const MAX_SRTCP_IDX: u32 = 0x7FFF_FF00;
/// SRTP 防重放环形位图 64 位字数（64 * 64 = 4096 位环，支持 O(1) 2048 包窗口）。
const SRTP_REPLAY_RING_WORDS: usize = 64;
/// SRTP RFC 6479 防重放滑动窗口宽度（2048 包，容忍跨洋 ECMP 乱序）。
const SRTP_REPLAY_WINDOW: u64 = 2048;
/// 数据面下行丢包统计排除的尾部乱序缓冲带宽度（24 包，免疫跨洋 ECMP 乱序误报）。
const SRTP_LOSS_REORDER_TAIL: u64 = 24;
/// 16 位 RTP 序列号 ROC 回绕判定低阈值（< 0x4000）。
const SRTP_ROC_WRAP_LOW: u16 = 0x4000;
/// 16 位 RTP 序列号 ROC 回绕判定高阈值（> 0xC000）。
const SRTP_ROC_WRAP_HIGH: u16 = 0xC000;
/// Opus 音频帧步长（20ms，严格遵守 RFC 7587 <= 50 pps 上限）。
const AUDIO_FRAME_MS: u64 = 20;
/// Opus 48 kHz 时钟每 20ms 帧对应的 RTP 时间戳增量（960 ticks）。
const AUDIO_TICKS_PER_FRAME: u64 = 960;
/// 音频静默间隔达到该阈值（毫秒）后，下一帧置 `M=1` 标记 talkspurt 起点。
const AUDIO_TALKSPURT_GAP_MS: u64 = 200;
/// 双 SSRC 小包路由到音频流的基准长度下界（字节，加 `0..=127` 抖动得 `180..=307B`）。
const AUDIO_SPLIT_BASE_LEN: usize = 180;
/// 双 SSRC 音频分流长度随机抖动掩码（0..=127 字节）。
const AUDIO_SPLIT_JITTER_MASK: usize = 0x7F;
/// 视频流标准 RTP 时钟频率（90 kHz）。
const VIDEO_CLOCK_KHZ: u128 = 90;
/// 视频单包成帧或判定大流帧的负载阈值（字节）。
const VIDEO_SMALL_PKT_THRESHOLD: usize = 1100;
/// 稀疏小包独立成帧（立即置 `M=1`）的最小时间间隔（90 kHz ticks，约 28ms）。
const VIDEO_SPARSE_GAP_90K: u64 = 2500;
/// 打开中的视频帧最大空闲年龄（90 kHz ticks，约 66ms），超时后另起新帧。
const VIDEO_MAX_FRAME_AGE_90K: u64 = 6000;
/// 标准 30 FPS 视频帧步进（90 kHz ticks = 33.3ms）。
const VIDEO_FRAME_STEP_30FPS_90K: u64 = 3000;
/// 标准 60 FPS 视频帧步进（90 kHz ticks = 16.7ms）。
const VIDEO_FRAME_STEP_60FPS_90K: u64 = 1500;
/// 真实摄像头采集时间戳半抖动幅值（±180 ticks = ±2ms，严格保证帧间步进 >= 1320 ticks <= 68 FPS）。
const VIDEO_FRAME_JITTER_HALF_90K: u64 = 180;
/// 含大包视频帧的随机每帧包数上限范围（18..=56 包，匹配 720p/1080p P/I 帧）。
const VIDEO_LARGE_FRAME_PKTS_MIN: u16 = 18;
const VIDEO_LARGE_FRAME_PKTS_SPAN: u16 = 39;
/// 纯小包溢出视频帧的随机每帧包数上限范围（6..=19 包，彻底消除 3 包机械微帧）。
const VIDEO_SMALL_FRAME_PKTS_MIN: u16 = 6;
const VIDEO_SMALL_FRAME_PKTS_SPAN: u16 = 14;
/// SplitMix64 伪随机数增量常量（黄金比例 64 位常数）。
const SPLITMIX64_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
/// SplitMix64 第一阶段混合乘数。
const SPLITMIX64_MUL1: u64 = 0xBF58_476D_1CE4_E5B9;
/// SplitMix64 第二阶段混合乘数。
const SPLITMIX64_MUL2: u64 = 0x94D0_49BB_1331_11EB;
/// SRTP 随机填充 LCG 初始种子异或常量。
const PAD_LCG_SEED_XOR: u64 = 0xA076_1D64_78BD_642F;
/// SRTP 随机填充 LCG 乘数（Knuth MMIX 64 位同余常数）。
const PAD_LCG_MUL: u64 = 6_364_136_223_846_793_005;

pub fn derive_stun_material(
    psk: &[u8],
    stun_txid: &[u8; 12],
    username: &str,
) -> ([u8; 32], u32, u32) {
    let mut seed = Vec::with_capacity(64 + psk.len() + username.len());
    seed.extend_from_slice(b"webrtc-cloak-v3|");
    seed.extend_from_slice(psk);
    seed.push(b'|');
    seed.extend_from_slice(stun_txid);
    seed.push(b'|');
    seed.extend_from_slice(username.as_bytes());

    let mut hk = Sha256::new();
    hk.update(&seed);
    hk.update(b"|stun-key");
    let stun_key: [u8; 32] = hk.finalize().into();

    let mut hs = Sha256::new();
    hs.update(&seed);
    hs.update(b"|ssrc");
    let sb = hs.finalize();
    let ssrc_c2s = u32::from_be_bytes([sb[0], sb[1], sb[2], sb[3]]);
    let ssrc_s2c = u32::from_be_bytes([sb[4], sb[5], sb[6], sb[7]]);
    (stun_key, ssrc_c2s, ssrc_s2c)
}

/// Bind PSK-authenticated STUN key with ephemeral ECDHE DTLS-SRTP keying material (True PFS!).
pub fn combine_session_key(stun_key: &[u8; 32], dtls_km: Option<&[u8]>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"webrtc-cloak-v3|pfs-bind|");
    h.update(stun_key);
    if let Some(km) = dtls_km {
        h.update(b"|dtls-km|");
        h.update(km);
    }
    h.finalize().into()
}

pub(super) fn derive_audio_ssrc(session_key: &[u8; 32], video_ssrc: u32) -> u32 {
    let mut h = Sha256::new();
    h.update(b"webrtc-cloak-v3-audio-ssrc|");
    h.update(session_key);
    h.update(video_ssrc.to_be_bytes());
    let d: [u8; 32] = h.finalize().into();
    let mut s = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    // Enforce strict high-16-bit disjointness (`iv[4..6]` in `gcm_nonce`), guaranteeing
    // 0% Nonce overlap across the entire 2^48 sequence space even without separate direction bits.
    if s == 0 || (s >> 16) == (video_ssrc >> 16) {
        s = video_ssrc ^ 0x5A3C_A5C3;
    }
    if s == 0 || (s >> 16) == (video_ssrc >> 16) {
        s = (video_ssrc ^ 0x1357_9BDF) | 1;
    }
    s
}

pub(super) enum CipherBackend {
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(ChaCha20Poly1305),
    Blake2b {
        enc_key: [u8; 32],
        mac_key: [u8; 32],
    },
}

pub struct SrtpCloakCipher {
    pub(super) backend: CipherBackend,
    pub(super) max_wire_udp: usize,
    pub(super) dual_ssrc: bool,
    pub(super) gcm_salt: [u8; 4],
    pub(super) cname: [u8; RTCP_CNAME_LEN],
    pub ssrc_tx: u32,
    pub ssrc_rx: u32,
    pub audio_ssrc_tx: u32,
    pub audio_ssrc_rx: u32,
    pub(super) tx_dir: u8,
    pub(super) rx_dir: u8,
    pub tx_ext_seq: u64,
    pub(super) tx_video_init_seq: u64,
    pub(super) audio_tx_ext_seq: u64,
    pub(super) tx_audio_init_seq: u64,
    pub(super) tx_twcc_seq: u16,
    pub(super) pad_rng: u64,
    pub(super) ts_base: u32,
    pub(super) audio_ts_base: u32,
    pub(super) t0: Instant,
    pub(super) video_frame_step_90k: u64,
    pub(super) video_frame_open: bool,
    pub(super) cur_video_ts: u64,
    pub(super) cur_frame_opened_wall_90k: u64,
    pub(super) cur_frame_close_age_90k: u64,
    pub(super) cur_frame_has_large: bool,
    pub(super) last_closed_video_ts: u64,
    pub(super) frame_pkt_count: u16,
    pub(super) cur_frame_max_pkts: u16,
    pub(super) last_audio_frame: u64,
    pub(super) last_audio_wall_ms: u64,
    pub(super) video_tx_since_rtcp: u64,
    pub(super) audio_tx_since_rtcp: u64,
    pub(super) rx_initialized: bool,
    pub rx_roc: u32,
    pub(super) rx_highest_seq16: u16,
    pub(super) rx_base_ext_seq: u64,
    pub(super) rx_unique_total: u64,
    pub(super) rx_loss_epoch_floor: u64,
    pub(super) rx_loss_reset_pending: bool,
    pub(super) rx_replay_ring: [u64; SRTP_REPLAY_RING_WORDS],
    pub(super) audio_rx_initialized: bool,
    pub(super) audio_rx_roc: u32,
    pub(super) audio_rx_highest_seq16: u16,
    pub(super) audio_rx_base_ext_seq: u64,
    pub(super) audio_rx_unique_total: u64,
    pub(super) audio_rx_loss_epoch_floor: u64,
    pub(super) audio_rx_loss_reset_pending: bool,
    pub(super) audio_rx_replay_ring: [u64; SRTP_REPLAY_RING_WORDS],
    pub(super) tx_srtcp_idx: u32,
    pub(super) rx_srtcp_seen: bool,
    pub(super) rx_srtcp_highest: u32,
    pub(super) rx_srtcp_bitmap: u64,
}

impl SrtpCloakCipher {
    pub fn new(
        session_key: &[u8; 32],
        ssrc_tx: u32,
        ssrc_rx: u32,
        is_client: bool,
        suite: CipherSuite,
    ) -> Self {
        let mut he = Sha256::new();
        he.update(session_key);
        he.update(b"|enc");
        let enc_key: [u8; 32] = he.finalize().into();

        let mut gcm_salt = [0u8; 4];
        gcm_salt.copy_from_slice(&enc_key[16..20]);

        let backend = match suite {
            CipherSuite::Aes128Gcm => {
                let cipher = <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(&enc_key[..16])
                    .expect("16B AES-128 key");
                CipherBackend::Aes128Gcm(Box::new(cipher))
            }
            CipherSuite::ChaCha20Poly1305 => {
                let cipher =
                    <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new_from_slice(&enc_key)
                        .expect("32B ChaCha20 key");
                CipherBackend::ChaCha20Poly1305(cipher)
            }
            CipherSuite::Blake2b => {
                let mut hm = Sha256::new();
                hm.update(session_key);
                hm.update(b"|mac");
                let mac_key: [u8; 32] = hm.finalize().into();
                CipherBackend::Blake2b { enc_key, mac_key }
            }
        };

        let audio_ssrc_tx = derive_audio_ssrc(session_key, ssrc_tx);
        let audio_ssrc_rx = derive_audio_ssrc(session_key, ssrc_rx);

        let mut r = [0u8; 37];
        fill_random(&mut r);
        let init_seq = (u16::from_be_bytes([r[0], r[1]]) & 0x7FFF) as u64;
        let ts_base = u32::from_be_bytes([r[2], r[3], r[4], r[5]]);
        let tx_twcc_seq = u16::from_be_bytes([r[6], r[7]]) & 0x7FFF;
        let pad_rng = u64::from_ne_bytes(r[8..16].try_into().unwrap()) | 1;
        let audio_init_seq = (u16::from_be_bytes([r[16], r[17]]) & 0x7FFF) as u64;
        let audio_ts_base = u32::from_be_bytes([r[18], r[19], r[20], r[21]]);
        let init_max_pkts =
            VIDEO_LARGE_FRAME_PKTS_MIN + ((r[22] as u16) % VIDEO_LARGE_FRAME_PKTS_SPAN);
        // 60% 30 FPS (3000 ticks), 40% 60 FPS (1500 ticks) — realistic WebRTC camera profile
        let video_frame_step_90k = if (r[23] % 5) < 3 {
            VIDEO_FRAME_STEP_30FPS_90K
        } else {
            VIDEO_FRAME_STEP_60FPS_90K
        };
        let mut cname = [0u8; RTCP_CNAME_LEN];
        for i in 0..RTCP_CNAME_LEN {
            cname[i] = BASE64_ALPHABET[(r[24 + i] as usize) & 63];
        }

        Self {
            backend,
            max_wire_udp: DEFAULT_WAN_MTU - IPV4_UDP_HDR_LEN,
            dual_ssrc: false,
            gcm_salt,
            cname,
            ssrc_tx,
            ssrc_rx,
            audio_ssrc_tx,
            audio_ssrc_rx,
            tx_dir: if is_client { DIR_C2S } else { DIR_S2C },
            rx_dir: if is_client { DIR_S2C } else { DIR_C2S },
            tx_ext_seq: init_seq,
            tx_video_init_seq: init_seq,
            audio_tx_ext_seq: audio_init_seq,
            tx_audio_init_seq: audio_init_seq,
            tx_twcc_seq,
            pad_rng,
            ts_base,
            audio_ts_base,
            t0: Instant::now(),
            video_frame_step_90k,
            video_frame_open: false,
            cur_video_ts: 0,
            cur_frame_opened_wall_90k: 0,
            cur_frame_close_age_90k: video_frame_step_90k,
            cur_frame_has_large: false,
            last_closed_video_ts: u64::MAX,
            frame_pkt_count: 0,
            cur_frame_max_pkts: init_max_pkts,
            last_audio_frame: u64::MAX,
            last_audio_wall_ms: u64::MAX,
            video_tx_since_rtcp: 0,
            audio_tx_since_rtcp: 0,
            rx_initialized: false,
            rx_roc: 0,
            rx_highest_seq16: 0,
            rx_base_ext_seq: 0,
            rx_unique_total: 0,
            rx_loss_epoch_floor: 0,
            rx_loss_reset_pending: false,
            rx_replay_ring: [0u64; SRTP_REPLAY_RING_WORDS],
            audio_rx_initialized: false,
            audio_rx_roc: 0,
            audio_rx_highest_seq16: 0,
            audio_rx_base_ext_seq: 0,
            audio_rx_unique_total: 0,
            audio_rx_loss_epoch_floor: 0,
            audio_rx_loss_reset_pending: false,
            audio_rx_replay_ring: [0u64; SRTP_REPLAY_RING_WORDS],
            tx_srtcp_idx: 0,
            rx_srtcp_seen: false,
            rx_srtcp_highest: 0,
            rx_srtcp_bitmap: 0,
        }
    }

    /// True if any SRTP 48-bit sequence or SRTCP 31-bit index is approaching exhaustion (must rekey).
    #[inline]
    pub fn is_seq_exhausted(&self) -> bool {
        self.tx_ext_seq >= MAX_SRTP_EXT_SEQ
            || self.audio_tx_ext_seq >= MAX_SRTP_EXT_SEQ
            || self.tx_srtcp_idx >= MAX_SRTCP_IDX
    }

    /// Enable dual-SSRC audio/video stream splitting (`PT=111` 48kHz Opus for `< 256B` small packets
    /// + `PT=96` 90kHz video for `>= 256B` packets), sharing a single global TWCC transport sequence.
    pub fn set_dual_ssrc(&mut self, enabled: bool) {
        self.dual_ssrc = enabled;
    }

    /// Configure outer IPv4 WAN MTU ceiling (`0` disables cap for jumbo/loopback testing).
    #[allow(dead_code)]
    pub fn set_wan_mtu(&mut self, wan_mtu: usize) {
        self.set_wan_mtu_for(wan_mtu, IPV4_UDP_HDR_LEN);
    }

    /// Configure outer WAN MTU ceiling with explicit IP+UDP header size (28B IPv4 / 48B IPv6).
    pub fn set_wan_mtu_for(&mut self, wan_mtu: usize, outer_hdr_len: usize) {
        self.max_wire_udp = if wan_mtu == 0 {
            0
        } else {
            wan_mtu.saturating_sub(outer_hdr_len).max(MIN_WIRE_UDP_MTU)
        };
    }

    #[inline]
    pub(super) fn next_rng(&mut self) -> u64 {
        self.pad_rng = self.pad_rng.wrapping_add(SPLITMIX64_GAMMA);
        let mut z = self.pad_rng;
        z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX64_MUL1);
        z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX64_MUL2);
        z ^ (z >> 31)
    }

    #[inline]
    fn is_replay_stream(
        initialized: bool,
        roc: u32,
        highest_seq16: u16,
        ring: &[u64; SRTP_REPLAY_RING_WORDS],
        ext_seq: u64,
    ) -> bool {
        if !initialized {
            return false;
        }
        let highest = ((roc as u64) << 16) | (highest_seq16 as u64);
        if ext_seq > highest {
            return false;
        }
        if highest - ext_seq >= SRTP_REPLAY_WINDOW {
            return true;
        }
        let word_idx = ((ext_seq >> 6) as usize) & (SRTP_REPLAY_RING_WORDS - 1);
        let bit_idx = ext_seq & 63;
        ((ring[word_idx] >> bit_idx) & 1) != 0
    }

    #[inline]
    pub(super) fn gcm_nonce(&self, direction: u8, ssrc: u32, ext_seq: u64) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[0] = self.gcm_salt[0] ^ direction;
        iv[1] = self.gcm_salt[1];
        iv[2] = self.gcm_salt[2];
        iv[3] = self.gcm_salt[3];
        let ssrc_b = ssrc.to_be_bytes();
        let seq_b = ext_seq.to_be_bytes();
        iv[4] = ssrc_b[0];
        iv[5] = ssrc_b[1];
        iv[6] = ssrc_b[2] ^ seq_b[2];
        iv[7] = ssrc_b[3] ^ seq_b[3];
        iv[8..12].copy_from_slice(&seq_b[4..8]);
        iv
    }

    #[inline]
    pub(super) fn xor_keystream(
        enc_key: &[u8; 32],
        direction: u8,
        ssrc: u32,
        ext_seq: u64,
        buf: &mut [u8],
    ) {
        if buf.is_empty() {
            return;
        }
        let mut block_in = [0u8; 17];
        block_in[0] = direction;
        block_in[1..5].copy_from_slice(&ssrc.to_be_bytes());
        block_in[5..13].copy_from_slice(&ext_seq.to_be_bytes());

        let mut ctr: u32 = 0;
        let mut offset = 0usize;
        let total = buf.len();
        while offset < total {
            block_in[13..17].copy_from_slice(&ctr.to_be_bytes());
            let mut hasher = Blake2bMac::<U64>::new_from_slice(enc_key).expect("key");
            hasher.update(&block_in);
            let ks = hasher.finalize().into_bytes();

            let take = (total - offset).min(64);
            let dst = &mut buf[offset..offset + take];
            let src = &ks[..take];

            let chunks = take / 8;
            for i in 0..chunks {
                let p = i * 8;
                let a = u64::from_ne_bytes(dst[p..p + 8].try_into().unwrap());
                let b = u64::from_ne_bytes(src[p..p + 8].try_into().unwrap());
                dst[p..p + 8].copy_from_slice(&(a ^ b).to_ne_bytes());
            }
            for i in (chunks * 8)..take {
                dst[i] ^= src[i];
            }

            offset += take;
            ctr += 1;
        }
    }

    #[inline]
    pub(super) fn auth_tag(
        mac_key: &[u8; 32],
        direction: u8,
        aad_hdr: &[u8],
        ciphertext: &[u8],
        roc: u32,
    ) -> [u8; SRTP_TAG_LEN] {
        let mut h = Blake2bMac::<U16>::new_from_slice(mac_key).expect("key");
        h.update(&[direction]);
        h.update(aad_hdr);
        h.update(ciphertext);
        h.update(&roc.to_be_bytes());
        h.finalize().into_bytes().into()
    }

    #[inline]
    pub(super) fn fill_fast_random(&mut self, buf: &mut [u8]) {
        let mut i = 0usize;
        while i < buf.len() {
            let r = self.next_rng().to_ne_bytes();
            let take = (buf.len() - i).min(8);
            buf[i..i + take].copy_from_slice(&r[..take]);
            i += take;
        }
    }

    /// Zero-allocation wrap into caller-provided `out` buffer; returns `Some(written_len)`.
    /// Wire format (RFC 3550 + RFC 8285 + RFC 7714 — fixes V3-H-03, V3-M-02, V3-L-03):
    ///   [12B RTP Header: 0x90 (V=2, P=0, X=1, CC=0), M | PT=96, pure wall-clock 90kHz TS]
    ///   [ 8B RFC 8285 0xBEDE One-Byte Extension (transport-wide-cc seq)]
    ///   [AEAD Ciphertext of: [inner_len: u16 BE] || [plaintext] || [0..=31B random pad]]
    ///   [16B AEAD / MAC Tag]
    #[inline]
    pub fn wrap_into(&mut self, plaintext: &[u8], out: &mut [u8]) -> Option<usize> {
        self.wrap_inner(None, None, false, plaintext, out)
    }

    /// Zero-allocation wrap of a reverse-tunnel multiplexed UDP flow packet
    /// (`0xFFFB || payload_len(2B) || flow_id(4B) || payload || random pad`) inside AEAD ciphertext.
    /// Wire-indistinguishable from normal Chrome `0x90` SRTP media packets.
    #[inline]
    pub fn wrap_reverse_data_into(
        &mut self,
        flow_id: u32,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        self.wrap_inner(
            Some(SRTP_REVERSE_DATA_MAGIC),
            Some(flow_id),
            false,
            plaintext,
            out,
        )
    }

    /// Wrap an in-band AEAD-encrypted reverse-tunnel control frame (`0xFFFA`).
    #[inline]
    pub fn wrap_reverse_ctrl_into(&mut self, payload: &[u8], out: &mut [u8]) -> Option<usize> {
        self.wrap_control_inner(SRTP_REVERSE_CTRL_MAGIC, false, payload, out)
    }

    /// Wrap an in-band AEAD-encrypted diagnostic probe (`0xFFFE || probe_len || payload || random pad`).
    /// Identical Chrome `0x90` SRTP format on the wire; strictly disjoint from real UDP (`<= 65400`).
    #[inline]
    pub fn wrap_probe_into(&mut self, payload: &[u8], out: &mut [u8]) -> Option<usize> {
        self.wrap_control_into(SRTP_PROBE_MAGIC_LEN, payload, out)
    }

    /// Wrap an in-band AEAD-encrypted control frame (`magic` in `{0xFFFE, 0xFFFD, 0xFFFC, 0xFFFA}`).
    /// Byte-for-byte identical Chrome `0x90` SRTP on the wire; strictly inside AEAD ciphertext.
    #[inline]
    pub fn wrap_control_into(
        &mut self,
        magic: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        self.wrap_control_inner(magic, false, payload, out)
    }

    /// Wrap an unpadded in-band encrypted control frame (used for server -> unverified candidate
    /// `0xFFFD` path challenges so total reply stays strictly `64B STUN + 57B SRTP = 121B <= 1.32x`).
    #[inline]
    pub fn wrap_control_unpadded_into(
        &mut self,
        magic: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        self.wrap_control_inner(magic, true, payload, out)
    }

    #[inline]
    fn wrap_control_inner(
        &mut self,
        magic: u16,
        no_pad: bool,
        payload: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        if payload.len() > SRTP_MAX_CTRL_PAYLOAD_LEN
            || !matches!(
                magic,
                SRTP_PROBE_MAGIC_LEN
                    | SRTP_PATH_CHALLENGE_MAGIC
                    | SRTP_HANDOVER_MAGIC
                    | SRTP_REVERSE_CTRL_MAGIC
            )
        {
            return None;
        }
        self.wrap_inner(Some(magic), None, no_pad, payload, out)
    }

    #[inline]
    fn wrap_inner(
        &mut self,
        control_magic: Option<u16>,
        rev_flow_id: Option<u32>,
        no_pad: bool,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        let is_control = control_magic.is_some();
        let prefix_len = if rev_flow_id.is_some() {
            SRTP_REV_DATA_PREFIX_LEN
        } else if is_control {
            SRTP_CTRL_PREFIX_LEN
        } else {
            SRTP_DATA_PREFIX_LEN
        };
        if plaintext.len() > MAX_INNER_UDP_LEN {
            return None;
        }
        if self.tx_ext_seq >= MAX_SRTP_EXT_SEQ || self.audio_tx_ext_seq >= MAX_SRTP_EXT_SEQ {
            return None; // Never wrap 48-bit SRTP sequence (RFC 3711 / RFC 7714)
        }

        let rnd = self.next_rng();
        let elapsed = self.t0.elapsed();
        let wall_ms = elapsed.as_millis() as u64;
        let audio_frame = wall_ms / AUDIO_FRAME_MS;
        // Jittered audio/video split threshold (180..=307B) + strict RFC 7587 <=50pps Opus cap
        // (max 1 PT=111 packet per 20ms frame; bursty QUIC ACKs cleanly spill onto PT=96 Video).
        let audio_thresh =
            AUDIO_SPLIT_BASE_LEN + (((rnd >> 24) as usize) & AUDIO_SPLIT_JITTER_MASK);
        let use_audio = self.dual_ssrc
            && plaintext.len() < audio_thresh
            && audio_frame != self.last_audio_frame;

        // Multi-element RFC 8285 One-Byte RTP Header Extensions matching Chrome libwebrtc:
        //   Audio (PT=111): ID=1 (ssrc-audio-level) + ID=3 (twcc) [+ ID=4 (sdes:mid="0") on opening pkts] -> 24B
        //   Video (PT=96) : ID=2 (abs-send-time)    + ID=3 (twcc) [+ ID=4 (sdes:mid="1") on opening/keyframe pkts] -> 24B / 28B
        // Automatically degrades 28B -> 24B -> 20B (TWCC-only) when an external tunnel packet is right at MTU.
        let want_mid = if use_audio {
            self.audio_tx_ext_seq.saturating_sub(self.tx_audio_init_seq) < 12
        } else {
            self.tx_ext_seq.saturating_sub(self.tx_video_init_seq) < 16
                || (!self.video_frame_open && ((rnd >> 44) & 0x0F) == 0)
        };
        let desired_hdr_len: usize = if !use_audio && want_mid { 28 } else { 24 };
        let max_allowed = {
            let cap_out = out.len().min(MAX_IPV4_UDP_PAYLOAD);
            if self.max_wire_udp > 0 {
                cap_out.min(self.max_wire_udp)
            } else {
                cap_out
            }
        };
        let hdr_len: usize = if desired_hdr_len + prefix_len + SRTP_TAG_LEN + plaintext.len()
            <= max_allowed
        {
            desired_hdr_len
        } else if 24 + prefix_len + SRTP_TAG_LEN + plaintext.len() <= max_allowed {
            24
        } else if RTP_FULL_HDR_LEN + prefix_len + SRTP_TAG_LEN + plaintext.len() <= max_allowed {
            RTP_FULL_HDR_LEN
        } else {
            return None; // Prevents IPv4 fragmentation & guides inner QUIC DPLPMTUD cleanly
        };
        let base_total = hdr_len + prefix_len + SRTP_TAG_LEN + plaintext.len();
        let headroom = if self.max_wire_udp > 0 {
            self.max_wire_udp.saturating_sub(base_total)
        } else {
            SRTP_PAD_TINY_VIDEO_MAX
        }
        .min(out.len().saturating_sub(base_total))
        .min(MAX_IPV4_UDP_PAYLOAD.saturating_sub(base_total));
        let eff_len = plaintext.len() + if is_control { SRTP_DATA_PREFIX_LEN } else { 0 };

        let pad_len: usize = if no_pad || headroom == 0 {
            0
        } else if !use_audio && !is_control && eff_len < SRTP_PAD_TINY_VIDEO_THRESHOLD {
            // Tiny packets spilling past the 50pps Opus audio cap onto Video PT=96 (e.g. high-rate
            // QUIC ACKs): widen into realistic video slice sizes (5% short 70..180B, 70% medium
            // triangular 160..660B, 25% large video slice 580..1040B) so PT=96 never produces
            // sub-MTU 3-packet micro-frames or <150B razor spikes.
            let bucket = (rnd >> 52) % 100;
            let (raw_min, raw_max) = if bucket < 5 {
                (70usize, 180usize)
            } else if bucket < 75 {
                (160usize, 660usize)
            } else {
                (580usize, SRTP_PAD_TINY_VIDEO_MAX)
            };
            let max_p = headroom.min(raw_max);
            let min_p = max_p.min(raw_min);
            let span = max_p.saturating_sub(min_p);
            if span == 0 {
                min_p
            } else {
                let half = (span / 2).max(1);
                let u1 = ((rnd >> 8) as usize) % (half + 1);
                let u2 = ((rnd >> 32) as usize) % (span - half + 1);
                min_p + u1 + u2
            }
        } else {
            let max_pad = if eff_len >= SRTP_PAD_LARGE_PKT_THRESHOLD {
                headroom.min(SRTP_PAD_LARGE_MAX)
            } else {
                headroom.min(SRTP_PAD_NORMAL_MAX)
            };
            if max_pad == 0 {
                0
            } else {
                (rnd as usize) % (max_pad + 1)
            }
        };
        let ct_len = prefix_len + plaintext.len() + pad_len;
        let total = hdr_len + ct_len + SRTP_TAG_LEN;
        if total > out.len() || total > MAX_IPV4_UDP_PAYLOAD {
            return None;
        }
        let (ext_seq, active_ssrc, pt, ts, marker, tx_domain_dir) = if use_audio {
            let es = self.audio_tx_ext_seq;
            self.audio_tx_ext_seq += 1;
            self.audio_tx_since_rtcp += 1;
            self.last_audio_frame = audio_frame;
            // RFC 7587 Opus 48,000 Hz clock quantized to 20ms frames (960 ticks/frame); M=1 on talkspurt start
            let a_ts = self
                .audio_ts_base
                .wrapping_add((audio_frame.wrapping_mul(AUDIO_TICKS_PER_FRAME)) as u32);
            let m: u8 = if self.last_audio_wall_ms == u64::MAX
                || wall_ms.saturating_sub(self.last_audio_wall_ms) >= AUDIO_TALKSPURT_GAP_MS
            {
                RTP_MARKER_BIT
            } else {
                0x00
            };
            self.last_audio_wall_ms = wall_ms;
            // Orthogonal AEAD Nonce domain (`dir | 0x40`) + high-16-bit disjoint Audio SSRC
            (
                es,
                self.audio_ssrc_tx,
                RTP_AUDIO_PT,
                a_ts,
                m,
                self.tx_dir | NONCE_DOMAIN_AUDIO_BIT,
            )
        } else {
            let es = self.tx_ext_seq;
            self.tx_ext_seq += 1;
            self.video_tx_since_rtcp += 1;
            // v0.7 Quantized 30/60 FPS 90 kHz virtual video frame clock with STRICT RFC 3550 M=1
            // causality: consecutive video frames ALWAYS advance by >= 1320 ticks (<= 68 FPS,
            // 0.00% >200 FPS or +1/+2 tick bursts), and frame boundaries close on frame-slot age
            // or varied per-frame packet caps (6..19 small / 18..56 large) — zero 3-pkt micro-frames!
            let wall_90k: u64 = ((elapsed.as_nanos() * VIDEO_CLOCK_KHZ) / 1_000_000) as u64;
            let jitter_span = VIDEO_FRAME_JITTER_HALF_90K * 2 + 1;
            let min_step = self
                .video_frame_step_90k
                .saturating_sub(VIDEO_FRAME_JITTER_HALF_90K)
                + ((rnd >> 16) % jitter_span);
            let is_large_pkt = plaintext.len() >= VIDEO_SMALL_PKT_THRESHOLD;
            let (frame_ts, m): (u64, u8) = if !self.video_frame_open {
                let start_ts = if self.last_closed_video_ts == u64::MAX {
                    wall_90k
                } else {
                    wall_90k.max(self.last_closed_video_ts.wrapping_add(min_step))
                };
                // Sparse small packet after >=28ms quiet gap -> clean single-packet frame (M=1)
                let sparse_gap = self.last_closed_video_ts == u64::MAX
                    || wall_90k.saturating_sub(self.cur_frame_opened_wall_90k)
                        >= VIDEO_SPARSE_GAP_90K;
                if !is_large_pkt && sparse_gap {
                    self.last_closed_video_ts = start_ts;
                    self.cur_frame_opened_wall_90k = wall_90k;
                    self.frame_pkt_count = 0;
                    (start_ts, RTP_MARKER_BIT)
                } else {
                    self.video_frame_open = true;
                    self.cur_video_ts = start_ts;
                    self.cur_frame_opened_wall_90k = wall_90k;
                    self.cur_frame_close_age_90k = min_step;
                    self.cur_frame_has_large = is_large_pkt;
                    self.frame_pkt_count = 1;
                    self.cur_frame_max_pkts = if is_large_pkt {
                        VIDEO_LARGE_FRAME_PKTS_MIN
                            + (((rnd >> 8) as u16) % VIDEO_LARGE_FRAME_PKTS_SPAN)
                    } else {
                        VIDEO_SMALL_FRAME_PKTS_MIN
                            + (((rnd >> 8) as u16) % VIDEO_SMALL_FRAME_PKTS_SPAN)
                    };
                    (start_ts, 0x00)
                }
            } else {
                if is_large_pkt && !self.cur_frame_has_large {
                    self.cur_frame_has_large = true;
                    self.cur_frame_max_pkts = VIDEO_LARGE_FRAME_PKTS_MIN
                        + (((rnd >> 8) as u16) % VIDEO_LARGE_FRAME_PKTS_SPAN);
                }
                let wall_age_90k = wall_90k.saturating_sub(self.cur_frame_opened_wall_90k);
                if wall_age_90k >= VIDEO_MAX_FRAME_AGE_90K {
                    // Long idle gap (>66ms): start fresh frame cleanly >= min_step ahead
                    let start_ts = wall_90k.max(self.cur_video_ts.wrapping_add(min_step));
                    self.cur_frame_opened_wall_90k = wall_90k;
                    if !is_large_pkt {
                        self.video_frame_open = false;
                        self.last_closed_video_ts = start_ts;
                        self.frame_pkt_count = 0;
                        (start_ts, RTP_MARKER_BIT)
                    } else {
                        self.cur_video_ts = start_ts;
                        self.cur_frame_close_age_90k = min_step;
                        self.cur_frame_has_large = true;
                        self.frame_pkt_count = 1;
                        self.cur_frame_max_pkts = VIDEO_LARGE_FRAME_PKTS_MIN
                            + (((rnd >> 8) as u16) % VIDEO_LARGE_FRAME_PKTS_SPAN);
                        (start_ts, 0x00)
                    }
                } else if wall_age_90k >= self.cur_frame_close_age_90k
                    || self.frame_pkt_count >= self.cur_frame_max_pkts
                {
                    // Close current frame with M=1 as its FINAL packet; next frame advances >= min_step!
                    let close_ts = self.cur_video_ts;
                    self.video_frame_open = false;
                    self.last_closed_video_ts = close_ts;
                    self.frame_pkt_count = 0;
                    (close_ts, RTP_MARKER_BIT)
                } else {
                    self.frame_pkt_count = self.frame_pkt_count.saturating_add(1);
                    (self.cur_video_ts, 0x00)
                }
            };
            let v_ts = self.ts_base.wrapping_add(frame_ts as u32);
            (es, self.ssrc_tx, RTP_VIDEO_PT, v_ts, m, self.tx_dir)
        };
        let roc = ((ext_seq >> 16) & 0xFFFF_FFFF) as u32;
        let seq16 = (ext_seq & 0xFFFF) as u16;
        // Shared global Transport-Wide CC sequence across both Audio & Video SSRCs (matches Chrome libwebrtc)
        let twcc = self.tx_twcc_seq;
        self.tx_twcc_seq = self.tx_twcc_seq.wrapping_add(1);

        // 12B standard Chrome RTP header: 0x90 (V=2, P=0, X=1, CC=0), or ~12.5% 0xB0 (P=1) when padded
        let use_rtp_pad_bit = !no_pad && pad_len >= 4 && ((rnd >> 48) & 0x07) == 0;
        out[0] = if use_rtp_pad_bit {
            RTP_V2_EXT_BYTE | RTP_PADDING_FLAG_BIT
        } else {
            RTP_V2_EXT_BYTE
        };
        out[1] = marker | pt;
        out[2..4].copy_from_slice(&seq16.to_be_bytes());
        out[4..8].copy_from_slice(&ts.to_be_bytes());
        out[8..12].copy_from_slice(&active_ssrc.to_be_bytes());

        // RFC 8285 One-Byte Extension Header (dynamic 20B / 24B / 28B Chrome layout)
        out[12] = RTP_ONE_BYTE_EXT_MAGIC_HI;
        out[13] = RTP_ONE_BYTE_EXT_MAGIC_LO;
        let ext_words = ((hdr_len - RTP_FIXED_HDR_LEN - 4) / 4) as u16;
        out[14..16].copy_from_slice(&ext_words.to_be_bytes());
        if hdr_len == RTP_FULL_HDR_LEN {
            // Minimal MTU-constrained fallback: ID=3 L=1 transport-wide-cc
            out[16] = RTP_TWCC_EXT_ID_LEN;
            out[17..19].copy_from_slice(&twcc.to_be_bytes());
            out[19] = 0x00;
        } else if use_audio {
            // Audio (24B): ID=1 ssrc-audio-level (V=1 + 20..55 dBov) + ID=3 twcc [+ ID=4 mid="0"]
            let audio_level = 0x80u8 | (20 + (((rnd >> 40) as u8) % 36));
            out[16] = RTP_AUDIO_LEVEL_EXT_ID_LEN;
            out[17] = audio_level;
            out[18] = RTP_TWCC_EXT_ID_LEN;
            out[19..21].copy_from_slice(&twcc.to_be_bytes());
            if want_mid {
                out[21] = RTP_MID_EXT_ID_LEN;
                out[22] = b'0';
                out[23] = 0x00;
            } else {
                out[21] = 0x00;
                out[22] = 0x00;
                out[23] = 0x00;
            }
        } else {
            // Video (24B or 28B): ID=2 abs-send-time (24-bit 6.18 fixed-point seconds) + ID=3 twcc
            let ast24 = (((elapsed.as_nanos() << 18) / 1_000_000_000) as u32) & 0x00FF_FFFF;
            out[16] = RTP_ABS_SEND_TIME_EXT_ID_LEN;
            out[17] = ((ast24 >> 16) & 0xFF) as u8;
            out[18] = ((ast24 >> 8) & 0xFF) as u8;
            out[19] = (ast24 & 0xFF) as u8;
            out[20] = RTP_TWCC_EXT_ID_LEN;
            out[21..23].copy_from_slice(&twcc.to_be_bytes());
            if hdr_len == 28 {
                out[23] = RTP_MID_EXT_ID_LEN;
                out[24] = b'1';
                out[25] = 0x00;
                out[26] = 0x00;
                out[27] = 0x00;
            } else {
                out[23] = 0x00;
            }
        }

        // Inner encrypted payload:
        //   Data       : [inner_len: u16 BE] || [plaintext] || [random pad]
        //   Control    : [magic: u16 BE (0xFFFE/0xFFFD/0xFFFC/0xFFFA)] || [len: u16 BE] || [payload] || [random pad]
        //   ReverseData: [0xFFFB: u16 BE] || [len: u16 BE] || [flow_id: u32 BE] || [plaintext] || [random pad]
        let ct_end = hdr_len + ct_len;
        if let Some(magic) = control_magic {
            out[hdr_len..hdr_len + 2].copy_from_slice(&magic.to_be_bytes());
            out[hdr_len + 2..hdr_len + 4].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
            if let Some(fid) = rev_flow_id {
                out[hdr_len + 4..hdr_len + 8].copy_from_slice(&fid.to_be_bytes());
            }
        } else {
            out[hdr_len..hdr_len + 2].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
        }
        out[hdr_len + prefix_len..hdr_len + prefix_len + plaintext.len()]
            .copy_from_slice(plaintext);
        if pad_len > 0 {
            let p_start = hdr_len + prefix_len + plaintext.len();
            let mut st = rnd ^ PAD_LCG_SEED_XOR;
            for b in &mut out[p_start..ct_end] {
                st = st.wrapping_mul(PAD_LCG_MUL).wrapping_add(1);
                *b = (st >> 56) as u8;
            }
            if use_rtp_pad_bit {
                out[ct_end - 1] = pad_len.min(255) as u8;
            }
        }

        let mut aad = [0u8; 32];
        aad[..hdr_len].copy_from_slice(&out[..hdr_len]);
        aad[hdr_len..hdr_len + 4].copy_from_slice(&roc.to_be_bytes());
        let aad_slice = &aad[..hdr_len + 4];

        match self.backend {
            CipherBackend::Aes128Gcm(ref aes_gcm) => {
                let iv = GcmNonce::from(self.gcm_nonce(tx_domain_dir, active_ssrc, ext_seq));
                let tag = aes_gcm
                    .encrypt_inout_detached(&iv, aad_slice, (&mut out[hdr_len..ct_end]).into())
                    .expect("AES-GCM encrypt");
                out[ct_end..total].copy_from_slice(&tag);
            }
            CipherBackend::ChaCha20Poly1305(ref chacha) => {
                let iv = ChaNonce::from(self.gcm_nonce(tx_domain_dir, active_ssrc, ext_seq));
                let tag = chacha
                    .encrypt_inout_detached(&iv, aad_slice, (&mut out[hdr_len..ct_end]).into())
                    .expect("ChaCha20-Poly1305 encrypt");
                out[ct_end..total].copy_from_slice(&tag);
            }
            CipherBackend::Blake2b {
                ref enc_key,
                ref mac_key,
            } => {
                Self::xor_keystream(
                    enc_key,
                    tx_domain_dir,
                    active_ssrc,
                    ext_seq,
                    &mut out[hdr_len..ct_end],
                );
                let tag = Self::auth_tag(
                    mac_key,
                    tx_domain_dir,
                    &out[..hdr_len],
                    &out[hdr_len..ct_end],
                    roc,
                );
                out[ct_end..total].copy_from_slice(&tag);
            }
        }
        Some(total)
    }

    /// Zero-allocation unwrap into caller-provided `out` buffer; returns `Some(inner_len)` for normal UDP data.
    #[inline]
    pub fn unwrap_into(&mut self, packet: &[u8], out: &mut [u8]) -> Option<usize> {
        match self.unwrap_into_ex(packet, out) {
            Some(SrtpFrame::Data(n)) => Some(n),
            _ => None,
        }
    }

    /// Zero-allocation unwrap distinguishing normal UDP `Data(len)` from in-band encrypted `Probe(len)`.
    #[inline]
    pub fn unwrap_into_ex(&mut self, packet: &[u8], out: &mut [u8]) -> Option<SrtpFrame> {
        if packet.len() < RTP_FIXED_HDR_LEN + SRTP_DATA_PREFIX_LEN + SRTP_TAG_LEN {
            return None;
        }
        let b0 = packet[0];
        if (b0 & RTP_V2_MASK) != RTP_V2_BITS {
            return None;
        }
        let has_ext = (b0 & 0x10) != 0;
        let csrc_len = ((b0 & 0x0F) as usize) * 4;
        let mut hdr_len = RTP_FIXED_HDR_LEN + csrc_len;
        if has_ext {
            if packet.len() < hdr_len + 4 + SRTP_TAG_LEN {
                return None;
            }
            let ext_words = u16::from_be_bytes([packet[hdr_len + 2], packet[hdr_len + 3]]) as usize;
            hdr_len += 4 + ext_words * 4;
        }
        if packet.len() < hdr_len + SRTP_DATA_PREFIX_LEN + SRTP_TAG_LEN || hdr_len > RTP_MAX_HDR_LEN
        {
            return None;
        }

        let seq16 = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        let is_audio = if ssrc == self.ssrc_rx {
            false
        } else if self.dual_ssrc && ssrc == self.audio_ssrc_rx {
            true
        } else {
            return None;
        };

        let rtp_hdr = &packet[..hdr_len];
        let ct_len = packet.len() - hdr_len - SRTP_TAG_LEN;
        if ct_len > out.len() {
            return None;
        }
        let ciphertext = &packet[hdr_len..hdr_len + ct_len];

        let (rx_init, rx_roc, rx_highest) = if is_audio {
            (
                self.audio_rx_initialized,
                self.audio_rx_roc,
                self.audio_rx_highest_seq16,
            )
        } else {
            (self.rx_initialized, self.rx_roc, self.rx_highest_seq16)
        };

        let mut candidates = [0u32; 3];
        let mut n_cand = 0usize;
        if rx_init {
            if seq16 < SRTP_ROC_WRAP_LOW && rx_highest > SRTP_ROC_WRAP_HIGH {
                candidates[n_cand] = rx_roc.wrapping_add(1);
                n_cand += 1;
                candidates[n_cand] = rx_roc;
                n_cand += 1;
            } else if seq16 > SRTP_ROC_WRAP_HIGH && rx_highest < SRTP_ROC_WRAP_LOW && rx_roc > 0 {
                candidates[n_cand] = rx_roc - 1;
                n_cand += 1;
                candidates[n_cand] = rx_roc;
                n_cand += 1;
            } else {
                candidates[n_cand] = rx_roc;
                n_cand += 1;
                candidates[n_cand] = rx_roc.wrapping_add(1);
                n_cand += 1;
                if rx_roc > 0 {
                    candidates[n_cand] = rx_roc - 1;
                    n_cand += 1;
                }
            }
        } else {
            candidates[0] = rx_roc;
            n_cand = 1;
        }

        let is_replay_cand = |this: &Self, ext_seq: u64| -> bool {
            if is_audio {
                Self::is_replay_stream(
                    this.audio_rx_initialized,
                    this.audio_rx_roc,
                    this.audio_rx_highest_seq16,
                    &this.audio_rx_replay_ring,
                    ext_seq,
                )
            } else {
                Self::is_replay_stream(
                    this.rx_initialized,
                    this.rx_roc,
                    this.rx_highest_seq16,
                    &this.rx_replay_ring,
                    ext_seq,
                )
            }
        };

        let rx_domain_dir = if is_audio {
            self.rx_dir | NONCE_DOMAIN_AUDIO_BIT
        } else {
            self.rx_dir
        };

        let tag_arr: [u8; SRTP_TAG_LEN] = packet[packet.len() - SRTP_TAG_LEN..].try_into().unwrap();
        let matched_roc = match self.backend {
            CipherBackend::Aes128Gcm(ref aes_gcm) => {
                let got_tag = GcmTag::from(tag_arr);
                let mut aad = [0u8; RTP_MAX_HDR_LEN + 4];
                aad[..hdr_len].copy_from_slice(rtp_hdr);
                let mut found = None;
                for &cand in &candidates[..n_cand] {
                    let ext_seq = ((cand as u64) << 16) | (seq16 as u64);
                    if is_replay_cand(self, ext_seq) {
                        continue;
                    }
                    let iv = GcmNonce::from(self.gcm_nonce(rx_domain_dir, ssrc, ext_seq));
                    aad[hdr_len..hdr_len + 4].copy_from_slice(&cand.to_be_bytes());
                    out[..ct_len].copy_from_slice(ciphertext);
                    if aes_gcm
                        .decrypt_inout_detached(
                            &iv,
                            &aad[..hdr_len + 4],
                            (&mut out[..ct_len]).into(),
                            &got_tag,
                        )
                        .is_ok()
                    {
                        found = Some(cand);
                        break;
                    }
                }
                found
            }
            CipherBackend::ChaCha20Poly1305(ref chacha) => {
                let got_tag = ChaTag::from(tag_arr);
                let mut aad = [0u8; RTP_MAX_HDR_LEN + 4];
                aad[..hdr_len].copy_from_slice(rtp_hdr);
                let mut found = None;
                for &cand in &candidates[..n_cand] {
                    let ext_seq = ((cand as u64) << 16) | (seq16 as u64);
                    if is_replay_cand(self, ext_seq) {
                        continue;
                    }
                    let iv = ChaNonce::from(self.gcm_nonce(rx_domain_dir, ssrc, ext_seq));
                    aad[hdr_len..hdr_len + 4].copy_from_slice(&cand.to_be_bytes());
                    out[..ct_len].copy_from_slice(ciphertext);
                    if chacha
                        .decrypt_inout_detached(
                            &iv,
                            &aad[..hdr_len + 4],
                            (&mut out[..ct_len]).into(),
                            &got_tag,
                        )
                        .is_ok()
                    {
                        found = Some(cand);
                        break;
                    }
                }
                found
            }
            CipherBackend::Blake2b {
                ref enc_key,
                ref mac_key,
            } => {
                let mut found = None;
                for &cand in &candidates[..n_cand] {
                    let ext_seq = ((cand as u64) << 16) | (seq16 as u64);
                    if is_replay_cand(self, ext_seq) {
                        continue;
                    }
                    let expected =
                        Self::auth_tag(mac_key, rx_domain_dir, rtp_hdr, ciphertext, cand);
                    if bool::from(tag_arr.ct_eq(&expected[..])) {
                        found = Some(cand);
                        break;
                    }
                }
                if let Some(roc) = found {
                    let ext_seq = ((roc as u64) << 16) | (seq16 as u64);
                    out[..ct_len].copy_from_slice(ciphertext);
                    Self::xor_keystream(enc_key, rx_domain_dir, ssrc, ext_seq, &mut out[..ct_len]);
                }
                found
            }
        };

        let roc = matched_roc?;
        self.update_rx_seq_stream(is_audio, roc, seq16);
        let raw_len = u16::from_be_bytes([out[0], out[1]]);
        if raw_len == SRTP_REVERSE_DATA_MAGIC {
            if ct_len < SRTP_REV_DATA_PREFIX_LEN {
                return None;
            }
            let payload_len = u16::from_be_bytes([out[2], out[3]]) as usize;
            let flow_id = u32::from_be_bytes([out[4], out[5], out[6], out[7]]);
            if payload_len > MAX_INNER_UDP_LEN || SRTP_REV_DATA_PREFIX_LEN + payload_len > ct_len {
                return None;
            }
            out.copy_within(
                SRTP_REV_DATA_PREFIX_LEN..SRTP_REV_DATA_PREFIX_LEN + payload_len,
                0,
            );
            return Some(SrtpFrame::ReverseData {
                flow_id,
                len: payload_len,
            });
        }
        if matches!(
            raw_len,
            SRTP_PROBE_MAGIC_LEN
                | SRTP_PATH_CHALLENGE_MAGIC
                | SRTP_HANDOVER_MAGIC
                | SRTP_REVERSE_CTRL_MAGIC
        ) {
            if ct_len < SRTP_CTRL_PREFIX_LEN {
                return None;
            }
            let ctrl_len = u16::from_be_bytes([out[2], out[3]]) as usize;
            if ctrl_len > SRTP_MAX_CTRL_PAYLOAD_LEN || SRTP_CTRL_PREFIX_LEN + ctrl_len > ct_len {
                return None;
            }
            out.copy_within(SRTP_CTRL_PREFIX_LEN..SRTP_CTRL_PREFIX_LEN + ctrl_len, 0);
            return Some(match raw_len {
                SRTP_PROBE_MAGIC_LEN => SrtpFrame::Probe(ctrl_len),
                SRTP_PATH_CHALLENGE_MAGIC => SrtpFrame::PathChallenge(ctrl_len),
                SRTP_HANDOVER_MAGIC => SrtpFrame::Handover(ctrl_len),
                SRTP_REVERSE_CTRL_MAGIC => SrtpFrame::ReverseCtrl(ctrl_len),
                _ => unreachable!(),
            });
        }
        let inner_len = raw_len as usize;
        if inner_len > MAX_INNER_UDP_LEN || SRTP_DATA_PREFIX_LEN + inner_len > ct_len {
            return None;
        }
        out.copy_within(SRTP_DATA_PREFIX_LEN..SRTP_DATA_PREFIX_LEN + inner_len, 0);
        Some(SrtpFrame::Data(inner_len))
    }

    #[inline]
    fn settled_rx_stream(
        initialized: bool,
        reset_pending: bool,
        base_ext_seq: u64,
        roc: u32,
        highest_seq16: u16,
        ring: &[u64; SRTP_REPLAY_RING_WORDS],
        unique_total: u64,
    ) -> (u64, u64) {
        if !initialized || reset_pending {
            return (0, 0);
        }
        let highest = ((roc as u64) << 16) | (highest_seq16 as u64);
        if highest < base_ext_seq {
            return (0, 0);
        }
        let span = highest.saturating_sub(base_ext_seq).saturating_add(1);
        if span <= SRTP_LOSS_REORDER_TAIL {
            return (0, 0);
        }
        let ring_mask = SRTP_REPLAY_RING_WORDS - 1;
        let tail_start = highest.saturating_sub(SRTP_LOSS_REORDER_TAIL - 1);
        let mut tail_received = 0u64;
        let mut seq = tail_start;
        while seq <= highest {
            let word_idx = ((seq >> 6) as usize) & ring_mask;
            let bit_idx = seq & 63;
            if ((ring[word_idx] >> bit_idx) & 1) != 0 {
                tail_received += 1;
            }
            if seq == u64::MAX {
                break;
            }
            seq += 1;
        }
        let settled_expected = span - SRTP_LOSS_REORDER_TAIL;
        let settled_received = unique_total
            .saturating_sub(tail_received)
            .min(settled_expected);
        (settled_expected, settled_received)
    }

    /// 1-RTT 路径迁移完成后重置数据面丢包统计纪元：
    /// 隔离旧黑洞路径产生的序号断层以及经 `old_path_drains` 延迟到达的旧路径尾包，
    /// 待新路径首包到达后再重新锚定统计基线，同时 100% 保持防重放窗口完整不降级。
    pub fn reset_rx_loss_epoch(&mut self) {
        if self.rx_initialized {
            let highest = ((self.rx_roc as u64) << 16) | (self.rx_highest_seq16 as u64);
            self.rx_loss_epoch_floor = highest.saturating_add(1);
            self.rx_loss_reset_pending = true;
            self.rx_unique_total = 0;
        }
        if self.audio_rx_initialized {
            let highest = ((self.audio_rx_roc as u64) << 16) | (self.audio_rx_highest_seq16 as u64);
            self.audio_rx_loss_epoch_floor = highest.saturating_add(1);
            self.audio_rx_loss_reset_pending = true;
            self.audio_rx_unique_total = 0;
        }
    }

    /// 返回视频与音频双 SSRC 合并后的已稳定累计下行 `(expected_pkts, received_pkts)`。
    /// 排除每个流最新 24 个序号的在途乱序尾窗，零额外线开销即可精确观测数据面丢包率且免疫 ECMP 乱序。
    pub fn rx_settled_stats(&self) -> (u64, u64) {
        let (ve, vr) = Self::settled_rx_stream(
            self.rx_initialized,
            self.rx_loss_reset_pending,
            self.rx_base_ext_seq,
            self.rx_roc,
            self.rx_highest_seq16,
            &self.rx_replay_ring,
            self.rx_unique_total,
        );
        let (ae, ar) = if self.dual_ssrc {
            Self::settled_rx_stream(
                self.audio_rx_initialized,
                self.audio_rx_loss_reset_pending,
                self.audio_rx_base_ext_seq,
                self.audio_rx_roc,
                self.audio_rx_highest_seq16,
                &self.audio_rx_replay_ring,
                self.audio_rx_unique_total,
            )
        } else {
            (0, 0)
        };
        (ve.saturating_add(ae), vr.saturating_add(ar))
    }

    #[inline]
    fn update_rx_seq_stream(&mut self, is_audio: bool, roc: u32, seq16: u16) {
        let (
            rx_initialized,
            rx_roc,
            rx_highest_seq16,
            rx_base_ext_seq,
            rx_unique_total,
            rx_loss_epoch_floor,
            rx_loss_reset_pending,
            rx_replay_ring,
        ) = if is_audio {
            (
                &mut self.audio_rx_initialized,
                &mut self.audio_rx_roc,
                &mut self.audio_rx_highest_seq16,
                &mut self.audio_rx_base_ext_seq,
                &mut self.audio_rx_unique_total,
                &mut self.audio_rx_loss_epoch_floor,
                &mut self.audio_rx_loss_reset_pending,
                &mut self.audio_rx_replay_ring,
            )
        } else {
            (
                &mut self.rx_initialized,
                &mut self.rx_roc,
                &mut self.rx_highest_seq16,
                &mut self.rx_base_ext_seq,
                &mut self.rx_unique_total,
                &mut self.rx_loss_epoch_floor,
                &mut self.rx_loss_reset_pending,
                &mut self.rx_replay_ring,
            )
        };
        let ext_seq = ((roc as u64) << 16) | (seq16 as u64);
        let new_block = ext_seq >> 6;
        let bit_mask = 1u64 << (ext_seq & 63);
        let ring_mask = SRTP_REPLAY_RING_WORDS - 1;

        if !*rx_initialized {
            *rx_initialized = true;
            *rx_roc = roc;
            *rx_highest_seq16 = seq16;
            *rx_base_ext_seq = ext_seq;
            *rx_unique_total = 1;
            *rx_loss_epoch_floor = ext_seq;
            *rx_loss_reset_pending = false;
            *rx_replay_ring = [0u64; SRTP_REPLAY_RING_WORDS];
            rx_replay_ring[(new_block as usize) & ring_mask] = bit_mask;
            return;
        }
        let highest = ((*rx_roc as u64) << 16) | (*rx_highest_seq16 as u64);
        let mut newly_accepted = false;
        if ext_seq > highest {
            let old_block = highest >> 6;
            let diff_blocks = new_block - old_block;
            if diff_blocks >= SRTP_REPLAY_RING_WORDS as u64 {
                *rx_replay_ring = [0u64; SRTP_REPLAY_RING_WORDS];
            } else {
                for b in (old_block + 1)..=new_block {
                    rx_replay_ring[(b as usize) & ring_mask] = 0;
                }
            }
            rx_replay_ring[(new_block as usize) & ring_mask] |= bit_mask;
            *rx_roc = roc;
            *rx_highest_seq16 = seq16;
            newly_accepted = true;
        } else if highest - ext_seq < SRTP_REPLAY_WINDOW {
            let slot = &mut rx_replay_ring[(new_block as usize) & ring_mask];
            if (*slot & bit_mask) == 0 {
                *slot |= bit_mask;
                newly_accepted = true;
            }
        }
        if newly_accepted && ext_seq >= *rx_loss_epoch_floor {
            if *rx_loss_reset_pending {
                *rx_loss_reset_pending = false;
                *rx_base_ext_seq = ext_seq;
                *rx_unique_total = 1;
            } else {
                *rx_unique_total = rx_unique_total.saturating_add(1);
                if ext_seq < *rx_base_ext_seq {
                    *rx_base_ext_seq = ext_seq;
                }
            }
        }
    }
}
