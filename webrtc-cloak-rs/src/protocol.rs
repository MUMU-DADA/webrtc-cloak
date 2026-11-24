//! Wire-format protocol primitives for webrtc-cloak V3.2 (Hardened):
//!   - RFC 5389 / 8445 STUN ICE Binding Request & Success Response:
//!     * libwebrtc 4-char Base64 ufrag (zero modulo bias), libwebrtc attribute order
//!     * Session-constant ICE-CONTROLLING tie-breaker & PRIORITY; USE-CANDIDATE only on nomination
//!     * Timestamp-masked anti-replay txid (±30s window) + zero-alloc pre-auth strict MI-then-FP parsing
//!   - Real RFC 9147 DTLS 1.3 + RFC 6347 DTLS 1.2 via `dimpl 0.9.0` (pure-Rust Sans-IO, mutual ECDSA
//!     P-256 certs, encrypted DTLS 1.3 certs, multi-MTU ClientHello pool, optional strict 1.3 anti-downgrade,
//!     RFC 5764/7714 KeyingMaterial export -> Fail-Closed Hybrid PFS, real `close_notify` teardown)
//!   - RFC 3550 / 3711 / 7714 / 8285 SRTP framing:
//!     * Standard Chrome `0x90` (V=2, P=0, X=1, CC=0) + 8B RFC 8285 `0xBEDE` global transport-wide-cc ext
//!     * Dual-SSRC Audio (`PT=111`, 48kHz Opus capped <=50pps) + Video (`PT=96`, 90kHz strict M=1 causality)
//!     * Orthogonal AEAD Nonce domains (Video `dir`, Audio `dir|0x40` + high-16-bit disjoint SSRC, SRTCP `dir|0x80`)
//!     * Inner-ciphertext length prefix + randomized 0..=31B padding + 2048-packet RFC 6479 sliding replay rings
//!   - RFC 3550 §6.1 / 5761 / 7714 §9.1 Compound SRTCP:
//!     * Plaintext header ALWAYS PT=200(SR) or PT=201(RR), real RC=0/1 matching rx media state
//!     * Encrypted compound subpackets (session-constant 13B CNAME SDES + smooth FB + encrypted trailing BYE PT=203)
//!     * Always 16B AEAD/MAC tag + trailing 4B E_SRTCP_Index (0-based) + 64-packet SRTCP sliding replay window

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce as GcmNonce, Tag as GcmTag};
use blake2::digest::consts::{U16, U64};
use blake2::{Blake2bMac, Digest as _};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce, Tag as ChaTag};
use dimpl::crypto::{
    rust_crypto, CryptoProvider, Dtls12CipherSuite, Dtls13CipherSuite, SupportedDtls12CipherSuite,
    SupportedDtls13CipherSuite,
};
use dimpl::{Config as DtlsConfig, Dtls, DtlsCertificate};
use hmac::{Hmac, Mac as _};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use sha1::Sha1;
use sha2::Sha256;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_SUCCESS: u16 = 0x0101;
pub const STUN_MAX_SKEW_SECS: i64 = 30;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_PRIORITY: u16 = 0x0024;
const ATTR_USE_CANDIDATE: u16 = 0x0025;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_ICE_CONTROLLING: u16 = 0x802A;

const STUN_FINGERPRINT_XOR: u32 = 0x5354_554E;

pub const RTP_FIXED_HDR_LEN: usize = 12;
pub const RTP_EXT_LEN: usize = 8; // 4B 0xBEDE header + 4B one-byte transport-wide-cc extension
pub const RTP_FULL_HDR_LEN: usize = RTP_FIXED_HDR_LEN + RTP_EXT_LEN; // 20B
pub const SRTP_TAG_LEN: usize = 16; // Unified 16B tag across AES-GCM, ChaCha20, and BLAKE2b-128
pub const MAX_INNER_UDP_LEN: usize = 65_400; // Hard bound preventing wbuf[65664] overflow
pub const SRTP_PROBE_MAGIC_LEN: u16 = 0xFFFE; // Reserved > MAX_INNER_UDP_LEN for in-band encrypted selftest echo
pub const RTP_VIDEO_PT: u8 = 96;
pub const RTP_AUDIO_PT: u8 = 111; // Chrome Opus dynamic PT (48 kHz)
/// Hard SRTP 48-bit extended sequence exhaustion ceiling (never wrap Nonce!).
const MAX_SRTP_EXT_SEQ: u64 = 0xFFFF_FFFF_FF00;
/// Hard SRTCP 31-bit index exhaustion ceiling (never wrap Nonce!).
const MAX_SRTCP_IDX: u32 = 0x7FFF_FF00;

/// Minimum allowed DTLS protocol version for handshakes:
///   - `Auto` (`1.2` / `auto`, default): DTLS 1.3 preferred with seamless DTLS 1.2 fallback for rolling upgrades.
///   - `V13Only` (`1.3`): Strictly enforces RFC 9147 DTLS 1.3 (`Dtls::new_13`), completely blocking downgrade attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsMinVersion {
    Auto,
    V13Only,
}

impl DtlsMinVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            DtlsMinVersion::Auto => "auto(1.3+1.2)",
            DtlsMinVersion::V13Only => "1.3-only",
        }
    }
}

pub fn new_dtls_instance(
    min_ver: DtlsMinVersion,
    cfg: Arc<DtlsConfig>,
    cert: DtlsCertificate,
    now: Instant,
) -> Dtls {
    match min_ver {
        DtlsMinVersion::Auto => Dtls::new_auto(cfg, cert, now),
        DtlsMinVersion::V13Only => Dtls::new_13(cfg, cert, now),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpFrame {
    Data(usize),
    Probe(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// BLAKE2b-CTR + 16B BLAKE2b-128 tag (manual override)
    Blake2b,
    /// RFC 7714 SRTP AES-128-GCM (runtime AES-NI+PCLMULQDQ / ARMv8 AES+PMULL)
    Aes128Gcm,
    /// RFC 8439 ChaCha20-Poly1305 (runtime AVX-512 / AVX2 / SSE2 / ARM NEON)
    ChaCha20Poly1305,
}

impl CipherSuite {
    pub fn name(self) -> &'static str {
        match self {
            CipherSuite::Blake2b => "blake2b",
            CipherSuite::Aes128Gcm => "aes-128-gcm",
            CipherSuite::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherPref {
    /// Auto-negotiate best AEAD via standard 3-suite DTLS 1.2 cipher suite selection
    Auto,
    Fixed(CipherSuite),
}

/// Runtime CPU hardware acceleration probe (uses std::arch::is_*_feature_detected!).
#[derive(Debug, Clone)]
pub struct CpuAccelInfo {
    pub arch: &'static str,
    pub features: Vec<&'static str>,
    pub has_hw_aes_gcm: bool,
    pub recommended: CipherSuite,
}

pub fn detect_cpu_accel() -> CpuAccelInfo {
    #[allow(unused_mut)]
    let mut features = Vec::new();
    let has_hw_aes_gcm;

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sse2") { features.push("SSE2"); }
        if std::arch::is_x86_feature_detected!("ssse3") { features.push("SSSE3"); }
        if std::arch::is_x86_feature_detected!("sse4.2") { features.push("SSE4.2(CRC32)"); }
        if std::arch::is_x86_feature_detected!("aes") { features.push("AES-NI"); }
        if std::arch::is_x86_feature_detected!("pclmulqdq") { features.push("PCLMULQDQ(GCM)"); }
        if std::arch::is_x86_feature_detected!("sha") { features.push("SHA-NI"); }
        if std::arch::is_x86_feature_detected!("avx2") { features.push("AVX2"); }
        if std::arch::is_x86_feature_detected!("avx512f") { features.push("AVX-512F"); }
        if std::arch::is_x86_feature_detected!("vaes") { features.push("VAES"); }
        if std::arch::is_x86_feature_detected!("vpclmulqdq") { features.push("VPCLMULQDQ"); }
        has_hw_aes_gcm = std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq");
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") { features.push("NEON"); }
        if std::arch::is_aarch64_feature_detected!("aes") { features.push("ARMv8-AES"); }
        if std::arch::is_aarch64_feature_detected!("pmull") { features.push("ARMv8-PMULL(GCM)"); }
        if std::arch::is_aarch64_feature_detected!("sha2") { features.push("ARMv8-SHA2"); }
        if std::arch::is_aarch64_feature_detected!("crc") { features.push("ARMv8-CRC32"); }
        has_hw_aes_gcm = std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull");
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        has_hw_aes_gcm = false;
    }

    let recommended = if has_hw_aes_gcm {
        CipherSuite::Aes128Gcm
    } else {
        CipherSuite::ChaCha20Poly1305
    };

    CpuAccelInfo {
        arch: std::env::consts::ARCH,
        features,
        has_hw_aes_gcm,
        recommended,
    }
}

pub const DIR_C2S: u8 = 0;
pub const DIR_S2C: u8 = 1;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Stun,
    Dtls,
    Srtp,
    Srtcp,
    Unknown,
}

/// RFC 7983 §7 + RFC 5761 §4 demultiplexing (20..=63 covers DTLS 1.2 + RFC 9147 DTLS 1.3 unified ciphertext/ACK; RTCP 192..=223).
#[inline]
pub fn demux_rfc7983(data: &[u8]) -> PacketKind {
    match data.first().copied() {
        Some(0..=3) => PacketKind::Stun,
        Some(20..=63) => PacketKind::Dtls,
        Some(128..=191) => {
            if data.len() >= 8 && (192..=223).contains(&data[1]) {
                PacketKind::Srtcp
            } else {
                PacketKind::Srtp
            }
        }
        _ => PacketKind::Unknown,
    }
}

/// Strict pre-validation of DTLS 1.2 & RFC 9147 DTLS 1.3 datagrams before feeding to `dimpl` (fixes V3-H-01):
///   - Plaintext / DTLS 1.2 records (20..=23, 26 ACK): validates 13B header, DTLS version (0xFEFD/0xFEFF),
///     exact record boundaries, rejects unauthenticated plaintext Epoch=0 Alerts, requires >= 18B for epoch>=1.
///   - DTLS 1.3 Unified Ciphertext records (32..=63, `001C_SL_EE`): validates C==0 (no CID), S/L header lengths,
///     and minimum 18B AEAD ciphertext length.
///   - When `ready_only_alert == true`, only permits encrypted Epoch>=1 Alerts (DTLS 1.2), DTLS 1.3 ACK (26),
///     or DTLS 1.3 Unified Ciphertext records (32..=63, carrying encrypted close_notify/ACK).
pub fn validate_dtls_datagram(pkt: &[u8], ready_only_alert: bool) -> bool {
    if pkt.is_empty() {
        return false;
    }
    let mut pos = 0usize;
    let mut rec_count = 0usize;
    while pos < pkt.len() {
        let b0 = pkt[pos];
        if (b0 & 0xE0) == 0x20 {
            // RFC 9147 §4 DTLS 1.3 Unified Ciphertext Header: 001C_SL_EE (32..=63)
            if (b0 & 0x10) != 0 {
                return false; // Connection ID (C=1) not supported
            }
            let seq_len = if (b0 & 0x08) != 0 { 2usize } else { 1usize };
            let has_len = (b0 & 0x04) != 0;
            let hdr_len = 1 + seq_len + if has_len { 2 } else { 0 };
            if pos + hdr_len > pkt.len() {
                return false;
            }
            let rec_len = if has_len {
                u16::from_be_bytes([pkt[pos + 1 + seq_len], pkt[pos + 2 + seq_len]]) as usize
            } else {
                pkt.len() - (pos + hdr_len)
            };
            if rec_len < 18 || pos + hdr_len + rec_len > pkt.len() {
                return false;
            }
            pos += hdr_len + rec_len;
        } else {
            if pos + 13 > pkt.len() {
                return false;
            }
            let ct = b0;
            let ver_maj = pkt[pos + 1];
            let ver_min = pkt[pos + 2];
            let epoch = u16::from_be_bytes([pkt[pos + 3], pkt[pos + 4]]);
            let rec_len = u16::from_be_bytes([pkt[pos + 11], pkt[pos + 12]]) as usize;
            if !matches!(ct, 20..=23 | 26) {
                return false;
            }
            if ver_maj != 0xFE || (ver_min != 0xFD && ver_min != 0xFF) {
                return false;
            }
            if rec_len == 0 || pos + 13 + rec_len > pkt.len() {
                return false;
            }
            // Reject unauthenticated plaintext Epoch=0 Alerts during handshake,
            // and reject plaintext-framed Epoch>=1 ACK (RFC 9147 encrypted ACKs use 0x20..=0x3F).
            if (ct == 21 && epoch == 0) || (ct == 26 && epoch >= 1) {
                return false;
            }
            // AEAD encrypted DTLS 1.2 records (epoch >= 1) require >= 2B payload + 16B tag
            if epoch >= 1 && rec_len < 18 {
                return false;
            }
            // In established Ready state, plaintext-framed records may ONLY be DTLS 1.2 encrypted Alerts
            // (DTLS 1.3 encrypted close_notify / ACK arrive inside 0x20..=0x3F Unified Ciphertext).
            if ready_only_alert && !(ct == 21 && epoch >= 1) {
                return false;
            }
            pos += 13 + rec_len;
        }
        rec_count += 1;
        if rec_count > 24 {
            return false;
        }
    }
    rec_count > 0 && pos == pkt.len()
}

pub fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG failed");
}

pub fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    fill_random(&mut b);
    u32::from_ne_bytes(b)
}

/// Randomized jitter duration within [0.80 * base_ms, 1.20 * base_ms] (RFC 7675 ±20%).
pub fn jitter_duration_ms(base_ms: u64) -> Duration {
    if base_ms == 0 {
        return Duration::from_millis(0);
    }
    let min_ms = (base_ms * 4) / 5;
    let span = ((base_ms * 2) / 5).max(1);
    let offset = (rand_u32() as u64) % span;
    Duration::from_millis(min_ms + offset)
}

/// Uniform random duration in [min_ms, max_ms].
pub fn rand_duration_range_ms(min_ms: u64, max_ms: u64) -> Duration {
    if max_ms <= min_ms {
        return Duration::from_millis(min_ms);
    }
    let span = (max_ms - min_ms) + 1;
    Duration::from_millis(min_ms + ((rand_u32() as u64) % span))
}

/// Chrome/libwebrtc 4-char ICE ufrag from the 64-char Base64 alphabet (zero modulo bias).
pub fn rand_ufrag_chrome() -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut raw = [0u8; 4];
    fill_random(&mut raw);
    raw.iter().map(|&b| ALPHA[(b & 0x3F) as usize] as char).collect()
}

pub fn unix_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// RFC 5389 / 8445 STUN ICE + Timestamp-Masked Anti-Replay Transaction ID
// ---------------------------------------------------------------------------

/// Session-constant ICE attributes per RFC 8445 §5.1.2.1 & §5.2.
#[derive(Debug, Clone)]
pub struct SessionIceParams {
    pub ufrag_local: String,
    pub ufrag_remote: String,
    pub tie_breaker: [u8; 8],
    pub priority: u32,
}

impl SessionIceParams {
    pub fn generate() -> Self {
        let mut tie_breaker = [0u8; 8];
        fill_random(&mut tie_breaker);
        let local_pref = (rand_u32() & 0xFFFF) | 0x8000;
        let priority = (126u32 << 24) | (local_pref << 8) | 255u32;
        Self {
            ufrag_local: rand_ufrag_chrome(),
            ufrag_remote: rand_ufrag_chrome(),
            tie_breaker,
            priority,
        }
    }

    pub fn username(&self) -> String {
        format!("{}:{}", self.ufrag_remote, self.ufrag_local)
    }
}

fn txid_ts_mask(psk: &[u8], r8: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"webrtc-cloak:txid-ts:");
    h.update(psk);
    h.update(r8);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

pub fn make_fresh_stun_txid(psk: &[u8]) -> [u8; 12] {
    let mut txid = [0u8; 12];
    fill_random(&mut txid[..8]);
    let ts_b = unix_secs().to_be_bytes();
    let mask = txid_ts_mask(psk, &txid[..8]);
    for i in 0..4 {
        txid[8 + i] = ts_b[i] ^ mask[i];
    }
    txid
}

pub fn verify_stun_txid_fresh(psk: &[u8], txid: &[u8; 12]) -> bool {
    let mask = txid_ts_mask(psk, &txid[..8]);
    let ts_b = [
        txid[8] ^ mask[0],
        txid[9] ^ mask[1],
        txid[10] ^ mask[2],
        txid[11] ^ mask[3],
    ];
    let ts = u32::from_be_bytes(ts_b) as i64;
    let now = unix_secs() as i64;
    (now - ts).abs() <= STUN_MAX_SKEW_SECS
}

fn push_stun_attr(buf: &mut Vec<u8>, attr_type: u16, val: &[u8]) {
    buf.extend_from_slice(&attr_type.to_be_bytes());
    buf.extend_from_slice(&(val.len() as u16).to_be_bytes());
    buf.extend_from_slice(val);
    let pad = (4 - (val.len() % 4)) % 4;
    for _ in 0..pad {
        buf.push(0);
    }
}

pub fn stun_hmac_key(psk: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"webrtc-cloak:stun-mi:");
    h.update(psk);
    h.finalize().into()
}

fn finalize_stun(msg_type: u16, txid: &[u8; 12], body_in: &[u8], psk: &[u8]) -> Vec<u8> {
    let mut body = body_in.to_vec();
    let mi_key = stun_hmac_key(psk);
    let len_for_mi = (body.len() + 24) as u16;
    let mut mac = HmacSha1::new_from_slice(&mi_key).expect("HMAC key");
    mac.update(&msg_type.to_be_bytes());
    mac.update(&len_for_mi.to_be_bytes());
    mac.update(&STUN_MAGIC_COOKIE.to_be_bytes());
    mac.update(txid);
    mac.update(&body);
    let digest = mac.finalize().into_bytes();
    push_stun_attr(&mut body, ATTR_MESSAGE_INTEGRITY, &digest);

    let len_final = (body.len() + 8) as u16;
    let mut out = Vec::with_capacity(20 + body.len() + 8);
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&len_final.to_be_bytes());
    out.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(txid);
    out.extend_from_slice(&body);

    let crc = crc32fast::hash(&out) ^ STUN_FINGERPRINT_XOR;
    push_stun_attr(&mut out, ATTR_FINGERPRINT, &crc.to_be_bytes());
    out
}

pub fn encode_xor_mapped_v4(addr: SocketAddrV4) -> [u8; 8] {
    let x_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let ip_u32 = u32::from(*addr.ip());
    let x_ip = ip_u32 ^ STUN_MAGIC_COOKIE;
    let mut out = [0u8; 8];
    out[0] = 0x00;
    out[1] = 0x01;
    out[2..4].copy_from_slice(&x_port.to_be_bytes());
    out[4..8].copy_from_slice(&x_ip.to_be_bytes());
    out
}

pub fn decode_xor_mapped_v4(val: &[u8]) -> Option<SocketAddrV4> {
    if val.len() < 8 || val[1] != 0x01 {
        return None;
    }
    let x_port = u16::from_be_bytes([val[2], val[3]]);
    let x_ip = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
    let port = x_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let ip = Ipv4Addr::from(x_ip ^ STUN_MAGIC_COOKIE);
    Some(SocketAddrV4::new(ip, port))
}

/// Build an RFC 8445 ICE STUN Binding Request matching libwebrtc attribute ordering:
///   USERNAME -> ICE-CONTROLLING -> [USE-CANDIDATE] -> PRIORITY -> MESSAGE-INTEGRITY -> FINGERPRINT
pub fn build_ice_stun_request(
    psk: &[u8],
    ice: &SessionIceParams,
    txid_opt: Option<[u8; 12]>,
    include_use_candidate: bool,
) -> (Vec<u8>, [u8; 12]) {
    let txid = txid_opt.unwrap_or_else(|| make_fresh_stun_txid(psk));
    let uname = ice.username();
    let mut body = Vec::with_capacity(64);
    push_stun_attr(&mut body, ATTR_USERNAME, uname.as_bytes());
    push_stun_attr(&mut body, ATTR_ICE_CONTROLLING, &ice.tie_breaker);
    if include_use_candidate {
        push_stun_attr(&mut body, ATTR_USE_CANDIDATE, &[]);
    }
    push_stun_attr(&mut body, ATTR_PRIORITY, &ice.priority.to_be_bytes());

    let pkt = finalize_stun(STUN_BINDING_REQUEST, &txid, &body, psk);
    (pkt, txid)
}

/// Build an authenticated RFC 8445 ICE STUN Binding Success Response (always 64 bytes).
pub fn build_stun_success_response(txid: &[u8; 12], peer: SocketAddrV4, psk: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(48);
    let xma = encode_xor_mapped_v4(peer);
    push_stun_attr(&mut body, ATTR_XOR_MAPPED_ADDRESS, &xma);
    finalize_stun(STUN_BINDING_SUCCESS, txid, &body, psk)
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ParsedStun {
    pub msg_type: u16,
    pub txid: [u8; 12],
    pub username: Option<String>,
    pub use_candidate: bool,
    pub xor_mapped: Option<SocketAddrV4>,
    pub fingerprint_ok: bool,
    pub authenticated: bool,
}

/// Strict RFC 5389 §15.4 + RFC 8445 STUN parser (zero heap allocation before HMAC passes!):
///   - Rejects any attribute appearing AFTER MESSAGE-INTEGRITY except a single trailing FINGERPRINT.
///   - Mandates valid FINGERPRINT at the exact end of packet (`val_end == end`).
///   - Enforces valid `ufrag_r:ufrag_l` username format and ±30s timestamp freshness on requests.
pub fn parse_stun(data: &[u8], psk: &[u8]) -> Option<ParsedStun> {
    let mi_key = stun_hmac_key(psk);
    parse_stun_with_key(data, psk, &mi_key)
}

pub fn parse_stun_with_key(data: &[u8], psk: &[u8], mi_key: &[u8; 32]) -> Option<ParsedStun> {
    if data.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != STUN_MAGIC_COOKIE || msg_len % 4 != 0 || 20 + msg_len != data.len() {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&data[8..20]);

    let mut pos = 20usize;
    let end = 20 + msg_len;
    let mut username_range: Option<(usize, usize)> = None;
    let mut use_candidate = false;
    let mut xor_mapped = None;
    let mut seen_mi = false;
    let mut mi_ok = false;
    let mut fp_ok = false;

    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let val_start = pos + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return None;
        }
        let val = &data[val_start..val_end];
        let pad = (4 - (attr_len % 4)) % 4;
        let next_pos = val_end + pad;

        if seen_mi {
            // RFC 5389 §15.4: ONLY a single trailing 8-byte FINGERPRINT may follow MESSAGE-INTEGRITY!
            if attr_type == ATTR_FINGERPRINT && attr_len == 4 && next_pos == end {
                let expected_crc = crc32fast::hash(&data[..pos]) ^ STUN_FINGERPRINT_XOR;
                let got_crc = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
                fp_ok = got_crc == expected_crc;
                pos = next_pos;
                break;
            } else {
                // Any trailing attribute injected after MESSAGE-INTEGRITY -> immediate rejection!
                return None;
            }
        }

        match attr_type {
            ATTR_USERNAME => {
                username_range = Some((val_start, val_end));
            }
            ATTR_XOR_MAPPED_ADDRESS => {
                xor_mapped = decode_xor_mapped_v4(val);
            }
            ATTR_USE_CANDIDATE if attr_len == 0 => {
                use_candidate = true;
            }
            ATTR_MESSAGE_INTEGRITY if attr_len == 20 => {
                seen_mi = true;
                // Must be followed by exact 8-byte FINGERPRINT (next_pos + 8 == end)
                if next_pos + 8 != end {
                    return None;
                }
                let mi_hdr_len = ((pos - 20) + 24) as u16;
                let mut mac = HmacSha1::new_from_slice(mi_key).expect("HMAC key");
                mac.update(&msg_type.to_be_bytes());
                mac.update(&mi_hdr_len.to_be_bytes());
                mac.update(&STUN_MAGIC_COOKIE.to_be_bytes());
                mac.update(&txid);
                mac.update(&data[20..pos]);
                let expected = mac.finalize().into_bytes();
                mi_ok = bool::from(val.ct_eq(&expected[..]));
            }
            ATTR_FINGERPRINT => {
                // FINGERPRINT without preceding MESSAGE-INTEGRITY -> unauthenticated
                return None;
            }
            _ => {}
        }
        pos = next_pos;
    }

    let mut auth_ok = seen_mi && mi_ok && fp_ok && pos == end;
    let username = if auth_ok {
        if let Some((s, e)) = username_range {
            let raw = &data[s..e];
            if msg_type == STUN_BINDING_REQUEST {
                let valid_uname = !raw.is_empty() && raw.len() <= 64 && raw.contains(&b':');
                if !valid_uname || !verify_stun_txid_fresh(psk, &txid) {
                    auth_ok = false;
                    None
                } else {
                    Some(String::from_utf8_lossy(raw).into_owned())
                }
            } else {
                Some(String::from_utf8_lossy(raw).into_owned())
            }
        } else {
            if msg_type == STUN_BINDING_REQUEST {
                auth_ok = false;
            }
            None
        }
    } else {
        None
    };

    Some(ParsedStun {
        msg_type,
        txid,
        username,
        use_candidate,
        xor_mapped,
        fingerprint_ok: fp_ok,
        authenticated: auth_ok,
    })
}

// ---------------------------------------------------------------------------
// Chrome-Aligned Self-Signed X.509 v3 ECDSA P-256 Cert Cache + `dimpl` Config
// ---------------------------------------------------------------------------

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut out = Vec::with_capacity(len + 4);
    out.push(tag);
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(body);
    out
}

fn der_int(raw: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < raw.len() && raw[i] == 0 {
        i += 1;
    }
    let slice = &raw[i..];
    let mut body = Vec::with_capacity(slice.len() + 1);
    if slice[0] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(slice);
    der_tlv(0x02, &body)
}

fn der_bit_string(bytes: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes.len() + 1);
    body.push(unused_bits);
    body.extend_from_slice(bytes);
    der_tlv(0x03, &body)
}

fn format_utctime(secs: u64) -> Vec<u8> {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let yy = (year % 100) as u64;
    format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", yy, m, d, hh, mm, ss).into_bytes()
}

/// Randomly un-normalize ECDSA P-256 signature S with 50% probability so DER signature
/// `(r, s)` length distribution matches real OpenSSL/BoringSSL (fixes V3-M-01 Low-S fingerprint).
fn randomize_ecdsa_s_der(sig: &P256Signature) -> Vec<u8> {
    let (r, s) = sig.split_scalars();
    let r_bytes = r.to_bytes();
    let s_bytes = if (rand_u32() & 1) == 1 {
        (-*s).to_bytes() // n - s (valid ECDSA signature with high-S!)
    } else {
        s.to_bytes()
    };
    let mut inner = der_int(&r_bytes);
    inner.extend_from_slice(&der_int(&s_bytes));
    der_tlv(0x30, &inner)
}

/// Generate a Chrome/BoringSSL-aligned ephemeral self-signed X.509 v3 ECDSA P-256 certificate:
///   - Unbiased positive 16-byte serial (no forced odd-LSB bias!)
///   - Extension-less CN=WebRTC template (matches real Chrome BoringSSL WebRTC certs!)
///   - Randomized notBefore (-1..-24h) and validity span (29..31 days)
///   - Unnormalized 50/50 High-S / Low-S ECDSA self-signature matching BoringSSL
pub fn generate_ephemeral_webrtc_cert() -> DtlsCertificate {
    let signing_key = loop {
        let mut raw = [0u8; 32];
        fill_random(&mut raw);
        if let Ok(sk) = SigningKey::from_bytes(&raw.into()) {
            break sk;
        }
    };
    let pub_bytes = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let pkcs8_der = p256::SecretKey::from(&signing_key)
        .to_pkcs8_der()
        .expect("PKCS#8 DER encode")
        .as_bytes()
        .to_vec();

    let alg_ecdsa_sha256 = der_tlv(0x30, &der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]));
    let mut spki_alg_inner = der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
    spki_alg_inner.extend_from_slice(&der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]));
    let spki_alg = der_tlv(0x30, &spki_alg_inner);

    let mut cn_atv = der_tlv(0x06, &[0x55, 0x04, 0x03]);
    cn_atv.extend_from_slice(&der_tlv(0x0C, b"WebRTC"));
    let name_dn = der_tlv(0x30, &der_tlv(0x31, &der_tlv(0x30, &cn_atv)));

    // Unbiased positive 16-byte serial (clear MSB only; avoid 0x00 leading byte without odd-LSB bias!)
    let mut serial = [0u8; 16];
    fill_random(&mut serial);
    serial[0] &= 0x7F;
    if serial[0] == 0 {
        serial[0] = 0x01;
    }

    let now = unix_secs() as u64;
    let back_secs = 3600 + ((rand_u32() as u64) % (23 * 3600)); // 1..24h before now
    let span_secs = (29 * 86400) + ((rand_u32() as u64) % (2 * 86400)); // 29..31 days
    let not_before = format_utctime(now.saturating_sub(back_secs));
    let not_after = format_utctime(now + span_secs);
    let mut val_inner = der_tlv(0x17, &not_before);
    val_inner.extend_from_slice(&der_tlv(0x17, &not_after));
    let validity = der_tlv(0x30, &val_inner);

    let mut spki_inner = spki_alg;
    spki_inner.extend_from_slice(&der_bit_string(&pub_bytes, 0));
    let spki = der_tlv(0x30, &spki_inner);

    let mut tbs_inner = Vec::with_capacity(256);
    tbs_inner.extend_from_slice(&der_tlv(0xA0, &der_int(&[0x02]))); // v3
    tbs_inner.extend_from_slice(&der_int(&serial));
    tbs_inner.extend_from_slice(&alg_ecdsa_sha256);
    tbs_inner.extend_from_slice(&name_dn);
    tbs_inner.extend_from_slice(&validity);
    tbs_inner.extend_from_slice(&name_dn);
    tbs_inner.extend_from_slice(&spki);
    let tbs = der_tlv(0x30, &tbs_inner);

    let sig: P256Signature = signing_key.sign(&tbs);
    let sig_der = randomize_ecdsa_s_der(&sig);

    let mut cert_inner = Vec::with_capacity(tbs.len() + 96);
    cert_inner.extend_from_slice(&tbs);
    cert_inner.extend_from_slice(&alg_ecdsa_sha256);
    cert_inner.extend_from_slice(&der_bit_string(&sig_der, 0));
    let cert_der = der_tlv(0x30, &cert_inner);

    DtlsCertificate {
        certificate: cert_der,
        private_key: pkcs8_der,
    }
}

/// Worker-local rotating certificate cache (reuses RTCCertificate for ~20..24h like real browsers,
/// auto-rotates long before 30-day expiry, avoids per-session cert generation CPU cost).
pub struct CertCache {
    cert: DtlsCertificate,
    expires_at: Instant,
}

impl CertCache {
    pub fn new() -> Self {
        let ttl = rand_duration_range_ms(20 * 3600 * 1000, 24 * 3600 * 1000);
        Self {
            cert: generate_ephemeral_webrtc_cert(),
            expires_at: Instant::now() + ttl,
        }
    }

    pub fn get(&mut self, now: Instant) -> DtlsCertificate {
        if now >= self.expires_at {
            let ttl = rand_duration_range_ms(20 * 3600 * 1000, 24 * 3600 * 1000);
            self.cert = generate_ephemeral_webrtc_cert();
            self.expires_at = now + ttl;
        }
        self.cert.clone()
    }
}

/// Build a `CryptoProvider` whose DTLS 1.2 & DTLS 1.3 cipher suite order prefers ChaCha20 first
/// while STILL advertising all real AEAD suites (zero single-suite JA4D leak!).
fn chacha_first_provider() -> CryptoProvider {
    static CHACHA_FIRST_SUITES12: OnceLock<&'static [&'static dyn SupportedDtls12CipherSuite]> =
        OnceLock::new();
    static CHACHA_FIRST_SUITES13: OnceLock<&'static [&'static dyn SupportedDtls13CipherSuite]> =
        OnceLock::new();
    let mut provider = rust_crypto::default_provider();
    let suites12 = *CHACHA_FIRST_SUITES12.get_or_init(|| {
        let mut ordered: Vec<&'static dyn SupportedDtls12CipherSuite> = Vec::new();
        for &s in provider.cipher_suites {
            if s.suite() == Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 {
                ordered.push(s);
            }
        }
        for &s in provider.cipher_suites {
            if s.suite() != Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 {
                ordered.push(s);
            }
        }
        Box::leak(ordered.into_boxed_slice())
    });
    let suites13 = *CHACHA_FIRST_SUITES13.get_or_init(|| {
        let mut ordered: Vec<&'static dyn SupportedDtls13CipherSuite> = Vec::new();
        for &s in provider.dtls13_cipher_suites {
            if s.suite() == Dtls13CipherSuite::CHACHA20_POLY1305_SHA256 {
                ordered.push(s);
            }
        }
        for &s in provider.dtls13_cipher_suites {
            if s.suite() != Dtls13CipherSuite::CHACHA20_POLY1305_SHA256 {
                ordered.push(s);
            }
        }
        Box::leak(ordered.into_boxed_slice())
    });
    provider.cipher_suites = suites12;
    provider.dtls13_cipher_suites = suites13;
    provider
}

/// Pre-built pool of `dimpl::Config` instances with varied DTLS MTU targets (zero runtime
/// `crypto_provider.validate()` overhead while eliminating constant 1150B padded ClientHello spikes
/// and respecting `--mtu` ceilings on nested/PPPoE links).
#[derive(Clone)]
pub struct DtlsConfigPool {
    configs: Vec<Arc<DtlsConfig>>,
}

impl DtlsConfigPool {
    pub fn pick(&self) -> Arc<DtlsConfig> {
        if self.configs.len() <= 1 {
            return Arc::clone(&self.configs[0]);
        }
        let idx = (rand_u32() as usize) % self.configs.len();
        Arc::clone(&self.configs[idx])
    }

    #[cfg(test)]
    pub fn mtus(&self) -> Vec<usize> {
        self.configs.iter().map(|c| c.mtu()).collect()
    }
}

fn build_single_dimpl_config(
    pref: CipherPref,
    cpu: &CpuAccelInfo,
    is_client: bool,
    dtls_mtu: usize,
) -> Arc<DtlsConfig> {
    let want_chacha = match pref {
        CipherPref::Fixed(CipherSuite::ChaCha20Poly1305) => true,
        CipherPref::Auto => !cpu.has_hw_aes_gcm,
        _ => false,
    };

    let provider = if want_chacha {
        chacha_first_provider()
    } else {
        rust_crypto::default_provider()
    };

    let mut builder = DtlsConfig::builder()
        .with_crypto_provider(provider)
        .mtu(dtls_mtu)
        .require_client_certificate(true)
        .use_server_cookie(true)
        .flight_start_rto(Duration::from_millis(350))
        .flight_retries(5)
        .handshake_timeout(Duration::from_secs(12));

    // Client ALWAYS advertises all real DTLS 1.3 + 1.2 AEAD suites (zero 1-suite JA4D leak!).
    // Server only restricts allow-list when forcing ChaCha20 or AES-GCM explicitly.
    if !is_client && want_chacha {
        builder = builder
            .dtls12_cipher_suites(&[
                Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
            ])
            .dtls13_cipher_suites(&[Dtls13CipherSuite::CHACHA20_POLY1305_SHA256]);
    } else if !is_client && pref == CipherPref::Fixed(CipherSuite::Aes128Gcm) {
        builder = builder
            .dtls12_cipher_suites(&[
                Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
                Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
            ])
            .dtls13_cipher_suites(&[
                Dtls13CipherSuite::AES_128_GCM_SHA256,
                Dtls13CipherSuite::AES_256_GCM_SHA384,
            ]);
    }

    Arc::new(builder.build().expect("dimpl Config build"))
}

/// Build a pre-validated pool of `dimpl` DTLS 1.3 / 1.2 Configs clamped to `wan_mtu`.
pub fn build_dimpl_config_pool(
    pref: CipherPref,
    cpu: &CpuAccelInfo,
    is_client: bool,
    wan_mtu: usize,
) -> DtlsConfigPool {
    let max_dtls_mtu = if wan_mtu > 0 {
        wan_mtu.saturating_sub(28).min(1360).max(256)
    } else {
        1360
    };
    if !is_client {
        return DtlsConfigPool {
            configs: vec![build_single_dimpl_config(
                pref,
                cpu,
                false,
                1150.min(max_dtls_mtu),
            )],
        };
    }
    const CLIENT_MTUS: [usize; 8] = [760, 840, 920, 1000, 1080, 1150, 1240, 1340];
    let mut mtus: Vec<usize> = CLIENT_MTUS
        .iter()
        .map(|&m| m.min(max_dtls_mtu))
        .collect();
    mtus.sort_unstable();
    mtus.dedup();
    let configs = mtus
        .into_iter()
        .map(|m| build_single_dimpl_config(pref, cpu, true, m))
        .collect();
    DtlsConfigPool { configs }
}

/// Build a single `dimpl` DTLS 1.3 / 1.2 Config (default WAN MTU).
#[allow(dead_code)]
pub fn build_dimpl_config(pref: CipherPref, cpu: &CpuAccelInfo, is_client: bool) -> Arc<DtlsConfig> {
    build_single_dimpl_config(pref, cpu, is_client, 1150)
}

/// RFC 8446 §4.1.3 HelloRetryRequest magic ServerRandom (MUST NOT be mistaken for ServerHello).
const TLS13_HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Strictly extract negotiated 16-bit TLS cipher suite ID from an unfragmented Epoch=0 ServerHello
/// (supports both DTLS 1.2 and RFC 9147 DTLS 1.3; rejects RFC 8446 HelloRetryRequest and
/// malformed/truncated extension framing).
pub fn extract_dtls_server_hello_suite(datagram: &[u8]) -> Option<u16> {
    let mut pos = 0usize;
    while pos < datagram.len() {
        let b0 = datagram[pos];
        if (b0 & 0xE0) == 0x20 {
            // Skip RFC 9147 DTLS 1.3 unified ciphertext records
            if (b0 & 0x10) != 0 {
                return None;
            }
            let seq_len = if (b0 & 0x08) != 0 { 2usize } else { 1usize };
            let has_len = (b0 & 0x04) != 0;
            let hdr_len = 1 + seq_len + if has_len { 2 } else { 0 };
            if pos + hdr_len > datagram.len() {
                return None;
            }
            if has_len {
                let rlen =
                    u16::from_be_bytes([datagram[pos + 1 + seq_len], datagram[pos + 2 + seq_len]])
                        as usize;
                pos += hdr_len + rlen;
            } else {
                break;
            }
            continue;
        }
        if pos + 13 > datagram.len() {
            return None;
        }
        let ct = b0;
        if datagram[pos + 1] != 0xFE || (datagram[pos + 2] != 0xFD && datagram[pos + 2] != 0xFF) {
            return None;
        }
        let epoch = u16::from_be_bytes([datagram[pos + 3], datagram[pos + 4]]);
        let rec_len = u16::from_be_bytes([datagram[pos + 11], datagram[pos + 12]]) as usize;
        let rec_end = pos + 13 + rec_len;
        if rec_end > datagram.len() {
            return None;
        }
        if ct == 0x16 && epoch == 0 && rec_len >= 50 {
            let hs = &datagram[pos + 13..rec_end];
            // HandshakeType=ServerHello(0x02), unfragmented (msg_len == frag_len, frag_off == 0),
            // legacy_version=0xFEFD, NOT HelloRetryRequest, valid compression=0 & exact extensions framing.
            let msg_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
            let msg_seq = u16::from_be_bytes([hs[4], hs[5]]);
            let frag_off = u32::from_be_bytes([0, hs[6], hs[7], hs[8]]) as usize;
            let frag_len = u32::from_be_bytes([0, hs[9], hs[10], hs[11]]) as usize;
            let sh_end = 12usize.saturating_add(frag_len);
            if hs[0] == 0x02
                && msg_seq <= 1
                && frag_off == 0
                && msg_len == frag_len
                && sh_end <= hs.len()
                && hs[12] == 0xFE
                && hs[13] == 0xFD
                && &hs[14..46] != &TLS13_HRR_RANDOM
            {
                let sid_len = hs[46] as usize;
                let cs_pos = 47 + sid_len;
                if cs_pos + 3 <= sh_end && hs[cs_pos + 2] == 0 {
                    let ext_ok = if cs_pos + 3 == sh_end {
                        true
                    } else if cs_pos + 5 <= sh_end {
                        let ext_len = u16::from_be_bytes([hs[cs_pos + 3], hs[cs_pos + 4]]) as usize;
                        cs_pos + 5 + ext_len == sh_end
                    } else {
                        false
                    };
                    if ext_ok {
                        return Some(u16::from_be_bytes([hs[cs_pos], hs[cs_pos + 1]]));
                    }
                }
            }
        }
        pos = rec_end;
    }
    None
}

/// Map negotiated DTLS 1.3 / 1.2 ServerHello cipher suite + local CipherPref to SRTP CipherSuite.
/// Note: in `--no-dtls-decoy` mode (`dtls_suite_id == None` with `no_dtls == true`),
/// `CipherPref::Auto` deterministically picks `ChaCha20Poly1305` so heterogeneous CPUs always interop.
pub fn resolve_srtp_suite(
    pref: CipherPref,
    dtls_suite_id: Option<u16>,
    cpu: &CpuAccelInfo,
    no_dtls: bool,
) -> CipherSuite {
    match pref {
        CipherPref::Fixed(s) => s,
        CipherPref::Auto => {
            if no_dtls {
                CipherSuite::ChaCha20Poly1305
            } else {
                match dtls_suite_id {
                    Some(0xCCA9 | 0x1303) => CipherSuite::ChaCha20Poly1305,
                    Some(0xC02B | 0xC02C | 0x1301 | 0x1302) => CipherSuite::Aes128Gcm,
                    _ => cpu.recommended,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Key Derivation (STUN PSK + DTLS-SRTP Forward-Secret KeyingMaterial)
// & RFC 3550 / 3711 / 7714 / 8285 SRTP + Compound SRTCP
// ---------------------------------------------------------------------------

pub fn derive_stun_material(psk: &[u8], stun_txid: &[u8; 12], username: &str) -> ([u8; 32], u32, u32) {
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

const SRTP_REPLAY_RING_WORDS: usize = 64; // 4096-bit ring buffer -> exact O(1) 2048-packet RFC 6479 window
const SRTP_REPLAY_WINDOW: u64 = 2048;     // WireGuard-grade trans-Pacific ECMP reorder tolerance
/// Default outer IPv4 WAN MTU ceiling (1488B < 1492B PPPoE -> max outer UDP payload 1460B).
/// Eliminates IPv4 UDP fragmentation on PPPoE/CGNAT links and forces inner QUIC DPLPMTUD
/// (e.g. Hysteria 2 over 127.0.0.1) to converge cleanly without fragmented packets.
pub const DEFAULT_WAN_MTU: usize = 1488;

fn derive_audio_ssrc(session_key: &[u8; 32], video_ssrc: u32) -> u32 {
    let mut h = Sha256::new();
    h.update(b"webrtc-cloak-v3-audio-ssrc|");
    h.update(session_key);
    h.update(&video_ssrc.to_be_bytes());
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

pub struct SrtpCloakCipher {
    suite: CipherSuite,
    max_wire_udp: usize,
    dual_ssrc: bool,
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    aes_gcm: Aes128Gcm,
    chacha: ChaCha20Poly1305,
    gcm_salt: [u8; 4],
    cname: [u8; 13],
    pub ssrc_tx: u32,
    pub ssrc_rx: u32,
    pub audio_ssrc_tx: u32,
    pub audio_ssrc_rx: u32,
    tx_dir: u8,
    rx_dir: u8,
    pub tx_ext_seq: u64,
    audio_tx_ext_seq: u64,
    tx_twcc_seq: u16,
    pad_rng: u64,
    ts_base: u32,
    audio_ts_base: u32,
    t0: Instant,
    video_frame_open: bool,
    cur_video_ts: u64,
    last_closed_video_ts: u64,
    frame_pkt_count: u16,
    frame_pkt_budget: u16,
    last_audio_frame: u64,
    last_audio_wall_ms: u64,
    video_tx_since_rtcp: u64,
    audio_tx_since_rtcp: u64,
    rx_initialized: bool,
    pub rx_roc: u32,
    rx_highest_seq16: u16,
    rx_replay_ring: [u64; SRTP_REPLAY_RING_WORDS],
    audio_rx_initialized: bool,
    audio_rx_roc: u32,
    audio_rx_highest_seq16: u16,
    audio_rx_replay_ring: [u64; SRTP_REPLAY_RING_WORDS],
    tx_srtcp_idx: u32,
    rx_srtcp_seen: bool,
    rx_srtcp_highest: u32,
    rx_srtcp_bitmap: u64,
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

        let mut hm = Sha256::new();
        hm.update(session_key);
        hm.update(b"|mac");
        let mac_key: [u8; 32] = hm.finalize().into();

        let aes_gcm = <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(&enc_key[..16])
            .expect("16B AES-128 key");
        let chacha = <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new_from_slice(&enc_key)
            .expect("32B ChaCha20 key");
        let mut gcm_salt = [0u8; 4];
        gcm_salt.copy_from_slice(&enc_key[16..20]);

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
        let init_budget = 8 + ((r[22] as u16) % 11);
        const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut cname = [0u8; 13];
        for i in 0..13 {
            cname[i] = B64[(r[24 + i] as usize) & 63];
        }

        Self {
            suite,
            max_wire_udp: DEFAULT_WAN_MTU - 28,
            dual_ssrc: false,
            enc_key,
            mac_key,
            aes_gcm,
            chacha,
            gcm_salt,
            cname,
            ssrc_tx,
            ssrc_rx,
            audio_ssrc_tx,
            audio_ssrc_rx,
            tx_dir: if is_client { DIR_C2S } else { DIR_S2C },
            rx_dir: if is_client { DIR_S2C } else { DIR_C2S },
            tx_ext_seq: init_seq,
            audio_tx_ext_seq: audio_init_seq,
            tx_twcc_seq,
            pad_rng,
            ts_base,
            audio_ts_base,
            t0: Instant::now(),
            video_frame_open: false,
            cur_video_ts: 0,
            last_closed_video_ts: u64::MAX,
            frame_pkt_count: 0,
            frame_pkt_budget: init_budget,
            last_audio_frame: u64::MAX,
            last_audio_wall_ms: u64::MAX,
            video_tx_since_rtcp: 0,
            audio_tx_since_rtcp: 0,
            rx_initialized: false,
            rx_roc: 0,
            rx_highest_seq16: 0,
            rx_replay_ring: [0u64; SRTP_REPLAY_RING_WORDS],
            audio_rx_initialized: false,
            audio_rx_roc: 0,
            audio_rx_highest_seq16: 0,
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
    pub fn set_wan_mtu(&mut self, wan_mtu: usize) {
        self.max_wire_udp = if wan_mtu == 0 {
            0
        } else {
            wan_mtu.saturating_sub(28).max(576)
        };
    }

    #[inline]
    fn next_rng(&mut self) -> u64 {
        self.pad_rng = self.pad_rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.pad_rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
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
    fn is_srtcp_replay(&self, idx: u32) -> bool {
        if !self.rx_srtcp_seen {
            return false;
        }
        if idx > self.rx_srtcp_highest {
            return false;
        }
        let delta = self.rx_srtcp_highest - idx;
        if delta >= 64 {
            return true;
        }
        ((self.rx_srtcp_bitmap >> delta) & 1) != 0
    }

    #[inline]
    fn update_srtcp_seq(&mut self, idx: u32) {
        if !self.rx_srtcp_seen {
            self.rx_srtcp_seen = true;
            self.rx_srtcp_highest = idx;
            self.rx_srtcp_bitmap = 1;
            return;
        }
        if idx > self.rx_srtcp_highest {
            let shift = idx - self.rx_srtcp_highest;
            self.rx_srtcp_bitmap = if shift >= 64 {
                1
            } else {
                (self.rx_srtcp_bitmap << shift) | 1
            };
            self.rx_srtcp_highest = idx;
        } else {
            let delta = self.rx_srtcp_highest - idx;
            if delta < 64 {
                self.rx_srtcp_bitmap |= 1u64 << delta;
            }
        }
    }

    #[inline]
    fn gcm_nonce(&self, direction: u8, ssrc: u32, ext_seq: u64) -> [u8; 12] {
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
    fn xor_keystream(&self, direction: u8, ssrc: u32, ext_seq: u64, buf: &mut [u8]) {
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
            let mut hasher = Blake2bMac::<U64>::new_from_slice(&self.enc_key).expect("key");
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
    fn auth_tag(&self, direction: u8, aad_hdr: &[u8], ciphertext: &[u8], roc: u32) -> [u8; SRTP_TAG_LEN] {
        let mut h = Blake2bMac::<U16>::new_from_slice(&self.mac_key).expect("key");
        h.update(&[direction]);
        h.update(aad_hdr);
        h.update(ciphertext);
        h.update(&roc.to_be_bytes());
        h.finalize().into_bytes().into()
    }

    #[inline]
    fn fill_fast_random(&mut self, buf: &mut [u8]) {
        let mut i = 0usize;
        while i < buf.len() {
            let r = self.next_rng().to_ne_bytes();
            let take = (buf.len() - i).min(8);
            buf[i..i + take].copy_from_slice(&r[..take]);
            i += take;
        }
    }

    /// Build a strictly RFC 3550 §6.1 + RFC 7714 §9.1 compliant Compound SRTCP packet (V3.2):
    ///   - Plaintext primary header is ALWAYS PT=200 (SR) or PT=201 (RR) — NEVER plaintext PT=203 (BYE)!
    ///   - In dual-SSRC mode, matches active media SSRC (avoids claiming SR on an idle Video SSRC when only
    ///     Audio sent, and periodically reports on Audio SSRC as well).
    ///   - RC=0 when `has_rx_media == false` (SR len=6 / RR len=1), RC=1 when `has_rx_media == true` (SR len=12 / RR len=7).
    ///   - Encrypted compound body contains primary remainder + session-constant CNAME SDES (PT=202)
    ///     + smooth randomized FB (PT=205/206) + optional trailing BYE (PT=203) when `include_bye == true`.
    ///   - Wire layout for ALL suites: `[8B Hdr] || [Ciphertext] || [16B Tag] || [4B E_SRTCP_Index]` (0-based).
    pub fn build_srtcp(&mut self, has_rx_media: bool, is_sender: bool, include_bye: bool) -> Vec<u8> {
        let video_sent = self.video_tx_since_rtcp > 0;
        let audio_sent = self.audio_tx_since_rtcp > 0;
        self.video_tx_since_rtcp = 0;
        self.audio_tx_since_rtcp = 0;

        let (report_ssrc, effective_sender) = if !self.dual_ssrc || include_bye {
            // Single-SSRC or teardown: report on primary Video SSRC; avoid ghost SR if only Audio sent
            let eff = if self.dual_ssrc {
                is_sender && video_sent
            } else {
                is_sender
            };
            (self.ssrc_tx, eff)
        } else if audio_sent && !video_sent {
            // Pure small-packet direction (e.g. uplink QUIC ACKs): report honestly on Audio SSRC!
            (self.audio_ssrc_tx, true)
        } else if video_sent && audio_sent && (self.next_rng() & 3) == 0 {
            // Both active: ~25% of RTCP reports cover Audio SSRC, ~75% cover Video SSRC
            (self.audio_ssrc_tx, true)
        } else {
            (self.ssrc_tx, is_sender && video_sent)
        };

        let pt: u8 = if effective_sender { 200 } else { 201 };
        let rc: u8 = if has_rx_media { 1 } else { 0 };
        let primary_words: u16 = match (effective_sender, has_rx_media) {
            (true, true) => 12,   // SR + 1 Report Block (52B)
            (true, false) => 6,   // SR + 0 Report Blocks (28B)
            (false, true) => 7,   // RR + 1 Report Block (32B)
            (false, false) => 1,  // Empty RR (8B)
        };
        let primary_rem_len = ((primary_words as usize) - 1) * 4;

        let idx = self.tx_srtcp_idx & 0x7FFF_FFFF;
        self.tx_srtcp_idx = self.tx_srtcp_idx.saturating_add(1).min(0x7FFF_FFFF);
        let e_idx = 0x8000_0000u32 | idx;

        let mut hdr = [0u8; 8];
        hdr[0] = 0x80 | rc;
        hdr[1] = pt;
        hdr[2..4].copy_from_slice(&primary_words.to_be_bytes());
        hdr[4..8].copy_from_slice(&report_ssrc.to_be_bytes());

        // Assemble authentic encrypted compound RTCP body:
        let mut body = Vec::with_capacity(primary_rem_len + 96);
        if primary_rem_len > 0 {
            let start = body.len();
            body.resize(start + primary_rem_len, 0);
            self.fill_fast_random(&mut body[start..]);
        }

        // Subpacket 2: strictly RFC 3550 §6.5 compliant SDES (PT=202) with session-constant CNAME + 0x00 END
        // Layout: [4B hdr] [4B SSRC] [1B type=1] [1B len=13] [13B ASCII CNAME] [1B END=0x00] = 24B (6 words -> len=5)
        let sdes_len_words: u16 = 5;
        body.extend_from_slice(&[0x81, 202]);
        body.extend_from_slice(&sdes_len_words.to_be_bytes());
        body.extend_from_slice(&report_ssrc.to_be_bytes());
        body.push(1); // CNAME item type
        body.push(13);
        body.extend_from_slice(&self.cname);
        body.push(0); // RFC 3550 §6.5 END item (32-bit aligned at 24B)

        // Optional Subpacket 3: Transport-CC (205) / PSFB (206) smooth randomized length (~87.5% when not BYE)
        if !include_bye && (self.next_rng() & 7) != 0 {
            let fb_pt: u8 = if (self.next_rng() & 1) == 0 { 205 } else { 206 };
            let fb_words: u16 = 2 + ((self.next_rng() as u16) % 11); // 12..52B
            body.extend_from_slice(&[0x8F, fb_pt]);
            body.extend_from_slice(&fb_words.to_be_bytes());
            let fb_body_len = (fb_words as usize) * 4;
            let s = body.len();
            body.resize(s + fb_body_len, 0);
            self.fill_fast_random(&mut body[s..]);
        }

        // Final Subpacket (if tearing down): RFC 3550 §6.1 BYE (PT=203) MUST be last & encrypted!
        if include_bye {
            body.extend_from_slice(&[0x81, 203, 0x00, 0x01]);
            body.extend_from_slice(&report_ssrc.to_be_bytes());
        }

        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&hdr);
        aad[8..12].copy_from_slice(&e_idx.to_be_bytes());

        let tag_bytes: [u8; 16] = match self.suite {
            CipherSuite::Aes128Gcm => {
                let iv = self.gcm_nonce(self.tx_dir | 0x80, report_ssrc, idx as u64);
                let tag = self
                    .aes_gcm
                    .encrypt_in_place_detached(GcmNonce::from_slice(&iv), &aad, &mut body)
                    .expect("SRTCP AES-GCM encrypt");
                tag.into()
            }
            CipherSuite::ChaCha20Poly1305 => {
                let iv = self.gcm_nonce(self.tx_dir | 0x80, report_ssrc, idx as u64);
                let tag = self
                    .chacha
                    .encrypt_in_place_detached(ChaNonce::from_slice(&iv), &aad, &mut body)
                    .expect("SRTCP ChaCha20 encrypt");
                tag.into()
            }
            CipherSuite::Blake2b => {
                self.xor_keystream(self.tx_dir | 0x80, report_ssrc, idx as u64, &mut body);
                self.auth_tag(self.tx_dir | 0x80, &aad, &body, idx)
            }
        };

        let mut pkt = Vec::with_capacity(8 + body.len() + SRTP_TAG_LEN + 4);
        pkt.extend_from_slice(&hdr);
        pkt.extend_from_slice(&body);
        pkt.extend_from_slice(&tag_bytes);
        pkt.extend_from_slice(&e_idx.to_be_bytes());
        pkt
    }

    /// Verify an incoming RFC 7714 §9.1 Compound SRTCP packet (with 64-pkt sliding anti-replay).
    /// Accepts Video SSRC (`ssrc_rx`) and, in dual-SSRC mode, Audio SSRC (`audio_ssrc_rx`).
    /// Returns `Some(has_encrypted_bye)` on success, `None` on failure.
    pub fn verify_srtcp(&mut self, packet: &[u8]) -> Option<bool> {
        if packet.len() < 8 + SRTP_TAG_LEN + 4 {
            return None;
        }
        // RFC 3550 §6.1: plaintext first subpacket MUST be SR (200) or RR (201)
        if (packet[0] & 0xC0) != 0x80 || (packet[1] != 200 && packet[1] != 201) {
            return None;
        }
        let primary_words = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if primary_words == 0 {
            return None;
        }
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        if ssrc != self.ssrc_rx && !(self.dual_ssrc && ssrc == self.audio_ssrc_rx) {
            return None;
        }

        let idx_pos = packet.len() - 4;
        let tag_pos = idx_pos - SRTP_TAG_LEN;
        let e_idx = u32::from_be_bytes([
            packet[idx_pos],
            packet[idx_pos + 1],
            packet[idx_pos + 2],
            packet[idx_pos + 3],
        ]);
        if (e_idx & 0x8000_0000) == 0 {
            return None;
        }
        let idx = e_idx & 0x7FFF_FFFF;
        if self.is_srtcp_replay(idx) {
            return None;
        }

        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&packet[..8]);
        aad[8..12].copy_from_slice(&packet[idx_pos..]);
        let mut plain = packet[8..tag_pos].to_vec();

        let ok = match self.suite {
            CipherSuite::Aes128Gcm => {
                let iv = self.gcm_nonce(self.rx_dir | 0x80, ssrc, idx as u64);
                self.aes_gcm
                    .decrypt_in_place_detached(
                        GcmNonce::from_slice(&iv),
                        &aad,
                        &mut plain,
                        GcmTag::from_slice(&packet[tag_pos..idx_pos]),
                    )
                    .is_ok()
            }
            CipherSuite::ChaCha20Poly1305 => {
                let iv = self.gcm_nonce(self.rx_dir | 0x80, ssrc, idx as u64);
                self.chacha
                    .decrypt_in_place_detached(
                        ChaNonce::from_slice(&iv),
                        &aad,
                        &mut plain,
                        ChaTag::from_slice(&packet[tag_pos..idx_pos]),
                    )
                    .is_ok()
            }
            CipherSuite::Blake2b => {
                let expected = self.auth_tag(self.rx_dir | 0x80, &aad, &plain, idx);
                if bool::from(packet[tag_pos..idx_pos].ct_eq(&expected[..])) {
                    self.xor_keystream(self.rx_dir | 0x80, ssrc, idx as u64, &mut plain);
                    true
                } else {
                    false
                }
            }
        };
        if !ok {
            return None;
        }

        self.update_srtcp_seq(idx);

        // Walk decrypted compound RTCP subpackets after primary packet to detect authenticated BYE (PT=203)
        let mut pos = (primary_words - 1) * 4;
        let mut has_bye = false;
        while pos + 4 <= plain.len() {
            if (plain[pos] & 0xC0) != 0x80 {
                break;
            }
            let sub_pt = plain[pos + 1];
            let sub_words = u16::from_be_bytes([plain[pos + 2], plain[pos + 3]]) as usize;
            let sub_len = (sub_words + 1) * 4;
            if pos + sub_len > plain.len() {
                break;
            }
            if sub_pt == 203 {
                has_bye = true;
            }
            pos += sub_len;
        }
        Some(has_bye)
    }

    /// Zero-allocation wrap into caller-provided `out` buffer; returns `Some(written_len)`.
    /// Wire format (RFC 3550 + RFC 8285 + RFC 7714 — fixes V3-H-03, V3-M-02, V3-L-03):
    ///   [12B RTP Header: 0x90 (V=2, P=0, X=1, CC=0), M | PT=96, pure wall-clock 90kHz TS]
    ///   [ 8B RFC 8285 0xBEDE One-Byte Extension (transport-wide-cc seq)]
    ///   [AEAD Ciphertext of: [inner_len: u16 BE] || [plaintext] || [0..=31B random pad]]
    ///   [16B AEAD / MAC Tag]
    #[inline]
    pub fn wrap_into(&mut self, plaintext: &[u8], out: &mut [u8]) -> Option<usize> {
        self.wrap_inner(false, plaintext, out)
    }

    /// Wrap an in-band AEAD-encrypted diagnostic probe (`0xFFFE || probe_len || payload || random pad`).
    /// Identical Chrome `0x90` SRTP format on the wire; strictly disjoint from real UDP (`<= 65400`).
    #[inline]
    pub fn wrap_probe_into(&mut self, payload: &[u8], out: &mut [u8]) -> Option<usize> {
        if payload.len() > 1460 {
            return None;
        }
        self.wrap_inner(true, payload, out)
    }

    #[inline]
    fn wrap_inner(&mut self, is_probe: bool, plaintext: &[u8], out: &mut [u8]) -> Option<usize> {
        let prefix_len = if is_probe { 4 } else { 2 };
        let fixed_overhead = RTP_FULL_HDR_LEN + prefix_len + SRTP_TAG_LEN;
        let base_total = fixed_overhead.saturating_add(plaintext.len());
        if plaintext.len() > MAX_INNER_UDP_LEN
            || base_total > out.len()
            || base_total > 65_507
            || (self.max_wire_udp > 0 && base_total > self.max_wire_udp)
        {
            return None; // Prevents IPv4 fragmentation & guides inner QUIC DPLPMTUD cleanly
        }
        let headroom = if self.max_wire_udp > 0 {
            self.max_wire_udp - base_total
        } else {
            31
        };
        let eff_len = plaintext.len() + if is_probe { 2 } else { 0 };
        let max_pad = if eff_len >= 1340 {
            headroom.min(7)
        } else {
            headroom.min(31)
        };
        let rnd = self.next_rng();
        let pad_len: usize = if max_pad == 0 {
            0
        } else {
            (rnd as usize) % (max_pad + 1)
        };
        let ct_len = prefix_len + plaintext.len() + pad_len;
        let total = RTP_FULL_HDR_LEN + ct_len + SRTP_TAG_LEN;
        if total > out.len() || total > 65_507 {
            return None;
        }

        if self.tx_ext_seq >= MAX_SRTP_EXT_SEQ || self.audio_tx_ext_seq >= MAX_SRTP_EXT_SEQ {
            return None; // Never wrap 48-bit SRTP sequence (RFC 3711 / RFC 7714)
        }

        let elapsed = self.t0.elapsed();
        let wall_ms = elapsed.as_millis() as u64;
        let audio_frame = wall_ms / 20;
        // Jittered audio/video split threshold (180..=307B) + strict RFC 7587 <=50pps Opus cap
        // (max 1 PT=111 packet per 20ms frame; bursty QUIC ACKs cleanly spill onto PT=96 Video).
        // Applies uniformly to Data and 0xFFFE Probe frames for zero selftest fingerprint delta.
        let audio_thresh = 180 + (((rnd >> 24) as usize) & 0x7F);
        let use_audio = self.dual_ssrc
            && plaintext.len() < audio_thresh
            && audio_frame != self.last_audio_frame;
        let (ext_seq, active_ssrc, pt, ts, marker, tx_domain_dir) = if use_audio {
            let es = self.audio_tx_ext_seq;
            self.audio_tx_ext_seq += 1;
            self.audio_tx_since_rtcp += 1;
            self.last_audio_frame = audio_frame;
            // RFC 7587 Opus 48,000 Hz clock quantized to 20ms frames (960 ticks/frame); M=1 on talkspurt start
            let a_ts = self.audio_ts_base.wrapping_add((audio_frame.wrapping_mul(960)) as u32);
            let m: u8 = if self.last_audio_wall_ms == u64::MAX
                || wall_ms.saturating_sub(self.last_audio_wall_ms) >= 200
            {
                0x80
            } else {
                0x00
            };
            self.last_audio_wall_ms = wall_ms;
            // Orthogonal AEAD Nonce domain (`dir | 0x40`) + high-16-bit disjoint Audio SSRC
            (es, self.audio_ssrc_tx, RTP_AUDIO_PT, a_ts, m, self.tx_dir | 0x40)
        } else {
            let es = self.tx_ext_seq;
            self.tx_ext_seq += 1;
            self.video_tx_since_rtcp += 1;
            // Exact 90,000 Hz wall-clock video framing with STRICT RFC 3550 M=1 causality:
            // once a packet emits M=1 for timestamp T, NO subsequent packet EVER reuses T!
            let wall_90k: u64 = ((elapsed.as_nanos() * 90) / 1_000_000) as u64;
            let (frame_ts, m): (u64, u8) = if !self.video_frame_open {
                let start_ts = if self.last_closed_video_ts == u64::MAX {
                    wall_90k
                } else {
                    wall_90k.max(self.last_closed_video_ts.wrapping_add(1))
                };
                // Sparse small packet after >=28ms gap -> clean single-packet frame (M=1 & close)
                let sparse_gap = self.last_closed_video_ts == u64::MAX
                    || start_ts.saturating_sub(self.last_closed_video_ts) >= 2500;
                if plaintext.len() < 1100 && sparse_gap {
                    self.last_closed_video_ts = start_ts;
                    self.frame_pkt_count = 0;
                    (start_ts, 0x80)
                } else {
                    self.video_frame_open = true;
                    self.cur_video_ts = start_ts;
                    self.frame_pkt_count = 1;
                    self.frame_pkt_budget = 8 + (((rnd >> 8) as u16) % 11); // 8..=18 pkts
                    (start_ts, 0x00)
                }
            } else {
                let age_90k = wall_90k.saturating_sub(self.cur_video_ts);
                if age_90k >= 6000 {
                    // Long idle gap (>66ms): abandon old open frame cleanly & start fresh at wall_90k
                    let start_ts = wall_90k.max(self.cur_video_ts.wrapping_add(1));
                    if plaintext.len() < 1100 {
                        self.video_frame_open = false;
                        self.last_closed_video_ts = start_ts;
                        self.frame_pkt_count = 0;
                        (start_ts, 0x80)
                    } else {
                        self.cur_video_ts = start_ts;
                        self.frame_pkt_count = 1;
                        self.frame_pkt_budget = 8 + (((rnd >> 8) as u16) % 11);
                        (start_ts, 0x00)
                    }
                } else if age_90k >= 2900
                    || (age_90k >= 1500
                        && (plaintext.len() < 1100
                            || self.frame_pkt_count >= self.frame_pkt_budget))
                {
                    // Close current frame with M=1 as its FINAL packet; next packet MUST advance TS!
                    let close_ts = self.cur_video_ts;
                    self.video_frame_open = false;
                    self.last_closed_video_ts = close_ts;
                    self.frame_pkt_count = 0;
                    (close_ts, 0x80)
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

        // 12B standard Chrome RTP header: 0x90 (V=2, P=0, X=1, CC=0)
        out[0] = 0x90;
        out[1] = marker | pt;
        out[2..4].copy_from_slice(&seq16.to_be_bytes());
        out[4..8].copy_from_slice(&ts.to_be_bytes());
        out[8..12].copy_from_slice(&active_ssrc.to_be_bytes());

        // 8B RFC 8285 One-Byte Extension Header (0xBEDE, len=1 word, ID=3 L=1 transport-wide-cc)
        out[12] = 0xBE;
        out[13] = 0xDE;
        out[14] = 0x00;
        out[15] = 0x01;
        out[16] = 0x31;
        out[17..19].copy_from_slice(&twcc.to_be_bytes());
        out[19] = 0x00;

        // Inner encrypted payload:
        //   Data : [inner_len: u16 BE] || [plaintext] || [random pad]
        //   Probe: [0xFFFE: u16 BE] || [probe_len: u16 BE] || [payload] || [random pad]
        let ct_end = RTP_FULL_HDR_LEN + ct_len;
        if is_probe {
            out[RTP_FULL_HDR_LEN..RTP_FULL_HDR_LEN + 2]
                .copy_from_slice(&SRTP_PROBE_MAGIC_LEN.to_be_bytes());
            out[RTP_FULL_HDR_LEN + 2..RTP_FULL_HDR_LEN + 4]
                .copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
        } else {
            out[RTP_FULL_HDR_LEN..RTP_FULL_HDR_LEN + 2]
                .copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
        }
        out[RTP_FULL_HDR_LEN + prefix_len..RTP_FULL_HDR_LEN + prefix_len + plaintext.len()]
            .copy_from_slice(plaintext);
        if pad_len > 0 {
            let p_start = RTP_FULL_HDR_LEN + prefix_len + plaintext.len();
            let mut st = rnd ^ 0xA076_1D64_78BD_642F;
            for b in &mut out[p_start..ct_end] {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (st >> 56) as u8;
            }
        }

        let mut aad = [0u8; RTP_FULL_HDR_LEN + 4];
        aad[..RTP_FULL_HDR_LEN].copy_from_slice(&out[..RTP_FULL_HDR_LEN]);
        aad[RTP_FULL_HDR_LEN..RTP_FULL_HDR_LEN + 4].copy_from_slice(&roc.to_be_bytes());

        match self.suite {
            CipherSuite::Aes128Gcm => {
                let iv = self.gcm_nonce(tx_domain_dir, active_ssrc, ext_seq);
                let tag = self
                    .aes_gcm
                    .encrypt_in_place_detached(
                        GcmNonce::from_slice(&iv),
                        &aad,
                        &mut out[RTP_FULL_HDR_LEN..ct_end],
                    )
                    .expect("AES-GCM encrypt");
                out[ct_end..total].copy_from_slice(&tag);
            }
            CipherSuite::ChaCha20Poly1305 => {
                let iv = self.gcm_nonce(tx_domain_dir, active_ssrc, ext_seq);
                let tag = self
                    .chacha
                    .encrypt_in_place_detached(
                        ChaNonce::from_slice(&iv),
                        &aad,
                        &mut out[RTP_FULL_HDR_LEN..ct_end],
                    )
                    .expect("ChaCha20-Poly1305 encrypt");
                out[ct_end..total].copy_from_slice(&tag);
            }
            CipherSuite::Blake2b => {
                self.xor_keystream(tx_domain_dir, active_ssrc, ext_seq, &mut out[RTP_FULL_HDR_LEN..ct_end]);
                let tag = self.auth_tag(
                    tx_domain_dir,
                    &out[..RTP_FULL_HDR_LEN],
                    &out[RTP_FULL_HDR_LEN..ct_end],
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
        if packet.len() < RTP_FIXED_HDR_LEN + 2 + SRTP_TAG_LEN {
            return None;
        }
        let b0 = packet[0];
        if (b0 & 0xC0) != 0x80 {
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
        if packet.len() < hdr_len + 2 + SRTP_TAG_LEN || hdr_len > 64 {
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
            (self.audio_rx_initialized, self.audio_rx_roc, self.audio_rx_highest_seq16)
        } else {
            (self.rx_initialized, self.rx_roc, self.rx_highest_seq16)
        };

        let mut candidates = [0u32; 3];
        let mut n_cand = 0usize;
        if rx_init {
            if seq16 < 0x4000 && rx_highest > 0xC000 {
                candidates[n_cand] = rx_roc.wrapping_add(1);
                n_cand += 1;
                candidates[n_cand] = rx_roc;
                n_cand += 1;
            } else if seq16 > 0xC000 && rx_highest < 0x4000 && rx_roc > 0 {
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

        let rx_domain_dir = if is_audio { self.rx_dir | 0x40 } else { self.rx_dir };

        let decrypted = match self.suite {
            CipherSuite::Aes128Gcm => {
                let got_tag = GcmTag::from_slice(&packet[packet.len() - SRTP_TAG_LEN..]);
                let mut aad = [0u8; 68];
                aad[..hdr_len].copy_from_slice(rtp_hdr);
                let mut ok = false;
                for &cand in &candidates[..n_cand] {
                    let ext_seq = ((cand as u64) << 16) | (seq16 as u64);
                    if is_replay_cand(self, ext_seq) {
                        continue;
                    }
                    let iv = self.gcm_nonce(rx_domain_dir, ssrc, ext_seq);
                    aad[hdr_len..hdr_len + 4].copy_from_slice(&cand.to_be_bytes());
                    out[..ct_len].copy_from_slice(ciphertext);
                    if self
                        .aes_gcm
                        .decrypt_in_place_detached(
                            GcmNonce::from_slice(&iv),
                            &aad[..hdr_len + 4],
                            &mut out[..ct_len],
                            got_tag,
                        )
                        .is_ok()
                    {
                        self.update_rx_seq_stream(is_audio, cand, seq16);
                        ok = true;
                        break;
                    }
                }
                ok
            }
            CipherSuite::ChaCha20Poly1305 => {
                let got_tag = ChaTag::from_slice(&packet[packet.len() - SRTP_TAG_LEN..]);
                let mut aad = [0u8; 68];
                aad[..hdr_len].copy_from_slice(rtp_hdr);
                let mut ok = false;
                for &cand in &candidates[..n_cand] {
                    let ext_seq = ((cand as u64) << 16) | (seq16 as u64);
                    if is_replay_cand(self, ext_seq) {
                        continue;
                    }
                    let iv = self.gcm_nonce(rx_domain_dir, ssrc, ext_seq);
                    aad[hdr_len..hdr_len + 4].copy_from_slice(&cand.to_be_bytes());
                    out[..ct_len].copy_from_slice(ciphertext);
                    if self
                        .chacha
                        .decrypt_in_place_detached(
                            ChaNonce::from_slice(&iv),
                            &aad[..hdr_len + 4],
                            &mut out[..ct_len],
                            got_tag,
                        )
                        .is_ok()
                    {
                        self.update_rx_seq_stream(is_audio, cand, seq16);
                        ok = true;
                        break;
                    }
                }
                ok
            }
            CipherSuite::Blake2b => {
                let got_tag = &packet[packet.len() - SRTP_TAG_LEN..];
                let mut matched_roc = None;
                for &cand in &candidates[..n_cand] {
                    let ext_seq = ((cand as u64) << 16) | (seq16 as u64);
                    if is_replay_cand(self, ext_seq) {
                        continue;
                    }
                    let expected = self.auth_tag(rx_domain_dir, rtp_hdr, ciphertext, cand);
                    if bool::from(got_tag.ct_eq(&expected[..])) {
                        matched_roc = Some(cand);
                        break;
                    }
                }
                if let Some(roc) = matched_roc {
                    let ext_seq = ((roc as u64) << 16) | (seq16 as u64);
                    self.update_rx_seq_stream(is_audio, roc, seq16);
                    out[..ct_len].copy_from_slice(ciphertext);
                    self.xor_keystream(rx_domain_dir, ssrc, ext_seq, &mut out[..ct_len]);
                    true
                } else {
                    false
                }
            }
        };

        if !decrypted {
            return None;
        }
        let raw_len = u16::from_be_bytes([out[0], out[1]]);
        if raw_len == SRTP_PROBE_MAGIC_LEN {
            if ct_len < 4 {
                return None;
            }
            let probe_len = u16::from_be_bytes([out[2], out[3]]) as usize;
            if probe_len > 1460 || 4 + probe_len > ct_len {
                return None;
            }
            out.copy_within(4..4 + probe_len, 0);
            return Some(SrtpFrame::Probe(probe_len));
        }
        let inner_len = raw_len as usize;
        if inner_len > MAX_INNER_UDP_LEN || 2 + inner_len > ct_len {
            return None;
        }
        out.copy_within(2..2 + inner_len, 0);
        Some(SrtpFrame::Data(inner_len))
    }

    #[inline]
    fn update_rx_seq_stream(&mut self, is_audio: bool, roc: u32, seq16: u16) {
        let (rx_initialized, rx_roc, rx_highest_seq16, rx_replay_ring) = if is_audio {
            (
                &mut self.audio_rx_initialized,
                &mut self.audio_rx_roc,
                &mut self.audio_rx_highest_seq16,
                &mut self.audio_rx_replay_ring,
            )
        } else {
            (
                &mut self.rx_initialized,
                &mut self.rx_roc,
                &mut self.rx_highest_seq16,
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
            *rx_replay_ring = [0u64; SRTP_REPLAY_RING_WORDS];
            rx_replay_ring[(new_block as usize) & ring_mask] = bit_mask;
            return;
        }
        let highest = ((*rx_roc as u64) << 16) | (*rx_highest_seq16 as u64);
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
        } else if highest - ext_seq < SRTP_REPLAY_WINDOW {
            rx_replay_ring[(new_block as usize) & ring_mask] |= bit_mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dimpl::{Dtls, Output};

    #[test]
    fn v31_full_security_and_protocol_invariants() {
        let psk = b"v31-unit-test-shared-secret-2026";
        let ice = SessionIceParams::generate();
        let (req, txid) = build_ice_stun_request(psk, &ice, None, true);
        let parsed = parse_stun(&req, psk).unwrap();
        assert!(parsed.authenticated);

        // V3-H-02 regression test: trailing ATTR_USERNAME injected AFTER MESSAGE-INTEGRITY MUST be rejected!
        let mut injected = req[..req.len() - 8].to_vec(); // strip old FINGERPRINT
        push_stun_attr(&mut injected, ATTR_USERNAME, b"evil:user");
        let new_len = (injected.len() - 20 + 8) as u16;
        injected[2..4].copy_from_slice(&new_len.to_be_bytes());
        let crc = crc32fast::hash(&injected) ^ STUN_FINGERPRINT_XOR;
        push_stun_attr(&mut injected, ATTR_FINGERPRINT, &crc.to_be_bytes());
        assert!(parse_stun(&injected, psk).is_none(), "Trailing attribute injection MUST fail!");

        // V3-H-01 regression test: malformed DTLS datagrams & Epoch=0 Alerts MUST fail pre-validation!
        assert!(!validate_dtls_datagram(b"\x16\x00\x00", false));
        assert!(!validate_dtls_datagram(b"\x20\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00", false));
        assert!(!validate_dtls_datagram(b"\x15\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02\x28", false)); // Epoch=0 Alert
        assert!(!validate_dtls_datagram(b"\x15\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00", true)); // NEW-L-01: <18B Epoch=1 Alert rejected
        assert!(validate_dtls_datagram(&[0x15, 0xfe, 0xfd, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x00, 0x12, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], true)); // >=18B Epoch=1 Alert allowed
        assert!(!validate_dtls_datagram(b"\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00", true)); // Epoch=0 blocked in Ready

        // V3-H-05: Even ChaCha20-preferred ClientHello advertises all 3 suites!
        let fake_no_aes = CpuAccelInfo {
            arch: "mips",
            features: vec![],
            has_hw_aes_gcm: false,
            recommended: CipherSuite::ChaCha20Poly1305,
        };
        let cli_cfg = build_dimpl_config(CipherPref::Auto, &fake_no_aes, true);
        let srv_cfg = build_dimpl_config(CipherPref::Auto, &detect_cpu_accel(), false);
        assert_eq!(cli_cfg.dtls12_cipher_suites().count(), 3);
        let now = Instant::now();
        let mut cli_dtls = Dtls::new_12(cli_cfg, generate_ephemeral_webrtc_cert(), now);
        cli_dtls.set_active(true);
        cli_dtls.handle_timeout(now).unwrap();
        let mut srv_dtls = Dtls::new_12(srv_cfg, generate_ephemeral_webrtc_cert(), now);
        srv_dtls.handle_timeout(now).unwrap();

        let mut buf = vec![0u8; 4096];
        let mut sh_cs = None;
        let mut cli_km = None;
        let mut srv_km = None;
        for _ in 0..20 {
            let mut c2s = Vec::new();
            loop {
                match cli_dtls.poll_output(&mut buf) {
                    Output::Packet(p) => c2s.push(p.to_vec()),
                    Output::BufferTooSmall { needed } => buf.resize(needed, 0),
                    Output::KeyingMaterial(km, _) => cli_km = Some(km.to_vec()),
                    Output::Timeout(_) => break,
                    _ => {}
                }
            }
            for p in c2s { srv_dtls.handle_packet(&p).unwrap(); }
            let mut s2c = Vec::new();
            loop {
                match srv_dtls.poll_output(&mut buf) {
                    Output::Packet(p) => {
                        if let Some(cs) = extract_dtls_server_hello_suite(p) { sh_cs = Some(cs); }
                        s2c.push(p.to_vec());
                    }
                    Output::BufferTooSmall { needed } => buf.resize(needed, 0),
                    Output::KeyingMaterial(km, _) => srv_km = Some(km.to_vec()),
                    Output::Timeout(_) => break,
                    _ => {}
                }
            }
            for p in s2c { cli_dtls.handle_packet(&p).unwrap(); }
            if cli_km.is_some() && srv_km.is_some() { break; }
        }
        assert_eq!(sh_cs, Some(0xCCA9), "3-suite ChaCha20-first ClientHello should negotiate 0xCCA9!");
        assert_eq!(cli_km, srv_km);

        // V3-H-03, V3-H-04, V3-M-02, V3-L-03 checks across all 3 suites
        let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, &ice.username());
        let skey = combine_session_key(&stun_key, cli_km.as_deref());
        for suite in [CipherSuite::Aes128Gcm, CipherSuite::ChaCha20Poly1305, CipherSuite::Blake2b] {
            let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
            let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);

            // V3-H-04: Plaintext SRTCP primary is ALWAYS 200/201, RC=0 on zero rx media, BYE is encrypted!
            let rtcp_zero = cli.build_srtcp(false, false, false);
            assert_eq!(rtcp_zero[0], 0x80); // RC=0!
            assert_eq!(rtcp_zero[1], 201);
            assert_eq!(srv.verify_srtcp(&rtcp_zero), Some(false));
            assert_eq!(srv.verify_srtcp(&rtcp_zero), None); // replay blocked!

            // Out-of-order SRTCP works via 64-bit sliding window (V3-L-03)
            let rtcp_a = cli.build_srtcp(true, true, false);
            let rtcp_bye = cli.build_srtcp(true, true, true);
            assert_eq!(rtcp_bye[0], 0x81);
            assert_eq!(rtcp_bye[1], 200); // Plaintext is STILL SR(200), NEVER 203!
            assert_eq!(srv.verify_srtcp(&rtcp_bye), Some(true)); // Encrypted BYE detected!
            assert_eq!(srv.verify_srtcp(&rtcp_a), Some(false));  // Earlier out-of-order SRTCP still accepted!
            assert_eq!(srv.verify_srtcp(&rtcp_a), None);         // Duplicate still blocked!

            // V3-H-03: Standard 0x90 header, oversized UDP (>MAX_INNER_UDP_LEN) returns None cleanly (no panic!)
            let mut wbuf = vec![0u8; 65536 + 128];
            let mut rbuf = vec![0u8; 65536 + 128];
            let huge = vec![0x42u8; 65_500];
            assert!(cli.wrap_into(&huge, &mut wbuf).is_none());

            // v0.3.3: Default 1488B WAN MTU caps wire UDP <= 1460B (1422B plain fits; 1452B QUIC probe dropped)
            let wg_1420 = vec![0x55u8; 1420];
            let wn_wg = cli.wrap_into(&wg_1420, &mut wbuf).unwrap();
            assert!(wn_wg <= DEFAULT_WAN_MTU - 28, "wire UDP {} exceeded PPPoE-safe ceiling!", wn_wg);
            let rn_wg = srv.unwrap_into(&wbuf[..wn_wg], &mut rbuf).unwrap();
            assert_eq!(rn_wg, 1420);
            let quic_probe_1452 = vec![0x66u8; 1452];
            assert!(cli.wrap_into(&quic_probe_1452, &mut wbuf).is_none(), "1452B probe MUST be dropped before IPv4 frag!");

            // V3-M-02: Burst of 20 small packets in <1ms -> same wall-clock TS, ONLY 1 packet has M=1!
            let mut marked_cnt = 0;
            let mut ts_set = std::collections::HashSet::new();
            for _ in 0..20 {
                let p = vec![0xABu8; 148];
                let wn = cli.wrap_into(&p, &mut wbuf).unwrap();
                assert_eq!(wbuf[0], 0x90); // V=2, P=0, X=1
                if (wbuf[1] & 0x80) != 0 { marked_cnt += 1; }
                ts_set.insert(u32::from_be_bytes([wbuf[4], wbuf[5], wbuf[6], wbuf[7]]));
                let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
                assert_eq!(&rbuf[..rn], &p[..]);
            }
            assert!(marked_cnt <= ts_set.len(), "At most 1 M=1 per wall-clock frame!");

            // v0.3.2: RFC 6479 2048-packet anti-replay window handles deep trans-Pacific ECMP reordering
            if suite == CipherSuite::Aes128Gcm {
                let mut pkts: Vec<Vec<u8>> = Vec::with_capacity(2060);
                for idx in 0..2060u32 {
                    let payload = idx.to_be_bytes();
                    let wn = cli.wrap_into(&payload, &mut wbuf).unwrap();
                    pkts.push(wbuf[..wn].to_vec());
                }
                // Receive the newest packet first (index 2059)
                let rn = srv.unwrap_into(&pkts[2059], &mut rbuf).unwrap();
                assert_eq!(&rbuf[..rn], &2059u32.to_be_bytes());
                // Duplicate of newest MUST fail
                assert!(srv.unwrap_into(&pkts[2059], &mut rbuf).is_none());
                // 500 packets behind (previously dropped by 64-bit window!) MUST succeed
                let rn500 = srv.unwrap_into(&pkts[1559], &mut rbuf).unwrap();
                assert_eq!(&rbuf[..rn500], &1559u32.to_be_bytes());
                assert!(srv.unwrap_into(&pkts[1559], &mut rbuf).is_none()); // duplicate blocked
                // Exact window edge (2047 behind -> idx 12) MUST succeed
                let rn_edge = srv.unwrap_into(&pkts[12], &mut rbuf).unwrap();
                assert_eq!(&rbuf[..rn_edge], &12u32.to_be_bytes());
                assert!(srv.unwrap_into(&pkts[12], &mut rbuf).is_none());
                // Just outside window (2048 behind -> idx 11) MUST be rejected!
                assert!(srv.unwrap_into(&pkts[11], &mut rbuf).is_none());
            }
        }
    }

    #[test]
    fn srtp_inband_probe_roundtrip_and_zero_collision() {
        let psk = b"probe-echo-unit-test-psk";
        let txid = make_fresh_stun_txid(psk);
        let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, "prb1:prb2");
        let skey = combine_session_key(&stun_key, None);
        for suite in [
            CipherSuite::Aes128Gcm,
            CipherSuite::ChaCha20Poly1305,
            CipherSuite::Blake2b,
        ] {
            let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
            let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);
            cli.set_wan_mtu(DEFAULT_WAN_MTU);
            srv.set_wan_mtu(DEFAULT_WAN_MTU);

            let mut wbuf = [0u8; 2048];
            let mut rbuf = [0u8; 2048];

            // Probe packet round-trip must be recognized as Probe, NOT Data
            let probe = b"PING_INBAND_PROBE_123456";
            let wn = cli.wrap_probe_into(probe, &mut wbuf).unwrap();
            assert_eq!(wbuf[0], 0x90);
            assert!(wn <= DEFAULT_WAN_MTU - 28);
            assert_eq!(srv.unwrap_into_ex(&wbuf[..wn], &mut rbuf), Some(SrtpFrame::Probe(probe.len())));
            assert_eq!(&rbuf[..probe.len()], probe);

            // Normal data packet must NEVER be mistaken for Probe, even if payload starts with 0xFF 0xFE
            let tricky_data = [0xFFu8, 0xFE, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
            let wn2 = cli.wrap_into(&tricky_data, &mut wbuf).unwrap();
            assert_eq!(srv.unwrap_into_ex(&wbuf[..wn2], &mut rbuf), Some(SrtpFrame::Data(tricky_data.len())));
            assert_eq!(&rbuf[..tricky_data.len()], &tricky_data);

            // Exact MTU edge: 1420B probe payload + 40B fixed = 1460B UDP (= 1488B IPv4) passes; 1421B drops
            let max_probe = vec![0x5Au8; 1420];
            assert!(cli.wrap_probe_into(&max_probe, &mut wbuf).is_some());
            let over_probe = vec![0x5Au8; 1421];
            assert!(cli.wrap_probe_into(&over_probe, &mut wbuf).is_none());
        }
    }

    #[test]
    fn dtls13_auto_and_dtls12_fallback_interop() {
        use dimpl::ProtocolVersion;
        let cpu = detect_cpu_accel();
        let cli_cfg = build_dimpl_config(CipherPref::Auto, &cpu, true);
        let srv_cfg = build_dimpl_config(CipherPref::Auto, &cpu, false);
        let now = Instant::now();

        let drive = |mut cli: Dtls, mut srv: Dtls| -> (Option<ProtocolVersion>, Option<ProtocolVersion>, Vec<u8>, Vec<u8>) {
            cli.set_active(true);
            let _ = cli.handle_timeout(now);
            let _ = srv.handle_timeout(now);
            let mut cbuf = vec![0u8; 4096];
            let mut sbuf = vec![0u8; 4096];
            let mut c_km = Vec::new();
            let mut s_km = Vec::new();
            let mut c_ok = false;
            let mut s_ok = false;
            for _ in 0..16 {
                let mut c_pkts = Vec::new();
                loop {
                    match cli.poll_output(&mut cbuf) {
                        Output::Packet(p) => {
                            assert!(validate_dtls_datagram(p, false), "client DTLS datagram must pass validator");
                            c_pkts.push(p.to_vec());
                        }
                        Output::KeyingMaterial(km, _) => c_km = km.to_vec(),
                        Output::Connected => c_ok = true,
                        Output::Timeout(_) => break,
                        _ => {}
                    }
                }
                for p in c_pkts {
                    srv.handle_packet(&p).unwrap();
                }
                let mut s_pkts = Vec::new();
                loop {
                    match srv.poll_output(&mut sbuf) {
                        Output::Packet(p) => {
                            assert!(validate_dtls_datagram(p, false), "server DTLS datagram must pass validator");
                            s_pkts.push(p.to_vec());
                        }
                        Output::KeyingMaterial(km, _) => s_km = km.to_vec(),
                        Output::Connected => s_ok = true,
                        Output::Timeout(_) => break,
                        _ => {}
                    }
                }
                for p in s_pkts {
                    cli.handle_packet(&p).unwrap();
                }
                if c_ok && s_ok {
                    break;
                }
            }
            assert!(c_ok && s_ok, "DTLS handshake should complete");
            assert_eq!(c_km, s_km, "Exported SRTP KeyingMaterial must match");
            assert!(!c_km.is_empty());
            (cli.protocol_version(), srv.protocol_version(), c_km, s_km)
        };

        // 1. Auto <-> Auto MUST negotiate DTLS 1.3
        let (cv1, sv1, _, _) = drive(
            Dtls::new_auto(Arc::clone(&cli_cfg), generate_ephemeral_webrtc_cert(), now),
            Dtls::new_auto(Arc::clone(&srv_cfg), generate_ephemeral_webrtc_cert(), now),
        );
        assert_eq!(cv1, Some(ProtocolVersion::DTLS1_3));
        assert_eq!(sv1, Some(ProtocolVersion::DTLS1_3));

        // 2. Auto client <-> legacy DTLS 1.2 server MUST seamlessly fall back to DTLS 1.2
        let (cv2, sv2, _, _) = drive(
            Dtls::new_auto(Arc::clone(&cli_cfg), generate_ephemeral_webrtc_cert(), now),
            Dtls::new_12(Arc::clone(&srv_cfg), generate_ephemeral_webrtc_cert(), now),
        );
        assert_eq!(cv2, Some(ProtocolVersion::DTLS1_2));
        assert_eq!(sv2, Some(ProtocolVersion::DTLS1_2));

        // 3. Legacy DTLS 1.2 client <-> Auto server MUST seamlessly fall back to DTLS 1.2
        let (cv3, sv3, _, _) = drive(
            Dtls::new_12(Arc::clone(&cli_cfg), generate_ephemeral_webrtc_cert(), now),
            Dtls::new_auto(Arc::clone(&srv_cfg), generate_ephemeral_webrtc_cert(), now),
        );
        assert_eq!(cv3, Some(ProtocolVersion::DTLS1_2));
        assert_eq!(sv3, Some(ProtocolVersion::DTLS1_2));
    }

    #[test]
    fn dual_ssrc_audio_video_split_and_replay_isolation() {
        let psk = b"dual-ssrc-test-psk-2026";
        let txid = make_fresh_stun_txid(psk);
        let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, "av01:av02");
        let skey = combine_session_key(&stun_key, None);
        for suite in [
            CipherSuite::Aes128Gcm,
            CipherSuite::ChaCha20Poly1305,
            CipherSuite::Blake2b,
        ] {
            let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
            let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);
            cli.set_dual_ssrc(true);
            srv.set_dual_ssrc(true);
            assert_ne!(cli.ssrc_tx, cli.audio_ssrc_tx);
            assert_eq!(cli.audio_ssrc_tx, srv.audio_ssrc_rx);

            let mut wbuf = [0u8; 2048];
            let mut rbuf = [0u8; 2048];

            // Small ACK packet (< 256B) -> Audio SSRC + PT=111 (Opus)
            let small = vec![0x11u8; 64];
            let wn_a = cli.wrap_into(&small, &mut wbuf).unwrap();
            assert_eq!(wbuf[1] & 0x7F, RTP_AUDIO_PT);
            assert_eq!(u32::from_be_bytes([wbuf[8], wbuf[9], wbuf[10], wbuf[11]]), cli.audio_ssrc_tx);
            let twcc1 = u16::from_be_bytes([wbuf[17], wbuf[18]]);
            let rn_a = srv.unwrap_into(&wbuf[..wn_a], &mut rbuf).unwrap();
            assert_eq!(&rbuf[..rn_a], &small[..]);
            // Replay of Audio packet MUST be blocked independently
            assert!(srv.unwrap_into(&wbuf[..wn_a], &mut rbuf).is_none());

            // Large data packet (>= 256B) -> Video SSRC + PT=96, global TWCC increments by +1
            let large = vec![0x22u8; 1200];
            let wn_v = cli.wrap_into(&large, &mut wbuf).unwrap();
            assert_eq!(wbuf[1] & 0x7F, RTP_VIDEO_PT);
            assert_eq!(u32::from_be_bytes([wbuf[8], wbuf[9], wbuf[10], wbuf[11]]), cli.ssrc_tx);
            let twcc2 = u16::from_be_bytes([wbuf[17], wbuf[18]]);
            assert_eq!(twcc2, twcc1.wrapping_add(1));
            let rn_v = srv.unwrap_into(&wbuf[..wn_v], &mut rbuf).unwrap();
            assert_eq!(&rbuf[..rn_v], &large[..]);
            // Replay of Video packet MUST be blocked independently
            assert!(srv.unwrap_into(&wbuf[..wn_v], &mut rbuf).is_none());

            // High-16-bit SSRC disjointness across full 2^48 Nonce space (P0-5 / M-02)
            assert_ne!(cli.ssrc_tx >> 16, cli.audio_ssrc_tx >> 16);
            assert_ne!(cli.ssrc_rx >> 16, cli.audio_ssrc_rx >> 16);
        }
    }

    #[test]
    fn v32_hardening_invariants_crypto_dpi_and_anti_downgrade() {
        // 1. derive_audio_ssrc high-16-bit disjointness even for adversarial edge SSRCs
        let key = [0x42u8; 32];
        for v_ssrc in [0u32, 1, 0x5A3C_A5C3, 0xFFFF_FFFF, 0x1357_9BDF, 0x1234_5678] {
            let a_ssrc = derive_audio_ssrc(&key, v_ssrc);
            assert_ne!(a_ssrc, 0);
            assert_ne!(a_ssrc >> 16, v_ssrc >> 16, "high 16 bits MUST be disjoint for Nonce orthogonality");
        }

        // 2. validate_dtls_datagram rejects plaintext ct=26 in Ready and epoch>=1 (P0-4 / M-01)
        let mut fake_ack = [0u8; 32];
        fake_ack[0] = 26; // plaintext ACK
        fake_ack[1] = 0xFE;
        fake_ack[2] = 0xFD;
        fake_ack[12] = 19; // rec_len = 19
        assert!(validate_dtls_datagram(&fake_ack, false)); // epoch=0 allowed during handshake
        assert!(!validate_dtls_datagram(&fake_ack, true)); // MUST be rejected in Ready!
        fake_ack[4] = 1; // epoch=1 plaintext ct=26 -> rejected always!
        assert!(!validate_dtls_datagram(&fake_ack, false));

        // 3. extract_dtls_server_hello_suite rejects malformed extensions_len (P0-2 / M-03)
        let mut bad_sh = vec![0u8; 13 + 54];
        bad_sh[0] = 0x16;
        bad_sh[1] = 0xFE;
        bad_sh[2] = 0xFD;
        bad_sh[11..13].copy_from_slice(&54u16.to_be_bytes());
        let hs = &mut bad_sh[13..];
        hs[0] = 0x02; // ServerHello
        hs[1..4].copy_from_slice(&[0, 0, 42]); // msg_len = 42
        hs[9..12].copy_from_slice(&[0, 0, 42]); // frag_len = 42
        hs[12] = 0xFE;
        hs[13] = 0xFD;
        hs[46] = 0; // sid_len = 0
        hs[47..49].copy_from_slice(&0x1303u16.to_be_bytes());
        hs[49] = 0; // compression = 0
        hs[50..52].copy_from_slice(&0xFFFFu16.to_be_bytes()); // MALFORMED extensions_len!
        assert_eq!(extract_dtls_server_hello_suite(&bad_sh), None);
        // Valid 2-byte extensions (len=2) succeeds:
        bad_sh[13 + 50..13 + 52].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(extract_dtls_server_hello_suite(&bad_sh), Some(0x1303));

        // 4. Multi-MTU DtlsConfigPool respects --mtu clamping (P1-2 / L-03)
        let cpu = detect_cpu_accel();
        let pool_default = build_dimpl_config_pool(CipherPref::Auto, &cpu, true, DEFAULT_WAN_MTU);
        assert_eq!(pool_default.mtus().len(), 8);
        let pool_small = build_dimpl_config_pool(CipherPref::Auto, &cpu, true, 1000);
        assert!(pool_small.mtus().iter().all(|&m| m <= 972));

        // 5. Strict DTLS 1.3 mode (DtlsMinVersion::V13Only) negotiates DTLS 1.3 cleanly
        let now = Instant::now();
        let cli_cfg = pool_default.pick();
        let srv_cfg = build_dimpl_config_pool(CipherPref::Auto, &cpu, false, DEFAULT_WAN_MTU).pick();
        let mut c13 = new_dtls_instance(DtlsMinVersion::V13Only, cli_cfg, generate_ephemeral_webrtc_cert(), now);
        let mut s13 = new_dtls_instance(DtlsMinVersion::V13Only, srv_cfg, generate_ephemeral_webrtc_cert(), now);
        c13.set_active(true);
        let _ = c13.handle_timeout(now);
        let _ = s13.handle_timeout(now);
        let mut buf = vec![0u8; 4096];
        let (mut c_ok, mut s_ok) = (false, false);
        for _ in 0..12 {
            let mut cp = Vec::new();
            loop {
                match c13.poll_output(&mut buf) {
                    Output::Packet(p) => cp.push(p.to_vec()),
                    Output::Connected => c_ok = true,
                    Output::Timeout(_) => break,
                    _ => {}
                }
            }
            for p in cp { s13.handle_packet(&p).unwrap(); }
            let mut sp = Vec::new();
            loop {
                match s13.poll_output(&mut buf) {
                    Output::Packet(p) => sp.push(p.to_vec()),
                    Output::Connected => s_ok = true,
                    Output::Timeout(_) => break,
                    _ => {}
                }
            }
            for p in sp { c13.handle_packet(&p).unwrap(); }
            if c_ok && s_ok { break; }
        }
        assert!(c_ok && s_ok);
        assert_eq!(c13.protocol_version(), Some(dimpl::ProtocolVersion::DTLS1_3));
        assert_eq!(s13.protocol_version(), Some(dimpl::ProtocolVersion::DTLS1_3));

        // 6. Opus <=50pps cap (max 1 PT=111 per 20ms frame) + strict Video M=1 causality + Audio SRTCP!
        let mut cli = SrtpCloakCipher::new(&key, 0x1122_3344, 0x5566_7788, true, CipherSuite::Aes128Gcm);
        let mut srv = SrtpCloakCipher::new(&key, 0x5566_7788, 0x1122_3344, false, CipherSuite::Aes128Gcm);
        cli.set_dual_ssrc(true);
        srv.set_dual_ssrc(true);

        let mut wbuf = [0u8; 2048];
        let mut rbuf = [0u8; 2048];
        let mut audio_cnt = 0usize;
        let mut video_cnt = 0usize;
        let mut prev_marked_video_ts: Option<u32> = None;
        for _ in 0..20 {
            let small = [0x77u8; 80];
            let wn = cli.wrap_into(&small, &mut wbuf).unwrap();
            let pt = wbuf[1] & 0x7F;
            let m = (wbuf[1] & 0x80) != 0;
            let ts = u32::from_be_bytes([wbuf[4], wbuf[5], wbuf[6], wbuf[7]]);
            if pt == RTP_AUDIO_PT {
                audio_cnt += 1;
            } else {
                assert_eq!(pt, RTP_VIDEO_PT);
                video_cnt += 1;
                if let Some(closed_ts) = prev_marked_video_ts {
                    assert_ne!(ts, closed_ts, "Video packet after M=1 MUST NEVER reuse closed timestamp!");
                }
                if m {
                    prev_marked_video_ts = Some(ts);
                }
            }
            assert_eq!(srv.unwrap_into(&wbuf[..wn], &mut rbuf), Some(80));
        }
        assert!(audio_cnt >= 1 && audio_cnt <= 2, "Opus cap MUST limit burst to <=1 pkt/20ms (got {})", audio_cnt);
        assert!(video_cnt >= 18, "Overflow small ACKs MUST spill onto Video SSRC (got {})", video_cnt);

        // 7. Audio-only SRTCP reports on Audio SSRC with 0-based index & verifies cleanly on peer
        let mut cli2 = SrtpCloakCipher::new(&key, 0x1122_3344, 0x5566_7788, true, CipherSuite::Aes128Gcm);
        let mut srv2 = SrtpCloakCipher::new(&key, 0x5566_7788, 0x1122_3344, false, CipherSuite::Aes128Gcm);
        cli2.set_dual_ssrc(true);
        srv2.set_dual_ssrc(true);
        let wn = cli2.wrap_into(&[0x33u8; 64], &mut wbuf).unwrap();
        assert_eq!(wbuf[1] & 0x7F, RTP_AUDIO_PT);
        assert_eq!(srv2.unwrap_into(&wbuf[..wn], &mut rbuf), Some(64));
        let rtcp = cli2.build_srtcp(false, true, false);
        assert_eq!(rtcp[1], 200); // SR on Audio SSRC!
        assert_eq!(u32::from_be_bytes([rtcp[4], rtcp[5], rtcp[6], rtcp[7]]), cli2.audio_ssrc_tx);
        assert_eq!(&rtcp[rtcp.len() - 4..], &0x8000_0000u32.to_be_bytes()); // 0-based SRTCP index!
        assert_eq!(srv2.verify_srtcp(&rtcp), Some(false));
        assert_eq!(srv2.verify_srtcp(&rtcp), None); // replay blocked!
    }
}
