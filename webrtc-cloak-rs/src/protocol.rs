//! Wire-format protocol primitives for webrtc-cloak V3.1 (Production Freeze):
//!   - RFC 5389 / 8445 STUN ICE Binding Request & Success Response:
//!     * libwebrtc 4-char Base64 ufrag (zero modulo bias), libwebrtc attribute order
//!     * Session-constant ICE-CONTROLLING tie-breaker & PRIORITY; USE-CANDIDATE only on nomination
//!     * Timestamp-masked anti-replay txid (±30s window) + strict RFC 5389 §15.4 MI-then-FP parsing
//!   - Real RFC 6347 DTLS 1.2 via `dimpl` (pure-Rust Sans-IO, mutual ECDSA P-256 certs,
//!     HelloVerifyRequest cookie, 3-suite Chrome-ordered ClientHello, real ECDHE/EMS/Finished,
//!     RFC 5764/7714 KeyingMaterial export -> True PFS, real `close_notify` teardown)
//!   - RFC 3550 / 3711 / 7714 / 8285 SRTP framing:
//!     * Standard Chrome `0x90` (V=2, P=0, X=1, CC=0) + 8B RFC 8285 `0xBEDE` transport-wide-cc ext
//!     * Inner-ciphertext length prefix + randomized 0..=31B padding (breaks WG/QUIC alignment
//!       without plaintext P=1 statistical giveaway!)
//!     * Pure u64 wall-clock 90,000 Hz 30fps timestamps (zero drift, zero 13.25h wrap, <=1 M=1/frame)
//!     * 64-packet sliding anti-replay window
//!   - RFC 3550 §6.1 / 5761 / 7714 §9.1 Compound SRTCP:
//!     * Plaintext header ALWAYS PT=200(SR) or PT=201(RR), real RC=0/1 matching rx media state
//!     * Encrypted compound subpackets (SDES + optional FB + encrypted trailing BYE PT=203)
//!     * Always 16B AEAD/MAC tag + trailing 4B E_SRTCP_Index + 64-packet SRTCP sliding replay window

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce as GcmNonce, Tag as GcmTag};
use blake2::digest::consts::{U16, U64};
use blake2::{Blake2bMac, Digest as _};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce, Tag as ChaTag};
use dimpl::crypto::{rust_crypto, CryptoProvider, Dtls12CipherSuite, SupportedDtls12CipherSuite};
use dimpl::{Config as DtlsConfig, DtlsCertificate};
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
pub const RTP_VIDEO_PT: u8 = 96;

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

/// RFC 7983 §7 + RFC 5761 §4 demultiplexing (strict valid TLS ContentType 20..=23; full RTCP 192..=223).
#[inline]
pub fn demux_rfc7983(data: &[u8]) -> PacketKind {
    match data.first().copied() {
        Some(0..=3) => PacketKind::Stun,
        Some(20..=23) => PacketKind::Dtls,
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

/// Strict pre-validation of DTLS 1.2 datagrams before feeding to `dimpl` (fixes V3-H-01):
///   - Validates every packed DTLS record's ContentType (20..=23), DTLS version (0xFEFD/0xFEFF),
///     and exact record boundary lengths.
///   - Rejects unauthenticated plaintext Epoch=0 Alerts (ct=21, epoch=0) that could DoS handshakes.
///   - When `ready_only_alert == true` (established Ready session), ONLY permits encrypted
///     Epoch >= 1 Alert records (ct=21, epoch>=1), silently dropping everything else.
pub fn validate_dtls_datagram(pkt: &[u8], ready_only_alert: bool) -> bool {
    if pkt.len() < 13 {
        return false;
    }
    let mut pos = 0usize;
    let mut rec_count = 0usize;
    while pos < pkt.len() {
        if pos + 13 > pkt.len() {
            return false;
        }
        let ct = pkt[pos];
        let ver_maj = pkt[pos + 1];
        let ver_min = pkt[pos + 2];
        let epoch = u16::from_be_bytes([pkt[pos + 3], pkt[pos + 4]]);
        let rec_len = u16::from_be_bytes([pkt[pos + 11], pkt[pos + 12]]) as usize;
        if !matches!(ct, 20..=23) {
            return false;
        }
        if ver_maj != 0xFE || (ver_min != 0xFD && ver_min != 0xFF) {
            return false;
        }
        if rec_len == 0 || pos + 13 + rec_len > pkt.len() {
            return false;
        }
        // Reject unauthenticated plaintext Epoch=0 Alerts during handshake
        if ct == 21 && epoch == 0 {
            return false;
        }
        // NEW-L-01: DTLS 1.2 AEAD encrypted records (epoch >= 1) require >= 2B payload + 16B tag
        if epoch >= 1 && rec_len < 18 {
            return false;
        }
        // In established Ready state (past final-flight retransmit grace), only allow Epoch>=1 encrypted Alerts
        if ready_only_alert && (ct != 21 || epoch == 0) {
            return false;
        }
        pos += 13 + rec_len;
        rec_count += 1;
        if rec_count > 16 {
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

fn stun_hmac_key(psk: &[u8]) -> [u8; 32] {
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

/// Strict RFC 5389 §15.4 + RFC 8445 STUN parser (fixes V3-H-02 trailing-attribute injection):
///   - Rejects any attribute appearing AFTER MESSAGE-INTEGRITY except a single trailing FINGERPRINT.
///   - Mandates valid FINGERPRINT at the exact end of packet (`val_end == end`).
///   - Enforces valid `ufrag_r:ufrag_l` username format and ±30s timestamp freshness on requests.
pub fn parse_stun(data: &[u8], psk: &[u8]) -> Option<ParsedStun> {
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

    let mi_key = stun_hmac_key(psk);
    let mut pos = 20usize;
    let end = 20 + msg_len;
    let mut username: Option<String> = None;
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
                username = Some(String::from_utf8_lossy(val).into_owned());
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
                let mut mac = HmacSha1::new_from_slice(&mi_key).expect("HMAC key");
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
    if auth_ok && msg_type == STUN_BINDING_REQUEST {
        let valid_uname = username
            .as_deref()
            .map(|u| !u.is_empty() && u.len() <= 64 && u.contains(':'))
            .unwrap_or(false);
        if !valid_uname || !verify_stun_txid_fresh(psk, &txid) {
            auth_ok = false;
        }
    }

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

/// Build a `CryptoProvider` whose 3-suite DTLS 1.2 order prefers ChaCha20 first
/// while STILL advertising all 3 ECDHE-ECDSA AEAD suites (fixes V3-H-05 single-suite JA4D!).
fn chacha_first_provider() -> CryptoProvider {
    static CHACHA_FIRST_SUITES: OnceLock<&'static [&'static dyn SupportedDtls12CipherSuite]> =
        OnceLock::new();
    let mut provider = rust_crypto::default_provider();
    let suites = *CHACHA_FIRST_SUITES.get_or_init(|| {
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
    provider.cipher_suites = suites;
    provider
}

/// Build a real `dimpl` DTLS 1.2 Config with mutual client certificate authentication,
/// stateless HelloVerifyRequest cookie exchange, and FULL 3-suite ClientHello ordering.
pub fn build_dimpl_config(pref: CipherPref, cpu: &CpuAccelInfo, is_client: bool) -> Arc<DtlsConfig> {
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
        .require_client_certificate(true)
        .use_server_cookie(true)
        .flight_start_rto(Duration::from_millis(350))
        .flight_retries(5)
        .handshake_timeout(Duration::from_secs(12));

    // Client ALWAYS advertises all 3 real ECDHE-ECDSA AEAD suites (zero 1-suite JA4D leak!).
    // Server only restricts allow-list if it must force ChaCha20 when peer put AES first.
    if !is_client && want_chacha {
        builder = builder.dtls12_cipher_suites(&[
            Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
        ]);
    } else if !is_client && pref == CipherPref::Fixed(CipherSuite::Aes128Gcm) {
        builder = builder.dtls12_cipher_suites(&[
            Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
            Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
        ]);
    }

    Arc::new(builder.build().expect("dimpl Config build"))
}

/// Strictly extract negotiated 16-bit TLS cipher suite ID from an unfragmented Epoch=0 ServerHello.
pub fn extract_dtls_server_hello_suite(datagram: &[u8]) -> Option<u16> {
    let mut pos = 0usize;
    while pos + 13 <= datagram.len() {
        let ct = datagram[pos];
        if datagram[pos + 1] != 0xFE || datagram[pos + 2] != 0xFD {
            return None;
        }
        let epoch = u16::from_be_bytes([datagram[pos + 3], datagram[pos + 4]]);
        let rec_len = u16::from_be_bytes([datagram[pos + 11], datagram[pos + 12]]) as usize;
        let rec_end = pos + 13 + rec_len;
        if rec_end > datagram.len() {
            return None;
        }
        if ct == 0x16 && epoch == 0 && rec_len >= 49 {
            let hs = &datagram[pos + 13..rec_end];
            // NEW-L-01: HandshakeType=ServerHello(0x02), post-HVR message_seq==1, fragment_offset==0
            let msg_seq = u16::from_be_bytes([hs[4], hs[5]]);
            if hs[0] == 0x02 && msg_seq == 1 && hs[6] == 0 && hs[7] == 0 && hs[8] == 0 {
                let sid_len = hs[46] as usize;
                let cs_pos = 47 + sid_len;
                if cs_pos + 2 <= hs.len() {
                    return Some(u16::from_be_bytes([hs[cs_pos], hs[cs_pos + 1]]));
                }
            }
        }
        pos = rec_end;
    }
    None
}

/// Map negotiated TLS 1.2 ServerHello cipher suite + local CipherPref to SRTP CipherSuite.
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
                    Some(0xCCA9) => CipherSuite::ChaCha20Poly1305,
                    Some(0xC02B | 0xC02C) => CipherSuite::Aes128Gcm,
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

pub struct SrtpCloakCipher {
    suite: CipherSuite,
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    aes_gcm: Aes128Gcm,
    chacha: ChaCha20Poly1305,
    gcm_salt: [u8; 4],
    pub ssrc_tx: u32,
    pub ssrc_rx: u32,
    tx_dir: u8,
    rx_dir: u8,
    pub tx_ext_seq: u64,
    tx_twcc_seq: u16,
    pad_rng: u64,
    ts_base: u32,
    t0: Instant,
    last_wall_frame: u64,
    last_marked_frame: u64,
    frame_pkt_count: u16,
    rx_initialized: bool,
    pub rx_roc: u32,
    rx_highest_seq16: u16,
    rx_replay_bitmap: u64,
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

        let mut r = [0u8; 16];
        fill_random(&mut r);
        let init_seq = (u16::from_be_bytes([r[0], r[1]]) & 0x7FFF) as u64;
        let ts_base = u32::from_be_bytes([r[2], r[3], r[4], r[5]]);
        let tx_twcc_seq = u16::from_be_bytes([r[6], r[7]]) & 0x7FFF;
        let pad_rng = u64::from_ne_bytes(r[8..16].try_into().unwrap()) | 1;

        Self {
            suite,
            enc_key,
            mac_key,
            aes_gcm,
            chacha,
            gcm_salt,
            ssrc_tx,
            ssrc_rx,
            tx_dir: if is_client { DIR_C2S } else { DIR_S2C },
            rx_dir: if is_client { DIR_S2C } else { DIR_C2S },
            tx_ext_seq: init_seq,
            tx_twcc_seq,
            pad_rng,
            ts_base,
            t0: Instant::now(),
            last_wall_frame: 0,
            last_marked_frame: u64::MAX,
            frame_pkt_count: 0,
            rx_initialized: false,
            rx_roc: 0,
            rx_highest_seq16: 0,
            rx_replay_bitmap: 0,
            tx_srtcp_idx: 1,
            rx_srtcp_seen: false,
            rx_srtcp_highest: 0,
            rx_srtcp_bitmap: 0,
        }
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
    fn is_replay(&self, ext_seq: u64) -> bool {
        if !self.rx_initialized {
            return false;
        }
        let highest = ((self.rx_roc as u64) << 16) | (self.rx_highest_seq16 as u64);
        if ext_seq > highest {
            return false;
        }
        let delta = highest - ext_seq;
        if delta >= 64 {
            return true;
        }
        ((self.rx_replay_bitmap >> delta) & 1) != 0
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

    /// Build a strictly RFC 3550 §6.1 + RFC 7714 §9.1 compliant Compound SRTCP packet (fixes V3-H-04):
    ///   - Plaintext primary header is ALWAYS PT=200 (SR) or PT=201 (RR) — NEVER plaintext PT=203 (BYE)!
    ///   - RC=0 when `has_rx_media == false` (SR len=6 / RR len=1), RC=1 when `has_rx_media == true` (SR len=12 / RR len=7).
    ///   - Encrypted compound body contains primary remainder + valid SDES (PT=202) + optional FB (PT=205/206)
    ///     + optional trailing BYE (PT=203) subpacket when `include_bye == true`.
    ///   - Wire layout for ALL suites: `[8B Hdr] || [Ciphertext] || [16B Tag] || [4B E_SRTCP_Index]`.
    pub fn build_srtcp(&mut self, has_rx_media: bool, is_sender: bool, include_bye: bool) -> Vec<u8> {
        let pt: u8 = if is_sender { 200 } else { 201 };
        let rc: u8 = if has_rx_media { 1 } else { 0 };
        let primary_words: u16 = match (is_sender, has_rx_media) {
            (true, true) => 12,   // SR + 1 Report Block (52B)
            (true, false) => 6,   // SR + 0 Report Blocks (28B)
            (false, true) => 7,   // RR + 1 Report Block (32B)
            (false, false) => 1,  // Empty RR (8B)
        };
        let primary_rem_len = ((primary_words as usize) - 1) * 4;

        let idx = self.tx_srtcp_idx & 0x7FFF_FFFF;
        self.tx_srtcp_idx = self.tx_srtcp_idx.wrapping_add(1).max(1);
        let e_idx = 0x8000_0000u32 | idx;

        let mut hdr = [0u8; 8];
        hdr[0] = 0x80 | rc;
        hdr[1] = pt;
        hdr[2..4].copy_from_slice(&primary_words.to_be_bytes());
        hdr[4..8].copy_from_slice(&self.ssrc_tx.to_be_bytes());

        // Assemble authentic encrypted compound RTCP body:
        let mut body = Vec::with_capacity(primary_rem_len + 96);
        if primary_rem_len > 0 {
            let start = body.len();
            body.resize(start + primary_rem_len, 0);
            fill_random(&mut body[start..]);
        }

        // Subpacket 2: SDES (PT=202) with CNAME item (16B total = 3 words + 1)
        let sdes_len_words: u16 = 5; // 24B SDES chunk
        body.extend_from_slice(&[0x81, 202]);
        body.extend_from_slice(&sdes_len_words.to_be_bytes());
        body.extend_from_slice(&self.ssrc_tx.to_be_bytes());
        let mut cname = [0u8; 14];
        fill_random(&mut cname);
        body.push(1); // CNAME item type
        body.push(14);
        body.extend_from_slice(&cname);

        // Optional Subpacket 3: Transport-CC (205) / PSFB (206) randomized length when not BYE
        if !include_bye && (self.next_rng() & 1) == 1 {
            let fb_pt: u8 = if (self.next_rng() & 1) == 0 { 205 } else { 206 };
            let fb_words: u16 = 3 + ((self.next_rng() as u16) % 10); // 16..52B
            body.extend_from_slice(&[0x8F, fb_pt]);
            body.extend_from_slice(&fb_words.to_be_bytes());
            let fb_body_len = (fb_words as usize) * 4;
            let s = body.len();
            body.resize(s + fb_body_len, 0);
            fill_random(&mut body[s..]);
        }

        // Final Subpacket (if tearing down): RFC 3550 §6.1 BYE (PT=203) MUST be last & encrypted!
        if include_bye {
            body.extend_from_slice(&[0x81, 203, 0x00, 0x01]);
            body.extend_from_slice(&self.ssrc_tx.to_be_bytes());
        }

        let mut aad = [0u8; 12];
        aad[..8].copy_from_slice(&hdr);
        aad[8..12].copy_from_slice(&e_idx.to_be_bytes());

        let tag_bytes: [u8; 16] = match self.suite {
            CipherSuite::Aes128Gcm => {
                let iv = self.gcm_nonce(self.tx_dir | 0x80, self.ssrc_tx, idx as u64);
                let tag = self
                    .aes_gcm
                    .encrypt_in_place_detached(GcmNonce::from_slice(&iv), &aad, &mut body)
                    .expect("SRTCP AES-GCM encrypt");
                tag.into()
            }
            CipherSuite::ChaCha20Poly1305 => {
                let iv = self.gcm_nonce(self.tx_dir | 0x80, self.ssrc_tx, idx as u64);
                let tag = self
                    .chacha
                    .encrypt_in_place_detached(ChaNonce::from_slice(&iv), &aad, &mut body)
                    .expect("SRTCP ChaCha20 encrypt");
                tag.into()
            }
            CipherSuite::Blake2b => {
                self.xor_keystream(self.tx_dir | 0x80, self.ssrc_tx, idx as u64, &mut body);
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
        if ssrc != self.ssrc_rx {
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
                let iv = self.gcm_nonce(self.rx_dir | 0x80, self.ssrc_rx, idx as u64);
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
                let iv = self.gcm_nonce(self.rx_dir | 0x80, self.ssrc_rx, idx as u64);
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
                    self.xor_keystream(self.rx_dir | 0x80, self.ssrc_rx, idx as u64, &mut plain);
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
        if plaintext.len() > MAX_INNER_UDP_LEN {
            return None;
        }
        let rnd = self.next_rng();
        let pad_len: usize = if plaintext.len() >= 1340 {
            (rnd as usize) & 7 // 0..=7B near MTU (stays safely under 1472B Ethernet MTU)
        } else {
            (rnd as usize) & 31 // 0..=31B breaks WG 148B/92B/16*k & QUIC size fingerprints
        };
        let ct_len = 2 + plaintext.len() + pad_len;
        let total = RTP_FULL_HDR_LEN + ct_len + SRTP_TAG_LEN;
        if total > out.len() || total > 65_507 {
            return None;
        }

        let ext_seq = self.tx_ext_seq;
        self.tx_ext_seq = (self.tx_ext_seq + 1) & 0xFFFF_FFFF_FFFF;
        let roc = ((ext_seq >> 16) & 0xFFFF_FFFF) as u32;
        let seq16 = (ext_seq & 0xFFFF) as u16;
        let twcc = self.tx_twcc_seq;
        self.tx_twcc_seq = self.tx_twcc_seq.wrapping_add(1);

        // Pure u64 wall-clock 90,000 Hz 30fps timestamp: exact 90kHz slope at any pps, zero 13.25h wrap!
        let wall_90k: u64 = ((self.t0.elapsed().as_nanos() * 90) / 1_000_000) as u64;
        let wall_frame: u64 = wall_90k / 3000;
        if wall_frame != self.last_wall_frame {
            self.last_wall_frame = wall_frame;
            self.frame_pkt_count = 0;
        }
        let ts = self.ts_base.wrapping_add((wall_frame.wrapping_mul(3000)) as u32);

        // Emit at most ONE M=1 per wall-clock frame (never forces fake frame jumps!)
        let marker: u8 = if self.last_marked_frame != wall_frame
            && (plaintext.len() < 1100 || self.frame_pkt_count >= 12)
        {
            self.last_marked_frame = wall_frame;
            0x80
        } else {
            self.frame_pkt_count = self.frame_pkt_count.saturating_add(1);
            0x00
        };

        // 12B standard Chrome RTP header: 0x90 (V=2, P=0, X=1, CC=0)
        out[0] = 0x90;
        out[1] = marker | RTP_VIDEO_PT;
        out[2..4].copy_from_slice(&seq16.to_be_bytes());
        out[4..8].copy_from_slice(&ts.to_be_bytes());
        out[8..12].copy_from_slice(&self.ssrc_tx.to_be_bytes());

        // 8B RFC 8285 One-Byte Extension Header (0xBEDE, len=1 word, ID=3 L=1 transport-wide-cc)
        out[12] = 0xBE;
        out[13] = 0xDE;
        out[14] = 0x00;
        out[15] = 0x01;
        out[16] = 0x31;
        out[17..19].copy_from_slice(&twcc.to_be_bytes());
        out[19] = 0x00;

        // Inner encrypted payload: [inner_len: u16 BE] || [plaintext] || [random pad]
        let ct_end = RTP_FULL_HDR_LEN + ct_len;
        out[RTP_FULL_HDR_LEN..RTP_FULL_HDR_LEN + 2]
            .copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
        out[RTP_FULL_HDR_LEN + 2..RTP_FULL_HDR_LEN + 2 + plaintext.len()]
            .copy_from_slice(plaintext);
        if pad_len > 0 {
            let p_start = RTP_FULL_HDR_LEN + 2 + plaintext.len();
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
                let iv = self.gcm_nonce(self.tx_dir, self.ssrc_tx, ext_seq);
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
                let iv = self.gcm_nonce(self.tx_dir, self.ssrc_tx, ext_seq);
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
                self.xor_keystream(self.tx_dir, self.ssrc_tx, ext_seq, &mut out[RTP_FULL_HDR_LEN..ct_end]);
                let tag = self.auth_tag(
                    self.tx_dir,
                    &out[..RTP_FULL_HDR_LEN],
                    &out[RTP_FULL_HDR_LEN..ct_end],
                    roc,
                );
                out[ct_end..total].copy_from_slice(&tag);
            }
        }
        Some(total)
    }

    /// Zero-allocation unwrap into caller-provided `out` buffer; returns `Some(inner_len)`.
    #[inline]
    pub fn unwrap_into(&mut self, packet: &[u8], out: &mut [u8]) -> Option<usize> {
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
        if ssrc != self.ssrc_rx {
            return None;
        }

        let rtp_hdr = &packet[..hdr_len];
        let ct_len = packet.len() - hdr_len - SRTP_TAG_LEN;
        if ct_len > out.len() {
            return None;
        }
        let ciphertext = &packet[hdr_len..hdr_len + ct_len];

        let mut candidates = [0u32; 3];
        let mut n_cand = 0usize;
        if self.rx_initialized {
            if seq16 < 0x4000 && self.rx_highest_seq16 > 0xC000 {
                candidates[n_cand] = self.rx_roc.wrapping_add(1);
                n_cand += 1;
                candidates[n_cand] = self.rx_roc;
                n_cand += 1;
            } else if seq16 > 0xC000 && self.rx_highest_seq16 < 0x4000 && self.rx_roc > 0 {
                candidates[n_cand] = self.rx_roc - 1;
                n_cand += 1;
                candidates[n_cand] = self.rx_roc;
                n_cand += 1;
            } else {
                candidates[n_cand] = self.rx_roc;
                n_cand += 1;
                candidates[n_cand] = self.rx_roc.wrapping_add(1);
                n_cand += 1;
                if self.rx_roc > 0 {
                    candidates[n_cand] = self.rx_roc - 1;
                    n_cand += 1;
                }
            }
        } else {
            candidates[0] = self.rx_roc;
            n_cand = 1;
        }

        let decrypted = match self.suite {
            CipherSuite::Aes128Gcm => {
                let got_tag = GcmTag::from_slice(&packet[packet.len() - SRTP_TAG_LEN..]);
                let mut aad = [0u8; 68];
                aad[..hdr_len].copy_from_slice(rtp_hdr);
                let mut ok = false;
                for &cand in &candidates[..n_cand] {
                    let ext_seq = ((cand as u64) << 16) | (seq16 as u64);
                    if self.is_replay(ext_seq) {
                        continue;
                    }
                    let iv = self.gcm_nonce(self.rx_dir, self.ssrc_rx, ext_seq);
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
                        self.update_rx_seq(cand, seq16);
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
                    if self.is_replay(ext_seq) {
                        continue;
                    }
                    let iv = self.gcm_nonce(self.rx_dir, self.ssrc_rx, ext_seq);
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
                        self.update_rx_seq(cand, seq16);
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
                    if self.is_replay(ext_seq) {
                        continue;
                    }
                    let expected = self.auth_tag(self.rx_dir, rtp_hdr, ciphertext, cand);
                    if bool::from(got_tag.ct_eq(&expected[..])) {
                        matched_roc = Some(cand);
                        break;
                    }
                }
                if let Some(roc) = matched_roc {
                    let ext_seq = ((roc as u64) << 16) | (seq16 as u64);
                    self.update_rx_seq(roc, seq16);
                    out[..ct_len].copy_from_slice(ciphertext);
                    self.xor_keystream(self.rx_dir, self.ssrc_rx, ext_seq, &mut out[..ct_len]);
                    true
                } else {
                    false
                }
            }
        };

        if !decrypted {
            return None;
        }
        let inner_len = u16::from_be_bytes([out[0], out[1]]) as usize;
        if 2 + inner_len > ct_len {
            return None;
        }
        out.copy_within(2..2 + inner_len, 0);
        Some(inner_len)
    }

    #[inline]
    fn update_rx_seq(&mut self, roc: u32, seq16: u16) {
        let ext_seq = ((roc as u64) << 16) | (seq16 as u64);
        if !self.rx_initialized {
            self.rx_initialized = true;
            self.rx_roc = roc;
            self.rx_highest_seq16 = seq16;
            self.rx_replay_bitmap = 1;
            return;
        }
        let highest = ((self.rx_roc as u64) << 16) | (self.rx_highest_seq16 as u64);
        if ext_seq > highest {
            let shift = ext_seq - highest;
            self.rx_replay_bitmap = if shift >= 64 {
                1
            } else {
                (self.rx_replay_bitmap << shift) | 1
            };
            self.rx_roc = roc;
            self.rx_highest_seq16 = seq16;
        } else {
            let delta = highest - ext_seq;
            if delta < 64 {
                self.rx_replay_bitmap |= 1u64 << delta;
            }
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
        }
    }
}
