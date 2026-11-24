//! 协议公共类型、常量、CPU 加速探测、RFC 7983 解复用与随机定时工具。

mod dtls;
mod srtcp;
mod srtp;
mod stun;
#[cfg(test)]
mod tests;

pub use dtls::{
    build_dimpl_config_pool, extract_dtls_server_hello_suite, generate_ephemeral_webrtc_cert,
    new_dtls_instance, resolve_srtp_suite, validate_dtls_datagram, CertCache, DtlsConfigPool,
};
pub use srtp::{combine_session_key, derive_stun_material, SrtpCloakCipher};
pub use stun::{
    build_ice_stun_request, build_ice_stun_request_with_key, build_stun_success_response,
    build_stun_success_response_with_key, compute_handover_proof, derive_ice_migration_key,
    make_fresh_stun_txid, parse_stun, parse_stun_with_key, peek_stun_request_username,
    stun_hmac_key, SessionIceParams,
};

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SHUTDOWN_WAKERS: OnceLock<Mutex<Vec<Arc<mio::Waker>>>> = OnceLock::new();

/// Register a worker `mio::Waker` to be notified immediately upon `SIGTERM`/`SIGINT`.
pub fn register_shutdown_waker(waker: Arc<mio::Waker>) {
    let lock = SHUTDOWN_WAKERS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut guard) = lock.lock() {
        guard.push(waker);
    }
}

/// Wake all registered production workers immediately so graceful shutdown needs zero poll lag.
pub fn trigger_shutdown_wakers() {
    if let Some(lock) = SHUTDOWN_WAKERS.get() {
        if let Ok(guard) = lock.lock() {
            for w in guard.iter() {
                let _ = w.wake();
            }
        }
    }
}

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_SUCCESS: u16 = 0x0101;
pub const STUN_MAX_SKEW_SECS: i64 = 30;

pub const RTP_FIXED_HDR_LEN: usize = 12;
pub const RTP_EXT_LEN: usize = 8; // 4B 0xBEDE header + 4B one-byte transport-wide-cc extension
pub const RTP_FULL_HDR_LEN: usize = RTP_FIXED_HDR_LEN + RTP_EXT_LEN; // 20B
pub const SRTP_TAG_LEN: usize = 16; // Unified 16B tag across AES-GCM, ChaCha20, and BLAKE2b-128
pub const MAX_INNER_UDP_LEN: usize = 65_400; // Hard bound preventing wbuf[65664] overflow
pub const SRTP_PROBE_MAGIC_LEN: u16 = 0xFFFE; // Reserved > MAX_INNER_UDP_LEN for in-band encrypted selftest echo
pub const SRTP_PATH_CHALLENGE_MAGIC: u16 = 0xFFFD; // V4: in-band encrypted 1-RTT ICE migration challenge/response/confirm
pub const SRTP_HANDOVER_MAGIC: u16 = 0xFFFC; // V4: in-band encrypted MBB backend_sock atomic handover request/ack
pub const RTP_VIDEO_PT: u8 = 96;
pub const RTP_AUDIO_PT: u8 = 111; // Chrome Opus dynamic PT (48 kHz)

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpFrame {
    Data(usize),
    Probe(usize),
    /// V4 in-band encrypted path reachability challenge / response / confirm (`0xFFFD`)
    PathChallenge(usize),
    /// V4 in-band encrypted MBB `backend_sock` atomic handover request / ack (`0xFFFC`)
    Handover(usize),
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

/// Smooth right-skewed log-normal multiplier via Irwin-Hall (sum of 6 uniforms -> Z ~ N(0, 1)).
/// Breaks rectangular `[0.8R, 1.2R]` box-edge fingerprints on long-running session lifetimes.
fn lognormal_factor(sigma: f64, min_factor: f64, max_factor: f64) -> f64 {
    let mut raw = [0u8; 24];
    fill_random(&mut raw);
    let mut sum6 = 0.0f64;
    for chunk in raw.chunks_exact(4) {
        let u = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as f64
            / (u32::MAX as f64 + 1.0);
        sum6 += u;
    }
    // Mean of 6 U(0,1) is 3.0, variance is 6/12 = 0.5 -> std = 1/sqrt(2)
    let z = (sum6 - 3.0) * std::f64::consts::SQRT_2;
    (sigma * z).exp().clamp(min_factor, max_factor)
}

/// Log-normal wide-distribution duration around `median_ms` (spanning `[0.35x, 2.80x]`, heavy right tail).
pub fn lognormal_duration_ms(median_ms: u64) -> Duration {
    if median_ms == 0 {
        return Duration::from_millis(0);
    }
    let f = lognormal_factor(0.45, 0.35, 2.80);
    let ms = ((median_ms as f64) * f).round().max(1.0) as u64;
    Duration::from_millis(ms)
}

/// Log-normal randomized byte budget around `base_bytes` (spanning `[0.50x, 1.85x]`).
/// For default `1200 MiB`, produces smooth natural per-session budgets in `600 MiB .. 2220 MiB`.
pub fn rand_byte_budget(base_bytes: u64) -> u64 {
    if base_bytes == 0 {
        return 0;
    }
    let f = lognormal_factor(0.35, 0.50, 1.85);
    ((base_bytes as f64) * f).round().max(1.0) as u64
}

/// O(1), zero-allocation two-bucket sliding byte window (Cloudflare weighted moving window).
/// Accurately tracks rolling byte volume over `window` without bucket-boundary cliffs.
#[derive(Clone, Copy)]
pub struct RollingByteWindow {
    window: Duration,
    bucket_start: Instant,
    prev_bytes: u64,
    cur_bytes: u64,
}

impl RollingByteWindow {
    pub fn new(now: Instant, window: Duration) -> Self {
        Self {
            window: window.max(Duration::from_millis(1)),
            bucket_start: now,
            prev_bytes: 0,
            cur_bytes: 0,
        }
    }

    #[inline]
    fn advance(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.bucket_start);
        if elapsed >= self.window.saturating_mul(2) {
            self.prev_bytes = 0;
            self.cur_bytes = 0;
            self.bucket_start = now;
        } else if elapsed >= self.window {
            self.prev_bytes = self.cur_bytes;
            self.cur_bytes = 0;
            self.bucket_start += self.window;
        }
    }

    #[inline]
    pub fn record(&mut self, now: Instant, bytes: u64) {
        self.advance(now);
        self.cur_bytes = self.cur_bytes.saturating_add(bytes);
    }

    #[inline]
    pub fn bytes_in_window(&mut self, now: Instant) -> u64 {
        self.advance(now);
        let elapsed = now.saturating_duration_since(self.bucket_start);
        let rem_frac =
            1.0 - (elapsed.as_secs_f64() / self.window.as_secs_f64()).clamp(0.0, 1.0);
        let weighted_prev = ((self.prev_bytes as f64) * rem_frac) as u64;
        weighted_prev.saturating_add(self.cur_bytes)
    }
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


/// Default outer IPv4 WAN MTU ceiling (1488B < 1492B PPPoE -> max outer UDP payload 1460B).
/// Eliminates IPv4 UDP fragmentation on PPPoE/CGNAT links and forces inner QUIC DPLPMTUD
/// (e.g. Hysteria 2 over 127.0.0.1) to converge cleanly without fragmented packets.
pub const DEFAULT_WAN_MTU: usize = 1488;

