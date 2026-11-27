//! 协议公共类型、常量、CPU 加速探测、RFC 7983 解复用与随机定时工具。

mod dtls;
mod srtcp;
mod srtp;
mod stun;
#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use dtls::build_dimpl_config_pool;
pub use dtls::{
    build_dimpl_config_pool_for, extract_dtls_server_hello_suite, generate_ephemeral_webrtc_cert,
    new_dtls_instance, resolve_srtp_suite, validate_dtls_datagram, CertCache, DtlsConfigPool,
};
pub use srtp::{combine_session_key, derive_stun_material, SrtpCloakCipher};
#[cfg(test)]
pub use stun::build_stun_success_response;
pub use stun::{
    build_bypass_stun_request, build_ice_stun_request, build_ice_stun_request_with_key,
    build_stun_success_response_with_key, compute_handover_proof, derive_ice_migration_key,
    derive_stun_scope_key, derive_stun_scope_key_for, make_fresh_stun_txid, parse_stun,
    parse_stun_with_key, peek_stun_request_username, set_global_stun_scope, stun_hmac_key,
    SessionIceParams,
};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(not(unix))]
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// RFC 7983 首字节 `0..=3` 归类为 STUN 报文。
const DEMUX_STUN_MAX: u8 = 3;
/// RFC 7983 首字节 `20..=63` 归类为 DTLS 1.2/1.3 报文（下界）。
const DEMUX_DTLS_MIN: u8 = 20;
/// RFC 7983 首字节 `20..=63` 归类为 DTLS 1.2/1.3 报文（上界）。
const DEMUX_DTLS_MAX: u8 = 63;
/// RFC 7983 首字节 `128..=191` 归类为 RTP/RTCP 报文（下界）。
const DEMUX_RTP_MIN: u8 = 128;
/// RFC 7983 首字节 `128..=191` 归类为 RTP/RTCP 报文（上界）。
const DEMUX_RTP_MAX: u8 = 191;
/// RFC 5761 次字节 `192..=223` 归类为 SRTCP 报文（下界）。
const DEMUX_RTCP_PT_MIN: u8 = 192;
/// RFC 5761 次字节 `192..=223` 归类为 SRTCP 报文（上界）。
const DEMUX_RTCP_PT_MAX: u8 = 223;
/// 对数正态时长分布标准差参数（打破矩形抖动边界指纹）。
const LOGNORMAL_DUR_SIGMA: f64 = 0.45;
/// 对数正态时长分布最小倍率下限（0.35x）。
const LOGNORMAL_DUR_MIN: f64 = 0.35;
/// 对数正态时长分布最大倍率上限（2.80x）。
const LOGNORMAL_DUR_MAX: f64 = 2.80;
/// 对数正态字节预算分布标准差参数。
const LOGNORMAL_BUDGET_SIGMA: f64 = 0.35;
/// 对数正态字节预算分布最小倍率下限（0.50x）。
const LOGNORMAL_BUDGET_MIN: f64 = 0.50;
/// 对数正态字节预算分布最大倍率上限（1.85x）。
const LOGNORMAL_BUDGET_MAX: f64 = 1.85;
/// 标准 64 字符 Base64 字母表，用于生成无模偏差的 ICE ufrag 与 RTCP CNAME。
pub(super) const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// RTP/RTCP 首字节版本号掩码（高 2 位）。
pub(super) const RTP_V2_MASK: u8 = 0xC0;
/// RTP/RTCP 版本 2 对应位值（`10xxxxxx`）。
pub(super) const RTP_V2_BITS: u8 = 0x80;
/// RTCP 明文主报头长度（字节）。
pub(super) const RTCP_HDR_LEN: usize = 8;
/// SDES CNAME 固定 ASCII 长度（13 字节，使 SDES 子包精确对齐 24B）。
pub(super) const RTCP_CNAME_LEN: usize = 13;

#[cfg(unix)]
mod unix_signal {
    use super::*;
    use std::sync::atomic::AtomicI32;

    static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);
    static PIPE_READ_FD: AtomicI32 = AtomicI32::new(-1);
    static PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
        SIGNAL_STOP.store(true, Ordering::SeqCst);
        let fd = PIPE_WRITE_FD.load(Ordering::Acquire);
        if fd >= 0 {
            let b = 1u8;
            // SAFETY: `libc::write` is async-signal-safe per POSIX.1-2008; non-blocking fd avoids blocking.
            unsafe {
                let _ = libc::write(fd, (&b as *const u8).cast::<libc::c_void>(), 1);
            }
        }
    }

    fn set_nonblock_cloexec(fd: libc::c_int) {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
            let fl = libc::fcntl(fd, libc::F_GETFL);
            if fl >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
    }

    pub(super) fn install() {
        if PIPE_WRITE_FD.load(Ordering::Acquire) < 0 {
            let mut fds = [-1 as libc::c_int; 2];
            // SAFETY: valid 2-element array passed to POSIX `pipe`.
            if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
                set_nonblock_cloexec(fds[0]);
                set_nonblock_cloexec(fds[1]);
                PIPE_READ_FD.store(fds[0], Ordering::Release);
                PIPE_WRITE_FD.store(fds[1], Ordering::Release);
            }
        }
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handle_shutdown_signal as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = libc::SA_RESTART;
            let _ = libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
            let _ = libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        }
    }

    #[inline]
    pub(super) fn read_fd() -> Option<libc::c_int> {
        let fd = PIPE_READ_FD.load(Ordering::Acquire);
        if fd >= 0 {
            Some(fd)
        } else {
            None
        }
    }

    #[inline]
    pub(super) fn received() -> bool {
        SIGNAL_STOP.load(Ordering::Relaxed)
    }
}

#[cfg(not(unix))]
static SHUTDOWN_WAKERS: OnceLock<Mutex<Vec<Arc<mio::Waker>>>> = OnceLock::new();

/// Install OS `SIGINT`/`SIGTERM` handler for graceful shutdown.
/// On Unix, uses async-signal-safe `sigaction` + self-pipe (zero extra signal thread!).
pub fn install_shutdown_handler() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        unix_signal::install();
    }
    #[cfg(not(unix))]
    {
        let flag = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || {
            flag.store(true, Ordering::SeqCst);
            trigger_shutdown_wakers();
        });
    }
    stop
}

/// Register a worker's `mio::Poll` to wake immediately upon `SIGTERM`/`SIGINT`.
pub fn register_shutdown_poll(poll: &mio::Poll, quiet: bool, has_stop: bool) {
    if quiet || !has_stop {
        return;
    }
    #[cfg(unix)]
    {
        if let Some(rfd) = unix_signal::read_fd() {
            let mut src = mio::unix::SourceFd(&rfd);
            let _ = poll.registry().register(
                &mut src,
                crate::constants::SHUTDOWN_PIPE_TOKEN,
                mio::Interest::READABLE,
            );
        }
    }
    #[cfg(not(unix))]
    {
        if let Ok(waker) = mio::Waker::new(poll.registry(), crate::constants::WAKE_TOKEN) {
            let lock = SHUTDOWN_WAKERS.get_or_init(|| Mutex::new(Vec::new()));
            if let Ok(mut guard) = lock.lock() {
                guard.push(Arc::new(waker));
            }
        }
    }
}

/// Check whether graceful shutdown has been requested (either via test `stop` flag or OS signal).
#[inline]
pub fn is_shutdown_requested(stop: Option<&Arc<AtomicBool>>, quiet: bool) -> bool {
    if stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
        return true;
    }
    #[cfg(unix)]
    if !quiet && stop.is_some() && unix_signal::received() {
        return true;
    }
    #[cfg(not(unix))]
    let _ = quiet;
    false
}

/// Wake all registered production workers immediately (Windows `ctrlc` path).
#[cfg(not(unix))]
pub fn trigger_shutdown_wakers() {
    if let Some(lock) = SHUTDOWN_WAKERS.get() {
        if let Ok(guard) = lock.lock() {
            for w in guard.iter() {
                let _ = w.wake();
            }
        }
    }
}

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
    /// Reverse tunnel multiplexed L4 UDP payload (`0xFFFB || len(2B) || flow_id(4B) || payload`)
    ReverseData {
        flow_id: u32,
        len: usize,
    },
    /// Reverse tunnel in-band control frame (`0xFFFA || len(2B) || ctrl_payload`)
    ReverseCtrl(usize),
}

impl SrtpFrame {
    #[inline]
    pub const fn payload_len(self) -> usize {
        match self {
            SrtpFrame::Data(n)
            | SrtpFrame::Probe(n)
            | SrtpFrame::PathChallenge(n)
            | SrtpFrame::Handover(n)
            | SrtpFrame::ReverseData { len: n, .. }
            | SrtpFrame::ReverseCtrl(n) => n,
        }
    }
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

/// Runtime CPU hardware acceleration probe (uses std::arch::is_*_feature_detected!
/// cross-checked against actual compiled crate backends so silent fallbacks never hide).
#[derive(Debug, Clone)]
pub struct CpuAccelInfo {
    pub arch: &'static str,
    pub features: Vec<&'static str>,
    pub has_hw_aes_gcm: bool,
    pub aes_backend: &'static str,
    pub gcm_polyval_backend: &'static str,
    pub chacha20_backend: &'static str,
    pub poly1305_backend: &'static str,
    pub recommended: CipherSuite,
}

pub fn detect_cpu_accel() -> CpuAccelInfo {
    #[allow(unused_mut)]
    let mut features = Vec::new();
    let aes_backend: &'static str;
    let chacha20_backend: &'static str;

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if std::arch::is_x86_feature_detected!("sse2") {
            features.push("SSE2");
        }
        if std::arch::is_x86_feature_detected!("ssse3") {
            features.push("SSSE3");
        }
        if std::arch::is_x86_feature_detected!("sse4.2") {
            features.push("SSE4.2(CRC32)");
        }
        if std::arch::is_x86_feature_detected!("aes") {
            features.push("AES-NI");
        }
        if std::arch::is_x86_feature_detected!("pclmulqdq") {
            features.push("PCLMULQDQ(GCM)");
        }
        if std::arch::is_x86_feature_detected!("sha") {
            features.push("SHA-NI");
        }
        if std::arch::is_x86_feature_detected!("avx") {
            features.push("AVX");
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            features.push("AVX2");
        }
        if std::arch::is_x86_feature_detected!("avx512f") {
            features.push("AVX-512F");
        }
        if std::arch::is_x86_feature_detected!("vaes") {
            features.push("VAES");
        }
        if std::arch::is_x86_feature_detected!("vpclmulqdq") {
            features.push("VPCLMULQDQ");
        }
        aes_backend = if !aes::hardware_accelerated() {
            "soft"
        } else if std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("vaes")
        {
            "x86-vaes512"
        } else if std::arch::is_x86_feature_detected!("vaes") {
            "x86-vaes256"
        } else {
            "x86-aesni"
        };
        chacha20_backend = if cfg!(chacha20_avx512)
            && std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512vl")
        {
            "x86-avx512"
        } else if std::arch::is_x86_feature_detected!("avx2") {
            "x86-avx2"
        } else if std::arch::is_x86_feature_detected!("sse2") {
            "x86-sse2"
        } else {
            "soft"
        };
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            features.push("NEON");
        }
        if std::arch::is_aarch64_feature_detected!("aes") {
            features.push("ARMv8-AES");
        }
        if std::arch::is_aarch64_feature_detected!("pmull") {
            features.push("ARMv8-PMULL(GCM)");
        }
        if std::arch::is_aarch64_feature_detected!("sha2") {
            features.push("ARMv8-SHA2");
        }
        if std::arch::is_aarch64_feature_detected!("crc") {
            features.push("ARMv8-CRC32");
        }
        aes_backend = if aes::hardware_accelerated() {
            "armv8-aes"
        } else {
            "soft"
        };
        chacha20_backend = if cfg!(target_feature = "neon") {
            "armv8-neon"
        } else {
            "soft"
        };
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        aes_backend = "soft";
        chacha20_backend = "soft";
    }

    let gcm_polyval_backend = polyval::backend_name();
    let poly1305_backend = poly1305::backend_name();
    // Ground-truth check: require BOTH AES and POLYVAL/GHASH crate backends to actually accelerate!
    let has_hw_aes_gcm = aes::hardware_accelerated() && polyval::hardware_accelerated();

    let recommended = if has_hw_aes_gcm {
        CipherSuite::Aes128Gcm
    } else {
        CipherSuite::ChaCha20Poly1305
    };

    CpuAccelInfo {
        arch: std::env::consts::ARCH,
        features,
        has_hw_aes_gcm,
        aes_backend,
        gcm_polyval_backend,
        chacha20_backend,
        poly1305_backend,
        recommended,
    }
}

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
        Some(0..=DEMUX_STUN_MAX) => PacketKind::Stun,
        Some(DEMUX_DTLS_MIN..=DEMUX_DTLS_MAX) => PacketKind::Dtls,
        Some(DEMUX_RTP_MIN..=DEMUX_RTP_MAX) => {
            if data.len() >= RTCP_HDR_LEN
                && (DEMUX_RTCP_PT_MIN..=DEMUX_RTCP_PT_MAX).contains(&data[1])
            {
                PacketKind::Srtcp
            } else {
                PacketKind::Srtp
            }
        }
        _ => PacketKind::Unknown,
    }
}

pub fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS CSPRNG failed");
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
    for chunk in raw.as_chunks::<4>().0 {
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
    let f = lognormal_factor(LOGNORMAL_DUR_SIGMA, LOGNORMAL_DUR_MIN, LOGNORMAL_DUR_MAX);
    let ms = ((median_ms as f64) * f).round().max(1.0) as u64;
    Duration::from_millis(ms)
}

/// Log-normal randomized byte budget around `base_bytes` (spanning `[0.50x, 1.85x]`).
/// For default `1200 MiB`, produces smooth natural per-session budgets in `600 MiB .. 2220 MiB`.
pub fn rand_byte_budget(base_bytes: u64) -> u64 {
    if base_bytes == 0 {
        return 0;
    }
    let f = lognormal_factor(
        LOGNORMAL_BUDGET_SIGMA,
        LOGNORMAL_BUDGET_MIN,
        LOGNORMAL_BUDGET_MAX,
    );
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
        let rem_frac = 1.0 - (elapsed.as_secs_f64() / self.window.as_secs_f64()).clamp(0.0, 1.0);
        let weighted_prev = ((self.prev_bytes as f64) * rem_frac) as u64;
        weighted_prev.saturating_add(self.cur_bytes)
    }
}

/// Standard Chrome/Safari libwebrtc ICE ufrag: exact 4 Base64 chars (never non-browser 5/6/7 chars).
pub fn rand_ufrag_chrome() -> String {
    let mut raw = [0u8; 4];
    fill_random(&mut raw);
    raw.iter()
        .map(|&b| BASE64_ALPHABET[(b & 0x3F) as usize] as char)
        .collect()
}

pub fn unix_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}
