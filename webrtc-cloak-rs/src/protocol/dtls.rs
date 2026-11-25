//! DTLS 1.3/1.2 报文预校验、临时证书缓存与 dimpl 配置池。

use super::{
    fill_random, rand_duration_range_ms, rand_u32, unix_secs, CipherPref, CipherSuite,
    CpuAccelInfo, DtlsMinVersion,
};
use crate::constants::{
    DTLS_CT_HANDSHAKE, DTLS_PLAINTEXT_HDR_LEN, DTLS_VER_MAJOR, DTLS_VER_MINOR_12, IPV4_UDP_HDR_LEN,
};
use dimpl::crypto::{
    rust_crypto, CryptoProvider, Dtls12CipherSuite, Dtls13CipherSuite, SupportedDtls12CipherSuite,
    SupportedDtls13CipherSuite,
};
use dimpl::{Config as DtlsConfig, Dtls, DtlsCertificate};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// 加密 DTLS 记录最小密文长度（2B 最小内容 + 16B AEAD 标签）。
const DTLS_MIN_ENCRYPTED_RECORD_LEN: usize = 18;
/// 单个 UDP 数据报内允许拼接的最大 DTLS 记录条数，防止畸形包放大解析开销。
const DTLS_MAX_RECORDS_PER_DATAGRAM: usize = 24;
/// DTLS 记录类型：ChangeCipherSpec (20)。
const DTLS_CT_CHANGE_CIPHER_SPEC: u8 = 20;
/// DTLS 记录类型：Alert (21)。
const DTLS_CT_ALERT: u8 = 21;
/// DTLS 记录类型：ApplicationData (23)。
const DTLS_CT_APP_DATA: u8 = 23;
/// RFC 9147 DTLS 1.3 记录类型：ACK (26)。
const DTLS_CT_ACK: u8 = 26;
/// DTLS 握手消息类型：ServerHello (0x02)。
const DTLS_HS_SERVER_HELLO: u8 = 0x02;
/// DTLS 1.0 兼容记录次版本号低字节（0xFF）。
const DTLS_VER_MINOR_10: u8 = 0xFF;
/// RFC 9147 DTLS 1.3 统一密文头高 3 位掩码（`001C_SL_EE`）。
const DTLS13_UNIFIED_HDR_MASK: u8 = 0xE0;
/// RFC 9147 DTLS 1.3 统一密文头固定前缀位（`0x20`）。
const DTLS13_UNIFIED_HDR_TAG: u8 = 0x20;
/// RFC 9147 DTLS 1.3 统一密文头 Connection ID 标志位（本实现不支持 C=1）。
const DTLS13_FLAG_CID: u8 = 0x10;
/// RFC 9147 DTLS 1.3 统一密文头 16 位序列号标志位（S=1）。
const DTLS13_FLAG_SEQ16: u8 = 0x08;
/// RFC 9147 DTLS 1.3 统一密文头显式长度字段标志位（L=1）。
const DTLS13_FLAG_LEN: u8 = 0x04;
/// RFC 8446 §4.1.3 HelloRetryRequest 固定魔数 ServerRandom（不得误判为正式 ServerHello）。
const TLS13_HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];
/// TLS 1.3 密码套件 ID：`TLS_AES_128_GCM_SHA256`。
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS 1.3 密码套件 ID：`TLS_AES_256_GCM_SHA384`。
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
/// TLS 1.3 密码套件 ID：`TLS_CHACHA20_POLY1305_SHA256`。
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
/// TLS 1.2 密码套件 ID：`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`。
const TLS_ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xC02B;
/// TLS 1.2 密码套件 ID：`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`。
const TLS_ECDHE_ECDSA_AES256_GCM_SHA384: u16 = 0xC02C;
/// TLS 1.2 密码套件 ID：`TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`。
const TLS_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256: u16 = 0xCCA9;
/// 服务端及默认单实例 DTLS 分片目标 MTU（字节）。
const DTLS_DEFAULT_MTU: usize = 1150;
/// DTLS 配置允许的最大分片 MTU 上限（字节）。
const DTLS_MAX_MTU: usize = 1360;
/// DTLS 配置允许的最小分片 MTU 下限（字节）。
const DTLS_MIN_MTU: usize = 256;
/// 客户端随机选用的 DTLS MTU 候选池（字节），消除固定 1150B ClientHello 长度尖峰指纹。
const DTLS_CLIENT_MTUS: [usize; 8] = [760, 840, 920, 1000, 1080, 1150, 1240, 1340];
/// DTLS 握手首包重传超时 RTO（毫秒）。
const DTLS_FLIGHT_START_RTO_MS: u64 = 350;
/// DTLS 单个 flight 最大重传次数。
const DTLS_FLIGHT_RETRIES: usize = 5;
/// DTLS 整体握手超时时间（秒）。
const DTLS_HANDSHAKE_TIMEOUT_SECS: u64 = 12;
/// 工作线程本地临时证书缓存最小复用时长（20 小时，毫秒）。
const DTLS_CERT_CACHE_TTL_MIN_MS: u64 = 20 * 3600 * 1000;
/// 工作线程本地临时证书缓存最大复用时长（24 小时，毫秒）。
const DTLS_CERT_CACHE_TTL_MAX_MS: u64 = 24 * 3600 * 1000;
/// 自签临时证书 `notBefore` 最小回拨偏移（1 小时，秒）。
const DTLS_CERT_BACKDATE_MIN_SECS: u64 = 3600;
/// 自签临时证书 `notBefore` 随机回拨跨度（23 小时，即回拨 1..24 小时，秒）。
const DTLS_CERT_BACKDATE_SPAN_SECS: u64 = 23 * 3600;
/// 自签临时证书最短有效期（29 天，秒）。
const DTLS_CERT_VALIDITY_MIN_SECS: u64 = 29 * 86400;
/// 自签临时证书有效期随机跨度（2 天，即 29..31 天，秒）。
const DTLS_CERT_VALIDITY_SPAN_SECS: u64 = 2 * 86400;

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
        if (b0 & DTLS13_UNIFIED_HDR_MASK) == DTLS13_UNIFIED_HDR_TAG {
            // RFC 9147 §4 DTLS 1.3 Unified Ciphertext Header: 001C_SL_EE (32..=63)
            if (b0 & DTLS13_FLAG_CID) != 0 {
                return false; // Connection ID (C=1) not supported
            }
            let seq_len = if (b0 & DTLS13_FLAG_SEQ16) != 0 {
                2usize
            } else {
                1usize
            };
            let has_len = (b0 & DTLS13_FLAG_LEN) != 0;
            let hdr_len = 1 + seq_len + if has_len { 2 } else { 0 };
            if pos + hdr_len > pkt.len() {
                return false;
            }
            let rec_len = if has_len {
                u16::from_be_bytes([pkt[pos + 1 + seq_len], pkt[pos + 2 + seq_len]]) as usize
            } else {
                pkt.len() - (pos + hdr_len)
            };
            if rec_len < DTLS_MIN_ENCRYPTED_RECORD_LEN || pos + hdr_len + rec_len > pkt.len() {
                return false;
            }
            pos += hdr_len + rec_len;
        } else {
            if pos + DTLS_PLAINTEXT_HDR_LEN > pkt.len() {
                return false;
            }
            let ct = b0;
            let ver_maj = pkt[pos + 1];
            let ver_min = pkt[pos + 2];
            let epoch = u16::from_be_bytes([pkt[pos + 3], pkt[pos + 4]]);
            let rec_len = u16::from_be_bytes([pkt[pos + 11], pkt[pos + 12]]) as usize;
            if !matches!(
                ct,
                DTLS_CT_CHANGE_CIPHER_SPEC..=DTLS_CT_APP_DATA | DTLS_CT_ACK
            ) {
                return false;
            }
            if ver_maj != DTLS_VER_MAJOR
                || (ver_min != DTLS_VER_MINOR_12 && ver_min != DTLS_VER_MINOR_10)
            {
                return false;
            }
            if rec_len == 0 || pos + DTLS_PLAINTEXT_HDR_LEN + rec_len > pkt.len() {
                return false;
            }
            // Reject unauthenticated plaintext Epoch=0 Alerts during handshake,
            // and reject plaintext-framed Epoch>=1 ACK (RFC 9147 encrypted ACKs use 0x20..=0x3F).
            if (ct == DTLS_CT_ALERT && epoch == 0) || (ct == DTLS_CT_ACK && epoch >= 1) {
                return false;
            }
            // AEAD encrypted DTLS 1.2 records (epoch >= 1) require >= 2B payload + 16B tag
            if epoch >= 1 && rec_len < DTLS_MIN_ENCRYPTED_RECORD_LEN {
                return false;
            }
            // In established Ready state, plaintext-framed records may ONLY be DTLS 1.2 encrypted Alerts
            // (DTLS 1.3 encrypted close_notify / ACK arrive inside 0x20..=0x3F Unified Ciphertext).
            if ready_only_alert && !(ct == DTLS_CT_ALERT && epoch >= 1) {
                return false;
            }
            pos += DTLS_PLAINTEXT_HDR_LEN + rec_len;
        }
        rec_count += 1;
        if rec_count > DTLS_MAX_RECORDS_PER_DATAGRAM {
            return false;
        }
    }
    rec_count > 0 && pos == pkt.len()
}

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

    let alg_ecdsa_sha256 = der_tlv(
        0x30,
        &der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
    );
    let mut spki_alg_inner = der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
    spki_alg_inner.extend_from_slice(&der_tlv(
        0x06,
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    ));
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
    let back_secs =
        DTLS_CERT_BACKDATE_MIN_SECS + ((rand_u32() as u64) % DTLS_CERT_BACKDATE_SPAN_SECS);
    let span_secs =
        DTLS_CERT_VALIDITY_MIN_SECS + ((rand_u32() as u64) % DTLS_CERT_VALIDITY_SPAN_SECS);
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
        let ttl = rand_duration_range_ms(DTLS_CERT_CACHE_TTL_MIN_MS, DTLS_CERT_CACHE_TTL_MAX_MS);
        Self {
            cert: generate_ephemeral_webrtc_cert(),
            expires_at: Instant::now() + ttl,
        }
    }

    pub fn get(&mut self, now: Instant) -> DtlsCertificate {
        if now >= self.expires_at {
            let ttl =
                rand_duration_range_ms(DTLS_CERT_CACHE_TTL_MIN_MS, DTLS_CERT_CACHE_TTL_MAX_MS);
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
        .flight_start_rto(Duration::from_millis(DTLS_FLIGHT_START_RTO_MS))
        .flight_retries(DTLS_FLIGHT_RETRIES)
        .handshake_timeout(Duration::from_secs(DTLS_HANDSHAKE_TIMEOUT_SECS));

    // Client ALWAYS advertises all real DTLS 1.3 + 1.2 AEAD suites (zero 1-suite JA4D leak!).
    // Server only restricts allow-list when forcing ChaCha20 or AES-GCM explicitly.
    if !is_client && want_chacha {
        builder = builder
            .dtls12_cipher_suites(&[Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256])
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
        wan_mtu
            .saturating_sub(IPV4_UDP_HDR_LEN)
            .clamp(DTLS_MIN_MTU, DTLS_MAX_MTU)
    } else {
        DTLS_MAX_MTU
    };
    if !is_client {
        return DtlsConfigPool {
            configs: vec![build_single_dimpl_config(
                pref,
                cpu,
                false,
                DTLS_DEFAULT_MTU.min(max_dtls_mtu),
            )],
        };
    }
    let mut mtus: Vec<usize> = DTLS_CLIENT_MTUS
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
pub fn build_dimpl_config(
    pref: CipherPref,
    cpu: &CpuAccelInfo,
    is_client: bool,
) -> Arc<DtlsConfig> {
    build_single_dimpl_config(pref, cpu, is_client, DTLS_DEFAULT_MTU)
}

/// Strictly extract negotiated 16-bit TLS cipher suite ID from an unfragmented Epoch=0 ServerHello
/// (supports both DTLS 1.2 and RFC 9147 DTLS 1.3; rejects RFC 8446 HelloRetryRequest and
/// malformed/truncated extension framing).
pub fn extract_dtls_server_hello_suite(datagram: &[u8]) -> Option<u16> {
    let mut pos = 0usize;
    while pos < datagram.len() {
        let b0 = datagram[pos];
        if (b0 & DTLS13_UNIFIED_HDR_MASK) == DTLS13_UNIFIED_HDR_TAG {
            // Skip RFC 9147 DTLS 1.3 unified ciphertext records
            if (b0 & DTLS13_FLAG_CID) != 0 {
                return None;
            }
            let seq_len = if (b0 & DTLS13_FLAG_SEQ16) != 0 {
                2usize
            } else {
                1usize
            };
            let has_len = (b0 & DTLS13_FLAG_LEN) != 0;
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
        if pos + DTLS_PLAINTEXT_HDR_LEN > datagram.len() {
            return None;
        }
        let ct = b0;
        if datagram[pos + 1] != DTLS_VER_MAJOR
            || (datagram[pos + 2] != DTLS_VER_MINOR_12 && datagram[pos + 2] != DTLS_VER_MINOR_10)
        {
            return None;
        }
        let epoch = u16::from_be_bytes([datagram[pos + 3], datagram[pos + 4]]);
        let rec_len = u16::from_be_bytes([datagram[pos + 11], datagram[pos + 12]]) as usize;
        let rec_end = pos + DTLS_PLAINTEXT_HDR_LEN + rec_len;
        if rec_end > datagram.len() {
            return None;
        }
        if ct == DTLS_CT_HANDSHAKE && epoch == 0 && rec_len >= 50 {
            let hs = &datagram[pos + DTLS_PLAINTEXT_HDR_LEN..rec_end];
            // HandshakeType=ServerHello(0x02), unfragmented (msg_len == frag_len, frag_off == 0),
            // legacy_version=0xFEFD, NOT HelloRetryRequest, valid compression=0 & exact extensions framing.
            let msg_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
            let msg_seq = u16::from_be_bytes([hs[4], hs[5]]);
            let frag_off = u32::from_be_bytes([0, hs[6], hs[7], hs[8]]) as usize;
            let frag_len = u32::from_be_bytes([0, hs[9], hs[10], hs[11]]) as usize;
            let sh_end = 12usize.saturating_add(frag_len);
            if hs[0] == DTLS_HS_SERVER_HELLO
                && msg_seq <= 1
                && frag_off == 0
                && msg_len == frag_len
                && sh_end <= hs.len()
                && hs[12] == DTLS_VER_MAJOR
                && hs[13] == DTLS_VER_MINOR_12
                && hs[14..46] != TLS13_HRR_RANDOM
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
                    Some(
                        TLS_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 | TLS_CHACHA20_POLY1305_SHA256,
                    ) => CipherSuite::ChaCha20Poly1305,
                    Some(
                        TLS_ECDHE_ECDSA_AES128_GCM_SHA256
                        | TLS_ECDHE_ECDSA_AES256_GCM_SHA384
                        | TLS_AES_128_GCM_SHA256
                        | TLS_AES_256_GCM_SHA384,
                    ) => CipherSuite::Aes128Gcm,
                    _ => cpu.recommended,
                }
            }
        }
    }
}
