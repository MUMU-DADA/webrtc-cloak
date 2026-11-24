//! DTLS 1.3/1.2 报文预校验、临时证书缓存与 dimpl 配置池。

use super::{
    fill_random, rand_duration_range_ms, rand_u32, unix_secs, CipherPref, CipherSuite,
    CpuAccelInfo, DtlsMinVersion,
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
