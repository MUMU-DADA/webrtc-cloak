/// Version detection and hybrid ClientHello for auto-sensing DTLS endpoints.
///
/// `server_hello_version` does lightweight parsing of the first record in a
/// datagram. It looks for a `HelloVerifyRequest` or a `ServerHello` with the
/// `supported_versions` extension to decide between DTLS 1.2 and 1.3 for the
/// client auto-sense path.
///
/// [`HybridClientHello`] constructs a ClientHello compatible with both
/// DTLS 1.2 and 1.3 servers: it offers both versions cipher suites and
/// includes `supported_versions` with both versions. Once the server
/// responds, the caller inspects the reply with `server_hello_version`
/// and forks into the appropriate handshake path.
///
/// Server-side auto-sense does not use lightweight detection. Instead,
/// it starts a DTLS 1.3 server which handles fragment reassembly natively
/// and falls back to DTLS 1.2 via [`Error::Dtls12Fallback`] if the
/// reassembled ClientHello does not offer DTLS 1.3.
use std::sync::Arc;
use std::time::Instant;

use arrayvec::ArrayVec;

use crate::buffer::Buf;
use crate::crypto::ActiveKeyExchange;
use crate::dtls12::message::Cookie;
use crate::dtls13::message::KeyShareClientHello;
use crate::dtls13::message::KeyShareEntry;
use crate::dtls13::message::Random;
use crate::dtls13::message::UseSrtpExtension;
use crate::dtls13::message::{Extension, ExtensionType};
use crate::timer::HandshakeTimers;
use crate::types::NamedGroup;
use crate::{Config, CryptoError, DtlsCertificate, Error, Output, SeededRng, TimeoutError};
// Extension type constants
const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const EXT_EC_POINT_FORMATS: u16 = 0x000B;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;
const EXT_USE_SRTP: u16 = 0x000E;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_COOKIE: u16 = 0x002C;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;

const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

const CHROME_SIGALGS: [u16; 8] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

const CHROME_COMPAT_SUITES: [u16; 8] = [
    0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
];

/// A self-contained hybrid ClientHello compatible with both DTLS 1.2 and 1.3.
///
/// Holds the offer fields, serialized transcript and crypto state needed to fork into either
/// version's handshake once the server responds:
///
/// - **DTLS 1.3 fork**: transcript bytes and ECDHE private key are injected
///   into a `Client13` via `new_from_hybrid`.
/// - **DTLS 1.2 fork**: random and transcript are injected into `Client12`.
///   Both clients retain the offer for cookie retries.
///
/// These buffers are temporary probe state created before an engine exists.
/// The selected engine copies the needed bytes into its own buffers; probe
/// buffers are retained through ServerHello and never returned to the engine's pool.
pub(crate) struct HybridClientHello {
    /// Client random used in the ClientHello.
    pub random: Random,

    /// ECDHE private key from the key_share extension.
    pub active_key_exchange: Option<Box<dyn ActiveKeyExchange>>,

    cipher_suites: ArrayVec<u16, 16>,
    cookie: Cookie,
    extensions: ArrayVec<Extension, 16>,
    extension_data: Buf,
    #[allow(dead_code)]
    mtu: usize,

    /// TLS-style transcript bytes: msg_type(1) + length(3) + CH body.
    /// Does not include DTLS message_seq/fragment_offset/fragment_length.
    pub transcript_bytes: Buf,

    /// DTLS handshake fragment: msg_type(1) + length(3) + message_seq(2)
    ///     + fragment_offset(3) + fragment_length(3) + CH body.
    ///     Used by [`wire_packet`](Self::wire_packet) to build the on-wire record
    ///     and by `Client12::new_from_hybrid` for transcript injection.
    pub handshake_fragment: Buf,
}

impl HybridClientHello {
    /// Build a hybrid ClientHello from the given configuration.
    ///
    /// Serializes the ClientHello body with both DTLS 1.2 and 1.3 cipher
    /// suites, `supported_versions` offering both versions, and 1.2-compat
    /// extensions (`ec_point_formats`, `extended_master_secret`,
    /// `renegotiation_info`).
    pub fn new(config: &Arc<Config>) -> Result<Self, Error> {
        let mut rng = SeededRng::new(config.rng_seed());
        let random = Random::new(&mut rng);

        // Start ECDHE key exchange with the first supported group (filtered)
        let group = config.kx_groups().next().ok_or(Error::CryptoError(
            CryptoError::NoSupportedKeyExchangeGroups,
        ))?;
        let kx_buf = Buf::new();
        let key_exchange = group.start_exchange(kx_buf).map_err(Error::CryptoError)?;

        let grease_cs = GREASE_VALUES[(rng.random::<u8>() as usize) & 0x0F];
        let grease_ver = GREASE_VALUES[(rng.random::<u8>() as usize) & 0x0F];
        let grease_grp = GREASE_VALUES[(rng.random::<u8>() as usize) & 0x0F];
        let g1_idx = (rng.random::<u8>() as usize) & 0x0F;
        let g2_idx = (g1_idx + 1 + ((rng.random::<u8>() as usize) % 15)) & 0x0F;
        let grease_ext1 = GREASE_VALUES[g1_idx];
        let grease_ext2 = GREASE_VALUES[g2_idx];

        // cipher_suites: exact Chrome/BoringSSL order matching dtls13/client.rs
        // ([GREASE, 1301, 1302, 1303, c02b, c02f, c02c, c030, cca9, cca8, c013, c014]).
        let mut suites: ArrayVec<u16, 16> = ArrayVec::new();
        let _ = suites.try_push(grease_cs);
        for cs in config.dtls13_cipher_suites() {
            let _ = suites.try_push(cs.suite().as_u16());
        }
        for &compat in &CHROME_COMPAT_SUITES {
            if !suites.contains(&compat) {
                let _ = suites.try_push(compat);
            }
        }
        for cs in config
            .dtls12_cipher_suites()
            .filter(|cs| !cs.suite().is_psk())
        {
            let id = cs.suite().as_u16();
            if !suites.contains(&id) {
                let _ = suites.try_push(id);
            }
        }
        // ---- Extensions ----
        // Build extension data into a separate buffer, then shuffle order (Chrome 110+ behavior).
        let mut ext_buf = Buf::new();
        let mut ext_entries: Vec<(u16, usize, usize)> = Vec::new();

        // 0. GREASE extension #1 (empty)
        ext_entries.push((grease_ext1, ext_buf.len(), ext_buf.len()));

        // 1. supported_versions: [GREASE, DTLS 1.3, DTLS 1.2]
        let start = ext_buf.len();
        ext_buf.push(6); // list_len = 3 versions * 2 bytes
        ext_buf.extend_from_slice(&grease_ver.to_be_bytes());
        ext_buf.extend_from_slice(&0xFEFCu16.to_be_bytes()); // DTLS 1.3
        ext_buf.extend_from_slice(&0xFEFDu16.to_be_bytes()); // DTLS 1.2
        ext_entries.push((EXT_SUPPORTED_VERSIONS, start, ext_buf.len()));

        // 2. supported_groups: [GREASE, ...config.kx_groups()]
        let start = ext_buf.len();
        let groups: ArrayVec<NamedGroup, 4> = config.kx_groups().map(|g| g.name()).collect();
        ext_buf.extend_from_slice(&(((1 + groups.len()) * 2) as u16).to_be_bytes());
        ext_buf.extend_from_slice(&grease_grp.to_be_bytes());
        for g in &groups {
            ext_buf.extend_from_slice(&g.as_u16().to_be_bytes());
        }
        ext_entries.push((EXT_SUPPORTED_GROUPS, start, ext_buf.len()));

        // 3. key_share: [(GREASE_grp, [0x00]), (group, pub_key)] (RFC 8701 / Chrome)
        let pub_key = key_exchange.pub_key();
        let start = ext_buf.len();
        let entries_len = (2 + 2 + 1) + (2 + 2 + pub_key.len());
        ext_buf.extend_from_slice(&(entries_len as u16).to_be_bytes());
        ext_buf.extend_from_slice(&grease_grp.to_be_bytes());
        ext_buf.extend_from_slice(&1u16.to_be_bytes());
        ext_buf.push(0x00);
        ext_buf.extend_from_slice(&group.name().as_u16().to_be_bytes());
        ext_buf.extend_from_slice(&(pub_key.len() as u16).to_be_bytes());
        ext_buf.extend_from_slice(pub_key);
        ext_entries.push((EXT_KEY_SHARE, start, ext_buf.len()));

        // 4. signature_algorithms (Chrome 8-scheme list)
        let start = ext_buf.len();
        ext_buf.extend_from_slice(&((CHROME_SIGALGS.len() * 2) as u16).to_be_bytes());
        for &sa in &CHROME_SIGALGS {
            ext_buf.extend_from_slice(&sa.to_be_bytes());
        }
        ext_entries.push((EXT_SIGNATURE_ALGORITHMS, start, ext_buf.len()));

        // 5. use_srtp ([0x0007, 0x0008, 0x0001])
        let start = ext_buf.len();
        let use_srtp = UseSrtpExtension::default();
        use_srtp.serialize(&mut ext_buf);
        ext_entries.push((EXT_USE_SRTP, start, ext_buf.len()));

        // 6. ec_point_formats (uncompressed only)
        let start = ext_buf.len();
        ext_buf.push(1); // list length
        ext_buf.push(0); // ECPointFormat::Uncompressed
        ext_entries.push((EXT_EC_POINT_FORMATS, start, ext_buf.len()));

        // 7. extended_master_secret (empty)
        ext_entries.push((EXT_EXTENDED_MASTER_SECRET, ext_buf.len(), ext_buf.len()));

        // 8. renegotiation_info (empty renegotiated_connection)
        let start = ext_buf.len();
        ext_buf.push(0);
        ext_entries.push((EXT_RENEGOTIATION_INFO, start, ext_buf.len()));

        // 9. session_ticket (empty, standard Chrome WebRTC ClientHello)
        ext_entries.push((EXT_SESSION_TICKET, ext_buf.len(), ext_buf.len()));

        // 10. GREASE extension #2 (1 zero byte per RFC 8701)
        let start = ext_buf.len();
        ext_buf.push(0x00);
        ext_entries.push((grease_ext2, start, ext_buf.len()));

        // Chrome 110+ / BoringSSL extension permutation: pin GREASE #1 at index 0 and
        // GREASE #2 at the last index, shuffling only the interior extensions [1..len-1].
        if ext_entries.len() > 3 {
            let last_inner = ext_entries.len() - 2;
            for i in (2..=last_inner).rev() {
                let j = 1 + ((rng.random::<u32>() as usize) % i);
                ext_entries.swap(i, j);
            }
        }

        let mut hello = HybridClientHello {
            random,
            active_key_exchange: Some(key_exchange),
            cipher_suites: suites,
            cookie: Cookie::empty(),
            extensions: ext_entries
                .into_iter()
                .map(|(kind, start, end)| Extension {
                    extension_type: ExtensionType::from_u16(kind),
                    extension_data_range: start..end,
                })
                .collect(),
            extension_data: ext_buf,
            mtu: config.mtu(),
            transcript_bytes: Buf::new(),
            handshake_fragment: Buf::new(),
        };
        let mut ch_body = Buf::new();
        hello.serialize(&mut ch_body);

        // ---- Build transcript bytes: msg_type(1) + length(3) + body ----
        let mut transcript_bytes = Buf::new();
        transcript_bytes.push(0x01); // ClientHello msg_type
        let body_len = ch_body.len() as u32;
        transcript_bytes.extend_from_slice(&body_len.to_be_bytes()[1..]);
        transcript_bytes.extend_from_slice(&ch_body);

        // ---- Build DTLS handshake fragment ----
        // msg_type(1) + length(3) + message_seq(2) + frag_offset(3) + frag_len(3) + body
        let mut handshake_fragment = Buf::new();
        handshake_fragment.push(0x01); // msg_type = ClientHello
        handshake_fragment.extend_from_slice(&body_len.to_be_bytes()[1..]); // length (3 bytes)
        handshake_fragment.extend_from_slice(&0u16.to_be_bytes()); // message_seq = 0
        handshake_fragment.extend_from_slice(&0u32.to_be_bytes()[1..]); // fragment_offset (3 bytes)
        handshake_fragment.extend_from_slice(&body_len.to_be_bytes()[1..]); // fragment_length (3 bytes)
        handshake_fragment.extend_from_slice(&ch_body);

        hello.transcript_bytes = transcript_bytes;
        hello.handshake_fragment = handshake_fragment;
        Ok(hello)
    }

    /// Apply an HVR cookie after the server has selected DTLS 1.2.
    pub fn set_legacy_cookie(&mut self, cookie: Cookie) {
        self.cookie = cookie;
        // DTLS 1.3 requires an empty legacy cookie, so stop advertising it.
        self.extensions.retain(|ext| {
            ext.extension_type != ExtensionType::SupportedVersions
                && ext.extension_type != ExtensionType::KeyShare
        });
    }

    /// Apply an HRR cookie, including its existing u16 length prefix.
    pub fn set_retry_cookie(&mut self, cookie: &[u8]) {
        self.set_extension(EXT_COOKIE, |data| data.extend_from_slice(cookie));
    }

    /// Replace the public key share when HRR selects a different group.
    pub fn set_key_share(&mut self, group: NamedGroup, public_key: &[u8]) {
        self.set_extension(EXT_KEY_SHARE, |data| {
            let mut entries = ArrayVec::new();
            entries.push(KeyShareEntry {
                group,
                key_exchange_range: 0..public_key.len(),
            });
            KeyShareClientHello { entries }.serialize(public_key, data);
        });
    }

    fn set_extension(&mut self, kind: u16, write: impl FnOnce(&mut Buf)) {
        let start = self.extension_data.len();
        write(&mut self.extension_data);
        let entry = Extension {
            extension_type: ExtensionType::from_u16(kind),
            extension_data_range: start..self.extension_data.len(),
        };
        if let Some(existing) = self
            .extensions
            .iter_mut()
            .find(|ext| ext.extension_type == entry.extension_type)
        {
            *existing = entry;
        } else {
            self.extensions.push(entry);
        }
    }

    /// Serialize the retained offer without artificial RFC 7685 zero padding.
    pub fn serialize(&self, body: &mut Buf) {
        body.extend_from_slice(&0xFEFDu16.to_be_bytes());
        self.random.serialize(body);
        body.push(0); // empty session ID
        body.push(self.cookie.len() as u8);
        body.extend_from_slice(&self.cookie);
        body.extend_from_slice(&((self.cipher_suites.len() * 2) as u16).to_be_bytes());
        for suite in &self.cipher_suites {
            body.extend_from_slice(&suite.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]); // null compression

        let extensions_len: usize = self
            .extensions
            .iter()
            .map(|ext| 4 + ext.extension_data_range.len())
            .sum();
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        for ext in &self.extensions {
            ext.serialize(&self.extension_data, body);
        }
    }

    /// Build the full wire-format DTLSPlaintext record for the hybrid CH.
    pub fn wire_packet(&self) -> Buf {
        let mut pkt = Buf::new();
        // DTLSPlaintext header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2)
        pkt.push(0x16); // Handshake
        pkt.extend_from_slice(&0xFEFDu16.to_be_bytes()); // DTLS 1.2
        pkt.extend_from_slice(&0u16.to_be_bytes()); // epoch 0
        pkt.extend_from_slice(&[0u8; 6]); // sequence 0
        pkt.extend_from_slice(&(self.handshake_fragment.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&self.handshake_fragment);
        pkt
    }
}

/// Auto-sense client that sends a hybrid ClientHello and waits for the server's response
/// to determine the DTLS version.
pub(crate) struct ClientPending {
    hybrid: HybridClientHello,
    config: Arc<Config>,
    certificate: DtlsCertificate,
    /// Pre-built wire packet (record header + handshake fragment).
    wire_packet: Buf,
    /// Whether the wire_packet hasn't been polled yet.
    needs_send: bool,
    /// Last time handle_timeout was called.
    last_now: Instant,
    timers: HandshakeTimers,
    rng: SeededRng,
    closed: bool,
}

impl ClientPending {
    pub fn new(
        config: Arc<Config>,
        certificate: DtlsCertificate,
        now: Instant,
    ) -> Result<Self, Error> {
        let hybrid = HybridClientHello::new(&config)?;
        let wire_packet = hybrid.wire_packet();
        let mut rng = SeededRng::new(config.rng_seed());
        let mut timers = HandshakeTimers::new(&config, &mut rng);
        timers.begin_flight(&mut rng);
        Ok(ClientPending {
            hybrid,
            config,
            certificate,
            wire_packet,
            needs_send: true,
            last_now: now,
            timers,
            rng,
            closed: false,
        })
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.last_now = now;
        if self.closed {
            return Ok(());
        }
        let resend = self
            .timers
            .handle_timeout(now, &mut self.rng)
            .map_err(|error| {
                Error::Timeout(match error {
                    TimeoutError::Handshake => TimeoutError::HybridClientHello,
                    other => other,
                })
            })?;
        if resend {
            self.needs_send = true;
        }
        Ok(())
    }

    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        if self.needs_send {
            let len = self.wire_packet.len();
            if buf.len() < len {
                // Keep needs_send armed so the packet is emitted on retry.
                return Output::BufferTooSmall { needed: len };
            }
            self.needs_send = false;
            buf[..len].copy_from_slice(&self.wire_packet);
            self.timers.start_handshake(self.last_now);
            self.timers.flight_sent(self.last_now);
            return Output::Packet(&buf[..len]);
        }
        let next = self.timers.poll_timeout(self.last_now);
        Output::Timeout(next)
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn close(&mut self) -> Result<(), Error> {
        self.closed = true;
        self.needs_send = false;
        self.timers.stop();
        Ok(())
    }

    pub fn into_parts(
        self,
    ) -> (
        HybridClientHello,
        Arc<Config>,
        DtlsCertificate,
        Instant,
        HandshakeTimers,
    ) {
        // Bind the fields first: CodeQL treats a tuple holding `self.certificate`
        // directly as sensitive data and taints every element, including `config`.
        let Self {
            hybrid,
            config,
            certificate,
            last_now,
            timers,
            ..
        } = self;
        (hybrid, config, certificate, last_now, timers)
    }
}

// =========================================================================
// Version detection helpers
// =========================================================================

/// Detected DTLS version from packet inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetectedVersion {
    Dtls12,
    Dtls13,
    Unknown,
}

/// Detect DTLS version from a server response (ServerHello or HelloVerifyRequest).
///
/// - HelloVerifyRequest (msg_type 3) → `Dtls12`
/// - ServerHello with `supported_versions` containing DTLS 1.3 → `Dtls13`
/// - ServerHello without `supported_versions` → `Dtls12`
/// - Anything else → `Unknown`
pub(crate) fn server_hello_version(packet: &[u8]) -> DetectedVersion {
    server_hello_version_inner(packet).unwrap_or(DetectedVersion::Unknown)
}

fn server_hello_version_inner(packet: &[u8]) -> Option<DetectedVersion> {
    // Record header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13
    if packet.len() < 13 {
        return None;
    }

    // content_type must be 0x16 (Handshake)
    if packet[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([packet[11], packet[12]]) as usize;
    let record_body = packet.get(13..13 + record_len)?;

    // Handshake header: msg_type(1) + length(3) + message_seq(2) +
    //   fragment_offset(3) + fragment_length(3) = 12
    if record_body.len() < 12 {
        return None;
    }

    let msg_type = record_body[0];

    // HelloVerifyRequest → DTLS 1.2
    if msg_type == 3 {
        return Some(DetectedVersion::Dtls12);
    }

    // ServerHello → inspect supported_versions
    if msg_type != 2 {
        return None;
    }

    let fragment_len = ((record_body[9] as usize) << 16)
        | ((record_body[10] as usize) << 8)
        | (record_body[11] as usize);
    let body = record_body.get(12..12 + fragment_len)?;

    // ServerHello body:
    //   server_version(2) + random(32) + session_id_len(1) + session_id + ...
    if body.len() < 35 {
        return Some(DetectedVersion::Dtls12);
    }
    let mut pos = 34; // past version(2) + random(32)

    // session_id: 1-byte length + data
    let sid_len = *body.get(pos)? as usize;
    pos += 1 + sid_len;

    // cipher_suite: 2 bytes
    pos += 2;

    // compression_method: 1 byte
    pos += 1;

    // extensions: 2-byte total length (optional)
    if pos + 2 > body.len() {
        // No extensions → DTLS 1.2
        return Some(DetectedVersion::Dtls12);
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;
    if ext_end > body.len() {
        return Some(DetectedVersion::Dtls12);
    }

    // Walk extensions looking for supported_versions (0x002B)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x002B {
            // ServerHello supported_versions: just 2 bytes (selected_version)
            if ext_len >= 2 {
                let version = u16::from_be_bytes([body[pos], body[pos + 1]]);
                if version == 0xFEFC {
                    return Some(DetectedVersion::Dtls13);
                }
            }
            return Some(DetectedVersion::Dtls12);
        }

        pos += ext_len;
    }

    // No supported_versions → DTLS 1.2
    Some(DetectedVersion::Dtls12)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PskResolver;
    use crate::dtls12::message::Dtls12CipherSuite;

    fn offered_cipher_suites(hybrid: &HybridClientHello) -> Vec<u16> {
        let body = &hybrid.handshake_fragment[12..];
        let mut offset = 2 + 32; // legacy_version + random

        let session_id_len = body[offset] as usize;
        offset += 1 + session_id_len;

        let cookie_len = body[offset] as usize;
        offset += 1 + cookie_len;

        let suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;

        body[offset..offset + suites_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect()
    }

    struct DummyResolver;

    impl PskResolver for DummyResolver {
        fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
            Some(b"0123456789abcdef".to_vec())
        }
    }

    #[test]
    fn hello_verify_request_is_dtls12() {
        // Minimal HelloVerifyRequest packet
        let mut pkt = Vec::new();
        // Record header: content_type=22, version=DTLS1.2, epoch=0, seq=0, length=TBD
        pkt.push(0x16); // handshake
        pkt.extend_from_slice(&[0xFE, 0xFD]); // DTLS 1.2
        pkt.extend_from_slice(&[0x00, 0x00]); // epoch 0
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // seq 0
        // length placeholder (will fill)
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=3 (HVR), length=5, msg_seq=0, frag_off=0, frag_len=5
        pkt.push(3); // HelloVerifyRequest
        pkt.extend_from_slice(&[0x00, 0x00, 0x05]); // length
        pkt.extend_from_slice(&[0x00, 0x00]); // message_seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset
        pkt.extend_from_slice(&[0x00, 0x00, 0x05]); // fragment_length

        // HVR body: server_version(2) + cookie_len(1) + cookie(2)
        pkt.extend_from_slice(&[0xFE, 0xFD]); // server_version
        pkt.push(0x02); // cookie length
        pkt.extend_from_slice(&[0xAA, 0xBB]); // cookie

        // Fill record length
        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls12);
    }

    #[test]
    fn server_hello_with_supported_versions_is_dtls13() {
        let mut pkt = Vec::new();
        // Record header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=2 (ServerHello)
        pkt.push(2);
        let hs_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
        pkt.extend_from_slice(&[0x00, 0x00]); // message_seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset
        let frag_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_length placeholder

        let body_start = pkt.len();

        // ServerHello body: version(2) + random(32) + session_id
        pkt.extend_from_slice(&[0xFE, 0xFD]); // legacy version DTLS 1.2
        pkt.extend_from_slice(&[0u8; 32]); // random
        pkt.push(0x00); // session_id length = 0
        pkt.extend_from_slice(&[0x13, 0x01]); // cipher_suite AES_128_GCM_SHA256
        pkt.push(0x00); // compression_method = null

        // Extensions
        let ext_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]); // extensions length placeholder

        let ext_start = pkt.len();

        // supported_versions extension: type=0x002B, data=0xFEFC (DTLS 1.3)
        pkt.extend_from_slice(&[0x00, 0x2B]); // type
        pkt.extend_from_slice(&[0x00, 0x02]); // length
        pkt.extend_from_slice(&[0xFE, 0xFC]); // DTLS 1.3

        let ext_total = pkt.len() - ext_start;
        pkt[ext_len_pos] = (ext_total >> 8) as u8;
        pkt[ext_len_pos + 1] = ext_total as u8;

        let body_len = pkt.len() - body_start;
        // Fill handshake length and fragment length
        pkt[hs_len_pos] = 0;
        pkt[hs_len_pos + 1] = (body_len >> 8) as u8;
        pkt[hs_len_pos + 2] = body_len as u8;
        pkt[frag_len_pos] = 0;
        pkt[frag_len_pos + 1] = (body_len >> 8) as u8;
        pkt[frag_len_pos + 2] = body_len as u8;

        // Fill record length
        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls13);
    }

    #[test]
    fn server_hello_without_supported_versions_is_dtls12() {
        let mut pkt = Vec::new();
        // Record header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=2 (ServerHello)
        pkt.push(2);
        let hs_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        let frag_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);

        let body_start = pkt.len();

        // ServerHello body without extensions
        pkt.extend_from_slice(&[0xFE, 0xFD]); // version
        pkt.extend_from_slice(&[0u8; 32]); // random
        pkt.push(0x00); // session_id length
        pkt.extend_from_slice(&[0xC0, 0x2B]); // cipher_suite (1.2 ECDHE)
        pkt.push(0x00); // compression

        let body_len = pkt.len() - body_start;
        pkt[hs_len_pos] = 0;
        pkt[hs_len_pos + 1] = (body_len >> 8) as u8;
        pkt[hs_len_pos + 2] = body_len as u8;
        pkt[frag_len_pos] = 0;
        pkt[frag_len_pos + 1] = (body_len >> 8) as u8;
        pkt[frag_len_pos + 2] = body_len as u8;

        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls12);
    }

    #[test]
    fn garbage_packet_is_unknown() {
        assert_eq!(
            server_hello_version(&[0xFF, 0x00]),
            DetectedVersion::Unknown
        );
        assert_eq!(server_hello_version(&[]), DetectedVersion::Unknown);
    }

    #[test]
    fn too_short_is_unknown() {
        // Non-handshake content type
        let pkt = [
            0x17, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
        ];
        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn hybrid_client_hello_excludes_psk_dtls12_suites() {
        let config = Arc::new(
            Config::builder()
                .with_psk_client(b"identity".to_vec(), Arc::new(DummyResolver))
                .build()
                .expect("config with PSK should build"),
        );

        assert!(
            config.dtls12_cipher_suites().any(|cs| cs.suite().is_psk()),
            "precondition: PSK-enabled config should expose a PSK DTLS 1.2 suite"
        );

        let hybrid = HybridClientHello::new(&config).expect("hybrid ClientHello should build");
        let offered = offered_cipher_suites(&hybrid);

        assert!(
            !offered.contains(&Dtls12CipherSuite::PSK_AES128_CCM_8.as_u16()),
            "auto client must not advertise PSK DTLS 1.2 suites it cannot use after fallback"
        );
    }
}
