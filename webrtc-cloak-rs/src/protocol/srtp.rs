//! 会话密钥派生与双 SSRC SRTP 加解密及防重放状态机。

use super::{
    fill_random, CipherSuite, SrtpFrame, DEFAULT_WAN_MTU, DIR_C2S, DIR_S2C, MAX_INNER_UDP_LEN,
    RTP_AUDIO_PT, RTP_FIXED_HDR_LEN, RTP_FULL_HDR_LEN, RTP_VIDEO_PT, SRTP_HANDOVER_MAGIC,
    SRTP_PATH_CHALLENGE_MAGIC, SRTP_PROBE_MAGIC_LEN, SRTP_TAG_LEN,
};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce as GcmNonce, Tag as GcmTag};
use blake2::digest::consts::{U16, U64};
use blake2::{Blake2bMac, Digest as _};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce, Tag as ChaTag};
use hmac::Mac as _;
use sha2::Sha256;
use std::time::Instant;
use subtle::ConstantTimeEq;

/// Hard SRTP 48-bit extended sequence exhaustion ceiling (never wrap Nonce!).
const MAX_SRTP_EXT_SEQ: u64 = 0xFFFF_FFFF_FF00;
/// Hard SRTCP 31-bit index exhaustion ceiling (never wrap Nonce!).
const MAX_SRTCP_IDX: u32 = 0x7FFF_FF00;

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

pub(super) fn derive_audio_ssrc(session_key: &[u8; 32], video_ssrc: u32) -> u32 {
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
    pub(super) suite: CipherSuite,
    pub(super) max_wire_udp: usize,
    pub(super) dual_ssrc: bool,
    pub(super) enc_key: [u8; 32],
    pub(super) mac_key: [u8; 32],
    pub(super) aes_gcm: Aes128Gcm,
    pub(super) chacha: ChaCha20Poly1305,
    pub(super) gcm_salt: [u8; 4],
    pub(super) cname: [u8; 13],
    pub ssrc_tx: u32,
    pub ssrc_rx: u32,
    pub audio_ssrc_tx: u32,
    pub audio_ssrc_rx: u32,
    pub(super) tx_dir: u8,
    pub(super) rx_dir: u8,
    pub tx_ext_seq: u64,
    pub(super) audio_tx_ext_seq: u64,
    pub(super) tx_twcc_seq: u16,
    pub(super) pad_rng: u64,
    pub(super) ts_base: u32,
    pub(super) audio_ts_base: u32,
    pub(super) t0: Instant,
    pub(super) video_frame_open: bool,
    pub(super) cur_video_ts: u64,
    pub(super) last_closed_video_ts: u64,
    pub(super) frame_pkt_count: u16,
    pub(super) frame_pkt_budget: u16,
    pub(super) last_audio_frame: u64,
    pub(super) last_audio_wall_ms: u64,
    pub(super) video_tx_since_rtcp: u64,
    pub(super) audio_tx_since_rtcp: u64,
    pub(super) rx_initialized: bool,
    pub rx_roc: u32,
    pub(super) rx_highest_seq16: u16,
    pub(super) rx_replay_ring: [u64; SRTP_REPLAY_RING_WORDS],
    pub(super) audio_rx_initialized: bool,
    pub(super) audio_rx_roc: u32,
    pub(super) audio_rx_highest_seq16: u16,
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
    pub(super) fn next_rng(&mut self) -> u64 {
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
    pub(super) fn xor_keystream(&self, direction: u8, ssrc: u32, ext_seq: u64, buf: &mut [u8]) {
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
    pub(super) fn auth_tag(&self, direction: u8, aad_hdr: &[u8], ciphertext: &[u8], roc: u32) -> [u8; SRTP_TAG_LEN] {
        let mut h = Blake2bMac::<U16>::new_from_slice(&self.mac_key).expect("key");
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
        self.wrap_inner(None, false, plaintext, out)
    }

    /// Wrap an in-band AEAD-encrypted diagnostic probe (`0xFFFE || probe_len || payload || random pad`).
    /// Identical Chrome `0x90` SRTP format on the wire; strictly disjoint from real UDP (`<= 65400`).
    #[inline]
    pub fn wrap_probe_into(&mut self, payload: &[u8], out: &mut [u8]) -> Option<usize> {
        self.wrap_control_into(SRTP_PROBE_MAGIC_LEN, payload, out)
    }

    /// Wrap an in-band AEAD-encrypted control frame (`magic` in `{0xFFFE, 0xFFFD, 0xFFFC}`).
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
        if payload.len() > 1460
            || !matches!(
                magic,
                SRTP_PROBE_MAGIC_LEN | SRTP_PATH_CHALLENGE_MAGIC | SRTP_HANDOVER_MAGIC
            )
        {
            return None;
        }
        self.wrap_inner(Some(magic), no_pad, payload, out)
    }

    #[inline]
    fn wrap_inner(
        &mut self,
        control_magic: Option<u16>,
        no_pad: bool,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        let is_control = control_magic.is_some();
        let prefix_len = if is_control { 4 } else { 2 };
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
        let eff_len = plaintext.len() + if is_control { 2 } else { 0 };
        let max_pad = if no_pad {
            0
        } else if eff_len >= 1340 {
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
        //   Data   : [inner_len: u16 BE] || [plaintext] || [random pad]
        //   Control: [magic: u16 BE (0xFFFE/0xFFFD/0xFFFC)] || [len: u16 BE] || [payload] || [random pad]
        let ct_end = RTP_FULL_HDR_LEN + ct_len;
        if let Some(magic) = control_magic {
            out[RTP_FULL_HDR_LEN..RTP_FULL_HDR_LEN + 2]
                .copy_from_slice(&magic.to_be_bytes());
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
        if matches!(
            raw_len,
            SRTP_PROBE_MAGIC_LEN | SRTP_PATH_CHALLENGE_MAGIC | SRTP_HANDOVER_MAGIC
        ) {
            if ct_len < 4 {
                return None;
            }
            let ctrl_len = u16::from_be_bytes([out[2], out[3]]) as usize;
            if ctrl_len > 1460 || 4 + ctrl_len > ct_len {
                return None;
            }
            out.copy_within(4..4 + ctrl_len, 0);
            return Some(match raw_len {
                SRTP_PROBE_MAGIC_LEN => SrtpFrame::Probe(ctrl_len),
                SRTP_PATH_CHALLENGE_MAGIC => SrtpFrame::PathChallenge(ctrl_len),
                SRTP_HANDOVER_MAGIC => SrtpFrame::Handover(ctrl_len),
                _ => unreachable!(),
            });
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
