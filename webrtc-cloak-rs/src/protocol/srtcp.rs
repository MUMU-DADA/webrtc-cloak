//! RFC 3550/7714 复合 SRTCP 报文构造、校验与防重放。

use super::{CipherSuite, SrtpCloakCipher, RTCP_CNAME_LEN, RTCP_HDR_LEN, RTP_V2_BITS, RTP_V2_MASK};
use crate::constants::SRTP_TAG_LEN;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Nonce as GcmNonce, Tag as GcmTag};
use chacha20poly1305::{Nonce as ChaNonce, Tag as ChaTag};
use subtle::ConstantTimeEq;

/// SRTCP 控制面正交 AEAD Nonce 域掩码位。
const NONCE_DOMAIN_SRTCP_BIT: u8 = 0x80;
/// SRTCP 64 位滑动防重放窗口宽度（包）。
const SRTCP_REPLAY_WINDOW: u32 = 64;
/// SRTCP 尾部 `E || SRTCP_index` 字段长度（字节）。
const SRTCP_INDEX_LEN: usize = 4;
/// SRTCP 尾部加密标志位（最高位 `E=1`）。
const SRTCP_E_FLAG: u32 = 0x8000_0000;
/// SRTCP 31 位序列索引掩码。
const SRTCP_IDX_MASK: u32 = 0x7FFF_FFFF;
/// RTCP 类型：Sender Report (200)。
const RTCP_PT_SR: u8 = 200;
/// RTCP 类型：Receiver Report (201)。
const RTCP_PT_RR: u8 = 201;
/// RTCP 类型：Source Description / SDES (202)。
const RTCP_PT_SDES: u8 = 202;
/// RTCP 类型：Goodbye / BYE (203)。
const RTCP_PT_BYE: u8 = 203;
/// RTCP 类型：Transport-Layer Feedback / TWCC (205)。
const RTCP_PT_RTPFB: u8 = 205;
/// RTCP 类型：Payload-Specific Feedback (206)。
const RTCP_PT_PSFB: u8 = 206;

impl SrtpCloakCipher {
    #[inline]
    fn is_srtcp_replay(&self, idx: u32) -> bool {
        if !self.rx_srtcp_seen {
            return false;
        }
        if idx > self.rx_srtcp_highest {
            return false;
        }
        let delta = self.rx_srtcp_highest - idx;
        if delta >= SRTCP_REPLAY_WINDOW {
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
            self.rx_srtcp_bitmap = if shift >= SRTCP_REPLAY_WINDOW {
                1
            } else {
                (self.rx_srtcp_bitmap << shift) | 1
            };
            self.rx_srtcp_highest = idx;
        } else {
            let delta = self.rx_srtcp_highest - idx;
            if delta < SRTCP_REPLAY_WINDOW {
                self.rx_srtcp_bitmap |= 1u64 << delta;
            }
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

        let pt: u8 = if effective_sender {
            RTCP_PT_SR
        } else {
            RTCP_PT_RR
        };
        let rc: u8 = if has_rx_media { 1 } else { 0 };
        let primary_words: u16 = match (effective_sender, has_rx_media) {
            (true, true) => 12,   // SR + 1 Report Block (52B)
            (true, false) => 6,   // SR + 0 Report Blocks (28B)
            (false, true) => 7,   // RR + 1 Report Block (32B)
            (false, false) => 1,  // Empty RR (8B)
        };
        let primary_rem_len = ((primary_words as usize) - 1) * 4;

        let idx = self.tx_srtcp_idx & SRTCP_IDX_MASK;
        self.tx_srtcp_idx = self.tx_srtcp_idx.saturating_add(1).min(SRTCP_IDX_MASK);
        let e_idx = SRTCP_E_FLAG | idx;

        let mut hdr = [0u8; RTCP_HDR_LEN];
        hdr[0] = RTP_V2_BITS | rc;
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
        body.extend_from_slice(&[RTP_V2_BITS | 1, RTCP_PT_SDES]);
        body.extend_from_slice(&sdes_len_words.to_be_bytes());
        body.extend_from_slice(&report_ssrc.to_be_bytes());
        body.push(1); // CNAME item type
        body.push(RTCP_CNAME_LEN as u8);
        body.extend_from_slice(&self.cname);
        body.push(0); // RFC 3550 §6.5 END item (32-bit aligned at 24B)

        // Optional Subpacket 3: Transport-CC (205) / PSFB (206) smooth randomized length (~87.5%)
        // ONLY when media was actually received since the last RTCP (`has_rx_media`) and not BYE!
        // Prevents RFC 3550 semantic violation of emitting TWCC/PSFB feedback on zero-media RR intervals.
        if !include_bye && has_rx_media && (self.next_rng() & 7) != 0 {
            let fb_pt: u8 = if (self.next_rng() & 1) == 0 {
                RTCP_PT_RTPFB
            } else {
                RTCP_PT_PSFB
            };
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
            body.extend_from_slice(&[RTP_V2_BITS | 1, RTCP_PT_BYE, 0x00, 0x01]);
            body.extend_from_slice(&report_ssrc.to_be_bytes());
        }

        let mut aad = [0u8; RTCP_HDR_LEN + SRTCP_INDEX_LEN];
        aad[..RTCP_HDR_LEN].copy_from_slice(&hdr);
        aad[RTCP_HDR_LEN..RTCP_HDR_LEN + SRTCP_INDEX_LEN].copy_from_slice(&e_idx.to_be_bytes());

        let srtcp_tx_dir = self.tx_dir | NONCE_DOMAIN_SRTCP_BIT;
        let tag_bytes: [u8; SRTP_TAG_LEN] = match self.suite {
            CipherSuite::Aes128Gcm => {
                let iv = self.gcm_nonce(srtcp_tx_dir, report_ssrc, idx as u64);
                let tag = self
                    .aes_gcm
                    .encrypt_in_place_detached(GcmNonce::from_slice(&iv), &aad, &mut body)
                    .expect("SRTCP AES-GCM encrypt");
                tag.into()
            }
            CipherSuite::ChaCha20Poly1305 => {
                let iv = self.gcm_nonce(srtcp_tx_dir, report_ssrc, idx as u64);
                let tag = self
                    .chacha
                    .encrypt_in_place_detached(ChaNonce::from_slice(&iv), &aad, &mut body)
                    .expect("SRTCP ChaCha20 encrypt");
                tag.into()
            }
            CipherSuite::Blake2b => {
                self.xor_keystream(srtcp_tx_dir, report_ssrc, idx as u64, &mut body);
                self.auth_tag(srtcp_tx_dir, &aad, &body, idx)
            }
        };

        let mut pkt = Vec::with_capacity(RTCP_HDR_LEN + body.len() + SRTP_TAG_LEN + SRTCP_INDEX_LEN);
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
        if packet.len() < RTCP_HDR_LEN + SRTP_TAG_LEN + SRTCP_INDEX_LEN {
            return None;
        }
        // RFC 3550 §6.1: plaintext first subpacket MUST be SR (200) or RR (201)
        if (packet[0] & RTP_V2_MASK) != RTP_V2_BITS
            || (packet[1] != RTCP_PT_SR && packet[1] != RTCP_PT_RR)
        {
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

        let idx_pos = packet.len() - SRTCP_INDEX_LEN;
        let tag_pos = idx_pos - SRTP_TAG_LEN;
        let e_idx = u32::from_be_bytes([
            packet[idx_pos],
            packet[idx_pos + 1],
            packet[idx_pos + 2],
            packet[idx_pos + 3],
        ]);
        if (e_idx & SRTCP_E_FLAG) == 0 {
            return None;
        }
        let idx = e_idx & SRTCP_IDX_MASK;
        if self.is_srtcp_replay(idx) {
            return None;
        }

        let mut aad = [0u8; RTCP_HDR_LEN + SRTCP_INDEX_LEN];
        aad[..RTCP_HDR_LEN].copy_from_slice(&packet[..RTCP_HDR_LEN]);
        aad[RTCP_HDR_LEN..RTCP_HDR_LEN + SRTCP_INDEX_LEN].copy_from_slice(&packet[idx_pos..]);
        let mut plain = packet[RTCP_HDR_LEN..tag_pos].to_vec();

        let srtcp_rx_dir = self.rx_dir | NONCE_DOMAIN_SRTCP_BIT;
        let ok = match self.suite {
            CipherSuite::Aes128Gcm => {
                let iv = self.gcm_nonce(srtcp_rx_dir, ssrc, idx as u64);
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
                let iv = self.gcm_nonce(srtcp_rx_dir, ssrc, idx as u64);
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
                let expected = self.auth_tag(srtcp_rx_dir, &aad, &plain, idx);
                if bool::from(packet[tag_pos..idx_pos].ct_eq(&expected[..])) {
                    self.xor_keystream(srtcp_rx_dir, ssrc, idx as u64, &mut plain);
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
            if (plain[pos] & RTP_V2_MASK) != RTP_V2_BITS {
                break;
            }
            let sub_pt = plain[pos + 1];
            let sub_words = u16::from_be_bytes([plain[pos + 2], plain[pos + 3]]) as usize;
            let sub_len = (sub_words + 1) * 4;
            if pos + sub_len > plain.len() {
                break;
            }
            if sub_pt == RTCP_PT_BYE {
                has_bye = true;
            }
            pos += sub_len;
        }
        Some(has_bye)
    }
}
