# WebRTC-Cloak Protocol Specification (`V3.2` / `v0.3.7`)

This document specifies the wire format, cryptographic schedule, state machine, and security boundaries of `webrtc-cloak-rs`.

---

## 1. Single-Port Multiplexing (RFC 7983 & RFC 5761)

All protocol layers share a single UDP 5-tuple and are demultiplexed strictly by the first byte `b[0]` (and `b[1]` for RTP/RTCP):

| First Byte (`b[0]`) | Second Byte (`b[1]`) | Layer | Action on Unauthenticated / Unknown |
| :--- | :--- | :--- | :--- |
| `0..=3` | any | **ICE STUN** (RFC 5389 / 8445 / 7675) | 0-byte Silent Drop |
| `20..=63` | any | **DTLS 1.3 / 1.2** (RFC 9147 / 6347) | 0-byte Silent Drop (no session) |
| `128..=191` | `192..=223` | **Compound SRTCP** (RFC 3550 / 7714) | 0-byte Silent Drop |
| `128..=191` | other | **Dual-SSRC SRTP** (RFC 3711 / 7714 / 8285) | 0-byte Silent Drop |
| other | any | **Unknown** | 0-byte Silent Drop |

---

## 2. ICE STUN Authentication & Freshness

### 2.1 Transaction ID (`txid`, 12 bytes)
- `txid[0..8]`: 8 random bytes from OS CSPRNG.
- `txid[8..12]`: `unix_secs_u32_be ^ SHA256("webrtc-cloak:txid-mask:" || psk || txid[0..8])[0..4]`.
- Server accepts Binding Requests only if `|now - unix_secs| <= 30s` **after** `MESSAGE-INTEGRITY` verification passes.

### 2.2 Attributes & Strict RFC 5389 §15.4 Parsing
- Request attributes (libwebrtc order): `USERNAME` (`4:4` Base64 `ufrag_r:ufrag_l`), `ICE-CONTROLLING` (session-constant 64-bit tie-breaker), `USE-CANDIDATE` (present **only** on initial session nomination; omitted on keepalives), `PRIORITY` (session-constant), `MESSAGE-INTEGRITY` (20B HMAC-SHA1 keyed by `SHA256("webrtc-cloak:stun-mi:" || psk)`), and mandatory trailing 8B `FINGERPRINT` (`CRC-32 ^ 0x5354554E`).
- Zero heap allocation occurs before constant-time HMAC-SHA1 and FINGERPRINT verification succeed.
- Any attribute after `MESSAGE-INTEGRITY` other than an exact trailing 8B `FINGERPRINT` is rejected.
- Server rejects keepalives lacking `USE-CANDIDATE` when no active session matches (`NEW-M-01`), and enforces a shared bounded FIFO `SeenTxidCache` (`65,536` entries, 90s TTL, max 6 same-peer retransmits within 8s).

---

## 3. DTLS 1.3 / 1.2 Handshake & Pre-Validation

- Implemented with pure-Rust Sans-IO `dimpl 0.9.0` using mutual rotating ephemeral self-signed ECDSA P-256 certificates (`CN=WebRTC`, 20–24h per-worker cache) and stateless server cookies (`HelloRetryRequest` / `HelloVerifyRequest`).
- `--dtls-min-version auto|1.2` (default): `Dtls::new_auto` prefers RFC 9147 DTLS 1.3 (`0x2e` encrypted mutual certificates, saves 1 RTT) and falls back seamlessly to DTLS 1.2 for rolling upgrades.
- `--dtls-min-version 1.3`: `Dtls::new_13` disables DTLS 1.2 fallback completely, eliminating on-path downgrade attacks.
- Client pre-builds a multi-MTU `DtlsConfigPool` (8 MTUs across `760..=1340B`, clamped by `--mtu`) at startup with zero runtime validation cost.
- `validate_dtls_datagram(pkt, ready_only_alert)` validates RFC 9147 Unified Ciphertext (`001C_SL_EE`, `C=0`, `rec_len >= 18`) and plaintext-framed records (`20..=23`, `26` only at `epoch=0` during handshake; rejects `epoch=0` Alert and `Ready`-state plaintext `ct=26`).
- Client drives `dtls_next_timeout` inside `Ready` state so a dropped DTLS 1.3 Flight 5 retransmits at ~350ms RTO rather than stalling.
- Server never refreshes `last_peer_rx` from DTLS packets in `Ready` state.

---

## 4. Key Schedule & Orthogonal AEAD Nonce Domains

### 4.1 Fail-Closed Hybrid PFS
1. `seed = "webrtc-cloak-v3|" || psk || "|" || stun_txid || "|" || username`
2. `stun_key = SHA256(seed || "|stun-key")` (32B)
3. `ssrc_c2s = BE32(SHA256(seed || "|ssrc")[0..4])`, `ssrc_s2c = BE32(SHA256(seed || "|ssrc")[4..8])`
4. `dtls_km` = 64B RFC 5764 `EXTRACTOR-dtls_srtp` keying material (mandatory non-empty when DTLS is enabled — **Fail-Closed**).
5. `session_key = SHA256("webrtc-cloak-v3|pfs-bind|" || stun_key || "|dtls-km|" || dtls_km)` (32B)
6. `enc_key = SHA256(session_key || "|enc")`, `mac_key = SHA256(session_key || "|mac")`, `gcm_salt = enc_key[16..20]`.
7. `audio_ssrc = SHA256("webrtc-cloak-v3-audio-ssrc|" || session_key || BE32(video_ssrc))[0..4]`, constrained so `audio_ssrc != 0` and `(audio_ssrc >> 16) != (video_ssrc >> 16)`.

*(Note: A future breaking protocol revision `V4` may migrate step 5–6 to RFC 5869 HKDF-Extract/Expand while keeping `V3.x` rolling-upgrade wire compatibility intact.)*

### 4.2 Orthogonal 96-bit AEAD Nonce Layout
```text
iv[0..4]  = gcm_salt ^ [domain_dir, 0, 0, 0]
iv[4..6]  = ssrc[31:16]
iv[6..8]  = ssrc[15:0] ^ ext_seq[47:32]
iv[8..12] = ext_seq[31:0]
```
- **Video SRTP (`PT=96`)**: `domain_dir = dir` (`0x00` C2S / `0x01` S2C), `ssrc = video_ssrc`.
- **Audio SRTP (`PT=111`, DTLS 1.3 dual-SSRC)**: `domain_dir = dir | 0x40` (`0x40` / `0x41`), `ssrc = audio_ssrc` (also high-16-bit disjoint from `video_ssrc`).
- **Compound SRTCP**: `domain_dir = dir | 0x80` (`0x80` / `0x81`), `ext_seq = srtcp_idx` (0-based 31-bit index).
- Exhaustion ceilings (`MAX_SRTP_EXT_SEQ = 0xFFFF_FFFF_FF00`, `MAX_SRTCP_IDX = 0x7FFF_FF00`) trigger proactive rekeying; sequence numbers never wrap.

---

## 5. Dual-SSRC SRTP, Compound SRTCP & In-Band `0xFFFE` Probes

### 5.1 SRTP Wire Frame
```text
[12B RTP Header: 0x90 (V=2,P=0,X=1,CC=0), M|PT, seq16, ts32, ssrc32]
[ 8B RFC 8285 Ext: 0xBE 0xDE 0x00 0x01 0x31 global_twcc_u16 0x00]
[AEAD Ciphertext:  inner_frame || 0..=31B random pad (0..=7B if >=1340B)]
[16B AEAD/MAC Tag]
```
- `inner_frame`:
  - Normal UDP Data: `[inner_len: u16 BE (<= 65400)] || [udp_payload]`
  - In-Band Selftest Probe: `[0xFFFE: u16 BE] || [probe_len: u16 BE (<= 1460)] || [probe_payload]` (echoed 1:1 by Ready server; never forwarded to backend).
- **Dual-SSRC Routing** (enabled automatically when DTLS 1.3 is negotiated):
  - `PT=111` (Opus 48 kHz, 960 ticks/20ms): packets smaller than jittered threshold `180..=307B`, strictly capped to **at most 1 packet per 20ms frame (`<= 50 pps`)**; talkspurt `M=1` after `>=200ms` silence.
  - `PT=96` (Video 90 kHz): all remaining and overflow packets; strict RFC 3550 `M=1` causality guarantees no packet ever reuses a closed frame's timestamp after `M=1`.
  - Independent 2048-packet RFC 6479 sliding replay rings per SSRC; shared global `0xBEDE` TWCC sequence.
- **PPPoE Anti-Fragmentation**: Default `--mtu 1488` enforces outer UDP `<= 1460B` (`IPv4 <= 1488B < 1492B PPPoE`); oversized inner packets are dropped cleanly to converge inner QUIC DPLPMTUD.

### 5.2 Compound SRTCP Wire Frame (RFC 3550 §6.1 / RFC 7714 §9.1)
```text
[8B Plaintext Header: V=2,RC=0|1, PT=200(SR)|201(RR), len, report_ssrc]
[Encrypted Body: Primary remainder + SDES(PT=202, 13B session-constant CNAME + 0x00 END)
                 + randomized FB(PT=205/206) + optional trailing BYE(PT=203)]
[16B AEAD/MAC Tag]
[4B E_SRTCP_Index: 0x8000_0000 | idx (0-based)]
```
- 64-packet sliding anti-replay window; in dual-SSRC mode, `report_ssrc` accurately reflects active Audio/Video sending SSRC.

---

## 6. Lifecycle, Resilience & Zero-Downtime Rolling Mechanisms

1. **Asymmetric Uplink Blackhole Self-Healing**: Client validates uplink solely via RFC 7675 STUN Binding Success (`5s ± 20%`). Missed replies retransmit the exact same `txid` (`1.1s -> 1.6s -> 2.0s`; damped to 4 retries if rotated within 60s). Confirmed blackholes move the old socket to a 35s receive-only `Closing` drain (Make-Before-Break downlink SRTP delivery, zero WAN TX, zero ICMP bounce) while opening a fresh 5-tuple; server silently reaps old sessions after 30s (`PEER_CONSENT_TIMEOUT`).
2. **Graceful Shutdown (`SIGTERM`/`SIGINT`, `v0.3.7`)**: Server and client broadcast encrypted `SRTCP BYE + DTLS close_notify` to all active sessions before exiting. Active clients reconnect on a fresh 5-tuple immediately, cutting server restart recovery from ~5–7s down to ~0.5–0.8s.
3. **Proactive Make-Before-Break Scheduled Rotation (`--rotate-interval <SECS>`, `v0.3.7`)**: When enabled (`> 0`), client pre-establishes a standby 5-tuple in the background (with `±20%` jitter), atomically cuts over on `Ready` with **0ms stall and 0 packet loss**, sends `SRTCP BYE` on the old tuple, and drains in-flight downlink SRTP for 5s.
4. **Known Scope Boundaries**: `webrtc-cloak` is a transparent UDP transport wrapper (not a TCP/TUN VPN), cannot bypass networks blocking 100% of UDP egress, and carries pure-Rust `dimpl` JA4D stack characteristics distinct from C++ BoringSSL.
