# WebRTC-Cloak Protocol Specification (`V4.0` / `v0.4.2`)

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
  - V4 In-Band 1-RTT Path Challenge/Response/Confirm: `[0xFFFD: u16 BE] || [len] || [0x01|0x02|0x03 || nonce(8B) || optional epoch_be(8B)]`.
  - V4 In-Band MBB Atomic Backend Handover: `[0xFFFC: u16 BE] || [len] || [0x01 || old_ufrag_len || old_ufrag || HKDF-SHA256(old_skey, new_skey, "handover-v4")]` (and server ack `[0x02 || 0x01|0x00]`).
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
- **Strict RFC 3550 §6.4 Zero-Media Semantics (`v0.3.8`)**: `RC=1` and `PT=205/206` feedback subpackets are emitted **only** when media packets were actually received since the previous RTCP report; zero-media intervals emit minimal 52B `RR(RC=0) + SDES`.

---

## 6. Lifecycle, Resilience & Zero-Downtime Rolling Mechanisms

1. **Asymmetric Uplink Blackhole 1-RTT ICE Path Migration & Trickle Control-Plane Backoff (`V4.0`)**:
   - Client validates uplink solely via RFC 7675 STUN Binding Success (`5s ± 20%` during active traffic, conservatively backed off to `10–14s` during idle/trickle `< 4 KB / 15s`, snapping back immediately on data burst).
   - Missed replies retransmit the exact same `txid` (`1.1s -> 1.6s -> 2.0s`; damped to 4 retries if rotated within 60s).
   - On confirmed blackhole, client preserves its DTLS-PFS `session_key`, `SrtpCloakCipher` monotonic sequence state, and `ufrag`, moves the old socket into a **50s** silent receive-only drain pool (`old_path_drains`, zero ICMP bounce), and performs **1-RTT RFC 8445 ICE path migration** on a fresh 5-tuple using a standard `STUN Binding Request (USE-CANDIDATE)` signed with per-session `mi_key_mig = HKDF-SHA256("webrtc-cloak-v4-salt", session_key, "ice-pwd-v4")` (blocking global-PSK hijacking).
   - Server validates `mi_key_mig` + 64-bit `tie_breaker` + `SeenTxidCache` (capped at `<= 4` challenges/sec per session, bounded 4-slot per-session candidate table reusing `(nonce, epoch)` idempotently for reordered STUNs) and replies with `64B STUN Success` + unpadded encrypted `57B 0xFFFD` Challenge (`121B <= 1.32x` anti-reflection bound) **without touching `token_by_peer`, switching downlink, or moving multi-worker ownership until the candidate echoes the encrypted `0xFFFD` Response**. Once verified, server atomically updates `peer_addr` (keeping the exact same `backend_sock` / `backend_lport`, even across Linux `SO_REUSEPORT` workers via bounded `4096`-cap cross-worker queues!) and drains old-path ECMP-reordered uplink for 5s without rolling back `path_epoch`. Automatic fallback to fresh STUN+DTLS preserves both rolling-upgrade compatibility with `v0.3.8` servers and buffered `pending` app packets.
   - During idle/trickle (`< 4 KB / 15s`), client SRTCP backs off to `20–40s`, and server SRTCP backs off to `20–40s` before pausing unsolicited reports after 60s of pure trickle.
2. **Graceful Shutdown (`SIGTERM`/`SIGINT`, `v0.3.7` / hardened `v0.3.8`)**: Server and client register `mio::Waker` handles for sub-millisecond `SIGTERM` wakeup and broadcast encrypted `SRTCP BYE + DTLS close_notify` to all active sessions before exiting. Active clients defer reconnect by a jittered **`80–350ms`** (buffering arriving app packets) to clear `systemd` restart bind gaps without triggering plaintext `ICMP Port Unreachable`.
3. **Proactive Make-Before-Break Scheduled Rotation with Encrypted `0xFFFC` Backend Handover (`--rotate-interval` / `--rotate-bytes`, `V4.0`)**:
   - Uses a **complete fresh DTLS 1.3 handshake** with brand-new unlinkable `ufrag`, `SSRC`, `CNAME`, and ECDHE PFS `session_key` (never reusing plaintext identifiers across scheduled rotations).
   - Before promoting the standby session, client sends an encrypted in-band `0xFFFC` handover frame carrying `old_ufrag` and `HKDF-SHA256(old_session_key, new_session_key, "handover-v4")` (4 × 380ms retries). Server verifies the proof in constant time (single-use per old session, idempotent on retransmit) and atomically transfers exclusive ownership of `old_sess`'s live `backend_sock` (`BackendPipe::Owned` → `ForwardLocal`/`ForwardRemote`, chained forwarding up to 4 hops, zero `dup()` races, works across Linux `SO_REUSEPORT` workers) so **even strict source-port-pinned UDP backends see 0 port changes and 0 packet loss**. All `0xFFFD`/`0xFFFC` control frames account into SRTP `tx_pkts`/`rx_pkts` for strict RFC 3550 RTCP causality.
   - Dual triggers: right-skewed **log-normal duration** (`[0.35x, 2.80x]` around `--rotate-interval`) AND randomized **single-session byte-volume budget** (`--rotate-bytes`, default `1200 MiB` → `600–2220 MiB`, 60s cooldown), suspended during background trickle (`< 64 KB / 5 min`, 5–8h fallback cap).
   - Tracks explicit `standby_for_primary` ownership, cancels orphan standbys on primary failure/restart/close, and delays old-session `BYE` by randomized **2–10s** (`DrainingBeforeBye`) + 1s post-BYE client drain + 250ms server `Closing` downlink flush.
4. **Decoupled Outer Health Telemetry (`--status-file` / `--status-http`, `v0.4.1`)**:
   - Exposes real outer link quality (STUN RTT / EWMA / RFC 3550 jitter / rolling 20-probe loss %, smoothed Mbps throughput, 10-minute blackhole & 1-RTT migration counts, MBB handover counters, and server unauthenticated silent-drop scan counters) strictly off the SRTP hot path.
   - Available simultaneously via atomic `tmp + rename` JSON file (`--status-file`, powered by `serde_json`) and/or a lightweight read-only HTTP listener (`--status-http`, powered by pure-Rust `tiny_http` serving JSON on `/`, `/status`, `/health`, `/healthz` with `503` on critical, and Prometheus exposition text on `/metrics`), enabling external controllers or adaptive inner protocols to react to outer path degradation without coupling to tunnel internals.
5. **Known Scope Boundaries**: `webrtc-cloak` is a transparent UDP transport wrapper (not a TCP/TUN VPN), cannot bypass networks blocking 100% of UDP egress, cannot erase single-tenant `(src_ip, dst_ip)` macro NetFlow correlation on a single server, and carries pure-Rust `dimpl` JA4D stack characteristics distinct from C++ BoringSSL.
