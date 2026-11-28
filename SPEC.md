# WebRTC-Cloak Protocol Specification (`V4.0` / `v0.8.0`)

This document specifies the wire format, cryptographic schedule, state machine, operating topologies, embedded proxy architecture, zero-decrypt passthrough & `SIGHUP` hot-switch semantics, SIMD dispatch invariants, and security boundaries of `webrtc-cloak-rs`.

> **Wire Compatibility Note (`v0.8.0`)**: `v0.8.0` is **100% wire-compatible with `v0.7.0` and `v0.7.1`** and can be upgraded independently. Relative to `v0.6.x`, `v0.7+` introduced breaking wire & key-domain upgrades — endpoint-scoped STUN HKDF, per-session DTLS-PFS `mi_key_mig` Ready keepalives, dynamic multi-element `24B/28B` RFC 8285 RTP headers, RFC 3550 `P=1` (`0xB0`) SRTP padding, and default `--dtls-min-version 1.3` (`V13Only`) — so upgrades from `v0.6.x` require updating both endpoints together.

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

## 2. ICE STUN Authentication, Scoping & Freshness (`v0.7.0`)

### 2.1 Endpoint-Scoped STUN HKDF Key
To prevent cross-port and cross-mode (`cloak` vs `bypass`) STUN capture replay, initial STUN authentication keys are derived via RFC 5869 HKDF-SHA256 instead of raw PSK:
```text
scope_tag = explicit --stun-scope <TAG> (or listen/target port in decimal if unset)
domain    = "bypass:" if bypass mode else "cloak:"
stun_psk  = HKDF-SHA256(
    salt = "webrtc-cloak-v7-stun-salt",
    ikm  = psk,
    info = "webrtc-cloak-v7:stun-scope:" || domain || scope_tag
)
```
- `MESSAGE-INTEGRITY` HMAC-SHA1 key for initial handshake/hunt probes: `SHA256("webrtc-cloak:stun-mi:" || stun_psk)`.
- Deployments behind DNAT / Docker / `nftables` port forwarding (where client destination port differs from server listen port) pass matching `--stun-scope <TAG>` (or `--upstream-stun-scope <TAG>` on `relay`).

### 2.2 Transaction ID (`txid`, 12 bytes) & Freshness
- `txid[0..8]`: 8 random bytes from OS CSPRNG.
- `txid[8..12]`: `unix_secs_u32_be ^ SHA256("webrtc-cloak:txid-ts:" || stun_psk || txid[0..8])[0..4]`.
- Server accepts Binding Requests only if `|now - unix_secs| <= 10s` (tightened from `±30s` in `v0.6`) **after** `MESSAGE-INTEGRITY` verification passes.

### 2.3 Attributes, RFC 8445 Regular Nomination & Anti-Replay
- **Cloak Request attributes** (libwebrtc order): `USERNAME` (Chrome `4:4` Base64 `ufrag_r:ufrag_l`, matching the Chrome/BoringSSL DTLS persona), `ICE-CONTROLLING` (mandatory 64-bit session-constant `tie_breaker`), optional `USE-CANDIDATE` (present **only** on initial session nomination and 1-RTT path migration; omitted on `--lane-hunt` connectivity checks and keepalives), `PRIORITY` (RFC 8445 host priority `(126 << 24) | ((0xFFFF - candidate_idx) << 8) | 0xFF`), `MESSAGE-INTEGRITY` (20B HMAC-SHA1), and mandatory trailing 8B `FINGERPRINT` (`CRC-32 ^ 0x5354554E`).
- **Bypass Request attributes** (`bypass` mode): minimal `68B` RFC 5389 authenticated Binding Request (`USERNAME + MESSAGE-INTEGRITY + FINGERPRINT`, omitting WebRTC-only ICE attributes), isolated under the `bypass:` HKDF domain and sharing one `SessionIceParams` across parallel hunt probes.
- Zero heap allocation occurs before constant-time HMAC-SHA1 and FINGERPRINT verification succeed. Any attribute after `MESSAGE-INTEGRITY` other than an exact trailing 8B `FINGERPRINT` is rejected.
- **Tightened `SeenTxidCache` (pre-DTLS only)**: Bounded FIFO (`65,536` entries, `90s` TTL) permits same-peer idempotent retransmits for at most **`2.5s` and `2` retries** exclusively during initial pre-DTLS STUN setup. As soon as DTLS begins, the initial `txid` is permanently burned (`invalidate()`).
- **Per-Session DTLS-PFS `Ready` Keepalives**: Once a session reaches `Ready`, RFC 7675 consent keepalive requests **and** responses are authenticated with per-session `mi_key_mig` (derived from DTLS-PFS `session_key`, never static PSK), using a fresh `txid` on every retry (`0` cached retransmits in `Ready`). This prevents both post-`SIGKILL` server-restart false-64B zombie replies and `>90s` post-close keepalive replay.
- **`HuntUfragTable` Tombstones**: Parallel `--lane-hunt` candidates share one `ufrag` and `tie_breaker`, probing with `USE-CANDIDATE=false` and nominating only the winning 5-tuple with `USE-CANDIDATE=true`. Server enforces mandatory `ICE-CONTROLLING`, allows unnominated probes only from the same source IP within **`4s`** (max `16` probes), retains unnominated tombstones for **`20s`** (`> ±10s` STUN skew so delayed replays cannot delete-and-reinsert), and retains locked/post-close (`unregister_session`) tombstones for **`90s`**.

---

## 3. DTLS 1.3 / 1.2 Handshake, BoringSSL Wire Parity & Pre-Validation (`v0.7.0`)

- Implemented with a vendored, hardened pure-Rust Sans-IO **`dimpl 0.9.0`** (`webrtc-cloak-rs/patches/dimpl`) using mutual rotating ephemeral self-signed ECDSA P-256 certificates (`CN=WebRTC`, 20–24h per-worker cache).
- **Default `--dtls-min-version 1.3` (`DtlsMinVersion::V13Only`)**: Calls `Dtls::new_13`, completely disabling DTLS 1.2 fallback to eliminate 1-byte MITM downgrade attacks and plaintext `CN=WebRTC` certificate exposure. Explicit `--dtls-min-version auto` (`Dtls::new_auto`) retains RFC 8446 §4.1.3 `DOWNGRD\x01` downgrade sentinel protection.
- **0% `HelloRetryRequest` & 0% `EXT_PADDING (0x0015)`**: Because ICE STUN already authenticates the peer 5-tuple and prevents amplification, the server responds with a 1-RTT direct `ServerHello` (0% HRR), and `ClientHello` omits `0x0015` zero-padding blobs. Client `DtlsConfigPool` uses a single consistent per-process MTU (pool size = 1).
- **Chrome/BoringSSL `ClientHello` Wire Parity** (unified across `V13Only` and `auto`):
  - Cipher suites: `[GREASE, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014]`.
  - `use_srtp` profile order: `[0x0007, 0x0008, 0x0001]`.
  - RFC 8701 GREASE in cipher suites, `supported_versions`, `supported_groups` + matching `key_share`, plus **BoringSSL-pinned GREASE extension bookends**: `exts[0]` = empty GREASE, `exts[last]` = 1B `0x00` GREASE, with Fisher-Yates randomization applied strictly to interior extensions.
- **RFC 9147 §4.2 Inner Ciphertext Padding**: Randomized inner plaintext padding is applied to DTLS 1.3 `Handshake`, `Ack`, and `Alert` records, eliminating fixed Flight-4 (`709B`), Flight-5 (`506B`), Server ACK (`72B`), and `close_notify` (`24B`) length fingerprints.
- **Pre-Validation & Spoof/Corruption Resilience**:
  - `validate_dtls_datagram(pkt, ready_only_alert)` validates RFC 9147 Unified Ciphertext (`001C_SL_EE`, `C=0`, `rec_len >= 18`) and plaintext-framed records (`20..=23`, `26` only at `epoch=0` during handshake; rejects `epoch=0` Alert and `Ready`-state plaintext `ct=26`).
  - Partial-handled coalesced Flight-4 records preserve missing trailing handshake messages (e.g., `Finished`) across retransmissions; server requires `record_seq == 0` (`pkt[5..11] == [0; 6]`) before accepting `is_fresh_epoch0_ch` resets and silently drops invalid handshake records per RFC 9147 §4.5.2; client `enable_peer_encryption()` detects poisoned `ServerHello` (`hs_decrypt_failures >= 3`) for `< 9ms` fail-fast reset.
  - Client drives `dtls_next_timeout` inside `Ready` state so a dropped DTLS 1.3 Flight 5 retransmits at ~350ms RTO; server never refreshes `last_peer_rx` from DTLS packets in `Ready` state.

---

## 4. Key Schedule & Orthogonal AEAD Nonce Domains

### 4.1 Fail-Closed Hybrid PFS
1. `seed = "webrtc-cloak-v3|" || stun_psk || "|" || stun_txid || "|" || username`
2. `stun_key = SHA256(seed || "|stun-key")` (32B)
3. `ssrc_c2s = BE32(SHA256(seed || "|ssrc")[0..4])`, `ssrc_s2c = BE32(SHA256(seed || "|ssrc")[4..8])`
4. `dtls_km` = 64B RFC 5764 `EXTRACTOR-dtls_srtp` keying material (mandatory non-empty when DTLS is enabled — **Fail-Closed**).
5. `session_key = SHA256("webrtc-cloak-v3|pfs-bind|" || stun_key || "|dtls-km|" || dtls_km)` (32B)
6. `enc_key = SHA256(session_key || "|enc")`, `mac_key = SHA256(session_key || "|mac")`, `gcm_salt = enc_key[16..20]`.
7. `audio_ssrc = SHA256("webrtc-cloak-v3-audio-ssrc|" || session_key || BE32(video_ssrc))[0..4]`, constrained so `audio_ssrc != 0` and `(audio_ssrc >> 16) != (video_ssrc >> 16)`.
8. Per-session ICE/keepalive key: `mi_key_mig = HKDF-SHA256("webrtc-cloak-v4-salt", session_key, "ice-pwd-v4")`.

### 4.2 Orthogonal 96-bit AEAD Nonce Layout
```text
iv[0..4]  = gcm_salt ^ [domain_dir, 0, 0, 0]
iv[4..6]  = ssrc[31:16]
iv[6..8]  = ssrc[15:0] ^ ext_seq[47:32]
iv[8..12] = ext_seq[31:0]
```
- **Video SRTP (`PT=96`)**: `domain_dir = dir` (`0x00` C2S / `0x01` S2C), `ssrc = video_ssrc`.
- **Audio SRTP (`PT=111`, DTLS 1.3 dual-SSRC)**: `domain_dir = dir | 0x40` (`0x40` / `0x41`), `ssrc = audio_ssrc` (high-16-bit disjoint from `video_ssrc`).
- **Compound SRTCP**: `domain_dir = dir | 0x80` (`0x80` / `0x81`), `ext_seq = srtcp_idx` (0-based 31-bit index).
- Exhaustion ceilings (`MAX_SRTP_EXT_SEQ = 0xFFFF_FFFF_FF00`, `MAX_SRTCP_IDX = 0x7FFF_FF00`) trigger proactive rekeying; sequence numbers never wrap.

---

## 5. Dual-SSRC SRTP, Compound SRTCP & Encrypted In-Band Frames (`v0.7.0`)

### 5.1 SRTP Wire Frame
```text
[12B RTP Header: 0x90 (P=0) or 0xB0 (P=1, ~12.5% when pad_len >= 4), M|PT, seq16, ts32, ssrc32]
[12B or 16B RFC 8285 One-Byte Ext (0xBE 0xDE, 2 or 3 32-bit words; falls back to 8B TWCC-only near MTU):
   - Video PT=96: ID=2 abs-send-time (3B) + ID=3 TWCC (2B) (24B total) [+ ID=4 sdes:mid (1B) -> 28B on start/talkspurt]
   - Audio PT=111: ID=1 ssrc-audio-level (1B) + ID=3 TWCC (2B) [+ ID=4 sdes:mid (1B)] (24B total)]
[AEAD Ciphertext: inner_frame || random_pad (if P=1, final byte = pad_len)]
[16B AEAD/MAC Tag]
```
- **RFC 3550 `P=1` (`0xB0`) Padding & Dynamic Widening**:
  - When `pad_len >= 4`, ~12.5% of SRTP packets set `P=1` (`0xB0`, mixed with `0x90`) with the trailing pad-count byte per RFC 3550 §5.1.
  - Standard packets receive `0..=63B` random padding; large packets (`>= 1340B`) narrow to `0..=7B`; tiny packets (`< 160B`, e.g., high-rate QUIC ACKs) spilled into Video SSRC (`PT=96`) widen smoothly (up to `1040B` cap, clamped by WAN MTU) to eliminate `< 89B` video-stream spikes.
- `inner_frame` (first 2 bytes BE act as length for data `<= 65400`, or reserved magic `>= 0xFFFA` inside AEAD ciphertext):
  - **Normal UDP Data**: `[inner_len: u16 BE (<= 65400)] || [udp_payload]`
  - **`0xFFFE` In-Band Selftest Probe**: `[0xFFFE: u16 BE] || [probe_len: u16 BE (<= 1460)] || [probe_payload]` (echoed 1:1 by Ready server; never forwarded to backend; never emitted by idle `PreWarm` or `proxy` sessions).
  - **`0xFFFD` V4 1-RTT Path Challenge/Response/Confirm**: `[0xFFFD: u16 BE] || [len] || [0x01|0x02|0x03 || nonce(8B) || optional epoch_be(8B)]` (unpadded server challenge = `24B RTP + 4B ctrl + 17B body + 16B tag = 61B`).
  - **`0xFFFC` V4 MBB Atomic Handover**: `[0xFFFC: u16 BE] || [len] || [0x01 || old_ufrag_len || old_ufrag || HKDF-SHA256(old_skey, new_skey, "handover-v4")]` (and server ack `[0x02 || 0x01|0x00]`).
  - **`0xFFFB` Reverse Tunnel Multiplexed Data**: `[0xFFFB: u16 BE] || [payload_len: u16 BE (<= 65396)] || [flow_id: u32 BE] || [udp_payload]` (used exclusively by `webrtc-cloak reverse --entry | --agent`).
  - **`0xFFFA` Reverse Tunnel Control**: `[0xFFFA: u16 BE] || [ctrl_len: u16 BE] || [opcode: u8 || body]` (`0x01 REV_OP_HELLO`, `0x02 REV_OP_HELLO_ACK`, `0x03 REV_OP_FLOW_CLOSE`).
- **Dual-SSRC Routing & Quantized Video Clock**:
  - `PT=111` (Opus 48 kHz, 960 ticks/20ms): packets smaller than jittered threshold `180..=307B`, strictly capped to **at most 1 packet per 20ms frame (`<= 50 pps`)**; talkspurt `M=1` after `>= 200ms` silence.
  - `PT=96` (Video 90 kHz): all remaining and overflow packets. Video timestamps quantize to realistic **30/60 FPS** (`3000` / `1500` ticks ± `180` jitter, strictly `min_dt >= 1320` ticks `<= 68 FPS`, `0.00%` `>200 FPS` spikes), with randomized per-frame packet caps (`18..=56` for large-packet frames, `6..=19` for small-packet overflow frames, hard cap `<= 60` pkts/frame; eliminates mechanical 3-packet micro-frames) and strict RFC 3550 `M=1` causality.
  - Independent 2048-packet RFC 6479 sliding replay rings per SSRC; shared global `0xBEDE` TWCC sequence.
- **PPPoE Anti-Fragmentation (IPv4 & IPv6)**: Default `--mtu 1488` enforces outer UDP `<= 1460B` on IPv4 (28B IPv4+UDP header) and `<= 1440B` on IPv6 (48B IPv6+UDP header, `< 1492B` PPPoE); STUN `XOR-MAPPED-ADDRESS` implements RFC 5389 §15.2 for both IPv4 (`64B` total reply) and IPv6 (`76B` total reply).

### 5.2 Compound SRTCP Wire Frame (RFC 3550 §6.1 / RFC 7714 §9.1)
```text
[8B Plaintext Header: V=2,RC=0|1, PT=200(SR)|201(RR), len, report_ssrc]
[Encrypted Body: Primary remainder + SDES(PT=202, 13B session-constant CNAME + 0x00 END)
                 + randomized FB(PT=205/206) + optional trailing BYE(PT=203)]
[16B AEAD/MAC Tag]
[4B E_SRTCP_Index: 0x8000_0000 | idx (0-based)]
```
- 64-packet sliding anti-replay window; in dual-SSRC mode, `report_ssrc` accurately reflects active Audio/Video sending SSRC.
- **Strict RFC 3550 §6.4 Zero-Media Semantics**: `RC=1` and `PT=205/206` feedback subpackets are emitted **only** when media packets were actually received since the previous RTCP report; zero-media intervals emit minimal 52B `RR(RC=0) + SDES`.
- **Symmetric Long-Trickle RTCP**: During idle/trickle (`< 4 KiB / 15s`), both client and server back off SRTCP to `20–40s`, and beyond `60s` of pure silence both endpoints symmetrically emit ultra-low-frequency `25–45s` `RR(RC=0) + SDES` (avoiding "live STUN with 0 RTCP" asymmetry).

---

## 6. Lifecycle, Resilience & Zero-Downtime Rolling Mechanisms

1. **Asymmetric Uplink Blackhole 1-RTT ICE Path Migration & Crash Recovery (`V4.0` / `v0.7.0`)**:
   - Client validates uplink solely via RFC 7675 STUN Binding Success (`5s ± 20%` during active traffic, backed off to `10–14s` during idle/trickle `< 4 KiB / 15s`, snapping back immediately on data burst), authenticated in `Ready` state by per-session `mi_key_mig` with a fresh `txid` per retry (`1.1s -> 1.6s -> 2.0s`).
   - Even when `--keepalive 0` is configured, client tracks `last_auth_dl_rx` + `tx_pkts_since_dl_rx` (`dl_deadlock` guard) to detect silent server `SIGKILL` crashes and re-establish automatically.
   - On confirmed blackhole, client preserves its DTLS-PFS `session_key`, `SrtpCloakCipher` monotonic sequence state, and `ufrag`, moves the old socket into a **50s** silent receive-only drain pool (`old_path_drains`, zero ICMP bounce), and performs **1-RTT RFC 8445 ICE path migration** on a fresh 5-tuple using `STUN Binding Request (USE-CANDIDATE)` signed with `mi_key_mig`.
   - Server validates `mi_key_mig` + 64-bit `tie_breaker` + `SeenTxidCache` (capped at `<= 4` challenges/sec per session, bounded 4-slot per-session candidate table reusing `(nonce, epoch)` idempotently for reordered STUNs) and replies with `64B STUN Success` + unpadded encrypted `61B 0xFFFD` Challenge (`125B <= 1.36x` anti-reflection bound) **without touching `token_by_peer`, switching downlink, or moving multi-worker ownership until the candidate echoes the encrypted `0xFFFD` Response**. Once verified, server atomically updates `peer_addr` (keeping the exact same `backend_sock` / `backend_lport`, even across Linux `SO_REUSEPORT` workers via bounded `4096`-cap cross-worker queues) and drains old-path ECMP-reordered uplink for 5s without rolling back `path_epoch`.
2. **Async Graceful Teardown (`BYE -> close_notify`, `v0.7.0`)**:
   - Runtime closes send encrypted `SRTCP BYE` immediately and schedule `DTLS close_notify` after an asynchronous randomized **`18..=95ms`** timer; `SIGTERM`/`SIGINT` handlers (async-signal-safe `sigaction` self-pipe on Unix, `ctrlc` + `mio::Waker` on Windows) separate `SRTCP BYE` and `DTLS close_notify` by **`22..=65ms`**, eliminating `< 0.1ms` paired teardown packet fingerprints. Active clients defer reconnect by jittered `80–350ms` while buffering arriving app packets.
3. **Proactive Make-Before-Break Scheduled Rotation with Encrypted `0xFFFC` Handover (`--rotate-interval` / `--rotate-bytes`)**:
   - Uses a **complete fresh DTLS 1.3 handshake** with brand-new unlinkable `ufrag`, `SSRC`, `CNAME`, and ECDHE PFS `session_key`.
   - Before promoting the standby session, client sends an encrypted in-band `0xFFFC` handover frame carrying `old_ufrag` and `HKDF-SHA256(old_session_key, new_session_key, "handover-v4")` (4 × 380ms retries). Server verifies the proof in constant time (single-use per old session, idempotent on retransmit) and atomically transfers exclusive ownership of `old_sess`'s live backend pipe (`BackendPipe::Owned`, `RelayDirect`, `ReverseAgent`, or `ProxyServer` without firing `NewConnection`), ensuring **0 backend port changes and 0 packet loss**.
   - Dual triggers: right-skewed **log-normal duration** (`[0.35x, 2.80x]` around `--rotate-interval`) AND randomized **single-session byte-volume budget** (`--rotate-bytes`, default `1200 MiB` → `600–2220 MiB`, 60s cooldown), suspended during background trickle (`< 64 KiB / 5 min`, 5–8h fallback cap).
   - Delays old-session `BYE` by randomized **2–10s** (`DrainingBeforeBye`) + 1s post-BYE client drain + 250ms server `Closing` downlink flush.
4. **Non-Blocking ECMP Multi-Metric Adaptive Lane Hunting (`--lane-hunt`)**:
   - Uses RFC 8445 regular nomination (shared Chrome `ufrag`/`tie_breaker`, decremented `PRIORITY`, `USE-CANDIDATE=false` probes → `USE-CANDIDATE=true` winner).
   - **Scale-Invariant Cold-Start Calibration (`--lane-target-rtt 0`)**: Probes across `>= 2` staggered STUN rounds (`--lane-probes`, default `4`, up to 3 rounds for background `PreWarm`), pre-warms DTLS 1.3 to `Ready`, and hands off at 0ms on the first local packet. Unused `PreWarm` sessions are exempt from data-idle timeout (bound only by 45s ICE consent), emitting **0 `0xFFFE` keepwarm beacons**.
   - **Zero-Overhead Multi-Metric Lane Scoring & Canary Confirmation**: Computes a scale-invariant `0–100` score from relative RTT, real downlink SRTP settled packet loss (`rx_settled_stats()`, excluding 24-pkt reorder tail), STUN consent loss, and jitter, triggering 0ms MBB `0xFFFC` handovers on degradation/optimization.
5. **Decoupled Outer Health Telemetry (`--status-file` / `--status-http`)**:
   - Exposes real outer link quality (STUN RTT/EWMA/jitter/loss, SRTP downlink `data_loss_pct`, `lane_score`, Mbps throughput, blackhole/migration/MBB/lane-hunt counters, and silent-drop scan counters) off the SRTP hot path across all roles (`client`, `server`, `relay`, `reverse-entry`, `reverse-agent`, `proxy-client`, `proxy-server`, `bypass`, `bypass-responder`) via atomic JSON (`--status-file`) and/or a single-thread `mio::Poll` read-only HTTP / Prometheus listener (`--status-http`).

---

## 7. Operating Topologies & Transport Modes (`v0.5.0`–`v0.8.0`)

### 7.1 Out-of-Band ECMP Lane-Hunting Raw UDP Bypass (`webrtc-cloak bypass`, non-DPI only)
- Shares a single UDP 5-tuple between minimal `68B` authenticated RFC 5389 STUN probes (isolated under `bypass:` HKDF domain) and raw unframed inner UDP payloads (e.g., QUIC / WireGuard).
- Delivers zero payload overhead, zero double-encryption, and full kernel `UDP_SEGMENT` (UDP GSO) compatibility for non-DPI ECMP lane hunting, seamless NAT-rebinding port migration (3s drain overlap), and blackhole escape. Companion `bypass --responder` serves ultra-lightweight STUN replies.

### 7.2 Native Single-Process Zero-Loopback Relay (`webrtc-cloak relay`, `v0.6.0`–`v0.8.0`)
- Supports four single-thread `mio::Poll` relay modes:
  - **`passthrough` (`v0.8.0`, Zero-Decrypt L4 UDP Pass-Through)**: Pure L4 IPv6↔IPv4 UDP forwarding with **zero decryption/encryption and zero PSK requirement** (`--psk` optional), `recvmmsg`/`sendmmsg` batching (`--udp-batch`), idle session GC, and bounded LRU eviction (`--max-sessions`). Pins one dedicated connected upstream UDP socket per client source `SocketAddr`, preserving end-to-end client↔exit DTLS 1.3 + Dual-SSRC SRTP, `--lane-hunt` multi-port probing, and 0ms MBB rotation through the relay.
  - **`bypass` / `cloak` / `reverse`**: Fuses ingress `ServerWorker` (Leg 1 DTLS 1.3 + SRTP termination) and egress `BypassWorker`, `ClientWorker`, or reverse-listening `ServerWorker` inside a single `mio::Poll` loop (`SharedPoll`) with zero localhost loopback sockets, independent ingress/egress PSKs (`--upstream-psk[-file]`), independent STUN scopes (`--upstream-stun-scope`), independent cipher suites/DTLS minimums, and full `0xFFFC`/`0xFFFD` self-healing.
- **Zero-Downtime `SIGHUP` Hot-Switching (`--hot-config <PATH>`, `v0.8.0`)**:
  - Uses an async-signal-safe Unix `SIGHUP` self-pipe (`RELOAD_PIPE_TOKEN = Token(usize::MAX - 2)`) and zero-dependency `key=value`/flat-JSON config loader (`src/hot_reload.rs`) without ever closing the bound ingress UDP socket.
  - Supports seamless `AB` dual-mode draining via `RelayPassthroughPolicy` (`Disabled`, `DrainExistingOnly`, `PreferPassthrough`, `FallbackOnUnauth` / `--passthrough-fallback`) using disjoint `mio::Token` space (`PASSTHROUGH_TOK_BASE`): transitioning `cloak → passthrough` drains existing tracked `cloak` sessions to completion while immediately forwarding new client flows via zero-crypto `passthrough`, then automatically sheds `ServerWorker` + `DtlsConfigPool` once old sessions hit zero; transitioning `passthrough → cloak/bypass` drains existing passthrough flows while accepting new `cloak`/`bypass` handshakes on the same port.

### 7.3 Native L4 UDP Reverse Tunnel Mode (`webrtc-cloak reverse --entry | --agent`)
- Enables NAT-traversal exposure of arbitrary L4 UDP services with **zero inbound ports** on the Agent side:
  - **Entry (`reverse --entry`)** binds a public WebRTC tunnel port (`--listen-host:--listen-port`) and exposed UDP port (`--expose-host:--expose-port`) within one `mio::Poll` loop, multiplexing external peer 5-tuples by `flow_id: u32` inside encrypted `0xFFFB` frames (buffering up to 64 packets / 3s TTL while Agent connects).
  - **Agent (`reverse --agent`)** dials outbound to Entry immediately, registers via `0xFFFA REV_OP_HELLO`, maintains a persistent idle-exempt tunnel (still bound by 45s ICE consent) with 24×7 self-healing, MBB `0xFFFC` handover, and 1-RTT migration, and pins one dedicated backend UDP socket per `flow_id` (evicted on `--idle-timeout` with `0xFFFA REV_OP_FLOW_CLOSE`).

### 7.4 Optional Zero-Loopback Embedded Hy2-Like Proxy (`webrtc-cloak proxy`, `v0.7.0`)
- Controlled by Cargo feature `embedded-proxy` (enabled by default; omit via `--no-default-features` to build a minimal pure-UDP binary without `quinn-proto` / `bytes`).
- **In-Process Zero-Double-Encryption Architecture**: Embeds Sans-IO `quinn-proto` directly inside the same single-thread `mio::Poll` loop as the outer WebRTC-Cloak worker (zero localhost loopback sockets). Inner QUIC uses a custom **No-op crypto provider** (`tag_len == 0`, zero `rustls`, zero inner AEAD overhead); confidentiality, authenticity, and PFS are provided exclusively by the outer WebRTC-Cloak DTLS 1.3 + SRTP layer. *(Because inner QUIC is unencrypted, `proxy` strictly requires encrypted WebRTC-Cloak outer transport and is incompatible with `bypass`.)*
- **Congestion Control & Inner Wire Framing**:
  - Control stream opens with 19B `CtrlHello` (`0x57 0x43 0x01 || up_bps: u64 BE || down_bps: u64 BE`), negotiating Hysteria 2-style **Brutal** loss-compensated constant-rate pacing clamped by server `--max-up` / `--max-down` (client defaults `100Mbps`/`300Mbps`, server cap `500Mbps`).
  - Bidirectional TCP streams prefix RFC 1928 target address framing (`0x01 || ATYP || ADDR || PORT`) and receive 1B status (`0x00 OK`, `0x01 ACL_DENIED`, `0x02 CONNECT_FAILED`).
  - UDP traffic rides over RFC 9221 unreliable **QUIC Datagrams** with automatic fragmentation and bounded reassembly (`64` entries, `2s` TTL).
- **Ingress, Egress & Security Controls**:
  - Client (`proxy --client`) exposes local SOCKS5 (`TCP CONNECT` + `UDP ASSOCIATE`, default `127.0.0.1:19548`, disable via `--no-socks`) and repeatable L4 TCP port forwards (`--tcp-forward LOCAL=TARGET`).
  - Server (`proxy --server`) performs non-blocking `mio` TCP/UDP egress backed by a 2-thread async DNS resolver pool and post-DNS CIDR ACL (`--acl-allow`, `--acl-deny`, private/loopback IPs rejected by default unless `--allow-private`, optional `--outbound-ipv4-only`).
- **Forward & Reverse Topologies (`--reverse`)**:
  - Forward: `proxy --client` dials `proxy --server`.
  - Reverse (NAT-to-NAT / zero inbound port on exit): `proxy --client --reverse` listens on `--listen-host:--listen-port` while exposing local SOCKS5/`--tcp-forward`; `proxy --server --reverse` dials outbound 24×7 to the entry (or to a 3-hop `relay --upstream-mode reverse`).
- **Persistence, Orphan Cleanup, High-BDP Pacing & In-Process MBB Hot-Switch (`v0.7.0`–`v0.8.0`)**:
  - Outer tunnel runs in `persistent_tunnel` mode (exempt from data-idle teardown, emitting 0 SRTP beacons during long silence while maintaining symmetric long-trickle RTCP RR and 45s ICE consent).
  - On reverse peer `SIGKILL` + reconnect, `ServerHook::Proxy` receives `NewConnection` and immediately reaps orphaned `ServerQuicConn` and backend TCP/UDP sockets (`0` FD leaks; lossless outer MBB `0xFFFC` handovers transfer the outer pipe without emitting `NewConnection`).
  - Both `ProxyServerEngine` (DL) and `ProxyClientEngine` (UL) shape continuous bulk TCP→QUIC streams into `5..=10 * mss + 500..=979B` video-frame bursts (yielding `~10–12%` non-full frame-tail packets under bulk load with zero buffering penalty on tiny interactive writes), pipelining up to `16` strictly frame-separated bursts per pass into a shared 32-pkt `sendmmsg` batch, calibrated with Brutal `CWND_BDP_GAIN = 1.00` (matching `quinn-proto`'s 1.25× pacer to avoid `fq flows_plimit` drops) and Linux `timerfd` nanosecond wakeup (`PROXY_TIMER_TOKEN`) to eliminate sub-millisecond `epoll_wait` rounding stalls (`v0.8.0`).
  - **In-Process Make-Before-Break Hot-Switch (`proxy --client --hot-config <PATH>`, `v0.8.0`)**: On `SIGHUP`, keeps local SOCKS5 and `--tcp-forward` listeners open continuously, spawns a standby `(ClientWorker, QuicTunnel)` in an isolated 1M-token slot (`CLIENT_TOK_SLOT_STRIDE`), and waits up to `--hot-switch-timeout` (default `12s`) for end-to-end outer DTLS 1.3 + inner QUIC `CtrlHello` readiness. Upon readiness, atomically promotes standby to primary for all new TCP/UDP streams while moving the previous tunnel into a draining pool (up to 60s grace) so in-flight TCP streams complete with zero drops; on timeout or invalid config, automatically aborts and rolls back with zero disruption to live traffic.

---

## 8. Cryptographic Backends, SIMD Dispatch & Batch I/O (`v0.4.6`–`v0.7.0`)

### 8.1 Runtime SIMD Coverage Across All 16 Release Targets
- **AES-128 (`aes 0.9`)**: Runtime CPUID dispatch across x86/x86_64 (`VAES-512` → `VAES-256` → `AES-NI`, no AVX gate) and AArch64 (`ARMv8-AES`).
- **GHASH / POLYVAL (`patches/polyval`)**: Two-tier x86/x86_64 runtime dispatcher (`avx + pclmulqdq` VEX Tier 1 and `sse2 + pclmulqdq` Legacy SSE Tier 2 — accelerating non-AVX x86 CPUs with hardware `AES-NI + PCLMULQDQ`) plus 4-block aggregated `ARMv8-PMULL` on AArch64.
- **ChaCha20 (`chacha20 0.10` + `.cargo/config.toml`)**: Enables `--cfg chacha20_avx512` across x86/x86_64 targets for runtime-dispatched 16-block `AVX-512F+VL` (safely falling back to `AVX2` → `SSE2` → `soft`), plus `ARMv8-NEON` on all `aarch64` targets.
- **Poly1305 (`patches/poly1305`)**: Runtime `AVX2` on x86/x86_64, and constant-time **64-bit 3-limb `radix-2^44` (`u64` + `u128`, 9 muls/block)** across all 64-bit targets (`aarch64`, non-AVX2 `x86_64`, `riscv64`, `loongarch64`, `powerpc64le`), retaining 5-limb `radix-2^26` (`u32`) on 32-bit targets.
- **SHA-1 / SHA-2 (`sha1 0.11` / `sha2 0.11`)**: Runtime x86 `SHA-NI + SSE4.1` (no AVX gate), AArch64 `ARMv8-SHA2`/`SHA3`, and `loongarch64` assembly.
- **Ground-Truth Auto-Selection (`detect_cpu_accel`)**: Evaluates `has_hw_aes_gcm = aes::hardware_accelerated() && polyval::hardware_accelerated()` across `x86`, `x86_64`, and `aarch64`, preventing false hardware claims on platforms where upstream `cpufeatures` lacks OS probing (such as `windows-arm64`, which safely auto-selects NEON `ChaCha20-Poly1305`). `webrtc-cloak cpu` reports exact active backend identifiers.

### 8.2 Opt-In Linux UDP Batch I/O & Burst Buffers
- `--udp-batch <0|2..64>` defaults to `0` (zero extra heap allocation). When enabled on Linux (e.g., `--udp-batch 32`), all hot data-plane loops (`server`, `client`, `proxy`, `relay`, `reverse`, `bypass`) use pre-allocated zero-copy `recvmmsg`/`sendmmsg` batching across IPv4 and IPv6 while preserving strict control-frame ordering and exact telemetry counters. Non-Linux OSes safely fall back to single-packet syscalls.
- Kernel UDP socket buffers scale up to `8 MiB` on tunnel/listen/upstream sockets and `4 MiB` on per-session backend sockets, preventing `Udp: RcvbufErrors` under hypervisor scheduling pauses and multi-hop bursts with zero idle RSS penalty.

---

## 9. Known Scope Boundaries

- `webrtc-cloak` provides transparent UDP encapsulation (`client`/`server`/`relay`/`reverse`) and optional embedded SOCKS5 + L4 TCP-forward proxying (`proxy`); it is not a kernel TUN VPN.
- It cannot bypass networks that block 100% of UDP egress, and cannot erase single-tenant `(src_ip, dst_ip)` macro NetFlow/ISP volume correlation on a single server.
- `bypass` mode is strictly for non-DPI ECMP route optimization and provides no DPI obfuscation or outer payload encryption (and must not carry the unencrypted inner `proxy` transport).
- While `v0.7.0` aligns DTLS 1.3 `ClientHello`, RFC 9147 inner padding, ICE STUN regular nomination, and dynamic RFC 8285 dual-SSRC SRTP closely with Chrome/libwebrtc, long-duration continuous bulk transfers remain inherently bounded by macro bandwidth symmetry and real-time congestion dynamics.
