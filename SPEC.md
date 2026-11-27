# WebRTC-Cloak Protocol Specification (`V4.0` / `v0.6.0`)

This document specifies the wire format, cryptographic schedule, state machine, operating topologies, SIMD dispatch invariants, and security boundaries of `webrtc-cloak-rs`.

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
- `txid[8..12]`: `unix_secs_u32_be ^ SHA256("webrtc-cloak:txid-ts:" || psk || txid[0..8])[0..4]`.
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

*(Note: Steps 5–6 retain SHA-256 binding to preserve zero-downtime rolling-upgrade compatibility with `v0.3.x`, while V4-introduced subkeys—per-session `mi_key_mig` and MBB `handover` proofs—use RFC 5869 HKDF-SHA256.)*

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

## 5. Dual-SSRC SRTP, Compound SRTCP & Encrypted In-Band Frames

### 5.1 SRTP Wire Frame
```text
[12B RTP Header: 0x90 (V=2,P=0,X=1,CC=0), M|PT, seq16, ts32, ssrc32]
[ 8B RFC 8285 Ext: 0xBE 0xDE 0x00 0x01 0x31 global_twcc_u16 0x00]
[AEAD Ciphertext:  inner_frame || 0..=31B random pad (0..=7B if >=1340B)]
[16B AEAD/MAC Tag]
```
- `inner_frame` (first 2 bytes BE act as length for data `<= 65400`, or reserved magic `>= 0xFFFA` inside AEAD ciphertext):
  - **Normal UDP Data**: `[inner_len: u16 BE (<= 65400)] || [udp_payload]`
  - **`0xFFFE` In-Band Selftest Probe**: `[0xFFFE: u16 BE] || [probe_len: u16 BE (<= 1460)] || [probe_payload]` (echoed 1:1 by Ready server; never forwarded to backend).
  - **`0xFFFD` V4 1-RTT Path Challenge/Response/Confirm**: `[0xFFFD: u16 BE] || [len] || [0x01|0x02|0x03 || nonce(8B) || optional epoch_be(8B)]`.
  - **`0xFFFC` V4 MBB Atomic Handover**: `[0xFFFC: u16 BE] || [len] || [0x01 || old_ufrag_len || old_ufrag || HKDF-SHA256(old_skey, new_skey, "handover-v4")]` (and server ack `[0x02 || 0x01|0x00]`).
  - **`0xFFFB` Reverse Tunnel Multiplexed Data (`v0.6.0`)**: `[0xFFFB: u16 BE] || [payload_len: u16 BE (<= 65396)] || [flow_id: u32 BE] || [udp_payload]` (used exclusively by `webrtc-cloak reverse --entry | --agent`; wire-invisible outside AEAD ciphertext).
  - **`0xFFFA` Reverse Tunnel Control (`v0.6.0`)**: `[0xFFFA: u16 BE] || [ctrl_len: u16 BE] || [opcode: u8 || body]`, with opcodes:
    - `0x01` (`REV_OP_HELLO`): `[0x01, proto_ver=0x01]` — sent by Agent upon DTLS `Ready` to bind the active reverse tunnel on Entry and flush buffered pre-connect packets.
    - `0x02` (`REV_OP_HELLO_ACK`): `[0x02, proto_ver=0x01]` — Entry confirmation stopping Agent HELLO retries.
    - `0x03` (`REV_OP_FLOW_CLOSE`): `[0x03, flow_id: u32 BE]` — sent by Entry when an exposed UDP peer flow expires so Agent promptly releases the corresponding backend socket.
- **Dual-SSRC Routing** (enabled automatically when DTLS 1.3 is negotiated):
  - `PT=111` (Opus 48 kHz, 960 ticks/20ms): packets smaller than jittered threshold `180..=307B`, strictly capped to **at most 1 packet per 20ms frame (`<= 50 pps`)**; talkspurt `M=1` after `>=200ms` silence.
  - `PT=96` (Video 90 kHz): all remaining and overflow packets; strict RFC 3550 `M=1` causality guarantees no packet ever reuses a closed frame's timestamp after `M=1`.
  - Independent 2048-packet RFC 6479 sliding replay rings per SSRC; shared global `0xBEDE` TWCC sequence.
- **PPPoE Anti-Fragmentation (IPv4 & IPv6)**: Default `--mtu 1488` enforces outer UDP `<= 1460B` on IPv4 (28B IPv4+UDP header) and `<= 1440B` on IPv6 (48B IPv6+UDP header, `< 1492B` PPPoE); STUN `XOR-MAPPED-ADDRESS` implements RFC 5389 §15.2 for both IPv4 (`64B` total reply) and IPv6 (`76B` total reply). Oversized inner packets are dropped cleanly to converge inner QUIC DPLPMTUD.

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
2. **Graceful Shutdown (`SIGTERM`/`SIGINT`, `v0.3.7` / hardened `v0.3.8`)**: On Unix, server and client install async-signal-safe `sigaction` + self-pipe wakeups (zero background signal thread); on Windows, `ctrlc` + `mio::Waker` handles provide sub-millisecond `SIGTERM`/`SIGINT` wakeup. Both broadcast encrypted `SRTCP BYE + DTLS close_notify` to all active sessions before exiting. Active clients defer reconnect by a jittered **`80–350ms`** (buffering arriving app packets) to clear `systemd` restart bind gaps without triggering plaintext `ICMP Port Unreachable`.
3. **Proactive Make-Before-Break Scheduled Rotation with Encrypted `0xFFFC` Handover (`--rotate-interval` / `--rotate-bytes`, `V4.0`)**:
   - Uses a **complete fresh DTLS 1.3 handshake** with brand-new unlinkable `ufrag`, `SSRC`, `CNAME`, and ECDHE PFS `session_key` (never reusing plaintext identifiers across scheduled rotations).
   - Before promoting the standby session, client sends an encrypted in-band `0xFFFC` handover frame carrying `old_ufrag` and `HKDF-SHA256(old_session_key, new_session_key, "handover-v4")` (4 × 380ms retries). Server verifies the proof in constant time (single-use per old session, idempotent on retransmit) and atomically transfers exclusive ownership of `old_sess`'s live backend pipe (`BackendPipe::Owned` → `ForwardLocal`/`ForwardRemote`, `RelayDirect` key rebinding, or `ReverseAgent` active tunnel switch; zero `dup()` races; works across Linux `SO_REUSEPORT` workers) so **even strict source-port-pinned UDP backends see 0 port changes and 0 packet loss**. All `0xFFFD`/`0xFFFC`/`0xFFFA` control frames account into SRTP `tx_pkts`/`rx_pkts` for strict RFC 3550 RTCP causality.
   - Dual triggers: right-skewed **log-normal duration** (`[0.35x, 2.80x]` around `--rotate-interval`) AND randomized **single-session byte-volume budget** (`--rotate-bytes`, default `1200 MiB` → `600–2220 MiB`, 60s cooldown), suspended during background trickle (`< 64 KB / 5 min`, 5–8h fallback cap).
   - Tracks explicit `standby_for_primary` ownership, cancels orphan standbys on primary failure/restart/close, and delays old-session `BYE` by randomized **2–10s** (`DrainingBeforeBye`) + 1s post-BYE client drain + 250ms server `Closing` downlink flush.
4. **Non-Blocking ECMP Multi-Metric Adaptive Lane Hunting (`--lane-hunt`, `v0.4.4`–`v0.4.5`)**:
   - Designed for multi-path / ECMP networks where per-5-tuple hashing maps different UDP ephemeral source ports to distinct routing paths, requiring **zero wire-format changes** (100% compatible with `v0.4.0+` servers).
   - **Scale-Invariant Cold-Start Calibration (`--lane-target-rtt 0`, default)**: At startup without a hardcoded ms threshold, client automatically probes across at least 2 staggered STUN rounds (`--lane-probes`, default `4`, up to 3 rounds / `>= 6` ports for background `PreWarm`; capped at 2 rounds for interactive `NewPrimary`), using universal early-settle `(best_rtt + 45ms).clamp(80, 550)` to lock onto the global minimum RTT baseline across 5ms–250ms geographies, pre-warm DTLS 1.3 to `Ready`, and hand off at 0ms on the first local packet (`0xFFFE` keepwarm while idle).
   - **Zero-Overhead Multi-Metric Lane Scoring & Canary Confirmation**: Continuously computes a scale-invariant `0–100` composite score combining normalized relative RTT (`scale = max(ref_rtt, 30ms)`), real downlink data-plane SRTP packet loss (measured locally across Video+Audio SSRCs via `SrtpCloakCipher::rx_settled_stats()`, excluding the trailing 24-packet reorder tail for 0% false loss under heavy ECMP reordering and isolating 1-RTT migration gaps via `reset_rx_loss_epoch()`), single-drop-immune STUN consent loss, and jitter. Newly adopted/switched lanes enter a Canary trial window (confirming `lane_confirmed = true` after 2 clean windows, or fast-escaping throttled/lossy "fake-good" lanes via shortened cooldown with 2^k exponential anti-storm backoff on consecutive network-wide failures).
   - **Continuous Reinforcement & Hysteresis**: Confirmed clean lanes continuously reinforce `best_observed_rtt_ms` downward via smoothed EWMA; auto target thresholds (`max(1.40*b, b+20ms)`) stay strictly below the `score < 55` degradation boundary to prevent trap-band switching loops, while unsuccessful hunts gently relax stale baselines when the underlying network floor rises. Degraded (`DegradeRtt` / `DegradeLoss`) or sustained sub-optimal (`Optimize`) lanes trigger background multi-candidate MBB `0xFFFC` handovers (0 backend source-port change); scheduled rotations and 1-RTT blackhole migrations likewise race multiple candidate ports (aligned with server `MAX_CHALLENGES_PER_SEC=4`).
5. **Decoupled Outer Health Telemetry (`--status-file` / `--status-http`, `v0.4.1`–`v0.6.0`)**:
   - Exposes real outer link quality (STUN RTT / EWMA / RFC 3550 jitter / rolling 20-probe loss %, real SRTP downlink `data_loss_pct`, composite `lane_score`, calibrated `lane_best_rtt_ms`, `lane_confirmed`, smoothed Mbps throughput, 10-minute blackhole & 1-RTT migration counts, MBB handover counters, `lane_hunts_total` / `lane_switches_total`, and server unauthenticated silent-drop scan counters) strictly off the SRTP hot path across all roles (`client`, `server`, `relay`, `reverse-entry`, `reverse-agent`, `bypass`, `bypass-responder`).
   - Available simultaneously via zero-dependency atomic `tmp + rename` RFC 8259 JSON file (`--status-file`) and/or a lightweight single-thread `mio::Poll` read-only HTTP listener (`--status-http`, 64 KiB stack, zero idle wakeups, serving JSON on `/`, `/status`, `/health`, `/healthz` with `503` on critical, and Prometheus exposition text on `/metrics`).

---

## 7. Operating Topologies & Transport Modes (`v0.5.0`–`v0.6.0`)

### 7.1 Out-of-Band ECMP Lane-Hunting Raw UDP Bypass (`webrtc-cloak bypass`, `v0.5.0`)
- Shares a single UDP 5-tuple between authenticated RFC 8445 ICE STUN probes (same HMAC-SHA1 + timestamped `txid` + `FINGERPRINT` validation as `server`) and raw unframed inner UDP payloads (e.g., QUIC / WireGuard).
- Delivers zero payload overhead, zero double-encryption, and full kernel `UDP_SEGMENT` (UDP GSO) compatibility, while providing multi-candidate ECMP lane hunting, continuous RTT/jitter guard, seamless NAT-rebinding port migration with a 3-second old-port drain overlap, and automatic blackhole escape.
- Companion `bypass --responder` operates as an ultra-lightweight STUN responder for deployments without a full `server` instance.

### 7.2 Native Single-Process Zero-Loopback Relay (`webrtc-cloak relay`, `v0.6.0`)
- Fuses an ingress `ServerWorker` (WebRTC DTLS 1.3 + SRTP termination) and an egress `BypassWorker` (`--upstream-mode bypass`) or `ClientWorker` (`--upstream-mode cloak`) inside a single thread and a single `mio::Poll` event loop (`SharedPoll` wrapping `Arc<mio::Registry>`).
- Eliminates localhost loopback sockets, redundant kernel UDP packet copies, and cross-process wakeups/context switches via direct in-memory handoff hooks (`ServerHook::Relay` and `ClientDownlink::Relay` / `BypassEgress`).
- Supports independent ingress/egress PSKs (`--upstream-psk[-file]` / `WEBRTC_CLOAK_UPSTREAM_PSK`), independent cipher suites, independent DTLS minimum versions, Linux `recvmmsg/sendmmsg` batching on both legs, and full `0xFFFC` MBB handover + `0xFFFD` 1-RTT migration independently on both ingress and egress legs.

### 7.3 Native Reverse Tunnel Mode (`webrtc-cloak reverse --entry | --agent`, `v0.6.0`)
- Enables NAT-traversal exposure of arbitrary L4 UDP services with **zero inbound ports** on the Agent side:
  - **Entry (`reverse --entry`)** binds a public WebRTC tunnel port (`--listen-host:--listen-port`) and an exposed business UDP port (`--expose-host:--expose-port`) within a single `mio::Poll` loop (`ServerWorker` + `ReverseEntryHub`). Incoming packets from external UDP peers are mapped per 5-tuple to a `flow_id: u32` and encapsulated in encrypted `0xFFFB` SRTP frames sent over the active Agent tunnel (buffering up to 64 packets / 3s TTL while Agent is connecting or briefly reconnecting).
  - **Agent (`reverse --agent`)** dials outbound to Entry immediately at startup (`ClientWorker` + `ReverseAgentMux` sharing one `mio::Poll` with strictly partitioned token ranges) and sends `0xFFFA REV_OP_HELLO` upon DTLS `Ready`. Its persistent tunnel is exempt from data-idle teardown while still enforcing the 45s RFC 7675 consent timeout, and triggers 24×7 self-healing reconnects, `--lane-hunt` multi-candidate selection, `0xFFFC` MBB zero-loss rotation (`LocalHandoverAction::TransferReverseAgent`), and `0xFFFD` 1-RTT blackhole escape even when no traffic is flowing.
  - For each distinct `flow_id`, Agent maintains a dedicated connected backend UDP socket (preserving a **pinned local source port** across MBB handovers and 1-RTT migrations so stateful backends such as WireGuard or QUIC never see spurious port changes). Idle flows are evicted after `--idle-timeout` and signaled via `0xFFFA REV_OP_FLOW_CLOSE`.
  - Both Entry and Agent run single-worker (`--workers 1`) to guarantee deterministic flow-to-socket pinning, support IPv4/IPv6 cross-family bridging, inherit Linux `--udp-batch` acceleration, and enforce strict 0-byte Silent Drop against unauthenticated probes on the tunnel port.

---

## 8. Cryptographic Backends, SIMD Dispatch & Batch I/O (`v0.4.6`–`v0.6.0`)

### 8.1 Runtime SIMD Coverage Across All 16 Release Targets
- **AES-128 (`aes 0.9.4`)**: Runtime CPUID dispatch across x86/x86_64 (`VAES-512` → `VAES-256` → `AES-NI`, no AVX gate) and AArch64 (`ARMv8-AES`).
- **GHASH / POLYVAL (`patches/polyval`, `v0.5.1`–`v0.6.0`)**: Two-tier x86/x86_64 runtime dispatcher (`avx + pclmulqdq` VEX Tier 1 and `sse2 + pclmulqdq` Legacy SSE Tier 2 — accelerating non-AVX x86 CPUs with hardware `AES-NI + PCLMULQDQ`) plus 4-block aggregated `ARMv8-PMULL` on AArch64.
- **ChaCha20 (`chacha20 0.10.2` + `.cargo/config.toml`, `v0.6.0`)**: Enables `--cfg chacha20_avx512` across x86/x86_64 targets for runtime-dispatched 16-block `AVX-512F+VL` (safely falling back to `AVX2` → `SSE2` → `soft`), plus `ARMv8-NEON` on all `aarch64` targets.
- **Poly1305 (`patches/poly1305`, `v0.6.0`)**: Runtime `AVX2` on x86/x86_64, and constant-time **64-bit 3-limb `radix-2^44` (`u64` + `u128`, 9 muls/block)** across all 64-bit targets (`aarch64`, non-AVX2 `x86_64`, `riscv64`, `loongarch64`, `powerpc64le`), retaining 5-limb `radix-2^26` (`u32`) on 32-bit targets (`i686` non-AVX2, `armv7*`, `arm*`, `armv5te`).
- **SHA-1 / SHA-2 (`sha1 0.11` / `sha2 0.11`)**: Runtime x86 `SHA-NI + SSE4.1` (no AVX gate), AArch64 `ARMv8-SHA2`/`SHA3`, and `loongarch64` assembly.
- **Ground-Truth Auto-Selection (`detect_cpu_accel`)**: Evaluates `has_hw_aes_gcm = aes::hardware_accelerated() && polyval::hardware_accelerated()` across `x86`, `x86_64`, and `aarch64`, preventing false hardware claims on platforms where upstream `cpufeatures` lacks OS probing (such as `windows-arm64`, which safely auto-selects NEON `ChaCha20-Poly1305`). `webrtc-cloak cpu` reports exact active backend identifiers (`aes=... gcm=... chacha20=... poly1305=...`).

### 8.2 Opt-In Linux UDP Batch I/O & Burst Buffers (`v0.4.6`–`v0.4.7`)
- `--udp-batch <0|2..64>` defaults to `0` (zero extra heap allocation). When enabled on Linux (e.g., `--udp-batch 32`), all hot data-plane loops (`server`, `client`, `relay`, `reverse`, `bypass`) use pre-allocated zero-copy `recvmmsg`/`sendmmsg` batching across IPv4 and IPv6 while preserving strict control-frame ordering and exact telemetry counters. Non-Linux OSes safely fall back to single-packet syscalls.
- Kernel UDP socket buffers scale up to `8 MiB` on tunnel/listen/upstream sockets and `4 MiB` on per-session backend sockets, preventing `Udp: RcvbufErrors` under hypervisor scheduling pauses and multi-hop bursts with zero idle RSS penalty.

---

## 9. Known Scope Boundaries

`webrtc-cloak` is a transparent UDP transport wrapper (not a TCP/TUN VPN), cannot bypass networks blocking 100% of UDP egress, cannot erase single-tenant `(src_ip, dst_ip)` macro NetFlow correlation on a single server, and carries pure-Rust `dimpl` JA4D stack characteristics distinct from C++ BoringSSL.
