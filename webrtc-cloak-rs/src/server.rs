//! mio-based zero-allocation webrtc-cloak V4.0 server (Hardened):
//!   - Pure Silent-Drop on all unauthenticated, malformed, expired, or replayed probes
//!   - Zero-alloc pre-auth STUN parser + shared O(1) bounded FIFO `SeenTxidCache` across workers
//!   - Real RFC 9147 DTLS 1.3 + RFC 6347 DTLS 1.2 via `dimpl 0.9.0` (strict pre-validation, optional
//!     `--dtls-min-version 1.3`, Fail-Closed Hybrid PFS, fail-fast handshake reset, Ready gating)
//!   - V4.0 Universal Seamless UDP Carrier ("change path, never change backend port"):
//!     * 1-RTT RFC 8445 ICE path migration authenticated by DTLS-PFS HKDF `ice-pwd-v4` + tie-breaker
//!       + unpadded encrypted `0xFFFD` challenge (`<= 1.32x` anti-reflection, rate-limited, 4-slot
//!       per-session candidate table, never mutates `token_by_peer` before cryptographic proof!)
//!     * Scheduled DTLS 1.3 MBB rekey with encrypted in-band `0xFFFC` single-use atomic `backend_sock`
//!       handover (unlinkable new ufrag/SSRC/CNAME, chained <=4-hop drain forwarding, 0 port changes)
//!     * Bounded lockless multi-worker `SO_REUSEPORT` cross-thread ownership transfer
//!   - Dual-SSRC SRTP (PT=111 <=50pps Opus + PT=96 video) + in-band `0xFFFE` probe echo
//!   - RFC 3550 §6.1 / 7714 §9.1 Compound SRTCP + idle/trickle control-plane backoff + Closing flush

use crate::protocol::{
    build_dimpl_config_pool, build_stun_success_response, build_stun_success_response_with_key,
    combine_session_key, compute_handover_proof, demux_rfc7983, derive_ice_migration_key,
    derive_stun_material, detect_cpu_accel, extract_dtls_server_hello_suite, fill_random,
    new_dtls_instance, parse_stun_with_key, peek_stun_request_username, rand_duration_range_ms,
    register_shutdown_waker, resolve_srtp_suite, stun_hmac_key, validate_dtls_datagram, CertCache,
    CipherPref, CipherSuite, DtlsConfigPool, DtlsMinVersion, PacketKind, RollingByteWindow,
    SrtpCloakCipher, SrtpFrame, MAX_INNER_UDP_LEN, SRTP_HANDOVER_MAGIC, SRTP_PATH_CHALLENGE_MAGIC,
    STUN_BINDING_REQUEST,
};
use crate::telemetry::{TelemetryConfig, TelemetryHub, WorkerSnapshot};
use dimpl::{Dtls, Output as DtlsOutput, ProtocolVersion};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

thread_local! {
    static SERVER_QUIET: Cell<bool> = const { Cell::new(false) };
}

const LISTEN_TOKEN: Token = Token(0);
const WAKE_TOKEN: Token = Token(usize::MAX);
const SEEN_TXID_TTL: Duration = Duration::from_secs(90);
const RETRANSMIT_WINDOW: Duration = Duration::from_secs(8);
const MAX_STUN_RETRANSMITS: u8 = 6;
const SEEN_TXID_CAP: usize = 65_536;
const EARLY_SRTP_CAP: usize = 32;
const MAX_DTLS_RESETS: u8 = 3;
const CLOSING_DRAIN_MS: u64 = 250;
/// RFC 7675 §5.1 consent lifetime: stop transmitting and silently release session after 45s
/// with zero authenticated packets (STUN/SRTP/SRTCP/DTLS) received from peer.
const PEER_CONSENT_TIMEOUT: Duration = Duration::from_secs(45);
/// Rolling 15-second media byte threshold below which a session enters quiet trickle backoff (~270 B/s).
const TRICKLE_RATE_15S_BYTES: u64 = 4 * 1024;
/// Lifetime of an unverified 1-RTT ICE path migration reachability challenge.
const MIGRATION_CHALLENGE_TTL: Duration = Duration::from_secs(5);
/// Window after verified 1-RTT migration during which ECMP-reordered uplink packets from the
/// old peer address are still accepted and delivered without rolling back `sess.peer_addr`.
const OLD_PEER_DRAIN_TTL: Duration = Duration::from_secs(5);
/// P0-2: Fixed per-session pending candidate slots (isolates legitimate retries from spoofed racers).
const MAX_PENDING_MIGRATIONS_PER_SESSION: usize = 4;
/// P0-4: Strict per-session 0xFFFD challenge rate ceiling (prevents same-PSK reflection flooding).
const MAX_CHALLENGES_PER_SEC: u8 = 4;
/// P0-4: Hard upper bounds on cross-worker queues and unverified candidate maps (prevents OOM).
const MAX_WORKER_CMD_QUEUE: usize = 4096;
const MAX_MIG_PENDING_MAP: usize = 4096;
/// P1-1: Maximum chained MBB handover forwarding hops during overlapping drains.
const MAX_FORWARD_HOPS: u8 = 4;

enum TxidCheck {
    Fresh,
    /// Genuine same-peer short-window UDP retry (bounded <= 6x): resend exact cached 64B reply!
    Retransmit([u8; 64], u8),
    /// Cross-IP replay, post-close replay, or exceeded retries -> Silent Drop!
    Rejected,
}

struct TxidEntry {
    peer: SocketAddr,
    seen_at: Instant,
    cached_reply: [u8; 64],
    cached_len: u8,
    retransmits: u8,
}

/// Shared O(1) bounded FIFO anti-replay cache across all SO_REUSEPORT workers.
struct SeenTxidCache {
    map: HashMap<[u8; 12], TxidEntry>,
    order: VecDeque<([u8; 12], Instant)>,
}

impl SeenTxidCache {
    fn new() -> Self {
        Self {
            map: HashMap::with_capacity(1024),
            order: VecDeque::with_capacity(1024),
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        while let Some(&(txid, ts)) = self.order.front() {
            if now.duration_since(ts) > SEEN_TXID_TTL {
                self.order.pop_front();
                if let Some(entry) = self.map.get(&txid) {
                    if entry.seen_at == ts {
                        self.map.remove(&txid);
                    }
                }
            } else {
                break;
            }
        }
    }

    fn check(
        &mut self,
        txid: [u8; 12],
        peer: SocketAddr,
        now: Instant,
        same_session_active: bool,
    ) -> TxidCheck {
        self.evict_expired(now);
        if let Some(entry) = self.map.get_mut(&txid) {
            if entry.peer == peer
                && same_session_active
                && now.duration_since(entry.seen_at) <= RETRANSMIT_WINDOW
                && entry.retransmits < MAX_STUN_RETRANSMITS
            {
                entry.retransmits += 1;
                return TxidCheck::Retransmit(entry.cached_reply, entry.cached_len);
            }
            return TxidCheck::Rejected;
        }
        TxidCheck::Fresh
    }

    fn record(&mut self, txid: [u8; 12], peer: SocketAddr, now: Instant, resp: &[u8]) {
        self.evict_expired(now);
        while self.map.len() >= SEEN_TXID_CAP {
            if let Some((old_txid, old_ts)) = self.order.pop_front() {
                if let Some(e) = self.map.get(&old_txid) {
                    if e.seen_at == old_ts {
                        self.map.remove(&old_txid);
                    }
                }
            } else {
                break;
            }
        }
        let mut buf = [0u8; 64];
        let clen = resp.len().min(64);
        buf[..clen].copy_from_slice(&resp[..clen]);
        self.map.insert(
            txid,
            TxidEntry {
                peer,
                seen_at: now,
                cached_reply: buf,
                cached_len: clen as u8,
                retransmits: 0,
            },
        );
        self.order.push_back((txid, now));
    }
}

// ---------------------------------------------------------------------------
// V4.0 Control-Plane Shared Registry & Bounded Lockless Cross-Worker Transfer
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct ActiveSessionMeta {
    worker_id: usize,
    mi_key_mig: [u8; 32],
    tie_breaker: [u8; 8],
}

enum WorkerCmd {
    /// Worker receiving migration STUN asks owner worker to arm/reuse `0xFFFD` challenge WITHOUT
    /// moving the session yet (prevents spoofed-IP DoS against live owner!).
    CrossWorkerChallengeRequest {
        ufrag: String,
        cand_addr: SocketAddr,
        cand_worker: usize,
        stun_resp: Vec<u8>,
    },
    /// Worker receiving `0xFFFD` response (or early SRTP) from `cand_addr` forwards it to owner for
    /// AEAD verification; ONLY upon cryptographic proof does owner deregister & transfer `ServerSession`!
    CrossWorkerChallengeVerify {
        ufrag: String,
        cand_addr: SocketAddr,
        cand_worker: usize,
        pkt: Vec<u8>,
    },
    /// Owner worker delivers verified migrated `ServerSession` (with intact `backend_sock`!) to new worker.
    MigrateInstall {
        sess: Box<ServerSession>,
    },
    /// MBB scheduled DTLS 1.3 rekey: new worker asks old owner worker to verify handover proof and
    /// atomically transfer `backend_sock` ownership to `new_ufrag`.
    HandoverExtract {
        old_ufrag: String,
        new_ufrag: String,
        new_session_key: [u8; 32],
        proof: [u8; 32],
        target_worker: usize,
    },
    /// Old owner worker delivers extracted `backend_sock` to new MBB session on `target_worker`.
    HandoverInstall {
        new_ufrag: String,
        backend_sock: MioUdpSocket,
        backend_lport: u16,
    },
    /// Handover finished without a socket to transfer (unbound old session) or failed verification.
    HandoverAckOnly {
        new_ufrag: String,
        ok: bool,
    },
    /// Rare draining-window ECMP-reordered uplink packet forwarded from old session (`ForwardRemote`)
    /// with bounded hop count (`hops_left`) to survive chained MBB handovers / cross-worker migrations.
    DrainUplinkForward {
        target_ufrag: String,
        payload: Vec<u8>,
        hops_left: u8,
    },
    /// Bounce an in-flight SRTP packet that raced ahead of `MigrateInstall` back to the new owner worker.
    ReprocessSrtp {
        peer_addr: SocketAddr,
        pkt: Vec<u8>,
    },
}

struct WorkerInbox {
    queue: Mutex<VecDeque<WorkerCmd>>,
    waker: Mutex<Option<Arc<Waker>>>,
}

struct SharedV4Registry {
    ufrag_index: Mutex<HashMap<String, ActiveSessionMeta>>,
    inboxes: Vec<WorkerInbox>,
}

impl SharedV4Registry {
    fn new(workers: usize) -> Self {
        let mut inboxes = Vec::with_capacity(workers);
        for _ in 0..workers {
            inboxes.push(WorkerInbox {
                queue: Mutex::new(VecDeque::new()),
                waker: Mutex::new(None),
            });
        }
        Self {
            ufrag_index: Mutex::new(HashMap::with_capacity(256)),
            inboxes,
        }
    }

    fn set_waker(&self, worker_id: usize, waker: Arc<Waker>) {
        if let Some(inbox) = self.inboxes.get(worker_id) {
            if let Ok(mut g) = inbox.waker.lock() {
                *g = Some(waker);
            }
        }
    }

    fn register_session(
        &self,
        ufrag: &str,
        worker_id: usize,
        mi_key_mig: [u8; 32],
        tie_breaker: [u8; 8],
    ) {
        if let Ok(mut idx) = self.ufrag_index.lock() {
            idx.insert(
                ufrag.to_string(),
                ActiveSessionMeta {
                    worker_id,
                    mi_key_mig,
                    tie_breaker,
                },
            );
        }
    }

    /// P0-3 fix: NEVER wildcard-delete when `mi_key_mig` is `None` (unready sessions never registered!).
    fn unregister_session(&self, ufrag: &str, worker_id: usize, mi_key_mig: Option<[u8; 32]>) {
        let Some(mk) = mi_key_mig else {
            return;
        };
        if let Ok(mut idx) = self.ufrag_index.lock() {
            let matches = idx
                .get(ufrag)
                .map_or(false, |m| m.worker_id == worker_id && m.mi_key_mig == mk);
            if matches {
                idx.remove(ufrag);
            }
        }
    }

    fn lookup_ufrag(&self, ufrag: &str) -> Option<ActiveSessionMeta> {
        self.ufrag_index.lock().ok().and_then(|idx| idx.get(ufrag).copied())
    }

    /// P0-4 fix: Bounded inbox capacity prevents memory exhaustion under same-PSK flooding.
    /// Ownership-bearing commands (`MigrateInstall` / `HandoverInstall`) bypass the cap so live
    /// `MioUdpSocket` handles are never dropped in transit.
    fn send_cmd(&self, target_worker: usize, cmd: WorkerCmd) {
        let is_ownership_transfer = matches!(
            cmd,
            WorkerCmd::MigrateInstall { .. } | WorkerCmd::HandoverInstall { .. }
        );
        if let Some(inbox) = self.inboxes.get(target_worker) {
            if let Ok(mut q) = inbox.queue.lock() {
                if !is_ownership_transfer && q.len() >= MAX_WORKER_CMD_QUEUE {
                    return;
                }
                q.push_back(cmd);
            }
            if let Ok(w) = inbox.waker.lock() {
                if let Some(ref waker) = *w {
                    let _ = waker.wake();
                }
            }
        }
    }

    fn drain_cmds(&self, worker_id: usize, out: &mut Vec<WorkerCmd>) {
        if let Some(inbox) = self.inboxes.get(worker_id) {
            if let Ok(mut q) = inbox.queue.lock() {
                while let Some(cmd) = q.pop_front() {
                    out.push(cmd);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub backend_addr: SocketAddr,
    pub psk: Vec<u8>,
    pub cipher_pref: CipherPref,
    pub dtls_required: bool,
    pub dtls_min_version: DtlsMinVersion,
    pub workers: usize,
    pub max_sessions: usize,
    pub wan_mtu: usize,
    pub idle_timeout_secs: u64,
    pub stats_interval_secs: u64,
    pub wire_audit_file: Option<String>,
    pub telemetry: TelemetryConfig,
    pub quiet: bool,
    pub stop: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ServerState {
    DtlsHandshake,
    Ready,
    /// Closing(deadline, allow_downlink_flush):
    /// When entered due to peer BYE/close_notify, `allow_downlink_flush = true` still delivers
    /// slow in-flight backend replies during the brief 250ms Closing window to the peer's
    /// receive-only drain socket instead of silently dropping them.
    Closing(Instant, bool),
}

enum BackendPipe {
    /// Lazily unbound until first Data packet arrives OR atomic `0xFFFC` handover installs old socket.
    Unbound,
    /// Exclusively owned backend UDP socket registered in this worker's `mio::Poll`.
    Owned(MioUdpSocket),
    /// Handed over to a newer MBB session on the SAME worker (chained <=4-hop drain forwarding).
    ForwardLocal {
        target_tok: Token,
        target_ufrag: String,
    },
    /// Handed over to a newer MBB session on ANOTHER worker (chained <=4-hop drain forwarding).
    ForwardRemote {
        target_worker: usize,
        target_ufrag: String,
    },
}

#[derive(Clone, Copy)]
struct PendingPathMigration {
    cand_addr: SocketAddr,
    cand_worker: usize,
    nonce: [u8; 8],
    epoch: u64,
    expires_at: Instant,
}

struct ServerSession {
    peer_addr: SocketAddr,
    old_peer_addr: Option<(SocketAddr, Instant)>,
    username: String,
    tie_breaker: [u8; 8],
    backend: BackendPipe,
    backend_lport: u16,
    /// P1-1: Single-use MBB handover lock (idempotent for same `new_ufrag`, blocks double-handover).
    handed_over_to: Option<String>,
    state: ServerState,
    ready_at: Option<Instant>,
    stun_key: [u8; 32],
    session_key: Option<[u8; 32]>,
    mi_key_mig: Option<[u8; 32]>,
    path_epoch: u64,
    /// P0-2: Fixed-size <=4-slot candidate table isolating legitimate retries from spoofed racers.
    pending_migrations: Vec<PendingPathMigration>,
    /// P0-4: Per-session 0xFFFD challenge rate limiter (`<= MAX_CHALLENGES_PER_SEC` per 1s).
    mig_challenge_win: Instant,
    mig_challenge_cnt: u8,
    ssrc_c2s: u32,
    ssrc_s2c: u32,
    dtls: Option<Dtls>,
    dtls_resets: u8,
    dtls_next_timeout: Option<Instant>,
    dtls_suite_id: Option<u16>,
    dtls_km: Option<Vec<u8>>,
    negotiated_cipher: Option<CipherSuite>,
    cipher: Option<SrtpCloakCipher>,
    /// V3-M-03: buffers early 0-RTT SRTP packets arriving before Flight 5 finishes!
    early_srtp: VecDeque<Vec<u8>>,
    last_data_active: Instant,
    last_peer_rx: Instant,
    last_active_burst: Instant,
    next_srtcp_at: Instant,
    rate_15s: RollingByteWindow,
    rx_pkts: u64,
    rx_pkts_at_last_rtcp: u64,
    rx_bytes: u64,
    tx_pkts: u64,
    tx_pkts_at_last_rtcp: u64,
    tx_bytes: u64,
    keepalives: u64,
    srtcp_tx: u64,
    srtcp_rx: u64,
    auth_drops: u64,
}

#[inline]
fn record_server_media_bytes(sess: &mut ServerSession, now: Instant, bytes: u64) {
    sess.rate_15s.record(now, bytes);
    if sess.rate_15s.bytes_in_window(now) >= TRICKLE_RATE_15S_BYTES {
        sess.last_active_burst = now;
        if sess.next_srtcp_at > now + Duration::from_millis(1950) {
            sess.next_srtcp_at = now + rand_duration_range_ms(950, 1950);
        }
    }
}

fn make_udp_socket(
    bind_addr: SocketAddr,
    connect_to: Option<SocketAddr>,
    reuse_port: bool,
    buf_bytes: usize,
) -> std::io::Result<MioUdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = sock.set_reuse_address(true);
    #[cfg(unix)]
    if reuse_port {
        sock.set_reuse_port(true)?;
    }
    #[cfg(not(unix))]
    let _ = reuse_port;
    let _ = sock.set_recv_buffer_size(buf_bytes);
    let _ = sock.set_send_buffer_size(buf_bytes);
    sock.set_nonblocking(true)?;
    sock.bind(&bind_addr.into())?;
    if let Some(target) = connect_to {
        sock.connect(&target.into())?;
    }
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(MioUdpSocket::from_std(std_sock))
}

fn log(worker_id: usize, msg: &str) {
    if !SERVER_QUIET.with(|q| q.get()) {
        println!("[server-rs#{}] {}", worker_id, msg);
    }
}

fn ensure_owned_backend(
    worker_id: usize,
    tok: Token,
    sess: &mut ServerSession,
    backend_addr: SocketAddr,
    poll: &Poll,
) -> bool {
    if matches!(sess.backend, BackendPipe::Unbound) {
        let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let mut bs = match make_udp_socket(bind_any, Some(backend_addr), false, 512 * 1024) {
            Ok(s) => s,
            Err(e) => {
                log(worker_id, &format!("backend socket error: {}", e));
                return false;
            }
        };
        let blport = bs.local_addr().map(|a| a.port()).unwrap_or(0);
        if poll.registry().register(&mut bs, tok, Interest::READABLE).is_err() {
            return false;
        }
        sess.backend = BackendPipe::Owned(bs);
        sess.backend_lport = blport;
    }
    true
}

fn deregister_backend(poll: &Poll, backend: &mut BackendPipe) {
    if let BackendPipe::Owned(ref mut sock) = backend {
        let _ = poll.registry().deregister(sock);
    }
}

/// P1-3: Unified route & registry cleanup whenever a session is removed/evicted/rekeyed.
fn cleanup_session_routes(
    worker_id: usize,
    tok: Token,
    sess: &mut ServerSession,
    poll: &Poll,
    token_by_peer: &mut HashMap<SocketAddr, Token>,
    token_by_ufrag: &mut HashMap<String, Token>,
    local_mig_pending: &mut HashMap<SocketAddr, (Token, Instant)>,
    registry: &SharedV4Registry,
) {
    deregister_backend(poll, &mut sess.backend);
    if token_by_peer.get(&sess.peer_addr) == Some(&tok) {
        token_by_peer.remove(&sess.peer_addr);
    }
    if let Some((old_p, _)) = sess.old_peer_addr.take() {
        if token_by_peer.get(&old_p) == Some(&tok) {
            token_by_peer.remove(&old_p);
        }
    }
    for mig in sess.pending_migrations.drain(..) {
        if local_mig_pending.get(&mig.cand_addr).map(|&(t, _)| t) == Some(tok) {
            local_mig_pending.remove(&mig.cand_addr);
        }
    }
    if token_by_ufrag.get(&sess.username) == Some(&tok) {
        token_by_ufrag.remove(&sess.username);
    }
    registry.unregister_session(&sess.username, worker_id, sess.mi_key_mig);
}

/// P0-2 & P0-4: Rate-limited, idempotent 4-slot candidate challenge allocator.
/// Reuses exact `(nonce, epoch)` if `cand_addr` already has an unexpired slot so reordered STUN
/// retries NEVER invalidate an in-flight challenge!
fn arm_or_reuse_migration_challenge(
    sess: &mut ServerSession,
    cand_addr: SocketAddr,
    cand_worker: usize,
    now: Instant,
) -> Option<([u8; 8], u64)> {
    if now.duration_since(sess.mig_challenge_win) >= Duration::from_secs(1) {
        sess.mig_challenge_win = now;
        sess.mig_challenge_cnt = 0;
    }
    if sess.mig_challenge_cnt >= MAX_CHALLENGES_PER_SEC {
        return None;
    }
    sess.mig_challenge_cnt = sess.mig_challenge_cnt.saturating_add(1);

    sess.pending_migrations.retain(|m| now <= m.expires_at);
    if let Some(existing) = sess
        .pending_migrations
        .iter_mut()
        .find(|m| m.cand_addr == cand_addr)
    {
        existing.cand_worker = cand_worker;
        existing.expires_at = now + MIGRATION_CHALLENGE_TTL;
        return Some((existing.nonce, existing.epoch));
    }

    if sess.pending_migrations.len() >= MAX_PENDING_MIGRATIONS_PER_SESSION {
        sess.pending_migrations.remove(0);
    }
    let mut nonce = [0u8; 8];
    fill_random(&mut nonce);
    let epoch = sess.path_epoch.saturating_add(1);
    sess.pending_migrations.push(PendingPathMigration {
        cand_addr,
        cand_worker,
        nonce,
        epoch,
        expires_at: now + MIGRATION_CHALLENGE_TTL,
    });
    Some((nonce, epoch))
}

/// P0-4 + P1-4: Unpadded 57B SRTP 0xFFFD challenge (`64B STUN + 57B SRTP = 121B <= 1.32x`)
/// + increments `sess.tx_pkts` for strict RTCP causality!
fn send_encrypted_path_challenge<F>(
    sess: &mut ServerSession,
    target_addr: SocketAddr,
    nonce: [u8; 8],
    epoch: u64,
    listen_sock: &MioUdpSocket,
    audit_pkt: &mut F,
) where
    F: FnMut(u8, &[u8]),
{
    let mut payload = [0u8; 17];
    payload[0] = 0x01; // Server -> Client challenge
    payload[1..9].copy_from_slice(&nonce);
    payload[9..17].copy_from_slice(&epoch.to_be_bytes());
    let mut pbuf = [0u8; 256];
    if let Some(ref mut cipher) = sess.cipher {
        if let Some(wn) =
            cipher.wrap_control_unpadded_into(SRTP_PATH_CHALLENGE_MAGIC, &payload, &mut pbuf)
        {
            audit_pkt(1, &pbuf[..wn]);
            if listen_sock.send_to(&pbuf[..wn], target_addr).is_ok() {
                sess.tx_pkts += 1;
            }
        }
    }
}

fn send_encrypted_path_confirm<F>(
    sess: &mut ServerSession,
    target_addr: SocketAddr,
    nonce: [u8; 8],
    listen_sock: &MioUdpSocket,
    audit_pkt: &mut F,
) where
    F: FnMut(u8, &[u8]),
{
    let mut payload = [0u8; 9];
    payload[0] = 0x03; // Server -> Client confirm
    payload[1..9].copy_from_slice(&nonce);
    let mut pbuf = [0u8; 256];
    if let Some(ref mut cipher) = sess.cipher {
        if let Some(wn) = cipher.wrap_control_into(SRTP_PATH_CHALLENGE_MAGIC, &payload, &mut pbuf) {
            audit_pkt(1, &pbuf[..wn]);
            if listen_sock.send_to(&pbuf[..wn], target_addr).is_ok() {
                sess.tx_pkts += 1;
            }
        }
    }
}

fn send_encrypted_handover_ack<F>(
    sess: &mut ServerSession,
    ok: bool,
    listen_sock: &MioUdpSocket,
    audit_pkt: &mut F,
) where
    F: FnMut(u8, &[u8]),
{
    let payload = [0x02u8, if ok { 0x01 } else { 0x00 }];
    let mut pbuf = [0u8; 256];
    if let Some(ref mut cipher) = sess.cipher {
        if let Some(wn) = cipher.wrap_control_into(SRTP_HANDOVER_MAGIC, &payload, &mut pbuf) {
            audit_pkt(1, &pbuf[..wn]);
            if listen_sock.send_to(&pbuf[..wn], sess.peer_addr).is_ok() {
                sess.tx_pkts += 1;
            }
        }
    }
}

/// P1-1: Deliver decrypted uplink UDP payload following up to `hops_left` chained MBB handovers
/// (`ForwardLocal` -> `ForwardLocal` -> `Owned`/`Unbound` or `ForwardRemote` across workers!).
#[allow(clippy::too_many_arguments)]
fn deliver_uplink_payload(
    worker_id: usize,
    start_tok: Token,
    payload: &[u8],
    hops_left: u8,
    sessions_by_token: &mut HashMap<Token, ServerSession>,
    poll: &Poll,
    backend_addr: SocketAddr,
    registry: &SharedV4Registry,
) -> bool {
    let mut cur_tok = start_tok;
    let mut remaining = hops_left;
    loop {
        if let Some(sess) = sessions_by_token.get_mut(&cur_tok) {
            if matches!(sess.backend, BackendPipe::Unbound) {
                let _ = ensure_owned_backend(worker_id, cur_tok, sess, backend_addr, poll);
            }
            match sess.backend {
                BackendPipe::Owned(ref sock) => return sock.send(payload).is_ok(),
                BackendPipe::ForwardLocal {
                    target_tok,
                    ref target_ufrag,
                } => {
                    if remaining == 0 {
                        return false;
                    }
                    remaining -= 1;
                    let tu = target_ufrag.clone();
                    if sessions_by_token.contains_key(&target_tok) {
                        cur_tok = target_tok;
                        continue;
                    }
                    // Target session may have migrated to another worker after handover!
                    if let Some(meta) = registry.lookup_ufrag(&tu) {
                        if meta.worker_id != worker_id {
                            registry.send_cmd(
                                meta.worker_id,
                                WorkerCmd::DrainUplinkForward {
                                    target_ufrag: tu,
                                    payload: payload.to_vec(),
                                    hops_left: remaining,
                                },
                            );
                            return true;
                        }
                    }
                    return false;
                }
                BackendPipe::ForwardRemote {
                    target_worker,
                    ref target_ufrag,
                } => {
                    if remaining == 0 {
                        return false;
                    }
                    let tu = target_ufrag.clone();
                    let dest_worker = registry
                        .lookup_ufrag(&tu)
                        .map(|m| m.worker_id)
                        .unwrap_or(target_worker);
                    registry.send_cmd(
                        dest_worker,
                        WorkerCmd::DrainUplinkForward {
                            target_ufrag: tu,
                            payload: payload.to_vec(),
                            hops_left: remaining - 1,
                        },
                    );
                    return true;
                }
                BackendPipe::Unbound => return false,
            }
        } else {
            return false;
        }
    }
}

/// Returns `(peer_closed, became_ready)`.
#[allow(clippy::too_many_arguments)]
fn drain_server_dtls<F>(
    worker_id: usize,
    sess: &mut ServerSession,
    listen_sock: &MioUdpSocket,
    dtls_buf: &mut Vec<u8>,
    cfg: &ServerConfig,
    cpu: &crate::protocol::CpuAccelInfo,
    registry: &SharedV4Registry,
    now: Instant,
    mut audit_pkt: F,
) -> (bool, bool)
where
    F: FnMut(u8, &[u8]),
{
    let mut connected_now = false;
    let mut peer_closed = false;
    let mut became_ready = false;

    if let Some(ref mut dtls) = sess.dtls {
        loop {
            match dtls.poll_output(dtls_buf) {
                DtlsOutput::Packet(p) => {
                    if let Some(cs) = extract_dtls_server_hello_suite(p) {
                        sess.dtls_suite_id = Some(cs);
                    }
                    audit_pkt(1, p);
                    let _ = listen_sock.send_to(p, sess.peer_addr);
                }
                DtlsOutput::BufferTooSmall { needed } => {
                    dtls_buf.resize(needed, 0);
                }
                DtlsOutput::Timeout(t) => {
                    sess.dtls_next_timeout = Some(t);
                    break;
                }
                DtlsOutput::KeyingMaterial(km, _profile) => {
                    sess.dtls_km = Some(km.to_vec());
                }
                DtlsOutput::Connected => {
                    connected_now = true;
                }
                DtlsOutput::CloseNotify => {
                    peer_closed = true;
                }
                _ => {}
            }
        }
    }

    if connected_now && sess.state == ServerState::DtlsHandshake {
        let Some(km) = sess.dtls_km.as_deref().filter(|k| !k.is_empty()) else {
            log(
                worker_id,
                &format!(
                    "DTLS Connected without SRTP KeyingMaterial peer={} (Fail-Closed!)",
                    sess.peer_addr
                ),
            );
            return (true, false);
        };
        let is_dtls13 = sess
            .dtls
            .as_ref()
            .and_then(|d| d.protocol_version())
            == Some(ProtocolVersion::DTLS1_3);
        let chosen = resolve_srtp_suite(cfg.cipher_pref, sess.dtls_suite_id, cpu, false);
        let final_key = combine_session_key(&sess.stun_key, Some(km));
        let mi_key_mig = derive_ice_migration_key(&final_key);
        sess.session_key = Some(final_key);
        sess.mi_key_mig = Some(mi_key_mig);
        sess.negotiated_cipher = Some(chosen);
        let mut c = SrtpCloakCipher::new(
            &final_key,
            sess.ssrc_s2c,
            sess.ssrc_c2s,
            false,
            chosen,
        );
        c.set_wan_mtu(cfg.wan_mtu);
        c.set_dual_ssrc(is_dtls13);
        sess.cipher = Some(c);
        sess.state = ServerState::Ready;
        sess.ready_at = Some(now);
        sess.last_data_active = now;
        sess.last_peer_rx = now;
        sess.last_active_burst = now;
        sess.rate_15s = RollingByteWindow::new(now, Duration::from_secs(15));
        sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
        sess.next_srtcp_at = now + rand_duration_range_ms(300, 750);
        registry.register_session(&sess.username, worker_id, mi_key_mig, sess.tie_breaker);
        became_ready = true;
        log(
            worker_id,
            &format!(
                "DTLS {} (dimpl mutual-cert PFS) OK -> READY peer={} cipher={} dual_ssrc={} backend_sport={} early_srtp={}",
                if is_dtls13 { "1.3" } else { "1.2" },
                sess.peer_addr,
                chosen.name(),
                is_dtls13,
                sess.backend_lport,
                sess.early_srtp.len()
            ),
        );
    }

    (peer_closed, became_ready)
}

fn graceful_teardown_server<F>(
    sess: &mut ServerSession,
    listen_sock: &MioUdpSocket,
    dtls_buf: &mut Vec<u8>,
    mut audit_pkt: F,
) where
    F: FnMut(u8, &[u8]),
{
    if sess.state == ServerState::Ready {
        let has_rx = sess.rx_pkts > sess.rx_pkts_at_last_rtcp;
        let is_sender = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
        if let Some(ref mut cipher) = sess.cipher {
            let bye = cipher.build_srtcp(has_rx, is_sender, true);
            audit_pkt(1, &bye);
            let _ = listen_sock.send_to(&bye, sess.peer_addr);
        }
        if let Some(ref mut dtls) = sess.dtls {
            if dtls.close().is_ok() {
                loop {
                    match dtls.poll_output(dtls_buf) {
                        DtlsOutput::Packet(p) => {
                            audit_pkt(1, p);
                            let _ = listen_sock.send_to(p, sess.peer_addr);
                        }
                        DtlsOutput::BufferTooSmall { needed } => dtls_buf.resize(needed, 0),
                        DtlsOutput::Timeout(_) => break,
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Process a decrypted Ready-state SRTP packet (normal Data, `0xFFFE` Probe, `0xFFFD` PathChallenge
/// response, or `0xFFFC` MBB backend_sock handover) with full multi-worker & chained handover support.
#[allow(clippy::too_many_arguments)]
fn process_ready_srtp<F>(
    worker_id: usize,
    tok: Token,
    from_peer: SocketAddr,
    pkt: &[u8],
    sessions_by_token: &mut HashMap<Token, ServerSession>,
    token_by_peer: &mut HashMap<SocketAddr, Token>,
    token_by_ufrag: &mut HashMap<String, Token>,
    local_mig_pending: &mut HashMap<SocketAddr, (Token, Instant)>,
    poll: &Poll,
    listen_sock: &MioUdpSocket,
    cfg: &ServerConfig,
    registry: &SharedV4Registry,
    telemetry: Option<&Arc<TelemetryHub>>,
    wbuf: &mut [u8],
    now: Instant,
    audit_pkt: &mut F,
) where
    F: FnMut(u8, &[u8]),
{
    let frame = {
        let Some(sess) = sessions_by_token.get_mut(&tok) else {
            return;
        };
        if sess.state != ServerState::Ready {
            return;
        }
        match sess.cipher.as_mut().and_then(|c| c.unwrap_into_ex(pkt, wbuf)) {
            Some(f) => f,
            None => {
                sess.auth_drops += 1;
                return;
            }
        }
    };

    match frame {
        SrtpFrame::Data(pn) => {
            let delivered = deliver_uplink_payload(
                worker_id,
                tok,
                &wbuf[..pn],
                MAX_FORWARD_HOPS,
                sessions_by_token,
                poll,
                cfg.backend_addr,
                registry,
            );
            if let Some(sess) = sessions_by_token.get_mut(&tok) {
                sess.last_data_active = now;
                sess.last_peer_rx = now;
                if delivered {
                    sess.rx_pkts += 1;
                    sess.rx_bytes += pn as u64;
                    record_server_media_bytes(sess, now, pn as u64);
                }
            }
        }
        SrtpFrame::Probe(pn) => {
            if let Some(sess) = sessions_by_token.get_mut(&tok) {
                sess.last_data_active = now;
                sess.last_peer_rx = now;
                let target = if sess
                    .pending_migrations
                    .iter()
                    .any(|m| m.cand_addr == from_peer && now <= m.expires_at)
                {
                    from_peer
                } else {
                    sess.peer_addr
                };
                let mut pbuf = [0u8; 2048];
                if let Some(ref mut cipher) = sess.cipher {
                    if let Some(wn) = cipher.wrap_probe_into(&wbuf[..pn], &mut pbuf) {
                        audit_pkt(1, &pbuf[..wn]);
                        if listen_sock.send_to(&pbuf[..wn], target).is_ok() {
                            sess.rx_pkts += 1;
                            sess.tx_pkts += 1;
                        }
                    }
                }
                record_server_media_bytes(sess, now, (pn as u64) * 2);
            }
        }
        SrtpFrame::PathChallenge(pn) => {
            // V4 1-RTT ICE path reachability response: [0x02 || nonce(8B) || epoch_be(8B)]
            if pn == 17 && wbuf[0] == 0x02 {
                let got_nonce: [u8; 8] = wbuf[1..9].try_into().unwrap();
                let got_epoch = u64::from_be_bytes(wbuf[9..17].try_into().unwrap());
                if let Some(sess) = sessions_by_token.get_mut(&tok) {
                    sess.rx_pkts += 1;
                    sess.last_peer_rx = now;
                    let matched_mig = sess
                        .pending_migrations
                        .iter()
                        .find(|m| {
                            m.cand_addr == from_peer
                                && now <= m.expires_at
                                && got_epoch == m.epoch
                                && bool::from(got_nonce.ct_eq(&m.nonce))
                        })
                        .copied();
                    if let Some(mig) = matched_mig {
                        let old_peer = sess.peer_addr;
                        // Clean previous old_peer_addr & all local_mig_pending entries for this session
                        if let Some((prev_old, _)) = sess.old_peer_addr.take() {
                            if prev_old != old_peer
                                && prev_old != from_peer
                                && token_by_peer.get(&prev_old) == Some(&tok)
                            {
                                token_by_peer.remove(&prev_old);
                            }
                        }
                        for m in sess.pending_migrations.drain(..) {
                            if local_mig_pending.get(&m.cand_addr).map(|&(t, _)| t) == Some(tok) {
                                local_mig_pending.remove(&m.cand_addr);
                            }
                        }
                        sess.path_epoch = mig.epoch;
                        sess.peer_addr = from_peer;
                        if old_peer != from_peer {
                            sess.old_peer_addr = Some((old_peer, now + OLD_PEER_DRAIN_TTL));
                        }
                        // P0-1: ONLY insert `from_peer` into `token_by_peer` AFTER 0xFFFD verification!
                        token_by_peer.insert(from_peer, tok);
                        send_encrypted_path_confirm(
                            sess,
                            from_peer,
                            got_nonce,
                            listen_sock,
                            audit_pkt,
                        );
                        log(
                            worker_id,
                            &format!(
                                "ICE 1-RTT MIGRATION verified ufrag={} {} -> {} epoch={} backend_sport={} (preserved!)",
                                sess.username, old_peer, from_peer, sess.path_epoch, sess.backend_lport
                            ),
                        );
                        if let Some(th) = telemetry {
                            th.record_migration_1rtt(format!(
                                "ufrag={} backend_sport={}",
                                sess.username, sess.backend_lport
                            ));
                        }
                        return;
                    }
                    // Duplicate response after migration already completed -> idempotently re-confirm
                    if from_peer == sess.peer_addr && got_epoch == sess.path_epoch {
                        send_encrypted_path_confirm(
                            sess,
                            from_peer,
                            got_nonce,
                            listen_sock,
                            audit_pkt,
                        );
                    }
                }
            }
        }
        SrtpFrame::Handover(pn) => {
            // V4 MBB encrypted backend_sock handover: [0x01 || old_ufrag_len(1B) || old_ufrag || proof(32B)]
            if pn < 34 || wbuf[0] != 0x01 {
                return;
            }
            let ulen = wbuf[1] as usize;
            if ulen == 0 || ulen > 64 || pn != 2 + ulen + 32 {
                return;
            }
            let Ok(old_ufrag) = std::str::from_utf8(&wbuf[2..2 + ulen]) else {
                return;
            };
            let old_ufrag = old_ufrag.to_string();
            let proof: [u8; 32] = wbuf[2 + ulen..2 + ulen + 32].try_into().unwrap();

            let Some((new_ufrag, new_key)) = sessions_by_token.get_mut(&tok).and_then(|s| {
                s.rx_pkts += 1;
                s.last_peer_rx = now;
                s.session_key.map(|k| (s.username.clone(), k))
            }) else {
                return;
            };
            if old_ufrag == new_ufrag {
                return;
            }

            // 1) Check if old session lives on THIS worker (fast atomic local handover!)
            if let Some(&old_tok) = token_by_ufrag.get(&old_ufrag) {
                if old_tok != tok {
                    enum LocalHandoverAction {
                        Reject,
                        IdempotentOk,
                        Transfer(Option<(MioUdpSocket, u16)>),
                    }
                    let action = if let Some(old_s) = sessions_by_token.get_mut(&old_tok) {
                        let verified = old_s
                            .session_key
                            .map(|old_key| {
                                let expected = compute_handover_proof(&old_key, &new_key);
                                bool::from(proof.ct_eq(&expected))
                            })
                            .unwrap_or(false);
                        if !verified {
                            LocalHandoverAction::Reject
                        } else if old_s.handed_over_to.as_deref() == Some(new_ufrag.as_str()) {
                            // P1-1: Idempotent retry of same handover!
                            LocalHandoverAction::IdempotentOk
                        } else if old_s.handed_over_to.is_some() {
                            // P1-1: Already handed over to another session -> block double-handover!
                            LocalHandoverAction::Reject
                        } else {
                            old_s.handed_over_to = Some(new_ufrag.clone());
                            let old_lport = old_s.backend_lport;
                            let prev_pipe = std::mem::replace(
                                &mut old_s.backend,
                                BackendPipe::ForwardLocal {
                                    target_tok: tok,
                                    target_ufrag: new_ufrag.clone(),
                                },
                            );
                            match prev_pipe {
                                BackendPipe::Owned(mut sock) => {
                                    let _ = poll.registry().deregister(&mut sock);
                                    LocalHandoverAction::Transfer(Some((sock, old_lport)))
                                }
                                // P1-1: Even if Unbound, old_s stays ForwardLocal so no dual-socket split-brain!
                                BackendPipe::Unbound => LocalHandoverAction::Transfer(None),
                                other => {
                                    old_s.backend = other;
                                    LocalHandoverAction::Transfer(None)
                                }
                            }
                        }
                    } else {
                        LocalHandoverAction::Reject
                    };

                    if let Some(new_s) = sessions_by_token.get_mut(&tok) {
                        match action {
                            LocalHandoverAction::Reject => {
                                new_s.auth_drops += 1;
                                send_encrypted_handover_ack(new_s, false, listen_sock, audit_pkt);
                            }
                            LocalHandoverAction::IdempotentOk => {
                                send_encrypted_handover_ack(new_s, true, listen_sock, audit_pkt);
                            }
                            LocalHandoverAction::Transfer(sock_opt) => {
                                if let Some((mut sock, lport)) = sock_opt {
                                    deregister_backend(poll, &mut new_s.backend);
                                    if poll
                                        .registry()
                                        .register(&mut sock, tok, Interest::READABLE)
                                        .is_ok()
                                    {
                                        new_s.backend = BackendPipe::Owned(sock);
                                        new_s.backend_lport = lport;
                                        log(
                                            worker_id,
                                            &format!(
                                                "MBB HANDOVER (local) {} -> {} backend_sport={} (0 port change!)",
                                                old_ufrag, new_ufrag, lport
                                            ),
                                        );
                                        if let Some(th) = telemetry {
                                            th.record_mbb_rotation(format!(
                                                "{}->{} backend_sport={}",
                                                old_ufrag, new_ufrag, lport
                                            ));
                                        }
                                    }
                                }
                                send_encrypted_handover_ack(new_s, true, listen_sock, audit_pkt);
                            }
                        }
                    }
                    return;
                }
            }

            // 2) Check if old session lives on ANOTHER worker (Linux SO_REUSEPORT multi-worker!)
            if let Some(meta) = registry.lookup_ufrag(&old_ufrag) {
                if meta.worker_id != worker_id {
                    registry.send_cmd(
                        meta.worker_id,
                        WorkerCmd::HandoverExtract {
                            old_ufrag,
                            new_ufrag,
                            new_session_key: new_key,
                            proof,
                            target_worker: worker_id,
                        },
                    );
                    return;
                }
            }

            // Not found anywhere -> send negative ack cleanly so client does not stall
            if let Some(s) = sessions_by_token.get_mut(&tok) {
                send_encrypted_handover_ack(s, false, listen_sock, audit_pkt);
            }
        }
    }
}

pub fn run_server(cfg: ServerConfig) -> std::io::Result<()> {
    let workers = cfg.workers.max(1);
    let cpu = detect_cpu_accel();
    let dtls_pool = build_dimpl_config_pool(cfg.cipher_pref, &cpu, false, cfg.wan_mtu);
    let seen_txids = Arc::new(Mutex::new(SeenTxidCache::new()));
    let registry = Arc::new(SharedV4Registry::new(workers));
    let telemetry = TelemetryHub::start(
        "server",
        &cfg.telemetry,
        workers,
        cfg.wan_mtu,
        cfg.quiet,
        cfg.stop.clone(),
    );
    if !cfg.quiet {
        println!(
            "[server-rs] V4.0 CPU arch={} hw_accel=[{}] recommended={} workers={} dtls=dimpl-{}(mutual-cert,cookie,pfs) silent_drop=true",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            workers,
            cfg.dtls_min_version.as_str(),
        );
    }
    #[cfg(not(target_os = "linux"))]
    if workers > 1 {
        eprintln!("[server-rs] WARN: SO_REUSEPORT UDP hash load-balancing is Linux-specific.");
    }

    if workers == 1 {
        let res = run_server_worker(0, cfg, false, dtls_pool, seen_txids, registry, telemetry.clone());
        if let Some(ref th) = telemetry {
            th.shutdown();
        }
        return res;
    }

    let mut handles = Vec::with_capacity(workers - 1);
    for wid in 1..workers {
        let mut c = cfg.clone();
        c.wire_audit_file = None;
        let dp = dtls_pool.clone();
        let cache = Arc::clone(&seen_txids);
        let reg = Arc::clone(&registry);
        let tel = telemetry.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = run_server_worker(wid, c, true, dp, cache, reg, tel) {
                eprintln!("[server-rs#{}] error: {}", wid, e);
            }
        }));
    }
    let res = run_server_worker(0, cfg, true, dtls_pool, seen_txids, registry, telemetry.clone());
    for h in handles {
        let _ = h.join();
    }
    if let Some(ref th) = telemetry {
        th.shutdown();
    }
    res
}

fn run_server_worker(
    worker_id: usize,
    cfg: ServerConfig,
    reuse_port: bool,
    dtls_pool: DtlsConfigPool,
    seen_txids: Arc<Mutex<SeenTxidCache>>,
    registry: Arc<SharedV4Registry>,
    telemetry: Option<Arc<TelemetryHub>>,
) -> std::io::Result<()> {
    SERVER_QUIET.with(|q| q.set(cfg.quiet));
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(256);
    if let Ok(waker) = Waker::new(poll.registry(), WAKE_TOKEN) {
        let arc_w = Arc::new(waker);
        registry.set_waker(worker_id, Arc::clone(&arc_w));
        if !cfg.quiet && cfg.stop.is_some() {
            register_shutdown_waker(arc_w);
        }
    }

    let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port, 8 * 1024 * 1024)?;
    poll.registry()
        .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;

    let mut sessions_by_token: HashMap<Token, ServerSession> = HashMap::new();
    let mut token_by_peer: HashMap<SocketAddr, Token> = HashMap::new();
    let mut token_by_ufrag: HashMap<String, Token> = HashMap::new();
    // P0-1 & P0-4: Unverified same-worker 1-RTT migration candidates (NEVER pollute `token_by_peer`!).
    let mut local_mig_pending: HashMap<SocketAddr, (Token, Instant)> = HashMap::new();
    // Pending cross-worker 1-RTT migration candidates seen on THIS worker:
    // `cand_addr -> (ufrag, owner_worker_id, expires_at)`.
    let mut cross_worker_pending: HashMap<SocketAddr, (String, usize, Instant)> = HashMap::new();
    let mut cmd_buf: Vec<WorkerCmd> = Vec::new();
    let mut next_token_id: usize = 1;
    let mut cert_cache = CertCache::new();
    let stun_mi_key = stun_hmac_key(&cfg.psk);
    let max_early_srtp_len = if cfg.wan_mtu > 0 {
        cfg.wan_mtu.saturating_sub(28).clamp(576, 2048)
    } else {
        2048
    };

    let mut audit_fp = cfg
        .wire_audit_file
        .as_ref()
        .map(|p| File::create(p))
        .transpose()?;
    let mut audit_count: usize = 0;
    let mut unauth_drops: u64 = 0;
    let mut closed_tx_bytes: u64 = 0;
    let mut closed_rx_bytes: u64 = 0;
    let mut closed_tx_pkts: u64 = 0;
    let mut closed_rx_pkts: u64 = 0;
    let mut closed_auth_drops: u64 = 0;

    let mut rbuf = vec![0u8; 65536];
    let mut wbuf = vec![0u8; 65536 + 128];
    let mut dtls_buf = vec![0u8; 4096];

    let cpu = detect_cpu_accel();
    log(
        worker_id,
        &format!(
            "listening on {} -> backend {} (reuse_port={}, cipher_pref={:?}, dtls_required={}, max_sessions={})",
            cfg.listen_addr, cfg.backend_addr, reuse_port, cfg.cipher_pref, cfg.dtls_required, cfg.max_sessions
        ),
    );

    let idle_dur = Duration::from_secs(cfg.idle_timeout_secs);
    let stats_dur = Duration::from_secs(cfg.stats_interval_secs);
    let mut last_stats = Instant::now();
    let telemetry_dur = telemetry
        .as_ref()
        .map(|th| th.interval())
        .unwrap_or(Duration::from_secs(5));
    let mut last_telemetry = Instant::now();

    let mut audit_pkt = |d_code: u8, payload: &[u8]| {
        if let Some(ref mut f) = audit_fp {
            if audit_count < 128 {
                let _ = f.write_all(&[d_code]);
                let _ = f.write_all(&(payload.len() as u32).to_be_bytes());
                let _ = f.write_all(payload);
                let _ = f.flush();
                audit_count += 1;
            }
        }
    };

    let alloc_token = |next_id: &mut usize| -> Token {
        let tok = Token(*next_id);
        *next_id = next_id.wrapping_add(1);
        if *next_id == 0 || *next_id == usize::MAX {
            *next_id = 1;
        }
        tok
    };

    loop {
        if let Some(ref s) = cfg.stop {
            if s.load(Ordering::Relaxed) {
                let mut torn = 0usize;
                for sess in sessions_by_token.values_mut() {
                    if sess.state == ServerState::Ready {
                        graceful_teardown_server(sess, &listen_sock, &mut dtls_buf, &mut audit_pkt);
                        torn += 1;
                    }
                }
                if torn > 0 {
                    log(
                        worker_id,
                        &format!(
                            "shutdown signal: sent graceful SRTCP BYE + DTLS close_notify to {} active session(s)",
                            torn
                        ),
                    );
                }
                return Ok(());
            }
        }

        let now = Instant::now();

        // Drain cross-worker V4 control commands (0 lock on SRTP hot path!)
        cmd_buf.clear();
        registry.drain_cmds(worker_id, &mut cmd_buf);
        for cmd in cmd_buf.drain(..) {
            match cmd {
                WorkerCmd::CrossWorkerChallengeRequest {
                    ufrag,
                    cand_addr,
                    cand_worker,
                    stun_resp,
                } => {
                    if let Some(&tok) = token_by_ufrag.get(&ufrag) {
                        if let Some(sess) = sessions_by_token.get_mut(&tok) {
                            if sess.state == ServerState::Ready {
                                if let Some((nonce, epoch)) = arm_or_reuse_migration_challenge(
                                    sess,
                                    cand_addr,
                                    cand_worker,
                                    now,
                                ) {
                                    audit_pkt(1, &stun_resp);
                                    let _ = listen_sock.send_to(&stun_resp, cand_addr);
                                    send_encrypted_path_challenge(
                                        sess,
                                        cand_addr,
                                        nonce,
                                        epoch,
                                        &listen_sock,
                                        &mut audit_pkt,
                                    );
                                }
                            }
                        }
                    }
                }
                WorkerCmd::CrossWorkerChallengeVerify {
                    ufrag,
                    cand_addr,
                    cand_worker,
                    pkt,
                } => {
                    let Some(&tok) = token_by_ufrag.get(&ufrag) else {
                        // Session may have just migrated to `cand_worker` (<20us race): bounce packet there!
                        if let Some(meta) = registry.lookup_ufrag(&ufrag) {
                            if meta.worker_id == cand_worker {
                                registry.send_cmd(
                                    cand_worker,
                                    WorkerCmd::ReprocessSrtp {
                                        peer_addr: cand_addr,
                                        pkt,
                                    },
                                );
                            }
                        }
                        continue;
                    };
                    let mut should_move = false;
                    let mut early_data_len: Option<usize> = None;
                    if let Some(sess) = sessions_by_token.get_mut(&tok) {
                        if sess.state == ServerState::Ready {
                            let has_slot = sess.pending_migrations.iter().any(|m| {
                                m.cand_addr == cand_addr
                                    && m.cand_worker == cand_worker
                                    && now <= m.expires_at
                            });
                            if has_slot {
                                match sess
                                    .cipher
                                    .as_mut()
                                    .and_then(|c| c.unwrap_into_ex(&pkt, &mut wbuf))
                                {
                                    Some(SrtpFrame::PathChallenge(pn))
                                        if pn == 17 && wbuf[0] == 0x02 =>
                                    {
                                        sess.rx_pkts += 1;
                                        let got_nonce: [u8; 8] = wbuf[1..9].try_into().unwrap();
                                        let got_epoch =
                                            u64::from_be_bytes(wbuf[9..17].try_into().unwrap());
                                        let matched = sess
                                            .pending_migrations
                                            .iter()
                                            .find(|m| {
                                                m.cand_addr == cand_addr
                                                    && m.cand_worker == cand_worker
                                                    && now <= m.expires_at
                                                    && got_epoch == m.epoch
                                                    && bool::from(got_nonce.ct_eq(&m.nonce))
                                            })
                                            .copied();
                                        if let Some(mig) = matched {
                                            // P1-3: Clean any prior old_peer_addr before overwriting!
                                            if let Some((prev_old, _)) = sess.old_peer_addr.take() {
                                                if prev_old != sess.peer_addr
                                                    && token_by_peer.get(&prev_old) == Some(&tok)
                                                {
                                                    token_by_peer.remove(&prev_old);
                                                }
                                            }
                                            let old_peer = sess.peer_addr;
                                            sess.path_epoch = mig.epoch;
                                            sess.old_peer_addr =
                                                Some((old_peer, now + OLD_PEER_DRAIN_TTL));
                                            sess.peer_addr = cand_addr;
                                            for m in sess.pending_migrations.drain(..) {
                                                if local_mig_pending
                                                    .get(&m.cand_addr)
                                                    .map(|&(t, _)| t)
                                                    == Some(tok)
                                                {
                                                    local_mig_pending.remove(&m.cand_addr);
                                                }
                                            }
                                            sess.last_peer_rx = now;
                                            send_encrypted_path_confirm(
                                                sess,
                                                cand_addr,
                                                got_nonce,
                                                &listen_sock,
                                                &mut audit_pkt,
                                            );
                                            should_move = true;
                                        }
                                    }
                                    Some(SrtpFrame::Data(pn)) => {
                                        sess.last_data_active = now;
                                        sess.last_peer_rx = now;
                                        early_data_len = Some(pn);
                                    }
                                    _ => {
                                        sess.auth_drops += 1;
                                    }
                                }
                            }
                        }
                    }
                    if let Some(pn) = early_data_len {
                        let ok = deliver_uplink_payload(
                            worker_id,
                            tok,
                            &wbuf[..pn],
                            MAX_FORWARD_HOPS,
                            &mut sessions_by_token,
                            &poll,
                            cfg.backend_addr,
                            &registry,
                        );
                        if ok {
                            if let Some(sess) = sessions_by_token.get_mut(&tok) {
                                sess.rx_pkts += 1;
                                sess.rx_bytes += pn as u64;
                                record_server_media_bytes(sess, now, pn as u64);
                            }
                        }
                    }
                    if should_move {
                        if let Some(mut sess) = sessions_by_token.remove(&tok) {
                            deregister_backend(&poll, &mut sess.backend);
                            token_by_ufrag.remove(&sess.username);
                            if let Some((old_p, _)) = sess.old_peer_addr.take() {
                                if token_by_peer.get(&old_p) == Some(&tok) {
                                    token_by_peer.remove(&old_p);
                                }
                            }
                            if token_by_peer.get(&sess.peer_addr) == Some(&tok) {
                                token_by_peer.remove(&sess.peer_addr);
                            }
                            if let Some(mk) = sess.mi_key_mig {
                                registry.register_session(
                                    &sess.username,
                                    cand_worker,
                                    mk,
                                    sess.tie_breaker,
                                );
                            }
                            log(
                                worker_id,
                                &format!(
                                    "ICE 1-RTT MIGRATION (cross-worker {}->{}) ufrag={} -> {} epoch={} backend_sport={}",
                                    worker_id, cand_worker, sess.username, sess.peer_addr, sess.path_epoch, sess.backend_lport
                                ),
                            );
                            if let Some(ref th) = telemetry {
                                th.record_migration_1rtt(format!(
                                    "ufrag={} cross_worker={}->{} backend_sport={}",
                                    sess.username, worker_id, cand_worker, sess.backend_lport
                                ));
                            }
                            registry.send_cmd(
                                cand_worker,
                                WorkerCmd::MigrateInstall {
                                    sess: Box::new(sess),
                                },
                            );
                        }
                    }
                }
                WorkerCmd::MigrateInstall { mut sess } => {
                    let new_tok = alloc_token(&mut next_token_id);
                    if let BackendPipe::Owned(ref mut sock) = sess.backend {
                        let _ = poll.registry().register(sock, new_tok, Interest::READABLE);
                    }
                    cross_worker_pending.remove(&sess.peer_addr);
                    // P1-3: Only register verified `sess.peer_addr` (do not insert foreign old_p!)
                    sess.old_peer_addr = None;
                    token_by_peer.insert(sess.peer_addr, new_tok);
                    token_by_ufrag.insert(sess.username.clone(), new_tok);
                    sessions_by_token.insert(new_tok, *sess);
                }
                WorkerCmd::HandoverExtract {
                    old_ufrag,
                    new_ufrag,
                    new_session_key,
                    proof,
                    target_worker,
                } => {
                    let mut ok = false;
                    let mut extracted: Option<(MioUdpSocket, u16)> = None;
                    if let Some(&old_tok) = token_by_ufrag.get(&old_ufrag) {
                        if let Some(old_s) = sessions_by_token.get_mut(&old_tok) {
                            if let Some(old_key) = old_s.session_key {
                                let expected = compute_handover_proof(&old_key, &new_session_key);
                                if bool::from(proof.ct_eq(&expected)) {
                                    if old_s.handed_over_to.as_deref() == Some(new_ufrag.as_str()) {
                                        ok = true;
                                    } else if old_s.handed_over_to.is_none() {
                                        ok = true;
                                        old_s.handed_over_to = Some(new_ufrag.clone());
                                        let lport = old_s.backend_lport;
                                        let prev = std::mem::replace(
                                            &mut old_s.backend,
                                            BackendPipe::ForwardRemote {
                                                target_worker,
                                                target_ufrag: new_ufrag.clone(),
                                            },
                                        );
                                        match prev {
                                            BackendPipe::Owned(mut sock) => {
                                                let _ = poll.registry().deregister(&mut sock);
                                                extracted = Some((sock, lport));
                                            }
                                            // P1-1: Even if Unbound, old_s stays ForwardRemote!
                                            BackendPipe::Unbound => {}
                                            other => {
                                                old_s.backend = other;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if let Some((sock, lport)) = extracted {
                        registry.send_cmd(
                            target_worker,
                            WorkerCmd::HandoverInstall {
                                new_ufrag,
                                backend_sock: sock,
                                backend_lport: lport,
                            },
                        );
                    } else {
                        registry.send_cmd(
                            target_worker,
                            WorkerCmd::HandoverAckOnly { new_ufrag, ok },
                        );
                    }
                }
                WorkerCmd::HandoverInstall {
                    new_ufrag,
                    mut backend_sock,
                    backend_lport,
                } => {
                    if let Some(&new_tok) = token_by_ufrag.get(&new_ufrag) {
                        if let Some(new_s) = sessions_by_token.get_mut(&new_tok) {
                            if new_s.state == ServerState::Ready {
                                deregister_backend(&poll, &mut new_s.backend);
                                if poll
                                    .registry()
                                    .register(&mut backend_sock, new_tok, Interest::READABLE)
                                    .is_ok()
                                {
                                    new_s.backend = BackendPipe::Owned(backend_sock);
                                    new_s.backend_lport = backend_lport;
                                    log(
                                        worker_id,
                                        &format!(
                                            "MBB HANDOVER (cross-worker) -> {} backend_sport={} (0 port change!)",
                                            new_ufrag, backend_lport
                                        ),
                                    );
                                    if let Some(ref th) = telemetry {
                                        th.record_mbb_rotation(format!(
                                            "cross_worker->{} backend_sport={}",
                                            new_ufrag, backend_lport
                                        ));
                                    }
                                    send_encrypted_handover_ack(
                                        new_s,
                                        true,
                                        &listen_sock,
                                        &mut audit_pkt,
                                    );
                                }
                            }
                        }
                    }
                }
                WorkerCmd::HandoverAckOnly { new_ufrag, ok } => {
                    if let Some(&new_tok) = token_by_ufrag.get(&new_ufrag) {
                        if let Some(new_s) = sessions_by_token.get_mut(&new_tok) {
                            send_encrypted_handover_ack(new_s, ok, &listen_sock, &mut audit_pkt);
                        }
                    }
                }
                WorkerCmd::DrainUplinkForward {
                    target_ufrag,
                    payload,
                    hops_left,
                } => {
                    if let Some(&t_tok) = token_by_ufrag.get(&target_ufrag) {
                        let _ = deliver_uplink_payload(
                            worker_id,
                            t_tok,
                            &payload,
                            hops_left,
                            &mut sessions_by_token,
                            &poll,
                            cfg.backend_addr,
                            &registry,
                        );
                    } else if hops_left > 0 {
                        if let Some(meta) = registry.lookup_ufrag(&target_ufrag) {
                            if meta.worker_id != worker_id {
                                registry.send_cmd(
                                    meta.worker_id,
                                    WorkerCmd::DrainUplinkForward {
                                        target_ufrag,
                                        payload,
                                        hops_left: hops_left - 1,
                                    },
                                );
                            }
                        }
                    }
                }
                WorkerCmd::ReprocessSrtp { peer_addr, pkt } => {
                    if let Some(&tok) = token_by_peer.get(&peer_addr) {
                        process_ready_srtp(
                            worker_id,
                            tok,
                            peer_addr,
                            &pkt,
                            &mut sessions_by_token,
                            &mut token_by_peer,
                            &mut token_by_ufrag,
                            &mut local_mig_pending,
                            &poll,
                            &listen_sock,
                            &cfg,
                            &registry,
                            telemetry.as_ref(),
                            &mut wbuf,
                            now,
                            &mut audit_pkt,
                        );
                    }
                }
            }
        }

        // Expire stale local & cross-worker pending migration lookups
        if !local_mig_pending.is_empty() {
            local_mig_pending.retain(|_, (_, exp)| now <= *exp);
        }
        if !cross_worker_pending.is_empty() {
            cross_worker_pending.retain(|_, (_, _, exp)| now <= *exp);
        }

        let mut wait = if sessions_by_token.is_empty() {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(1)
        };
        let mut to_close: Vec<(Token, &'static str)> = Vec::new();
        let mut newly_ready_early: Vec<Token> = Vec::new();

        for (&tok, sess) in sessions_by_token.iter_mut() {
            // Expire old_peer_addr and unverified pending_migrations cleanly
            if let Some((old_p, exp)) = sess.old_peer_addr {
                if now >= exp {
                    sess.old_peer_addr = None;
                    if old_p != sess.peer_addr && token_by_peer.get(&old_p) == Some(&tok) {
                        token_by_peer.remove(&old_p);
                    }
                }
            }
            if !sess.pending_migrations.is_empty() {
                sess.pending_migrations.retain(|m| now <= m.expires_at);
            }

            match sess.state {
                ServerState::DtlsHandshake => {
                    if now.duration_since(sess.last_data_active) > Duration::from_secs(15) {
                        to_close.push((tok, "dtls_handshake_timeout"));
                        continue;
                    }
                    if let Some(t) = sess.dtls_next_timeout {
                        if now >= t {
                            let err = if let Some(ref mut dtls) = sess.dtls {
                                dtls.handle_timeout(now).is_err()
                            } else {
                                true
                            };
                            if err {
                                to_close.push((tok, "dtls_timeout_err"));
                                continue;
                            }
                            let (peer_closed, became_ready) = drain_server_dtls(
                                worker_id,
                                sess,
                                &listen_sock,
                                &mut dtls_buf,
                                &cfg,
                                &cpu,
                                &registry,
                                now,
                                &mut audit_pkt,
                            );
                            if became_ready && !sess.early_srtp.is_empty() {
                                newly_ready_early.push(tok);
                            }
                            if peer_closed {
                                sess.state = ServerState::Closing(
                                    now + Duration::from_millis(CLOSING_DRAIN_MS),
                                    false,
                                );
                            }
                        } else {
                            let rem = t.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(5));
                            }
                        }
                    }
                }
                ServerState::Ready => {
                    if now.duration_since(sess.last_peer_rx) > PEER_CONSENT_TIMEOUT {
                        to_close.push((tok, "consent_timeout"));
                        continue;
                    }
                    let seq_exhausted = sess
                        .cipher
                        .as_ref()
                        .map(|c| c.is_seq_exhausted())
                        .unwrap_or(false);
                    if seq_exhausted || now.duration_since(sess.last_data_active) > idle_dur {
                        graceful_teardown_server(sess, &listen_sock, &mut dtls_buf, &mut audit_pkt);
                        sess.state = ServerState::Closing(
                            now + Duration::from_millis(CLOSING_DRAIN_MS),
                            false,
                        );
                        continue;
                    }
                    if now >= sess.next_srtcp_at {
                        let age_ge_15s = sess
                            .ready_at
                            .map_or(false, |r| now.duration_since(r) >= Duration::from_secs(15));
                        let in_trickle = age_ge_15s
                            && sess.rate_15s.bytes_in_window(now) < TRICKLE_RATE_15S_BYTES;
                        let long_trickle = in_trickle
                            && now.duration_since(sess.last_active_burst) >= Duration::from_secs(60);
                        if long_trickle {
                            sess.next_srtcp_at = now + Duration::from_secs(10);
                        } else {
                            let is_active_media = !in_trickle
                                && now.duration_since(sess.last_data_active) <= Duration::from_secs(3);
                            let sent_media = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
                            let has_rx = sess.rx_pkts > sess.rx_pkts_at_last_rtcp;
                            sess.tx_pkts_at_last_rtcp = sess.tx_pkts;
                            sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
                            if let Some(ref mut cipher) = sess.cipher {
                                let rtcp = cipher.build_srtcp(has_rx, sent_media, false);
                                audit_pkt(1, &rtcp);
                                if listen_sock.send_to(&rtcp, sess.peer_addr).is_ok() {
                                    sess.srtcp_tx += 1;
                                }
                            }
                            sess.next_srtcp_at = now
                                + if is_active_media {
                                    rand_duration_range_ms(950, 1950)
                                } else if !in_trickle {
                                    rand_duration_range_ms(3500, 6500)
                                } else {
                                    rand_duration_range_ms(20_000, 40_000)
                                };
                        }
                    } else {
                        let rem = sess.next_srtcp_at.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(10));
                        }
                    }
                }
                ServerState::Closing(deadline, _) => {
                    if now >= deadline {
                        to_close.push((tok, "graceful_close"));
                    } else {
                        let rem = deadline.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(10));
                        }
                    }
                }
            }
        }

        // Flush any buffered early SRTP on sessions that became Ready during DTLS timeout
        for tok in newly_ready_early {
            let (peer_addr, early_pkts): (SocketAddr, Vec<Vec<u8>>) =
                match sessions_by_token.get_mut(&tok) {
                    Some(s) => (s.peer_addr, s.early_srtp.drain(..).collect()),
                    None => continue,
                };
            for raw in early_pkts {
                process_ready_srtp(
                    worker_id,
                    tok,
                    peer_addr,
                    &raw,
                    &mut sessions_by_token,
                    &mut token_by_peer,
                    &mut token_by_ufrag,
                    &mut local_mig_pending,
                    &poll,
                    &listen_sock,
                    &cfg,
                    &registry,
                    telemetry.as_ref(),
                    &mut wbuf,
                    now,
                    &mut audit_pkt,
                );
            }
        }

        for (tok, reason) in to_close {
            if let Some(mut sess) = sessions_by_token.remove(&tok) {
                closed_tx_bytes = closed_tx_bytes.saturating_add(sess.tx_bytes);
                closed_rx_bytes = closed_rx_bytes.saturating_add(sess.rx_bytes);
                closed_tx_pkts = closed_tx_pkts.saturating_add(sess.tx_pkts);
                closed_rx_pkts = closed_rx_pkts.saturating_add(sess.rx_pkts);
                closed_auth_drops = closed_auth_drops.saturating_add(sess.auth_drops);
                cleanup_session_routes(
                    worker_id,
                    tok,
                    &mut sess,
                    &poll,
                    &mut token_by_peer,
                    &mut token_by_ufrag,
                    &mut local_mig_pending,
                    &registry,
                );
                log(
                    worker_id,
                    &format!(
                        "close session peer={} reason={} rx={}pkts tx={}pkts ka={} rtcp={}/{} drops={}",
                        sess.peer_addr, reason, sess.rx_pkts, sess.tx_pkts, sess.keepalives,
                        sess.srtcp_tx, sess.srtcp_rx, sess.auth_drops
                    ),
                );
            }
        }

        if telemetry.is_some() && wait > telemetry_dur {
            wait = telemetry_dur;
        }
        if cfg.stop.is_some() && cfg.quiet && wait > Duration::from_millis(20) {
            wait = Duration::from_millis(20);
        }
        if let Err(e) = poll.poll(&mut events, Some(wait)) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }

        let now = Instant::now();
        for ev in events.iter() {
            if ev.token() == WAKE_TOKEN {
                continue;
            }
            if ev.token() == LISTEN_TOKEN {
                loop {
                    let (n, peer_addr) = match listen_sock.recv_from(&mut rbuf) {
                        Ok(v) => v,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    };
                    let pkt = &rbuf[..n];
                    audit_pkt(0, pkt);

                    let peer_v4 = match peer_addr {
                        SocketAddr::V4(v4) => v4,
                        SocketAddr::V6(_) => SocketAddrV4::new(Ipv4Addr::LOCALHOST, peer_addr.port()),
                    };

                    match demux_rfc7983(pkt) {
                        PacketKind::Stun => {
                            // V4 + P0-1 fix: `already_same_peer` strictly checks `s.peer_addr == peer_addr`
                            // (NOT old_peer_addr or unverified candidate!) so retries & Addr1->Addr2->Addr1
                            // switchbacks always enter the V4 migration path cleanly!
                            let mig_meta = peek_stun_request_username(pkt).and_then(|u| {
                                let already_same_peer = token_by_peer
                                    .get(&peer_addr)
                                    .and_then(|t| sessions_by_token.get(t))
                                    .map(|s| {
                                        s.peer_addr == peer_addr
                                            && s.username == u
                                            && !matches!(s.state, ServerState::Closing(_, _))
                                    })
                                    .unwrap_or(false);
                                if already_same_peer {
                                    None
                                } else {
                                    registry.lookup_ufrag(u)
                                }
                            });

                            if let Some(meta) = mig_meta {
                                if let Some(parsed) =
                                    parse_stun_with_key(pkt, &cfg.psk, &meta.mi_key_mig)
                                {
                                    if parsed.msg_type == STUN_BINDING_REQUEST
                                        && parsed.authenticated
                                        && parsed.use_candidate
                                        && parsed.tie_breaker == Some(meta.tie_breaker)
                                    {
                                        let uname = parsed.username.unwrap_or_default();
                                        let txid_status = {
                                            let mut cache = seen_txids.lock().unwrap();
                                            cache.check(parsed.txid, peer_addr, now, true)
                                        };
                                        match txid_status {
                                            TxidCheck::Rejected => {
                                                unauth_drops += 1;
                                                continue;
                                            }
                                            TxidCheck::Retransmit(buf, len) => {
                                                let reply = &buf[..len as usize];
                                                if meta.worker_id == worker_id {
                                                    if let Some(&tok) = token_by_ufrag.get(&uname) {
                                                        if let Some(sess) =
                                                            sessions_by_token.get_mut(&tok)
                                                        {
                                                            if let Some((nonce, epoch)) =
                                                                arm_or_reuse_migration_challenge(
                                                                    sess,
                                                                    peer_addr,
                                                                    worker_id,
                                                                    now,
                                                                )
                                                            {
                                                                audit_pkt(1, reply);
                                                                let _ = listen_sock
                                                                    .send_to(reply, peer_addr);
                                                                send_encrypted_path_challenge(
                                                                    sess,
                                                                    peer_addr,
                                                                    nonce,
                                                                    epoch,
                                                                    &listen_sock,
                                                                    &mut audit_pkt,
                                                                );
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    // P2-2: Symmetric cross-worker retransmit re-triggers idempotent challenge
                                                    registry.send_cmd(
                                                        meta.worker_id,
                                                        WorkerCmd::CrossWorkerChallengeRequest {
                                                            ufrag: uname,
                                                            cand_addr: peer_addr,
                                                            cand_worker: worker_id,
                                                            stun_resp: reply.to_vec(),
                                                        },
                                                    );
                                                }
                                                continue;
                                            }
                                            TxidCheck::Fresh => {}
                                        }

                                        let resp = build_stun_success_response_with_key(
                                            &parsed.txid,
                                            peer_v4,
                                            &meta.mi_key_mig,
                                        );
                                        {
                                            let mut cache = seen_txids.lock().unwrap();
                                            cache.record(parsed.txid, peer_addr, now, &resp);
                                        }

                                        if meta.worker_id == worker_id {
                                            // P0-1 & P0-2 & P0-4: Same-worker migration uses bounded `local_mig_pending`
                                            // (NEVER touches `token_by_peer` before 0xFFFD proof!) + idempotent nonce + rate limit!
                                            if local_mig_pending.len() >= MAX_MIG_PENDING_MAP {
                                                local_mig_pending.retain(|_, (_, e)| now <= *e);
                                                if local_mig_pending.len() >= MAX_MIG_PENDING_MAP {
                                                    unauth_drops += 1;
                                                    continue;
                                                }
                                            }
                                            if let Some(&tok) = token_by_ufrag.get(&uname) {
                                                if let Some(sess) = sessions_by_token.get_mut(&tok) {
                                                    if sess.state == ServerState::Ready {
                                                        if let Some((nonce, epoch)) =
                                                            arm_or_reuse_migration_challenge(
                                                                sess,
                                                                peer_addr,
                                                                worker_id,
                                                                now,
                                                            )
                                                        {
                                                            local_mig_pending.insert(
                                                                peer_addr,
                                                                (tok, now + MIGRATION_CHALLENGE_TTL),
                                                            );
                                                            audit_pkt(1, &resp);
                                                            let _ = listen_sock
                                                                .send_to(&resp, peer_addr);
                                                            send_encrypted_path_challenge(
                                                                sess,
                                                                peer_addr,
                                                                nonce,
                                                                epoch,
                                                                &listen_sock,
                                                                &mut audit_pkt,
                                                            );
                                                        }
                                                        continue;
                                                    }
                                                }
                                            }
                                        } else {
                                            // P0-4: Bounded `cross_worker_pending`
                                            if cross_worker_pending.len() >= MAX_MIG_PENDING_MAP {
                                                cross_worker_pending
                                                    .retain(|_, (_, _, e)| now <= *e);
                                                if cross_worker_pending.len()
                                                    >= MAX_MIG_PENDING_MAP
                                                {
                                                    unauth_drops += 1;
                                                    continue;
                                                }
                                            }
                                            cross_worker_pending.insert(
                                                peer_addr,
                                                (
                                                    uname.clone(),
                                                    meta.worker_id,
                                                    now + MIGRATION_CHALLENGE_TTL,
                                                ),
                                            );
                                            registry.send_cmd(
                                                meta.worker_id,
                                                WorkerCmd::CrossWorkerChallengeRequest {
                                                    ufrag: uname,
                                                    cand_addr: peer_addr,
                                                    cand_worker: worker_id,
                                                    stun_resp: resp,
                                                },
                                            );
                                            continue;
                                        }
                                    }
                                }
                                // Existing active ufrag from another peer MUST pass mi_key_mig; reject global PSK hijack!
                                unauth_drops += 1;
                                continue;
                            }

                            let parsed = match parse_stun_with_key(pkt, &cfg.psk, &stun_mi_key) {
                                Some(p) if p.msg_type == STUN_BINDING_REQUEST && p.authenticated => p,
                                _ => {
                                    unauth_drops += 1;
                                    continue;
                                }
                            };

                            let uname = parsed.username.unwrap_or_default();
                            let same_active = token_by_peer
                                .get(&peer_addr)
                                .and_then(|tok| sessions_by_token.get(tok))
                                .map(|s| {
                                    s.peer_addr == peer_addr
                                        && s.username == uname
                                        && !matches!(s.state, ServerState::Closing(_, _))
                                })
                                .unwrap_or(false);

                            let txid_status = {
                                let mut cache = seen_txids.lock().unwrap();
                                cache.check(parsed.txid, peer_addr, now, same_active)
                            };

                            match txid_status {
                                TxidCheck::Rejected => {
                                    unauth_drops += 1;
                                    continue;
                                }
                                TxidCheck::Retransmit(buf, len) => {
                                    let reply = &buf[..len as usize];
                                    audit_pkt(1, reply);
                                    let _ = listen_sock.send_to(reply, peer_addr);
                                    if same_active {
                                        if let Some(&tok) = token_by_peer.get(&peer_addr) {
                                            if let Some(sess) = sessions_by_token.get_mut(&tok) {
                                                sess.last_peer_rx = now;
                                            }
                                        }
                                    }
                                    continue;
                                }
                                TxidCheck::Fresh => {}
                            }

                            if same_active {
                                if let Some(&tok) = token_by_peer.get(&peer_addr) {
                                    let resp = build_stun_success_response(&parsed.txid, peer_v4, &cfg.psk);
                                    {
                                        let mut cache = seen_txids.lock().unwrap();
                                        cache.record(parsed.txid, peer_addr, now, &resp);
                                    }
                                    audit_pkt(1, &resp);
                                    let _ = listen_sock.send_to(&resp, peer_addr);
                                    if let Some(sess) = sessions_by_token.get_mut(&tok) {
                                        sess.keepalives += 1;
                                        sess.last_peer_rx = now;
                                    }
                                    continue;
                                }
                            }

                            // NEW-M-01: Reject orphan STUN keepalives (without USE-CANDIDATE)
                            if !parsed.use_candidate {
                                unauth_drops += 1;
                                continue;
                            }

                            // P0-3: Reject duplicate ufrag hijacking an active/handshaking session on another peer!
                            let same_peer_rekey_same_ufrag = token_by_peer
                                .get(&peer_addr)
                                .and_then(|t| sessions_by_token.get(t))
                                .map(|s| s.peer_addr == peer_addr && s.username == uname)
                                .unwrap_or(false);
                            if !same_peer_rekey_same_ufrag
                                && (token_by_ufrag.contains_key(&uname)
                                    || registry.lookup_ufrag(&uname).is_some())
                            {
                                unauth_drops += 1;
                                continue;
                            }

                            // P0-1 fix: Re-key ONLY if `old.peer_addr == peer_addr`!
                            // If `peer_addr` was only a draining `old_peer_addr`, detach that drain key cleanly
                            // WITHOUT destroying the live migrated session!
                            if let Some(&old_tok) = token_by_peer.get(&peer_addr) {
                                let is_exact_primary_peer = sessions_by_token
                                    .get(&old_tok)
                                    .map(|s| s.peer_addr == peer_addr)
                                    .unwrap_or(false);
                                if is_exact_primary_peer {
                                    if let Some(mut old) = sessions_by_token.remove(&old_tok) {
                                        closed_tx_bytes = closed_tx_bytes.saturating_add(old.tx_bytes);
                                        closed_rx_bytes = closed_rx_bytes.saturating_add(old.rx_bytes);
                                        closed_tx_pkts = closed_tx_pkts.saturating_add(old.tx_pkts);
                                        closed_rx_pkts = closed_rx_pkts.saturating_add(old.rx_pkts);
                                        closed_auth_drops = closed_auth_drops.saturating_add(old.auth_drops);
                                        cleanup_session_routes(
                                            worker_id,
                                            old_tok,
                                            &mut old,
                                            &poll,
                                            &mut token_by_peer,
                                            &mut token_by_ufrag,
                                            &mut local_mig_pending,
                                            &registry,
                                        );
                                        log(
                                            worker_id,
                                            &format!(
                                                "REKEY peer={} old_ufrag={} -> new_ufrag={}",
                                                peer_addr, old.username, uname
                                            ),
                                        );
                                    }
                                } else {
                                    token_by_peer.remove(&peer_addr);
                                    if let Some(old) = sessions_by_token.get_mut(&old_tok) {
                                        if old.old_peer_addr.map(|(p, _)| p) == Some(peer_addr) {
                                            old.old_peer_addr = None;
                                        }
                                    }
                                }
                            }

                            if sessions_by_token.len() >= cfg.max_sessions {
                                let expired: Vec<Token> = sessions_by_token
                                    .iter()
                                    .filter(|(_, s)| {
                                        matches!(s.state, ServerState::Closing(_, _))
                                            || now.duration_since(s.last_data_active) > idle_dur
                                    })
                                    .map(|(&t, _)| t)
                                    .collect();
                                for t in expired {
                                    if let Some(mut s) = sessions_by_token.remove(&t) {
                                        closed_tx_bytes = closed_tx_bytes.saturating_add(s.tx_bytes);
                                        closed_rx_bytes = closed_rx_bytes.saturating_add(s.rx_bytes);
                                        closed_tx_pkts = closed_tx_pkts.saturating_add(s.tx_pkts);
                                        closed_rx_pkts = closed_rx_pkts.saturating_add(s.rx_pkts);
                                        closed_auth_drops = closed_auth_drops.saturating_add(s.auth_drops);
                                        graceful_teardown_server(&mut s, &listen_sock, &mut dtls_buf, &mut audit_pkt);
                                        cleanup_session_routes(
                                            worker_id,
                                            t,
                                            &mut s,
                                            &poll,
                                            &mut token_by_peer,
                                            &mut token_by_ufrag,
                                            &mut local_mig_pending,
                                            &registry,
                                        );
                                    }
                                }
                                if sessions_by_token.len() >= cfg.max_sessions {
                                    log(
                                        worker_id,
                                        &format!("max_sessions={} reached, rejecting {}", cfg.max_sessions, peer_addr),
                                    );
                                    continue;
                                }
                            }

                            let (stun_key, s_c2s, s_s2c) =
                                derive_stun_material(&cfg.psk, &parsed.txid, &uname);
                            let tok = alloc_token(&mut next_token_id);
                            let tie_breaker = parsed.tie_breaker.unwrap_or([0u8; 8]);

                            let (state, dtls_opt, cipher_opt, chosen_opt, ready_at, skey_opt, mkey_opt) =
                                if cfg.dtls_required {
                                    let cert = cert_cache.get(now);
                                    let mut dtls = new_dtls_instance(
                                        cfg.dtls_min_version,
                                        dtls_pool.pick(),
                                        cert,
                                        now,
                                    );
                                    let _ = dtls.handle_timeout(now);
                                    (ServerState::DtlsHandshake, Some(dtls), None, None, None, None, None)
                                } else {
                                    let chosen = resolve_srtp_suite(cfg.cipher_pref, None, &cpu, true);
                                    let final_key = combine_session_key(&stun_key, None);
                                    let mk = derive_ice_migration_key(&final_key);
                                    let mut c = SrtpCloakCipher::new(&final_key, s_s2c, s_c2s, false, chosen);
                                    c.set_wan_mtu(cfg.wan_mtu);
                                    registry.register_session(&uname, worker_id, mk, tie_breaker);
                                    (
                                        ServerState::Ready,
                                        None,
                                        Some(c),
                                        Some(chosen),
                                        Some(now),
                                        Some(final_key),
                                        Some(mk),
                                    )
                                };

                            let resp = build_stun_success_response(&parsed.txid, peer_v4, &cfg.psk);
                            {
                                let mut cache = seen_txids.lock().unwrap();
                                cache.record(parsed.txid, peer_addr, now, &resp);
                            }

                            log(
                                worker_id,
                                &format!(
                                    "AUTH STUN OK new session peer={} ufrag={} ssrc_rx=0x{:08x} ssrc_tx=0x{:08x}",
                                    peer_addr, uname, s_c2s, s_s2c
                                ),
                            );

                            let sess = ServerSession {
                                peer_addr,
                                old_peer_addr: None,
                                username: uname.clone(),
                                tie_breaker,
                                backend: BackendPipe::Unbound,
                                backend_lport: 0,
                                handed_over_to: None,
                                state,
                                ready_at,
                                stun_key,
                                session_key: skey_opt,
                                mi_key_mig: mkey_opt,
                                path_epoch: 0,
                                pending_migrations: Vec::new(),
                                mig_challenge_win: now,
                                mig_challenge_cnt: 0,
                                ssrc_c2s: s_c2s,
                                ssrc_s2c: s_s2c,
                                dtls: dtls_opt,
                                dtls_resets: 0,
                                dtls_next_timeout: None,
                                dtls_suite_id: None,
                                dtls_km: None,
                                negotiated_cipher: chosen_opt,
                                cipher: cipher_opt,
                                early_srtp: VecDeque::new(),
                                last_data_active: now,
                                last_peer_rx: now,
                                last_active_burst: now,
                                next_srtcp_at: now + rand_duration_range_ms(300, 750),
                                rate_15s: RollingByteWindow::new(now, Duration::from_secs(15)),
                                rx_pkts: 0,
                                rx_pkts_at_last_rtcp: 0,
                                rx_bytes: 0,
                                tx_pkts: 0,
                                tx_pkts_at_last_rtcp: 0,
                                tx_bytes: 0,
                                keepalives: 0,
                                srtcp_tx: 0,
                                srtcp_rx: 0,
                                auth_drops: 0,
                            };
                            token_by_peer.insert(peer_addr, tok);
                            token_by_ufrag.insert(uname, tok);
                            sessions_by_token.insert(tok, sess);

                            audit_pkt(1, &resp);
                            let _ = listen_sock.send_to(&resp, peer_addr);
                        }
                        PacketKind::Dtls => {
                            if let Some(&tok) = token_by_peer.get(&peer_addr) {
                                let mut became_ready = false;
                                if let Some(sess) = sessions_by_token.get_mut(&tok) {
                                    // P0-1: Ignore DTLS from draining old_peer_addr so reused NAT ports cannot kill `sess.dtls`!
                                    if sess.peer_addr != peer_addr
                                        || matches!(sess.state, ServerState::Closing(_, _))
                                    {
                                        continue;
                                    }
                                    let ready_only_alert = sess.state == ServerState::Ready
                                        && (sess.rx_pkts > 0
                                            || sess
                                                .ready_at
                                                .map(|r| now.duration_since(r) > Duration::from_secs(5))
                                                .unwrap_or(false));
                                    if !validate_dtls_datagram(pkt, ready_only_alert) {
                                        sess.auth_drops += 1;
                                        continue;
                                    }
                                    let mut dtls_err = false;
                                    if let Some(ref mut dtls) = sess.dtls {
                                        if sess.dtls_next_timeout.map(|t| now >= t).unwrap_or(false) {
                                            let _ = dtls.handle_timeout(now);
                                        }
                                        if dtls.handle_packet(pkt).is_err() {
                                            dtls_err = true;
                                        }
                                    } else {
                                        sess.auth_drops += 1;
                                        continue;
                                    }
                                    if dtls_err {
                                        sess.auth_drops += 1;
                                        if sess.state == ServerState::Ready {
                                            sess.dtls = None;
                                            sess.dtls_next_timeout = None;
                                        } else if sess.state == ServerState::DtlsHandshake
                                            && sess.dtls_resets < MAX_DTLS_RESETS
                                            && sess.dtls_suite_id.is_none()
                                        {
                                            sess.dtls_resets += 1;
                                            sess.dtls_km = None;
                                            let cert = cert_cache.get(now);
                                            let mut fresh = new_dtls_instance(
                                                cfg.dtls_min_version,
                                                dtls_pool.pick(),
                                                cert,
                                                now,
                                            );
                                            let _ = fresh.handle_timeout(now);
                                            sess.dtls = Some(fresh);
                                            sess.dtls_next_timeout = None;
                                        }
                                        continue;
                                    }
                                    if sess.state == ServerState::DtlsHandshake {
                                        sess.last_peer_rx = now;
                                    }
                                    let (peer_closed, br) = drain_server_dtls(
                                        worker_id,
                                        sess,
                                        &listen_sock,
                                        &mut dtls_buf,
                                        &cfg,
                                        &cpu,
                                        &registry,
                                        now,
                                        &mut audit_pkt,
                                    );
                                    became_ready = br;
                                    if peer_closed {
                                        sess.state = ServerState::Closing(
                                            now + Duration::from_millis(CLOSING_DRAIN_MS),
                                            true,
                                        );
                                    }
                                }
                                if became_ready {
                                    let early_pkts: Vec<Vec<u8>> = sessions_by_token
                                        .get_mut(&tok)
                                        .map(|s| s.early_srtp.drain(..).collect())
                                        .unwrap_or_default();
                                    for raw in early_pkts {
                                        process_ready_srtp(
                                            worker_id,
                                            tok,
                                            peer_addr,
                                            &raw,
                                            &mut sessions_by_token,
                                            &mut token_by_peer,
                                            &mut token_by_ufrag,
                                            &mut local_mig_pending,
                                            &poll,
                                            &listen_sock,
                                            &cfg,
                                            &registry,
                                            telemetry.as_ref(),
                                            &mut wbuf,
                                            now,
                                            &mut audit_pkt,
                                        );
                                    }
                                }
                            } else {
                                unauth_drops += 1;
                            }
                        }
                        PacketKind::Srtcp => {
                            if let Some(&tok) = token_by_peer.get(&peer_addr) {
                                if let Some(sess) = sessions_by_token.get_mut(&tok) {
                                    if sess.state == ServerState::Ready {
                                        if let Some(ref mut cipher) = sess.cipher {
                                            if let Some(has_bye) = cipher.verify_srtcp(pkt) {
                                                sess.srtcp_rx += 1;
                                                sess.last_peer_rx = now;
                                                if has_bye {
                                                    sess.state = ServerState::Closing(
                                                        now + Duration::from_millis(CLOSING_DRAIN_MS),
                                                        true,
                                                    );
                                                }
                                            } else {
                                                sess.auth_drops += 1;
                                            }
                                        }
                                    } else if !matches!(sess.state, ServerState::Closing(_, _)) {
                                        sess.auth_drops += 1;
                                    }
                                }
                            } else {
                                unauth_drops += 1;
                            }
                        }
                        PacketKind::Srtp => {
                            // 1) Fast path: verified active or draining `token_by_peer`
                            if let Some(&tok) = token_by_peer.get(&peer_addr) {
                                let state = sessions_by_token.get(&tok).map(|s| s.state);
                                match state {
                                    Some(ServerState::Ready) => {
                                        process_ready_srtp(
                                            worker_id,
                                            tok,
                                            peer_addr,
                                            pkt,
                                            &mut sessions_by_token,
                                            &mut token_by_peer,
                                            &mut token_by_ufrag,
                                            &mut local_mig_pending,
                                            &poll,
                                            &listen_sock,
                                            &cfg,
                                            &registry,
                                            telemetry.as_ref(),
                                            &mut wbuf,
                                            now,
                                            &mut audit_pkt,
                                        );
                                    }
                                    Some(ServerState::DtlsHandshake) => {
                                        if let Some(sess) = sessions_by_token.get_mut(&tok) {
                                            if sess.early_srtp.len() < EARLY_SRTP_CAP
                                                && pkt.len() >= 38
                                                && pkt.len() <= max_early_srtp_len
                                            {
                                                sess.early_srtp.push_back(pkt.to_vec());
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            } else if let Some((tok, exp)) =
                                local_mig_pending.get(&peer_addr).copied()
                            {
                                // 2) P0-1: Unverified same-worker 1-RTT migration candidate (SRTP-only fallback!)
                                if now <= exp {
                                    process_ready_srtp(
                                        worker_id,
                                        tok,
                                        peer_addr,
                                        pkt,
                                        &mut sessions_by_token,
                                        &mut token_by_peer,
                                        &mut token_by_ufrag,
                                        &mut local_mig_pending,
                                        &poll,
                                        &listen_sock,
                                        &cfg,
                                        &registry,
                                        telemetry.as_ref(),
                                        &mut wbuf,
                                        now,
                                        &mut audit_pkt,
                                    );
                                } else {
                                    local_mig_pending.remove(&peer_addr);
                                    unauth_drops += 1;
                                }
                            } else if let Some((ufrag, owner_wid, exp)) =
                                cross_worker_pending.get(&peer_addr).cloned()
                            {
                                // 3) Unverified cross-worker 1-RTT migration candidate
                                if now <= exp {
                                    registry.send_cmd(
                                        owner_wid,
                                        WorkerCmd::CrossWorkerChallengeVerify {
                                            ufrag,
                                            cand_addr: peer_addr,
                                            cand_worker: worker_id,
                                            pkt: pkt.to_vec(),
                                        },
                                    );
                                } else {
                                    cross_worker_pending.remove(&peer_addr);
                                    unauth_drops += 1;
                                }
                            } else {
                                unauth_drops += 1;
                            }
                        }
                        PacketKind::Unknown => {
                            unauth_drops += 1;
                        }
                    }
                }
            } else if let Some(sess) = sessions_by_token.get_mut(&ev.token()) {
                loop {
                    let n = match sess.backend {
                        BackendPipe::Owned(ref sock) => match sock.recv(&mut rbuf) {
                            Ok(n) => n,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        },
                        _ => break,
                    };
                    let can_tx_downlink = matches!(
                        sess.state,
                        ServerState::Ready | ServerState::Closing(_, true)
                    );
                    if !can_tx_downlink || n > MAX_INNER_UDP_LEN {
                        continue;
                    }
                    let mut sent_bytes = 0u64;
                    if let Some(ref mut cipher) = sess.cipher {
                        if sess.state == ServerState::Ready {
                            sess.last_data_active = now;
                        }
                        if let Some(wn) = cipher.wrap_into(&rbuf[..n], &mut wbuf) {
                            audit_pkt(1, &wbuf[..wn]);
                            if listen_sock.send_to(&wbuf[..wn], sess.peer_addr).is_ok() {
                                sess.tx_pkts += 1;
                                sess.tx_bytes += n as u64;
                                sent_bytes = n as u64;
                            }
                        }
                    }
                    if sent_bytes > 0 && sess.state == ServerState::Ready {
                        record_server_media_bytes(sess, now, sent_bytes);
                    }
                }
            }
        }

        if let Some(ref th) = telemetry {
            if now.duration_since(last_telemetry) >= telemetry_dur {
                last_telemetry = now;
                let mut snap = WorkerSnapshot {
                    tx_bytes_total: closed_tx_bytes,
                    rx_bytes_total: closed_rx_bytes,
                    tx_pkts_total: closed_tx_pkts,
                    rx_pkts_total: closed_rx_pkts,
                    auth_drops_total: closed_auth_drops,
                    unauth_drops_total: unauth_drops,
                    dtls_version: "none",
                    cipher: "none",
                    ..Default::default()
                };
                for sess in sessions_by_token.values() {
                    snap.tx_bytes_total = snap.tx_bytes_total.saturating_add(sess.tx_bytes);
                    snap.rx_bytes_total = snap.rx_bytes_total.saturating_add(sess.rx_bytes);
                    snap.tx_pkts_total = snap.tx_pkts_total.saturating_add(sess.tx_pkts);
                    snap.rx_pkts_total = snap.rx_pkts_total.saturating_add(sess.rx_pkts);
                    snap.auth_drops_total = snap.auth_drops_total.saturating_add(sess.auth_drops);
                    match sess.state {
                        ServerState::Ready => {
                            snap.active_sessions += 1;
                            if snap.active_backend_sport == 0 && sess.backend_lport != 0 {
                                snap.active_backend_sport = sess.backend_lport;
                            }
                            if snap.cipher == "none" {
                                if let Some(c) = sess.negotiated_cipher {
                                    snap.cipher = c.name();
                                }
                            }
                            if snap.dtls_version == "none" {
                                snap.dtls_version = match sess
                                    .dtls
                                    .as_ref()
                                    .and_then(|d| d.protocol_version())
                                {
                                    Some(ProtocolVersion::DTLS1_3) => {
                                        snap.dual_ssrc = true;
                                        "1.3"
                                    }
                                    Some(ProtocolVersion::DTLS1_2) => "1.2",
                                    _ if cfg.dtls_required => "1.3",
                                    _ => "none",
                                };
                            }
                        }
                        ServerState::DtlsHandshake => {
                            snap.handshaking_sessions += 1;
                        }
                        ServerState::Closing(_, _) => {}
                    }
                }
                th.update_worker(worker_id, snap);
            }
        }

        if now.duration_since(last_stats) >= stats_dur {
            last_stats = now;
            for sess in sessions_by_token.values() {
                if matches!(sess.state, ServerState::Closing(_, _)) {
                    continue;
                }
                log(
                    worker_id,
                    &format!(
                        "stats peer={} backend_sport={} rx={}pkts/{:.1}KB tx={}pkts/{:.1}KB ka={} rtcp={}/{} drops={} unauth={}",
                        sess.peer_addr,
                        sess.backend_lport,
                        sess.rx_pkts,
                        sess.rx_bytes as f64 / 1024.0,
                        sess.tx_pkts,
                        sess.tx_bytes as f64 / 1024.0,
                        sess.keepalives,
                        sess.srtcp_tx,
                        sess.srtcp_rx,
                        sess.auth_drops,
                        unauth_drops
                    ),
                );
            }
        }
    }
}
