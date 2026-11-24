//! mio-based zero-allocation webrtc-cloak V4.0 client (Hardened):
//!   - RFC 8445 / 7675 STUN ICE (4:4 Base64 ufrag, session-constant tie-breaker & priority,
//!     5s±20% Consent Freshness keepalive with conservative 10–14s trickle backoff,
//!     V4.0 1-RTT ICE path migration using per-session HKDF `ice-pwd-v4` + `0xFFFD` challenge/echo)
//!   - Real RFC 9147 DTLS 1.3 + RFC 6347 DTLS 1.2 via `dimpl 0.9.0` (multi-MTU ClientHello pool,
//!     mutual rotating P-256 certs, encrypted DTLS 1.3 certs, optional `--dtls-min-version 1.3`,
//!     Fail-Closed Hybrid PFS, Flight 5 Ready-state retransmit driver, fail-fast handshake reset)
//!   - V4.0 Scheduled MBB rotation: unlinkable fresh DTLS 1.3 + encrypted `0xFFFC` atomic server
//!     `backend_sock` handover (0 backend port change, 2–10s delayed old-session BYE)
//!   - RFC 3550/7714/8285 Dual-SSRC SRTP (PT=111 <=50pps Opus + PT=96 strict M=1 video, 0xBEDE TWCC)
//!   - RFC 3550 §6.1 / 7714 §9.1 Compound SRTCP + Make-Before-Break Closing drain (zero ICMP bounce)

use crate::protocol::{
    build_dimpl_config_pool, build_ice_stun_request, build_ice_stun_request_with_key,
    combine_session_key, compute_handover_proof, demux_rfc7983, derive_ice_migration_key,
    derive_stun_material, detect_cpu_accel, extract_dtls_server_hello_suite, jitter_duration_ms,
    lognormal_duration_ms, make_fresh_stun_txid, new_dtls_instance, parse_stun_with_key,
    rand_byte_budget, rand_duration_range_ms, register_shutdown_waker, resolve_srtp_suite,
    stun_hmac_key, validate_dtls_datagram, CertCache, CipherPref, CipherSuite, DtlsConfigPool,
    DtlsMinVersion, PacketKind, RollingByteWindow, SessionIceParams, SrtpCloakCipher, SrtpFrame,
    MAX_INNER_UDP_LEN, SRTP_HANDOVER_MAGIC, SRTP_PATH_CHALLENGE_MAGIC, STUN_BINDING_SUCCESS,
};
use dimpl::{Dtls, Output as DtlsOutput, ProtocolVersion};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

thread_local! {
    static CLIENT_QUIET: Cell<bool> = const { Cell::new(false) };
}

const LISTEN_TOKEN: Token = Token(0);
const WAKE_TOKEN: Token = Token(usize::MAX);
const CLOSING_DRAIN_MS: u64 = 250;
/// Receive-only drain after sending client-initiated SRTCP BYE (strictly > server 250ms Closing
/// flush + trans-Pacific RTT so trailing downlink SRTP never triggers ICMP Port Unreachable).
const POST_BYE_CLOSING_DRAIN_MS: u64 = 1000;
/// Silent receive-only drain window after RFC 7675 consent loss (exceeds server's 45s consent
/// expiry so trailing downlink SRTCP never triggers ICMP Port Unreachable and CGNAT never reuses
/// the blackholed external port for the newly rotated 5-tuple).
const BLACKHOLE_DRAIN_SECS: u64 = 50;
const MAX_DRAINING_SESSIONS: usize = 16;
const ACTIVE_ROTATE_WINDOW_SECS: u64 = 30;
/// Rolling 15s media byte threshold below which a session enters quiet control-plane backoff (~270 B/s).
const TRICKLE_RATE_15S_BYTES: u64 = 4 * 1024;
/// Rolling 5-minute media byte threshold below which scheduled MBB rotation suspends (~218 B/s).
const TRICKLE_MBB_5MIN_BYTES: u64 = 64 * 1024;
/// RFC 5389 §7.2.1 STUN consent retries (1 initial + 2 same-txid retransmits = 3 attempts, ~4.7s).
const KA_MAX_RETRIES: u8 = 2;
/// Elevated retry count after a recent rotation (<60s) to damp flapping on 20%+ random-loss links.
const KA_MAX_RETRIES_DAMPED: u8 = 4;
const MAX_PENDING_BYTES: usize = 256 * 1024;
const MAX_DTLS_RESETS: u8 = 3;

#[derive(Clone)]
pub struct ClientConfig {
    pub listen_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub psk: Vec<u8>,
    pub cipher_pref: CipherPref,
    pub dtls_decoy: bool,
    pub dtls_min_version: DtlsMinVersion,
    /// Optional proactive Make-Before-Break 5-tuple rotation median interval in seconds (`0` = disabled).
    pub rotate_interval_secs: u64,
    /// Optional proactive Make-Before-Break base byte-volume budget (`0` = disabled; jittered `[0.50x, 1.85x]`).
    pub rotate_max_bytes: u64,
    /// Minimum Ready session age before byte-volume MBB rotation can trigger (prevents handshake storms).
    pub rotate_cooldown_secs: u64,
    pub workers: usize,
    pub max_sessions: usize,
    pub wan_mtu: usize,
    pub retry_ms: u64,
    pub max_retries: u32,
    pub keepalive_secs: u64,
    pub idle_timeout_secs: u64,
    pub stats_interval_secs: u64,
    pub quiet: bool,
    pub stop: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    StunWait,
    DtlsHandshake,
    /// V4: Standby MBB session completed DTLS 1.3 and sent encrypted `0xFFFC` Handover Request,
    /// waiting <=1 RTT for server Ack while the old primary remains 100% live (0ms stall!).
    HandoverWait,
    /// V4: Active session switched to a fresh local UDP socket after uplink blackhole and sent
    /// 1-RTT RFC 8445 ICE migration STUN (`mi_key_mig` + `USE-CANDIDATE`), awaiting `0xFFFD` challenge.
    Migrating,
    Ready,
    /// MBB post-promotion receive-only overlap: new 5-tuple already carries all new uplink while
    /// the old 5-tuple stays Ready on the server for a random 2–10s window so slow backend replies
    /// and ECMP-reordered packets arrive with zero loss and `<1ms` new-Ready->old-BYE correlation
    /// is broken. At the deadline, send encrypted BYE + close_notify and transition to `Closing`.
    DrainingBeforeBye(Instant),
    Closing(Instant),
}

struct OldPathDrain {
    sock: MioUdpSocket,
    owner_tok: Token,
    deadline: Instant,
}

struct PendingReconnect {
    at: Instant,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
}

struct ClientSession {
    client_addr: SocketAddr,
    upstream: MioUdpSocket,
    local_port: u16,
    ice: SessionIceParams,
    stun_txid: [u8; 12],
    cached_initial_stun: Vec<u8>,
    state: HandshakeState,
    created_at: Instant,
    ready_at: Option<Instant>,
    last_data_active: Instant,
    last_active_burst: Instant,
    next_retry_at: Instant,
    next_keepalive_at: Instant,
    next_srtcp_at: Instant,
    dtls_next_timeout: Option<Instant>,
    is_standby: bool,
    standby_for_primary: Option<Token>,
    standby_spawned: bool,
    rotate_at: Option<Instant>,
    hard_rotate_at: Option<Instant>,
    rotate_byte_budget: Option<u64>,
    rate_15s: RollingByteWindow,
    rate_5min: RollingByteWindow,
    retries: u32,
    /// In-flight RFC 7675 STUN consent check transaction (RFC 5389 §7.2.1 same-txid retransmission).
    ka_txid: Option<[u8; 12]>,
    ka_pkt: Vec<u8>,
    ka_retries: u8,
    ka_max_retries: u8,
    ka_rto_at: Option<Instant>,
    /// V4 1-RTT ICE path migration state & loss-resilient 0xFFFD response echo
    mig_txid: Option<[u8; 12]>,
    mig_retries: u8,
    mig_retry_at: Option<Instant>,
    mig_echo_payload: Option<Vec<u8>>,
    mig_echo_next_at: Option<Instant>,
    mig_echo_left: u8,
    /// V4 scheduled MBB encrypted 0xFFFC handover state
    handover_payload: Option<Vec<u8>>,
    handover_retries: u8,
    handover_retry_at: Option<Instant>,
    stun_key: Option<[u8; 32]>,
    session_key: Option<[u8; 32]>,
    mi_key_mig: Option<[u8; 32]>,
    ssrc_c2s: u32,
    ssrc_s2c: u32,
    dtls: Option<Dtls>,
    dtls_resets: u8,
    pending_sh_suite: Option<u16>,
    dtls_suite_id: Option<u16>,
    dtls_km: Option<Vec<u8>>,
    active_cipher: Option<CipherSuite>,
    cipher: Option<SrtpCloakCipher>,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    tx_pkts: u64,
    tx_pkts_at_last_rtcp: u64,
    tx_bytes: u64,
    rx_pkts: u64,
    rx_pkts_at_last_rtcp: u64,
    rx_bytes: u64,
    keepalives_ok: u64,
    srtcp_tx: u64,
    srtcp_rx: u64,
    auth_drops: u64,
}

fn schedule_mbb_timers(sess: &mut ClientSession, cfg: &ClientConfig, now: Instant) {
    if sess.is_standby {
        sess.rotate_at = None;
        sess.hard_rotate_at = None;
        sess.rotate_byte_budget = None;
        return;
    }
    if cfg.rotate_interval_secs > 0 {
        sess.rotate_at = Some(now + lognormal_duration_ms(cfg.rotate_interval_secs * 1000));
        sess.hard_rotate_at = if cfg.rotate_interval_secs >= 60 {
            let min_h = cfg.rotate_interval_secs.saturating_mul(4).max(5 * 3600);
            let max_h = (min_h.saturating_mul(8) / 5).max(min_h + 1800);
            Some(now + rand_duration_range_ms(min_h * 1000, max_h * 1000))
        } else {
            Some(now + Duration::from_secs(cfg.rotate_interval_secs.saturating_mul(6)))
        };
    } else {
        sess.rotate_at = None;
        sess.hard_rotate_at = None;
    }
    sess.rotate_byte_budget = if cfg.rotate_max_bytes > 0 {
        Some(rand_byte_budget(cfg.rotate_max_bytes))
    } else {
        None
    };
}

#[inline]
fn is_client_in_trickle(sess: &mut ClientSession, now: Instant) -> bool {
    let age_ge_15s = sess
        .ready_at
        .map_or(false, |r| now.duration_since(r) >= Duration::from_secs(15));
    age_ge_15s && sess.rate_15s.bytes_in_window(now) < TRICKLE_RATE_15S_BYTES
}

#[inline]
fn record_client_media_bytes(
    sess: &mut ClientSession,
    cfg: &ClientConfig,
    ka_base_ms: u64,
    now: Instant,
    bytes: u64,
) {
    sess.rate_15s.record(now, bytes);
    sess.rate_5min.record(now, bytes);
    if sess.rate_15s.bytes_in_window(now) >= TRICKLE_RATE_15S_BYTES {
        sess.last_active_burst = now;
        if cfg.keepalive_secs > 0 {
            let max_active_ka = Duration::from_millis(ka_base_ms + ka_base_ms / 5);
            if sess.next_keepalive_at > now + max_active_ka {
                sess.next_keepalive_at = now + jitter_duration_ms(ka_base_ms);
            }
        }
        if sess.next_srtcp_at > now + Duration::from_millis(1900) {
            sess.next_srtcp_at = now + rand_duration_range_ms(900, 1900);
        }
    }
}

fn cancel_standby_for_client(
    client_addr: SocketAddr,
    standby_by_client: &mut HashMap<SocketAddr, Token>,
    sessions_by_token: &mut HashMap<Token, ClientSession>,
    dtls_buf: &mut Vec<u8>,
    now: Instant,
) {
    if let Some(st_tok) = standby_by_client.remove(&client_addr) {
        let owner_prim = sessions_by_token
            .get(&st_tok)
            .and_then(|s| s.standby_for_primary);
        if let Some(st_sess) = sessions_by_token.get_mut(&st_tok) {
            if matches!(
                st_sess.state,
                HandshakeState::Ready
                    | HandshakeState::HandoverWait
                    | HandshakeState::DrainingBeforeBye(_)
            ) {
                graceful_teardown_client(st_sess, dtls_buf);
                st_sess.state =
                    HandshakeState::Closing(now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS));
            } else if !matches!(st_sess.state, HandshakeState::Closing(_)) {
                st_sess.state =
                    HandshakeState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
            }
        }
        // P1-2 fix: Always clear `standby_spawned` on the surviving primary so MBB never locks up!
        if let Some(pt) = owner_prim {
            if let Some(prim) = sessions_by_token.get_mut(&pt) {
                prim.standby_spawned = false;
            }
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
    if !CLIENT_QUIET.with(|q| q.get()) {
        println!("[client-rs#{}] {}", worker_id, msg);
    }
}

fn drain_client_dtls(
    worker_id: usize,
    sess: &mut ClientSession,
    dtls_buf: &mut Vec<u8>,
    wbuf: &mut [u8],
    cfg: &ClientConfig,
    cpu: &crate::protocol::CpuAccelInfo,
    now: Instant,
    candidate_sh_suite: Option<u16>,
) -> bool {
    if sess.dtls_suite_id.is_none() && sess.pending_sh_suite.is_none() {
        if let Some(cs) = candidate_sh_suite {
            sess.pending_sh_suite = Some(cs);
        }
    }
    let mut emitted_client_hello = false;
    let mut emitted_flight5_or_later = false;
    let mut connected_now = false;
    let mut peer_closed = false;

    if let Some(ref mut dtls) = sess.dtls {
        loop {
            match dtls.poll_output(dtls_buf) {
                DtlsOutput::Packet(p) => {
                    if p.len() >= 14 && p[0] == 22 && p[13] == 1 {
                        emitted_client_hello = true;
                    } else {
                        emitted_flight5_or_later = true;
                    }
                    let _ = sess.upstream.send(p);
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

    // V3-H-05 fix: clear any pre-HVR spoofed ServerHello when re-sending ClientHello,
    // and lock ServerHello cipher suite only once dimpl emits Flight 5+ or reaches Connected!
    if emitted_client_hello && !emitted_flight5_or_later && !connected_now {
        sess.pending_sh_suite = None;
    } else if sess.dtls_suite_id.is_none() && (emitted_flight5_or_later || connected_now) {
        if let Some(cs) = sess.pending_sh_suite.take() {
            sess.dtls_suite_id = Some(cs);
        }
    }

    if connected_now && sess.state == HandshakeState::DtlsHandshake {
        if let Some(stun_key) = sess.stun_key {
            let Some(km) = sess.dtls_km.as_deref().filter(|k| !k.is_empty()) else {
                log(
                    worker_id,
                    &format!(
                        "DTLS Connected without SRTP KeyingMaterial up_sport={} (Fail-Closed!)",
                        sess.local_port
                    ),
                );
                return true;
            };
            let is_dtls13 = sess
                .dtls
                .as_ref()
                .and_then(|d| d.protocol_version())
                == Some(ProtocolVersion::DTLS1_3);
            let chosen = resolve_srtp_suite(cfg.cipher_pref, sess.dtls_suite_id, cpu, false);
            let final_key = combine_session_key(&stun_key, Some(km));
            sess.session_key = Some(final_key);
            sess.mi_key_mig = Some(derive_ice_migration_key(&final_key));
            sess.active_cipher = Some(chosen);
            let mut c = SrtpCloakCipher::new(
                &final_key,
                sess.ssrc_c2s,
                sess.ssrc_s2c,
                true,
                chosen,
            );
            c.set_wan_mtu(cfg.wan_mtu);
            c.set_dual_ssrc(is_dtls13);
            sess.cipher = Some(c);
            sess.state = HandshakeState::Ready;
            sess.ready_at = Some(now);
            sess.last_data_active = now;
            sess.last_active_burst = now;
            sess.rate_15s = RollingByteWindow::new(now, Duration::from_secs(15));
            sess.rate_5min = RollingByteWindow::new(now, Duration::from_secs(300));
            sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
            sess.ka_txid = None;
            sess.ka_pkt.clear();
            sess.ka_retries = 0;
            sess.ka_rto_at = None;
            sess.next_keepalive_at = now + jitter_duration_ms(cfg.keepalive_secs * 1000);
            sess.next_srtcp_at = now + rand_duration_range_ms(250, 600);
            schedule_mbb_timers(sess, cfg, now);

            let mut flushed = 0usize;
            let mut flushed_bytes = 0u64;
            sess.pending_bytes = 0;
            if let Some(ref mut cipher) = sess.cipher {
                while let Some(raw) = sess.pending.pop_front() {
                    if let Some(wn) = cipher.wrap_into(&raw, wbuf) {
                        if sess.upstream.send(&wbuf[..wn]).is_ok() {
                            sess.tx_pkts += 1;
                            sess.tx_bytes += raw.len() as u64;
                            flushed_bytes = flushed_bytes.saturating_add(raw.len() as u64);
                            flushed += 1;
                        }
                    }
                }
            }
            if flushed_bytes > 0 {
                record_client_media_bytes(sess, cfg, cfg.keepalive_secs * 1000, now, flushed_bytes);
            }
            let total_ms = sess.created_at.elapsed().as_secs_f64() * 1000.0;
            log(
                worker_id,
                &format!(
                    "DTLS {} (dimpl mutual-cert PFS) OK -> READY up_sport={} cipher={} dual_ssrc={} total_hs={:.2}ms flushed={}",
                    if is_dtls13 { "1.3" } else { "1.2" },
                    sess.local_port,
                    chosen.name(),
                    is_dtls13,
                    total_ms,
                    flushed
                ),
            );
        }
    }

    peer_closed
}

fn graceful_teardown_client(sess: &mut ClientSession, dtls_buf: &mut Vec<u8>) {
    if matches!(
        sess.state,
        HandshakeState::Ready
            | HandshakeState::HandoverWait
            | HandshakeState::DrainingBeforeBye(_)
    ) {
        let has_rx = sess.rx_pkts > sess.rx_pkts_at_last_rtcp;
        let is_sender = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
        if let Some(ref mut cipher) = sess.cipher {
            let bye = cipher.build_srtcp(has_rx, is_sender, true);
            let _ = sess.upstream.send(&bye);
        }
        if let Some(ref mut dtls) = sess.dtls {
            if dtls.close().is_ok() {
                loop {
                    match dtls.poll_output(dtls_buf) {
                        DtlsOutput::Packet(p) => {
                            let _ = sess.upstream.send(p);
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

pub fn run_client(cfg: ClientConfig) -> std::io::Result<()> {
    let workers = cfg.workers.max(1);
    let cpu = detect_cpu_accel();
    let dtls_pool = build_dimpl_config_pool(cfg.cipher_pref, &cpu, true, cfg.wan_mtu);
    if !cfg.quiet {
        println!(
            "[client-rs] V4.0 CPU arch={} hw_accel=[{}] recommended={} workers={} dtls=dimpl-{}(mutual-cert,pfs)",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            workers,
            cfg.dtls_min_version.as_str()
        );
    }
    #[cfg(not(target_os = "linux"))]
    if workers > 1 {
        eprintln!("[client-rs] WARN: SO_REUSEPORT UDP hash load-balancing is Linux-specific.");
    }

    if workers == 1 {
        return run_client_worker(0, cfg, false, dtls_pool);
    }

    let mut handles = Vec::with_capacity(workers - 1);
    for wid in 1..workers {
        let c = cfg.clone();
        let dp = dtls_pool.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = run_client_worker(wid, c, true, dp) {
                eprintln!("[client-rs#{}] error: {}", wid, e);
            }
        }));
    }
    let res = run_client_worker(0, cfg, true, dtls_pool);
    for h in handles {
        let _ = h.join();
    }
    res
}

#[allow(clippy::too_many_arguments)]
fn spawn_client_session(
    worker_id: usize,
    client_addr: SocketAddr,
    cfg: &ClientConfig,
    poll: &mut Poll,
    sessions_by_token: &mut HashMap<Token, ClientSession>,
    token_by_client: &mut HashMap<SocketAddr, Token>,
    standby_by_client: &mut HashMap<SocketAddr, Token>,
    next_token_id: &mut usize,
    dtls_buf: &mut Vec<u8>,
    now: Instant,
    retry_dur: Duration,
    ka_base_ms: u64,
    idle_dur: Duration,
    ka_max_retries: u8,
    standby_for_primary: Option<Token>,
) -> Option<Token> {
    let is_standby = standby_for_primary.is_some();
    // Bound silent receive-only draining sockets so prolonged blackholes cannot leak FDs.
    let mut draining: Vec<(Token, Instant)> = sessions_by_token
        .iter()
        .filter_map(|(&t, s)| match s.state {
            HandshakeState::Closing(deadline) => Some((t, deadline)),
            _ => None,
        })
        .collect();
    if draining.len() >= MAX_DRAINING_SESSIONS {
        draining.sort_by_key(|&(_, d)| d);
        let to_evict = draining.len() - MAX_DRAINING_SESSIONS + 1;
        for (t, _) in draining.into_iter().take(to_evict) {
            if let Some(mut old) = sessions_by_token.remove(&t) {
                let _ = poll.registry().deregister(&mut old.upstream);
                if token_by_client.get(&old.client_addr) == Some(&t) {
                    token_by_client.remove(&old.client_addr);
                }
                if standby_by_client.get(&old.client_addr) == Some(&t) {
                    standby_by_client.remove(&old.client_addr);
                    if let Some(pt) = old.standby_for_primary {
                        if let Some(prim) = sessions_by_token.get_mut(&pt) {
                            prim.standby_spawned = false;
                        }
                    }
                }
            }
        }
    }

    if sessions_by_token.len() >= cfg.max_sessions {
        let expired: Vec<Token> = sessions_by_token
            .iter()
            .filter(|(_, s)| {
                matches!(
                    s.state,
                    HandshakeState::Closing(_) | HandshakeState::DrainingBeforeBye(_)
                ) || now.duration_since(s.last_data_active) > idle_dur
            })
            .map(|(&t, _)| t)
            .collect();
        for t in expired {
            if let Some(mut s) = sessions_by_token.remove(&t) {
                graceful_teardown_client(&mut s, dtls_buf);
                let _ = poll.registry().deregister(&mut s.upstream);
                if token_by_client.get(&s.client_addr) == Some(&t) {
                    token_by_client.remove(&s.client_addr);
                }
                if standby_by_client.get(&s.client_addr) == Some(&t) {
                    standby_by_client.remove(&s.client_addr);
                    if let Some(pt) = s.standby_for_primary {
                        if let Some(prim) = sessions_by_token.get_mut(&pt) {
                            prim.standby_spawned = false;
                        }
                    }
                }
            }
        }
        if sessions_by_token.len() >= cfg.max_sessions {
            log(
                worker_id,
                &format!(
                    "max_sessions={} reached, dropping new client {}",
                    cfg.max_sessions, client_addr
                ),
            );
            return None;
        }
    }

    let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let mut up = match make_udp_socket(bind_any, Some(cfg.server_addr), false, 2 * 1024 * 1024) {
        Ok(s) => s,
        Err(e) => {
            log(worker_id, &format!("upstream socket error: {}", e));
            return None;
        }
    };
    let local_port = up.local_addr().map(|a| a.port()).unwrap_or(0);
    let tok = Token(*next_token_id);
    *next_token_id = next_token_id.wrapping_add(1);
    if *next_token_id == 0 || *next_token_id == usize::MAX {
        *next_token_id = 1;
    }
    if poll.registry().register(&mut up, tok, Interest::READABLE).is_err() {
        return None;
    }
    let ice = SessionIceParams::generate();
    let stun_txid = make_fresh_stun_txid(&cfg.psk);
    let (stun_pkt, _) = build_ice_stun_request(&cfg.psk, &ice, Some(stun_txid), true);
    let _ = up.send(&stun_pkt);

    log(
        worker_id,
        &format!(
            "new {}session client={} -> up_sport={} target={} ufrag={}",
            if is_standby { "standby(MBB) " } else { "" },
            client_addr,
            local_port,
            cfg.server_addr,
            ice.username()
        ),
    );

    let sess = ClientSession {
        client_addr,
        upstream: up,
        local_port,
        ice,
        stun_txid,
        cached_initial_stun: stun_pkt,
        state: HandshakeState::StunWait,
        created_at: now,
        ready_at: None,
        last_data_active: now,
        last_active_burst: now,
        next_retry_at: now + retry_dur,
        next_keepalive_at: now + jitter_duration_ms(ka_base_ms),
        next_srtcp_at: now + rand_duration_range_ms(250, 600),
        dtls_next_timeout: None,
        is_standby,
        standby_for_primary,
        standby_spawned: false,
        rotate_at: None,
        hard_rotate_at: None,
        rotate_byte_budget: None,
        rate_15s: RollingByteWindow::new(now, Duration::from_secs(15)),
        rate_5min: RollingByteWindow::new(now, Duration::from_secs(300)),
        retries: 0,
        ka_txid: None,
        ka_pkt: Vec::new(),
        ka_retries: 0,
        ka_max_retries,
        ka_rto_at: None,
        mig_txid: None,
        mig_retries: 0,
        mig_retry_at: None,
        mig_echo_payload: None,
        mig_echo_next_at: None,
        mig_echo_left: 0,
        handover_payload: None,
        handover_retries: 0,
        handover_retry_at: None,
        stun_key: None,
        session_key: None,
        mi_key_mig: None,
        ssrc_c2s: 0,
        ssrc_s2c: 0,
        dtls: None,
        dtls_resets: 0,
        pending_sh_suite: None,
        dtls_suite_id: None,
        dtls_km: None,
        active_cipher: None,
        cipher: None,
        pending: VecDeque::with_capacity(64),
        pending_bytes: 0,
        tx_pkts: 0,
        tx_pkts_at_last_rtcp: 0,
        tx_bytes: 0,
        rx_pkts: 0,
        rx_pkts_at_last_rtcp: 0,
        rx_bytes: 0,
        keepalives_ok: 0,
        srtcp_tx: 0,
        srtcp_rx: 0,
        auth_drops: 0,
    };
    if is_standby {
        standby_by_client.insert(client_addr, tok);
    } else {
        token_by_client.insert(client_addr, tok);
    }
    sessions_by_token.insert(tok, sess);
    Some(tok)
}

fn run_client_worker(
    worker_id: usize,
    cfg: ClientConfig,
    reuse_port: bool,
    dtls_pool: DtlsConfigPool,
) -> std::io::Result<()> {
    CLIENT_QUIET.with(|q| q.set(cfg.quiet));
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(256);
    if !cfg.quiet && cfg.stop.is_some() {
        if let Ok(waker) = Waker::new(poll.registry(), WAKE_TOKEN) {
            register_shutdown_waker(Arc::new(waker));
        }
    }

    let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port, 8 * 1024 * 1024)?;
    poll.registry()
        .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;

    let mut sessions_by_token: HashMap<Token, ClientSession> = HashMap::new();
    let mut token_by_client: HashMap<SocketAddr, Token> = HashMap::new();
    let mut standby_by_client: HashMap<SocketAddr, Token> = HashMap::new();
    let mut old_path_drains: HashMap<Token, OldPathDrain> = HashMap::new();
    let mut pending_reconnects: HashMap<SocketAddr, PendingReconnect> = HashMap::new();
    let mut last_rotation_by_client: HashMap<SocketAddr, Instant> = HashMap::new();
    let mut next_token_id: usize = 1;
    let mut cert_cache = CertCache::new();
    let stun_mi_key = stun_hmac_key(&cfg.psk);
    let max_inner_pending = if cfg.wan_mtu > 0 {
        cfg.wan_mtu.saturating_sub(28 + 38).min(MAX_INNER_UDP_LEN)
    } else {
        MAX_INNER_UDP_LEN
    };

    let mut rbuf = vec![0u8; 65536];
    let mut wbuf = vec![0u8; 65536 + 128];
    let mut dtls_buf = vec![0u8; 4096];

    let cpu = detect_cpu_accel();
    log(
        worker_id,
        &format!(
            "listening on {} -> {} (reuse_port={}, cipher_pref={:?}, dtls={}, keepalive={}s±20%, max_sessions={})",
            cfg.listen_addr, cfg.server_addr, reuse_port, cfg.cipher_pref, cfg.dtls_decoy, cfg.keepalive_secs, cfg.max_sessions
        ),
    );

    let retry_dur = Duration::from_millis(cfg.retry_ms);
    let ka_base_ms = cfg.keepalive_secs * 1000;
    let idle_dur = Duration::from_secs(cfg.idle_timeout_secs);
    let stats_dur = Duration::from_secs(cfg.stats_interval_secs);
    let mut last_stats = Instant::now();

    loop {
        if let Some(ref s) = cfg.stop {
            if s.load(Ordering::Relaxed) {
                let mut torn = 0usize;
                for sess in sessions_by_token.values_mut() {
                    if matches!(
                        sess.state,
                        HandshakeState::Ready
                            | HandshakeState::HandoverWait
                            | HandshakeState::DrainingBeforeBye(_)
                    ) {
                        graceful_teardown_client(sess, &mut dtls_buf);
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
        let mut wait = if sessions_by_token.is_empty() && pending_reconnects.is_empty() {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(1)
        };
        let mut to_close: Vec<(Token, &'static str)> = Vec::new();
        let mut to_rotate: Vec<(Token, SocketAddr, bool)> = Vec::new();
        let mut to_migrate: Vec<Token> = Vec::new();
        let mut to_spawn_standby: Vec<(Token, SocketAddr)> = Vec::new();
        let mut standby_promoted_timers: Vec<(Token, SocketAddr)> = Vec::new();

        // Expire old migrated receive-only drain sockets
        if !old_path_drains.is_empty() {
            let expired_drains: Vec<Token> = old_path_drains
                .iter()
                .filter(|(_, d)| now >= d.deadline)
                .map(|(&t, _)| t)
                .collect();
            for dt in expired_drains {
                if let Some(mut d) = old_path_drains.remove(&dt) {
                    let _ = poll.registry().deregister(&mut d.sock);
                }
            }
        }

        // Fire jittered post-server-BYE reconnects once their 80..350ms backoff expires
        let mut due_reconnects: Vec<SocketAddr> = Vec::new();
        for (&caddr, pr) in pending_reconnects.iter() {
            if now >= pr.at {
                due_reconnects.push(caddr);
            } else {
                let rem = pr.at.saturating_duration_since(now);
                if rem < wait {
                    wait = rem.max(Duration::from_millis(5));
                }
            }
        }
        for caddr in due_reconnects {
            if let Some(pr) = pending_reconnects.remove(&caddr) {
                if !token_by_client.contains_key(&caddr) {
                    if let Some(new_tok) = spawn_client_session(
                        worker_id,
                        caddr,
                        &cfg,
                        &mut poll,
                        &mut sessions_by_token,
                        &mut token_by_client,
                        &mut standby_by_client,
                        &mut next_token_id,
                        &mut dtls_buf,
                        now,
                        retry_dur,
                        ka_base_ms,
                        idle_dur,
                        KA_MAX_RETRIES,
                        None,
                    ) {
                        if let Some(new_sess) = sessions_by_token.get_mut(&new_tok) {
                            new_sess.pending = pr.pending;
                            new_sess.pending_bytes = pr.pending_bytes;
                        }
                    }
                }
            }
        }

        for (&tok, sess) in sessions_by_token.iter_mut() {
            match sess.state {
                HandshakeState::StunWait => {
                    if now >= sess.next_retry_at {
                        if sess.retries >= cfg.max_retries {
                            to_close.push((tok, "stun_handshake_timeout"));
                            continue;
                        }
                        sess.retries += 1;
                        sess.next_retry_at = now + retry_dur;
                        let _ = sess.upstream.send(&sess.cached_initial_stun);
                    } else {
                        let rem = sess.next_retry_at.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(5));
                        }
                    }
                }
                HandshakeState::DtlsHandshake => {
                    if let Some(t) = sess.dtls_next_timeout {
                        if now >= t {
                            let err = if let Some(ref mut dtls) = sess.dtls {
                                dtls.handle_timeout(now).is_err()
                            } else {
                                true
                            };
                            if err {
                                to_close.push((tok, "dtls_handshake_timeout"));
                                continue;
                            }
                            if drain_client_dtls(
                                worker_id,
                                sess,
                                &mut dtls_buf,
                                &mut wbuf,
                                &cfg,
                                &cpu,
                                now,
                                None,
                            ) {
                                sess.state = HandshakeState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
                            }
                        } else {
                            let rem = t.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(5));
                            }
                        }
                    }
                }
                HandshakeState::HandoverWait => {
                    // Drive DTLS 1.3 Flight 5 retransmit timer if still armed while awaiting 0xFFFC Ack
                    if let Some(t) = sess.dtls_next_timeout {
                        let rem = t.saturating_duration_since(now);
                        if rem > Duration::from_secs(60) {
                            sess.dtls_next_timeout = None;
                        } else if now >= t {
                            let err = if let Some(ref mut dtls) = sess.dtls {
                                dtls.handle_timeout(now).is_err()
                            } else {
                                true
                            };
                            if err {
                                // P1-5 fix: clear expired DTLS timer on Err
                                sess.dtls_next_timeout = None;
                            } else if drain_client_dtls(
                                worker_id,
                                sess,
                                &mut dtls_buf,
                                &mut wbuf,
                                &cfg,
                                &cpu,
                                now,
                                None,
                            ) {
                                sess.state = HandshakeState::Closing(
                                    now + Duration::from_millis(CLOSING_DRAIN_MS),
                                );
                                continue;
                            }
                        } else if rem < wait {
                            wait = rem.max(Duration::from_millis(5));
                        }
                    }
                    if let Some(rt) = sess.handover_retry_at {
                        if now >= rt {
                            // P0-5 fix: 4 retries x ~380ms (~1.5s) covers >=2 full DTLS 1.3 Flight 5 RTOs
                            // on 180ms trans-Pacific WAN while old primary keeps running with 0ms stall!
                            if sess.handover_retries < 4 {
                                sess.handover_retries += 1;
                                if let (Some(ref payload), Some(ref mut cipher)) =
                                    (&sess.handover_payload, &mut sess.cipher)
                                {
                                    if let Some(wn) = cipher.wrap_control_into(
                                        SRTP_HANDOVER_MAGIC,
                                        payload,
                                        &mut wbuf,
                                    ) {
                                        if sess.upstream.send(&wbuf[..wn]).is_ok() {
                                            sess.tx_pkts += 1;
                                        }
                                    }
                                }
                                sess.handover_retry_at =
                                    Some(now + retry_dur.max(Duration::from_millis(380)));
                            } else {
                                // P0-5 fix: Only fall back to legacy v0.3.8 promotion if peer proved live
                                // (authenticated SRTCP/SRTP or DTLS 1.3 Flight 5 ACK received); otherwise
                                // abort the unconfirmed standby and keep the healthy primary untouched!
                                let server_confirmed_alive = sess.rx_pkts > 0
                                    || sess.srtcp_rx > 0
                                    || sess.dtls_next_timeout.is_none();
                                sess.handover_payload = None;
                                sess.handover_retry_at = None;
                                if server_confirmed_alive {
                                    sess.state = HandshakeState::Ready;
                                    standby_promoted_timers.push((tok, sess.client_addr));
                                } else {
                                    log(
                                        worker_id,
                                        &format!(
                                            "MBB standby handover unconfirmed (0 server rx) up_sport={} -> aborting standby",
                                            sess.local_port
                                        ),
                                    );
                                    graceful_teardown_client(sess, &mut dtls_buf);
                                    sess.state = HandshakeState::Closing(
                                        now + Duration::from_millis(CLOSING_DRAIN_MS),
                                    );
                                }
                            }
                        } else {
                            let rem = rt.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(5));
                            }
                        }
                    }
                }
                HandshakeState::Migrating => {
                    if let Some(rt) = sess.mig_retry_at {
                        if now >= rt {
                            if sess.mig_retries < 2 {
                                sess.mig_retries += 1;
                                if let Some(mk) = sess.mi_key_mig {
                                    // Fresh txid on each retry prevents an on-path spoofed-IP racer from stalling us!
                                    let (pkt, txid) = build_ice_stun_request_with_key(
                                        &cfg.psk,
                                        &mk,
                                        &sess.ice,
                                        None,
                                        true,
                                    );
                                    let _ = sess.upstream.send(&pkt);
                                    sess.mig_txid = Some(txid);
                                }
                                sess.mig_retry_at = Some(now + retry_dur);
                            } else {
                                // Server lost session state or is legacy v0.3.8 -> fall back to fresh STUN+DTLS!
                                log(
                                    worker_id,
                                    &format!(
                                        "ICE 1-RTT migration unanswered up_sport={} -> falling back to fresh STUN+DTLS",
                                        sess.local_port
                                    ),
                                );
                                sess.mig_txid = None;
                                sess.mig_retry_at = None;
                                sess.state = HandshakeState::Closing(
                                    now + Duration::from_millis(CLOSING_DRAIN_MS),
                                );
                                to_rotate.push((tok, sess.client_addr, true));
                                continue;
                            }
                        } else {
                            let rem = rt.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(5));
                            }
                        }
                    }
                }
                HandshakeState::Ready => {
                    // V4: Re-send encrypted 0xFFFD path challenge response if lossy link dropped first copy
                    if sess.mig_echo_left > 0 {
                        if let Some(next_at) = sess.mig_echo_next_at {
                            if now >= next_at {
                                if let (Some(ref payload), Some(ref mut cipher)) =
                                    (&sess.mig_echo_payload, &mut sess.cipher)
                                {
                                    if let Some(wn) = cipher.wrap_control_into(
                                        SRTP_PATH_CHALLENGE_MAGIC,
                                        payload,
                                        &mut wbuf,
                                    ) {
                                        if sess.upstream.send(&wbuf[..wn]).is_ok() {
                                            sess.tx_pkts += 1;
                                        }
                                    }
                                }
                                sess.mig_echo_left -= 1;
                                if sess.mig_echo_left == 0 {
                                    sess.mig_echo_payload = None;
                                    sess.mig_echo_next_at = None;
                                } else {
                                    sess.mig_echo_next_at =
                                        Some(now + Duration::from_millis(250));
                                }
                            } else {
                                let rem = next_at.saturating_duration_since(now);
                                if rem < wait {
                                    wait = rem.max(Duration::from_millis(10));
                                }
                            }
                        }
                    }
                    // H-01 fix: DTLS 1.3 Client emits Output::Connected upon sending Flight 5 (Cert+CV+Fin)
                    // while keeping its Flight 5 retransmission timer armed until server ACK arrives.
                    // Drive near-term (<60s) dtls_next_timeout in Ready state so a single lost Flight 5
                    // recovers within ~350ms instead of stalling 25s!
                    if let Some(t) = sess.dtls_next_timeout {
                        let rem = t.saturating_duration_since(now);
                        if rem > Duration::from_secs(60) {
                            // dimpl entered 10-year IDLE_INTERVAL after receiving server ACK
                            sess.dtls_next_timeout = None;
                        } else if now >= t {
                            let err = if let Some(ref mut dtls) = sess.dtls {
                                dtls.handle_timeout(now).is_err()
                            } else {
                                true
                            };
                            if err {
                                if sess.rx_pkts > 0 || sess.srtcp_rx > 0 {
                                    // Server is already Ready (only server's DTLS 1.3 ACK packet was lost)
                                    sess.dtls_next_timeout = None;
                                } else {
                                    log(
                                        worker_id,
                                        &format!(
                                            "DTLS 1.3 Flight 5 unacknowledged (0 rx) up_sport={} -> rotating",
                                            sess.local_port
                                        ),
                                    );
                                    sess.dtls_next_timeout = None;
                                    sess.state = HandshakeState::Closing(
                                        now + Duration::from_millis(CLOSING_DRAIN_MS),
                                    );
                                    to_rotate.push((tok, sess.client_addr, true));
                                    continue;
                                }
                            } else if drain_client_dtls(
                                worker_id,
                                sess,
                                &mut dtls_buf,
                                &mut wbuf,
                                &cfg,
                                &cpu,
                                now,
                                None,
                            ) {
                                sess.state = HandshakeState::Closing(
                                    now + Duration::from_millis(CLOSING_DRAIN_MS),
                                );
                                continue;
                            }
                        } else if rem < wait {
                            wait = rem.max(Duration::from_millis(5));
                        }
                    }

                    // Sequence/Nonce exhaustion or silent data-plane deadlock guard (e.g. --keepalive 0)
                    let seq_exhausted = sess
                        .cipher
                        .as_ref()
                        .map(|c| c.is_seq_exhausted())
                        .unwrap_or(false);
                    let dl_deadlock = sess.tx_pkts >= 3
                        && sess.rx_pkts == 0
                        && sess.srtcp_rx == 0
                        && sess
                            .ready_at
                            .map(|r| now.duration_since(r) > Duration::from_secs(15))
                            .unwrap_or(false);
                    if seq_exhausted || dl_deadlock {
                        log(
                            worker_id,
                            &format!(
                                "{} up_sport={} -> rotating to fresh session",
                                if seq_exhausted { "SRTP/SRTCP seq ceiling reached" } else { "Zero authenticated downlink SRTP/SRTCP after 15s" },
                                sess.local_port
                            ),
                        );
                        graceful_teardown_client(sess, &mut dtls_buf);
                        sess.state =
                            HandshakeState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
                        to_rotate.push((tok, sess.client_addr, true));
                        continue;
                    }

                    // Proactive Make-Before-Break scheduled 5-tuple rotation:
                    //   1) Random single-session byte-volume budget (e.g. 600MB..2.2GB) with cooldown lock
                    //   2) Log-normal wide-distribution duration, suspended during background trickle (<64KB/5m)
                    //      until real traffic resumes or hard fallback cap (5-8h) is reached.
                    if !sess.is_standby && !sess.standby_spawned {
                        let byte_trigger = sess.rotate_byte_budget.map_or(false, |budget| {
                            sess.tx_bytes.saturating_add(sess.rx_bytes) >= budget
                                && sess.ready_at.map_or(false, |r| {
                                    now.duration_since(r)
                                        >= Duration::from_secs(cfg.rotate_cooldown_secs)
                                })
                        });
                        if byte_trigger {
                            to_spawn_standby.push((tok, sess.client_addr));
                        } else if let Some(rot_at) = sess.rotate_at {
                            if now >= rot_at {
                                let obs_secs = sess
                                    .ready_at
                                    .map_or(1, |r| now.duration_since(r).as_secs().max(1))
                                    .min(300);
                                let threshold_bytes = (TRICKLE_MBB_5MIN_BYTES * obs_secs) / 300;
                                let recent_bytes = sess.rate_5min.bytes_in_window(now);
                                let active_traffic = now.duration_since(sess.last_data_active)
                                    <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS)
                                    && recent_bytes >= threshold_bytes;
                                let hard_cap_hit = sess.hard_rotate_at.map_or(false, |h| now >= h)
                                    && now.duration_since(sess.last_data_active) <= idle_dur;
                                if active_traffic || hard_cap_hit {
                                    to_spawn_standby.push((tok, sess.client_addr));
                                } else {
                                    // Background trickle keepalives only -> suspend MBB churn and re-check later!
                                    let recheck = if cfg.rotate_interval_secs >= 60 {
                                        rand_duration_range_ms(60_000, 180_000)
                                    } else {
                                        Duration::from_secs(cfg.rotate_interval_secs.max(1))
                                    };
                                    sess.rotate_at = Some(now + recheck);
                                }
                            } else {
                                let rem = rot_at.saturating_duration_since(now);
                                if rem < wait {
                                    wait = rem.max(Duration::from_millis(20));
                                }
                            }
                        }
                    }

                    if now.duration_since(sess.last_data_active) > idle_dur {
                        graceful_teardown_client(sess, &mut dtls_buf);
                        sess.state = HandshakeState::Closing(
                            now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS),
                        );
                        continue;
                    }
                    // RFC 7675 §5.1 + RFC 5389 §7.2.1 bidirectional STUN consent check:
                    // ONLY an authenticated STUN Binding Success Response proves uplink connectivity
                    // (unsolicited server SRTCP or QUIC PTO SRTP MUST NOT mask an asymmetric uplink blackhole!).
                    if cfg.keepalive_secs > 0 {
                        if sess.ka_txid.is_some() {
                            if let Some(rto_at) = sess.ka_rto_at {
                                if now >= rto_at {
                                    if sess.ka_retries < sess.ka_max_retries {
                                        sess.ka_retries += 1;
                                        // Retransmit the EXACT same STUN transaction (same txid) with
                                        // jittered exponential RTO backoff matching RFC 5389 / libwebrtc.
                                        let _ = sess.upstream.send(&sess.ka_pkt);
                                        let next_rto = if sess.ka_retries == 1 {
                                            rand_duration_range_ms(1400, 1800)
                                        } else {
                                            rand_duration_range_ms(1800, 2200)
                                        };
                                        sess.ka_rto_at = Some(now + next_rto);
                                    } else {
                                        let active_recently = now.duration_since(sess.last_data_active)
                                            <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS);
                                        if active_recently
                                            && !sess.is_standby
                                            && sess.mi_key_mig.is_some()
                                            && sess.cipher.is_some()
                                        {
                                            // V4: Attempt 1-RTT RFC 8445 ICE path migration on fresh 5-tuple
                                            // (preserves DTLS PFS key, SRTP seq, and server backend_lport!)
                                            log(
                                                worker_id,
                                                &format!(
                                                    "RFC 7675 consent lost ({}/{} STUN unanswered) client={} up_sport={} -> 1-RTT ICE path migration (draining old {}s)",
                                                    sess.ka_max_retries + 1,
                                                    sess.ka_max_retries + 1,
                                                    sess.client_addr,
                                                    sess.local_port,
                                                    BLACKHOLE_DRAIN_SECS,
                                                ),
                                            );
                                            sess.ka_txid = None;
                                            sess.ka_pkt.clear();
                                            sess.ka_retries = 0;
                                            sess.ka_rto_at = None;
                                            to_migrate.push(tok);
                                            continue;
                                        }
                                        log(
                                            worker_id,
                                            &format!(
                                                "RFC 7675 consent lost ({}/{} STUN unanswered) client={} up_sport={} -> draining {}s{}",
                                                sess.ka_max_retries + 1,
                                                sess.ka_max_retries + 1,
                                                sess.client_addr,
                                                sess.local_port,
                                                BLACKHOLE_DRAIN_SECS,
                                                if active_recently {
                                                    " + rotating to fresh 5-tuple"
                                                } else {
                                                    " (idle)"
                                                }
                                            ),
                                        );
                                        graceful_teardown_client(sess, &mut dtls_buf);
                                        sess.ka_txid = None;
                                        sess.ka_pkt.clear();
                                        sess.ka_retries = 0;
                                        sess.ka_rto_at = None;
                                        sess.state = HandshakeState::Closing(
                                            now + Duration::from_secs(BLACKHOLE_DRAIN_SECS),
                                        );
                                        to_rotate.push((tok, sess.client_addr, active_recently));
                                        continue;
                                    }
                                } else {
                                    let rem = rto_at.saturating_duration_since(now);
                                    if rem < wait {
                                        wait = rem.max(Duration::from_millis(10));
                                    }
                                }
                            }
                        } else if now >= sess.next_keepalive_at {
                            let (pkt, txid) = build_ice_stun_request(&cfg.psk, &sess.ice, None, false);
                            let _ = sess.upstream.send(&pkt);
                            sess.ka_txid = Some(txid);
                            sess.ka_pkt = pkt;
                            sess.ka_retries = 0;
                            sess.ka_rto_at = Some(now + rand_duration_range_ms(950, 1250));
                        } else {
                            let rem = sess.next_keepalive_at.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(10));
                            }
                        }
                    }
                    if now >= sess.next_srtcp_at {
                        let in_trickle = is_client_in_trickle(sess, now);
                        let is_active_media = !in_trickle
                            && now.duration_since(sess.last_data_active) <= Duration::from_secs(3);
                        let sent_media = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
                        let has_rx = sess.rx_pkts > sess.rx_pkts_at_last_rtcp;
                        sess.tx_pkts_at_last_rtcp = sess.tx_pkts;
                        sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
                        if let Some(ref mut cipher) = sess.cipher {
                            let pkt = cipher.build_srtcp(has_rx, sent_media, false);
                            if sess.upstream.send(&pkt).is_ok() {
                                sess.srtcp_tx += 1;
                            }
                        }
                        sess.next_srtcp_at = now
                            + if is_active_media {
                                rand_duration_range_ms(900, 1900)
                            } else if !in_trickle {
                                rand_duration_range_ms(3500, 6500)
                            } else {
                                rand_duration_range_ms(20_000, 40_000)
                            };
                    } else {
                        let rem = sess.next_srtcp_at.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(10));
                        }
                    }
                }
                HandshakeState::DrainingBeforeBye(bye_at) => {
                    if now >= bye_at {
                        graceful_teardown_client(sess, &mut dtls_buf);
                        sess.state = HandshakeState::Closing(
                            now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS),
                        );
                    } else {
                        let rem = bye_at.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(10));
                        }
                    }
                }
                HandshakeState::Closing(deadline) => {
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

        // Execute V4 1-RTT ICE path migrations (blackhole recovery without DTLS re-handshake or backend port change)
        for tok in to_migrate {
            let client_addr_opt = sessions_by_token.get(&tok).map(|s| s.client_addr);
            let Some(client_addr) = client_addr_opt else {
                continue;
            };
            cancel_standby_for_client(
                client_addr,
                &mut standby_by_client,
                &mut sessions_by_token,
                &mut dtls_buf,
                now,
            );
            let recently_rotated = last_rotation_by_client
                .get(&client_addr)
                .map(|&t| now.duration_since(t) < Duration::from_secs(60))
                .unwrap_or(false);
            last_rotation_by_client.insert(client_addr, now);
            let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let new_up = match make_udp_socket(bind_any, Some(cfg.server_addr), false, 2 * 1024 * 1024) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let new_port = new_up.local_addr().map(|a| a.port()).unwrap_or(0);
            if let Some(sess) = sessions_by_token.get_mut(&tok) {
                let mut old_up = std::mem::replace(&mut sess.upstream, new_up);
                let _ = poll.registry().deregister(&mut old_up);
                if poll.registry().register(&mut sess.upstream, tok, Interest::READABLE).is_err() {
                    // Restore old socket on unexpected registration failure
                    sess.upstream = old_up;
                    let _ = poll.registry().register(&mut sess.upstream, tok, Interest::READABLE);
                    continue;
                }
                // Move old blackholed socket into bounded silent receive-only drain pool (50s, zero ICMP bounce!)
                if old_path_drains.len() >= MAX_DRAINING_SESSIONS {
                    if let Some((&oldest_t, _)) = old_path_drains.iter().min_by_key(|(_, d)| d.deadline) {
                        if let Some(mut evicted) = old_path_drains.remove(&oldest_t) {
                            let _ = poll.registry().deregister(&mut evicted.sock);
                        }
                    }
                }
                let drain_tok = Token(next_token_id);
                next_token_id = next_token_id.wrapping_add(1);
                if next_token_id == 0 || next_token_id == usize::MAX {
                    next_token_id = 1;
                }
                if poll.registry().register(&mut old_up, drain_tok, Interest::READABLE).is_ok() {
                    old_path_drains.insert(
                        drain_tok,
                        OldPathDrain {
                            sock: old_up,
                            owner_tok: tok,
                            deadline: now + Duration::from_secs(BLACKHOLE_DRAIN_SECS),
                        },
                    );
                }

                let old_port = sess.local_port;
                sess.local_port = new_port;
                sess.ka_max_retries = if recently_rotated {
                    KA_MAX_RETRIES_DAMPED
                } else {
                    KA_MAX_RETRIES
                };
                if let Some(mk) = sess.mi_key_mig {
                    let (pkt, txid) =
                        build_ice_stun_request_with_key(&cfg.psk, &mk, &sess.ice, None, true);
                    let _ = sess.upstream.send(&pkt);
                    sess.state = HandshakeState::Migrating;
                    sess.mig_txid = Some(txid);
                    sess.mig_retries = 0;
                    sess.mig_retry_at = Some(now + retry_dur);
                    log(
                        worker_id,
                        &format!(
                            "ICE 1-RTT migration started client={} old_sport={} -> new_sport={} ufrag={}",
                            client_addr, old_port, new_port, sess.ice.username()
                        ),
                    );
                }
            }
        }

        for (prim_tok, client_addr) in to_spawn_standby {
            if !standby_by_client.contains_key(&client_addr) {
                // P1-2 fix: Only set `standby_spawned = true` when spawn actually succeeds!
                if spawn_client_session(
                    worker_id,
                    client_addr,
                    &cfg,
                    &mut poll,
                    &mut sessions_by_token,
                    &mut token_by_client,
                    &mut standby_by_client,
                    &mut next_token_id,
                    &mut dtls_buf,
                    now,
                    retry_dur,
                    ka_base_ms,
                    idle_dur,
                    KA_MAX_RETRIES,
                    Some(prim_tok),
                )
                .is_some()
                {
                    if let Some(prim) = sessions_by_token.get_mut(&prim_tok) {
                        prim.standby_spawned = true;
                    }
                }
            }
        }

        for (old_tok, client_addr, active_recently) in to_rotate {
            if token_by_client.get(&client_addr) == Some(&old_tok) {
                token_by_client.remove(&client_addr);
            }
            pending_reconnects.remove(&client_addr);
            cancel_standby_for_client(
                client_addr,
                &mut standby_by_client,
                &mut sessions_by_token,
                &mut dtls_buf,
                now,
            );
            let recently_rotated = last_rotation_by_client
                .get(&client_addr)
                .map(|&t| now.duration_since(t) < Duration::from_secs(60))
                .unwrap_or(false);
            last_rotation_by_client.insert(client_addr, now);
            if last_rotation_by_client.len() > 1024 {
                last_rotation_by_client.retain(|_, &mut t| now.duration_since(t) < Duration::from_secs(60));
            }
            let next_ka_retries = if recently_rotated {
                KA_MAX_RETRIES_DAMPED
            } else {
                KA_MAX_RETRIES
            };
            if active_recently {
                // P0-5 fix: Carry over any buffered app packets (`old_sess.pending`) into the replacement session!
                let (carried_pending, carried_bytes) = sessions_by_token
                    .get_mut(&old_tok)
                    .map(|s| {
                        let p = std::mem::take(&mut s.pending);
                        let b = s.pending_bytes;
                        s.pending_bytes = 0;
                        (p, b)
                    })
                    .unwrap_or_else(|| (VecDeque::new(), 0));
                if let Some(new_tok) = spawn_client_session(
                    worker_id,
                    client_addr,
                    &cfg,
                    &mut poll,
                    &mut sessions_by_token,
                    &mut token_by_client,
                    &mut standby_by_client,
                    &mut next_token_id,
                    &mut dtls_buf,
                    now,
                    retry_dur,
                    ka_base_ms,
                    idle_dur,
                    next_ka_retries,
                    None,
                ) {
                    if !carried_pending.is_empty() {
                        if let Some(ns) = sessions_by_token.get_mut(&new_tok) {
                            ns.pending = carried_pending;
                            ns.pending_bytes = carried_bytes;
                        }
                    }
                }
            }
        }

        for (tok, reason) in to_close {
            if let Some(mut sess) = sessions_by_token.remove(&tok) {
                let _ = poll.registry().deregister(&mut sess.upstream);
                // P2-1: Shrink any remaining old_path_drains owned by a normally closed session to free 2MB socket FDs promptly
                let drain_cap = now + Duration::from_millis(CLOSING_DRAIN_MS);
                for d in old_path_drains.values_mut() {
                    if d.owner_tok == tok && d.deadline > drain_cap {
                        d.deadline = drain_cap;
                    }
                }
                if token_by_client.get(&sess.client_addr) == Some(&tok) {
                    token_by_client.remove(&sess.client_addr);
                    // Primary closed -> cancel any orphan standby belonging to it!
                    cancel_standby_for_client(
                        sess.client_addr,
                        &mut standby_by_client,
                        &mut sessions_by_token,
                        &mut dtls_buf,
                        now,
                    );
                }
                if standby_by_client.get(&sess.client_addr) == Some(&tok) {
                    standby_by_client.remove(&sess.client_addr);
                    // Standby MBB handshake failed -> postpone retry ONLY on its exact owning primary!
                    if let Some(owner_tok) = sess.standby_for_primary {
                        if token_by_client.get(&sess.client_addr) == Some(&owner_tok) {
                            if let Some(prim) = sessions_by_token.get_mut(&owner_tok) {
                                prim.standby_spawned = false;
                                if cfg.rotate_interval_secs > 0 {
                                    prim.rotate_at =
                                        Some(now + rand_duration_range_ms(45_000, 90_000));
                                }
                            }
                        }
                    }
                }
                log(
                    worker_id,
                    &format!(
                        "close session client={} up_sport={} reason={} tx={}pkts/{}B rx={}pkts/{}B ka={} rtcp={}/{} drops={}",
                        sess.client_addr, sess.local_port, reason, sess.tx_pkts, sess.tx_bytes,
                        sess.rx_pkts, sess.rx_bytes, sess.keepalives_ok, sess.srtcp_tx, sess.srtcp_rx, sess.auth_drops
                    ),
                );
            }
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
        let mut standby_ready: Vec<(Token, SocketAddr)> = Vec::new();
        let mut standby_promoted: Vec<(Token, SocketAddr)> = standby_promoted_timers;
        let mut graceful_reconnects: Vec<(Token, SocketAddr)> = Vec::new();
        for ev in events.iter() {
            if ev.token() == WAKE_TOKEN {
                continue;
            }
            if ev.token() == LISTEN_TOKEN {
                loop {
                    let (n, client_addr) = match listen_sock.recv_from(&mut rbuf) {
                        Ok(v) => v,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    };
                    if n > MAX_INNER_UDP_LEN {
                        continue;
                    }

                    // If this client is inside the 80..350ms post-server-BYE reconnect jitter window,
                    // buffer arriving app packets so we never bypass the backoff and trigger ICMP bounce!
                    if let Some(pr) = pending_reconnects.get_mut(&client_addr) {
                        if n <= max_inner_pending
                            && pr.pending.len() < 256
                            && pr.pending_bytes.saturating_add(n) <= MAX_PENDING_BYTES
                        {
                            pr.pending.push_back(rbuf[..n].to_vec());
                            pr.pending_bytes += n;
                        }
                        continue;
                    }

                    // If existing session is in Closing/DrainingBeforeBye, detach it from token_by_client while
                    // letting its socket finish silent receive-only drain (zero ICMP Port Unreachable).
                    if let Some(&existing_tok) = token_by_client.get(&client_addr) {
                        if matches!(
                            sessions_by_token.get(&existing_tok).map(|s| s.state),
                            Some(HandshakeState::Closing(_) | HandshakeState::DrainingBeforeBye(_))
                        ) {
                            token_by_client.remove(&client_addr);
                        }
                    }

                    let tok = if let Some(&existing) = token_by_client.get(&client_addr) {
                        existing
                    } else {
                        let recently_rotated = last_rotation_by_client
                            .get(&client_addr)
                            .map(|&t| now.duration_since(t) < Duration::from_secs(60))
                            .unwrap_or(false);
                        let ka_retries = if recently_rotated {
                            KA_MAX_RETRIES_DAMPED
                        } else {
                            KA_MAX_RETRIES
                        };
                        match spawn_client_session(
                            worker_id,
                            client_addr,
                            &cfg,
                            &mut poll,
                            &mut sessions_by_token,
                            &mut token_by_client,
                            &mut standby_by_client,
                            &mut next_token_id,
                            &mut dtls_buf,
                            now,
                            retry_dur,
                            ka_base_ms,
                            idle_dur,
                            ka_retries,
                            None,
                        ) {
                            Some(t) => t,
                            None => continue,
                        }
                    };

                    if let Some(sess) = sessions_by_token.get_mut(&tok) {
                        sess.last_data_active = now;
                        if sess.state != HandshakeState::Ready {
                            if n <= max_inner_pending
                                && sess.pending.len() < 256
                                && sess.pending_bytes.saturating_add(n) <= MAX_PENDING_BYTES
                            {
                                sess.pending.push_back(rbuf[..n].to_vec());
                                sess.pending_bytes += n;
                            }
                        } else {
                            let mut sent_ok = false;
                            if let Some(ref mut cipher) = sess.cipher {
                                if let Some(wn) = cipher.wrap_into(&rbuf[..n], &mut wbuf) {
                                    if sess.upstream.send(&wbuf[..wn]).is_ok() {
                                        sess.tx_pkts += 1;
                                        sess.tx_bytes += n as u64;
                                        sent_ok = true;
                                    }
                                }
                            }
                            if sent_ok {
                                record_client_media_bytes(sess, &cfg, ka_base_ms, now, n as u64);
                            }
                        }
                    }
                }
            } else if let Some(drain) = old_path_drains.get_mut(&ev.token()) {
                // V4 silent receive-only drain for old socket after 1-RTT ICE migration:
                // still delivers trailing authenticated downlink SRTP with zero WAN TX (zero ICMP bounce!).
                let owner_tok = drain.owner_tok;
                loop {
                    let n = match drain.sock.recv(&mut rbuf) {
                        Ok(n) => n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    };
                    let pkt = &rbuf[..n];
                    match demux_rfc7983(pkt) {
                        PacketKind::Srtp => {
                            if let Some(owner) = sessions_by_token.get_mut(&owner_tok) {
                                if let Some(ref mut cipher) = owner.cipher {
                                    if let Some(pn) = cipher.unwrap_into(pkt, &mut wbuf) {
                                        if listen_sock.send_to(&wbuf[..pn], owner.client_addr).is_ok() {
                                            owner.rx_pkts += 1;
                                            owner.rx_bytes += pn as u64;
                                        }
                                    }
                                }
                            }
                        }
                        // P1-5 fix: Detect server SIGTERM graceful BYE arriving on old draining socket during migration!
                        PacketKind::Srtcp => {
                            if let Some(owner) = sessions_by_token.get_mut(&owner_tok) {
                                if matches!(
                                    owner.state,
                                    HandshakeState::Migrating | HandshakeState::Ready
                                ) {
                                    if let Some(ref mut cipher) = owner.cipher {
                                        if let Some(true) = cipher.verify_srtcp(pkt) {
                                            owner.srtcp_rx += 1;
                                            let active_recently = now
                                                .duration_since(owner.last_data_active)
                                                <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS);
                                            owner.state = HandshakeState::Closing(
                                                now + Duration::from_millis(CLOSING_DRAIN_MS),
                                            );
                                            if !owner.is_standby && active_recently {
                                                graceful_reconnects
                                                    .push((owner_tok, owner.client_addr));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            } else if let Some(sess) = sessions_by_token.get_mut(&ev.token()) {
                loop {
                    let n = match sess.upstream.recv(&mut rbuf) {
                        Ok(n) => n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    };
                    let pkt = &rbuf[..n];
                    if matches!(
                        sess.state,
                        HandshakeState::Closing(_) | HandshakeState::DrainingBeforeBye(_)
                    ) {
                        // Make-Before-Break silent receive-only drain: deliver authenticated in-flight
                        // downlink SRTP to local app while transmitting ZERO WAN packets until delayed BYE.
                        match demux_rfc7983(pkt) {
                            PacketKind::Srtp => {
                                if let Some(ref mut cipher) = sess.cipher {
                                    if let Some(pn) = cipher.unwrap_into(pkt, &mut wbuf) {
                                        if listen_sock.send_to(&wbuf[..pn], sess.client_addr).is_ok() {
                                            sess.rx_pkts += 1;
                                            sess.rx_bytes += pn as u64;
                                        }
                                    }
                                }
                            }
                            PacketKind::Srtcp
                                if matches!(sess.state, HandshakeState::DrainingBeforeBye(_)) =>
                            {
                                if let Some(ref mut cipher) = sess.cipher {
                                    if let Some(has_bye) = cipher.verify_srtcp(pkt) {
                                        sess.srtcp_rx += 1;
                                        if has_bye {
                                            sess.state = HandshakeState::Closing(
                                                now + Duration::from_millis(CLOSING_DRAIN_MS),
                                            );
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }

                    match demux_rfc7983(pkt) {
                        PacketKind::Stun => {
                            if sess.state == HandshakeState::Migrating {
                                // V4 1-RTT ICE migration STUN Success signed with per-session mi_key_mig
                                if let Some(mk) = sess.mi_key_mig {
                                    if let Some(parsed) = parse_stun_with_key(pkt, &cfg.psk, &mk) {
                                        if parsed.authenticated
                                            && parsed.msg_type == STUN_BINDING_SUCCESS
                                            && sess.mig_txid == Some(parsed.txid)
                                        {
                                            // Valid STUN reply; paired 0xFFFD challenge arrives in same flight
                                            continue;
                                        }
                                    }
                                }
                                sess.auth_drops += 1;
                                continue;
                            }
                            if let Some(parsed) = parse_stun_with_key(pkt, &cfg.psk, &stun_mi_key) {
                                if parsed.authenticated && parsed.msg_type == STUN_BINDING_SUCCESS {
                                    if sess.state == HandshakeState::StunWait && parsed.txid == sess.stun_txid {
                                        let rtt_ms = sess.created_at.elapsed().as_secs_f64() * 1000.0;
                                        let uname = sess.ice.username();
                                        let (stun_key, s_c2s, s_s2c) =
                                            derive_stun_material(&cfg.psk, &sess.stun_txid, &uname);
                                        sess.stun_key = Some(stun_key);
                                        sess.ssrc_c2s = s_c2s;
                                        sess.ssrc_s2c = s_s2c;
                                        let mapped_s = parsed
                                            .xor_mapped
                                            .map(|a| a.to_string())
                                            .unwrap_or_else(|| "unknown".into());
                                        log(
                                            worker_id,
                                            &format!(
                                                "ICE STUN OK up_sport={} rtt={:.2}ms mapped={} ssrc_tx=0x{:08x} ssrc_rx=0x{:08x}",
                                                sess.local_port, rtt_ms, mapped_s, s_c2s, s_s2c
                                            ),
                                        );
                                        if cfg.dtls_decoy {
                                            let cert = cert_cache.get(now);
                                            let mut dtls = new_dtls_instance(
                                                cfg.dtls_min_version,
                                                dtls_pool.pick(),
                                                cert,
                                                now,
                                            );
                                            dtls.set_active(true);
                                            let _ = dtls.handle_timeout(now);
                                            sess.dtls = Some(dtls);
                                            sess.state = HandshakeState::DtlsHandshake;
                                            let _ = drain_client_dtls(
                                                worker_id,
                                                sess,
                                                &mut dtls_buf,
                                                &mut wbuf,
                                                &cfg,
                                                &cpu,
                                                now,
                                                None,
                                            );
                                        } else {
                                            let chosen = resolve_srtp_suite(cfg.cipher_pref, None, &cpu, true);
                                            let final_key = combine_session_key(&stun_key, None);
                                            sess.session_key = Some(final_key);
                                            sess.mi_key_mig = Some(derive_ice_migration_key(&final_key));
                                            sess.active_cipher = Some(chosen);
                                            let mut c = SrtpCloakCipher::new(
                                                &final_key, s_c2s, s_s2c, true, chosen,
                                            );
                                            c.set_wan_mtu(cfg.wan_mtu);
                                            sess.cipher = Some(c);
                                            sess.state = HandshakeState::Ready;
                                            sess.ready_at = Some(now);
                                            sess.last_data_active = now;
                                            sess.last_active_burst = now;
                                            sess.rate_15s = RollingByteWindow::new(now, Duration::from_secs(15));
                                            sess.rate_5min = RollingByteWindow::new(now, Duration::from_secs(300));
                                            sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
                                            sess.ka_txid = None;
                                            sess.ka_pkt.clear();
                                            sess.ka_retries = 0;
                                            sess.ka_rto_at = None;
                                            sess.next_keepalive_at = now + jitter_duration_ms(ka_base_ms);
                                            sess.next_srtcp_at = now + rand_duration_range_ms(250, 600);
                                            schedule_mbb_timers(sess, &cfg, now);
                                            if sess.is_standby {
                                                standby_ready.push((ev.token(), sess.client_addr));
                                            }
                                            let mut flushed = 0usize;
                                            let mut flushed_bytes = 0u64;
                                            sess.pending_bytes = 0;
                                            if let Some(ref mut cipher) = sess.cipher {
                                                while let Some(raw) = sess.pending.pop_front() {
                                                    if let Some(wn) = cipher.wrap_into(&raw, &mut wbuf) {
                                                        if sess.upstream.send(&wbuf[..wn]).is_ok() {
                                                            sess.tx_pkts += 1;
                                                            sess.tx_bytes += raw.len() as u64;
                                                            flushed_bytes = flushed_bytes.saturating_add(raw.len() as u64);
                                                            flushed += 1;
                                                        }
                                                    }
                                                }
                                            }
                                            if flushed_bytes > 0 {
                                                record_client_media_bytes(sess, &cfg, ka_base_ms, now, flushed_bytes);
                                            }
                                            log(
                                                worker_id,
                                                &format!(
                                                    "session READY (no-dtls) up_sport={} cipher={} flushed={}",
                                                    sess.local_port,
                                                    chosen.name(),
                                                    flushed
                                                ),
                                            );
                                        }
                                    } else if sess.state == HandshakeState::Ready
                                        && sess.ka_txid == Some(parsed.txid)
                                    {
                                        sess.keepalives_ok += 1;
                                        sess.ka_txid = None;
                                        sess.ka_pkt.clear();
                                        sess.ka_retries = 0;
                                        sess.ka_rto_at = None;
                                        let in_trickle = is_client_in_trickle(sess, now);
                                        sess.next_keepalive_at = now
                                            + if in_trickle
                                                && cfg.keepalive_secs >= 3
                                                && cfg.keepalive_secs < 10
                                            {
                                                // Conservative trickle STUN backoff (10-14s, safely below 20-30s CGNAT & 45s server consent)
                                                rand_duration_range_ms(10_000, 14_000)
                                            } else {
                                                jitter_duration_ms(ka_base_ms)
                                            };
                                    }
                                } else {
                                    sess.auth_drops += 1;
                                }
                            } else {
                                sess.auth_drops += 1;
                            }
                        }
                        PacketKind::Dtls => {
                            // V3.2: strict DTLS pre-validation + Ready gating + Fail-Fast reset in DtlsHandshake
                            let ready_only_alert = matches!(
                                sess.state,
                                HandshakeState::Ready | HandshakeState::HandoverWait | HandshakeState::Migrating
                            ) && sess
                                .ready_at
                                .map(|r| now.duration_since(r) > Duration::from_secs(5))
                                .unwrap_or(false);
                            if !validate_dtls_datagram(pkt, ready_only_alert) {
                                sess.auth_drops += 1;
                                continue;
                            }
                            let candidate_sh = if sess.state == HandshakeState::DtlsHandshake {
                                extract_dtls_server_hello_suite(pkt)
                            } else {
                                None
                            };
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
                                if matches!(
                                    sess.state,
                                    HandshakeState::Ready | HandshakeState::HandoverWait | HandshakeState::Migrating
                                ) {
                                    // Keep established SRTP tunnel alive; drop corrupted DTLS handle only
                                    sess.dtls = None;
                                    sess.dtls_next_timeout = None;
                                } else if sess.state == HandshakeState::DtlsHandshake {
                                    // P0-4: dimpl Err during handshake means transcript/state is fatally poisoned.
                                    // Fail-fast reset (up to MAX_DTLS_RESETS) instead of stalling 12s!
                                    if sess.dtls_resets < MAX_DTLS_RESETS {
                                        sess.dtls_resets += 1;
                                        sess.pending_sh_suite = None;
                                        sess.dtls_suite_id = None;
                                        sess.dtls_km = None;
                                        let cert = cert_cache.get(now);
                                        let mut fresh = new_dtls_instance(
                                            cfg.dtls_min_version,
                                            dtls_pool.pick(),
                                            cert,
                                            now,
                                        );
                                        fresh.set_active(true);
                                        let _ = fresh.handle_timeout(now);
                                        sess.dtls = Some(fresh);
                                        let _ = drain_client_dtls(
                                            worker_id,
                                            sess,
                                            &mut dtls_buf,
                                            &mut wbuf,
                                            &cfg,
                                            &cpu,
                                            now,
                                            None,
                                        );
                                    } else {
                                        sess.state = HandshakeState::Closing(
                                            now + Duration::from_millis(CLOSING_DRAIN_MS),
                                        );
                                    }
                                }
                                continue;
                            }
                            let was_ready = sess.state == HandshakeState::Ready;
                            if drain_client_dtls(
                                worker_id,
                                sess,
                                &mut dtls_buf,
                                &mut wbuf,
                                &cfg,
                                &cpu,
                                now,
                                candidate_sh,
                            ) {
                                let active_recently = now.duration_since(sess.last_data_active)
                                    <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS);
                                sess.state = HandshakeState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
                                if was_ready && !sess.is_standby && active_recently {
                                    graceful_reconnects.push((ev.token(), sess.client_addr));
                                }
                            } else if !was_ready
                                && sess.state == HandshakeState::Ready
                                && sess.is_standby
                            {
                                standby_ready.push((ev.token(), sess.client_addr));
                            }
                        }
                        PacketKind::Srtcp => {
                            // P1-5 fix: Also accept authenticated SRTCP (esp. server SIGTERM BYE) during HandoverWait/Migrating!
                            if matches!(
                                sess.state,
                                HandshakeState::Ready
                                    | HandshakeState::HandoverWait
                                    | HandshakeState::Migrating
                            ) {
                                if let Some(ref mut cipher) = sess.cipher {
                                    if let Some(has_bye) = cipher.verify_srtcp(pkt) {
                                        sess.srtcp_rx += 1;
                                        if has_bye {
                                            let active_recently = now
                                                .duration_since(sess.last_data_active)
                                                <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS);
                                            sess.state = HandshakeState::Closing(
                                                now + Duration::from_millis(CLOSING_DRAIN_MS),
                                            );
                                            if !sess.is_standby && active_recently {
                                                graceful_reconnects.push((ev.token(), sess.client_addr));
                                            }
                                        }
                                    } else {
                                        sess.auth_drops += 1;
                                    }
                                }
                            } else {
                                sess.auth_drops += 1;
                            }
                        }
                        PacketKind::Srtp => {
                            if matches!(
                                sess.state,
                                HandshakeState::Ready
                                    | HandshakeState::HandoverWait
                                    | HandshakeState::Migrating
                            ) {
                                let mut rx_ok_bytes = 0u64;
                                let frame = sess
                                    .cipher
                                    .as_mut()
                                    .and_then(|c| c.unwrap_into_ex(pkt, &mut wbuf));
                                match frame {
                                    Some(SrtpFrame::Data(pn)) => {
                                        sess.last_data_active = now;
                                        if sess.state == HandshakeState::Ready && sess.mig_echo_left > 0 {
                                            sess.mig_echo_left = 0;
                                            sess.mig_echo_payload = None;
                                            sess.mig_echo_next_at = None;
                                        }
                                        if listen_sock.send_to(&wbuf[..pn], sess.client_addr).is_ok() {
                                            sess.rx_pkts += 1;
                                            sess.rx_bytes += pn as u64;
                                            rx_ok_bytes = pn as u64;
                                        }
                                    }
                                    Some(SrtpFrame::PathChallenge(pn)) => {
                                        sess.rx_pkts += 1;
                                        if pn == 17 && wbuf[0] == 0x01 {
                                            // P0-2 fix: Accept 0xFFFD(0x01) both in `Migrating` AND while
                                            // in `Ready` with unconfirmed `mig_echo_left > 0` (epoch >= current)!
                                            let cur_epoch = sess
                                                .mig_echo_payload
                                                .as_deref()
                                                .filter(|p| p.len() == 17)
                                                .map(|p| {
                                                    u64::from_be_bytes(p[9..17].try_into().unwrap())
                                                })
                                                .unwrap_or(0);
                                            let got_epoch =
                                                u64::from_be_bytes(wbuf[9..17].try_into().unwrap());
                                            let accept_challenge = sess.state
                                                == HandshakeState::Migrating
                                                || (sess.state == HandshakeState::Ready
                                                    && sess.mig_echo_left > 0
                                                    && got_epoch >= cur_epoch);
                                            if accept_challenge {
                                                let mut resp_payload = [0u8; 17];
                                                resp_payload[0] = 0x02;
                                                resp_payload[1..17].copy_from_slice(&wbuf[1..17]);
                                                let was_migrating =
                                                    sess.state == HandshakeState::Migrating;
                                                let mut flushed = 0usize;
                                                let mut flushed_bytes = 0u64;
                                                if was_migrating {
                                                    sess.pending_bytes = 0;
                                                }
                                                if let Some(ref mut cipher) = sess.cipher {
                                                    let mut cbuf = [0u8; 256];
                                                    if let Some(wn) = cipher.wrap_control_into(
                                                        SRTP_PATH_CHALLENGE_MAGIC,
                                                        &resp_payload,
                                                        &mut cbuf,
                                                    ) {
                                                        if sess.upstream.send(&cbuf[..wn]).is_ok() {
                                                            sess.tx_pkts += 1;
                                                        }
                                                    }
                                                    if was_migrating {
                                                        while let Some(raw) =
                                                            sess.pending.pop_front()
                                                        {
                                                            if let Some(wn) =
                                                                cipher.wrap_into(&raw, &mut wbuf)
                                                            {
                                                                if sess
                                                                    .upstream
                                                                    .send(&wbuf[..wn])
                                                                    .is_ok()
                                                                {
                                                                    sess.tx_pkts += 1;
                                                                    sess.tx_bytes +=
                                                                        raw.len() as u64;
                                                                    flushed_bytes = flushed_bytes
                                                                        .saturating_add(
                                                                            raw.len() as u64,
                                                                        );
                                                                    flushed += 1;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                sess.state = HandshakeState::Ready;
                                                sess.mig_txid = None;
                                                sess.mig_retry_at = None;
                                                sess.mig_echo_payload = Some(resp_payload.to_vec());
                                                sess.mig_echo_next_at =
                                                    Some(now + Duration::from_millis(250));
                                                sess.mig_echo_left = 3;
                                                if was_migrating {
                                                    sess.next_keepalive_at =
                                                        now + jitter_duration_ms(ka_base_ms);
                                                    if flushed_bytes > 0 {
                                                        record_client_media_bytes(
                                                            sess,
                                                            &cfg,
                                                            ka_base_ms,
                                                            now,
                                                            flushed_bytes,
                                                        );
                                                    }
                                                    log(
                                                        worker_id,
                                                        &format!(
                                                            "ICE 1-RTT MIGRATION OK -> READY up_sport={} flushed={}",
                                                            sess.local_port, flushed
                                                        ),
                                                    );
                                                }
                                            }
                                        } else if pn >= 9 && wbuf[0] == 0x03 {
                                            // P2-1: Verify confirm nonce matches active in-flight echo
                                            let nonce_ok = sess
                                                .mig_echo_payload
                                                .as_deref()
                                                .filter(|p| p.len() >= 9)
                                                .map(|p| &p[1..9] == &wbuf[1..9])
                                                .unwrap_or(true);
                                            if nonce_ok {
                                                sess.mig_echo_left = 0;
                                                sess.mig_echo_payload = None;
                                                sess.mig_echo_next_at = None;
                                            }
                                        }
                                    }
                                    Some(SrtpFrame::Handover(pn)) => {
                                        sess.rx_pkts += 1;
                                        if sess.state == HandshakeState::HandoverWait
                                            && pn >= 2
                                            && wbuf[0] == 0x02
                                        {
                                            sess.handover_payload = None;
                                            sess.handover_retry_at = None;
                                            sess.state = HandshakeState::Ready;
                                            standby_promoted.push((ev.token(), sess.client_addr));
                                        }
                                    }
                                    Some(SrtpFrame::Probe(_)) => {}
                                    None => {
                                        sess.auth_drops += 1;
                                    }
                                }
                                if rx_ok_bytes > 0 {
                                    record_client_media_bytes(sess, &cfg, ka_base_ms, now, rx_ok_bytes);
                                }
                            } else {
                                sess.auth_drops += 1;
                            }
                        }
                        PacketKind::Unknown => {
                            sess.auth_drops += 1;
                        }
                    }
                }
            }
        }

        // V4: When a standby MBB session completes DTLS 1.3 (or STUN), send encrypted 0xFFFC
        // backend_sock atomic handover request while keeping old primary 100% live (0ms stall!).
        for (new_tok, client_addr) in standby_ready {
            let is_current_standby = standby_by_client.get(&client_addr) == Some(&new_tok);
            let expected_prim = sessions_by_token
                .get(&new_tok)
                .and_then(|s| s.standby_for_primary);
            let owner_info = if is_current_standby
                && expected_prim.is_some()
                && token_by_client.get(&client_addr).copied() == expected_prim
            {
                expected_prim.and_then(|pt| {
                    sessions_by_token.get(&pt).and_then(|p| {
                        if p.state == HandshakeState::Ready {
                            p.session_key.map(|k| (p.ice.username(), k))
                        } else {
                            None
                        }
                    })
                })
            } else {
                None
            };

            let Some((old_ufrag, old_key)) = owner_info else {
                if is_current_standby {
                    standby_by_client.remove(&client_addr);
                }
                if let Some(orphan) = sessions_by_token.get_mut(&new_tok) {
                    graceful_teardown_client(orphan, &mut dtls_buf);
                    orphan.state = HandshakeState::Closing(
                        now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS),
                    );
                }
                continue;
            };

            if let Some(new_sess) = sessions_by_token.get_mut(&new_tok) {
                if let Some(new_key) = new_sess.session_key {
                    let proof = compute_handover_proof(&old_key, &new_key);
                    let ub = old_ufrag.as_bytes();
                    let mut payload = Vec::with_capacity(2 + ub.len() + 32);
                    payload.push(0x01);
                    payload.push(ub.len() as u8);
                    payload.extend_from_slice(ub);
                    payload.extend_from_slice(&proof);
                    if let Some(ref mut cipher) = new_sess.cipher {
                        if let Some(wn) =
                            cipher.wrap_control_into(SRTP_HANDOVER_MAGIC, &payload, &mut wbuf)
                        {
                            if new_sess.upstream.send(&wbuf[..wn]).is_ok() {
                                new_sess.tx_pkts += 1;
                            }
                        }
                    }
                    new_sess.state = HandshakeState::HandoverWait;
                    new_sess.handover_payload = Some(payload);
                    new_sess.handover_retries = 0;
                    new_sess.handover_retry_at =
                        Some(now + retry_dur.max(Duration::from_millis(380)));
                } else {
                    standby_promoted.push((new_tok, client_addr));
                }
            }
        }

        // Atomic 0ms Make-Before-Break standby promotion with ownership verification & delayed BYE (2-10s)
        for (new_tok, client_addr) in standby_promoted {
            let is_current_standby = standby_by_client.get(&client_addr) == Some(&new_tok);
            if is_current_standby {
                standby_by_client.remove(&client_addr);
            }
            let expected_prim = sessions_by_token
                .get(&new_tok)
                .and_then(|s| s.standby_for_primary);
            let owner_is_live_primary = is_current_standby
                && expected_prim.is_some()
                && token_by_client.get(&client_addr).copied() == expected_prim
                && expected_prim
                    .and_then(|pt| sessions_by_token.get(&pt))
                    .map(|p| p.state == HandshakeState::Ready)
                    .unwrap_or(false);

            if !owner_is_live_primary {
                // Orphaned standby (owning primary already rotated, restarted, or closed) -> tear down cleanly!
                if let Some(orphan) = sessions_by_token.get_mut(&new_tok) {
                    graceful_teardown_client(orphan, &mut dtls_buf);
                    orphan.state = HandshakeState::Closing(
                        now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS),
                    );
                }
                continue;
            }

            let new_port = match sessions_by_token.get_mut(&new_tok) {
                Some(new_sess) if new_sess.state == HandshakeState::Ready => {
                    new_sess.is_standby = false;
                    new_sess.standby_for_primary = None;
                    new_sess.standby_spawned = false;
                    schedule_mbb_timers(new_sess, &cfg, now);
                    new_sess.local_port
                }
                _ => continue,
            };
            if let Some(old_tok) = token_by_client.insert(client_addr, new_tok) {
                if old_tok != new_tok {
                    if let Some(old_sess) = sessions_by_token.get_mut(&old_tok) {
                        if old_sess.state == HandshakeState::Ready {
                            let bye_delay = rand_duration_range_ms(2_000, 10_000);
                            log(
                                worker_id,
                                &format!(
                                    "MBB 0ms rotation complete client={} old_sport={} -> new_sport={} (delayed BYE in {:.1}s)",
                                    client_addr,
                                    old_sess.local_port,
                                    new_port,
                                    bye_delay.as_secs_f64()
                                ),
                            );
                            old_sess.ka_txid = None;
                            old_sess.ka_pkt.clear();
                            old_sess.ka_retries = 0;
                            old_sess.ka_rto_at = None;
                            old_sess.state = HandshakeState::DrainingBeforeBye(now + bye_delay);
                        }
                    }
                }
            }
        }

        // Jittered sub-second reconnect when server sends graceful BYE/close_notify (e.g. SIGTERM restart).
        // Waits 80..350ms before transmitting fresh STUN to clear systemd restart bind gap (zero ICMP bounce!).
        for (old_tok, client_addr) in graceful_reconnects {
            if token_by_client.get(&client_addr) == Some(&old_tok) {
                token_by_client.remove(&client_addr);
                cancel_standby_for_client(
                    client_addr,
                    &mut standby_by_client,
                    &mut sessions_by_token,
                    &mut dtls_buf,
                    now,
                );
                let jitter = rand_duration_range_ms(80, 350);
                log(
                    worker_id,
                    &format!(
                        "peer sent graceful BYE/close_notify on active client={} -> fast-reconnecting in {}ms",
                        client_addr,
                        jitter.as_millis()
                    ),
                );
                pending_reconnects
                    .entry(client_addr)
                    .or_insert_with(|| PendingReconnect {
                        at: now + jitter,
                        pending: VecDeque::with_capacity(32),
                        pending_bytes: 0,
                    });
            }
        }

        if now.duration_since(last_stats) >= stats_dur {
            last_stats = now;
            for sess in sessions_by_token.values() {
                if matches!(
                    sess.state,
                    HandshakeState::Closing(_) | HandshakeState::DrainingBeforeBye(_)
                ) {
                    continue;
                }
                log(
                    worker_id,
                    &format!(
                        "stats up_sport={} tx={}pkts/{:.1}KB rx={}pkts/{:.1}KB ka={} rtcp={}/{} drops={}",
                        sess.local_port,
                        sess.tx_pkts,
                        sess.tx_bytes as f64 / 1024.0,
                        sess.rx_pkts,
                        sess.rx_bytes as f64 / 1024.0,
                        sess.keepalives_ok,
                        sess.srtcp_tx,
                        sess.srtcp_rx,
                        sess.auth_drops
                    ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{demux_rfc7983, parse_stun, PacketKind, STUN_BINDING_REQUEST};
    use crate::server::{run_server, ServerConfig};
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
    use std::thread;

    fn reserve_free_port() -> u16 {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    }

    #[test]
    fn asymmetric_uplink_blackhole_auto_rotates_and_single_stun_loss_retransmits_same_txid() {
        let psk = b"v034-asymmetric-blackhole-test-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        // 1. Local UDP echo backend (simulating Hysteria2 / QUIC backend accepting migrated source ports)
        let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                    let _ = echo_sock.send_to(&buf[..n], peer);
                }
            }
        });

        // 2. Real webrtc-cloak server
        let srv_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::Auto,
                workers: 1,
                max_sessions: 64,
                wan_mtu: 1488,
                idle_timeout_secs: 120,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: false,
                stop: None,
            });
        });

        // 3. Fault-injecting UDP relay between client and server (tracks per-client-port upstream sockets)
        let drop_first_ka = Arc::new(AtomicBool::new(true));
        let blackhole_port = Arc::new(AtomicU16::new(0));
        let first_port = Arc::new(AtomicU16::new(0));
        let latest_port = Arc::new(AtomicU16::new(0));
        let same_txid_retransmits = Arc::new(AtomicUsize::new(0));
        let blackholed_ka_txids_matched = Arc::new(AtomicUsize::new(0));
        let downlink_srtcp_during_blackhole = Arc::new(AtomicUsize::new(0));

        let relay_drop_first = Arc::clone(&drop_first_ka);
        let relay_bh_port = Arc::clone(&blackhole_port);
        let relay_first_port = Arc::clone(&first_port);
        let relay_latest_port = Arc::clone(&latest_port);
        let relay_same_txid = Arc::clone(&same_txid_retransmits);
        let relay_bh_txid_match = Arc::clone(&blackholed_ka_txids_matched);
        let relay_dl_srtcp = Arc::clone(&downlink_srtcp_during_blackhole);
        let relay_psk = psk.clone();

        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut dropped_ka_txid: Option<[u8; 12]> = None;
            let mut bh_first_ka_txid: Option<[u8; 12]> = None;
            let mut buf = [0u8; 4096];

            loop {
                // Client -> Server direction
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    let _ = relay_first_port.compare_exchange(0, cport, Ordering::SeqCst, Ordering::SeqCst);
                    relay_latest_port.store(cport, Ordering::SeqCst);

                    let pkt = &buf[..n];
                    let is_ka_stun = demux_rfc7983(pkt) == PacketKind::Stun
                        && parse_stun(pkt, &relay_psk)
                            .map(|p| p.authenticated && p.msg_type == STUN_BINDING_REQUEST && !p.use_candidate)
                            .unwrap_or(false);

                    // Phase 2: Asymmetric uplink blackhole on blackhole_port (0% uplink reaches server!)
                    let bh = relay_bh_port.load(Ordering::SeqCst);
                    if bh != 0 && cport == bh {
                        if is_ka_stun {
                            if let Some(p) = parse_stun(pkt, &relay_psk) {
                                match bh_first_ka_txid {
                                    None => bh_first_ka_txid = Some(p.txid),
                                    Some(prev) if prev == p.txid => {
                                        relay_bh_txid_match.fetch_add(1, Ordering::SeqCst);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        continue; // Drop 100% uplink for blackholed 5-tuple!
                    }

                    // Phase 1: Drop exactly ONE STUN keepalive to verify RFC 5389 same-txid retry without rotation
                    if is_ka_stun {
                        if let Some(p) = parse_stun(pkt, &relay_psk) {
                            if relay_drop_first.swap(false, Ordering::SeqCst) {
                                dropped_ka_txid = Some(p.txid);
                                continue;
                            }
                            if dropped_ka_txid == Some(p.txid) {
                                relay_same_txid.fetch_add(1, Ordering::SeqCst);
                                dropped_ka_txid = None;
                            }
                        }
                    }

                    let entry = upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    let _ = entry.0.send(pkt);
                }

                // Server -> Client direction (ALWAYS passed — even during uplink blackhole!)
                for (&cport, (usock, cli_addr)) in upstreams.iter() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let pkt = &buf[..n];
                        let bh = relay_bh_port.load(Ordering::SeqCst);
                        if bh != 0 && cport == bh && demux_rfc7983(pkt) == PacketKind::Srtcp {
                            relay_dl_srtcp.fetch_add(1, Ordering::SeqCst);
                        }
                        let _ = relay_front.send_to(pkt, *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
        });

        // 4. Real webrtc-cloak client pointing to relay (--keepalive 1 so test completes in ~8s)
        let cli_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::Auto,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 64,
                wan_mtu: 1488,
                retry_ms: 200,
                max_retries: 8,
                keepalive_secs: 1,
                idle_timeout_secs: 120,
                stats_interval_secs: 3600,
                quiet: false,
                stop: None,
            });
        });

        thread::sleep(Duration::from_millis(120));

        // 5. Local app socket (simulating mihomo Hysteria2 client staying on ONE fixed local port)
        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();

        let mut rbuf = [0u8; 256];
        let mut ready = false;
        let t_init = Instant::now();
        while t_init.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"PING_INIT");
            match app.recv(&mut rbuf) {
                Ok(n) if &rbuf[..n] == b"PING_INIT" => {
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                _ => {
                    // Linux returns immediate ECONNREFUSED before client thread binds listen_port
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        assert!(ready, "initial STUN+DTLS tunnel should come up");
        let port1 = first_port.load(Ordering::SeqCst);
        assert_ne!(port1, 0);

        // Phase 1: Wait for the 1st STUN keepalive drop + RFC 5389 same-txid retransmission recovery
        let t_p1 = Instant::now();
        while same_txid_retransmits.load(Ordering::SeqCst) == 0 && t_p1.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"PING_P1");
            let _ = app.recv(&mut rbuf);
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            same_txid_retransmits.load(Ordering::SeqCst),
            1,
            "single dropped STUN keepalive MUST trigger RFC 5389 same-txid retransmission"
        );
        assert_eq!(
            latest_port.load(Ordering::SeqCst),
            port1,
            "single dropped STUN keepalive MUST NOT cause false 5-tuple rotation"
        );

        // Phase 2: Inject 100% asymmetric uplink blackhole on port1 while downlink SRTCP continues!
        blackhole_port.store(port1, Ordering::SeqCst);
        let t_bh = Instant::now();
        let mut recovered = false;
        while t_bh.elapsed() < Duration::from_secs(10) {
            let _ = app.send(b"PING_AFTER_BH");
            if let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"PING_AFTER_BH" && latest_port.load(Ordering::SeqCst) != port1 {
                    recovered = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(150));
        }
        assert!(
            recovered,
            "client MUST detect asymmetric uplink blackhole despite downlink SRTCP (dl_srtcp={}) and rotate off port {}",
            downlink_srtcp_during_blackhole.load(Ordering::SeqCst),
            port1
        );
        assert_ne!(latest_port.load(Ordering::SeqCst), port1);
        assert_eq!(
            blackholed_ka_txids_matched.load(Ordering::SeqCst),
            KA_MAX_RETRIES as usize,
            "blackhole probe MUST perform exactly {} RFC 5389 same-txid retransmits before rotating",
            KA_MAX_RETRIES
        );
        assert!(
            downlink_srtcp_during_blackhole.load(Ordering::SeqCst) >= 1,
            "test should verify server was still sending downlink SRTCP during asymmetric blackhole"
        );
    }

    /// H-01 regression test: drop the client's DTLS 1.3 Flight 5 (0x2e encrypted Cert+CV+Fin) packet
    /// ONCE on the wire — client is ALREADY in HandshakeState::Ready and MUST drive dtls_next_timeout
    /// to retransmit Flight 5 and complete the tunnel within ~1.5s (not 25s blackout!).
    #[test]
    fn dtls13_flight5_packet_loss_retransmits_from_ready_state() {
        let psk = b"v036-h01-flight5-loss-regression-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                    let _ = echo_sock.send_to(&buf[..n], peer);
                }
            }
        });

        let srv_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 16,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: None,
            });
        });

        // Relay that drops the VERY FIRST client->server DTLS 1.3 Unified Ciphertext packet (0x20..=0x3F = Flight 5!)
        let dropped_f5 = Arc::new(AtomicBool::new(false));
        let relay_dropped_f5 = Arc::clone(&dropped_f5);
        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let usock = UdpSocket::bind("127.0.0.1:0").unwrap();
            usock.set_nonblocking(true).unwrap();
            usock.connect(srv_addr).unwrap();
            let mut cli_addr: Option<SocketAddr> = None;
            let mut buf = [0u8; 4096];
            loop {
                while let Ok((n, peer)) = relay_front.recv_from(&mut buf) {
                    cli_addr = Some(peer);
                    let pkt = &buf[..n];
                    // Drop the first DTLS 1.3 Unified Ciphertext (b0 in 0x20..=0x3F) from client = Flight 5!
                    if !pkt.is_empty()
                        && (pkt[0] & 0xE0) == 0x20
                        && !relay_dropped_f5.swap(true, Ordering::SeqCst)
                    {
                        continue;
                    }
                    let _ = usock.send(pkt);
                }
                if let Some(ca) = cli_addr {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let _ = relay_front.send_to(&buf[..n], ca);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 16,
                wan_mtu: 1488,
                retry_ms: 200,
                max_retries: 8,
                keepalive_secs: 5,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                quiet: true,
                stop: None,
            });
        });

        thread::sleep(Duration::from_millis(80));
        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();

        let t0 = Instant::now();
        let mut ok = false;
        let mut rbuf = [0u8; 256];
        while t0.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"PING_F5_RECOVER");
            match app.recv(&mut rbuf) {
                Ok(n) if &rbuf[..n] == b"PING_F5_RECOVER" => {
                    ok = true;
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                _ => {
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        assert!(dropped_f5.load(Ordering::SeqCst), "relay should have intercepted DTLS 1.3 Flight 5");
        assert!(
            ok,
            "client MUST retransmit dropped DTLS 1.3 Flight 5 from Ready state and recover within 3s!"
        );
    }

    /// v0.3.7 #7 regression test: graceful server shutdown (stop flag / SIGTERM) broadcasts
    /// encrypted SRTCP BYE + DTLS close_notify so client fast-reconnects in <1.5s (not 5-7s!).
    #[test]
    fn graceful_server_shutdown_bye_triggers_subsecond_reconnect() {
        let psk = b"v037-sigterm-bye-fast-reconnect-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                    let _ = echo_sock.send_to(&buf[..n], peer);
                }
            }
        });

        let stop1 = Arc::new(AtomicBool::new(false));
        let stop1_c = Arc::clone(&stop1);
        let srv_psk1 = psk.clone();
        let srv1_handle = thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk1,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::Auto,
                workers: 1,
                max_sessions: 16,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: Some(stop1_c),
            });
        });

        let first_port = Arc::new(AtomicU16::new(0));
        let latest_port = Arc::new(AtomicU16::new(0));
        let r_first = Arc::clone(&first_port);
        let r_latest = Arc::clone(&latest_port);
        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut buf = [0u8; 4096];
            loop {
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    let _ = r_first.compare_exchange(0, cport, Ordering::SeqCst, Ordering::SeqCst);
                    r_latest.store(cport, Ordering::SeqCst);
                    let entry = upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    let _ = entry.0.send(&buf[..n]);
                }
                for (usock, cli_addr) in upstreams.values() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let _ = relay_front.send_to(&buf[..n], *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        // Long keepalive (30s) proves recovery comes from server BYE/close_notify, NOT STUN consent timeout!
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::Auto,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 16,
                wan_mtu: 1488,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 30,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                quiet: true,
                stop: None,
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();

        let mut rbuf = [0u8; 256];
        let mut ready = false;
        let t_init = Instant::now();
        while t_init.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"PING_BEFORE_SHUTDOWN");
            match app.recv(&mut rbuf) {
                Ok(n) if &rbuf[..n] == b"PING_BEFORE_SHUTDOWN" => {
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                _ => thread::sleep(Duration::from_millis(40)),
            }
        }
        assert!(ready, "initial tunnel should come up");
        let port1 = first_port.load(Ordering::SeqCst);
        assert_ne!(port1, 0);

        // Trigger graceful server shutdown (SIGTERM equivalent) and spawn replacement server on same port
        let t_restart = Instant::now();
        stop1.store(true, Ordering::SeqCst);
        let _ = srv1_handle.join();

        let srv_psk2 = psk.clone();
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk2,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::Auto,
                workers: 1,
                max_sessions: 16,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: None,
            });
        });

        // Must recover via graceful BYE fast-reconnect well before the 30s keepalive!
        let mut recovered = false;
        while t_restart.elapsed() < Duration::from_secs(3) {
            let _ = app.send(b"PING_AFTER_BYE");
            if let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"PING_AFTER_BYE" && latest_port.load(Ordering::SeqCst) != port1 {
                    recovered = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(30));
        }
        assert!(
            recovered,
            "client MUST fast-reconnect on server graceful BYE well under 3s (keepalive=30s)!"
        );
    }

    /// v0.3.7 #8 regression test: proactive Make-Before-Break scheduled 5-tuple rotation
    /// (`--rotate-interval 2`) switches to a fresh UDP port with ZERO dropped packets!
    #[test]
    fn proactive_mbb_scheduled_rotation_zero_loss() {
        let psk = b"v037-mbb-zero-loss-rotation-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                    let _ = echo_sock.send_to(&buf[..n], peer);
                }
            }
        });

        let srv_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::Auto,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: None,
            });
        });

        let first_port = Arc::new(AtomicU16::new(0));
        let latest_port = Arc::new(AtomicU16::new(0));
        let r_first = Arc::clone(&first_port);
        let r_latest = Arc::clone(&latest_port);
        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut buf = [0u8; 4096];
            loop {
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    let _ = r_first.compare_exchange(0, cport, Ordering::SeqCst, Ordering::SeqCst);
                    r_latest.store(cport, Ordering::SeqCst);
                    let entry = upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    let _ = entry.0.send(&buf[..n]);
                }
                for (usock, cli_addr) in upstreams.values() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let _ = relay_front.send_to(&buf[..n], *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::Auto,
                rotate_interval_secs: 2, // log-normal MBB rotation in 0.7s..5.6s!
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 30,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                quiet: true,
                stop: None,
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();

        let mut rbuf = [0u8; 256];
        let mut ready = false;
        let t_init = Instant::now();
        while t_init.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"MBB_WARMUP");
            match app.recv(&mut rbuf) {
                Ok(n) if &rbuf[..n] == b"MBB_WARMUP" => {
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                _ => thread::sleep(Duration::from_millis(40)),
            }
        }
        assert!(ready, "initial tunnel should come up");
        let port1 = first_port.load(Ordering::SeqCst);
        assert_ne!(port1, 0);

        // Stream continuously across the log-normal [0.7s..5.6s] MBB cutover window + 30 packets post-cutover!
        let mut ok_cnt = 0usize;
        let mut post_cutover = 0usize;
        let t_stream = Instant::now();
        let mut seq = 0u32;
        while t_stream.elapsed() < Duration::from_secs(7) {
            let msg = format!("MBB_SEQ_{:04}", seq);
            seq += 1;
            app.send(msg.as_bytes()).unwrap();
            let n = app.recv(&mut rbuf).expect("MBB rotation MUST deliver with zero packet loss!");
            assert_eq!(&rbuf[..n], msg.as_bytes());
            ok_cnt += 1;
            if latest_port.load(Ordering::SeqCst) != port1 {
                post_cutover += 1;
                if post_cutover >= 30 {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        let port2 = latest_port.load(Ordering::SeqCst);
        assert!(ok_cnt >= 35);
        assert_ne!(
            port2, port1,
            "proactive MBB rotation MUST switch off port {} to a fresh 5-tuple within 7s!",
            port1
        );
    }

    /// v0.3.8 regression test:
    /// 1) Byte-volume budget triggers zero-loss MBB rotation after cooldown;
    /// 2) Delayed old-session BYE (2-10s) keeps old server session Ready during overlap so slow
    ///    backend replies (500ms) arrive intact instead of being dropped in ServerState::Closing!
    /// 3) Old-session BYE is NOT emitted immediately (<1.5s) after new port goes live.
    #[test]
    fn v38_byte_budget_mbb_and_delayed_bye_delivers_slow_backend_replies() {
        let psk = b"v038-byte-budget-delayed-bye-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        // Echo backend that delays packets starting with "SLOW:" by 500ms (simulating slow DNS/TCP reply)
        let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        let echo_tx = echo_sock.try_clone().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                    let data = buf[..n].to_vec();
                    if data.starts_with(b"SLOW:") {
                        let tx = echo_tx.try_clone().unwrap();
                        thread::spawn(move || {
                            thread::sleep(Duration::from_millis(500));
                            let _ = tx.send_to(&data, peer);
                        });
                    } else {
                        let _ = echo_sock.send_to(&data, peer);
                    }
                }
            }
        });

        let srv_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: None,
            });
        });

        let first_port = Arc::new(AtomicU16::new(0));
        let latest_port = Arc::new(AtomicU16::new(0));
        let port1_srtcp_after_cutover_ms = Arc::new(std::sync::Mutex::new(Option::<u128>::None));
        let r_first = Arc::clone(&first_port);
        let r_latest = Arc::clone(&latest_port);
        let r_bye_ms = Arc::clone(&port1_srtcp_after_cutover_ms);
        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut cutover_at: Option<Instant> = None;
            let mut buf = [0u8; 4096];
            loop {
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    let _ = r_first.compare_exchange(0, cport, Ordering::SeqCst, Ordering::SeqCst);
                    r_latest.store(cport, Ordering::SeqCst);
                    let p1 = r_first.load(Ordering::SeqCst);
                    let kind = demux_rfc7983(&buf[..n]);
                    if p1 != 0 && cport != p1 && kind == PacketKind::Srtp && cutover_at.is_none() {
                        cutover_at = Some(Instant::now());
                    }
                    if let Some(ct) = cutover_at {
                        if cport == p1 && kind == PacketKind::Srtcp {
                            let mut guard = r_bye_ms.lock().unwrap();
                            if guard.is_none() {
                                *guard = Some(ct.elapsed().as_millis());
                            }
                        }
                    }
                    let entry = upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    let _ = entry.0.send(&buf[..n]);
                }
                for (usock, cli_addr) in upstreams.values() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let _ = relay_front.send_to(&buf[..n], *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,      // time trigger disabled -> pure byte-budget test!
                rotate_max_bytes: 20 * 1024,  // 20KB base -> random 10..37KB budget!
                rotate_cooldown_secs: 1,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 30,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                quiet: true,
                stop: None,
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();

        let mut rbuf = [0u8; 2048];
        let mut ready = false;
        let t_init = Instant::now();
        while t_init.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"BYTE_WARMUP");
            match app.recv(&mut rbuf) {
                Ok(n) if &rbuf[..n] == b"BYTE_WARMUP" => {
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                _ => thread::sleep(Duration::from_millis(40)),
            }
        }
        assert!(ready, "initial tunnel should come up");
        let port1 = first_port.load(Ordering::SeqCst);

        // Wait past the 1s cooldown while streaming 1000B packets + SLOW:500ms probes across the byte-budget cutover!
        let mut slow_sent = std::collections::HashSet::<u32>::new();
        let mut slow_recvd = std::collections::HashSet::<u32>::new();
        let mut cutover_seen = false;
        app.set_nonblocking(true).unwrap();

        let t_run = Instant::now();
        let mut seq = 0u32;
        while t_run.elapsed() < Duration::from_secs(5) {
            let mut bulk = vec![0x41u8; 1000];
            bulk[..4].copy_from_slice(b"BLK:");
            let _ = app.send(&bulk);

            // Every 4th packet is a 500ms-delayed SLOW backend reply to prove old_sess does NOT drop it on cutover!
            if seq % 4 == 0 {
                let slow_msg = format!("SLOW:{:04}", seq);
                let _ = app.send(slow_msg.as_bytes());
                slow_sent.insert(seq);
            }
            seq += 1;

            while let Ok(n) = app.recv(&mut rbuf) {
                if n >= 9 && &rbuf[..5] == b"SLOW:" {
                    if let Ok(s) = std::str::from_utf8(&rbuf[5..9]) {
                        if let Ok(id) = s.parse::<u32>() {
                            slow_recvd.insert(id);
                        }
                    }
                }
            }
            if latest_port.load(Ordering::SeqCst) != port1 {
                cutover_seen = true;
                // Keep sending a few packets on new port so cutover_at triggers in relay
                for _ in 0..5 {
                    let _ = app.send(&bulk);
                    thread::sleep(Duration::from_millis(20));
                }
                break;
            }
            thread::sleep(Duration::from_millis(40));
        }
        assert!(cutover_seen, "byte-budget MBB rotation MUST trigger off port {}", port1);

        // Drain all in-flight 500ms SLOW backend replies (proves old session stayed Ready on server!)
        let t_drain = Instant::now();
        while t_drain.elapsed() < Duration::from_secs(1) {
            while let Ok(n) = app.recv(&mut rbuf) {
                if n >= 9 && &rbuf[..5] == b"SLOW:" {
                    if let Ok(s) = std::str::from_utf8(&rbuf[5..9]) {
                        if let Ok(id) = s.parse::<u32>() {
                            slow_recvd.insert(id);
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            slow_recvd.len(),
            slow_sent.len(),
            "ALL slow 500ms backend replies MUST survive MBB cutover via delayed BYE overlap ({}/{})",
            slow_recvd.len(),
            slow_sent.len()
        );

        // Verify old-session BYE was NOT sent immediately (<1.5s) after cutover!
        let early_bye = *port1_srtcp_after_cutover_ms.lock().unwrap();
        if let Some(ms) = early_bye {
            assert!(
                ms >= 1_500,
                "old-session BYE MUST be delayed 2..10s after MBB cutover (saw {}ms!)",
                ms
            );
        }
    }

    /// v0.3.8 regression test: overnight background trickle (<64KB/5min ≈ 218 B/s) MUST suspend
    /// proactive MBB rotation so idle keepalives don't churn full DTLS handshakes all night.
    #[test]
    fn v38_background_trickle_suspends_proactive_mbb_rotation() {
        let psk = b"v038-trickle-mbb-suspend-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                    let _ = echo_sock.send_to(&buf[..n], peer);
                }
            }
        });

        let srv_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 16,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: None,
            });
        });

        let first_port = Arc::new(AtomicU16::new(0));
        let latest_port = Arc::new(AtomicU16::new(0));
        let r_first = Arc::clone(&first_port);
        let r_latest = Arc::clone(&latest_port);
        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut buf = [0u8; 4096];
            loop {
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    let _ = r_first.compare_exchange(0, cport, Ordering::SeqCst, Ordering::SeqCst);
                    r_latest.store(cport, Ordering::SeqCst);
                    let entry = upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    let _ = entry.0.send(&buf[..n]);
                }
                for (usock, cli_addr) in upstreams.values() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let _ = relay_front.send_to(&buf[..n], *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 1, // median 1s -> max lognormal 2.8s, hard cap 6s
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 16,
                wan_mtu: 1488,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 30,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                quiet: true,
                stop: None,
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();

        let mut rbuf = [0u8; 256];
        let mut ready = false;
        let t_init = Instant::now();
        while t_init.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"KA_INIT");
            match app.recv(&mut rbuf) {
                Ok(n) if &rbuf[..n] == b"KA_INIT" => {
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                _ => thread::sleep(Duration::from_millis(40)),
            }
        }
        assert!(ready, "initial tunnel should come up");
        let port1 = first_port.load(Ordering::SeqCst);

        // Send only tiny 32B inner keepalives every 1s (64 B/s << 218 B/s threshold) across 3.8s
        // (well past max 2.8s lognormal rotate_at, before 6s hard cap) -> MUST stay on port1!
        for _ in 0..4 {
            thread::sleep(Duration::from_millis(950));
            let ka = [0x5Au8; 32];
            app.send(&ka).unwrap();
            let n = app.recv(&mut rbuf).unwrap();
            assert_eq!(n, 32);
        }
        assert_eq!(
            latest_port.load(Ordering::SeqCst),
            port1,
            "background trickle keepalives (<64KB/5min) MUST suspend proactive MBB rotation!"
        );
    }

    /// V4.0 Scenario #1 (Carbon): Strict source-port-pinned stateful UDP backend (simulating
    /// legacy game server / SIP / OpenVPN that breaks if server backend_lport EVER changes!)
    /// MUST see ZERO backend port changes across BOTH:
    ///   1) Scheduled DTLS 1.3 MBB rotation (unlinkable new ufrag/SSRC + encrypted 0xFFFC handover), AND
    ///   2) Asymmetric uplink blackhole 1-RTT ICE path migration (ZERO DTLS packets on migrated port!).
    #[test]
    fn v40_strict_pinned_udp_backend_survives_mbb_handover_and_1rtt_blackhole_migration() {
        let psk = b"v040-strict-pinned-udp-test-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        // StrictPinnedUdpBackend: locks onto first backend_lport; records any violation; pushes async ticks!
        let pinned_port = Arc::new(AtomicU16::new(0));
        let port_violations = Arc::new(AtomicUsize::new(0));
        let stop_backend = Arc::new(AtomicBool::new(false));
        let b_pinned = Arc::clone(&pinned_port);
        let b_viol = Arc::clone(&port_violations);
        let b_stop = Arc::clone(&stop_backend);

        let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        backend_sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut locked_peer: Option<SocketAddr> = None;
            let mut tick_seq = 0u32;
            let mut last_tick = Instant::now();
            while !b_stop.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = backend_sock.recv_from(&mut buf) {
                    match locked_peer {
                        None => {
                            locked_peer = Some(peer);
                            b_pinned.store(peer.port(), Ordering::SeqCst);
                        }
                        Some(p) if p != peer => {
                            b_viol.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    // Always reply ONLY to locked_peer!
                    if let Some(lp) = locked_peer {
                        let _ = backend_sock.send_to(&buf[..n], lp);
                    }
                }
                if let Some(lp) = locked_peer {
                    if last_tick.elapsed() >= Duration::from_millis(35) {
                        last_tick = Instant::now();
                        let msg = format!("TICK:{:05}", tick_seq);
                        tick_seq += 1;
                        let _ = backend_sock.send_to(msg.as_bytes(), lp);
                    }
                }
            }
        });

        let srv_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: None,
            });
        });

        let latest_port = Arc::new(AtomicU16::new(0));
        let blackhole_port = Arc::new(AtomicU16::new(0));
        let dtls_by_port = Arc::new(std::sync::Mutex::new(HashMap::<u16, usize>::new()));
        let r_latest = Arc::clone(&latest_port);
        let r_bh = Arc::clone(&blackhole_port);
        let r_dtls = Arc::clone(&dtls_by_port);

        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut buf = [0u8; 4096];
            loop {
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    r_latest.store(cport, Ordering::SeqCst);
                    let bh = r_bh.load(Ordering::SeqCst);
                    if bh != 0 && cport == bh {
                        continue; // 100% asymmetric uplink blackhole!
                    }
                    if demux_rfc7983(&buf[..n]) == PacketKind::Dtls {
                        *r_dtls.lock().unwrap().entry(cport).or_insert(0) += 1;
                    }
                    let entry = upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    let _ = entry.0.send(&buf[..n]);
                }
                for (usock, cli_addr) in upstreams.values() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let _ = relay_front.send_to(&buf[..n], *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 16 * 1024, // triggers full DTLS 1.3 MBB + 0xFFFC handover!
                rotate_cooldown_secs: 1,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 1,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                quiet: true,
                stop: None,
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();

        let mut rbuf = [0u8; 2048];
        let mut ready = false;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"PIN_INIT");
            if let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"PIN_INIT" {
                    ready = true;
                    break;
                }
            } else {
                thread::sleep(Duration::from_millis(30));
            }
        }
        assert!(ready, "initial tunnel must come up");
        let port1 = latest_port.load(Ordering::SeqCst);
        let initial_backend_port = pinned_port.load(Ordering::SeqCst);
        assert_ne!(initial_backend_port, 0);

        // Phase 1: Trigger full DTLS 1.3 MBB rotation via byte budget (port1 -> port2)
        // Verify unlinkable DTLS handshake happened on port2 AND backend_lport stayed 100% IDENTICAL!
        app.set_nonblocking(true).unwrap();
        let mut ticks_seen = 0usize;
        let t_mbb = Instant::now();
        let mut port2 = 0u16;
        while t_mbb.elapsed() < Duration::from_secs(5) {
            let bulk = vec![0x42u8; 900];
            let _ = app.send(&bulk);
            while let Ok(n) = app.recv(&mut rbuf) {
                if rbuf[..n].starts_with(b"TICK:") {
                    ticks_seen += 1;
                }
            }
            let cur = latest_port.load(Ordering::SeqCst);
            if cur != port1 {
                port2 = cur;
                // Send a few more packets on port2 to confirm StrictPinnedUdpBackend accepts them!
                for i in 0..5u32 {
                    let p = format!("POST_MBB_{}", i);
                    let _ = app.send(p.as_bytes());
                    thread::sleep(Duration::from_millis(25));
                    while let Ok(n) = app.recv(&mut rbuf) {
                        if rbuf[..n].starts_with(b"TICK:") {
                            ticks_seen += 1;
                        }
                    }
                }
                break;
            }
            thread::sleep(Duration::from_millis(30));
        }
        assert_ne!(port2, 0, "MBB byte-budget rotation must switch off port {}", port1);
        assert!(
            *dtls_by_port.lock().unwrap().get(&port2).unwrap_or(&0) >= 2,
            "scheduled MBB rotation MUST run fresh DTLS 1.3 handshake on port2 (unlinkable outer identity!)"
        );
        assert_eq!(
            port_violations.load(Ordering::SeqCst),
            0,
            "scheduled DTLS 1.3 MBB + 0xFFFC handover MUST NEVER change server backend_lport!"
        );

        // Phase 2: Inject 100% asymmetric uplink blackhole on port2 -> triggers V4 1-RTT ICE migration (port2 -> port3)!
        blackhole_port.store(port2, Ordering::SeqCst);
        let t_mig = Instant::now();
        let mut recovered_after_mig = false;
        let mut port3 = 0u16;
        while t_mig.elapsed() < Duration::from_secs(9) {
            let _ = app.send(b"PING_POST_1RTT_MIG");
            while let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"PING_POST_1RTT_MIG" {
                    let cur = latest_port.load(Ordering::SeqCst);
                    if cur != port2 && cur != port1 {
                        port3 = cur;
                        recovered_after_mig = true;
                    }
                } else if rbuf[..n].starts_with(b"TICK:") {
                    ticks_seen += 1;
                }
            }
            if recovered_after_mig {
                break;
            }
            thread::sleep(Duration::from_millis(80));
        }
        stop_backend.store(true, Ordering::SeqCst);

        assert!(recovered_after_mig, "1-RTT ICE migration MUST recover from asymmetric blackhole on port {}", port2);
        assert_eq!(
            *dtls_by_port.lock().unwrap().get(&port3).unwrap_or(&0),
            0,
            "1-RTT ICE blackhole migration on port {} MUST NOT run any DTLS handshake!",
            port3
        );
        assert_eq!(
            port_violations.load(Ordering::SeqCst),
            0,
            "StrictPinnedUdpBackend MUST see ZERO backend_lport changes across BOTH MBB handover AND 1-RTT migration!"
        );
        assert!(ticks_seen >= 5, "async backend ticks must keep flowing across cutovers (got {})", ticks_seen);
    }

    /// V4.0 Scenario #2 (Carbon Red-Team):
    /// 1) Spoofed-IP reflection DDoS: attacker clones legitimate migration STUN from `victim_sock`
    ///    while backend streams heavy downlink SRTP -> `victim_sock` MUST receive <200B total (0 business SRTP!);
    /// 2) Same-PSK cross-session hijack: evil peer with SAME PSK tries (a) global-PSK STUN migration
    ///    using victim's plaintext ufrag, and (b) encrypted 0xFFFC handover with forged proof -> BOTH 100% blocked!
    #[test]
    fn v40_redteam_spoofed_ip_reflection_and_same_psk_hijack_blocked() {
        let psk = b"v040-redteam-anti-reflection-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        // Heavy downlink echo backend (amplifies replies 20x to make any reflection leak unmistakable!)
        let stop_all = Arc::new(AtomicBool::new(false));
        let b_stop = Arc::clone(&stop_all);
        let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        backend_sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let big = vec![0xEEu8; 1000];
            while !b_stop.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = backend_sock.recv_from(&mut buf) {
                    if &buf[..n] == b"BLAST" {
                        for _ in 0..12 {
                            let _ = backend_sock.send_to(&big, peer);
                        }
                    } else {
                        let _ = backend_sock.send_to(&buf[..n], peer);
                    }
                }
            }
        });

        let srv_psk = psk.clone();
        let s_stop = Arc::clone(&stop_all);
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: Some(s_stop),
            });
        });

        let captured_ufrag = Arc::new(std::sync::Mutex::new(Option::<String>::None));
        let blackhole_port = Arc::new(AtomicU16::new(0));
        let latest_port = Arc::new(AtomicU16::new(0));
        let victim_rx_bytes = Arc::new(AtomicUsize::new(0));
        let spoof_fired = Arc::new(AtomicBool::new(false));

        let r_ufrag = Arc::clone(&captured_ufrag);
        let r_bh = Arc::clone(&blackhole_port);
        let r_latest = Arc::clone(&latest_port);
        let r_vbytes = Arc::clone(&victim_rx_bytes);
        let r_spoof = Arc::clone(&spoof_fired);
        let r_stop = Arc::clone(&stop_all);

        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        let victim_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        victim_sock.set_nonblocking(true).unwrap();
        victim_sock.connect(("127.0.0.1", server_port)).unwrap();

        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut buf = [0u8; 4096];
            while !r_stop.load(Ordering::Relaxed) {
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    r_latest.store(cport, Ordering::SeqCst);
                    let pkt = &buf[..n];
                    if demux_rfc7983(pkt) == PacketKind::Stun {
                        if let Some(u) = crate::protocol::peek_stun_request_username(pkt) {
                            let mut g = r_ufrag.lock().unwrap();
                            if g.is_none() {
                                *g = Some(u.to_string());
                            }
                        }
                    }
                    let bh = r_bh.load(Ordering::SeqCst);
                    if bh != 0 && cport == bh {
                        continue;
                    }
                    // When client opens migrated port (cport != bh && bh != 0), attacker intercepts first
                    // migration STUN and races it from victim_sock BEFORE forwarding!
                    if bh != 0
                        && cport != bh
                        && demux_rfc7983(pkt) == PacketKind::Stun
                        && !r_spoof.swap(true, Ordering::SeqCst)
                    {
                        let _ = victim_sock.send(pkt);
                        thread::sleep(Duration::from_millis(5));
                    }
                    let entry = upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    let _ = entry.0.send(pkt);
                }
                while let Ok(vn) = victim_sock.recv(&mut buf) {
                    r_vbytes.fetch_add(vn, Ordering::SeqCst);
                }
                for (usock, cli_addr) in upstreams.values() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let _ = relay_front.send_to(&buf[..n], *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        let c_stop = Arc::clone(&stop_all);
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 1,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                quiet: true,
                stop: Some(c_stop),
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();
        let mut rbuf = [0u8; 2048];
        let mut ready = false;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"REDTEAM_INIT");
            if let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"REDTEAM_INIT" {
                    ready = true;
                    break;
                }
            } else {
                thread::sleep(Duration::from_millis(30));
            }
        }
        assert!(ready);
        let port1 = latest_port.load(Ordering::SeqCst);
        let victim_ufrag = captured_ufrag.lock().unwrap().clone().expect("ufrag captured");

        // Attack 2a: Same-PSK attacker tries forging STUN migration with victim's plaintext ufrag using global PSK!
        let evil_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        evil_sock.set_read_timeout(Some(Duration::from_millis(120))).unwrap();
        evil_sock.connect(("127.0.0.1", server_port)).unwrap();
        let parts: Vec<&str> = victim_ufrag.split(':').collect();
        let mut evil_ice = SessionIceParams::generate();
        evil_ice.ufrag_remote = parts[0].to_string();
        evil_ice.ufrag_local = parts[1].to_string();
        let (forged_mig, _) = build_ice_stun_request(&psk, &evil_ice, None, true);
        let _ = evil_sock.send(&forged_mig);
        assert!(
            evil_sock.recv(&mut rbuf).is_err(),
            "global-PSK forged STUN migration for active ufrag MUST be 100% silent-dropped!"
        );

        // Attack 2b: Same-PSK attacker opens a real DTLS session and sends encrypted 0xFFFC handover with forged proof!
        let evil_ice2 = SessionIceParams::generate();
        let (evil_stun, evil_txid) = build_ice_stun_request(&psk, &evil_ice2, None, true);
        let _ = evil_sock.send(&evil_stun);
        let sn = evil_sock.recv(&mut rbuf).expect("evil legit STUN");
        let parsed_e = parse_stun(&rbuf[..sn], &psk).unwrap();
        assert!(parsed_e.authenticated);
        // Complete evil DTLS 1.3 handshake to get real encrypted SRTP channel
        let cpu = detect_cpu_accel();
        let dcfg = build_dimpl_config_pool(CipherPref::Auto, &cpu, true, 1488).pick();
        let mut edtls = new_dtls_instance(
            DtlsMinVersion::V13Only,
            dcfg,
            crate::protocol::generate_ephemeral_webrtc_cert(),
            Instant::now(),
        );
        edtls.set_active(true);
        let _ = edtls.handle_timeout(Instant::now());
        let mut dbuf = vec![0u8; 4096];
        let mut ekm = None;
        let mut e_conn = false;
        let t_hs = Instant::now();
        while !e_conn && t_hs.elapsed() < Duration::from_secs(3) {
            loop {
                match edtls.poll_output(&mut dbuf) {
                    DtlsOutput::Packet(p) => { let _ = evil_sock.send(p); }
                    DtlsOutput::KeyingMaterial(km, _) => ekm = Some(km.to_vec()),
                    DtlsOutput::Connected => e_conn = true,
                    DtlsOutput::Timeout(_) => break,
                    _ => {}
                }
            }
            if !e_conn {
                if let Ok(rn) = evil_sock.recv(&mut rbuf) {
                    if demux_rfc7983(&rbuf[..rn]) == PacketKind::Dtls {
                        let _ = edtls.handle_packet(&rbuf[..rn]);
                    }
                }
            }
        }
        assert!(e_conn && ekm.is_some());
        let (esk, es_c2s, es_s2c) = derive_stun_material(&psk, &evil_txid, &evil_ice2.username());
        let efk = combine_session_key(&esk, ekm.as_deref());
        let mut ecipher = SrtpCloakCipher::new(&efk, es_c2s, es_s2c, true, CipherSuite::Aes128Gcm);
        ecipher.set_dual_ssrc(true);
        let mut forged_ho = Vec::new();
        forged_ho.push(0x01);
        forged_ho.push(victim_ufrag.len() as u8);
        forged_ho.extend_from_slice(victim_ufrag.as_bytes());
        forged_ho.extend_from_slice(&[0xAAu8; 32]); // Forged proof!
        let mut wbuf = [0u8; 512];
        let wn = ecipher.wrap_control_into(SRTP_HANDOVER_MAGIC, &forged_ho, &mut wbuf).unwrap();
        let _ = evil_sock.send(&wbuf[..wn]);
        let mut saw_reject_ack = false;
        for _ in 0..5 {
            if let Ok(rn) = evil_sock.recv(&mut rbuf) {
                if demux_rfc7983(&rbuf[..rn]) == PacketKind::Srtp {
                    if let Some(SrtpFrame::Handover(hn)) = ecipher.unwrap_into_ex(&rbuf[..rn], &mut wbuf) {
                        if hn >= 2 && wbuf[0] == 0x02 && wbuf[1] == 0x00 {
                            saw_reject_ack = true;
                            break;
                        }
                    }
                }
            }
        }
        assert!(saw_reject_ack, "forged 0xFFFC handover proof MUST be rejected (status=0x00)!");

        // Attack 1: Trigger blackhole migration while spoofing victim_sock + blasting heavy downlink!
        blackhole_port.store(port1, Ordering::SeqCst);
        let t_mig = Instant::now();
        let mut healed = false;
        while t_mig.elapsed() < Duration::from_secs(9) {
            let _ = app.send(b"BLAST");
            if let Ok(n) = app.recv(&mut rbuf) {
                if n == 1000 && latest_port.load(Ordering::SeqCst) != port1 {
                    healed = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(80));
        }
        stop_all.store(true, Ordering::SeqCst);

        assert!(spoof_fired.load(Ordering::SeqCst), "spoof race must have been injected");
        assert!(healed, "legitimate client MUST still recover via fresh-txid retry despite spoofed racer!");
        let vbytes = victim_rx_bytes.load(Ordering::SeqCst);
        assert!(
            vbytes < 250,
            "victim_sock MUST NEVER receive reflected backend SRTP (received {}B, expected <250B bounded STUN+Challenge!)",
            vbytes
        );
    }

    /// V4.0 Scenario #3 & #6 (Carbon): High-BDP Trans-Pacific (160ms RTT + 3% loss + 20% reorder)
    /// mid-flight cutover with StrictPinnedUdpBackend + Outer Wire DPI Statistical Audit!
    #[test]
    fn v40_high_bdp_loss_reorder_cutover_and_outer_dpi_wire_audit() {
        let psk = b"v040-high-bdp-dpi-audit-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        let stop_all = Arc::new(AtomicBool::new(false));
        let pinned_port = Arc::new(AtomicU16::new(0));
        let port_violations = Arc::new(AtomicUsize::new(0));
        let b_stop = Arc::clone(&stop_all);
        let b_pinned = Arc::clone(&pinned_port);
        let b_viol = Arc::clone(&port_violations);

        let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        backend_sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut locked: Option<SocketAddr> = None;
            while !b_stop.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = backend_sock.recv_from(&mut buf) {
                    match locked {
                        None => {
                            locked = Some(peer);
                            b_pinned.store(peer.port(), Ordering::SeqCst);
                        }
                        Some(lp) if lp != peer => {
                            b_viol.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    if let Some(lp) = locked {
                        let _ = backend_sock.send_to(&buf[..n], lp);
                    }
                }
            }
        });

        let srv_psk = psk.clone();
        let s_stop = Arc::clone(&stop_all);
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: Some(s_stop),
            });
        });

        // Delay + 3% loss + 20% reorder relay WITH live DPI wire-statistics collector!
        let latest_port = Arc::new(AtomicU16::new(0));
        let max_wire_udp = Arc::new(AtomicUsize::new(0));
        let video_lens = Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));
        let audio_burst_violations = Arc::new(AtomicUsize::new(0));
        let r_latest = Arc::clone(&latest_port);
        let r_maxw = Arc::clone(&max_wire_udp);
        let r_vlens = Arc::clone(&video_lens);
        let r_aviol = Arc::clone(&audio_burst_violations);
        let r_stop = Arc::clone(&stop_all);

        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut queue: VecDeque<(Instant, bool, u16, SocketAddr, Vec<u8>)> = VecDeque::new();
            let mut prng: u64 = 0xDEAD_BEEF_CAFE_0040;
            let mut next_r = || -> u64 {
                prng ^= prng << 13;
                prng ^= prng >> 7;
                prng ^= prng << 17;
                prng
            };
            let mut last_audio_ts_c2s: Option<(u32, Instant)> = None;
            let mut buf = [0u8; 4096];
            while !r_stop.load(Ordering::Relaxed) {
                let now = Instant::now();
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    r_latest.store(cport, Ordering::SeqCst);
                    r_maxw.fetch_max(n, Ordering::SeqCst);
                    let pkt = &buf[..n];
                    if demux_rfc7983(pkt) == PacketKind::Srtp && n >= 12 {
                        let pt = pkt[1] & 0x7F;
                        if pt == crate::protocol::RTP_VIDEO_PT {
                            r_vlens.lock().unwrap().push(n);
                        } else if pt == crate::protocol::RTP_AUDIO_PT {
                            let ts = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
                            if let Some((prev_ts, prev_t)) = last_audio_ts_c2s {
                                if prev_ts == ts && now.duration_since(prev_t) < Duration::from_millis(18) {
                                    r_aviol.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                            last_audio_ts_c2s = Some((ts, now));
                        }
                    }
                    upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    // 3% random loss on SRTP data only (keep test deterministic), 80ms one-way + 20% reorder
                    if demux_rfc7983(pkt) == PacketKind::Srtp && (next_r() % 100) < 3 {
                        continue;
                    }
                    let mut delay = 40u64; // 80ms RTT
                    if (next_r() % 100) < 20 {
                        delay += 15 + (next_r() % 20);
                    }
                    queue.push_back((now + Duration::from_millis(delay), true, cport, cli_addr, pkt.to_vec()));
                }
                for (&cport, (usock, cli_addr)) in upstreams.iter() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        r_maxw.fetch_max(n, Ordering::SeqCst);
                        let pkt = &buf[..n];
                        let mut delay = 40u64;
                        if (next_r() % 100) < 20 {
                            delay += 15 + (next_r() % 20);
                        }
                        queue.push_back((now + Duration::from_millis(delay), false, cport, *cli_addr, pkt.to_vec()));
                    }
                }
                let mut i = 0;
                while i < queue.len() {
                    if queue[i].0 <= now {
                        let (_, c2s, cp, ca, data) = queue.remove(i).unwrap();
                        if c2s {
                            if let Some((us, _)) = upstreams.get(&cp) {
                                let _ = us.send(&data);
                            }
                        } else {
                            let _ = relay_front.send_to(&data, ca);
                        }
                    } else {
                        i += 1;
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        let c_stop = Arc::clone(&stop_all);
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 50 * 1024, // mid-flight byte-budget MBB handover during burst!
                rotate_cooldown_secs: 1,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                retry_ms: 250,
                max_retries: 8,
                keepalive_secs: 5,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                quiet: true,
                stop: Some(c_stop),
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();
        let mut rbuf = [0u8; 2048];
        let mut ready = false;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"BDP_INIT");
            if let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"BDP_INIT" {
                    ready = true;
                    break;
                }
            }
        }
        assert!(ready);
        let port1 = latest_port.load(Ordering::SeqCst);

        // Stream 120 x 1200B packets (~144KB each way) across the 1s cooldown + byte-budget MBB cutover!
        app.set_nonblocking(true).unwrap();
        let mut rx_seqs = std::collections::HashSet::<u32>::new();
        let mut payload = vec![0x55u8; 1200];
        for seq in 0..120u32 {
            payload[..4].copy_from_slice(&seq.to_be_bytes());
            let _ = app.send(&payload);
            while let Ok(n) = app.recv(&mut rbuf) {
                if n == 1200 {
                    rx_seqs.insert(u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]));
                }
            }
            thread::sleep(Duration::from_millis(18));
        }
        let t_drain = Instant::now();
        while t_drain.elapsed() < Duration::from_millis(400) {
            while let Ok(n) = app.recv(&mut rbuf) {
                if n == 1200 {
                    rx_seqs.insert(u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]));
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        stop_all.store(true, Ordering::SeqCst);

        let port2 = latest_port.load(Ordering::SeqCst);
        assert_ne!(port2, port1, "byte-budget MBB cutover must fire during high-BDP burst!");
        assert_eq!(
            port_violations.load(Ordering::SeqCst),
            0,
            "StrictPinnedUdpBackend MUST see ZERO port changes even under 80ms RTT + 3% loss + 20% reorder!"
        );
        assert!(
            rx_seqs.len() >= 100,
            "delivery under 3% loss + 20% reorder + mid-flight handover must stay >=83% (got {}/120)",
            rx_seqs.len()
        );
        // Outer Wire DPI Audit (Carbon Scenario #6):
        assert!(max_wire_udp.load(Ordering::SeqCst) <= 1460, "outer wire UDP MUST never exceed 1460B!");
        assert_eq!(
            audio_burst_violations.load(Ordering::SeqCst),
            0,
            "PT=111 Opus MUST NEVER exceed 1 packet per 20ms frame!"
        );
        let vlens = video_lens.lock().unwrap();
        assert!(vlens.len() >= 50);
        let mean = vlens.iter().map(|&x| x as f64).sum::<f64>() / (vlens.len() as f64);
        let var = vlens.iter().map(|&x| { let d = x as f64 - mean; d * d }).sum::<f64>() / (vlens.len() as f64);
        let stddev = var.sqrt();
        assert!(
            stddev > 4.0,
            "PT=96 video outer packet-length stddev MUST exceed 4.0B for padding entropy (got {:.2}B)!",
            stddev
        );
    }

    /// V4.0 Linux Multi-Worker (`--workers 4` SO_REUSEPORT) cross-thread ownership transfer test:
    /// Exercises real kernel 4-tuple hashing across 4 workers during BOTH scheduled DTLS 1.3 MBB
    /// `0xFFFC` handover AND 1-RTT ICE blackhole migration, asserting ZERO `backend_lport` changes!
    #[cfg(target_os = "linux")]
    #[test]
    fn v40_linux_multiworker_reuseport_cross_thread_migration_and_handover() {
        let psk = b"v040-linux-4worker-reuseport-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        let stop_all = Arc::new(AtomicBool::new(false));
        let port_violations = Arc::new(AtomicUsize::new(0));
        let b_stop = Arc::clone(&stop_all);
        let b_viol = Arc::clone(&port_violations);

        let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        backend_sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut locked: Option<SocketAddr> = None;
            while !b_stop.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = backend_sock.recv_from(&mut buf) {
                    match locked {
                        None => locked = Some(peer),
                        Some(lp) if lp != peer => {
                            b_viol.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    if let Some(lp) = locked {
                        let _ = backend_sock.send_to(&buf[..n], lp);
                    }
                }
            }
        });

        let srv_psk = psk.clone();
        let s_stop = Arc::clone(&stop_all);
        thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk: srv_psk,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 4, // Real Linux SO_REUSEPORT 4-worker hash distribution!
                max_sessions: 64,
                wan_mtu: 1488,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                quiet: true,
                stop: Some(s_stop),
            });
        });

        let latest_port = Arc::new(AtomicU16::new(0));
        let blackhole_port = Arc::new(AtomicU16::new(0));
        let r_latest = Arc::clone(&latest_port);
        let r_bh = Arc::clone(&blackhole_port);
        let r_stop = Arc::clone(&stop_all);
        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut buf = [0u8; 4096];
            while !r_stop.load(Ordering::Relaxed) {
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    r_latest.store(cport, Ordering::SeqCst);
                    let bh = r_bh.load(Ordering::SeqCst);
                    if bh != 0 && cport == bh {
                        continue;
                    }
                    let entry = upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    let _ = entry.0.send(&buf[..n]);
                }
                for (usock, cli_addr) in upstreams.values() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let _ = relay_front.send_to(&buf[..n], *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        let c_stop = Arc::clone(&stop_all);
        thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                psk: cli_psk,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 14 * 1024,
                rotate_cooldown_secs: 1,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 1,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                quiet: true,
                stop: Some(c_stop),
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();
        let mut rbuf = [0u8; 2048];
        let mut ready = false;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"MW_INIT");
            match app.recv(&mut rbuf) {
                Ok(n) if &rbuf[..n] == b"MW_INIT" => {
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                _ => thread::sleep(Duration::from_millis(40)),
            }
        }
        assert!(ready);
        let p1 = latest_port.load(Ordering::SeqCst);

        // Trigger MBB handover across 4 workers
        let mut p2 = 0u16;
        let t_mbb = Instant::now();
        while t_mbb.elapsed() < Duration::from_secs(5) {
            let bulk = vec![0x7Au8; 900];
            let _ = app.send(&bulk);
            let _ = app.recv(&mut rbuf);
            let cur = latest_port.load(Ordering::SeqCst);
            if cur != p1 {
                p2 = cur;
                break;
            }
            thread::sleep(Duration::from_millis(30));
        }
        assert_ne!(p2, 0);

        // Trigger 1-RTT blackhole migration across 4 workers
        blackhole_port.store(p2, Ordering::SeqCst);
        let mut healed = false;
        let t_bh = Instant::now();
        while t_bh.elapsed() < Duration::from_secs(9) {
            let _ = app.send(b"MW_POST_BH");
            if let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"MW_POST_BH" && latest_port.load(Ordering::SeqCst) != p2 {
                    healed = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(60));
        }
        stop_all.store(true, Ordering::SeqCst);
        assert!(healed, "4-worker SO_REUSEPORT 1-RTT blackhole migration MUST heal!");
        assert_eq!(
            port_violations.load(Ordering::SeqCst),
            0,
            "4-worker SO_REUSEPORT migration + handover MUST keep backend_lport 100% unchanged!"
        );
    }

    /// Carbon Audit P0-1 + P0-2 + P0-5 Regression Test:
    ///   - Part A (P0-1 + P0-2): Drop the server's VERY FIRST `0xFFFD(0x01)` PathChallenge during
    ///     1-RTT migration AND replay a reordered earlier migration STUN; client MUST recover cleanly
    ///     on the migrated port with 0 backend port changes (proving no `token_by_peer` self-lockout
    ///     and idempotent nonce reuse across the 4-slot candidate table).
    ///   - Part B (P0-5): When a legacy `v0.3.8` server ignores `mi_key_mig`-signed migration STUN,
    ///     `Migrating` timeout fallback (`to_rotate`) MUST preserve `old_sess.pending` app packets
    ///     into the replacement DTLS session without silently dropping them!
    #[test]
    fn v40_p0_dropped_challenge_reordered_stun_and_legacy_pending_fallback() {
        // ---- Part A: P0-1 (dropped 1st 0xFFFD challenge) + P0-2 (reordered dup migration STUN) ----
        {
            let psk = b"v040-carbon-p01-p02-regression-psk".to_vec();
            let backend_port = reserve_free_port();
            let server_port = reserve_free_port();
            let relay_port = reserve_free_port();
            let client_port = reserve_free_port();

            let stop_all = Arc::new(AtomicBool::new(false));
            let port_violations = Arc::new(AtomicUsize::new(0));
            let b_stop = Arc::clone(&stop_all);
            let b_viol = Arc::clone(&port_violations);

            let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
            backend_sock
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut locked: Option<SocketAddr> = None;
                while !b_stop.load(Ordering::Relaxed) {
                    if let Ok((n, peer)) = backend_sock.recv_from(&mut buf) {
                        match locked {
                            None => locked = Some(peer),
                            Some(lp) if lp != peer => {
                                b_viol.fetch_add(1, Ordering::SeqCst);
                            }
                            _ => {}
                        }
                        if let Some(lp) = locked {
                            let _ = backend_sock.send_to(&buf[..n], lp);
                        }
                    }
                }
            });

            let srv_psk = psk.clone();
            let s_stop = Arc::clone(&stop_all);
            thread::spawn(move || {
                let _ = run_server(ServerConfig {
                    listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                    backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                    psk: srv_psk,
                    cipher_pref: CipherPref::Auto,
                    dtls_required: true,
                    dtls_min_version: DtlsMinVersion::V13Only,
                    workers: 1,
                    max_sessions: 32,
                    wan_mtu: 1488,
                    idle_timeout_secs: 60,
                    stats_interval_secs: 3600,
                    wire_audit_file: None,
                    quiet: true,
                    stop: Some(s_stop),
                });
            });

            let blackhole_port = Arc::new(AtomicU16::new(0));
            let latest_port = Arc::new(AtomicU16::new(0));
            let dropped_first_challenge = Arc::new(AtomicBool::new(false));
            let replayed_reordered_stun = Arc::new(AtomicBool::new(false));
            let r_bh = Arc::clone(&blackhole_port);
            let r_latest = Arc::clone(&latest_port);
            let r_drop_ch = Arc::clone(&dropped_first_challenge);
            let r_replay = Arc::clone(&replayed_reordered_stun);
            let r_stop = Arc::clone(&stop_all);

            let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
            relay_front.set_nonblocking(true).unwrap();
            thread::spawn(move || {
                let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
                let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
                let mut saved_mig_stun: Option<(u16, Vec<u8>)> = None;
                let mut mig_stun_count: usize = 0;
                let mut buf = [0u8; 4096];
                while !r_stop.load(Ordering::Relaxed) {
                    while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                        let cport = cli_addr.port();
                        r_latest.store(cport, Ordering::SeqCst);
                        let pkt = &buf[..n];
                        let bh = r_bh.load(Ordering::SeqCst);
                        if bh != 0 && cport == bh {
                            continue; // 100% uplink blackhole on old port
                        }
                        let entry = upstreams.entry(cport).or_insert_with(|| {
                            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                            s.set_nonblocking(true).unwrap();
                            s.connect(srv_addr).unwrap();
                            (s, cli_addr)
                        });
                        if bh != 0 && cport != bh && demux_rfc7983(pkt) == PacketKind::Stun {
                            mig_stun_count += 1;
                            if mig_stun_count == 1 {
                                saved_mig_stun = Some((cport, pkt.to_vec()));
                            }
                            let _ = entry.0.send(pkt);
                            // On the 2nd migration STUN, immediately inject a reordered copy of the 1st STUN
                            // to verify P0-2 idempotent nonce reuse!
                            if mig_stun_count == 2 {
                                if let Some((sp, ref first_pkt)) = saved_mig_stun {
                                    if sp == cport {
                                        let _ = entry.0.send(first_pkt);
                                        r_replay.store(true, Ordering::SeqCst);
                                    }
                                }
                            }
                        } else {
                            let _ = entry.0.send(pkt);
                        }
                    }
                    let bh = r_bh.load(Ordering::SeqCst);
                    for (&cport, (usock, cli_addr)) in upstreams.iter() {
                        while let Ok(n) = usock.recv(&mut buf) {
                            let pkt = &buf[..n];
                            // P0-1 fault injection: drop the VERY FIRST 0xFFFD SRTP challenge
                            // sent to the migrated port (57B unpadded SRTP)!
                            if bh != 0
                                && cport != bh
                                && demux_rfc7983(pkt) == PacketKind::Srtp
                                && !r_drop_ch.swap(true, Ordering::SeqCst)
                            {
                                continue;
                            }
                            let _ = relay_front.send_to(pkt, *cli_addr);
                        }
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            });

            let cli_psk = psk.clone();
            let c_stop = Arc::clone(&stop_all);
            thread::spawn(move || {
                let _ = run_client(ClientConfig {
                    listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                    server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                    psk: cli_psk,
                    cipher_pref: CipherPref::Auto,
                    dtls_decoy: true,
                    dtls_min_version: DtlsMinVersion::V13Only,
                    rotate_interval_secs: 0,
                    rotate_max_bytes: 0,
                    rotate_cooldown_secs: 60,
                    workers: 1,
                    max_sessions: 32,
                    wan_mtu: 1488,
                    retry_ms: 150,
                    max_retries: 8,
                    keepalive_secs: 1,
                    idle_timeout_secs: 60,
                    stats_interval_secs: 3600,
                    quiet: true,
                    stop: Some(c_stop),
                });
            });

            let app = UdpSocket::bind("127.0.0.1:0").unwrap();
            app.set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            app.connect(("127.0.0.1", client_port)).unwrap();
            let mut rbuf = [0u8; 512];
            let mut ready = false;
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(5) {
                let _ = app.send(b"P01_INIT");
                match app.recv(&mut rbuf) {
                    Ok(n) if &rbuf[..n] == b"P01_INIT" => {
                        ready = true;
                        break;
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                    _ => thread::sleep(Duration::from_millis(30)),
                }
            }
            assert!(ready, "initial tunnel must come up");
            let port1 = latest_port.load(Ordering::SeqCst);

            blackhole_port.store(port1, Ordering::SeqCst);
            let mut recovered = false;
            let t_bh = Instant::now();
            while t_bh.elapsed() < Duration::from_secs(9) {
                let _ = app.send(b"P01_HEALED");
                if let Ok(n) = app.recv(&mut rbuf) {
                    if &rbuf[..n] == b"P01_HEALED" && latest_port.load(Ordering::SeqCst) != port1 {
                        recovered = true;
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(60));
            }
            stop_all.store(true, Ordering::SeqCst);

            assert!(
                dropped_first_challenge.load(Ordering::SeqCst),
                "fault injector must have dropped the 1st 0xFFFD challenge"
            );
            assert!(
                replayed_reordered_stun.load(Ordering::SeqCst),
                "fault injector must have replayed reordered 1st migration STUN"
            );
            assert!(
                recovered,
                "P0-1/P0-2: client MUST recover after dropped 1st 0xFFFD challenge + reordered STUN!"
            );
            assert_eq!(
                port_violations.load(Ordering::SeqCst),
                0,
                "P0-1/P0-2: StrictPinnedUdpBackend MUST keep exact same backend_lport!"
            );
        }

        // ---- Part B: P0-5 (`Migrating` fallback to legacy server preserves `old_sess.pending`) ----
        {
            let psk = b"v040-carbon-p05-pending-fallback-psk".to_vec();
            let backend_port = reserve_free_port();
            let server_port = reserve_free_port();
            let relay_port = reserve_free_port();
            let client_port = reserve_free_port();

            let stop_all = Arc::new(AtomicBool::new(false));
            let b_stop = Arc::clone(&stop_all);
            let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
            echo_sock
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !b_stop.load(Ordering::Relaxed) {
                    if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                        let _ = echo_sock.send_to(&buf[..n], peer);
                    }
                }
            });

            let srv_psk = psk.clone();
            let s_stop = Arc::clone(&stop_all);
            thread::spawn(move || {
                let _ = run_server(ServerConfig {
                    listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
                    backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                    psk: srv_psk,
                    cipher_pref: CipherPref::Auto,
                    dtls_required: true,
                    dtls_min_version: DtlsMinVersion::V13Only,
                    workers: 1,
                    max_sessions: 32,
                    wan_mtu: 1488,
                    idle_timeout_secs: 60,
                    stats_interval_secs: 3600,
                    wire_audit_file: None,
                    quiet: true,
                    stop: Some(s_stop),
                });
            });

            let blackhole_port = Arc::new(AtomicU16::new(0));
            let mig_port_seen = Arc::new(AtomicU16::new(0));
            let latest_port = Arc::new(AtomicU16::new(0));
            let r_bh = Arc::clone(&blackhole_port);
            let r_mig = Arc::clone(&mig_port_seen);
            let r_latest = Arc::clone(&latest_port);
            let r_stop = Arc::clone(&stop_all);
            let relay_psk = psk.clone();

            let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
            relay_front.set_nonblocking(true).unwrap();
            thread::spawn(move || {
                let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
                let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
                let mut buf = [0u8; 4096];
                while !r_stop.load(Ordering::Relaxed) {
                    while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                        let cport = cli_addr.port();
                        r_latest.store(cport, Ordering::SeqCst);
                        let pkt = &buf[..n];
                        let bh = r_bh.load(Ordering::SeqCst);
                        if bh != 0 && cport == bh {
                            continue;
                        }
                        // Emulate a v0.3.8 legacy server: drop migration STUNs that are NOT signed with global PSK!
                        // (Fresh fallback DTLS STUN IS signed with global PSK and passes cleanly!)
                        if bh != 0 && cport != bh && demux_rfc7983(pkt) == PacketKind::Stun {
                            let is_global_psk = parse_stun(pkt, &relay_psk)
                                .map(|p| p.authenticated)
                                .unwrap_or(false);
                            if !is_global_psk {
                                let _ = r_mig.compare_exchange(
                                    0,
                                    cport,
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                );
                                continue;
                            }
                        }
                        let entry = upstreams.entry(cport).or_insert_with(|| {
                            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                            s.set_nonblocking(true).unwrap();
                            s.connect(srv_addr).unwrap();
                            (s, cli_addr)
                        });
                        let _ = entry.0.send(pkt);
                    }
                    for (usock, cli_addr) in upstreams.values() {
                        while let Ok(n) = usock.recv(&mut buf) {
                            let _ = relay_front.send_to(&buf[..n], *cli_addr);
                        }
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            });

            let cli_psk = psk.clone();
            let c_stop = Arc::clone(&stop_all);
            thread::spawn(move || {
                let _ = run_client(ClientConfig {
                    listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
                    server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
                    psk: cli_psk,
                    cipher_pref: CipherPref::Auto,
                    dtls_decoy: true,
                    dtls_min_version: DtlsMinVersion::V13Only,
                    rotate_interval_secs: 0,
                    rotate_max_bytes: 0,
                    rotate_cooldown_secs: 60,
                    workers: 1,
                    max_sessions: 32,
                    wan_mtu: 1488,
                    retry_ms: 120,
                    max_retries: 8,
                    keepalive_secs: 1,
                    idle_timeout_secs: 60,
                    stats_interval_secs: 3600,
                    quiet: true,
                    stop: Some(c_stop),
                });
            });

            let app = UdpSocket::bind("127.0.0.1:0").unwrap();
            app.set_read_timeout(Some(Duration::from_millis(120)))
                .unwrap();
            app.connect(("127.0.0.1", client_port)).unwrap();
            let mut rbuf = [0u8; 512];
            let mut ready = false;
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(5) {
                let _ = app.send(b"P05_INIT");
                match app.recv(&mut rbuf) {
                    Ok(n) if &rbuf[..n] == b"P05_INIT" => {
                        ready = true;
                        break;
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                    _ => thread::sleep(Duration::from_millis(30)),
                }
            }
            assert!(ready, "initial tunnel must come up");
            let port1 = latest_port.load(Ordering::SeqCst);

            // Blackhole port1 and wait until client enters `Migrating` (observed via first per-session STUN)
            blackhole_port.store(port1, Ordering::SeqCst);
            let t_wait_mig = Instant::now();
            while mig_port_seen.load(Ordering::SeqCst) == 0
                && t_wait_mig.elapsed() < Duration::from_secs(8)
            {
                thread::sleep(Duration::from_millis(20));
            }
            assert_ne!(
                mig_port_seen.load(Ordering::SeqCst),
                0,
                "client must attempt V4 1-RTT migration first"
            );

            // Send a SINGLE app packet while client is in `Migrating`; it MUST be buffered in
            // `old_sess.pending`, carried across `to_rotate` fallback into the fresh DTLS session,
            // and echoed back WITHOUT the app ever re-sending it!
            let _ = app.send(b"PRESERVE_ME_P05");
            let mut got_preserved = false;
            let t_fb = Instant::now();
            while t_fb.elapsed() < Duration::from_secs(6) {
                if let Ok(n) = app.recv(&mut rbuf) {
                    if &rbuf[..n] == b"PRESERVE_ME_P05" {
                        got_preserved = true;
                        break;
                    }
                }
            }
            stop_all.store(true, Ordering::SeqCst);
            assert!(
                got_preserved,
                "P0-5: app packet buffered during Migrating MUST survive fallback to fresh DTLS session!"
            );
        }
    }
}
