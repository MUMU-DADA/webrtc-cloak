//! mio-based zero-allocation webrtc-cloak V3.1 client (Production Freeze):
//!   - RFC 8445 / 7675 STUN ICE (4:4 Base64 ufrag, session-constant tie-breaker & priority,
//!     5s±20% Consent Freshness keepalive, strict MI-then-FP parsing)
//!   - Real RFC 6347 DTLS 1.2 via `dimpl` (3-suite Chrome ClientHello, mutual rotating P-256 certs,
//!     strict record pre-validation + Ready gating + flight-5-bound ServerHello suite extraction)
//!   - RFC 3550/7714/8285 SRTP (0x90 header, 0xBEDE ext, encrypted inner length+padding, pure 90kHz clock)
//!   - RFC 3550 §6.1 / 7714 §9.1 Compound SRTCP + Closing(250ms) drain (zero ICMP bounce)

use crate::protocol::{
    build_dimpl_config, build_ice_stun_request, combine_session_key, demux_rfc7983,
    derive_stun_material, detect_cpu_accel, extract_dtls_server_hello_suite, jitter_duration_ms,
    make_fresh_stun_txid, parse_stun, rand_duration_range_ms, resolve_srtp_suite,
    validate_dtls_datagram, CertCache, CipherPref, CipherSuite, PacketKind, SessionIceParams,
    SrtpCloakCipher, MAX_INNER_UDP_LEN, STUN_BINDING_SUCCESS,
};
use dimpl::{Config as DtlsConfig, Dtls, Output as DtlsOutput};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

const LISTEN_TOKEN: Token = Token(0);
const CLOSING_DRAIN_MS: u64 = 250;
/// Silent receive-only drain window after RFC 7675 consent loss (exceeds server's 30s consent
/// expiry so trailing downlink SRTCP never triggers ICMP Port Unreachable and CGNAT never reuses
/// the blackholed external port for the newly rotated 5-tuple).
const BLACKHOLE_DRAIN_SECS: u64 = 35;
const MAX_DRAINING_SESSIONS: usize = 16;
const ACTIVE_ROTATE_WINDOW_SECS: u64 = 30;
/// RFC 5389 §7.2.1 STUN consent retries (1 initial + 2 same-txid retransmits = 3 attempts, ~4.7s).
const KA_MAX_RETRIES: u8 = 2;

#[derive(Clone)]
pub struct ClientConfig {
    pub listen_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub psk: Vec<u8>,
    pub cipher_pref: CipherPref,
    pub dtls_decoy: bool,
    pub workers: usize,
    pub max_sessions: usize,
    pub wan_mtu: usize,
    pub retry_ms: u64,
    pub max_retries: u32,
    pub keepalive_secs: u64,
    pub idle_timeout_secs: u64,
    pub stats_interval_secs: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    StunWait,
    DtlsHandshake,
    Ready,
    Closing(Instant),
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
    next_retry_at: Instant,
    next_keepalive_at: Instant,
    next_srtcp_at: Instant,
    dtls_next_timeout: Option<Instant>,
    retries: u32,
    /// In-flight RFC 7675 STUN consent check transaction (RFC 5389 §7.2.1 same-txid retransmission).
    ka_txid: Option<[u8; 12]>,
    ka_pkt: Vec<u8>,
    ka_retries: u8,
    ka_rto_at: Option<Instant>,
    stun_key: Option<[u8; 32]>,
    ssrc_c2s: u32,
    ssrc_s2c: u32,
    dtls: Option<Dtls>,
    pending_sh_suite: Option<u16>,
    dtls_suite_id: Option<u16>,
    dtls_km: Option<Vec<u8>>,
    active_cipher: Option<CipherSuite>,
    cipher: Option<SrtpCloakCipher>,
    pending: VecDeque<Vec<u8>>,
    tx_pkts: u64,
    tx_pkts_at_last_rtcp: u64,
    tx_bytes: u64,
    rx_pkts: u64,
    rx_bytes: u64,
    keepalives_ok: u64,
    srtcp_tx: u64,
    srtcp_rx: u64,
    auth_drops: u64,
}

fn make_udp_socket(
    bind_addr: SocketAddr,
    connect_to: Option<SocketAddr>,
    reuse_port: bool,
) -> std::io::Result<MioUdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = sock.set_reuse_address(true);
    #[cfg(unix)]
    if reuse_port {
        sock.set_reuse_port(true)?;
    }
    #[cfg(not(unix))]
    let _ = reuse_port;
    let _ = sock.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(8 * 1024 * 1024);
    sock.set_nonblocking(true)?;
    sock.bind(&bind_addr.into())?;
    if let Some(target) = connect_to {
        sock.connect(&target.into())?;
    }
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(MioUdpSocket::from_std(std_sock))
}

fn log(worker_id: usize, msg: &str) {
    println!("[client-rs#{}] {}", worker_id, msg);
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
    if sess.dtls_suite_id.is_none() {
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
            let chosen = resolve_srtp_suite(cfg.cipher_pref, sess.dtls_suite_id, cpu, false);
            let final_key = combine_session_key(&stun_key, sess.dtls_km.as_deref());
            sess.active_cipher = Some(chosen);
            let mut c = SrtpCloakCipher::new(
                &final_key,
                sess.ssrc_c2s,
                sess.ssrc_s2c,
                true,
                chosen,
            );
            c.set_wan_mtu(cfg.wan_mtu);
            sess.cipher = Some(c);
            sess.state = HandshakeState::Ready;
            sess.ready_at = Some(now);
            sess.last_data_active = now;
            sess.ka_txid = None;
            sess.ka_pkt.clear();
            sess.ka_retries = 0;
            sess.ka_rto_at = None;
            sess.next_keepalive_at = now + jitter_duration_ms(cfg.keepalive_secs * 1000);
            sess.next_srtcp_at = now + rand_duration_range_ms(250, 600);

            let mut flushed = 0usize;
            if let Some(ref mut cipher) = sess.cipher {
                while let Some(raw) = sess.pending.pop_front() {
                    if let Some(wn) = cipher.wrap_into(&raw, wbuf) {
                        if sess.upstream.send(&wbuf[..wn]).is_ok() {
                            sess.tx_pkts += 1;
                            sess.tx_bytes += raw.len() as u64;
                            flushed += 1;
                        }
                    }
                }
            }
            let total_ms = sess.created_at.elapsed().as_secs_f64() * 1000.0;
            log(
                worker_id,
                &format!(
                    "DTLS 1.2 (dimpl mutual-cert PFS) OK -> READY up_sport={} cipher={} total_hs={:.2}ms flushed={}",
                    sess.local_port,
                    chosen.name(),
                    total_ms,
                    flushed
                ),
            );
        }
    }

    peer_closed
}

fn graceful_teardown_client(sess: &mut ClientSession, dtls_buf: &mut Vec<u8>) {
    if sess.state == HandshakeState::Ready {
        let has_rx = sess.rx_pkts > 0;
        let is_sender = sess.tx_pkts > 0;
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
    let dtls_cfg = build_dimpl_config(cfg.cipher_pref, &cpu, true);
    println!(
        "[client-rs] V3.1 CPU arch={} hw_accel=[{}] recommended={} workers={} dtls=dimpl-1.2(3-suite,mutual-cert,pfs)",
        cpu.arch,
        cpu.features.join(", "),
        cpu.recommended.name(),
        workers
    );
    #[cfg(not(target_os = "linux"))]
    if workers > 1 {
        eprintln!("[client-rs] WARN: SO_REUSEPORT UDP hash load-balancing is Linux-specific.");
    }

    if workers == 1 {
        return run_client_worker(0, cfg, false, dtls_cfg);
    }

    let mut handles = Vec::with_capacity(workers - 1);
    for wid in 1..workers {
        let c = cfg.clone();
        let dc = Arc::clone(&dtls_cfg);
        handles.push(std::thread::spawn(move || {
            if let Err(e) = run_client_worker(wid, c, true, dc) {
                eprintln!("[client-rs#{}] error: {}", wid, e);
            }
        }));
    }
    let res = run_client_worker(0, cfg, true, dtls_cfg);
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
    next_token_id: &mut usize,
    dtls_buf: &mut Vec<u8>,
    now: Instant,
    retry_dur: Duration,
    ka_base_ms: u64,
    idle_dur: Duration,
) -> Option<Token> {
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
            }
        }
    }

    if sessions_by_token.len() >= cfg.max_sessions {
        let expired: Vec<Token> = sessions_by_token
            .iter()
            .filter(|(_, s)| {
                matches!(s.state, HandshakeState::Closing(_))
                    || now.duration_since(s.last_data_active) > idle_dur
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
    let mut up = match make_udp_socket(bind_any, Some(cfg.server_addr), false) {
        Ok(s) => s,
        Err(e) => {
            log(worker_id, &format!("upstream socket error: {}", e));
            return None;
        }
    };
    let local_port = up.local_addr().map(|a| a.port()).unwrap_or(0);
    let tok = Token(*next_token_id);
    *next_token_id += 1;
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
            "new session client={} -> up_sport={} target={} ufrag={}",
            client_addr, local_port, cfg.server_addr, ice.username()
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
        next_retry_at: now + retry_dur,
        next_keepalive_at: now + jitter_duration_ms(ka_base_ms),
        next_srtcp_at: now + rand_duration_range_ms(250, 600),
        dtls_next_timeout: None,
        retries: 0,
        ka_txid: None,
        ka_pkt: Vec::new(),
        ka_retries: 0,
        ka_rto_at: None,
        stun_key: None,
        ssrc_c2s: 0,
        ssrc_s2c: 0,
        dtls: None,
        pending_sh_suite: None,
        dtls_suite_id: None,
        dtls_km: None,
        active_cipher: None,
        cipher: None,
        pending: VecDeque::with_capacity(64),
        tx_pkts: 0,
        tx_pkts_at_last_rtcp: 0,
        tx_bytes: 0,
        rx_pkts: 0,
        rx_bytes: 0,
        keepalives_ok: 0,
        srtcp_tx: 0,
        srtcp_rx: 0,
        auth_drops: 0,
    };
    token_by_client.insert(client_addr, tok);
    sessions_by_token.insert(tok, sess);
    Some(tok)
}

fn run_client_worker(
    worker_id: usize,
    cfg: ClientConfig,
    reuse_port: bool,
    dtls_cfg: Arc<DtlsConfig>,
) -> std::io::Result<()> {
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(256);

    let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port)?;
    poll.registry()
        .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;

    let mut sessions_by_token: HashMap<Token, ClientSession> = HashMap::new();
    let mut token_by_client: HashMap<SocketAddr, Token> = HashMap::new();
    let mut next_token_id: usize = 1;
    let mut cert_cache = CertCache::new();

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
        let now = Instant::now();
        let mut wait = Duration::from_millis(150);
        let mut to_close: Vec<(Token, &'static str)> = Vec::new();
        let mut to_rotate: Vec<(Token, SocketAddr, bool)> = Vec::new();

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
                HandshakeState::Ready => {
                    if now.duration_since(sess.last_data_active) > idle_dur {
                        graceful_teardown_client(sess, &mut dtls_buf);
                        sess.state = HandshakeState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
                        continue;
                    }
                    // RFC 7675 §5.1 + RFC 5389 §7.2.1 bidirectional STUN consent check:
                    // ONLY an authenticated STUN Binding Success Response proves uplink connectivity
                    // (unsolicited server SRTCP or QUIC PTO SRTP MUST NOT mask an asymmetric uplink blackhole!).
                    if cfg.keepalive_secs > 0 {
                        if sess.ka_txid.is_some() {
                            if let Some(rto_at) = sess.ka_rto_at {
                                if now >= rto_at {
                                    if sess.ka_retries < KA_MAX_RETRIES {
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
                                        log(
                                            worker_id,
                                            &format!(
                                                "RFC 7675 consent lost ({}/{} STUN unanswered) client={} up_sport={} -> draining {}s{}",
                                                KA_MAX_RETRIES + 1,
                                                KA_MAX_RETRIES + 1,
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
                                }
                            }
                        } else if now >= sess.next_keepalive_at {
                            let (pkt, txid) = build_ice_stun_request(&cfg.psk, &sess.ice, None, false);
                            let _ = sess.upstream.send(&pkt);
                            sess.ka_txid = Some(txid);
                            sess.ka_pkt = pkt;
                            sess.ka_retries = 0;
                            sess.ka_rto_at = Some(now + rand_duration_range_ms(950, 1250));
                        }
                    }
                    if now >= sess.next_srtcp_at {
                        let is_active_media = now.duration_since(sess.last_data_active) <= Duration::from_secs(3);
                        let sent_media = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
                        let has_rx = sess.rx_pkts > 0;
                        sess.tx_pkts_at_last_rtcp = sess.tx_pkts;
                        if let Some(ref mut cipher) = sess.cipher {
                            let pkt = cipher.build_srtcp(has_rx, sent_media, false);
                            if sess.upstream.send(&pkt).is_ok() {
                                sess.srtcp_tx += 1;
                            }
                        }
                        sess.next_srtcp_at = now + if is_active_media {
                            rand_duration_range_ms(900, 1900)
                        } else {
                            rand_duration_range_ms(3500, 6500)
                        };
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

        for (old_tok, client_addr, active_recently) in to_rotate {
            if token_by_client.get(&client_addr) == Some(&old_tok) {
                token_by_client.remove(&client_addr);
            }
            if active_recently {
                let _ = spawn_client_session(
                    worker_id,
                    client_addr,
                    &cfg,
                    &mut poll,
                    &mut sessions_by_token,
                    &mut token_by_client,
                    &mut next_token_id,
                    &mut dtls_buf,
                    now,
                    retry_dur,
                    ka_base_ms,
                    idle_dur,
                );
            }
        }

        for (tok, reason) in to_close {
            if let Some(mut sess) = sessions_by_token.remove(&tok) {
                let _ = poll.registry().deregister(&mut sess.upstream);
                if token_by_client.get(&sess.client_addr) == Some(&tok) {
                    token_by_client.remove(&sess.client_addr);
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

        if let Err(e) = poll.poll(&mut events, Some(wait)) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }

        let now = Instant::now();
        for ev in events.iter() {
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

                    // If existing session is in Closing drain, detach it from token_by_client while
                    // letting its socket finish silent receive-only drain (zero ICMP Port Unreachable).
                    if let Some(&existing_tok) = token_by_client.get(&client_addr) {
                        if matches!(
                            sessions_by_token.get(&existing_tok).map(|s| s.state),
                            Some(HandshakeState::Closing(_))
                        ) {
                            token_by_client.remove(&client_addr);
                        }
                    }

                    let tok = if let Some(&existing) = token_by_client.get(&client_addr) {
                        existing
                    } else {
                        match spawn_client_session(
                            worker_id,
                            client_addr,
                            &cfg,
                            &mut poll,
                            &mut sessions_by_token,
                            &mut token_by_client,
                            &mut next_token_id,
                            &mut dtls_buf,
                            now,
                            retry_dur,
                            ka_base_ms,
                            idle_dur,
                        ) {
                            Some(t) => t,
                            None => continue,
                        }
                    };

                    if let Some(sess) = sessions_by_token.get_mut(&tok) {
                        sess.last_data_active = now;
                        if sess.state != HandshakeState::Ready {
                            if sess.pending.len() < 256 {
                                sess.pending.push_back(rbuf[..n].to_vec());
                            }
                        } else if let Some(ref mut cipher) = sess.cipher {
                            if let Some(wn) = cipher.wrap_into(&rbuf[..n], &mut wbuf) {
                                if sess.upstream.send(&wbuf[..wn]).is_ok() {
                                    sess.tx_pkts += 1;
                                    sess.tx_bytes += n as u64;
                                }
                            }
                        }
                    }
                }
            } else if let Some(sess) = sessions_by_token.get_mut(&ev.token()) {
                loop {
                    let n = match sess.upstream.recv(&mut rbuf) {
                        Ok(n) => n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    };
                    if matches!(sess.state, HandshakeState::Closing(_)) {
                        // Silently absorb trailing close_notify/BYE to avoid ICMP Port Unreachable!
                        continue;
                    }
                    let pkt = &rbuf[..n];

                    match demux_rfc7983(pkt) {
                        PacketKind::Stun => {
                            if let Some(parsed) = parse_stun(pkt, &cfg.psk) {
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
                                            let mut dtls = Dtls::new_12(Arc::clone(&dtls_cfg), cert, now);
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
                                            sess.active_cipher = Some(chosen);
                                            let mut c = SrtpCloakCipher::new(
                                                &final_key, s_c2s, s_s2c, true, chosen,
                                            );
                                            c.set_wan_mtu(cfg.wan_mtu);
                                            sess.cipher = Some(c);
                                            sess.state = HandshakeState::Ready;
                                            sess.ready_at = Some(now);
                                            sess.last_data_active = now;
                                            sess.ka_txid = None;
                                            sess.ka_pkt.clear();
                                            sess.ka_retries = 0;
                                            sess.ka_rto_at = None;
                                            sess.next_keepalive_at = now + jitter_duration_ms(ka_base_ms);
                                            sess.next_srtcp_at = now + rand_duration_range_ms(250, 600);
                                            let mut flushed = 0usize;
                                            if let Some(ref mut cipher) = sess.cipher {
                                                while let Some(raw) = sess.pending.pop_front() {
                                                    if let Some(wn) = cipher.wrap_into(&raw, &mut wbuf) {
                                                        if sess.upstream.send(&wbuf[..wn]).is_ok() {
                                                            sess.tx_pkts += 1;
                                                            sess.tx_bytes += raw.len() as u64;
                                                            flushed += 1;
                                                        }
                                                    }
                                                }
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
                                        sess.next_keepalive_at = now + jitter_duration_ms(ka_base_ms);
                                    }
                                } else {
                                    sess.auth_drops += 1;
                                }
                            } else {
                                sess.auth_drops += 1;
                            }
                        }
                        PacketKind::Dtls => {
                            // V3-H-01 fix: strict DTLS pre-validation + Ready gating + NEVER kill on handle_packet Err!
                            let ready_only_alert = sess.state == HandshakeState::Ready
                                && sess
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
                                let _ = dtls.handle_timeout(now);
                                if dtls.handle_packet(pkt).is_err() {
                                    dtls_err = true;
                                }
                            } else {
                                sess.auth_drops += 1;
                                continue;
                            }
                            if dtls_err {
                                sess.auth_drops += 1;
                                if sess.state == HandshakeState::Ready {
                                    // Keep established SRTP tunnel alive; drop corrupted DTLS handle only
                                    sess.dtls = None;
                                }
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
                                candidate_sh,
                            ) {
                                sess.state = HandshakeState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
                            }
                        }
                        PacketKind::Srtcp => {
                            if sess.state == HandshakeState::Ready {
                                if let Some(ref mut cipher) = sess.cipher {
                                    if let Some(has_bye) = cipher.verify_srtcp(pkt) {
                                        sess.srtcp_rx += 1;
                                        // Note: do NOT refresh uplink consent liveness from unsolicited server
                                        // SRTCP — only STUN Binding Success proves uplink reaches the server.
                                        if has_bye {
                                            // V3-M-05: enter brief Closing drain to absorb trailing close_notify!
                                            sess.state = HandshakeState::Closing(
                                                now + Duration::from_millis(CLOSING_DRAIN_MS),
                                            );
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
                            if sess.state == HandshakeState::Ready {
                                if let Some(ref mut cipher) = sess.cipher {
                                    if let Some(pn) = cipher.unwrap_into(pkt, &mut wbuf) {
                                        sess.last_data_active = now;
                                        if listen_sock.send_to(&wbuf[..pn], sess.client_addr).is_ok() {
                                            sess.rx_pkts += 1;
                                            sess.rx_bytes += pn as u64;
                                        }
                                    } else {
                                        sess.auth_drops += 1;
                                    }
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

        if now.duration_since(last_stats) >= stats_dur {
            last_stats = now;
            for sess in sessions_by_token.values() {
                if matches!(sess.state, HandshakeState::Closing(_)) {
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
                workers: 1,
                max_sessions: 64,
                wan_mtu: 1488,
                idle_timeout_secs: 120,
                stats_interval_secs: 3600,
                wire_audit_file: None,
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
                workers: 1,
                max_sessions: 64,
                wan_mtu: 1488,
                retry_ms: 200,
                max_retries: 8,
                keepalive_secs: 1,
                idle_timeout_secs: 120,
                stats_interval_secs: 3600,
            });
        });

        thread::sleep(Duration::from_millis(120));

        // 5. Local app socket (simulating mihomo Hysteria2 client staying on ONE fixed local port)
        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();

        let mut rbuf = [0u8; 256];
        let mut ready = false;
        for _ in 0..20 {
            let _ = app.send(b"PING_INIT");
            if let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"PING_INIT" {
                    ready = true;
                    break;
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
}
