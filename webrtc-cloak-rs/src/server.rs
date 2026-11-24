//! mio-based zero-allocation webrtc-cloak V3.2 server (Hardened):
//!   - Pure Silent-Drop on all unauthenticated, malformed, expired, or replayed probes
//!   - Zero-alloc pre-auth STUN parser + shared O(1) bounded FIFO `SeenTxidCache` across workers
//!   - Real RFC 9147 DTLS 1.3 + RFC 6347 DTLS 1.2 via `dimpl 0.9.0` (strict pre-validation, optional
//!     `--dtls-min-version 1.3`, Fail-Closed Hybrid PFS, fail-fast handshake reset, Ready gating)
//!   - Dual-SSRC SRTP (PT=111 <=50pps Opus + PT=96 video) + in-band `0xFFFE` probe echo (also early_srtp)
//!   - RFC 3550 §6.1 / 7714 §9.1 Compound SRTCP (encrypted BYE, real RC=0/1) + Closing(250ms) drain

use crate::protocol::{
    build_dimpl_config_pool, build_stun_success_response, combine_session_key, demux_rfc7983,
    derive_stun_material, detect_cpu_accel, extract_dtls_server_hello_suite, new_dtls_instance,
    parse_stun_with_key, rand_duration_range_ms, resolve_srtp_suite, stun_hmac_key,
    validate_dtls_datagram, CertCache, CipherPref, CipherSuite, DtlsConfigPool, DtlsMinVersion,
    PacketKind, SrtpCloakCipher, SrtpFrame, MAX_INNER_UDP_LEN, STUN_BINDING_REQUEST,
};
use dimpl::{Dtls, Output as DtlsOutput, ProtocolVersion};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token};
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

thread_local! {
    static SERVER_QUIET: Cell<bool> = const { Cell::new(false) };
}

const LISTEN_TOKEN: Token = Token(0);
const SEEN_TXID_TTL: Duration = Duration::from_secs(90);
const RETRANSMIT_WINDOW: Duration = Duration::from_secs(8);
const MAX_STUN_RETRANSMITS: u8 = 6;
const SEEN_TXID_CAP: usize = 65_536;
const EARLY_SRTP_CAP: usize = 32;
const MAX_DTLS_RESETS: u8 = 3;
const CLOSING_DRAIN_MS: u64 = 250;
/// RFC 7675 §5.1 consent lifetime: stop transmitting and silently release session after 30s
/// with zero authenticated packets (STUN/SRTP/SRTCP/DTLS) received from peer.
const PEER_CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

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
    pub quiet: bool,
    pub stop: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ServerState {
    DtlsHandshake,
    Ready,
    Closing(Instant),
}

struct ServerSession {
    peer_addr: SocketAddr,
    username: String,
    backend_sock: MioUdpSocket,
    backend_lport: u16,
    state: ServerState,
    ready_at: Option<Instant>,
    stun_key: [u8; 32],
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
    next_srtcp_at: Instant,
    rx_pkts: u64,
    rx_bytes: u64,
    tx_pkts: u64,
    tx_pkts_at_last_rtcp: u64,
    tx_bytes: u64,
    keepalives: u64,
    srtcp_tx: u64,
    srtcp_rx: u64,
    auth_drops: u64,
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

fn drain_server_dtls<F>(
    worker_id: usize,
    sess: &mut ServerSession,
    listen_sock: &MioUdpSocket,
    dtls_buf: &mut Vec<u8>,
    wbuf: &mut [u8],
    cfg: &ServerConfig,
    cpu: &crate::protocol::CpuAccelInfo,
    now: Instant,
    mut audit_pkt: F,
) -> bool
where
    F: FnMut(u8, &[u8]),
{
    let mut connected_now = false;
    let mut peer_closed = false;

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
            return true;
        };
        let is_dtls13 = sess
            .dtls
            .as_ref()
            .and_then(|d| d.protocol_version())
            == Some(ProtocolVersion::DTLS1_3);
        let chosen = resolve_srtp_suite(cfg.cipher_pref, sess.dtls_suite_id, cpu, false);
        let final_key = combine_session_key(&sess.stun_key, Some(km));
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
        sess.next_srtcp_at = now + rand_duration_range_ms(300, 750);

        // V3-M-03 + L-03: flush any reordered early SRTP (Data or in-band 0xFFFE Probe) arriving ahead of Flight 5!
        let mut early_flushed = 0usize;
        if let Some(ref mut cipher) = sess.cipher {
            while let Some(raw_srtp) = sess.early_srtp.pop_front() {
                match cipher.unwrap_into_ex(&raw_srtp, wbuf) {
                    Some(SrtpFrame::Data(pn)) => {
                        if sess.backend_sock.send(&wbuf[..pn]).is_ok() {
                            sess.rx_pkts += 1;
                            sess.rx_bytes += pn as u64;
                            early_flushed += 1;
                        }
                    }
                    Some(SrtpFrame::Probe(pn)) => {
                        let mut pbuf = [0u8; 2048];
                        if let Some(wn) = cipher.wrap_probe_into(&wbuf[..pn], &mut pbuf) {
                            audit_pkt(1, &pbuf[..wn]);
                            if listen_sock.send_to(&pbuf[..wn], sess.peer_addr).is_ok() {
                                sess.rx_pkts += 1;
                                sess.tx_pkts += 1;
                                early_flushed += 1;
                            }
                        }
                    }
                    None => {
                        sess.auth_drops += 1;
                    }
                }
            }
        }
        log(
            worker_id,
            &format!(
                "DTLS {} (dimpl mutual-cert PFS) OK -> READY peer={} cipher={} dual_ssrc={} backend_sport={} early_srtp={}",
                if is_dtls13 { "1.3" } else { "1.2" },
                sess.peer_addr,
                chosen.name(),
                is_dtls13,
                sess.backend_lport,
                early_flushed
            ),
        );
    }

    peer_closed
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
        let has_rx = sess.rx_pkts > 0;
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

pub fn run_server(cfg: ServerConfig) -> std::io::Result<()> {
    let workers = cfg.workers.max(1);
    let cpu = detect_cpu_accel();
    let dtls_pool = build_dimpl_config_pool(cfg.cipher_pref, &cpu, false, cfg.wan_mtu);
    let seen_txids = Arc::new(Mutex::new(SeenTxidCache::new()));
    if !cfg.quiet {
        println!(
            "[server-rs] V3.2 CPU arch={} hw_accel=[{}] recommended={} workers={} dtls=dimpl-{}(mutual-cert,cookie,pfs) silent_drop=true",
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
        return run_server_worker(0, cfg, false, dtls_pool, seen_txids);
    }

    let mut handles = Vec::with_capacity(workers - 1);
    for wid in 1..workers {
        let mut c = cfg.clone();
        c.wire_audit_file = None;
        let dp = dtls_pool.clone();
        let cache = Arc::clone(&seen_txids);
        handles.push(std::thread::spawn(move || {
            if let Err(e) = run_server_worker(wid, c, true, dp, cache) {
                eprintln!("[server-rs#{}] error: {}", wid, e);
            }
        }));
    }
    let res = run_server_worker(0, cfg, true, dtls_pool, seen_txids);
    for h in handles {
        let _ = h.join();
    }
    res
}

fn run_server_worker(
    worker_id: usize,
    cfg: ServerConfig,
    reuse_port: bool,
    dtls_pool: DtlsConfigPool,
    seen_txids: Arc<Mutex<SeenTxidCache>>,
) -> std::io::Result<()> {
    SERVER_QUIET.with(|q| q.set(cfg.quiet));
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(256);

    let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port, 8 * 1024 * 1024)?;
    poll.registry()
        .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;

    let mut sessions_by_token: HashMap<Token, ServerSession> = HashMap::new();
    let mut token_by_peer: HashMap<SocketAddr, Token> = HashMap::new();
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

    loop {
        if let Some(ref s) = cfg.stop {
            if s.load(Ordering::Relaxed) {
                return Ok(());
            }
        }
        let now = Instant::now();
        let mut wait = Duration::from_millis(150);
        let mut to_close: Vec<(Token, &'static str)> = Vec::new();

        for (&tok, sess) in sessions_by_token.iter_mut() {
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
                            if drain_server_dtls(
                                worker_id,
                                sess,
                                &listen_sock,
                                &mut dtls_buf,
                                &mut wbuf,
                                &cfg,
                                &cpu,
                                now,
                                &mut audit_pkt,
                            ) {
                                sess.state = ServerState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
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
                        // RFC 7675 §5.1: consent expired (30s with zero authenticated peer packets) ->
                        // cease transmitting immediately (silent close, zero ICMP bounce).
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
                        sess.state = ServerState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
                        continue;
                    }
                    if now >= sess.next_srtcp_at {
                        let is_active_media = now.duration_since(sess.last_data_active) <= Duration::from_secs(3);
                        let sent_media = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
                        let has_rx = sess.rx_pkts > 0;
                        sess.tx_pkts_at_last_rtcp = sess.tx_pkts;
                        if let Some(ref mut cipher) = sess.cipher {
                            let rtcp = cipher.build_srtcp(has_rx, sent_media, false);
                            audit_pkt(1, &rtcp);
                            if listen_sock.send_to(&rtcp, sess.peer_addr).is_ok() {
                                sess.srtcp_tx += 1;
                            }
                        }
                        sess.next_srtcp_at = now + if is_active_media {
                            rand_duration_range_ms(950, 1950)
                        } else {
                            rand_duration_range_ms(3500, 6500)
                        };
                    }
                }
                ServerState::Closing(deadline) => {
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

        for (tok, reason) in to_close {
            if let Some(mut sess) = sessions_by_token.remove(&tok) {
                let _ = poll.registry().deregister(&mut sess.backend_sock);
                if token_by_peer.get(&sess.peer_addr) == Some(&tok) {
                    token_by_peer.remove(&sess.peer_addr);
                }
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

        if cfg.stop.is_some() && wait > Duration::from_millis(20) {
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
                            let parsed = match parse_stun_with_key(pkt, &cfg.psk, &stun_mi_key) {
                                Some(p) if p.msg_type == STUN_BINDING_REQUEST && p.authenticated => p,
                                _ => {
                                    // Pure Silent Drop on all unauthenticated/malformed/expired STUN!
                                    unauth_drops += 1;
                                    continue;
                                }
                            };

                            let uname = parsed.username.unwrap_or_default();
                            let same_active = token_by_peer
                                .get(&peer_addr)
                                .and_then(|tok| sessions_by_token.get(tok))
                                .map(|s| s.username == uname && !matches!(s.state, ServerState::Closing(_)))
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

                            // NEW-M-01: Reject orphan STUN keepalives (without USE-CANDIDATE) after server restart / CGNAT rebind
                            if !parsed.use_candidate {
                                unauth_drops += 1;
                                continue;
                            }

                            // Re-key: tear down stale or closing session on same peer_addr
                            if let Some(&old_tok) = token_by_peer.get(&peer_addr) {
                                if let Some(mut old) = sessions_by_token.remove(&old_tok) {
                                    let _ = poll.registry().deregister(&mut old.backend_sock);
                                    token_by_peer.remove(&peer_addr);
                                    log(
                                        worker_id,
                                        &format!(
                                            "REKEY peer={} old_ufrag={} -> new_ufrag={}",
                                            peer_addr, old.username, uname
                                        ),
                                    );
                                }
                            }

                            if sessions_by_token.len() >= cfg.max_sessions {
                                let expired: Vec<Token> = sessions_by_token
                                    .iter()
                                    .filter(|(_, s)| {
                                        matches!(s.state, ServerState::Closing(_))
                                            || now.duration_since(s.last_data_active) > idle_dur
                                    })
                                    .map(|(&t, _)| t)
                                    .collect();
                                for t in expired {
                                    if let Some(mut s) = sessions_by_token.remove(&t) {
                                        graceful_teardown_server(&mut s, &listen_sock, &mut dtls_buf, &mut audit_pkt);
                                        let _ = poll.registry().deregister(&mut s.backend_sock);
                                        if token_by_peer.get(&s.peer_addr) == Some(&t) {
                                            token_by_peer.remove(&s.peer_addr);
                                        }
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
                            let bind_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                            let mut bs = match make_udp_socket(bind_any, Some(cfg.backend_addr), false, 512 * 1024) {
                                Ok(s) => s,
                                Err(e) => {
                                    log(worker_id, &format!("backend socket error: {}", e));
                                    continue;
                                }
                            };
                            let blport = bs.local_addr().map(|a| a.port()).unwrap_or(0);
                            let tok = Token(next_token_id);
                            next_token_id = next_token_id.wrapping_add(1);
                            if next_token_id == 0 {
                                next_token_id = 1;
                            }
                            if poll.registry().register(&mut bs, tok, Interest::READABLE).is_err() {
                                continue;
                            }

                            let (state, dtls_opt, cipher_opt, chosen_opt, ready_at) = if cfg.dtls_required {
                                let cert = cert_cache.get(now);
                                let mut dtls = new_dtls_instance(
                                    cfg.dtls_min_version,
                                    dtls_pool.pick(),
                                    cert,
                                    now,
                                );
                                let _ = dtls.handle_timeout(now);
                                (ServerState::DtlsHandshake, Some(dtls), None, None, None)
                            } else {
                                let chosen = resolve_srtp_suite(cfg.cipher_pref, None, &cpu, true);
                                let final_key = combine_session_key(&stun_key, None);
                                let mut c = SrtpCloakCipher::new(&final_key, s_s2c, s_c2s, false, chosen);
                                c.set_wan_mtu(cfg.wan_mtu);
                                (ServerState::Ready, None, Some(c), Some(chosen), Some(now))
                            };

                            let resp = build_stun_success_response(&parsed.txid, peer_v4, &cfg.psk);
                            {
                                let mut cache = seen_txids.lock().unwrap();
                                cache.record(parsed.txid, peer_addr, now, &resp);
                            }

                            log(
                                worker_id,
                                &format!(
                                    "AUTH STUN OK new session peer={} ufrag={} backend_sport={} ssrc_rx=0x{:08x} ssrc_tx=0x{:08x}",
                                    peer_addr, uname, blport, s_c2s, s_s2c
                                ),
                            );

                            let sess = ServerSession {
                                peer_addr,
                                username: uname,
                                backend_sock: bs,
                                backend_lport: blport,
                                state,
                                ready_at,
                                stun_key,
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
                                next_srtcp_at: now + rand_duration_range_ms(300, 750),
                                rx_pkts: 0,
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
                            sessions_by_token.insert(tok, sess);

                            audit_pkt(1, &resp);
                            let _ = listen_sock.send_to(&resp, peer_addr);
                        }
                        PacketKind::Dtls => {
                            if let Some(&tok) = token_by_peer.get(&peer_addr) {
                                if let Some(sess) = sessions_by_token.get_mut(&tok) {
                                    if matches!(sess.state, ServerState::Closing(_)) {
                                        continue;
                                    }
                                    // V3-H-01 fix: strict DTLS pre-validation + Ready gating + NEVER kill on Err!
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
                                            // P0-4: reset poisoned pre-ServerHello dimpl state instead of stalling 15s
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
                                    // M-01 / P0-4 fix: NEVER refresh last_peer_rx in Ready state from DTLS
                                    // (dimpl silently returns Ok(()) on forged AEAD ciphertext!).
                                    if sess.state == ServerState::DtlsHandshake {
                                        sess.last_peer_rx = now;
                                    }
                                    if drain_server_dtls(
                                        worker_id,
                                        sess,
                                        &listen_sock,
                                        &mut dtls_buf,
                                        &mut wbuf,
                                        &cfg,
                                        &cpu,
                                        now,
                                        &mut audit_pkt,
                                    ) {
                                        sess.state = ServerState::Closing(
                                            now + Duration::from_millis(CLOSING_DRAIN_MS),
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
                                                    );
                                                }
                                            } else {
                                                sess.auth_drops += 1;
                                            }
                                        }
                                    } else if !matches!(sess.state, ServerState::Closing(_)) {
                                        sess.auth_drops += 1;
                                    }
                                }
                            } else {
                                unauth_drops += 1;
                            }
                        }
                        PacketKind::Srtp => {
                            if let Some(&tok) = token_by_peer.get(&peer_addr) {
                                if let Some(sess) = sessions_by_token.get_mut(&tok) {
                                    match sess.state {
                                        ServerState::Ready => {
                                            if let Some(ref mut cipher) = sess.cipher {
                                                match cipher.unwrap_into_ex(pkt, &mut wbuf) {
                                                    Some(SrtpFrame::Data(pn)) => {
                                                        sess.last_data_active = now;
                                                        sess.last_peer_rx = now;
                                                        if sess.backend_sock.send(&wbuf[..pn]).is_ok() {
                                                            sess.rx_pkts += 1;
                                                            sess.rx_bytes += pn as u64;
                                                        }
                                                    }
                                                    Some(SrtpFrame::Probe(pn)) => {
                                                        // In-band AEAD-encrypted selftest echo (0xFFFE): strictly Ready-gated,
                                                        // 1:1 size (zero amplification), never forwarded to backend service.
                                                        sess.last_data_active = now;
                                                        sess.last_peer_rx = now;
                                                        let mut pbuf = [0u8; 2048];
                                                        if let Some(wn) = cipher.wrap_probe_into(&wbuf[..pn], &mut pbuf) {
                                                            audit_pkt(1, &pbuf[..wn]);
                                                            if listen_sock.send_to(&pbuf[..wn], sess.peer_addr).is_ok() {
                                                                sess.rx_pkts += 1;
                                                                sess.tx_pkts += 1;
                                                            }
                                                        }
                                                    }
                                                    None => {
                                                        sess.auth_drops += 1;
                                                    }
                                                }
                                            }
                                        }
                                        ServerState::DtlsHandshake => {
                                            // V3-M-03 + P1-4: bounded-length buffer for reordered early SRTP
                                            if sess.early_srtp.len() < EARLY_SRTP_CAP
                                                && pkt.len() >= 38
                                                && pkt.len() <= max_early_srtp_len
                                            {
                                                sess.early_srtp.push_back(pkt.to_vec());
                                            }
                                        }
                                        ServerState::Closing(_) => {}
                                    }
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
                    let n = match sess.backend_sock.recv(&mut rbuf) {
                        Ok(n) => n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    };
                    if sess.state != ServerState::Ready || n > MAX_INNER_UDP_LEN {
                        continue;
                    }
                    if let Some(ref mut cipher) = sess.cipher {
                        sess.last_data_active = now;
                        if let Some(wn) = cipher.wrap_into(&rbuf[..n], &mut wbuf) {
                            audit_pkt(1, &wbuf[..wn]);
                            if listen_sock.send_to(&wbuf[..wn], sess.peer_addr).is_ok() {
                                sess.tx_pkts += 1;
                                sess.tx_bytes += n as u64;
                            }
                        }
                    }
                }
            }
        }

        if now.duration_since(last_stats) >= stats_dur {
            last_stats = now;
            for sess in sessions_by_token.values() {
                if matches!(sess.state, ServerState::Closing(_)) {
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
