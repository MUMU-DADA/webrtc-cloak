//! 服务端 mio 工作线程状态容器、主事件循环与定时任务及遥测上报。

use super::handlers::{drain_server_dtls, graceful_teardown_server, process_ready_srtp};
use super::registry::{SeenTxidCache, SharedV4Registry, WorkerCmd};
use super::{
    cleanup_session_routes, log, make_udp_socket, ServerConfig, ServerSession, ServerState,
    WireAudit, SERVER_SRTCP_ACTIVE_MAX_MS, SERVER_SRTCP_ACTIVE_MIN_MS,
};
use crate::constants::{
    CLOSING_DRAIN_MS, DTLS_IO_BUF_LEN, IPV4_UDP_HDR_LEN, LISTEN_TOKEN, MIN_WIRE_UDP_MTU,
    MIO_EVENTS_CAP, PEER_CONSENT_TIMEOUT, PROBE_IO_BUF_LEN, SOCK_BUF_8MIB,
    SRTCP_ACTIVE_MEDIA_WINDOW_SECS, SRTCP_IDLE_MAX_MS, SRTCP_IDLE_MIN_MS, SRTCP_TRICKLE_MAX_MS,
    SRTCP_TRICKLE_MIN_MS, TELEMETRY_DEFAULT_INTERVAL_SECS, TRICKLE_RATE_15S_BYTES,
    TRICKLE_WINDOW_15S_SECS, UDP_RECV_BUF_LEN, UDP_WRITE_BUF_LEN, WAKE_TOKEN,
    WORKER_ACTIVE_POLL_SECS, WORKER_IDLE_POLL_SECS, WORKER_MIN_FAST_WAIT_MS,
    WORKER_MIN_NORMAL_WAIT_MS, WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{
    detect_cpu_accel, rand_duration_range_ms, register_shutdown_waker, stun_hmac_key, CertCache,
    CpuAccelInfo, DtlsConfigPool,
};
use crate::telemetry::{TelemetryHub, WorkerSnapshot};
use dimpl::ProtocolVersion;
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 服务端 DTLS 握手阶段无进展时的超时清理阈值（秒）。
const SERVER_DTLS_HS_TIMEOUT_SECS: u64 = 15;
/// 服务端连续细流超过该时长（秒）后暂停主动下行 SRTCP 心跳。
const SERVER_LONG_TRICKLE_SECS: u64 = 60;
/// 服务端处于长细流静默期时的 SRTCP 状态复检间隔（秒）。
const SERVER_LONG_TRICKLE_RECHECK_SECS: u64 = 10;

pub(super) struct ServerWorker {
    pub(super) worker_id: usize,
    pub(super) cfg: ServerConfig,
    pub(super) poll: Poll,
    pub(super) listen_sock: MioUdpSocket,
    pub(super) sessions_by_token: HashMap<Token, ServerSession>,
    pub(super) token_by_peer: HashMap<SocketAddr, Token>,
    pub(super) token_by_ufrag: HashMap<String, Token>,
    pub(super) local_mig_pending: HashMap<SocketAddr, (Token, Instant)>,
    pub(super) cross_worker_pending: HashMap<SocketAddr, (String, usize, Instant)>,
    pub(super) cmd_buf: Vec<WorkerCmd>,
    pub(super) next_token_id: usize,
    pub(super) cert_cache: CertCache,
    pub(super) dtls_pool: DtlsConfigPool,
    pub(super) stun_mi_key: [u8; 32],
    pub(super) max_early_srtp_len: usize,
    pub(super) seen_txids: Arc<Mutex<SeenTxidCache>>,
    pub(super) registry: Arc<SharedV4Registry>,
    pub(super) telemetry: Option<Arc<TelemetryHub>>,
    pub(super) audit: WireAudit,
    pub(super) unauth_drops: u64,
    pub(super) closed_tx_bytes: u64,
    pub(super) closed_rx_bytes: u64,
    pub(super) closed_tx_pkts: u64,
    pub(super) closed_rx_pkts: u64,
    pub(super) closed_auth_drops: u64,
    pub(super) rbuf: Vec<u8>,
    pub(super) wbuf: Vec<u8>,
    pub(super) dtls_buf: Vec<u8>,
    pub(super) cpu: CpuAccelInfo,
    pub(super) idle_dur: Duration,
    pub(super) stats_dur: Duration,
    pub(super) last_stats: Instant,
    pub(super) telemetry_dur: Duration,
    pub(super) last_telemetry: Instant,
}

pub(super) fn run_server_worker(
    worker_id: usize,
    cfg: ServerConfig,
    reuse_port: bool,
    dtls_pool: DtlsConfigPool,
    seen_txids: Arc<Mutex<SeenTxidCache>>,
    registry: Arc<SharedV4Registry>,
    telemetry: Option<Arc<TelemetryHub>>,
) -> std::io::Result<()> {
    super::SERVER_QUIET.with(|q| q.set(cfg.quiet));
    let poll = Poll::new()?;
    if let Ok(waker) = Waker::new(poll.registry(), WAKE_TOKEN) {
        let arc_w = Arc::new(waker);
        registry.set_waker(worker_id, Arc::clone(&arc_w));
        if !cfg.quiet && cfg.stop.is_some() {
            register_shutdown_waker(arc_w);
        }
    }

    let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port, SOCK_BUF_8MIB)?;
    poll.registry()
        .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;

    let stun_mi_key = stun_hmac_key(&cfg.psk);
    let max_early_srtp_len = if cfg.wan_mtu > 0 {
        cfg.wan_mtu
            .saturating_sub(IPV4_UDP_HDR_LEN)
            .clamp(MIN_WIRE_UDP_MTU, PROBE_IO_BUF_LEN)
    } else {
        PROBE_IO_BUF_LEN
    };
    let audit = WireAudit::new(cfg.wire_audit_file.as_ref())?;
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
    let telemetry_dur = telemetry
        .as_ref()
        .map(|th| th.interval())
        .unwrap_or(Duration::from_secs(TELEMETRY_DEFAULT_INTERVAL_SECS));
    let now = Instant::now();

    let mut worker = ServerWorker {
        worker_id,
        cfg,
        poll,
        listen_sock,
        sessions_by_token: HashMap::new(),
        token_by_peer: HashMap::new(),
        token_by_ufrag: HashMap::new(),
        local_mig_pending: HashMap::new(),
        cross_worker_pending: HashMap::new(),
        cmd_buf: Vec::new(),
        next_token_id: 1,
        cert_cache: CertCache::new(),
        dtls_pool,
        stun_mi_key,
        max_early_srtp_len,
        seen_txids,
        registry,
        telemetry,
        audit,
        unauth_drops: 0,
        closed_tx_bytes: 0,
        closed_rx_bytes: 0,
        closed_tx_pkts: 0,
        closed_rx_pkts: 0,
        closed_auth_drops: 0,
        rbuf: vec![0u8; UDP_RECV_BUF_LEN],
        wbuf: vec![0u8; UDP_WRITE_BUF_LEN],
        dtls_buf: vec![0u8; DTLS_IO_BUF_LEN],
        cpu,
        idle_dur,
        stats_dur,
        last_stats: now,
        telemetry_dur,
        last_telemetry: now,
    };
    worker.run()
}

impl ServerWorker {
    fn run(&mut self) -> std::io::Result<()> {
        let mut events = Events::with_capacity(MIO_EVENTS_CAP);
        loop {
            if self
                .cfg
                .stop
                .as_ref()
                .map_or(false, |s| s.load(Ordering::Relaxed))
            {
                self.graceful_shutdown_all();
                return Ok(());
            }

            let now = Instant::now();
            self.drain_worker_cmds(now);
            let mut wait = self.process_timers(now);

            if self.telemetry.is_some() && wait > self.telemetry_dur {
                wait = self.telemetry_dur;
            }
            let quiet_cap = Duration::from_millis(WORKER_QUIET_STOP_POLL_MS);
            if self.cfg.stop.is_some() && self.cfg.quiet && wait > quiet_cap {
                wait = quiet_cap;
            }
            if let Err(e) = self.poll.poll(&mut events, Some(wait)) {
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
                    self.handle_listen_readable(now);
                } else {
                    self.handle_backend_readable(ev.token(), now);
                }
            }

            self.maybe_report_telemetry(now);
            self.maybe_log_stats(now);
        }
    }

    fn graceful_shutdown_all(&mut self) {
        let mut torn = 0usize;
        for sess in self.sessions_by_token.values_mut() {
            if sess.state == ServerState::Ready {
                graceful_teardown_server(
                    sess,
                    &self.listen_sock,
                    &mut self.dtls_buf,
                    &mut self.audit,
                );
                torn += 1;
            }
        }
        if torn > 0 {
            log(
                self.worker_id,
                &format!(
                    "shutdown signal: sent graceful SRTCP BYE + DTLS close_notify to {} active session(s)",
                    torn
                ),
            );
        }
    }

    fn process_timers(&mut self, now: Instant) -> Duration {
    // Expire stale local & cross-worker pending migration lookups
    if !self.local_mig_pending.is_empty() {
        self.local_mig_pending.retain(|_, (_, exp)| now <= *exp);
    }
    if !self.cross_worker_pending.is_empty() {
        self.cross_worker_pending.retain(|_, (_, _, exp)| now <= *exp);
    }

    let mut wait = if self.sessions_by_token.is_empty() {
        Duration::from_secs(WORKER_IDLE_POLL_SECS)
    } else {
        Duration::from_secs(WORKER_ACTIVE_POLL_SECS)
    };
    let mut to_close: Vec<(Token, &'static str)> = Vec::new();
    let mut newly_ready_early: Vec<Token> = Vec::new();

    for (&tok, sess) in self.sessions_by_token.iter_mut() {
        // Expire old_peer_addr and unverified pending_migrations cleanly
        if let Some((old_p, exp)) = sess.old_peer_addr {
            if now >= exp {
                sess.old_peer_addr = None;
                if old_p != sess.peer_addr && self.token_by_peer.get(&old_p) == Some(&tok) {
                    self.token_by_peer.remove(&old_p);
                }
            }
        }
        if !sess.pending_migrations.is_empty() {
            sess.pending_migrations.retain(|m| now <= m.expires_at);
        }

        match sess.state {
            ServerState::DtlsHandshake => {
                if now.duration_since(sess.last_data_active)
                    > Duration::from_secs(SERVER_DTLS_HS_TIMEOUT_SECS)
                {
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
                            self.worker_id,
                            sess,
                            &self.listen_sock,
                            &mut self.dtls_buf,
                            &self.cfg,
                            &self.cpu,
                            &self.registry,
                            now,
                            &mut self.audit,
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
                            wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
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
                if seq_exhausted || now.duration_since(sess.last_data_active) > self.idle_dur {
                    graceful_teardown_server(sess, &self.listen_sock, &mut self.dtls_buf, &mut self.audit);
                    sess.state = ServerState::Closing(
                        now + Duration::from_millis(CLOSING_DRAIN_MS),
                        false,
                    );
                    continue;
                }
                if now >= sess.next_srtcp_at {
                    let age_ge_15s = sess.ready_at.map_or(false, |r| {
                        now.duration_since(r) >= Duration::from_secs(TRICKLE_WINDOW_15S_SECS)
                    });
                    let in_trickle = age_ge_15s
                        && sess.rate_15s.bytes_in_window(now) < TRICKLE_RATE_15S_BYTES;
                    let long_trickle = in_trickle
                        && now.duration_since(sess.last_active_burst)
                            >= Duration::from_secs(SERVER_LONG_TRICKLE_SECS);
                    if long_trickle {
                        sess.next_srtcp_at =
                            now + Duration::from_secs(SERVER_LONG_TRICKLE_RECHECK_SECS);
                    } else {
                        let is_active_media = !in_trickle
                            && now.duration_since(sess.last_data_active)
                                <= Duration::from_secs(SRTCP_ACTIVE_MEDIA_WINDOW_SECS);
                        let sent_media = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
                        let has_rx = sess.rx_pkts > sess.rx_pkts_at_last_rtcp;
                        sess.tx_pkts_at_last_rtcp = sess.tx_pkts;
                        sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
                        if let Some(ref mut cipher) = sess.cipher {
                            let rtcp = cipher.build_srtcp(has_rx, sent_media, false);
                            self.audit.record(1, &rtcp);
                            if self.listen_sock.send_to(&rtcp, sess.peer_addr).is_ok() {
                                sess.srtcp_tx += 1;
                            }
                        }
                        sess.next_srtcp_at = now
                            + if is_active_media {
                                rand_duration_range_ms(
                                    SERVER_SRTCP_ACTIVE_MIN_MS,
                                    SERVER_SRTCP_ACTIVE_MAX_MS,
                                )
                            } else if !in_trickle {
                                rand_duration_range_ms(SRTCP_IDLE_MIN_MS, SRTCP_IDLE_MAX_MS)
                            } else {
                                rand_duration_range_ms(SRTCP_TRICKLE_MIN_MS, SRTCP_TRICKLE_MAX_MS)
                            };
                    }
                } else {
                    let rem = sess.next_srtcp_at.saturating_duration_since(now);
                    if rem < wait {
                        wait = rem.max(Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS));
                    }
                }
            }
            ServerState::Closing(deadline, _) => {
                if now >= deadline {
                    to_close.push((tok, "graceful_close"));
                } else {
                    let rem = deadline.saturating_duration_since(now);
                    if rem < wait {
                        wait = rem.max(Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS));
                    }
                }
            }
        }
    }

    // Flush any buffered early SRTP on sessions that became Ready during DTLS timeout
    for tok in newly_ready_early {
        let (peer_addr, early_pkts): (SocketAddr, Vec<Vec<u8>>) =
            match self.sessions_by_token.get_mut(&tok) {
                Some(s) => (s.peer_addr, s.early_srtp.drain(..).collect()),
                None => continue,
            };
        for raw in early_pkts {
            process_ready_srtp(
                self.worker_id,
                tok,
                peer_addr,
                &raw,
                &mut self.sessions_by_token,
                &mut self.token_by_peer,
                &mut self.token_by_ufrag,
                &mut self.local_mig_pending,
                &self.poll,
                &self.listen_sock,
                &self.cfg,
                &self.registry,
                self.telemetry.as_ref(),
                &mut self.wbuf,
                now,
                &mut self.audit,
            );
        }
    }

    for (tok, reason) in to_close {
        if let Some(mut sess) = self.sessions_by_token.remove(&tok) {
            self.closed_tx_bytes = self.closed_tx_bytes.saturating_add(sess.tx_bytes);
            self.closed_rx_bytes = self.closed_rx_bytes.saturating_add(sess.rx_bytes);
            self.closed_tx_pkts = self.closed_tx_pkts.saturating_add(sess.tx_pkts);
            self.closed_rx_pkts = self.closed_rx_pkts.saturating_add(sess.rx_pkts);
            self.closed_auth_drops = self.closed_auth_drops.saturating_add(sess.auth_drops);
            cleanup_session_routes(
                self.worker_id,
                tok,
                &mut sess,
                &self.poll,
                &mut self.token_by_peer,
                &mut self.token_by_ufrag,
                &mut self.local_mig_pending,
                &self.registry,
            );
            log(
                self.worker_id,
                &format!(
                    "close session peer={} reason={} rx={}pkts tx={}pkts ka={} rtcp={}/{} drops={}",
                    sess.peer_addr, reason, sess.rx_pkts, sess.tx_pkts, sess.keepalives,
                    sess.srtcp_tx, sess.srtcp_rx, sess.auth_drops
                ),
            );
        }
    }
        wait
    }

    fn maybe_report_telemetry(&mut self, now: Instant) {
    if let Some(ref th) = self.telemetry {
        if now.duration_since(self.last_telemetry) >= self.telemetry_dur {
            self.last_telemetry = now;
            let mut snap = WorkerSnapshot {
                tx_bytes_total: self.closed_tx_bytes,
                rx_bytes_total: self.closed_rx_bytes,
                tx_pkts_total: self.closed_tx_pkts,
                rx_pkts_total: self.closed_rx_pkts,
                auth_drops_total: self.closed_auth_drops,
                unauth_drops_total: self.unauth_drops,
                dtls_version: "none",
                cipher: "none",
                ..Default::default()
            };
            for sess in self.sessions_by_token.values() {
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
                                _ if self.cfg.dtls_required => "1.3",
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
            th.update_worker(self.worker_id, snap);
        }
    }
    }

    fn maybe_log_stats(&mut self, now: Instant) {
    if now.duration_since(self.last_stats) >= self.stats_dur {
        self.last_stats = now;
        for sess in self.sessions_by_token.values() {
            if matches!(sess.state, ServerState::Closing(_, _)) {
                continue;
            }
            log(
                self.worker_id,
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
                    self.unauth_drops
                ),
            );
        }
    }
    }
}
