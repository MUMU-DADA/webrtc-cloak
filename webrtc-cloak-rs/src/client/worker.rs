//! 客户端 mio 工作线程状态容器、主事件循环与遥测上报。

use super::dtls::graceful_teardown_client;
use super::{
    log, make_udp_socket, ClientConfig, ClientSession, HandshakeState, OldPathDrain,
    PendingReconnect,
};
use crate::constants::{
    DTLS_IO_BUF_LEN, IPV4_UDP_HDR_LEN, LISTEN_TOKEN, MAX_INNER_UDP_LEN, MIO_EVENTS_CAP,
    SOCK_BUF_8MIB, SRTP_DATA_MIN_WIRE_LEN, TELEMETRY_DEFAULT_INTERVAL_SECS, UDP_RECV_BUF_LEN,
    UDP_WRITE_BUF_LEN, WAKE_TOKEN, WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{
    detect_cpu_accel, register_shutdown_waker, stun_hmac_key, CertCache, CpuAccelInfo,
    DtlsConfigPool,
};
use crate::telemetry::{TelemetryHub, WorkerSnapshot};
use dimpl::ProtocolVersion;
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) struct ClientWorker {
    pub(super) worker_id: usize,
    pub(super) cfg: ClientConfig,
    pub(super) poll: Poll,
    pub(super) listen_sock: MioUdpSocket,
    pub(super) sessions_by_token: HashMap<Token, ClientSession>,
    pub(super) token_by_client: HashMap<SocketAddr, Token>,
    pub(super) standby_by_client: HashMap<SocketAddr, Token>,
    pub(super) old_path_drains: HashMap<Token, OldPathDrain>,
    pub(super) pending_reconnects: HashMap<SocketAddr, PendingReconnect>,
    pub(super) last_rotation_by_client: HashMap<SocketAddr, Instant>,
    pub(super) next_token_id: usize,
    pub(super) cert_cache: CertCache,
    pub(super) dtls_pool: DtlsConfigPool,
    pub(super) stun_mi_key: [u8; 32],
    pub(super) max_inner_pending: usize,
    pub(super) telemetry: Option<Arc<TelemetryHub>>,
    pub(super) rbuf: Vec<u8>,
    pub(super) wbuf: Vec<u8>,
    pub(super) dtls_buf: Vec<u8>,
    pub(super) cpu: CpuAccelInfo,
    pub(super) retry_dur: Duration,
    pub(super) ka_base_ms: u64,
    pub(super) idle_dur: Duration,
    pub(super) stats_dur: Duration,
    pub(super) last_stats: Instant,
    pub(super) telemetry_dur: Duration,
    pub(super) last_telemetry: Instant,
    pub(super) closed_tx_bytes: u64,
    pub(super) closed_rx_bytes: u64,
    pub(super) closed_tx_pkts: u64,
    pub(super) closed_rx_pkts: u64,
    pub(super) closed_auth_drops: u64,
}

pub(super) fn run_client_worker(
    worker_id: usize,
    cfg: ClientConfig,
    reuse_port: bool,
    dtls_pool: DtlsConfigPool,
    telemetry: Option<Arc<TelemetryHub>>,
) -> std::io::Result<()> {
    super::CLIENT_QUIET.with(|q| q.set(cfg.quiet));
    let poll = Poll::new()?;
    if !cfg.quiet && cfg.stop.is_some() {
        if let Ok(waker) = Waker::new(poll.registry(), WAKE_TOKEN) {
            register_shutdown_waker(Arc::new(waker));
        }
    }

    let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port, SOCK_BUF_8MIB)?;
    poll.registry()
        .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;

    let stun_mi_key = stun_hmac_key(&cfg.psk);
    let max_inner_pending = if cfg.wan_mtu > 0 {
        cfg.wan_mtu
            .saturating_sub(IPV4_UDP_HDR_LEN + SRTP_DATA_MIN_WIRE_LEN)
            .min(MAX_INNER_UDP_LEN)
    } else {
        MAX_INNER_UDP_LEN
    };
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
    let telemetry_dur = telemetry
        .as_ref()
        .map(|th| th.interval())
        .unwrap_or(Duration::from_secs(TELEMETRY_DEFAULT_INTERVAL_SECS));
    let now = Instant::now();

    let mut worker = ClientWorker {
        worker_id,
        cfg,
        poll,
        listen_sock,
        sessions_by_token: HashMap::new(),
        token_by_client: HashMap::new(),
        standby_by_client: HashMap::new(),
        old_path_drains: HashMap::new(),
        pending_reconnects: HashMap::new(),
        last_rotation_by_client: HashMap::new(),
        next_token_id: 1,
        cert_cache: CertCache::new(),
        dtls_pool,
        stun_mi_key,
        max_inner_pending,
        telemetry,
        rbuf: vec![0u8; UDP_RECV_BUF_LEN],
        wbuf: vec![0u8; UDP_WRITE_BUF_LEN],
        dtls_buf: vec![0u8; DTLS_IO_BUF_LEN],
        cpu,
        retry_dur,
        ka_base_ms,
        idle_dur,
        stats_dur,
        last_stats: now,
        telemetry_dur,
        last_telemetry: now,
        closed_tx_bytes: 0,
        closed_rx_bytes: 0,
        closed_tx_pkts: 0,
        closed_rx_pkts: 0,
        closed_auth_drops: 0,
    };
    worker.run()
}

impl ClientWorker {
    fn run(&mut self) -> std::io::Result<()> {
        let mut events = Events::with_capacity(MIO_EVENTS_CAP);
        loop {
            if self
                .cfg
                .stop
                .as_ref()
                .is_some_and(|s| s.load(Ordering::Relaxed))
            {
                self.graceful_shutdown_all();
                return Ok(());
            }

            let now = Instant::now();
            let (mut wait, standby_promoted_timers) = self.process_timers(now);

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
            let mut standby_ready: Vec<(Token, SocketAddr)> = Vec::new();
            let mut standby_promoted: Vec<(Token, SocketAddr)> = standby_promoted_timers;
            let mut graceful_reconnects: Vec<(Token, SocketAddr)> = Vec::new();
            for ev in events.iter() {
                if ev.token() == WAKE_TOKEN {
                    continue;
                }
                if ev.token() == LISTEN_TOKEN {
                    self.handle_listen_readable(now);
                } else if self.old_path_drains.contains_key(&ev.token()) {
                    self.handle_old_path_drain(ev.token(), now, &mut graceful_reconnects);
                } else {
                    self.handle_upstream_readable(
                        ev.token(),
                        now,
                        &mut standby_ready,
                        &mut standby_promoted,
                        &mut graceful_reconnects,
                    );
                }
            }

            self.process_post_events(now, standby_ready, standby_promoted, graceful_reconnects);
            self.maybe_report_telemetry(now);
            self.maybe_log_stats(now);
        }
    }

    fn graceful_shutdown_all(&mut self) {
        let mut torn = 0usize;
        for sess in self.sessions_by_token.values_mut() {
            if matches!(
                sess.state,
                HandshakeState::Ready
                    | HandshakeState::HandoverWait
                    | HandshakeState::DrainingBeforeBye(_)
            ) {
                graceful_teardown_client(sess, &mut self.dtls_buf);
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
                        HandshakeState::Ready if !sess.is_standby => {
                            snap.active_sessions += 1;
                            if snap.active_up_sport == 0 {
                                snap.active_up_sport = sess.local_port;
                            }
                            if snap.cipher == "none" {
                                if let Some(c) = sess.active_cipher {
                                    snap.cipher = c.name();
                                }
                            }
                            if snap.dtls_version == "none" {
                                snap.dtls_version =
                                    match sess.dtls.as_ref().and_then(|d| d.protocol_version()) {
                                        Some(ProtocolVersion::DTLS1_3) => {
                                            snap.dual_ssrc = true;
                                            "1.3"
                                        }
                                        Some(ProtocolVersion::DTLS1_2) => "1.2",
                                        _ if self.cfg.dtls_decoy => "1.3",
                                        _ => "none",
                                    };
                            }
                        }
                        HandshakeState::Migrating => {
                            snap.migrating_sessions += 1;
                            if snap.active_up_sport == 0 {
                                snap.active_up_sport = sess.local_port;
                            }
                        }
                        HandshakeState::StunWait
                        | HandshakeState::DtlsHandshake
                        | HandshakeState::HandoverWait
                            if !sess.is_standby =>
                        {
                            snap.handshaking_sessions += 1;
                        }
                        _ => {}
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
                if matches!(
                    sess.state,
                    HandshakeState::Closing(_) | HandshakeState::DrainingBeforeBye(_)
                ) {
                    continue;
                }
                log(
                self.worker_id,
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
