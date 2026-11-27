//! 服务端 mio 工作线程状态容器、主事件循环与定时任务及遥测上报。

use super::handlers::{
    drain_server_dtls, process_ready_srtp, send_server_dtls_close_notify,
    send_server_srtcp_bye_only,
};
use super::registry::{SeenTxidCache, SharedV4Registry, WorkerCmd};
use super::{
    cleanup_session_routes, log, make_udp_socket, record_server_media_bytes, RelayState,
    ServerConfig, ServerHook, ServerSession, ServerState, WireAudit, SERVER_SRTCP_ACTIVE_MAX_MS,
    SERVER_SRTCP_ACTIVE_MIN_MS,
};
#[cfg(unix)]
use crate::constants::SHUTDOWN_PIPE_TOKEN;
use crate::constants::{
    outer_udp_hdr_len, worker_udp_recv_buf_len, worker_udp_write_buf_len, SharedPoll,
    CLOSING_DRAIN_MS, CTRL_FRAME_BUF_LEN, DTLS_IO_BUF_LEN, LISTEN_TOKEN, MAX_INNER_UDP_LEN,
    MIN_WIRE_UDP_MTU, MIO_EVENTS_CAP, PEER_CONSENT_TIMEOUT, PROBE_IO_BUF_LEN, REV_OP_FLOW_CLOSE,
    SOCK_BUF_8MIB, SRTCP_ACTIVE_MEDIA_WINDOW_SECS, SRTCP_IDLE_MAX_MS, SRTCP_IDLE_MIN_MS,
    SRTCP_LONG_TRICKLE_MAX_MS, SRTCP_LONG_TRICKLE_MIN_MS, SRTCP_TRICKLE_MAX_MS,
    SRTCP_TRICKLE_MIN_MS, TELEMETRY_DEFAULT_INTERVAL_SECS, TRICKLE_RATE_15S_BYTES,
    TRICKLE_WINDOW_15S_SECS, WAKE_TOKEN, WORKER_ACTIVE_POLL_SECS, WORKER_IDLE_POLL_SECS,
    WORKER_MIN_FAST_WAIT_MS, WORKER_MIN_NORMAL_WAIT_MS, WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{
    derive_stun_scope_key_for, detect_cpu_accel, is_shutdown_requested, rand_duration_range_ms,
    register_shutdown_poll, stun_hmac_key, CertCache, CpuAccelInfo, DtlsConfigPool,
};
use crate::telemetry::{TelemetryHub, WorkerSnapshot};
use crate::udp_batch::{is_udp_batch_active, UdpRecvBatch, UdpSendBatch};
use dimpl::ProtocolVersion;
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 服务端 DTLS 握手阶段无进展时的超时清理阈值（秒）。
const SERVER_DTLS_HS_TIMEOUT_SECS: u64 = 15;
/// 服务端连续细流超过该时长（秒）后进入极低频（25..45s）对称 RTCP RR 节奏。
const SERVER_LONG_TRICKLE_SECS: u64 = 60;
/// 服务端优雅关闭时 `SRTCP BYE` 与 `DTLS close_notify` 之间的异步随机间隔（毫秒）。
const SERVER_BYE_TO_CLOSE_NOTIFY_MIN_MS: u64 = 18;
const SERVER_BYE_TO_CLOSE_NOTIFY_MAX_MS: u64 = 95;

pub(crate) struct ServerWorker {
    pub(super) worker_id: usize,
    pub(super) cfg: ServerConfig,
    pub(super) poll: SharedPoll,
    pub(super) relay: RelayState,
    pub(crate) listen_sock: MioUdpSocket,
    pub(super) sessions_by_token: HashMap<Token, ServerSession>,
    pub(super) token_by_peer: HashMap<SocketAddr, Token>,
    pub(super) token_by_ufrag: HashMap<String, Token>,
    pub(super) local_mig_pending: HashMap<SocketAddr, (Token, Instant)>,
    pub(super) cross_worker_pending: HashMap<SocketAddr, (String, usize, Instant)>,
    pub(super) cmd_buf: Vec<WorkerCmd>,
    pub(super) next_token_id: usize,
    pub(super) cert_cache: CertCache,
    pub(super) dtls_pool: DtlsConfigPool,
    pub(super) stun_auth_psk: [u8; 32],
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
    pub(super) rx_batch: Option<UdpRecvBatch>,
    pub(super) tx_batch: Option<UdpSendBatch>,
    pub(super) cpu: CpuAccelInfo,
    /// True for always-on embedded proxy tunnels (`proxy --server`, `proxy --client --reverse`):
    /// exempts sessions from data-inactivity `idle_dur` teardown so idle SSH/TCP flows stay alive
    /// without needing periodic inner QUIC keepalive beacons (liveness relies on 45s ICE consent).
    pub(super) persistent_tunnel: bool,
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
    let mut poll = Poll::new()?;
    if cfg.workers > 1 {
        if let Ok(waker) = Waker::new(poll.registry(), WAKE_TOKEN) {
            registry.set_waker(worker_id, Arc::new(waker));
        }
    }
    register_shutdown_poll(&poll, cfg.quiet, cfg.stop.is_some());

    let shared_poll = SharedPoll::new(poll.registry().try_clone()?);
    let mut worker = ServerWorker::new_internal(
        worker_id,
        cfg,
        reuse_port,
        false,
        false,
        LISTEN_TOKEN,
        dtls_pool,
        seen_txids,
        registry,
        shared_poll,
        telemetry,
    )?;
    worker.run(&mut poll)
}

impl ServerWorker {
    #[allow(clippy::too_many_arguments)]
    fn new_internal(
        worker_id: usize,
        cfg: ServerConfig,
        reuse_port: bool,
        relay_mode: bool,
        reverse_entry: bool,
        listen_token: Token,
        dtls_pool: DtlsConfigPool,
        seen_txids: Arc<Mutex<SeenTxidCache>>,
        registry: Arc<SharedV4Registry>,
        poll: SharedPoll,
        telemetry: Option<Arc<TelemetryHub>>,
    ) -> std::io::Result<Self> {
        super::SERVER_QUIET.with(|q| q.set(cfg.quiet));
        let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port, SOCK_BUF_8MIB)?;
        poll.registry()
            .register(&mut listen_sock, listen_token, Interest::READABLE)?;

        let actual_port = listen_sock
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(cfg.listen_addr.port());
        let stun_auth_psk =
            derive_stun_scope_key_for(&cfg.psk, actual_port, cfg.stun_scope.as_deref(), false);
        let stun_mi_key = stun_hmac_key(&stun_auth_psk);
        let max_early_srtp_len = if cfg.wan_mtu > 0 {
            cfg.wan_mtu
                .saturating_sub(outer_udp_hdr_len(cfg.listen_addr))
                .clamp(MIN_WIRE_UDP_MTU, PROBE_IO_BUF_LEN)
        } else {
            PROBE_IO_BUF_LEN
        };
        let audit = WireAudit::new(cfg.wire_audit_file.as_ref())?;
        let cpu = detect_cpu_accel();
        if !relay_mode && !reverse_entry {
            log(
                worker_id,
                &format!(
                    "listening on {} -> backend {} (reuse_port={}, cipher_pref={:?}, dtls_required={}, max_sessions={})",
                    cfg.listen_addr, cfg.backend_addr, reuse_port, cfg.cipher_pref, cfg.dtls_required, cfg.max_sessions
                ),
            );
        }

        let idle_dur = Duration::from_secs(cfg.idle_timeout_secs);
        let stats_dur = Duration::from_secs(cfg.stats_interval_secs);
        let telemetry_dur = telemetry
            .as_ref()
            .map(|th| th.interval())
            .unwrap_or(Duration::from_secs(TELEMETRY_DEFAULT_INTERVAL_SECS));
        let now = Instant::now();

        let rbuf_len = worker_udp_recv_buf_len(cfg.wan_mtu);
        let wbuf_len = worker_udp_write_buf_len(cfg.wan_mtu);
        let batch_enabled = is_udp_batch_active(cfg.udp_batch);
        let rx_batch = batch_enabled.then(|| UdpRecvBatch::new(cfg.udp_batch, rbuf_len));
        let tx_batch = batch_enabled.then(|| UdpSendBatch::new(cfg.udp_batch, wbuf_len));
        Ok(ServerWorker {
            worker_id,
            cfg,
            poll,
            relay: RelayState {
                enabled: relay_mode,
                reverse_entry,
                ..Default::default()
            },
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
            stun_auth_psk,
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
            rbuf: vec![0u8; rbuf_len],
            wbuf: vec![0u8; wbuf_len],
            dtls_buf: vec![0u8; DTLS_IO_BUF_LEN],
            rx_batch,
            tx_batch,
            cpu,
            persistent_tunnel: false,
            idle_dur,
            stats_dur,
            last_stats: now,
            telemetry_dur,
            last_telemetry: now,
        })
    }

    #[cfg(feature = "embedded-proxy")]
    pub(crate) fn set_persistent_tunnel(&mut self, enabled: bool) {
        self.persistent_tunnel = enabled;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_relay(
        worker_id: usize,
        cfg: ServerConfig,
        reuse_port: bool,
        dtls_pool: DtlsConfigPool,
        seen_txids: Arc<Mutex<SeenTxidCache>>,
        registry: Arc<SharedV4Registry>,
        poll: SharedPoll,
        telemetry: Option<Arc<TelemetryHub>>,
    ) -> std::io::Result<Self> {
        Self::new_internal(
            worker_id,
            cfg,
            reuse_port,
            true,
            false,
            LISTEN_TOKEN,
            dtls_pool,
            seen_txids,
            registry,
            poll,
            telemetry,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_relay_with_token(
        worker_id: usize,
        cfg: ServerConfig,
        reuse_port: bool,
        listen_token: Token,
        dtls_pool: DtlsConfigPool,
        seen_txids: Arc<Mutex<SeenTxidCache>>,
        registry: Arc<SharedV4Registry>,
        poll: SharedPoll,
        telemetry: Option<Arc<TelemetryHub>>,
    ) -> std::io::Result<Self> {
        Self::new_internal(
            worker_id,
            cfg,
            reuse_port,
            true,
            false,
            listen_token,
            dtls_pool,
            seen_txids,
            registry,
            poll,
            telemetry,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_reverse_entry(
        worker_id: usize,
        cfg: ServerConfig,
        dtls_pool: DtlsConfigPool,
        seen_txids: Arc<Mutex<SeenTxidCache>>,
        registry: Arc<SharedV4Registry>,
        poll: SharedPoll,
        telemetry: Option<Arc<TelemetryHub>>,
    ) -> std::io::Result<Self> {
        Self::new_internal(
            worker_id,
            cfg,
            false,
            false,
            true,
            LISTEN_TOKEN,
            dtls_pool,
            seen_txids,
            registry,
            poll,
            telemetry,
        )
    }

    /// 返回当前最新活跃且已处于 `Ready` 状态会话对应的零回环 `RelayFlow` 标识；
    /// 若对端（如反向内嵌代理出口）刚完成 DTLS 握手尚未发业务首包，则主动为其分配 `RelayFlow`。
    /// MBB `0xFFFC` 交接时会原子转移同一 `flow_addr`，因此返回值在热切换期间保持不变。
    pub(crate) fn active_ready_relay_flow(&mut self) -> Option<SocketAddr> {
        if !self.relay.enabled {
            return None;
        }
        let now = Instant::now();
        // Prefer an already-bound `RelayFlow` session over a brand-new `Unbound` Ready session
        // so an in-flight MBB standby completing DTLS Flight 5 before its `0xFFFC` handover frame
        // arrives NEVER gets prematurely allocated a distinct flow_addr (which would reset inner QUIC!).
        // If an `Unbound` session has stayed Ready for >= 1.5s without sending `0xFFFC` (e.g. a
        // fresh reverse agent replacing a SIGKILL'd peer before consent timeout), promote it cleanly.
        let mut best_bound: Option<(Token, Instant)> = None;
        let mut best_unbound: Option<(Token, Instant, bool)> = None;
        for (&tok, sess) in &self.sessions_by_token {
            if sess.state != ServerState::Ready {
                continue;
            }
            match sess.backend {
                super::BackendPipe::ForwardLocal { .. }
                | super::BackendPipe::ForwardRemote { .. } => continue,
                super::BackendPipe::RelayFlow(_) => {
                    let ts = sess.last_peer_rx.max(sess.last_data_active);
                    if best_bound.is_none_or(|(_, b)| ts >= b) {
                        best_bound = Some((tok, ts));
                    }
                }
                super::BackendPipe::Unbound => {
                    let ts = sess.last_peer_rx.max(sess.last_data_active);
                    let mature = sess.ready_at.is_some_and(|r| {
                        now.saturating_duration_since(r) >= Duration::from_millis(1500)
                    });
                    if best_unbound.is_none_or(|(_, b, _)| ts >= b) {
                        best_unbound = Some((tok, ts, mature));
                    }
                }
                _ => continue,
            }
        }
        let tok = match (best_bound, best_unbound) {
            (Some((_, bts)), Some((ut, uts, true))) if uts > bts => ut,
            (Some((bt, _)), _) => bt,
            (None, Some((ut, _, _))) => ut,
            (None, None) => return None,
        };
        let sess = self.sessions_by_token.get_mut(&tok)?;
        if matches!(sess.backend, super::BackendPipe::Unbound) {
            let _ = super::ensure_owned_backend(
                self.worker_id,
                tok,
                sess,
                self.cfg.backend_addr,
                &self.poll,
                &mut self.relay,
            );
        }
        match sess.backend {
            super::BackendPipe::RelayFlow(flow_addr) => Some(flow_addr),
            _ => None,
        }
    }

    fn run(&mut self, poll: &mut Poll) -> std::io::Result<()> {
        let mut events = Events::with_capacity(MIO_EVENTS_CAP);
        loop {
            if is_shutdown_requested(self.cfg.stop.as_ref(), self.cfg.quiet) {
                self.graceful_shutdown_all();
                return Ok(());
            }

            let now = Instant::now();
            self.drain_worker_cmds_with(now, None);
            let mut wait = self.process_timers_with(now, None);

            if self.telemetry.is_some() && wait > self.telemetry_dur {
                wait = self.telemetry_dur;
            }
            let quiet_cap = Duration::from_millis(WORKER_QUIET_STOP_POLL_MS);
            if self.cfg.stop.is_some() && self.cfg.quiet && wait > quiet_cap {
                wait = quiet_cap;
            }
            if let Err(e) = poll.poll(&mut events, Some(wait)) {
                if e.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }

            let now = Instant::now();
            for ev in events.iter() {
                #[cfg(unix)]
                if ev.token() == SHUTDOWN_PIPE_TOKEN {
                    continue;
                }
                if ev.token() == WAKE_TOKEN {
                    continue;
                }
                if ev.token() == LISTEN_TOKEN {
                    self.handle_listen_readable_with(now, None);
                } else {
                    self.handle_backend_readable(ev.token(), now);
                }
            }

            self.maybe_report_telemetry(now);
            self.maybe_log_stats(now);
        }
    }

    pub(crate) fn graceful_shutdown_all(&mut self) {
        let mut torn = 0usize;
        for sess in self.sessions_by_token.values_mut() {
            if sess.state == ServerState::Ready {
                send_server_srtcp_bye_only(sess, &self.listen_sock, &mut self.audit);
                torn += 1;
            }
        }
        if torn > 0 {
            // R2-P2-4: Separate SIGTERM SRTCP BYE and DTLS close_notify by 22..65ms
            // to match runtime async teardown spacing instead of back-to-back <0.1ms burst.
            std::thread::sleep(rand_duration_range_ms(22, 65));
            for sess in self.sessions_by_token.values_mut() {
                if sess.state == ServerState::Ready {
                    send_server_dtls_close_notify(
                        sess,
                        &self.listen_sock,
                        &mut self.dtls_buf,
                        &mut self.audit,
                    );
                }
            }
            log(
                self.worker_id,
                &format!(
                    "shutdown signal: sent graceful SRTCP BYE + DTLS close_notify to {} active session(s)",
                    torn
                ),
            );
        }
    }

    pub(crate) fn process_timers_with(
        &mut self,
        now: Instant,
        mut hook: Option<ServerHook<'_>>,
    ) -> Duration {
        // Expire stale local & cross-worker pending migration lookups
        if !self.local_mig_pending.is_empty() {
            self.local_mig_pending.retain(|_, (_, exp)| now <= *exp);
        }
        if !self.cross_worker_pending.is_empty() {
            self.cross_worker_pending
                .retain(|_, (_, _, exp)| now <= *exp);
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
                    // Exempt always-on tunnels (reverse agent / embedded proxy) and pure unused
                    // pre-warmed standbys (`rx_pkts == 0 && tx_pkts == 0`, still bound by 45s ICE
                    // consent + max_sessions eviction) so PreWarm needs zero `0xFFFE` probes!
                    let idle_exempt = sess.is_reverse_agent
                        || self.persistent_tunnel
                        || (sess.rx_pkts == 0 && sess.tx_pkts == 0);
                    if seq_exhausted
                        || (!idle_exempt
                            && now.duration_since(sess.last_data_active) > self.idle_dur)
                    {
                        send_server_srtcp_bye_only(sess, &self.listen_sock, &mut self.audit);
                        let cn_delay = rand_duration_range_ms(
                            SERVER_BYE_TO_CLOSE_NOTIFY_MIN_MS,
                            SERVER_BYE_TO_CLOSE_NOTIFY_MAX_MS,
                        );
                        sess.pending_close_notify_at = Some(now + cn_delay);
                        if cn_delay < wait {
                            wait = cn_delay.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                        }
                        sess.state = ServerState::Closing(
                            now + Duration::from_millis(CLOSING_DRAIN_MS),
                            false,
                        );
                        continue;
                    }
                    if now >= sess.next_srtcp_at {
                        let age_ge_15s = sess.ready_at.is_some_and(|r| {
                            now.duration_since(r) >= Duration::from_secs(TRICKLE_WINDOW_15S_SECS)
                        });
                        let in_trickle = age_ge_15s
                            && sess.rate_15s.bytes_in_window(now) < TRICKLE_RATE_15S_BYTES;
                        let long_trickle = in_trickle
                            && now.duration_since(sess.last_active_burst)
                                >= Duration::from_secs(SERVER_LONG_TRICKLE_SECS);
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
                            + if long_trickle {
                                rand_duration_range_ms(
                                    SRTCP_LONG_TRICKLE_MIN_MS,
                                    SRTCP_LONG_TRICKLE_MAX_MS,
                                )
                            } else if is_active_media {
                                rand_duration_range_ms(
                                    SERVER_SRTCP_ACTIVE_MIN_MS,
                                    SERVER_SRTCP_ACTIVE_MAX_MS,
                                )
                            } else if !in_trickle {
                                rand_duration_range_ms(SRTCP_IDLE_MIN_MS, SRTCP_IDLE_MAX_MS)
                            } else {
                                rand_duration_range_ms(SRTCP_TRICKLE_MIN_MS, SRTCP_TRICKLE_MAX_MS)
                            };
                    } else {
                        let rem = sess.next_srtcp_at.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS));
                        }
                    }
                }
                ServerState::Closing(deadline, _) => {
                    if let Some(cn_at) = sess.pending_close_notify_at {
                        if now >= cn_at {
                            sess.pending_close_notify_at = None;
                            send_server_dtls_close_notify(
                                sess,
                                &self.listen_sock,
                                &mut self.dtls_buf,
                                &mut self.audit,
                            );
                        } else {
                            let rem = cn_at.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                            }
                        }
                    }
                    if now >= deadline {
                        if sess.pending_close_notify_at.take().is_some() {
                            send_server_dtls_close_notify(
                                sess,
                                &self.listen_sock,
                                &mut self.dtls_buf,
                                &mut self.audit,
                            );
                        }
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
                    Some(s) => {
                        let pkts: Vec<Vec<u8>> = s.early_srtp.drain(..).collect();
                        s.early_srtp.shrink_to_fit();
                        (s.peer_addr, pkts)
                    }
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
                    &mut self.relay,
                    &mut hook,
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
                    &mut self.relay,
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

    #[inline]
    pub(crate) fn encrypt_downlink_into_slot(
        &mut self,
        flow_addr: SocketAddr,
        plaintext: &[u8],
        slot: &mut [u8],
        now: Instant,
    ) -> Option<(usize, SocketAddr)> {
        if plaintext.is_empty() || plaintext.len() > MAX_INNER_UDP_LEN {
            return None;
        }
        let &tok = self.relay.flow_to_ingress.get(&flow_addr)?;
        let sess = self.sessions_by_token.get_mut(&tok)?;
        let can_tx = matches!(
            sess.state,
            ServerState::Ready | ServerState::Closing(_, true)
        );
        if !can_tx {
            return None;
        }
        if sess.state == ServerState::Ready {
            sess.last_data_active = now;
        }
        let wn = sess.cipher.as_mut()?.wrap_into(plaintext, slot)?;
        self.audit.record(1, &slot[..wn]);
        Some((wn, sess.peer_addr))
    }

    #[inline]
    pub(crate) fn record_downlink_sent(
        &mut self,
        flow_addr: SocketAddr,
        pkts: usize,
        bytes: u64,
        now: Instant,
    ) {
        if pkts == 0 {
            return;
        }
        if let Some(&tok) = self.relay.flow_to_ingress.get(&flow_addr) {
            if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                sess.tx_pkts += pkts as u64;
                sess.tx_bytes += bytes;
                if sess.state == ServerState::Ready {
                    record_server_media_bytes(sess, now, bytes);
                }
            }
        }
    }

    pub(crate) fn deliver_downlink_single(
        &mut self,
        flow_addr: SocketAddr,
        plaintext: &[u8],
        now: Instant,
    ) -> bool {
        if plaintext.is_empty() || plaintext.len() > MAX_INNER_UDP_LEN {
            return false;
        }
        let Some(&tok) = self.relay.flow_to_ingress.get(&flow_addr) else {
            return false;
        };
        let Some(sess) = self.sessions_by_token.get_mut(&tok) else {
            return false;
        };
        let can_tx = matches!(
            sess.state,
            ServerState::Ready | ServerState::Closing(_, true)
        );
        if !can_tx {
            return false;
        }
        let mut sent_bytes = 0u64;
        if let Some(ref mut cipher) = sess.cipher {
            if sess.state == ServerState::Ready {
                sess.last_data_active = now;
            }
            if let Some(wn) = cipher.wrap_into(plaintext, &mut self.wbuf) {
                self.audit.record(1, &self.wbuf[..wn]);
                if self
                    .listen_sock
                    .send_to(&self.wbuf[..wn], sess.peer_addr)
                    .is_ok()
                {
                    sess.tx_pkts += 1;
                    sess.tx_bytes += plaintext.len() as u64;
                    sent_bytes = plaintext.len() as u64;
                }
            }
        }
        if sent_bytes > 0 && sess.state == ServerState::Ready {
            record_server_media_bytes(sess, now, sent_bytes);
        }
        sent_bytes > 0
    }

    pub(crate) fn drain_closed_relay_flows(&mut self) -> Vec<SocketAddr> {
        std::mem::take(&mut self.relay.closed_flows)
    }

    pub(crate) fn drain_closed_reverse_tokens(&mut self) -> Vec<Token> {
        std::mem::take(&mut self.relay.closed_reverse_tokens)
    }

    #[inline]
    pub(crate) fn encrypt_reverse_into_slot(
        &mut self,
        tok: Token,
        flow_id: u32,
        plaintext: &[u8],
        slot: &mut [u8],
        now: Instant,
    ) -> Option<(usize, SocketAddr)> {
        if plaintext.is_empty() || plaintext.len() > MAX_INNER_UDP_LEN {
            return None;
        }
        let sess = self.sessions_by_token.get_mut(&tok)?;
        if sess.state != ServerState::Ready {
            return None;
        }
        sess.last_data_active = now;
        let wn = sess
            .cipher
            .as_mut()?
            .wrap_reverse_data_into(flow_id, plaintext, slot)?;
        self.audit.record(1, &slot[..wn]);
        Some((wn, sess.peer_addr))
    }

    #[inline]
    pub(crate) fn record_reverse_tx(&mut self, tok: Token, pkts: usize, bytes: u64, now: Instant) {
        if pkts == 0 {
            return;
        }
        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            sess.tx_pkts += pkts as u64;
            sess.tx_bytes += bytes;
            if sess.state == ServerState::Ready {
                record_server_media_bytes(sess, now, bytes);
            }
        }
    }

    pub(crate) fn send_reverse_data_single(
        &mut self,
        tok: Token,
        flow_id: u32,
        plaintext: &[u8],
        now: Instant,
    ) -> bool {
        if plaintext.is_empty() || plaintext.len() > MAX_INNER_UDP_LEN {
            return false;
        }
        let Some(sess) = self.sessions_by_token.get_mut(&tok) else {
            return false;
        };
        if sess.state != ServerState::Ready {
            return false;
        }
        let mut sent = 0u64;
        if let Some(ref mut cipher) = sess.cipher {
            sess.last_data_active = now;
            if let Some(wn) = cipher.wrap_reverse_data_into(flow_id, plaintext, &mut self.wbuf) {
                self.audit.record(1, &self.wbuf[..wn]);
                if self
                    .listen_sock
                    .send_to(&self.wbuf[..wn], sess.peer_addr)
                    .is_ok()
                {
                    sess.tx_pkts += 1;
                    sess.tx_bytes += plaintext.len() as u64;
                    sent = plaintext.len() as u64;
                }
            }
        }
        if sent > 0 {
            record_server_media_bytes(sess, now, sent);
        }
        sent > 0
    }

    pub(crate) fn send_reverse_flow_close(&mut self, tok: Token, flow_id: u32) {
        let Some(sess) = self.sessions_by_token.get_mut(&tok) else {
            return;
        };
        if sess.state != ServerState::Ready {
            return;
        }
        let mut payload = [0u8; 5];
        payload[0] = REV_OP_FLOW_CLOSE;
        payload[1..5].copy_from_slice(&flow_id.to_be_bytes());
        let mut cbuf = [0u8; CTRL_FRAME_BUF_LEN];
        if let Some(ref mut cipher) = sess.cipher {
            if let Some(wn) = cipher.wrap_reverse_ctrl_into(&payload, &mut cbuf) {
                self.audit.record(1, &cbuf[..wn]);
                if self
                    .listen_sock
                    .send_to(&cbuf[..wn], sess.peer_addr)
                    .is_ok()
                {
                    sess.tx_pkts += 1;
                }
            }
        }
    }

    pub(crate) fn build_worker_snapshot(&self) -> WorkerSnapshot {
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
                        snap.dtls_version =
                            match sess.dtls.as_ref().and_then(|d| d.protocol_version()) {
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
        snap
    }

    fn maybe_report_telemetry(&mut self, now: Instant) {
        if let Some(ref th) = self.telemetry {
            if now.duration_since(self.last_telemetry) >= self.telemetry_dur {
                self.last_telemetry = now;
                th.update_worker(self.worker_id, self.build_worker_snapshot());
            }
        }
    }

    fn maybe_log_stats(&mut self, now: Instant) {
        if self.cfg.stats_interval_secs > 0 && now.duration_since(self.last_stats) >= self.stats_dur
        {
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
