//! 客户端 mio 工作线程状态容器、主事件循环与遥测上报。

use super::dtls::{
    schedule_async_teardown_client, send_client_dtls_close_notify, send_client_srtcp_bye_only,
    spawn_client_session,
};
use super::lane_hunt::{HuntPurpose, LaneHunt};
use super::{
    cancel_standby_for_client, log, make_udp_socket, record_client_media_bytes, ClientConfig,
    ClientDownlink, ClientSession, HandshakeState, OldPathDrain, PendingReconnect,
    CLIENT_TOK_SLOT_STRIDE, KA_MAX_RETRIES,
};
#[cfg(unix)]
use crate::constants::SHUTDOWN_PIPE_TOKEN;
use crate::constants::{
    outer_udp_hdr_len, worker_udp_recv_buf_len, worker_udp_write_buf_len, SharedPoll,
    CTRL_FRAME_BUF_LEN, DTLS_IO_BUF_LEN, LISTEN_TOKEN, MAX_INNER_UDP_LEN, MIO_EVENTS_CAP,
    POST_BYE_CLOSING_DRAIN_MS, REV_OP_HELLO, REV_PROTO_VERSION, SOCK_BUF_8MIB,
    SRTP_DATA_MIN_WIRE_LEN, TELEMETRY_DEFAULT_INTERVAL_SECS, WAKE_TOKEN, WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{
    derive_stun_scope_key_for, detect_cpu_accel, is_shutdown_requested, rand_duration_range_ms,
    register_shutdown_poll, stun_hmac_key, CertCache, CpuAccelInfo, DtlsConfigPool,
};
use crate::telemetry::{TelemetryHub, WorkerSnapshot};
use crate::udp_batch::{is_udp_batch_active, UdpRecvBatch, UdpSendBatch};
use dimpl::ProtocolVersion;
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) struct ClientWorker {
    pub(super) worker_id: usize,
    pub(super) cfg: ClientConfig,
    pub(super) poll: SharedPoll,
    pub(super) listen_sock: Option<MioUdpSocket>,
    /// True ONLY for `reverse --agent` (sends `0xFFFA REV_OP_HELLO` registration).
    pub(super) reverse_agent: bool,
    /// True for always-on persistent tunnels (`reverse --agent`, `proxy --client`, `proxy --server --reverse`):
    /// disables idle-timeout teardown without triggering `reverse_agent` `REV_OP_HELLO` polling.
    pub(super) persistent_tunnel: bool,
    pub(super) sessions_by_token: HashMap<Token, ClientSession>,
    pub(super) token_by_client: HashMap<SocketAddr, Token>,
    pub(super) standby_by_client: HashMap<SocketAddr, Token>,
    pub(super) old_path_drains: HashMap<Token, OldPathDrain>,
    pub(super) pending_reconnects: HashMap<SocketAddr, PendingReconnect>,
    pub(super) last_rotation_by_client: HashMap<SocketAddr, Instant>,
    pub(super) lane_hunts: HashMap<usize, LaneHunt>,
    pub(super) hunt_tok_to_id: HashMap<Token, usize>,
    pub(super) next_hunt_id: usize,
    pub(super) prewarm_tok: Option<Token>,
    pub(super) next_prewarm_at: Option<Instant>,
    pub(super) hunt_fail_streak: u8,
    pub(super) best_observed_rtt_ms: Option<f64>,
    pub(super) consecutive_trial_failures: u8,
    #[cfg(feature = "embedded-proxy")]
    pub(super) token_slot: usize,
    pub(super) next_token_id: usize,
    pub(super) cert_cache: CertCache,
    pub(super) dtls_pool: DtlsConfigPool,
    pub(super) stun_auth_psk: [u8; 32],
    pub(super) stun_mi_key: [u8; 32],
    pub(super) max_inner_pending: usize,
    pub(super) telemetry: Option<Arc<TelemetryHub>>,
    pub(super) rbuf: Vec<u8>,
    pub(super) wbuf: Vec<u8>,
    pub(super) dtls_buf: Vec<u8>,
    pub(super) rx_batch: Option<UdpRecvBatch>,
    pub(super) tx_batch: Option<UdpSendBatch>,
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
    let mut poll = Poll::new()?;
    register_shutdown_poll(&poll, cfg.quiet, cfg.stop.is_some());

    let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port, SOCK_BUF_8MIB)?;
    poll.registry()
        .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;

    let stun_auth_psk = derive_stun_scope_key_for(
        &cfg.psk,
        cfg.server_addr.port(),
        cfg.stun_scope.as_deref(),
        false,
    );
    let stun_mi_key = stun_hmac_key(&stun_auth_psk);
    let max_inner_pending = if cfg.wan_mtu > 0 {
        cfg.wan_mtu
            .saturating_sub(outer_udp_hdr_len(cfg.server_addr) + SRTP_DATA_MIN_WIRE_LEN)
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

    let rbuf_len = worker_udp_recv_buf_len(cfg.wan_mtu);
    let wbuf_len = worker_udp_write_buf_len(cfg.wan_mtu);
    let batch_enabled = is_udp_batch_active(cfg.udp_batch);
    let rx_batch = batch_enabled.then(|| UdpRecvBatch::new(cfg.udp_batch, rbuf_len));
    let tx_batch = batch_enabled.then(|| UdpSendBatch::new(cfg.udp_batch, wbuf_len));
    let shared_poll = SharedPoll::new(poll.registry().try_clone()?);
    let mut worker = ClientWorker {
        worker_id,
        cfg,
        poll: shared_poll,
        listen_sock: Some(listen_sock),
        reverse_agent: false,
        persistent_tunnel: false,
        sessions_by_token: HashMap::new(),
        token_by_client: HashMap::new(),
        standby_by_client: HashMap::new(),
        old_path_drains: HashMap::new(),
        pending_reconnects: HashMap::new(),
        last_rotation_by_client: HashMap::new(),
        lane_hunts: HashMap::new(),
        hunt_tok_to_id: HashMap::new(),
        next_hunt_id: 1,
        prewarm_tok: None,
        next_prewarm_at: None,
        hunt_fail_streak: 0,
        best_observed_rtt_ms: None,
        consecutive_trial_failures: 0,
        #[cfg(feature = "embedded-proxy")]
        token_slot: 0,
        next_token_id: 1,
        cert_cache: CertCache::new(),
        dtls_pool,
        stun_auth_psk,
        stun_mi_key,
        max_inner_pending,
        telemetry,
        rbuf: vec![0u8; rbuf_len],
        wbuf: vec![0u8; wbuf_len],
        dtls_buf: vec![0u8; DTLS_IO_BUF_LEN],
        rx_batch,
        tx_batch,
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
    if worker.cfg.lane_hunt.enabled {
        let _ = worker.start_lane_hunt(HuntPurpose::PreWarm, now, VecDeque::new(), 0);
    }
    worker.run(&mut poll)
}

impl ClientWorker {
    fn run(&mut self, poll: &mut Poll) -> std::io::Result<()> {
        let mut events = Events::with_capacity(MIO_EVENTS_CAP);
        loop {
            if is_shutdown_requested(self.cfg.stop.as_ref(), self.cfg.quiet) {
                self.graceful_shutdown_all();
                return Ok(());
            }

            let now = Instant::now();
            let (mut wait, standby_promoted_timers, mut standby_ready) = self.process_timers(now);

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
            let mut standby_promoted: Vec<(Token, SocketAddr)> = standby_promoted_timers;
            let mut graceful_reconnects: Vec<(Token, SocketAddr)> = Vec::new();
            for ev in events.iter() {
                #[cfg(unix)]
                if ev.token() == SHUTDOWN_PIPE_TOKEN {
                    continue;
                }
                if ev.token() == WAKE_TOKEN {
                    continue;
                }
                if ev.token() == LISTEN_TOKEN {
                    self.handle_listen_readable(now);
                } else if self.old_path_drains.contains_key(&ev.token()) {
                    self.handle_old_path_drain_with(
                        ev.token(),
                        now,
                        &mut graceful_reconnects,
                        None,
                    );
                } else if !self.hunt_tok_to_id.is_empty()
                    && self.hunt_tok_to_id.contains_key(&ev.token())
                {
                    self.handle_hunt_readable(ev.token(), now, &mut standby_ready);
                } else {
                    self.handle_upstream_readable_with(
                        ev.token(),
                        now,
                        &mut standby_ready,
                        &mut standby_promoted,
                        &mut graceful_reconnects,
                        None,
                    );
                }
            }

            self.process_post_events(now, standby_ready, standby_promoted, graceful_reconnects);
            self.maybe_report_telemetry(now);
            self.maybe_log_stats(now);
        }
    }

    pub(crate) fn new_for_relay(
        worker_id: usize,
        cfg: ClientConfig,
        dtls_pool: DtlsConfigPool,
        poll: SharedPoll,
        telemetry: Option<Arc<TelemetryHub>>,
    ) -> Self {
        Self::new_embedded(worker_id, cfg, dtls_pool, poll, telemetry, true, 0)
    }

    fn new_embedded(
        worker_id: usize,
        cfg: ClientConfig,
        dtls_pool: DtlsConfigPool,
        poll: SharedPoll,
        telemetry: Option<Arc<TelemetryHub>>,
        prewarm_on_start: bool,
        token_slot: usize,
    ) -> Self {
        super::CLIENT_QUIET.with(|q| q.set(cfg.quiet));
        let stun_auth_psk = derive_stun_scope_key_for(
            &cfg.psk,
            cfg.server_addr.port(),
            cfg.stun_scope.as_deref(),
            false,
        );
        let stun_mi_key = stun_hmac_key(&stun_auth_psk);
        let max_inner_pending = if cfg.wan_mtu > 0 {
            cfg.wan_mtu
                .saturating_sub(outer_udp_hdr_len(cfg.server_addr) + SRTP_DATA_MIN_WIRE_LEN)
                .min(MAX_INNER_UDP_LEN)
        } else {
            MAX_INNER_UDP_LEN
        };
        let cpu = detect_cpu_accel();
        let retry_dur = Duration::from_millis(cfg.retry_ms);
        let ka_base_ms = cfg.keepalive_secs * 1000;
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
        let slot_start = if token_slot == 0 {
            1
        } else {
            token_slot * CLIENT_TOK_SLOT_STRIDE
        };
        let mut worker = ClientWorker {
            worker_id,
            cfg,
            poll,
            listen_sock: None,
            reverse_agent: false,
            persistent_tunnel: false,
            sessions_by_token: HashMap::new(),
            token_by_client: HashMap::new(),
            standby_by_client: HashMap::new(),
            old_path_drains: HashMap::new(),
            pending_reconnects: HashMap::new(),
            last_rotation_by_client: HashMap::new(),
            lane_hunts: HashMap::new(),
            hunt_tok_to_id: HashMap::new(),
            next_hunt_id: 1,
            prewarm_tok: None,
            next_prewarm_at: None,
            hunt_fail_streak: 0,
            best_observed_rtt_ms: None,
            consecutive_trial_failures: 0,
            #[cfg(feature = "embedded-proxy")]
            token_slot,
            next_token_id: slot_start,
            cert_cache: CertCache::new(),
            dtls_pool,
            stun_auth_psk,
            stun_mi_key,
            max_inner_pending,
            telemetry,
            rbuf: vec![0u8; rbuf_len],
            wbuf: vec![0u8; wbuf_len],
            dtls_buf: vec![0u8; DTLS_IO_BUF_LEN],
            rx_batch,
            tx_batch,
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
        if prewarm_on_start && worker.cfg.lane_hunt.enabled {
            let _ = worker.start_lane_hunt(HuntPurpose::PreWarm, now, VecDeque::new(), 0);
        }
        worker
    }

    #[inline]
    pub(crate) fn ready_upstream_tok(&self, client_addr: SocketAddr) -> Option<Token> {
        if self.pending_reconnects.contains_key(&client_addr) {
            return None;
        }
        let tok = *self.token_by_client.get(&client_addr)?;
        self.sessions_by_token
            .get(&tok)
            .is_some_and(|s| s.state == HandshakeState::Ready)
            .then_some(tok)
    }

    #[inline]
    pub(crate) fn wrap_uplink_into_slot(
        &mut self,
        tok: Token,
        plaintext: &[u8],
        slot: &mut [u8],
        now: Instant,
    ) -> Option<usize> {
        let sess = self.sessions_by_token.get_mut(&tok)?;
        sess.last_data_active = now;
        sess.cipher.as_mut()?.wrap_into(plaintext, slot)
    }

    #[inline]
    pub(crate) fn flush_batched_uplink(
        &mut self,
        tok: Token,
        tx_batch: &mut UdpSendBatch,
        now: Instant,
    ) -> (usize, u64) {
        if tx_batch.is_empty() {
            return (0, 0);
        }
        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            let (sp, sb) = tx_batch.flush_connected(&sess.upstream);
            if sp > 0 {
                sess.tx_pkts += sp as u64;
                sess.tx_pkts_since_dl_rx = sess.tx_pkts_since_dl_rx.saturating_add(sp as u64);
                sess.tx_bytes += sb;
                record_client_media_bytes(sess, &self.cfg, self.ka_base_ms, now, sb);
            }
            (sp, sb)
        } else {
            tx_batch.clear();
            (0, 0)
        }
    }

    pub(crate) fn send_uplink_single(
        &mut self,
        client_addr: SocketAddr,
        payload: &[u8],
        now: Instant,
    ) -> bool {
        if payload.is_empty()
            || payload.len() > MAX_INNER_UDP_LEN
            || payload.len() > self.rbuf.len()
        {
            return false;
        }
        let n = payload.len();
        self.rbuf[..n].copy_from_slice(payload);
        self.dispatch_listen_packet(n, client_addr, now);
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_event_relay(
        &mut self,
        tok: Token,
        ingress: &mut crate::server::ServerWorker,
        now: Instant,
        standby_ready: &mut Vec<(Token, SocketAddr)>,
        standby_promoted: &mut Vec<(Token, SocketAddr)>,
        graceful_reconnects: &mut Vec<(Token, SocketAddr)>,
    ) {
        if self.old_path_drains.contains_key(&tok) {
            self.handle_old_path_drain_with(
                tok,
                now,
                graceful_reconnects,
                Some(ClientDownlink::Relay(ingress)),
            );
        } else if !self.hunt_tok_to_id.is_empty() && self.hunt_tok_to_id.contains_key(&tok) {
            self.handle_hunt_readable(tok, now, standby_ready);
        } else {
            self.handle_upstream_readable_with(
                tok,
                now,
                standby_ready,
                standby_promoted,
                graceful_reconnects,
                Some(ClientDownlink::Relay(ingress)),
            );
        }
    }

    pub(crate) fn new_for_reverse_agent(
        worker_id: usize,
        cfg: ClientConfig,
        dtls_pool: DtlsConfigPool,
        poll: SharedPoll,
        telemetry: Option<Arc<TelemetryHub>>,
        tunnel_key: SocketAddr,
    ) -> Self {
        let mut w = Self::new_embedded(worker_id, cfg, dtls_pool, poll, telemetry, false, 0);
        w.reverse_agent = true;
        w.persistent_tunnel = true;
        w.ensure_reverse_tunnel(tunnel_key, Instant::now());
        w
    }

    pub(crate) fn ensure_reverse_tunnel(&mut self, tunnel_key: SocketAddr, now: Instant) {
        if self.token_by_client.contains_key(&tunnel_key)
            || self.pending_reconnects.contains_key(&tunnel_key)
        {
            return;
        }
        let has_active_hunt = self.lane_hunts.values().any(|h| {
            matches!(
                h.purpose,
                HuntPurpose::NewPrimary { client_addr, .. } if client_addr == tunnel_key
            )
        });
        if has_active_hunt {
            return;
        }
        if self.cfg.lane_hunt.enabled {
            let _ = self.start_lane_hunt(
                HuntPurpose::NewPrimary {
                    client_addr: tunnel_key,
                    ka_max_retries: KA_MAX_RETRIES,
                },
                now,
                VecDeque::new(),
                0,
            );
        } else {
            let _ = spawn_client_session(
                self.worker_id,
                tunnel_key,
                &self.cfg,
                &mut self.poll,
                &mut self.sessions_by_token,
                &mut self.token_by_client,
                &mut self.standby_by_client,
                &mut self.next_token_id,
                &mut self.dtls_buf,
                now,
                self.retry_dur,
                self.ka_base_ms,
                self.idle_dur,
                KA_MAX_RETRIES,
                None,
            );
        }
    }

    pub(crate) fn drive_reverse_persistence(&mut self, tunnel_key: SocketAddr, now: Instant) {
        if let Some(&tok) = self.token_by_client.get(&tunnel_key) {
            if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                if sess.state == HandshakeState::Ready
                    && !sess.is_standby
                    && !sess.is_prewarm
                    && !sess.rev_registered
                    && sess.next_rev_hello_at.is_none_or(|t| now >= t)
                {
                    let hello = [REV_OP_HELLO, REV_PROTO_VERSION];
                    let mut cbuf = [0u8; CTRL_FRAME_BUF_LEN];
                    if let Some(ref mut cipher) = sess.cipher {
                        if let Some(wn) = cipher.wrap_reverse_ctrl_into(&hello, &mut cbuf) {
                            if sess.upstream.send(&cbuf[..wn]).is_ok() {
                                sess.tx_pkts += 1;
                            }
                        }
                    }
                    sess.next_rev_hello_at = Some(now + Duration::from_millis(300));
                }
            }
            return;
        }
        self.ensure_reverse_tunnel(tunnel_key, now);
    }

    #[cfg(feature = "embedded-proxy")]
    pub(crate) fn new_for_proxy_client(
        worker_id: usize,
        cfg: ClientConfig,
        dtls_pool: DtlsConfigPool,
        poll: SharedPoll,
        telemetry: Option<Arc<TelemetryHub>>,
        tunnel_key: SocketAddr,
    ) -> Self {
        Self::new_for_proxy_client_slot(worker_id, cfg, dtls_pool, poll, telemetry, tunnel_key, 0)
    }

    #[cfg(feature = "embedded-proxy")]
    pub(crate) fn new_for_proxy_client_slot(
        worker_id: usize,
        cfg: ClientConfig,
        dtls_pool: DtlsConfigPool,
        poll: SharedPoll,
        telemetry: Option<Arc<TelemetryHub>>,
        tunnel_key: SocketAddr,
        token_slot: usize,
    ) -> Self {
        let mut w = Self::new_embedded(
            worker_id, cfg, dtls_pool, poll, telemetry, false, token_slot,
        );
        w.persistent_tunnel = true;
        w.ensure_persistent_tunnel(tunnel_key, Instant::now());
        w
    }

    #[cfg(feature = "embedded-proxy")]
    #[inline]
    pub(crate) fn token_slot(&self) -> usize {
        self.token_slot
    }

    #[cfg(feature = "embedded-proxy")]
    #[inline]
    pub(crate) fn owns_token(&self, tok: Token) -> bool {
        let start = if self.token_slot == 0 {
            1
        } else {
            self.token_slot * CLIENT_TOK_SLOT_STRIDE
        };
        let end = (self.token_slot + 1) * CLIENT_TOK_SLOT_STRIDE;
        tok.0 >= start && tok.0 < end
    }

    #[cfg(feature = "embedded-proxy")]
    pub(crate) fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    #[cfg(feature = "embedded-proxy")]
    pub(crate) fn ensure_persistent_tunnel(&mut self, tunnel_key: SocketAddr, now: Instant) {
        self.ensure_reverse_tunnel(tunnel_key, now);
    }

    #[cfg(feature = "embedded-proxy")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_event_proxy(
        &mut self,
        tok: Token,
        engine: &mut crate::proxy::ProxyClientEngine,
        now: Instant,
        standby_ready: &mut Vec<(Token, SocketAddr)>,
        standby_promoted: &mut Vec<(Token, SocketAddr)>,
        graceful_reconnects: &mut Vec<(Token, SocketAddr)>,
    ) {
        if self.old_path_drains.contains_key(&tok) {
            self.handle_old_path_drain_with(
                tok,
                now,
                graceful_reconnects,
                Some(ClientDownlink::Proxy(engine)),
            );
        } else if !self.hunt_tok_to_id.is_empty() && self.hunt_tok_to_id.contains_key(&tok) {
            self.handle_hunt_readable(tok, now, standby_ready);
        } else {
            self.handle_upstream_readable_with(
                tok,
                now,
                standby_ready,
                standby_promoted,
                graceful_reconnects,
                Some(ClientDownlink::Proxy(engine)),
            );
        }
    }

    #[cfg(feature = "embedded-proxy")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_event_proxy_server(
        &mut self,
        tok: Token,
        engine: &mut crate::proxy::ProxyServerEngine,
        now: Instant,
        standby_ready: &mut Vec<(Token, SocketAddr)>,
        standby_promoted: &mut Vec<(Token, SocketAddr)>,
        graceful_reconnects: &mut Vec<(Token, SocketAddr)>,
    ) {
        if self.old_path_drains.contains_key(&tok) {
            self.handle_old_path_drain_with(
                tok,
                now,
                graceful_reconnects,
                Some(ClientDownlink::ProxyServer(engine)),
            );
        } else if !self.hunt_tok_to_id.is_empty() && self.hunt_tok_to_id.contains_key(&tok) {
            self.handle_hunt_readable(tok, now, standby_ready);
        } else {
            self.handle_upstream_readable_with(
                tok,
                now,
                standby_ready,
                standby_promoted,
                graceful_reconnects,
                Some(ClientDownlink::ProxyServer(engine)),
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_event_reverse(
        &mut self,
        tok: Token,
        mux: &mut crate::reverse::ReverseAgentMux,
        now: Instant,
        standby_ready: &mut Vec<(Token, SocketAddr)>,
        standby_promoted: &mut Vec<(Token, SocketAddr)>,
        graceful_reconnects: &mut Vec<(Token, SocketAddr)>,
    ) {
        if self.old_path_drains.contains_key(&tok) {
            self.handle_old_path_drain_with(
                tok,
                now,
                graceful_reconnects,
                Some(ClientDownlink::ReverseAgent(mux)),
            );
        } else if !self.hunt_tok_to_id.is_empty() && self.hunt_tok_to_id.contains_key(&tok) {
            self.handle_hunt_readable(tok, now, standby_ready);
        } else {
            self.handle_upstream_readable_with(
                tok,
                now,
                standby_ready,
                standby_promoted,
                graceful_reconnects,
                Some(ClientDownlink::ReverseAgent(mux)),
            );
        }
    }

    #[inline]
    pub(crate) fn encrypt_reverse_uplink_into_slot(
        &mut self,
        tunnel_key: SocketAddr,
        flow_id: u32,
        plaintext: &[u8],
        slot: &mut [u8],
        now: Instant,
    ) -> Option<usize> {
        if plaintext.is_empty() || plaintext.len() > MAX_INNER_UDP_LEN {
            return None;
        }
        let &tok = self.token_by_client.get(&tunnel_key)?;
        let sess = self.sessions_by_token.get_mut(&tok)?;
        if sess.state != HandshakeState::Ready {
            return None;
        }
        sess.last_data_active = now;
        sess.cipher
            .as_mut()?
            .wrap_reverse_data_into(flow_id, plaintext, slot)
    }

    #[inline]
    pub(crate) fn flush_reverse_uplink_batch(
        &mut self,
        tunnel_key: SocketAddr,
        tx_batch: &mut UdpSendBatch,
        now: Instant,
    ) -> (usize, u64) {
        if tx_batch.is_empty() {
            return (0, 0);
        }
        let Some(&tok) = self.token_by_client.get(&tunnel_key) else {
            tx_batch.clear();
            return (0, 0);
        };
        self.flush_batched_uplink(tok, tx_batch, now)
    }

    pub(crate) fn send_reverse_uplink_single(
        &mut self,
        tunnel_key: SocketAddr,
        flow_id: u32,
        plaintext: &[u8],
        now: Instant,
    ) -> bool {
        if plaintext.is_empty() || plaintext.len() > MAX_INNER_UDP_LEN {
            return false;
        }
        let Some(&tok) = self.token_by_client.get(&tunnel_key) else {
            return false;
        };
        let Some(sess) = self.sessions_by_token.get_mut(&tok) else {
            return false;
        };
        if sess.state != HandshakeState::Ready {
            return false;
        }
        let mut sent = 0u64;
        if let Some(ref mut cipher) = sess.cipher {
            sess.last_data_active = now;
            if let Some(wn) = cipher.wrap_reverse_data_into(flow_id, plaintext, &mut self.wbuf) {
                if sess.upstream.send(&self.wbuf[..wn]).is_ok() {
                    sess.tx_pkts += 1;
                    sess.tx_pkts_since_dl_rx = sess.tx_pkts_since_dl_rx.saturating_add(1);
                    sess.tx_bytes += plaintext.len() as u64;
                    sent = plaintext.len() as u64;
                }
            }
        }
        if sent > 0 {
            record_client_media_bytes(sess, &self.cfg, self.ka_base_ms, now, sent);
        }
        sent > 0
    }

    pub(crate) fn close_flow(&mut self, client_addr: SocketAddr, now: Instant) {
        self.pending_reconnects.remove(&client_addr);
        self.cancel_hunts_for_client(client_addr);
        cancel_standby_for_client(
            client_addr,
            &mut self.standby_by_client,
            &mut self.sessions_by_token,
            &mut self.dtls_buf,
            now,
        );
        if let Some(tok) = self.token_by_client.remove(&client_addr) {
            if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                schedule_async_teardown_client(sess, now);
                sess.state =
                    HandshakeState::Closing(now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS));
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn process_timers_relay(
        &mut self,
        now: Instant,
    ) -> (Duration, Vec<(Token, SocketAddr)>, Vec<(Token, SocketAddr)>) {
        self.process_timers(now)
    }

    pub(crate) fn process_post_events_relay(
        &mut self,
        now: Instant,
        standby_ready: Vec<(Token, SocketAddr)>,
        standby_promoted: Vec<(Token, SocketAddr)>,
        graceful_reconnects: Vec<(Token, SocketAddr)>,
    ) {
        self.process_post_events(now, standby_ready, standby_promoted, graceful_reconnects);
    }

    pub(crate) fn graceful_shutdown_all(&mut self) {
        for (_, mut hunt) in self.lane_hunts.drain() {
            for mut c in hunt.candidates.drain(..) {
                let _ = self.poll.registry().deregister(&mut c.sock);
            }
            if let Some(mut fb) = hunt.best_fallback.take() {
                let _ = self.poll.registry().deregister(&mut fb.sock);
            }
        }
        self.hunt_tok_to_id.clear();
        let mut torn = 0usize;
        for sess in self.sessions_by_token.values_mut() {
            if matches!(
                sess.state,
                HandshakeState::Ready
                    | HandshakeState::HandoverWait
                    | HandshakeState::DrainingBeforeBye(_)
            ) {
                send_client_srtcp_bye_only(sess);
                torn += 1;
            }
        }
        if torn > 0 {
            std::thread::sleep(rand_duration_range_ms(22, 65));
            for sess in self.sessions_by_token.values_mut() {
                if matches!(
                    sess.state,
                    HandshakeState::Ready
                        | HandshakeState::HandoverWait
                        | HandshakeState::DrainingBeforeBye(_)
                ) {
                    send_client_dtls_close_notify(sess, &mut self.dtls_buf);
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

    pub(crate) fn build_worker_snapshot(&self) -> WorkerSnapshot {
        let mut snap = WorkerSnapshot {
            tx_bytes_total: self.closed_tx_bytes,
            rx_bytes_total: self.closed_rx_bytes,
            tx_pkts_total: self.closed_tx_pkts,
            rx_pkts_total: self.closed_rx_pkts,
            auth_drops_total: self.closed_auth_drops,
            lane_best_rtt_ms: self.best_observed_rtt_ms,
            dtls_version: "none",
            cipher: "none",
            ..Default::default()
        };
        let mut has_primary_metrics = false;
        for sess in self.sessions_by_token.values() {
            snap.tx_bytes_total = snap.tx_bytes_total.saturating_add(sess.tx_bytes);
            snap.rx_bytes_total = snap.rx_bytes_total.saturating_add(sess.rx_bytes);
            snap.tx_pkts_total = snap.tx_pkts_total.saturating_add(sess.tx_pkts);
            snap.rx_pkts_total = snap.rx_pkts_total.saturating_add(sess.rx_pkts);
            snap.auth_drops_total = snap.auth_drops_total.saturating_add(sess.auth_drops);
            match sess.state {
                HandshakeState::Ready if !sess.is_standby => {
                    snap.active_sessions += 1;
                    if snap.active_up_sport == 0 || (!has_primary_metrics && !sess.is_prewarm) {
                        snap.active_up_sport = sess.local_port;
                        snap.data_loss_pct = (sess.lane_data_loss_rate * 100.0).clamp(0.0, 100.0);
                        snap.lane_score = sess.lane_score;
                        snap.lane_confirmed = sess.lane_confirmed;
                        if !sess.is_prewarm {
                            has_primary_metrics = true;
                        }
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
