//! 反向隧道公网入口端（`webrtc-cloak reverse --entry`）。
//!
//! 在同一单线程 `mio::Poll` 事件循环内融合 `ServerWorker`（公网 WebRTC 隧道终止 + MBB/1-RTT 迁移）
//! 与 `ReverseEntryHub`（`--expose-host:--expose-port` UDP 多路复用器），零回环、零锁、支持 `recvmmsg/sendmmsg`。

use super::{log, make_udp_socket, REV_QUIET};
#[cfg(unix)]
use crate::constants::SHUTDOWN_PIPE_TOKEN;
use crate::constants::{
    outer_udp_hdr_len, worker_udp_recv_buf_len, worker_udp_write_buf_len, SharedPoll, LISTEN_TOKEN,
    MIO_EVENTS_CAP, SOCK_BUF_8MIB, TELEMETRY_DEFAULT_INTERVAL_SECS, WAKE_TOKEN,
    WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{
    build_dimpl_config_pool_for, detect_cpu_accel, is_shutdown_requested, register_shutdown_poll,
};
use crate::server::{SeenTxidCache, ServerConfig, ServerHook, ServerWorker, SharedV4Registry};
use crate::telemetry::TelemetryHub;
use crate::udp_batch::{format_udp_batch_mode, is_udp_batch_active, UdpRecvBatch, UdpSendBatch};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Entry 暴露业务 UDP 套接字在 `mio::Poll` 中的保留令牌（与 `LISTEN_TOKEN`/`WAKE_TOKEN`/`SHUTDOWN_PIPE_TOKEN` 严格隔离）。
const REVERSE_EXPOSE_TOKEN: Token = Token(usize::MAX - 2);
/// Agent 尚未上线或短暂重连期间，Entry 最多缓存的待发业务包数。
const REV_PENDING_CAP: usize = 64;
/// 待发缓存包最长保留时长（秒）。
const REV_PENDING_TTL: Duration = Duration::from_secs(3);

/// 反向隧道公网入口端配置（`webrtc-cloak reverse --entry`）。
#[derive(Clone)]
pub struct ReverseEntryConfig {
    pub server: ServerConfig,
    pub expose_addr: SocketAddr,
}

/// Entry 侧业务 UDP 多路复用器（按来源五元组分配 `flow_id: u32`，与 `ServerWorker` 同线程零锁交互）。
pub(crate) struct ReverseEntryHub {
    expose_sock: MioUdpSocket,
    active_tunnel: Option<Token>,
    next_flow_id: u32,
    flow_by_peer: HashMap<SocketAddr, u32>,
    peer_by_flow: HashMap<u32, (SocketAddr, Instant)>,
    max_flows: usize,
    pending_to_agent: VecDeque<(u32, Vec<u8>, Instant)>,
    rbuf: Vec<u8>,
    rx_batch: Option<UdpRecvBatch>,
    tx_batch: Option<UdpSendBatch>,
}

impl ReverseEntryHub {
    fn new(
        expose_addr: SocketAddr,
        poll: &SharedPoll,
        wan_mtu: usize,
        udp_batch: usize,
        max_flows: usize,
    ) -> std::io::Result<Self> {
        let mut expose_sock = make_udp_socket(expose_addr, None, SOCK_BUF_8MIB)?;
        poll.registry()
            .register(&mut expose_sock, REVERSE_EXPOSE_TOKEN, Interest::READABLE)?;

        let rbuf_len = worker_udp_recv_buf_len(wan_mtu);
        let wbuf_len = worker_udp_write_buf_len(wan_mtu);
        let batch_enabled = is_udp_batch_active(udp_batch);
        let rx_batch = batch_enabled.then(|| UdpRecvBatch::new(udp_batch, rbuf_len));
        // TX batch carries SRTP-encrypted reverse frames straight to `server.listen_sock`.
        let tx_batch = batch_enabled.then(|| UdpSendBatch::new(udp_batch, wbuf_len));

        Ok(Self {
            expose_sock,
            active_tunnel: None,
            next_flow_id: 1,
            flow_by_peer: HashMap::with_capacity(16),
            peer_by_flow: HashMap::with_capacity(16),
            max_flows: max_flows.max(1),
            pending_to_agent: VecDeque::with_capacity(16),
            rbuf: vec![0u8; rbuf_len],
            rx_batch,
            tx_batch,
        })
    }

    #[inline]
    pub(crate) fn expose_sock(&self) -> &MioUdpSocket {
        &self.expose_sock
    }

    fn alloc_flow_id(&mut self) -> u32 {
        loop {
            let id = self.next_flow_id;
            self.next_flow_id = self.next_flow_id.wrapping_add(1);
            if self.next_flow_id == 0 {
                self.next_flow_id = 1;
            }
            if id != 0 && !self.peer_by_flow.contains_key(&id) {
                return id;
            }
        }
    }

    fn get_or_alloc_flow(&mut self, peer: SocketAddr, now: Instant) -> Option<u32> {
        if let Some(&fid) = self.flow_by_peer.get(&peer) {
            if let Some(entry) = self.peer_by_flow.get_mut(&fid) {
                entry.1 = now;
            }
            return Some(fid);
        }
        if self.peer_by_flow.len() >= self.max_flows {
            // Evict oldest inactive flow to keep memory bounded under UDP scan storms.
            if let Some((&oldest_fid, &(oldest_peer, _))) =
                self.peer_by_flow.iter().min_by_key(|(_, (_, ts))| *ts)
            {
                self.peer_by_flow.remove(&oldest_fid);
                self.flow_by_peer.remove(&oldest_peer);
            } else {
                return None;
            }
        }
        let fid = self.alloc_flow_id();
        self.flow_by_peer.insert(peer, fid);
        self.peer_by_flow.insert(fid, (peer, now));
        Some(fid)
    }

    #[inline]
    pub(crate) fn peer_for_flow(&mut self, flow_id: u32, now: Instant) -> Option<SocketAddr> {
        let entry = self.peer_by_flow.get_mut(&flow_id)?;
        entry.1 = now;
        Some(entry.0)
    }

    pub(crate) fn deliver_to_peer_single(
        &mut self,
        flow_id: u32,
        payload: &[u8],
        now: Instant,
    ) -> bool {
        let Some(peer) = self.peer_for_flow(flow_id, now) else {
            return false;
        };
        self.expose_sock.send_to(payload, peer).is_ok()
    }

    pub(crate) fn remove_flow(&mut self, flow_id: u32) {
        if let Some((peer, _)) = self.peer_by_flow.remove(&flow_id) {
            if self.flow_by_peer.get(&peer) == Some(&flow_id) {
                self.flow_by_peer.remove(&peer);
            }
        }
    }

    pub(crate) fn on_agent_hello(&mut self, tok: Token) -> Vec<(u32, Vec<u8>)> {
        self.active_tunnel = Some(tok);
        let now = Instant::now();
        let mut ready = Vec::new();
        while let Some((fid, pkt, queued_at)) = self.pending_to_agent.pop_front() {
            if now.saturating_duration_since(queued_at) <= REV_PENDING_TTL {
                ready.push((fid, pkt));
            }
        }
        ready
    }

    pub(crate) fn on_tunnel_handover(&mut self, old_tok: Token, new_tok: Token) {
        if self.active_tunnel == Some(old_tok) || self.active_tunnel.is_none() {
            self.active_tunnel = Some(new_tok);
        }
    }

    fn on_tunnel_closed(&mut self, tok: Token) {
        if self.active_tunnel == Some(tok) {
            self.active_tunnel = None;
        }
    }

    fn evict_idle_flows(&mut self, now: Instant, idle_dur: Duration) -> Vec<u32> {
        let mut expired = Vec::new();
        for (&fid, &(_, last_active)) in &self.peer_by_flow {
            if now.saturating_duration_since(last_active) > idle_dur {
                expired.push(fid);
            }
        }
        for &fid in &expired {
            self.remove_flow(fid);
        }
        while let Some((_, _, ts)) = self.pending_to_agent.front() {
            if now.saturating_duration_since(*ts) > REV_PENDING_TTL {
                self.pending_to_agent.pop_front();
            } else {
                break;
            }
        }
        expired
    }

    fn queue_pending(&mut self, flow_id: u32, pkt: &[u8], now: Instant) {
        if self.pending_to_agent.len() >= REV_PENDING_CAP {
            self.pending_to_agent.pop_front();
        }
        self.pending_to_agent
            .push_back((flow_id, pkt.to_vec(), now));
    }

    fn handle_expose_readable(&mut self, server: &mut ServerWorker, now: Instant) {
        if self.rx_batch.is_some() {
            self.handle_expose_readable_batched(server, now);
            return;
        }
        loop {
            let (n, peer_addr) = match self.expose_sock.recv_from(&mut self.rbuf) {
                Ok(v) => v,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if n == 0 {
                continue;
            }
            let Some(fid) = self.get_or_alloc_flow(peer_addr, now) else {
                continue;
            };
            if let Some(tok) = self.active_tunnel {
                let _ = server.send_reverse_data_single(tok, fid, &self.rbuf[..n], now);
            } else {
                let raw = self.rbuf[..n].to_vec();
                if self.pending_to_agent.len() >= REV_PENDING_CAP {
                    self.pending_to_agent.pop_front();
                }
                self.pending_to_agent.push_back((fid, raw, now));
            }
        }
    }

    fn handle_expose_readable_batched(&mut self, server: &mut ServerWorker, now: Instant) {
        let Some(mut rx_batch) = self.rx_batch.take() else {
            return;
        };
        let Some(mut tx_batch) = self.tx_batch.take() else {
            self.rx_batch = Some(rx_batch);
            return;
        };

        loop {
            let count = match rx_batch.recv_from(&self.expose_sock) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            let active_tok = self.active_tunnel;
            for i in 0..count {
                let pkt = rx_batch.packet(i);
                let Some(peer_addr) = rx_batch.peer(i) else {
                    continue;
                };
                if pkt.is_empty() {
                    continue;
                }
                let Some(fid) = self.get_or_alloc_flow(peer_addr, now) else {
                    continue;
                };
                if let Some(tok) = active_tok {
                    if tx_batch.is_full() {
                        let (sp, sb) = tx_batch.flush_to(&server.listen_sock);
                        server.record_reverse_tx(tok, sp, sb, now);
                    }
                    if let Some(slot) = tx_batch.next_slot_mut() {
                        if let Some((wn, dst)) =
                            server.encrypt_reverse_into_slot(tok, fid, pkt, slot, now)
                        {
                            tx_batch.commit_slot(wn, pkt.len() as u64, Some(dst));
                        }
                    }
                } else {
                    self.queue_pending(fid, pkt, now);
                }
            }
            if let Some(tok) = active_tok {
                if !tx_batch.is_empty() {
                    let (sp, sb) = tx_batch.flush_to(&server.listen_sock);
                    server.record_reverse_tx(tok, sp, sb, now);
                }
            }
        }

        self.rx_batch = Some(rx_batch);
        self.tx_batch = Some(tx_batch);
    }
}

/// 启动反向隧道公网入口端（`webrtc-cloak reverse --entry`）。
pub fn run_reverse_entry(mut cfg: ReverseEntryConfig) -> std::io::Result<()> {
    let quiet = cfg.server.quiet;
    let stop = cfg.server.stop.clone();
    REV_QUIET.with(|q| q.set(quiet));
    if cfg.server.workers > 1 && !quiet {
        eprintln!("[reverse-entry] WARN: reverse entry runs single-worker to pin exposed UDP flows; clamping --workers to 1.");
    }
    cfg.server.workers = 1;

    let cpu = detect_cpu_accel();
    let dtls_pool = build_dimpl_config_pool_for(
        cfg.server.cipher_pref,
        &cpu,
        false,
        cfg.server.wan_mtu,
        outer_udp_hdr_len(cfg.server.listen_addr),
    );
    let seen_txids = Arc::new(Mutex::new(SeenTxidCache::new()));
    let registry = Arc::new(SharedV4Registry::new(1));
    let telemetry = TelemetryHub::start(
        "reverse-entry",
        &cfg.server.telemetry,
        1,
        cfg.server.wan_mtu,
        quiet,
        stop.clone(),
    );

    if !quiet {
        println!(
            "[reverse-entry] CPU arch={} hw_accel=[{}] recommended={} tunnel={} expose={} dtls=dimpl-{} silent_drop=true udp_batch={}",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            cfg.server.listen_addr,
            cfg.expose_addr,
            cfg.server.dtls_min_version.as_str(),
            format_udp_batch_mode(cfg.server.udp_batch),
        );
    }

    let mut poll = Poll::new()?;
    register_shutdown_poll(&poll, quiet, stop.is_some());
    let shared_poll = SharedPoll::new(poll.registry().try_clone()?);

    let idle_dur = Duration::from_secs(cfg.server.idle_timeout_secs);
    let stats_dur = Duration::from_secs(cfg.server.stats_interval_secs);
    let stats_enabled = cfg.server.stats_interval_secs > 0;
    let wan_mtu = cfg.server.wan_mtu;
    let udp_batch = cfg.server.udp_batch;
    let max_flows = cfg.server.max_sessions;

    let mut hub =
        ReverseEntryHub::new(cfg.expose_addr, &shared_poll, wan_mtu, udp_batch, max_flows)?;
    let mut server = ServerWorker::new_for_reverse_entry(
        0,
        cfg.server,
        dtls_pool,
        seen_txids,
        registry,
        shared_poll,
        telemetry.clone(),
    )?;

    let telemetry_dur = telemetry
        .as_ref()
        .map(|th| th.interval())
        .unwrap_or(Duration::from_secs(TELEMETRY_DEFAULT_INTERVAL_SECS));
    let mut last_telemetry = Instant::now();
    let mut last_stats = last_telemetry;
    let mut last_evict = last_telemetry;
    let mut events = Events::with_capacity(MIO_EVENTS_CAP);

    loop {
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        let now = Instant::now();
        server.drain_worker_cmds_with(now, Some(ServerHook::ReverseEntry(&mut hub)));
        let mut wait = server.process_timers_with(now, Some(ServerHook::ReverseEntry(&mut hub)));
        for closed_tok in server.drain_closed_reverse_tokens() {
            hub.on_tunnel_closed(closed_tok);
        }

        if now.duration_since(last_evict) >= Duration::from_secs(1) {
            last_evict = now;
            let expired = hub.evict_idle_flows(now, idle_dur);
            if let Some(tok) = hub.active_tunnel {
                for fid in expired {
                    server.send_reverse_flow_close(tok, fid);
                }
            }
        }

        if telemetry.is_some() && wait > telemetry_dur {
            wait = telemetry_dur;
        }
        let quiet_cap = Duration::from_millis(WORKER_QUIET_STOP_POLL_MS);
        if stop.is_some() && wait > quiet_cap {
            wait = quiet_cap;
        }

        if let Err(e) = poll.poll(&mut events, Some(wait)) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            if let Some(ref th) = telemetry {
                th.shutdown();
            }
            return Err(e);
        }
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        let now = Instant::now();
        for ev in events.iter() {
            let tok = ev.token();
            #[cfg(unix)]
            if tok == SHUTDOWN_PIPE_TOKEN {
                continue;
            }
            if tok == WAKE_TOKEN {
                continue;
            }
            if tok == LISTEN_TOKEN {
                server.handle_listen_readable_with(now, Some(ServerHook::ReverseEntry(&mut hub)));
            } else if tok == REVERSE_EXPOSE_TOKEN {
                hub.handle_expose_readable(&mut server, now);
            }
        }

        for closed_tok in server.drain_closed_reverse_tokens() {
            hub.on_tunnel_closed(closed_tok);
        }

        let post_now = Instant::now();
        if let Some(ref th) = telemetry {
            if post_now.duration_since(last_telemetry) >= telemetry_dur {
                last_telemetry = post_now;
                th.update_worker(0, server.build_worker_snapshot());
            }
        }
        if stats_enabled && post_now.duration_since(last_stats) >= stats_dur {
            last_stats = post_now;
            let snap = server.build_worker_snapshot();
            log(
                "reverse-entry",
                &format!(
                    "stats agent_online={} flows={} rx={}pkts/{:.1}KB tx={}pkts/{:.1}KB drops={} unauth={}",
                    hub.active_tunnel.is_some(),
                    hub.peer_by_flow.len(),
                    snap.rx_pkts_total,
                    snap.rx_bytes_total as f64 / 1024.0,
                    snap.tx_pkts_total,
                    snap.tx_bytes_total as f64 / 1024.0,
                    snap.auth_drops_total,
                    snap.unauth_drops_total,
                ),
            );
        }
    }

    server.graceful_shutdown_all();
    if let Some(ref th) = telemetry {
        th.update_worker(0, server.build_worker_snapshot());
        th.shutdown();
    }
    Ok(())
}
