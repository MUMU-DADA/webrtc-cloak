//! 反向隧道内网/NAT 出口端（`webrtc-cloak reverse --agent`）。
//!
//! 零公网入站端口：启动后立即主动外拨 Entry 建立常驻 WebRTC 加密隧道，完整复用 `ClientWorker`
//! 的 ECMP `--lane-hunt` 抽卡、`0xFFFC` MBB 零中断轮换、`0xFFFD` 1-RTT 迁移与断线自动重连，
//! 并按 `flow_id: u32` 为每条业务流维护独立的固定源端口本地后端 UDP 套接字。

use super::{log, make_udp_socket, rev_tunnel_key, REV_QUIET};
use crate::client::{ClientConfig, ClientWorker, REV_BACKEND_TOK_BASE};
#[cfg(unix)]
use crate::constants::SHUTDOWN_PIPE_TOKEN;
use crate::constants::{
    outer_udp_hdr_len, unspecified_addr_for, worker_udp_recv_buf_len, worker_udp_write_buf_len,
    SharedPoll, MIO_EVENTS_CAP, SOCK_BUF_4MIB, TELEMETRY_DEFAULT_INTERVAL_SECS, WAKE_TOKEN,
    WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{
    build_dimpl_config_pool_for, detect_cpu_accel, is_shutdown_requested, register_shutdown_poll,
};
use crate::telemetry::TelemetryHub;
use crate::udp_batch::{format_udp_batch_mode, is_udp_batch_active, UdpRecvBatch, UdpSendBatch};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 反向隧道内网/NAT 出口端配置（`webrtc-cloak reverse --agent`）。
#[derive(Clone)]
pub struct ReverseAgentConfig {
    pub client: ClientConfig,
    pub backend_addr: SocketAddr,
}

struct AgentFlow {
    flow_id: u32,
    sock: MioUdpSocket,
    last_active: Instant,
}

/// Agent 侧本地后端 UDP 流表（与 `ClientWorker` 共享同一个 `mio::Poll`，零回环、零锁）。
pub(crate) struct ReverseAgentMux {
    poll: SharedPoll,
    backend_addr: SocketAddr,
    max_flows: usize,
    next_tok_offset: usize,
    tok_by_flow: HashMap<u32, Token>,
    flows_by_tok: HashMap<Token, AgentFlow>,
    rbuf: Vec<u8>,
    rx_batch: Option<UdpRecvBatch>,
    tx_batch: Option<UdpSendBatch>,
}

impl ReverseAgentMux {
    fn new(
        poll: SharedPoll,
        backend_addr: SocketAddr,
        wan_mtu: usize,
        udp_batch: usize,
        max_flows: usize,
    ) -> Self {
        let rbuf_len = worker_udp_recv_buf_len(wan_mtu);
        let wbuf_len = worker_udp_write_buf_len(wan_mtu);
        let batch_enabled = is_udp_batch_active(udp_batch);
        let rx_batch = batch_enabled.then(|| UdpRecvBatch::new(udp_batch, rbuf_len));
        // TX batch carries SRTP-encrypted reverse uplink frames straight to `client` upstream socket.
        let tx_batch = batch_enabled.then(|| UdpSendBatch::new(udp_batch, wbuf_len));

        Self {
            poll,
            backend_addr,
            max_flows: max_flows.max(1),
            next_tok_offset: 0,
            tok_by_flow: HashMap::with_capacity(16),
            flows_by_tok: HashMap::with_capacity(16),
            rbuf: vec![0u8; rbuf_len],
            rx_batch,
            tx_batch,
        }
    }

    fn alloc_backend_token(&mut self) -> Token {
        let span = REV_BACKEND_TOK_BASE.saturating_sub(8).max(1);
        loop {
            let off = self.next_tok_offset;
            self.next_tok_offset = (self.next_tok_offset + 1) % span;
            let tok = Token(REV_BACKEND_TOK_BASE + off);
            if !self.flows_by_tok.contains_key(&tok) {
                return tok;
            }
        }
    }

    pub(crate) fn deliver_to_backend(
        &mut self,
        flow_id: u32,
        payload: &[u8],
        now: Instant,
    ) -> bool {
        if payload.is_empty() {
            return false;
        }
        if let Some(&tok) = self.tok_by_flow.get(&flow_id) {
            if let Some(flow) = self.flows_by_tok.get_mut(&tok) {
                flow.last_active = now;
                return flow.sock.send(payload).is_ok();
            }
        }
        if self.flows_by_tok.len() >= self.max_flows {
            if let Some((&oldest_tok, oldest_fid)) = self
                .flows_by_tok
                .iter()
                .min_by_key(|(_, f)| f.last_active)
                .map(|(t, f)| (t, f.flow_id))
            {
                if let Some(mut old) = self.flows_by_tok.remove(&oldest_tok) {
                    let _ = self.poll.registry().deregister(&mut old.sock);
                }
                self.tok_by_flow.remove(&oldest_fid);
            } else {
                return false;
            }
        }
        let bind_any = unspecified_addr_for(self.backend_addr);
        let mut sock = match make_udp_socket(bind_any, Some(self.backend_addr), SOCK_BUF_4MIB) {
            Ok(s) => s,
            Err(e) => {
                log(
                    "reverse-agent",
                    &format!("backend socket error for flow {}: {}", flow_id, e),
                );
                return false;
            }
        };
        let tok = self.alloc_backend_token();
        if self
            .poll
            .registry()
            .register(&mut sock, tok, Interest::READABLE)
            .is_err()
        {
            return false;
        }
        let ok = sock.send(payload).is_ok();
        self.tok_by_flow.insert(flow_id, tok);
        self.flows_by_tok.insert(
            tok,
            AgentFlow {
                flow_id,
                sock,
                last_active: now,
            },
        );
        ok
    }

    pub(crate) fn close_flow(&mut self, flow_id: u32) {
        if let Some(tok) = self.tok_by_flow.remove(&flow_id) {
            if let Some(mut flow) = self.flows_by_tok.remove(&tok) {
                let _ = self.poll.registry().deregister(&mut flow.sock);
            }
        }
    }

    fn evict_idle_flows(&mut self, now: Instant, idle_dur: Duration) {
        let expired: Vec<u32> = self
            .flows_by_tok
            .values()
            .filter(|f| now.saturating_duration_since(f.last_active) > idle_dur)
            .map(|f| f.flow_id)
            .collect();
        for fid in expired {
            self.close_flow(fid);
        }
    }

    fn shutdown_all(&mut self) {
        for (_, mut flow) in self.flows_by_tok.drain() {
            let _ = self.poll.registry().deregister(&mut flow.sock);
        }
        self.tok_by_flow.clear();
    }

    fn handle_backend_readable(
        &mut self,
        tok: Token,
        client: &mut ClientWorker,
        tunnel_key: SocketAddr,
        now: Instant,
    ) {
        if self.rx_batch.is_some() {
            self.handle_backend_readable_batched(tok, client, tunnel_key, now);
            return;
        }
        let Some(flow) = self.flows_by_tok.get_mut(&tok) else {
            return;
        };
        let fid = flow.flow_id;
        loop {
            let n = match flow.sock.recv(&mut self.rbuf) {
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if n == 0 {
                continue;
            }
            flow.last_active = now;
            let _ = client.send_reverse_uplink_single(tunnel_key, fid, &self.rbuf[..n], now);
        }
    }

    fn handle_backend_readable_batched(
        &mut self,
        tok: Token,
        client: &mut ClientWorker,
        tunnel_key: SocketAddr,
        now: Instant,
    ) {
        let Some(mut rx_batch) = self.rx_batch.take() else {
            return;
        };
        let Some(mut tx_batch) = self.tx_batch.take() else {
            self.rx_batch = Some(rx_batch);
            return;
        };

        if let Some(flow) = self.flows_by_tok.get_mut(&tok) {
            let fid = flow.flow_id;
            loop {
                let count = match rx_batch.recv_connected(&flow.sock) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                flow.last_active = now;
                for i in 0..count {
                    let pkt = rx_batch.packet(i);
                    if pkt.is_empty() {
                        continue;
                    }
                    if tx_batch.is_full() {
                        let _ = client.flush_reverse_uplink_batch(tunnel_key, &mut tx_batch, now);
                    }
                    if let Some(slot) = tx_batch.next_slot_mut() {
                        if let Some(wn) =
                            client.encrypt_reverse_uplink_into_slot(tunnel_key, fid, pkt, slot, now)
                        {
                            tx_batch.commit_slot(wn, pkt.len() as u64, None);
                        }
                    }
                }
                if !tx_batch.is_empty() {
                    let _ = client.flush_reverse_uplink_batch(tunnel_key, &mut tx_batch, now);
                }
            }
        }

        self.rx_batch = Some(rx_batch);
        self.tx_batch = Some(tx_batch);
    }
}

/// 启动反向隧道内网/NAT 出口端（`webrtc-cloak reverse --agent`）。
pub fn run_reverse_agent(mut cfg: ReverseAgentConfig) -> std::io::Result<()> {
    let quiet = cfg.client.quiet;
    let stop = cfg.client.stop.clone();
    REV_QUIET.with(|q| q.set(quiet));
    if cfg.client.workers > 1 && !quiet {
        eprintln!("[reverse-agent] WARN: reverse agent maintains a single persistent tunnel; clamping --workers to 1.");
    }
    cfg.client.workers = 1;

    let cpu = detect_cpu_accel();
    let dtls_pool = build_dimpl_config_pool_for(
        cfg.client.cipher_pref,
        &cpu,
        true,
        cfg.client.wan_mtu,
        outer_udp_hdr_len(cfg.client.server_addr),
    );
    let telemetry = TelemetryHub::start(
        "reverse-agent",
        &cfg.client.telemetry,
        1,
        cfg.client.wan_mtu,
        quiet,
        stop.clone(),
    );

    if !quiet {
        let lh = cfg.client.lane_hunt.normalized();
        let lane_info = if lh.enabled {
            format!(
                " lane_hunt=on(probes={},rounds={})",
                lh.probes, lh.max_rounds
            )
        } else {
            String::new()
        };
        println!(
            "[reverse-agent] CPU arch={} hw_accel=[{}] recommended={} entry={} backend={} dtls=dimpl-{} keepalive={}s{} udp_batch={}",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            cfg.client.server_addr,
            cfg.backend_addr,
            cfg.client.dtls_min_version.as_str(),
            cfg.client.keepalive_secs,
            lane_info,
            format_udp_batch_mode(cfg.client.udp_batch),
        );
    }

    let mut poll = Poll::new()?;
    register_shutdown_poll(&poll, quiet, stop.is_some());
    let shared_poll = SharedPoll::new(poll.registry().try_clone()?);

    let idle_dur = Duration::from_secs(cfg.client.idle_timeout_secs);
    let stats_dur = Duration::from_secs(cfg.client.stats_interval_secs);
    let stats_enabled = cfg.client.stats_interval_secs > 0;
    let wan_mtu = cfg.client.wan_mtu;
    let udp_batch = cfg.client.udp_batch;
    let max_flows = cfg.client.max_sessions;
    let tunnel_key = rev_tunnel_key();

    let mut mux = ReverseAgentMux::new(
        shared_poll.clone(),
        cfg.backend_addr,
        wan_mtu,
        udp_batch,
        max_flows,
    );
    let mut client = ClientWorker::new_for_reverse_agent(
        0,
        cfg.client,
        dtls_pool,
        shared_poll,
        telemetry.clone(),
        tunnel_key,
    );

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
        client.drive_reverse_persistence(tunnel_key, now);
        let (mut wait, mut standby_promoted, mut standby_ready) = client.process_timers_relay(now);

        if now.duration_since(last_evict) >= Duration::from_secs(1) {
            last_evict = now;
            mux.evict_idle_flows(now, idle_dur);
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
        let mut graceful_reconnects: Vec<(Token, SocketAddr)> = Vec::new();
        for ev in events.iter() {
            let tok = ev.token();
            #[cfg(unix)]
            if tok == SHUTDOWN_PIPE_TOKEN {
                continue;
            }
            if tok == WAKE_TOKEN {
                continue;
            }
            if tok.0 >= REV_BACKEND_TOK_BASE && tok.0 < usize::MAX - 2 {
                mux.handle_backend_readable(tok, &mut client, tunnel_key, now);
            } else {
                client.handle_event_reverse(
                    tok,
                    &mut mux,
                    now,
                    &mut standby_ready,
                    &mut standby_promoted,
                    &mut graceful_reconnects,
                );
            }
        }

        client.process_post_events_relay(now, standby_ready, standby_promoted, graceful_reconnects);
        client.drive_reverse_persistence(tunnel_key, Instant::now());

        let post_now = Instant::now();
        if let Some(ref th) = telemetry {
            if post_now.duration_since(last_telemetry) >= telemetry_dur {
                last_telemetry = post_now;
                th.update_worker(0, client.build_worker_snapshot());
            }
        }
        if stats_enabled && post_now.duration_since(last_stats) >= stats_dur {
            last_stats = post_now;
            let snap = client.build_worker_snapshot();
            log(
                "reverse-agent",
                &format!(
                    "stats active={} up_sport={} flows={} tx={}pkts/{:.1}KB rx={}pkts/{:.1}KB drops={}",
                    snap.active_sessions,
                    snap.active_up_sport,
                    mux.flows_by_tok.len(),
                    snap.tx_pkts_total,
                    snap.tx_bytes_total as f64 / 1024.0,
                    snap.rx_pkts_total,
                    snap.rx_bytes_total as f64 / 1024.0,
                    snap.auth_drops_total,
                ),
            );
        }
    }

    client.graceful_shutdown_all();
    mux.shutdown_all();
    if let Some(ref th) = telemetry {
        th.update_worker(0, client.build_worker_snapshot());
        th.shutdown();
    }
    Ok(())
}
