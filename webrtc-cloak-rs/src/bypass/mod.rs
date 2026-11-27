//! 一级旁路直通模式（`webrtc-cloak bypass`）：带外认证 ICE STUN 多候选抽卡选路、延迟劣化换道与黑洞自愈 + 数据面零封装原样 UDP 直通。
//!
//! 包含两种配套角色：
//! - **转发端（默认 `webrtc-cloak bypass`）**：监听本地/前跳原始 UDP（如 Hysteria 2 / QUIC / WireGuard），
//!   在出站五元组上通过低频认证 ICE STUN 并发抽卡锁定最低延迟 ECMP 车道、持续监测 RTT/抖动并在劣化或黑洞时
//!   后台重抽平滑切换源端口（旧端口保留引流窗口零丢包），同时将全部业务报文 100% 零拷贝头、零加解密原样透传。
//! - **应答端（`webrtc-cloak bypass --responder`）**：超轻量纯认证 ICE STUN 应答器（无 DTLS/证书池开销），
//!   配合出口防火墙按 RFC 7983 首字节将 `0x0001` STUN 探测包旁路分流至此应答，使 99.999% 业务包直入后端服务并保留内核 `UDP GSO`。

mod worker;
#[cfg(test)]
mod tests;

use self::worker::run_bypass_worker;
use crate::client::LaneHuntConfig;
#[cfg(unix)]
use crate::constants::SHUTDOWN_PIPE_TOKEN;
use crate::constants::{
    worker_udp_recv_buf_len, LISTEN_TOKEN, MIO_EVENTS_CAP, SOCK_BUF_8MIB, STUN_BINDING_REQUEST,
    TELEMETRY_DEFAULT_INTERVAL_SECS, WORKER_IDLE_POLL_SECS, WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{
    build_stun_success_response, is_shutdown_requested, parse_stun, register_shutdown_poll,
};
use crate::server::{SeenTxidCache, TxidCheck};
use crate::telemetry::{TelemetryConfig, TelemetryHub, WorkerSnapshot};
use crate::udp_batch::{format_udp_batch_mode, is_udp_batch_active, UdpRecvBatch, UdpSendBatch};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll};
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::Cell;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

thread_local! {
    pub(super) static BYPASS_QUIET: Cell<bool> = const { Cell::new(false) };
}

/// 旁路转发端配置（`webrtc-cloak bypass`）。
#[derive(Clone)]
pub struct BypassConfig {
    pub listen_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub psk: Vec<u8>,
    pub rotate_interval_secs: u64,
    pub workers: usize,
    pub max_sessions: usize,
    pub wan_mtu: usize,
    pub udp_batch: usize,
    pub retry_ms: u64,
    pub max_retries: u32,
    pub keepalive_secs: u64,
    pub idle_timeout_secs: u64,
    pub stats_interval_secs: u64,
    pub lane_hunt: LaneHuntConfig,
    pub telemetry: TelemetryConfig,
    pub quiet: bool,
    pub stop: Option<Arc<AtomicBool>>,
}

/// 旁路轻量 STUN 测速应答端配置（`webrtc-cloak bypass --responder`）。
#[derive(Clone)]
pub struct BypassResponderConfig {
    pub listen_addr: SocketAddr,
    pub psk: Vec<u8>,
    pub workers: usize,
    pub wan_mtu: usize,
    pub udp_batch: usize,
    pub stats_interval_secs: u64,
    pub telemetry: TelemetryConfig,
    pub quiet: bool,
    pub stop: Option<Arc<AtomicBool>>,
}

pub(super) fn log(role_tag: &str, worker_id: usize, msg: &str) {
    if !BYPASS_QUIET.with(|q| q.get()) {
        println!("[{}#{}] {}", role_tag, worker_id, msg);
    }
}

pub(super) fn make_udp_socket(
    bind_addr: SocketAddr,
    connect_to: Option<SocketAddr>,
    reuse_port: bool,
    buf_bytes: usize,
) -> std::io::Result<MioUdpSocket> {
    let sock = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
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

/// 启动旁路直通转发器（支持单线程或 `SO_REUSEPORT` 多工作线程）。
pub fn run_bypass(cfg: BypassConfig) -> std::io::Result<()> {
    let workers = cfg.workers.max(1);
    let telemetry = TelemetryHub::start(
        "bypass",
        &cfg.telemetry,
        workers,
        cfg.wan_mtu,
        cfg.quiet,
        cfg.stop.clone(),
    );
    if !cfg.quiet {
        let lh_desc = if cfg.lane_hunt.enabled {
            let tgt = if cfg.lane_hunt.target_rtt_ms == 0 {
                "auto".to_string()
            } else {
                format!("{}ms", cfg.lane_hunt.target_rtt_ms)
            };
            format!(
                "on(probes={},rounds={},target={},cooldown={}s)",
                cfg.lane_hunt.probes,
                cfg.lane_hunt.max_rounds,
                tgt,
                cfg.lane_hunt.degrade_cooldown_secs
            )
        } else {
            "off".to_string()
        };
        println!(
            "[bypass-rs] mode=raw-udp+stun-ecmp workers={} lane_hunt={} udp_batch={}",
            workers,
            lh_desc,
            format_udp_batch_mode(cfg.udp_batch)
        );
    }

    if workers == 1 {
        let res = run_bypass_worker(0, cfg, false, telemetry.clone());
        if let Some(ref th) = telemetry {
            th.shutdown();
        }
        return res;
    }

    let mut handles = Vec::with_capacity(workers);
    for id in 0..workers {
        let c = cfg.clone();
        let th = telemetry.clone();
        handles.push(thread::spawn(move || run_bypass_worker(id, c, true, th)));
    }
    let mut first_err = None;
    for h in handles {
        if let Ok(Err(e)) = h.join() {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
    }
    if let Some(ref th) = telemetry {
        th.shutdown();
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// 启动超轻量旁路 ICE STUN 测速应答器（`webrtc-cloak bypass --responder`）。
pub fn run_bypass_responder(cfg: BypassResponderConfig) -> std::io::Result<()> {
    let workers = cfg.workers.max(1);
    let seen_txids = Arc::new(Mutex::new(SeenTxidCache::new()));
    let telemetry = TelemetryHub::start(
        "bypass-responder",
        &cfg.telemetry,
        workers,
        cfg.wan_mtu,
        cfg.quiet,
        cfg.stop.clone(),
    );
    if !cfg.quiet {
        println!(
            "[bypass-responder] mode=stun-only silent_drop=true workers={} udp_batch={}",
            workers,
            format_udp_batch_mode(cfg.udp_batch)
        );
    }

    if workers == 1 {
        let res = run_responder_worker(0, cfg, false, seen_txids, telemetry.clone());
        if let Some(ref th) = telemetry {
            th.shutdown();
        }
        return res;
    }

    let mut handles = Vec::with_capacity(workers);
    for id in 0..workers {
        let c = cfg.clone();
        let seen = Arc::clone(&seen_txids);
        let th = telemetry.clone();
        handles.push(thread::spawn(move || {
            run_responder_worker(id, c, true, seen, th)
        }));
    }
    let mut first_err = None;
    for h in handles {
        if let Ok(Err(e)) = h.join() {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
    }
    if let Some(ref th) = telemetry {
        th.shutdown();
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[derive(Default)]
struct ResponderCounters {
    tx_pkts: u64,
    tx_bytes: u64,
    rx_pkts: u64,
    rx_bytes: u64,
    unauth_drops: u64,
}

fn handle_responder_packet(
    pkt: &[u8],
    peer: SocketAddr,
    now: Instant,
    psk: &[u8],
    seen_txids: &Mutex<SeenTxidCache>,
    cnt: &mut ResponderCounters,
) -> Option<Vec<u8>> {
    if pkt.is_empty() || pkt[0] > 3 {
        cnt.unauth_drops = cnt.unauth_drops.saturating_add(1);
        return None;
    }
    let Some(parsed) = parse_stun(pkt, psk) else {
        cnt.unauth_drops = cnt.unauth_drops.saturating_add(1);
        return None;
    };
    if !parsed.authenticated || parsed.msg_type != STUN_BINDING_REQUEST {
        cnt.unauth_drops = cnt.unauth_drops.saturating_add(1);
        return None;
    }
    let mut cache = seen_txids.lock().unwrap_or_else(|e| e.into_inner());
    match cache.check(parsed.txid, peer, now, true) {
        TxidCheck::Fresh => {
            let resp = build_stun_success_response(&parsed.txid, peer, psk);
            cache.record(parsed.txid, peer, now, &resp);
            drop(cache);
            cnt.rx_pkts = cnt.rx_pkts.saturating_add(1);
            cnt.rx_bytes = cnt.rx_bytes.saturating_add(pkt.len() as u64);
            Some(resp)
        }
        TxidCheck::Retransmit(buf, len) => {
            drop(cache);
            cnt.rx_pkts = cnt.rx_pkts.saturating_add(1);
            cnt.rx_bytes = cnt.rx_bytes.saturating_add(pkt.len() as u64);
            Some(buf[..len as usize].to_vec())
        }
        TxidCheck::Rejected => {
            drop(cache);
            cnt.unauth_drops = cnt.unauth_drops.saturating_add(1);
            None
        }
    }
}

fn run_responder_worker(
    worker_id: usize,
    cfg: BypassResponderConfig,
    reuse_port: bool,
    seen_txids: Arc<Mutex<SeenTxidCache>>,
    telemetry: Option<Arc<TelemetryHub>>,
) -> std::io::Result<()> {
    BYPASS_QUIET.with(|q| q.set(cfg.quiet));
    let mut poll = Poll::new()?;
    register_shutdown_poll(&poll, cfg.quiet, cfg.stop.is_some());

    let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port, SOCK_BUF_8MIB)?;
    poll.registry()
        .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;

    log(
        "bypass-responder",
        worker_id,
        &format!(
            "listening on {} (reuse_port={}, stun_only=true)",
            cfg.listen_addr, reuse_port
        ),
    );

    let rbuf_len = worker_udp_recv_buf_len(cfg.wan_mtu);
    let batch_enabled = is_udp_batch_active(cfg.udp_batch);
    let mut rx_batch = batch_enabled.then(|| UdpRecvBatch::new(cfg.udp_batch, rbuf_len));
    let mut tx_batch = batch_enabled.then(|| UdpSendBatch::new(cfg.udp_batch, rbuf_len));
    let mut rbuf = vec![0u8; rbuf_len];

    let stats_dur = Duration::from_secs(cfg.stats_interval_secs);
    let telemetry_dur = telemetry
        .as_ref()
        .map(|th| th.interval())
        .unwrap_or(Duration::from_secs(TELEMETRY_DEFAULT_INTERVAL_SECS));
    let mut last_stats = Instant::now();
    let mut last_telemetry = Instant::now();
    let mut cnt = ResponderCounters::default();

    let mut events = Events::with_capacity(MIO_EVENTS_CAP);
    loop {
        if is_shutdown_requested(cfg.stop.as_ref(), cfg.quiet) {
            break;
        }
        let max_wait = if cfg.stop.is_some() {
            Duration::from_millis(WORKER_QUIET_STOP_POLL_MS)
        } else {
            Duration::from_secs(WORKER_IDLE_POLL_SECS)
        };
        let wait = if telemetry.is_some() {
            max_wait.min(telemetry_dur)
        } else {
            max_wait
        };
        if let Err(e) = poll.poll(&mut events, Some(wait)) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if is_shutdown_requested(cfg.stop.as_ref(), cfg.quiet) {
            break;
        }

        let now = Instant::now();
        for ev in events.iter() {
            #[cfg(unix)]
            if ev.token() == SHUTDOWN_PIPE_TOKEN {
                break;
            }
            if ev.token() == LISTEN_TOKEN {
                if let (Some(rx_b), Some(tx_b)) = (rx_batch.as_mut(), tx_batch.as_mut()) {
                    loop {
                        match rx_b.recv_from(&listen_sock) {
                            Ok(count) => {
                                for i in 0..count {
                                    let Some(peer) = rx_b.peer(i) else {
                                        continue;
                                    };
                                    let pkt = rx_b.packet(i);
                                    if pkt.is_empty() {
                                        continue;
                                    }
                                    if let Some(resp) = handle_responder_packet(
                                        pkt,
                                        peer,
                                        now,
                                        &cfg.psk,
                                        &seen_txids,
                                        &mut cnt,
                                    ) {
                                        if tx_b.is_full() {
                                            let (sp, sb) = tx_b.flush_to(&listen_sock);
                                            cnt.tx_pkts = cnt.tx_pkts.saturating_add(sp as u64);
                                            cnt.tx_bytes = cnt.tx_bytes.saturating_add(sb);
                                        }
                                        if let Some(slot) = tx_b.next_slot_mut() {
                                            if resp.len() <= slot.len() {
                                                slot[..resp.len()].copy_from_slice(&resp);
                                                tx_b.commit_slot(
                                                    resp.len(),
                                                    resp.len() as u64,
                                                    Some(peer),
                                                );
                                            }
                                        }
                                    }
                                }
                                if !tx_b.is_empty() {
                                    let (sp, sb) = tx_b.flush_to(&listen_sock);
                                    cnt.tx_pkts = cnt.tx_pkts.saturating_add(sp as u64);
                                    cnt.tx_bytes = cnt.tx_bytes.saturating_add(sb);
                                }
                            }
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                } else {
                    loop {
                        match listen_sock.recv_from(&mut rbuf) {
                            Ok((n, peer)) => {
                                if let Some(resp) = handle_responder_packet(
                                    &rbuf[..n],
                                    peer,
                                    now,
                                    &cfg.psk,
                                    &seen_txids,
                                    &mut cnt,
                                ) {
                                    if listen_sock.send_to(&resp, peer).is_ok() {
                                        cnt.tx_pkts = cnt.tx_pkts.saturating_add(1);
                                        cnt.tx_bytes =
                                            cnt.tx_bytes.saturating_add(resp.len() as u64);
                                    }
                                }
                            }
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                }
            }
        }

        if cfg.stats_interval_secs > 0 && now.duration_since(last_stats) >= stats_dur {
            last_stats = now;
            if cnt.rx_pkts > 0 || cnt.unauth_drops > 0 {
                log(
                    "bypass-responder",
                    worker_id,
                    &format!(
                        "stats stun_ok={} tx={}B unauth_drops={}",
                        cnt.rx_pkts, cnt.tx_bytes, cnt.unauth_drops
                    ),
                );
            }
        }
        if let Some(ref th) = telemetry {
            if now.duration_since(last_telemetry) >= telemetry_dur {
                last_telemetry = now;
                th.update_worker(
                    worker_id,
                    WorkerSnapshot {
                        active_sessions: usize::from(cnt.rx_pkts > 0),
                        tx_bytes_total: cnt.tx_bytes,
                        rx_bytes_total: cnt.rx_bytes,
                        tx_pkts_total: cnt.tx_pkts,
                        rx_pkts_total: cnt.rx_pkts,
                        unauth_drops_total: cnt.unauth_drops,
                        dtls_version: "none",
                        cipher: "bypass-stun",
                        dual_ssrc: false,
                        ..WorkerSnapshot::default()
                    },
                );
            }
        }
    }

    if let Some(ref th) = telemetry {
        th.update_worker(
            worker_id,
            WorkerSnapshot {
                active_sessions: 0,
                tx_bytes_total: cnt.tx_bytes,
                rx_bytes_total: cnt.rx_bytes,
                tx_pkts_total: cnt.tx_pkts,
                rx_pkts_total: cnt.rx_pkts,
                unauth_drops_total: cnt.unauth_drops,
                dtls_version: "none",
                cipher: "bypass-stun",
                dual_ssrc: false,
                ..WorkerSnapshot::default()
            },
        );
    }
    let _ = cfg.stop.as_ref().map(|s| s.load(Ordering::Acquire));
    Ok(())
}
