//! 旁路转发器 `mio` 工作线程：带外 STUN ECMP 抽卡状态机、劣化换道、黑洞自愈与零封装 UDP 热路径转发。

use super::{log, make_udp_socket, BypassConfig, BYPASS_QUIET};
use crate::client::compute_lane_score;
#[cfg(unix)]
use crate::constants::SHUTDOWN_PIPE_TOKEN;
use crate::constants::{
    unspecified_addr_for, worker_udp_recv_buf_len, LISTEN_TOKEN, MIO_EVENTS_CAP, SOCK_BUF_8MIB,
    STUN_BINDING_SUCCESS, STUN_HDR_LEN, TELEMETRY_DEFAULT_INTERVAL_SECS, WORKER_ACTIVE_POLL_SECS,
    WORKER_IDLE_POLL_SECS, WORKER_MIN_FAST_WAIT_MS, WORKER_MIN_NORMAL_WAIT_MS,
    WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{
    build_ice_stun_request, is_shutdown_requested, jitter_duration_ms, make_fresh_stun_txid,
    parse_stun, register_shutdown_poll, SessionIceParams,
};
use crate::telemetry::{TelemetryHub, WorkerSnapshot};
use crate::udp_batch::{is_udp_batch_active, UdpRecvBatch, UdpSendBatch};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// RFC 5389 STUN Magic Cookie（用于单指令判别上游回包是带外 STUN 还是内层业务报文）。
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
/// 切换上游源端口后保留旧端口只收在途 QUIC 尾包的重叠排空时长（秒）。
const BYPASS_OLD_PORT_DRAIN_SECS: u64 = 3;
/// 单工作线程最多同时保留的排空旧套接字数上限。
const MAX_OLD_DRAINS: usize = 16;
/// 同轮抽卡候选端口之间的错峰发包间隔（毫秒）。
const HUNT_STAGGER_MS: u64 = 15;
/// 冷启动自动校准最少跨越轮数（取全局最低 RTT 建立跨地域基线）。
const COLD_CALIBRATION_ROUNDS: usize = 2;
/// 冷启动自动校准期望最小总候选数。
const COLD_MIN_PROBES: usize = 6;
/// 冷启动单轮探测超时（毫秒）。
const COLD_ROUND_TIMEOUT_MS: u64 = 750;
/// 常规抽卡单轮超时上下限（毫秒）。
const ROUND_TIMEOUT_MIN_MS: u64 = 450;
const ROUND_TIMEOUT_MAX_MS: u64 = 1200;
/// 同轮首个达标候选返回后的早停等待余量与上下限（毫秒）。
const EARLY_SETTLE_MARGIN_MS: f64 = 45.0;
const EARLY_SETTLE_MIN_MS: u64 = 80;
const EARLY_SETTLE_MAX_MS: u64 = 500;
/// 预热失败重试间隔（毫秒）。
const PREWARM_RETRY_MS: u64 = 3_000;
/// 预热就绪套接字空闲保鲜探针间隔（毫秒）。
const PREWARM_KEEP_FRESH_MS: u64 = 20_000;
/// 常规 STUN 同意探针最大重传次数（共 3 次尝试）。
const KA_MAX_RETRIES: u8 = 2;
/// 刚切换端口阻尼窗口内的 STUN 同意探针最大重传次数（共 5 次尝试）。
const KA_MAX_RETRIES_DAMPED: u8 = 4;
/// 刚切换端口后的阻尼窗口时长（秒）。
const RECENT_SWITCH_DAMP_SECS: u64 = 60;
/// 无业务数据包超过该窗口（秒）后自动退避低频 STUN 探测。
const IDLE_BACKOFF_AFTER_SECS: u64 = 30;
/// 空闲退避态 STUN 探测基准间隔（毫秒）。
const IDLE_KA_BASE_MS: u64 = 25_000;
/// 判定近期有活跃流量（允许定时轮换）的窗口（秒）。
const ACTIVE_TRAFFIC_WINDOW_SECS: u64 = 30;
/// 活跃信道 RTT EWMA 新样本权重。
const RTT_EWMA_ALPHA: f64 = 0.35;
/// STUN 保活成功/失败滑动窗口容量（配合单包偶发丢失免疫）。
const STUN_LOSS_WIN_CAP: usize = 16;
/// 综合信道评分退化阈值与 Canary 确认阈值（与 `client::lane_hunt` 对齐）。
const DEGRADE_SCORE_THRESHOLD: f64 = 55.0;
const CONFIRM_SCORE_THRESHOLD: f64 = 70.0;
const CONFIRM_GOOD_WINDOWS: u16 = 2;
const DEGRADE_CONSECUTIVE: u8 = 3;
const TRIAL_DEGRADE_CONSECUTIVE: u8 = 2;
const TRIAL_FAIL_COOLDOWN_SECS: u64 = 15;
const MAX_FAST_TRIAL_RETRIES: u8 = 2;
/// 退化重抽切换所需的最小绝对收益（毫秒）与最大 RTT 比例。
const IMPROVE_MIN_DELTA_MS: f64 = 20.0;
const IMPROVE_MAX_RATIO: f64 = 0.85;
/// 自动阈值目标倍率与增量（严格低于 `score < 55` 退化线）。
const AUTO_TARGET_MULT: f64 = 1.40;
const AUTO_TARGET_ADD_MS: f64 = 20.0;

#[inline]
fn is_stun_wire_packet(pkt: &[u8]) -> bool {
    pkt.len() >= STUN_HDR_LEN
        && pkt[0] <= 3
        && u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]) == STUN_MAGIC_COOKIE
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HuntReason {
    PreWarm,
    UpgradeInitial { client_addr: SocketAddr },
    DegradeRtt { client_addr: SocketAddr },
    BlackholeEscape { client_addr: SocketAddr },
    ScheduledRotate { client_addr: SocketAddr },
}

struct HuntCandidate {
    tok: Token,
    sock: MioUdpSocket,
    local_port: u16,
    ice: SessionIceParams,
    txid: [u8; 12],
    stun_pkt: Vec<u8>,
    send_at: Instant,
    sent_at: Option<Instant>,
    rtt_ms: Option<f64>,
    mapped_nat: Option<SocketAddr>,
}

struct BypassHunt {
    reason: HuntReason,
    round: usize,
    max_rounds: usize,
    min_rounds_before_accept: usize,
    target_rtt_ms: f64,
    round_deadline: Instant,
    early_settle_at: Option<Instant>,
    candidates: Vec<HuntCandidate>,
    best: Option<(MioUdpSocket, Token, u16, SessionIceParams, f64, Option<SocketAddr>)>,
    total_probed: usize,
}

struct PrewarmedSocket {
    tok: Token,
    sock: MioUdpSocket,
    local_port: u16,
    ice: SessionIceParams,
    rtt_ms: f64,
    mapped_nat: Option<SocketAddr>,
    next_refresh_at: Instant,
    pending_txid: Option<([u8; 12], Instant)>,
}

struct OldDrain {
    sock: MioUdpSocket,
    client_addr: SocketAddr,
    expires_at: Instant,
}

#[derive(Clone)]
struct PendingKa {
    txid: [u8; 12],
    pkt: Vec<u8>,
    first_sent: Instant,
    retry_at: Instant,
    retries: u8,
}

struct BypassSession {
    tok: Token,
    client_addr: SocketAddr,
    upstream: MioUdpSocket,
    local_port: u16,
    ice: SessionIceParams,
    mapped_nat: Option<SocketAddr>,
    last_activity: Instant,
    last_switched_at: Instant,
    next_rotate_at: Option<Instant>,
    next_ka_at: Instant,
    pending_ka: Option<PendingKa>,
    rtt_ewma_ms: Option<f64>,
    last_rtt_ms: Option<f64>,
    jitter_ms: f64,
    stun_window: VecDeque<bool>,
    lane_score: Option<f64>,
    lane_confirmed: bool,
    good_windows: u16,
    degrade_streak: u8,
    last_hunt_at: Option<Instant>,
    migrating: bool,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_pkts: u64,
    rx_pkts: u64,
    auth_drops: u64,
}

struct BypassWorker {
    worker_id: usize,
    cfg: BypassConfig,
    poll: Poll,
    listen_sock: MioUdpSocket,
    sessions_by_tok: HashMap<Token, BypassSession>,
    tok_by_client: HashMap<SocketAddr, Token>,
    old_drains: HashMap<Token, OldDrain>,
    drain_order: VecDeque<Token>,
    hunt: Option<BypassHunt>,
    hunt_tok_set: HashMap<Token, usize>,
    prewarm: Option<PrewarmedSocket>,
    next_prewarm_at: Option<Instant>,
    best_observed_rtt_ms: Option<f64>,
    trial_fail_streak: u8,
    next_token_id: usize,
    telemetry: Option<Arc<TelemetryHub>>,
    rbuf: Vec<u8>,
    rx_batch: Option<UdpRecvBatch>,
    tx_batch: Option<UdpSendBatch>,
    ka_base_ms: u64,
    idle_dur: Duration,
    stats_dur: Duration,
    last_stats: Instant,
    telemetry_dur: Duration,
    last_telemetry: Instant,
    closed_tx_bytes: u64,
    closed_rx_bytes: u64,
    closed_tx_pkts: u64,
    closed_rx_pkts: u64,
    closed_auth_drops: u64,
}

#[inline]
fn alloc_token(next_id: &mut usize) -> Token {
    loop {
        let id = *next_id;
        *next_id = next_id.wrapping_add(1);
        if id != 0 && id < usize::MAX - 2 {
            return Token(id);
        }
    }
}

pub(super) fn run_bypass_worker(
    worker_id: usize,
    cfg: BypassConfig,
    reuse_port: bool,
    telemetry: Option<Arc<TelemetryHub>>,
) -> std::io::Result<()> {
    BYPASS_QUIET.with(|q| q.set(cfg.quiet));
    let poll = Poll::new()?;
    register_shutdown_poll(&poll, cfg.quiet, cfg.stop.is_some());

    let mut listen_sock = make_udp_socket(cfg.listen_addr, None, reuse_port, SOCK_BUF_8MIB)?;
    poll.registry()
        .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;

    log(
        "bypass-rs",
        worker_id,
        &format!(
            "listening on {} -> {} (reuse_port={}, raw_udp=true, keepalive={}s±20%, max_sessions={})",
            cfg.listen_addr, cfg.server_addr, reuse_port, cfg.keepalive_secs, cfg.max_sessions
        ),
    );

    let rbuf_len = worker_udp_recv_buf_len(cfg.wan_mtu);
    let batch_enabled = is_udp_batch_active(cfg.udp_batch);
    let rx_batch = batch_enabled.then(|| UdpRecvBatch::new(cfg.udp_batch, rbuf_len));
    let tx_batch = batch_enabled.then(|| UdpSendBatch::new(cfg.udp_batch, rbuf_len));
    let telemetry_dur = telemetry
        .as_ref()
        .map(|th| th.interval())
        .unwrap_or(Duration::from_secs(TELEMETRY_DEFAULT_INTERVAL_SECS));
    let now = Instant::now();

    let mut w = BypassWorker {
        worker_id,
        ka_base_ms: cfg.keepalive_secs.max(1) * 1000,
        idle_dur: Duration::from_secs(cfg.idle_timeout_secs),
        stats_dur: Duration::from_secs(cfg.stats_interval_secs),
        last_stats: now,
        telemetry_dur,
        last_telemetry: now,
        poll,
        listen_sock,
        sessions_by_tok: HashMap::with_capacity(8),
        tok_by_client: HashMap::with_capacity(8),
        old_drains: HashMap::with_capacity(4),
        drain_order: VecDeque::with_capacity(4),
        hunt: None,
        hunt_tok_set: HashMap::with_capacity(8),
        prewarm: None,
        next_prewarm_at: cfg.lane_hunt.enabled.then_some(now),
        best_observed_rtt_ms: None,
        trial_fail_streak: 0,
        next_token_id: 1,
        telemetry,
        rbuf: vec![0u8; rbuf_len],
        rx_batch,
        tx_batch,
        closed_tx_bytes: 0,
        closed_rx_bytes: 0,
        closed_tx_pkts: 0,
        closed_rx_pkts: 0,
        closed_auth_drops: 0,
        cfg,
    };

    if w.cfg.lane_hunt.enabled {
        w.start_hunt(HuntReason::PreWarm, now);
    }

    let mut events = Events::with_capacity(MIO_EVENTS_CAP);
    loop {
        if is_shutdown_requested(w.cfg.stop.as_ref(), w.cfg.quiet) {
            break;
        }
        let wait = w.next_poll_timeout(Instant::now());
        if let Err(e) = w.poll.poll(&mut events, Some(wait)) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if is_shutdown_requested(w.cfg.stop.as_ref(), w.cfg.quiet) {
            break;
        }

        let now = Instant::now();
        let mut tokens = Vec::with_capacity(events.iter().count().max(1));
        let mut stop_pipe = false;
        for ev in events.iter() {
            #[cfg(unix)]
            if ev.token() == SHUTDOWN_PIPE_TOKEN {
                stop_pipe = true;
                break;
            }
            tokens.push(ev.token());
        }
        if stop_pipe {
            break;
        }

        for tok in tokens {
            if tok == LISTEN_TOKEN {
                w.handle_local_readable(now);
            } else if w.sessions_by_tok.contains_key(&tok) {
                w.handle_upstream_readable(tok, now);
            } else if w.old_drains.contains_key(&tok) {
                w.handle_drain_readable(tok, now);
            } else if w.hunt_tok_set.contains_key(&tok) {
                w.handle_hunt_readable(tok, now);
            } else if w.prewarm.as_ref().is_some_and(|p| p.tok == tok) {
                w.handle_prewarm_readable(now);
            }
        }

        w.drive_timers(Instant::now());
    }

    w.push_telemetry_snapshot();
    Ok(())
}

impl BypassWorker {
    fn effective_target_rtt_ms(&self) -> f64 {
        let lh = self.cfg.lane_hunt.normalized();
        if lh.target_rtt_ms > 0 {
            lh.target_rtt_ms as f64
        } else if let Some(best) = self.best_observed_rtt_ms {
            (best * AUTO_TARGET_MULT).max(best + AUTO_TARGET_ADD_MS)
        } else {
            0.0
        }
    }

    fn round_timeout(&self) -> Duration {
        let tgt = self.effective_target_rtt_ms();
        if tgt <= 0.0 {
            Duration::from_millis(COLD_ROUND_TIMEOUT_MS)
        } else {
            let ms = ((tgt * 2.6) as u64).clamp(ROUND_TIMEOUT_MIN_MS, ROUND_TIMEOUT_MAX_MS);
            Duration::from_millis(ms)
        }
    }

    fn ka_retry_timeout(&self, rtt_hint: Option<f64>) -> Duration {
        let base = self.cfg.retry_ms.max(300);
        if let Some(rtt) = rtt_hint.or(self.best_observed_rtt_ms) {
            let dyn_ms = ((rtt * 2.5) as u64).clamp(base.max(350), 1200);
            Duration::from_millis(dyn_ms)
        } else {
            Duration::from_millis(base.max(450))
        }
    }

    fn next_rotate_deadline(&self, now: Instant) -> Option<Instant> {
        if self.cfg.rotate_interval_secs == 0 {
            None
        } else {
            Some(now + jitter_duration_ms(self.cfg.rotate_interval_secs * 1000))
        }
    }

    fn start_hunt(&mut self, reason: HuntReason, now: Instant) {
        if self.hunt.is_some() {
            return;
        }
        let lh = self.cfg.lane_hunt.normalized();
        let probes = if lh.enabled { lh.probes } else { 2 };
        let is_cold = lh.target_rtt_ms == 0 && self.best_observed_rtt_ms.is_none();
        let min_rounds = if !lh.enabled || matches!(reason, HuntReason::BlackholeEscape { .. }) {
            1
        } else if is_cold {
            let needed = COLD_MIN_PROBES.div_ceil(probes.max(1));
            needed.max(COLD_CALIBRATION_ROUNDS).min(lh.max_rounds.max(2))
        } else {
            1
        };
        let max_rounds = if lh.enabled {
            lh.max_rounds.max(min_rounds)
        } else {
            1
        };
        let mut hunt = BypassHunt {
            reason,
            round: 0,
            max_rounds,
            min_rounds_before_accept: min_rounds,
            target_rtt_ms: self.effective_target_rtt_ms(),
            round_deadline: now,
            early_settle_at: None,
            candidates: Vec::with_capacity(probes),
            best: None,
            total_probed: 0,
        };
        if self.spawn_hunt_round(&mut hunt, probes, now) {
            self.hunt = Some(hunt);
        }
    }

    fn spawn_hunt_round(&mut self, hunt: &mut BypassHunt, probes: usize, now: Instant) -> bool {
        self.clear_hunt_candidates(&mut hunt.candidates);
        let bind_any = unspecified_addr_for(self.cfg.server_addr);
        for i in 0..probes {
            let Ok(mut sock) =
                make_udp_socket(bind_any, Some(self.cfg.server_addr), false, SOCK_BUF_8MIB)
            else {
                continue;
            };
            let local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
            let tok = alloc_token(&mut self.next_token_id);
            if self
                .poll
                .registry()
                .register(&mut sock, tok, Interest::READABLE)
                .is_err()
            {
                continue;
            }
            let ice = SessionIceParams::generate();
            let txid = make_fresh_stun_txid(&self.cfg.psk);
            let (stun_pkt, _) = build_ice_stun_request(&self.cfg.psk, &ice, Some(txid), true);
            let send_at = now + Duration::from_millis((i as u64) * HUNT_STAGGER_MS);
            let sent_at = if i == 0 {
                let _ = sock.send(&stun_pkt);
                Some(now)
            } else {
                None
            };
            let idx = hunt.candidates.len();
            self.hunt_tok_set.insert(tok, idx);
            hunt.candidates.push(HuntCandidate {
                tok,
                sock,
                local_port,
                ice,
                txid,
                stun_pkt,
                send_at,
                sent_at,
                rtt_ms: None,
                mapped_nat: None,
            });
        }
        if hunt.candidates.is_empty() {
            return false;
        }
        hunt.round += 1;
        hunt.total_probed += hunt.candidates.len();
        let stagger = Duration::from_millis(((probes as u64).saturating_sub(1)) * HUNT_STAGGER_MS);
        hunt.round_deadline = now + self.round_timeout() + stagger;
        hunt.early_settle_at = None;
        true
    }

    fn clear_hunt_candidates(&mut self, cands: &mut Vec<HuntCandidate>) {
        for mut c in cands.drain(..) {
            self.hunt_tok_set.remove(&c.tok);
            let _ = self.poll.registry().deregister(&mut c.sock);
        }
    }

    fn update_best_baseline(&mut self, rtt_ms: f64) {
        if !rtt_ms.is_finite() || rtt_ms <= 0.0 {
            return;
        }
        self.best_observed_rtt_ms = Some(match self.best_observed_rtt_ms {
            Some(prev) if rtt_ms < prev => prev * 0.30 + rtt_ms * 0.70,
            Some(prev) => prev,
            None => rtt_ms,
        });
    }

    fn drop_prewarm(&mut self) {
        if let Some(mut pw) = self.prewarm.take() {
            let _ = self.poll.registry().deregister(&mut pw.sock);
        }
    }

    fn push_old_drain(&mut self, old_tok: Token, old_sock: MioUdpSocket, client_addr: SocketAddr, now: Instant) {
        while self.old_drains.len() >= MAX_OLD_DRAINS {
            if let Some(evict_tok) = self.drain_order.pop_front() {
                if let Some(mut d) = self.old_drains.remove(&evict_tok) {
                    let _ = self.poll.registry().deregister(&mut d.sock);
                }
            } else {
                break;
            }
        }
        self.old_drains.insert(
            old_tok,
            OldDrain {
                sock: old_sock,
                client_addr,
                expires_at: now + Duration::from_secs(BYPASS_OLD_PORT_DRAIN_SECS),
            },
        );
        self.drain_order.push_back(old_tok);
    }

    fn ensure_session(&mut self, client_addr: SocketAddr, now: Instant) -> Option<Token> {
        if let Some(&tok) = self.tok_by_client.get(&client_addr) {
            return Some(tok);
        }
        if self.sessions_by_tok.len() >= self.cfg.max_sessions {
            return None;
        }

        if let Some(pw) = self.prewarm.take() {
            let tok = pw.tok;
            self.update_best_baseline(pw.rtt_ms);
            let ref_rtt = self.best_observed_rtt_ms.unwrap_or(pw.rtt_ms);
            let score = compute_lane_score(pw.rtt_ms, ref_rtt, 0.0, 0.0);
            let mut win = VecDeque::with_capacity(STUN_LOSS_WIN_CAP);
            win.push_back(true);
            let sess = BypassSession {
                tok,
                client_addr,
                upstream: pw.sock,
                local_port: pw.local_port,
                ice: pw.ice,
                mapped_nat: pw.mapped_nat,
                last_activity: now,
                last_switched_at: now,
                next_rotate_at: self.next_rotate_deadline(now),
                next_ka_at: now + jitter_duration_ms(self.ka_base_ms),
                pending_ka: None,
                rtt_ewma_ms: Some(pw.rtt_ms),
                last_rtt_ms: Some(pw.rtt_ms),
                jitter_ms: 0.0,
                stun_window: win,
                lane_score: Some(score),
                lane_confirmed: false,
                good_windows: 1,
                degrade_streak: 0,
                last_hunt_at: Some(now),
                migrating: false,
                tx_bytes: 0,
                rx_bytes: 0,
                tx_pkts: 0,
                rx_pkts: 0,
                auth_drops: 0,
            };
            log(
                "bypass-rs",
                self.worker_id,
                &format!(
                    "ADOPT PREWARM client={} up_sport={} rtt={:.1}ms",
                    client_addr, pw.local_port, pw.rtt_ms
                ),
            );
            self.sessions_by_tok.insert(tok, sess);
            self.tok_by_client.insert(client_addr, tok);
            return Some(tok);
        }

        // Immediate non-blocking bind so the very first inner packet experiences 0ms wait;
        // if lane-hunting is enabled, upgrade to a hunted fast lane in the background!
        let bind_any = unspecified_addr_for(self.cfg.server_addr);
        let mut up = make_udp_socket(bind_any, Some(self.cfg.server_addr), false, SOCK_BUF_8MIB).ok()?;
        let local_port = up.local_addr().map(|a| a.port()).unwrap_or(0);
        let tok = alloc_token(&mut self.next_token_id);
        if self
            .poll
            .registry()
            .register(&mut up, tok, Interest::READABLE)
            .is_err()
        {
            return None;
        }
        let ice = SessionIceParams::generate();
        let sess = BypassSession {
            tok,
            client_addr,
            upstream: up,
            local_port,
            ice,
            mapped_nat: None,
            last_activity: now,
            last_switched_at: now,
            next_rotate_at: self.next_rotate_deadline(now),
            next_ka_at: now,
            pending_ka: None,
            rtt_ewma_ms: None,
            last_rtt_ms: None,
            jitter_ms: 0.0,
            stun_window: VecDeque::with_capacity(STUN_LOSS_WIN_CAP),
            lane_score: None,
            lane_confirmed: false,
            good_windows: 0,
            degrade_streak: 0,
            last_hunt_at: None,
            migrating: false,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_pkts: 0,
            rx_pkts: 0,
            auth_drops: 0,
        };
        self.sessions_by_tok.insert(tok, sess);
        self.tok_by_client.insert(client_addr, tok);

        if self.cfg.lane_hunt.enabled {
            if let Some(ref mut h) = self.hunt {
                if matches!(h.reason, HuntReason::PreWarm) {
                    h.reason = HuntReason::UpgradeInitial { client_addr };
                }
            } else {
                self.start_hunt(HuntReason::UpgradeInitial { client_addr }, now);
            }
        }
        Some(tok)
    }

    fn handle_local_readable(&mut self, now: Instant) {
        if self.rx_batch.is_some() && self.tx_batch.is_some() {
            let mut rx_b = self.rx_batch.take().unwrap();
            let mut tx_b = self.tx_batch.take().unwrap();
            loop {
                match rx_b.recv_from(&self.listen_sock) {
                    Ok(count) => {
                        let mut cur_tok: Option<Token> = None;
                        for i in 0..count {
                            let Some(client_addr) = rx_b.peer(i) else {
                                continue;
                            };
                            let pkt = rx_b.packet(i);
                            if pkt.is_empty() {
                                continue;
                            }
                            let Some(tok) = self.ensure_session(client_addr, now) else {
                                continue;
                            };
                            if cur_tok != Some(tok) {
                                if let Some(prev_t) = cur_tok.take() {
                                    self.flush_tx_batch_to_session(prev_t, &mut tx_b, now);
                                }
                                cur_tok = Some(tok);
                            }
                            if tx_b.is_full() {
                                self.flush_tx_batch_to_session(tok, &mut tx_b, now);
                            }
                            if let Some(slot) = tx_b.next_slot_mut() {
                                if pkt.len() <= slot.len() {
                                    slot[..pkt.len()].copy_from_slice(pkt);
                                    tx_b.commit_slot(pkt.len(), pkt.len() as u64, None);
                                }
                            }
                        }
                        if let Some(prev_t) = cur_tok {
                            self.flush_tx_batch_to_session(prev_t, &mut tx_b, now);
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            self.rx_batch = Some(rx_b);
            self.tx_batch = Some(tx_b);
            return;
        }

        loop {
            let (n, client_addr) = match self.listen_sock.recv_from(&mut self.rbuf) {
                Ok(v) => v,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if n == 0 {
                continue;
            }
            let Some(tok) = self.ensure_session(client_addr, now) else {
                continue;
            };
            if let Some(sess) = self.sessions_by_tok.get_mut(&tok) {
                if sess.upstream.send(&self.rbuf[..n]).is_ok() {
                    sess.tx_pkts = sess.tx_pkts.saturating_add(1);
                    sess.tx_bytes = sess.tx_bytes.saturating_add(n as u64);
                    sess.last_activity = now;
                }
            }
        }
    }

    fn flush_tx_batch_to_session(&mut self, tok: Token, tx_b: &mut UdpSendBatch, now: Instant) {
        if tx_b.is_empty() {
            return;
        }
        if let Some(sess) = self.sessions_by_tok.get_mut(&tok) {
            let (sp, sb) = tx_b.flush_connected(&sess.upstream);
            if sp > 0 {
                sess.tx_pkts = sess.tx_pkts.saturating_add(sp as u64);
                sess.tx_bytes = sess.tx_bytes.saturating_add(sb);
                sess.last_activity = now;
            }
        } else {
            let _ = tx_b;
        }
    }

    fn handle_upstream_readable(&mut self, tok: Token, now: Instant) {
        if self.rx_batch.is_some() && self.tx_batch.is_some() {
            let mut rx_b = self.rx_batch.take().unwrap();
            let mut tx_b = self.tx_batch.take().unwrap();
            while let Some((recv_res, client_addr)) = self
                .sessions_by_tok
                .get(&tok)
                .map(|s| (rx_b.recv_connected(&s.upstream), s.client_addr))
            {
                match recv_res {
                    Ok(count) => {
                        let mut stun_frames: Vec<Vec<u8>> = Vec::new();
                        for i in 0..count {
                            let pkt = rx_b.packet(i);
                            if pkt.is_empty() {
                                continue;
                            }
                            if is_stun_wire_packet(pkt) {
                                stun_frames.push(pkt.to_vec());
                                continue;
                            }
                            if tx_b.is_full() {
                                let (sp, sb) = tx_b.flush_to(&self.listen_sock);
                                if let Some(s) = self.sessions_by_tok.get_mut(&tok) {
                                    s.rx_pkts = s.rx_pkts.saturating_add(sp as u64);
                                    s.rx_bytes = s.rx_bytes.saturating_add(sb);
                                    s.last_activity = now;
                                }
                            }
                            if let Some(slot) = tx_b.next_slot_mut() {
                                if pkt.len() <= slot.len() {
                                    slot[..pkt.len()].copy_from_slice(pkt);
                                    tx_b.commit_slot(
                                        pkt.len(),
                                        pkt.len() as u64,
                                        Some(client_addr),
                                    );
                                }
                            }
                        }
                        if !tx_b.is_empty() {
                            let (sp, sb) = tx_b.flush_to(&self.listen_sock);
                            if let Some(s) = self.sessions_by_tok.get_mut(&tok) {
                                s.rx_pkts = s.rx_pkts.saturating_add(sp as u64);
                                s.rx_bytes = s.rx_bytes.saturating_add(sb);
                                s.last_activity = now;
                            }
                        }
                        for sf in stun_frames {
                            self.process_session_stun(tok, &sf, now);
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            self.rx_batch = Some(rx_b);
            self.tx_batch = Some(tx_b);
            return;
        }

        while let Some(sess) = self.sessions_by_tok.get(&tok) {
            let (n, client_addr) = match sess.upstream.recv(&mut self.rbuf) {
                Ok(n) => (n, sess.client_addr),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if n == 0 {
                continue;
            }
            if is_stun_wire_packet(&self.rbuf[..n]) {
                let sf = self.rbuf[..n].to_vec();
                self.process_session_stun(tok, &sf, now);
                continue;
            }
            if self.listen_sock.send_to(&self.rbuf[..n], client_addr).is_ok() {
                if let Some(s) = self.sessions_by_tok.get_mut(&tok) {
                    s.rx_pkts = s.rx_pkts.saturating_add(1);
                    s.rx_bytes = s.rx_bytes.saturating_add(n as u64);
                    s.last_activity = now;
                }
            }
        }
    }

    fn handle_drain_readable(&mut self, tok: Token, now: Instant) {
        while let Some(d) = self.old_drains.get(&tok) {
            let (n, client_addr) = match d.sock.recv(&mut self.rbuf) {
                Ok(n) => (n, d.client_addr),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if n == 0 || is_stun_wire_packet(&self.rbuf[..n]) {
                continue;
            }
            if self.listen_sock.send_to(&self.rbuf[..n], client_addr).is_ok() {
                if let Some(&active_tok) = self.tok_by_client.get(&client_addr) {
                    if let Some(s) = self.sessions_by_tok.get_mut(&active_tok) {
                        s.rx_pkts = s.rx_pkts.saturating_add(1);
                        s.rx_bytes = s.rx_bytes.saturating_add(n as u64);
                        s.last_activity = now;
                    }
                }
            }
        }
    }

    fn process_session_stun(&mut self, tok: Token, pkt: &[u8], now: Instant) {
        let Some(parsed) = parse_stun(pkt, &self.cfg.psk) else {
            if let Some(s) = self.sessions_by_tok.get_mut(&tok) {
                s.auth_drops = s.auth_drops.saturating_add(1);
            }
            return;
        };
        if !parsed.authenticated || parsed.msg_type != STUN_BINDING_SUCCESS {
            if let Some(s) = self.sessions_by_tok.get_mut(&tok) {
                s.auth_drops = s.auth_drops.saturating_add(1);
            }
            return;
        }

        let mut trigger_degrade_client: Option<SocketAddr> = None;
        let mut rtt_sample_opt: Option<(f64, u8, Option<SocketAddr>)> = None;

        if let Some(s) = self.sessions_by_tok.get_mut(&tok) {
            let Some(ref ka) = s.pending_ka else {
                return;
            };
            if parsed.txid != ka.txid {
                return;
            }
            let first_sent = ka.first_sent;
            let retries = ka.retries;
            s.pending_ka = None;
            s.migrating = false;
            let rtt_ms = now.saturating_duration_since(first_sent).as_secs_f64() * 1000.0;
            if let Some(prev) = s.last_rtt_ms {
                let d = (rtt_ms - prev).abs();
                s.jitter_ms += (d - s.jitter_ms) / 4.0;
            }
            s.last_rtt_ms = Some(rtt_ms);
            let ewma = match s.rtt_ewma_ms {
                Some(prev) => prev * (1.0 - RTT_EWMA_ALPHA) + rtt_ms * RTT_EWMA_ALPHA,
                None => rtt_ms,
            };
            s.rtt_ewma_ms = Some(ewma);
            if parsed.xor_mapped.is_some() {
                s.mapped_nat = parsed.xor_mapped;
            }
            for _ in 0..retries {
                if s.stun_window.len() >= STUN_LOSS_WIN_CAP {
                    s.stun_window.pop_front();
                }
                s.stun_window.push_back(false);
            }
            if s.stun_window.len() >= STUN_LOSS_WIN_CAP {
                s.stun_window.pop_front();
            }
            s.stun_window.push_back(true);

            let idle_secs = now.saturating_duration_since(s.last_activity).as_secs();
            let next_base = if idle_secs >= IDLE_BACKOFF_AFTER_SECS {
                IDLE_KA_BASE_MS
            } else {
                self.ka_base_ms
            };
            s.next_ka_at = now + jitter_duration_ms(next_base);
            rtt_sample_opt = Some((rtt_ms, retries, parsed.xor_mapped));
        }

        let Some((rtt_ms, retries, mapped)) = rtt_sample_opt else {
            return;
        };
        self.update_best_baseline(rtt_ms);
        if let Some(ref th) = self.telemetry {
            th.record_stun_ok(rtt_ms, retries, mapped);
        }

        if let Some(s) = self.sessions_by_tok.get_mut(&tok) {
            let ewma = s.rtt_ewma_ms.unwrap_or(rtt_ms);
            let ref_rtt = self.best_observed_rtt_ms.unwrap_or(ewma);
            let lost = s.stun_window.iter().filter(|&&ok| !ok).count();
            // Single-loss immunity so 1 stray UDP drop doesn't trigger spurious switching
            let loss_eff = if lost <= 1 || s.stun_window.is_empty() {
                0.0
            } else {
                (lost - 1) as f64 / (s.stun_window.len() as f64)
            };
            let score = compute_lane_score(ewma, ref_rtt, loss_eff, s.jitter_ms);
            s.lane_score = Some(score);

            if score >= CONFIRM_SCORE_THRESHOLD {
                s.degrade_streak = 0;
                s.good_windows = s.good_windows.saturating_add(1);
                if !s.lane_confirmed && s.good_windows >= CONFIRM_GOOD_WINDOWS {
                    s.lane_confirmed = true;
                    self.trial_fail_streak = 0;
                }
            } else if score < DEGRADE_SCORE_THRESHOLD {
                s.degrade_streak = s.degrade_streak.saturating_add(1);
                let needed = if s.lane_confirmed {
                    DEGRADE_CONSECUTIVE
                } else {
                    TRIAL_DEGRADE_CONSECUTIVE
                };
                if s.degrade_streak >= needed && self.cfg.lane_hunt.enabled {
                    let cd_secs = if !s.lane_confirmed
                        && self.trial_fail_streak < MAX_FAST_TRIAL_RETRIES
                    {
                        self.cfg
                            .lane_hunt
                            .degrade_cooldown_secs
                            .min(TRIAL_FAIL_COOLDOWN_SECS)
                    } else {
                        self.cfg.lane_hunt.degrade_cooldown_secs
                    };
                    let cd_ok = s
                        .last_hunt_at
                        .map(|t| now.saturating_duration_since(t) >= Duration::from_secs(cd_secs))
                        .unwrap_or(true);
                    if cd_ok {
                        s.degrade_streak = 0;
                        s.last_hunt_at = Some(now);
                        if !s.lane_confirmed {
                            self.trial_fail_streak = self.trial_fail_streak.saturating_add(1);
                        }
                        trigger_degrade_client = Some(s.client_addr);
                    }
                }
            } else {
                s.degrade_streak = 0;
            }
        }

        if let Some(client_addr) = trigger_degrade_client {
            self.start_hunt(HuntReason::DegradeRtt { client_addr }, now);
        }
    }

    fn handle_prewarm_readable(&mut self, now: Instant) {
        let Some(ref mut pw) = self.prewarm else {
            return;
        };
        loop {
            let n = match pw.sock.recv(&mut self.rbuf) {
                Ok(n) => n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if !is_stun_wire_packet(&self.rbuf[..n]) {
                continue;
            }
            if let Some(parsed) = parse_stun(&self.rbuf[..n], &self.cfg.psk) {
                if parsed.authenticated && parsed.msg_type == STUN_BINDING_SUCCESS {
                    if let Some((txid, sent_at)) = pw.pending_txid {
                        if parsed.txid == txid {
                            pw.rtt_ms =
                                now.saturating_duration_since(sent_at).as_secs_f64() * 1000.0;
                            pw.pending_txid = None;
                            pw.next_refresh_at =
                                now + Duration::from_millis(PREWARM_KEEP_FRESH_MS);
                            if parsed.xor_mapped.is_some() {
                                pw.mapped_nat = parsed.xor_mapped;
                            }
                        }
                    }
                }
            }
        }
    }

    fn handle_hunt_readable(&mut self, tok: Token, now: Instant) {
        let Some(&idx) = self.hunt_tok_set.get(&tok) else {
            return;
        };
        let mut matched: Option<(f64, Option<SocketAddr>)> = None;
        if let Some(ref mut hunt) = self.hunt {
            if let Some(c) = hunt.candidates.get_mut(idx) {
                loop {
                    match c.sock.recv(&mut self.rbuf) {
                        Ok(n) => {
                            if !is_stun_wire_packet(&self.rbuf[..n]) {
                                continue;
                            }
                            if let Some(parsed) = parse_stun(&self.rbuf[..n], &self.cfg.psk) {
                                if parsed.authenticated
                                    && parsed.msg_type == STUN_BINDING_SUCCESS
                                    && parsed.txid == c.txid
                                {
                                    if let Some(sent) = c.sent_at {
                                        let rtt =
                                            now.saturating_duration_since(sent).as_secs_f64()
                                                * 1000.0;
                                        c.rtt_ms = Some(rtt);
                                        c.mapped_nat = parsed.xor_mapped;
                                        matched = Some((rtt, parsed.xor_mapped));
                                    }
                                }
                            }
                        }
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
        }

        if let Some((rtt, _mapped)) = matched {
            self.update_best_baseline(rtt);
            let new_tgt = self.effective_target_rtt_ms();
            let mut finish_now = false;
            if let Some(ref mut hunt) = self.hunt {
                hunt.target_rtt_ms = new_tgt;
                // Blackhole escape prioritizes immediate recovery once all candidates in round 1 reply or settle!
                if matches!(hunt.reason, HuntReason::BlackholeEscape { .. }) {
                    let margin = (rtt + EARLY_SETTLE_MARGIN_MS)
                        .clamp(EARLY_SETTLE_MIN_MS as f64, EARLY_SETTLE_MAX_MS as f64);
                    let settle = now + Duration::from_millis(margin as u64);
                    hunt.early_settle_at = Some(
                        hunt.early_settle_at
                            .map(|prev| prev.min(settle))
                            .unwrap_or(settle),
                    );
                } else if hunt.round >= hunt.min_rounds_before_accept {
                    let hit_target = hunt.target_rtt_ms > 0.0 && rtt <= hunt.target_rtt_ms;
                    if hit_target || hunt.target_rtt_ms <= 0.0 {
                        let margin = (rtt + EARLY_SETTLE_MARGIN_MS)
                            .clamp(EARLY_SETTLE_MIN_MS as f64, EARLY_SETTLE_MAX_MS as f64);
                        let settle = now + Duration::from_millis(margin as u64);
                        hunt.early_settle_at = Some(
                            hunt.early_settle_at
                                .map(|prev| prev.min(settle))
                                .unwrap_or(settle),
                        );
                    }
                }
                if hunt.candidates.iter().all(|c| c.rtt_ms.is_some())
                    && hunt.round >= hunt.min_rounds_before_accept
                {
                    let best_round = hunt
                        .candidates
                        .iter()
                        .filter_map(|c| c.rtt_ms)
                        .fold(f64::INFINITY, f64::min);
                    if matches!(hunt.reason, HuntReason::BlackholeEscape { .. })
                        || hunt.target_rtt_ms <= 0.0
                        || best_round <= hunt.target_rtt_ms
                        || hunt.round >= hunt.max_rounds
                    {
                        finish_now = true;
                    }
                }
            }
            if finish_now {
                self.advance_or_finish_hunt(now, true);
            }
        }
    }

    fn harvest_round_best(&mut self, hunt: &mut BypassHunt) {
        let mut best_idx: Option<usize> = None;
        let mut best_rtt = hunt
            .best
            .as_ref()
            .map(|b| b.4)
            .unwrap_or(f64::INFINITY);
        for (i, c) in hunt.candidates.iter().enumerate() {
            if let Some(r) = c.rtt_ms {
                if r < best_rtt {
                    best_rtt = r;
                    best_idx = Some(i);
                }
            }
        }
        let mut cands = std::mem::take(&mut hunt.candidates);
        for (i, mut c) in cands.drain(..).enumerate() {
            self.hunt_tok_set.remove(&c.tok);
            if Some(i) == best_idx {
                if let Some((mut prev_sock, _, _, _, _, _)) = hunt.best.take() {
                    let _ = self.poll.registry().deregister(&mut prev_sock);
                }
                let r = c.rtt_ms.unwrap_or(best_rtt);
                hunt.best = Some((c.sock, c.tok, c.local_port, c.ice, r, c.mapped_nat));
            } else {
                let _ = self.poll.registry().deregister(&mut c.sock);
            }
        }
    }

    fn advance_or_finish_hunt(&mut self, now: Instant, force_accept: bool) {
        let Some(mut hunt) = self.hunt.take() else {
            return;
        };
        self.harvest_round_best(&mut hunt);
        hunt.target_rtt_ms = self.effective_target_rtt_ms();

        let have_best = hunt.best.is_some();
        let best_rtt = hunt.best.as_ref().map(|b| b.4).unwrap_or(f64::INFINITY);
        let met_target = have_best
            && hunt.round >= hunt.min_rounds_before_accept
            && (force_accept
                || matches!(hunt.reason, HuntReason::BlackholeEscape { .. })
                || hunt.target_rtt_ms <= 0.0
                || best_rtt <= hunt.target_rtt_ms);

        if !met_target && hunt.round < hunt.max_rounds {
            let probes = if self.cfg.lane_hunt.enabled {
                self.cfg.lane_hunt.normalized().probes
            } else {
                2
            };
            if self.spawn_hunt_round(&mut hunt, probes, now) {
                self.hunt = Some(hunt);
                return;
            }
        }

        let Some((mut win_sock, win_tok, win_port, win_ice, win_rtt, win_mapped)) = hunt.best
        else {
            if matches!(hunt.reason, HuntReason::PreWarm) {
                self.next_prewarm_at = Some(now + Duration::from_millis(PREWARM_RETRY_MS));
            }
            return;
        };

        if let Some(ref th) = self.telemetry {
            th.record_stun_ok(win_rtt, 0, win_mapped);
        }

        match hunt.reason {
            HuntReason::PreWarm => {
                self.drop_prewarm();
                log(
                    "bypass-rs",
                    self.worker_id,
                    &format!(
                        "PREWARM READY up_sport={} rtt={:.1}ms probed={}",
                        win_port, win_rtt, hunt.total_probed
                    ),
                );
                if let Some(ref th) = self.telemetry {
                    th.record_lane_hunt(
                        false,
                        format!(
                            "prewarm up_sport={} rtt={:.1}ms probed={}",
                            win_port, win_rtt, hunt.total_probed
                        ),
                    );
                }
                self.prewarm = Some(PrewarmedSocket {
                    tok: win_tok,
                    sock: win_sock,
                    local_port: win_port,
                    ice: win_ice,
                    rtt_ms: win_rtt,
                    mapped_nat: win_mapped,
                    next_refresh_at: now + Duration::from_millis(PREWARM_KEEP_FRESH_MS),
                    pending_txid: None,
                });
            }
            HuntReason::UpgradeInitial { client_addr }
            | HuntReason::DegradeRtt { client_addr }
            | HuntReason::BlackholeEscape { client_addr }
            | HuntReason::ScheduledRotate { client_addr } => {
                let Some(&old_tok) = self.tok_by_client.get(&client_addr) else {
                    let _ = self.poll.registry().deregister(&mut win_sock);
                    return;
                };
                let should_swap = match self.sessions_by_tok.get(&old_tok) {
                    Some(cur) => match hunt.reason {
                        HuntReason::BlackholeEscape { .. }
                        | HuntReason::ScheduledRotate { .. } => true,
                        HuntReason::UpgradeInitial { .. } => cur
                            .rtt_ewma_ms
                            .map(|cur_rtt| win_rtt + 5.0 < cur_rtt)
                            .unwrap_or(true),
                        HuntReason::DegradeRtt { .. } => {
                            if let Some(cur_rtt) = cur.rtt_ewma_ms {
                                let hit_tgt =
                                    hunt.target_rtt_ms > 0.0 && win_rtt <= hunt.target_rtt_ms;
                                let sig_gain = (cur_rtt - win_rtt) >= IMPROVE_MIN_DELTA_MS
                                    && win_rtt <= cur_rtt * IMPROVE_MAX_RATIO;
                                hit_tgt || sig_gain
                            } else {
                                true
                            }
                        }
                        HuntReason::PreWarm => false,
                    },
                    None => false,
                };

                if !should_swap {
                    let _ = self.poll.registry().deregister(&mut win_sock);
                    if let Some(ref th) = self.telemetry {
                        th.record_lane_hunt(
                            false,
                            format!(
                                "keep-current candidate_rtt={:.1}ms probed={}",
                                win_rtt, hunt.total_probed
                            ),
                        );
                    }
                    return;
                }

                let Some(mut sess) = self.sessions_by_tok.remove(&old_tok) else {
                    let _ = self.poll.registry().deregister(&mut win_sock);
                    return;
                };
                let old_port = sess.local_port;
                let old_sock = std::mem::replace(&mut sess.upstream, win_sock);
                self.push_old_drain(old_tok, old_sock, client_addr, now);

                let ref_rtt = self.best_observed_rtt_ms.unwrap_or(win_rtt);
                let score = compute_lane_score(win_rtt, ref_rtt, 0.0, 0.0);
                sess.tok = win_tok;
                sess.local_port = win_port;
                sess.ice = win_ice;
                if win_mapped.is_some() {
                    sess.mapped_nat = win_mapped;
                }
                sess.last_switched_at = now;
                sess.pending_ka = None;
                sess.migrating = false;
                sess.rtt_ewma_ms = Some(win_rtt);
                sess.last_rtt_ms = Some(win_rtt);
                sess.jitter_ms = 0.0;
                sess.stun_window.clear();
                sess.stun_window.push_back(true);
                sess.lane_score = Some(score);
                sess.lane_confirmed = false;
                sess.good_windows = 1;
                sess.degrade_streak = 0;
                sess.last_hunt_at = Some(now);
                sess.next_ka_at = now + jitter_duration_ms(self.ka_base_ms);
                if matches!(hunt.reason, HuntReason::ScheduledRotate { .. }) {
                    sess.next_rotate_at = self.next_rotate_deadline(now);
                }

                self.tok_by_client.insert(client_addr, win_tok);
                self.sessions_by_tok.insert(win_tok, sess);

                log(
                    "bypass-rs",
                    self.worker_id,
                    &format!(
                        "LANE SWITCH {} -> {} rtt={:.1}ms probed={}",
                        old_port, win_port, win_rtt, hunt.total_probed
                    ),
                );
                if let Some(ref th) = self.telemetry {
                    let detail = format!(
                        "{}->{} rtt={:.1}ms probed={}",
                        old_port, win_port, win_rtt, hunt.total_probed
                    );
                    match hunt.reason {
                        HuntReason::BlackholeEscape { .. } => {
                            th.record_migration_1rtt(detail.clone());
                            th.record_lane_hunt(true, detail);
                        }
                        HuntReason::ScheduledRotate { .. } => {
                            th.record_mbb_rotation(detail.clone());
                            th.record_lane_hunt(true, detail);
                        }
                        _ => th.record_lane_hunt(true, detail),
                    }
                }
            }
        }
    }

    fn drive_timers(&mut self, now: Instant) {
        // 1. Staggered hunt candidate sends & round deadlines
        let mut finish_early = false;
        let mut round_timed_out = false;
        if let Some(ref mut hunt) = self.hunt {
            for c in &mut hunt.candidates {
                if c.sent_at.is_none() && now >= c.send_at {
                    let _ = c.sock.send(&c.stun_pkt);
                    c.sent_at = Some(now);
                }
            }
            if let Some(early) = hunt.early_settle_at {
                if now >= early {
                    finish_early = true;
                }
            }
            if now >= hunt.round_deadline {
                round_timed_out = true;
            }
        }
        if finish_early || round_timed_out {
            self.advance_or_finish_hunt(now, finish_early);
        }

        // 2. Expire old draining sockets
        while let Some(&tok) = self.drain_order.front() {
            let expired = self
                .old_drains
                .get(&tok)
                .map(|d| now >= d.expires_at)
                .unwrap_or(true);
            if expired {
                self.drain_order.pop_front();
                if let Some(mut d) = self.old_drains.remove(&tok) {
                    let _ = self.poll.registry().deregister(&mut d.sock);
                }
            } else {
                break;
            }
        }

        // 3. Prewarm refresh or re-arm when idle
        if self.sessions_by_tok.is_empty() && self.hunt.is_none() && self.cfg.lane_hunt.enabled {
            if let Some(ref mut pw) = self.prewarm {
                if let Some((_, sent_at)) = pw.pending_txid {
                    if now.saturating_duration_since(sent_at) >= Duration::from_secs(2) {
                        self.drop_prewarm();
                        self.next_prewarm_at = Some(now + Duration::from_millis(PREWARM_RETRY_MS));
                    }
                } else if now >= pw.next_refresh_at {
                    let txid = make_fresh_stun_txid(&self.cfg.psk);
                    let (pkt, _) =
                        build_ice_stun_request(&self.cfg.psk, &pw.ice, Some(txid), false);
                    let _ = pw.sock.send(&pkt);
                    pw.pending_txid = Some((txid, now));
                }
            } else if self.next_prewarm_at.is_some_and(|t| now >= t) {
                self.next_prewarm_at = None;
                self.start_hunt(HuntReason::PreWarm, now);
            }
        }

        // 4. Active session idle expiry, STUN keepalive, blackhole escape & timed rotation
        let mut expired_toks = Vec::new();
        let mut escape_client: Option<(SocketAddr, u16, u8)> = None;
        let mut rotate_client: Option<SocketAddr> = None;
        let ka_retry_default = self.ka_retry_timeout(None);
        let rot_iv_secs = self.cfg.rotate_interval_secs;
        let hunt_busy = self.hunt.is_some();

        for (&tok, s) in &mut self.sessions_by_tok {
            if self.cfg.idle_timeout_secs > 0
                && now.saturating_duration_since(s.last_activity) >= self.idle_dur
            {
                expired_toks.push(tok);
                continue;
            }

            let retry_dur = if let Some(rtt) = s.rtt_ewma_ms {
                Duration::from_millis(((rtt * 2.5) as u64).clamp(350, 1200))
            } else {
                ka_retry_default
            };

            if let Some(ka) = s.pending_ka.clone() {
                if now >= ka.retry_at {
                    let base_r = (self.cfg.max_retries.clamp(1, 10) as u8).max(KA_MAX_RETRIES);
                    let max_r = if now.saturating_duration_since(s.last_switched_at)
                        <= Duration::from_secs(RECENT_SWITCH_DAMP_SECS)
                    {
                        base_r.max(KA_MAX_RETRIES_DAMPED)
                    } else {
                        base_r
                    };
                    if ka.retries < max_r {
                        let _ = s.upstream.send(&ka.pkt);
                        s.pending_ka = Some(PendingKa {
                            txid: ka.txid,
                            pkt: ka.pkt,
                            first_sent: ka.first_sent,
                            retry_at: now + retry_dur,
                            retries: ka.retries + 1,
                        });
                    } else {
                        s.pending_ka = None;
                        s.migrating = true;
                        s.next_ka_at = now + Duration::from_secs(2);
                        if escape_client.is_none() {
                            escape_client = Some((s.client_addr, s.local_port, ka.retries + 1));
                        }
                    }
                }
            } else if now >= s.next_ka_at {
                let txid = make_fresh_stun_txid(&self.cfg.psk);
                let (pkt, _) = build_ice_stun_request(&self.cfg.psk, &s.ice, Some(txid), false);
                let _ = s.upstream.send(&pkt);
                s.pending_ka = Some(PendingKa {
                    txid,
                    pkt,
                    first_sent: now,
                    retry_at: now + retry_dur,
                    retries: 0,
                });
            }

            if let Some(rot_at) = s.next_rotate_at {
                if now >= rot_at {
                    let active_recently = now.saturating_duration_since(s.last_activity)
                        <= Duration::from_secs(ACTIVE_TRAFFIC_WINDOW_SECS);
                    if active_recently && rotate_client.is_none() && !hunt_busy {
                        rotate_client = Some(s.client_addr);
                    }
                    s.next_rotate_at = (rot_iv_secs > 0)
                        .then(|| now + jitter_duration_ms(rot_iv_secs * 1000));
                }
            }
        }

        for tok in expired_toks {
            if let Some(mut s) = self.sessions_by_tok.remove(&tok) {
                self.tok_by_client.remove(&s.client_addr);
                let _ = self.poll.registry().deregister(&mut s.upstream);
                self.closed_tx_bytes = self.closed_tx_bytes.saturating_add(s.tx_bytes);
                self.closed_rx_bytes = self.closed_rx_bytes.saturating_add(s.rx_bytes);
                self.closed_tx_pkts = self.closed_tx_pkts.saturating_add(s.tx_pkts);
                self.closed_rx_pkts = self.closed_rx_pkts.saturating_add(s.rx_pkts);
                self.closed_auth_drops = self.closed_auth_drops.saturating_add(s.auth_drops);
            }
            if self.sessions_by_tok.is_empty() && self.cfg.lane_hunt.enabled && self.prewarm.is_none()
            {
                self.next_prewarm_at = Some(now + Duration::from_secs(1));
            }
        }

        if let Some((client_addr, old_sport, attempts)) = escape_client {
            if let Some(ref th) = self.telemetry {
                th.record_blackhole(
                    attempts,
                    format!("bypass up_sport={} unanswered={}", old_sport, attempts),
                );
            }
            if let Some(mut prev_hunt) = self.hunt.take() {
                self.clear_hunt_candidates(&mut prev_hunt.candidates);
                if let Some((mut bs, _, _, _, _, _)) = prev_hunt.best {
                    let _ = self.poll.registry().deregister(&mut bs);
                }
            }
            self.start_hunt(HuntReason::BlackholeEscape { client_addr }, now);
        } else if let Some(client_addr) = rotate_client {
            self.start_hunt(HuntReason::ScheduledRotate { client_addr }, now);
        }

        // 5. Periodic stats & telemetry
        if self.cfg.stats_interval_secs > 0 && now.duration_since(self.last_stats) >= self.stats_dur
        {
            self.last_stats = now;
            if !self.sessions_by_tok.is_empty() {
                let tx_b: u64 = self
                    .closed_tx_bytes
                    .saturating_add(self.sessions_by_tok.values().map(|s| s.tx_bytes).sum());
                let rx_b: u64 = self
                    .closed_rx_bytes
                    .saturating_add(self.sessions_by_tok.values().map(|s| s.rx_bytes).sum());
                log(
                    "bypass-rs",
                    self.worker_id,
                    &format!(
                        "stats sessions={} tx={}B rx={}B best_rtt={:?}ms",
                        self.sessions_by_tok.len(),
                        tx_b,
                        rx_b,
                        self.best_observed_rtt_ms.map(|v| (v * 10.0).round() / 10.0)
                    ),
                );
            }
        }

        if self.telemetry.is_some()
            && now.duration_since(self.last_telemetry) >= self.telemetry_dur
        {
            self.last_telemetry = now;
            self.push_telemetry_snapshot();
        }
    }

    fn push_telemetry_snapshot(&self) {
        let Some(ref th) = self.telemetry else {
            return;
        };
        let mut active = 0usize;
        let mut migrating = 0usize;
        let mut tx_bytes = self.closed_tx_bytes;
        let mut rx_bytes = self.closed_rx_bytes;
        let mut tx_pkts = self.closed_tx_pkts;
        let mut rx_pkts = self.closed_rx_pkts;
        let mut auth_drops = self.closed_auth_drops;
        let mut up_sport = self.prewarm.as_ref().map(|p| p.local_port).unwrap_or(0);
        let mut lane_score: Option<f64> = None;
        let mut all_confirmed = !self.sessions_by_tok.is_empty();

        for s in self.sessions_by_tok.values() {
            if s.migrating {
                migrating += 1;
            } else {
                active += 1;
            }
            tx_bytes = tx_bytes.saturating_add(s.tx_bytes);
            rx_bytes = rx_bytes.saturating_add(s.rx_bytes);
            tx_pkts = tx_pkts.saturating_add(s.tx_pkts);
            rx_pkts = rx_pkts.saturating_add(s.rx_pkts);
            auth_drops = auth_drops.saturating_add(s.auth_drops);
            if s.local_port != 0 {
                up_sport = s.local_port;
            }
            if !s.lane_confirmed {
                all_confirmed = false;
            }
            if let Some(sc) = s.lane_score {
                lane_score = Some(lane_score.map(|p| p.min(sc)).unwrap_or(sc));
            }
        }

        th.update_worker(
            self.worker_id,
            WorkerSnapshot {
                active_sessions: active,
                handshaking_sessions: 0,
                migrating_sessions: migrating,
                tx_bytes_total: tx_bytes,
                rx_bytes_total: rx_bytes,
                tx_pkts_total: tx_pkts,
                rx_pkts_total: rx_pkts,
                auth_drops_total: auth_drops,
                unauth_drops_total: 0,
                active_up_sport: up_sport,
                active_backend_sport: 0,
                data_loss_pct: 0.0,
                lane_score,
                lane_best_rtt_ms: self.best_observed_rtt_ms,
                lane_confirmed: all_confirmed,
                dtls_version: "none",
                cipher: "bypass-raw",
                dual_ssrc: false,
            },
        );
    }

    fn next_poll_timeout(&self, now: Instant) -> Duration {
        let mut earliest: Option<Instant> = None;
        let mut consider = |t: Instant| {
            earliest = Some(match earliest {
                Some(prev) => prev.min(t),
                None => t,
            });
        };

        if let Some(ref hunt) = self.hunt {
            consider(hunt.round_deadline);
            if let Some(early) = hunt.early_settle_at {
                consider(early);
            }
            for c in &hunt.candidates {
                if c.sent_at.is_none() {
                    consider(c.send_at);
                }
            }
        }
        if let Some(t) = self.next_prewarm_at {
            consider(t);
        }
        if let Some(ref pw) = self.prewarm {
            consider(pw.next_refresh_at);
        }
        for s in self.sessions_by_tok.values() {
            if let Some(ref ka) = s.pending_ka {
                consider(ka.retry_at);
            } else {
                consider(s.next_ka_at);
            }
            if let Some(rot) = s.next_rotate_at {
                consider(rot);
            }
        }
        if let Some(&front_tok) = self.drain_order.front() {
            if let Some(d) = self.old_drains.get(&front_tok) {
                consider(d.expires_at);
            }
        }
        if self.telemetry.is_some() {
            consider(self.last_telemetry + self.telemetry_dur);
        }

        let max_wait = if self.cfg.stop.is_some() {
            Duration::from_millis(WORKER_QUIET_STOP_POLL_MS)
        } else if self.sessions_by_tok.is_empty() && self.hunt.is_none() {
            Duration::from_secs(WORKER_IDLE_POLL_SECS)
        } else {
            Duration::from_secs(WORKER_ACTIVE_POLL_SECS)
        };

        match earliest {
            Some(target) => {
                let raw = target.saturating_duration_since(now);
                let min_floor = if self.hunt.is_some() {
                    Duration::from_millis(WORKER_MIN_FAST_WAIT_MS)
                } else {
                    Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS)
                };
                raw.max(min_floor).min(max_wait)
            }
            None => max_wait,
        }
    }
}
