//! 外层链路健康状态聚合与只读遥测中心。

mod export;
#[cfg(test)]
mod tests;

use self::export::{handle_http_request, write_atomic_file};
use crate::constants::TELEMETRY_DEFAULT_INTERVAL_SECS;
use serde::Serialize;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tiny_http::Server as HttpServer;

/// `--status-interval` 允许的最小刷新间隔（秒）。
const TELEMETRY_INTERVAL_MIN_SECS: u64 = 1;
/// `--status-interval` 允许的最大刷新间隔（秒）。
const TELEMETRY_INTERVAL_MAX_SECS: u64 = 60;
/// 计算外层 STUN 丢包率的最近探测结果滑动窗口大小（条）。
const TELEMETRY_STUN_LOSS_WINDOW: usize = 20;
/// JSON 状态报告中保留的最近关键事件历史条数上限。
const TELEMETRY_RECENT_EVENT_CAP: usize = 8;
/// 统计黑洞、1-RTT 迁移及未认证静默丢弃计数的滑动时间窗（10 分钟）。
const TELEMETRY_SLIDING_WINDOW: Duration = Duration::from_secs(600);
/// 非强制触发时状态 JSON 文件最小原子写入间隔（毫秒），防止突发事件频繁落盘。
const TELEMETRY_MIN_FILE_FLUSH_GAP: Duration = Duration::from_millis(250);
/// 遥测只读 HTTP 服务接收请求的轮询超时（毫秒），确保退出信号快速响应。
const TELEMETRY_HTTP_RECV_TIMEOUT: Duration = Duration::from_millis(100);
/// 计算实时吞吐 Mbps 所需的最小采样时间差（秒）。
const TELEMETRY_MIN_RATE_DT_SECS: f64 = 0.5;
/// 计入 STUN RTT 统计的单样本合法上限（毫秒），过滤异常尖刺。
const TELEMETRY_MAX_VALID_RTT_MS: f64 = 60_000.0;
/// STUN RTT 指数加权移动平均（EWMA）新样本权重系数。
const TELEMETRY_RTT_EWMA_ALPHA: f64 = 0.25;
/// 10 分钟内黑洞次数达到该阈值时判定链路健康状态为 `critical`。
const TELEMETRY_HEALTH_CRITICAL_BLACKHOLES: usize = 2;
/// STUN 滑动丢包率达到该百分比时判定链路健康状态为 `critical`。
const TELEMETRY_HEALTH_CRITICAL_LOSS_PCT: f64 = 15.0;
/// STUN 滑动丢包率达到该百分比时判定链路健康状态为 `degraded`。
const TELEMETRY_HEALTH_DEGRADED_LOSS_PCT: f64 = 2.0;
/// STUN 抖动达到该毫秒阈值时判定链路健康状态为 `degraded`。
const TELEMETRY_HEALTH_DEGRADED_JITTER_MS: f64 = 30.0;
/// Prometheus `webrtc_cloak_health_code` 数值编码：`critical`。
pub(super) const HEALTH_CODE_CRITICAL: u8 = 0;
/// Prometheus `webrtc_cloak_health_code` 数值编码：`idle`。
const HEALTH_CODE_IDLE: u8 = 1;
/// Prometheus `webrtc_cloak_health_code` 数值编码：`degraded`。
const HEALTH_CODE_DEGRADED: u8 = 2;
/// Prometheus `webrtc_cloak_health_code` 数值编码：`good`。
const HEALTH_CODE_GOOD: u8 = 3;

#[derive(Clone, Default)]
pub struct TelemetryConfig {
    pub status_file: Option<String>,
    pub status_http: Option<SocketAddr>,
    /// Refresh interval in seconds (`0` defaults to `5s`, clamped to `1..=60s`).
    pub status_interval_secs: u64,
}

impl TelemetryConfig {
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.status_file.is_some() || self.status_http.is_some()
    }

    #[inline]
    pub fn interval(&self) -> Duration {
        let s = if self.status_interval_secs == 0 {
            TELEMETRY_DEFAULT_INTERVAL_SECS
        } else {
            self.status_interval_secs
                .clamp(TELEMETRY_INTERVAL_MIN_SECS, TELEMETRY_INTERVAL_MAX_SECS)
        };
        Duration::from_secs(s)
    }
}

#[derive(Clone, Default)]
pub struct WorkerSnapshot {
    pub active_sessions: usize,
    pub handshaking_sessions: usize,
    pub migrating_sessions: usize,
    /// Monotonic cumulative totals (active + closed sessions) for this worker.
    pub tx_bytes_total: u64,
    pub rx_bytes_total: u64,
    pub tx_pkts_total: u64,
    pub rx_pkts_total: u64,
    pub auth_drops_total: u64,
    pub unauth_drops_total: u64,
    pub active_up_sport: u16,
    pub active_backend_sport: u16,
    pub dtls_version: &'static str,
    pub cipher: &'static str,
    pub dual_ssrc: bool,
}

#[derive(Clone, Serialize)]
pub(super) struct TelemetryEvent {
    #[serde(rename = "ts")]
    pub(super) ts_unix: u64,
    pub(super) event: &'static str,
    pub(super) detail: String,
}

#[derive(Serialize)]
pub(super) struct LinkPayload {
    pub(super) stun_rtt_ms: Option<f64>,
    pub(super) stun_rtt_ewma_ms: Option<f64>,
    pub(super) stun_jitter_ms: f64,
    pub(super) stun_loss_pct: f64,
    pub(super) tx_mbps: f64,
    pub(super) rx_mbps: f64,
    pub(super) tx_bytes_total: u64,
    pub(super) rx_bytes_total: u64,
    pub(super) tx_pkts_total: u64,
    pub(super) rx_pkts_total: u64,
}

#[derive(Serialize)]
pub(super) struct EventsPayload {
    pub(super) blackholes_total: u64,
    pub(super) blackholes_last_10m: usize,
    pub(super) migrations_1rtt_total: u64,
    pub(super) migrations_1rtt_last_10m: usize,
    pub(super) mbb_rotations_total: u64,
    pub(super) graceful_reconnects_total: u64,
    pub(super) stun_probes_ok_total: u64,
    pub(super) stun_probes_lost_total: u64,
    pub(super) last_event: &'static str,
    pub(super) last_event_unix: u64,
    pub(super) recent: Vec<TelemetryEvent>,
}

#[derive(Serialize)]
pub(super) struct SessionsPayload {
    pub(super) active: usize,
    pub(super) handshaking: usize,
    pub(super) migrating: usize,
    pub(super) up_sport: u16,
    pub(super) backend_sport: u16,
    pub(super) mapped_nat: Option<String>,
    pub(super) auth_drops_total: u64,
    pub(super) unauth_silent_drops_total: u64,
    pub(super) unauth_silent_drops_last_10m: u64,
}

#[derive(Serialize)]
pub(super) struct StatusPayload {
    pub(super) version: &'static str,
    pub(super) role: &'static str,
    pub(super) updated_at_unix: u64,
    pub(super) uptime_secs: u64,
    pub(super) health: &'static str,
    pub(super) dtls_version: &'static str,
    pub(super) cipher: &'static str,
    pub(super) dual_ssrc: bool,
    pub(super) mtu: usize,
    pub(super) workers: usize,
    pub(super) link: LinkPayload,
    pub(super) events: EventsPayload,
    pub(super) sessions: SessionsPayload,
}

pub(super) struct TelemetryInner {
    pub(super) role: &'static str,
    pub(super) started_at: Instant,
    pub(super) wan_mtu: usize,
    pub(super) workers: Vec<WorkerSnapshot>,
    // Rate tracking
    pub(super) rate_prev_at: Instant,
    pub(super) rate_prev_tx_bytes: u64,
    pub(super) rate_prev_rx_bytes: u64,
    pub(super) tx_mbps: f64,
    pub(super) rx_mbps: f64,
    // Client outer STUN link quality
    pub(super) stun_rtt_ms: Option<f64>,
    pub(super) stun_rtt_ewma_ms: Option<f64>,
    pub(super) stun_jitter_ms: f64,
    pub(super) stun_rtt_samples: u64,
    pub(super) stun_outcomes: VecDeque<bool>,
    pub(super) stun_probes_ok_total: u64,
    pub(super) stun_probes_lost_total: u64,
    pub(super) mapped_nat: Option<String>,
    // Outer lifecycle events & 10-minute sliding windows
    pub(super) blackholes_total: u64,
    pub(super) blackhole_times: VecDeque<Instant>,
    pub(super) migrations_1rtt_total: u64,
    pub(super) migration_times: VecDeque<Instant>,
    pub(super) mbb_rotations_total: u64,
    pub(super) graceful_reconnects_total: u64,
    pub(super) unauth_prev_total: u64,
    pub(super) unauth_deltas_10m: VecDeque<(Instant, u64)>,
    pub(super) last_event: &'static str,
    pub(super) last_event_unix: u64,
    pub(super) recent_events: VecDeque<TelemetryEvent>,
    // Atomic file write throttle
    pub(super) last_file_flush: Option<Instant>,
}

pub struct TelemetryHub {
    status_file: Option<String>,
    interval: Duration,
    inner: Mutex<TelemetryInner>,
    file_write_lock: Mutex<()>,
    http_stop: Arc<AtomicBool>,
    http_server: Mutex<Option<Arc<HttpServer>>>,
    http_handle: Mutex<Option<JoinHandle<()>>>,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[inline]
pub(super) fn round_n(v: f64, scale: f64) -> f64 {
    if v.is_finite() {
        (v * scale).round() / scale
    } else {
        0.0
    }
}

fn prune_times(q: &mut VecDeque<Instant>, now: Instant) {
    while let Some(&t) = q.front() {
        if now.saturating_duration_since(t) > TELEMETRY_SLIDING_WINDOW {
            q.pop_front();
        } else {
            break;
        }
    }
}

fn prune_unauth(q: &mut VecDeque<(Instant, u64)>, now: Instant) {
    while let Some(&(t, _)) = q.front() {
        if now.saturating_duration_since(t) > TELEMETRY_SLIDING_WINDOW {
            q.pop_front();
        } else {
            break;
        }
    }
}

pub(super) struct AggregatedView {
    pub(super) updated_at_unix: u64,
    pub(super) uptime_secs: u64,
    pub(super) health: &'static str,
    pub(super) health_code: u8,
    pub(super) dtls_version: &'static str,
    pub(super) cipher: &'static str,
    pub(super) dual_ssrc: bool,
    pub(super) active_sessions: usize,
    pub(super) handshaking_sessions: usize,
    pub(super) migrating_sessions: usize,
    pub(super) tx_bytes_total: u64,
    pub(super) rx_bytes_total: u64,
    pub(super) tx_pkts_total: u64,
    pub(super) rx_pkts_total: u64,
    pub(super) auth_drops_total: u64,
    pub(super) unauth_drops_total: u64,
    pub(super) unauth_drops_last_10m: u64,
    pub(super) active_up_sport: u16,
    pub(super) active_backend_sport: u16,
    pub(super) stun_loss_pct: f64,
    pub(super) blackholes_last_10m: usize,
    pub(super) migrations_1rtt_last_10m: usize,
}


impl TelemetryInner {
    pub(super) fn compute_view(&mut self, now: Instant) -> AggregatedView {
        prune_times(&mut self.blackhole_times, now);
        prune_times(&mut self.migration_times, now);
        prune_unauth(&mut self.unauth_deltas_10m, now);

        let mut active_sessions = 0usize;
        let mut handshaking_sessions = 0usize;
        let mut migrating_sessions = 0usize;
        let mut tx_bytes_total = 0u64;
        let mut rx_bytes_total = 0u64;
        let mut tx_pkts_total = 0u64;
        let mut rx_pkts_total = 0u64;
        let mut auth_drops_total = 0u64;
        let mut unauth_drops_total = 0u64;
        let mut active_up_sport = 0u16;
        let mut active_backend_sport = 0u16;
        let mut dtls_version = "none";
        let mut cipher = "none";
        let mut dual_ssrc = false;

        for w in &self.workers {
            active_sessions += w.active_sessions;
            handshaking_sessions += w.handshaking_sessions;
            migrating_sessions += w.migrating_sessions;
            tx_bytes_total = tx_bytes_total.saturating_add(w.tx_bytes_total);
            rx_bytes_total = rx_bytes_total.saturating_add(w.rx_bytes_total);
            tx_pkts_total = tx_pkts_total.saturating_add(w.tx_pkts_total);
            rx_pkts_total = rx_pkts_total.saturating_add(w.rx_pkts_total);
            auth_drops_total = auth_drops_total.saturating_add(w.auth_drops_total);
            unauth_drops_total = unauth_drops_total.saturating_add(w.unauth_drops_total);
            if active_up_sport == 0 && w.active_up_sport != 0 {
                active_up_sport = w.active_up_sport;
            }
            if active_backend_sport == 0 && w.active_backend_sport != 0 {
                active_backend_sport = w.active_backend_sport;
            }
            if dtls_version == "none" && !w.dtls_version.is_empty() && w.dtls_version != "none" {
                dtls_version = w.dtls_version;
            }
            if cipher == "none" && !w.cipher.is_empty() && w.cipher != "none" {
                cipher = w.cipher;
            }
            if w.dual_ssrc {
                dual_ssrc = true;
            }
        }

        // Track 10-minute unauthenticated silent-drop delta for scan alerting
        if unauth_drops_total > self.unauth_prev_total {
            let delta = unauth_drops_total - self.unauth_prev_total;
            self.unauth_prev_total = unauth_drops_total;
            self.unauth_deltas_10m.push_back((now, delta));
        }
        let unauth_drops_last_10m: u64 = self.unauth_deltas_10m.iter().map(|&(_, d)| d).sum();

        let stun_loss_pct = if self.stun_outcomes.is_empty() {
            0.0
        } else {
            let lost = self.stun_outcomes.iter().filter(|&&ok| !ok).count();
            (lost as f64) * 100.0 / (self.stun_outcomes.len() as f64)
        };

        let blackholes_last_10m = self.blackhole_times.len();
        let migrations_1rtt_last_10m = self.migration_times.len();

        let (health, health_code) = if active_sessions == 0
            && migrating_sessions == 0
            && handshaking_sessions == 0
        {
            ("idle", HEALTH_CODE_IDLE)
        } else if migrating_sessions > 0
            || blackholes_last_10m >= TELEMETRY_HEALTH_CRITICAL_BLACKHOLES
            || stun_loss_pct >= TELEMETRY_HEALTH_CRITICAL_LOSS_PCT
        {
            ("critical", HEALTH_CODE_CRITICAL)
        } else if blackholes_last_10m == 1
            || stun_loss_pct >= TELEMETRY_HEALTH_DEGRADED_LOSS_PCT
            || self.stun_jitter_ms >= TELEMETRY_HEALTH_DEGRADED_JITTER_MS
            || (active_sessions == 0 && handshaking_sessions > 0)
        {
            ("degraded", HEALTH_CODE_DEGRADED)
        } else {
            ("good", HEALTH_CODE_GOOD)
        };

        AggregatedView {
            updated_at_unix: unix_now_secs(),
            uptime_secs: now.saturating_duration_since(self.started_at).as_secs(),
            health,
            health_code,
            dtls_version,
            cipher,
            dual_ssrc,
            active_sessions,
            handshaking_sessions,
            migrating_sessions,
            tx_bytes_total,
            rx_bytes_total,
            tx_pkts_total,
            rx_pkts_total,
            auth_drops_total,
            unauth_drops_total,
            unauth_drops_last_10m,
            active_up_sport,
            active_backend_sport,
            stun_loss_pct,
            blackholes_last_10m,
            migrations_1rtt_last_10m,
        }
    }
}

impl TelemetryHub {
    pub fn start(
        role: &'static str,
        cfg: &TelemetryConfig,
        workers: usize,
        wan_mtu: usize,
        quiet: bool,
        external_stop: Option<Arc<AtomicBool>>,
    ) -> Option<Arc<Self>> {
        if !cfg.is_enabled() {
            return None;
        }
        let now = Instant::now();
        let inner = TelemetryInner {
            role,
            started_at: now,
            wan_mtu,
            workers: vec![WorkerSnapshot::default(); workers.max(1)],
            rate_prev_at: now,
            rate_prev_tx_bytes: 0,
            rate_prev_rx_bytes: 0,
            tx_mbps: 0.0,
            rx_mbps: 0.0,
            stun_rtt_ms: None,
            stun_rtt_ewma_ms: None,
            stun_jitter_ms: 0.0,
            stun_rtt_samples: 0,
            stun_outcomes: VecDeque::with_capacity(TELEMETRY_STUN_LOSS_WINDOW),
            stun_probes_ok_total: 0,
            stun_probes_lost_total: 0,
            mapped_nat: None,
            blackholes_total: 0,
            blackhole_times: VecDeque::new(),
            migrations_1rtt_total: 0,
            migration_times: VecDeque::new(),
            mbb_rotations_total: 0,
            graceful_reconnects_total: 0,
            unauth_prev_total: 0,
            unauth_deltas_10m: VecDeque::new(),
            last_event: "started",
            last_event_unix: unix_now_secs(),
            recent_events: VecDeque::with_capacity(TELEMETRY_RECENT_EVENT_CAP),
            last_file_flush: None,
        };
        let hub = Arc::new(Self {
            status_file: cfg.status_file.clone(),
            interval: cfg.interval(),
            inner: Mutex::new(inner),
            file_write_lock: Mutex::new(()),
            http_stop: Arc::new(AtomicBool::new(false)),
            http_server: Mutex::new(None),
            http_handle: Mutex::new(None),
        });

        if let Some(ref path) = hub.status_file {
            let body = hub.snapshot_json();
            if let Err(e) = write_atomic_file(path, &body) {
                if !quiet {
                    eprintln!("[telemetry] WARN: failed initial write to --status-file {}: {}", path, e);
                }
            } else if !quiet {
                println!("[telemetry] status-file enabled -> {} (interval={}s)", path, hub.interval.as_secs());
            }
        }

        if let Some(addr) = cfg.status_http {
            if !addr.ip().is_loopback() && !quiet {
                eprintln!(
                    "[telemetry] WARN: --status-http {} binds non-loopback; prefer 127.0.0.1:<port> for local-only access",
                    addr
                );
            }
            match HttpServer::http(addr) {
                Ok(server) => {
                    let server = Arc::new(server);
                    if let Ok(mut g) = hub.http_server.lock() {
                        *g = Some(Arc::clone(&server));
                    }
                    if !quiet {
                        println!(
                            "[telemetry] status-http (tiny_http) listening on http://{} (/status, /healthz, /metrics)",
                            addr
                        );
                    }
                    let hub_c = Arc::clone(&hub);
                    let h_stop = Arc::clone(&hub.http_stop);
                    let ext_stop = external_stop;
                    let handle = thread::Builder::new()
                        .name("wc-status-http".to_string())
                        .spawn(move || loop {
                            if h_stop.load(Ordering::Relaxed)
                                || ext_stop
                                    .as_ref()
                                    .map_or(false, |s| s.load(Ordering::Relaxed))
                            {
                                break;
                            }
                            match server.recv_timeout(TELEMETRY_HTTP_RECV_TIMEOUT) {
                                Ok(Some(req)) => handle_http_request(req, &hub_c),
                                Ok(None) => {}
                                Err(_) => break,
                            }
                        });
                    if let Ok(h) = handle {
                        if let Ok(mut g) = hub.http_handle.lock() {
                            *g = Some(h);
                        }
                    }
                }
                Err(e) => {
                    if !quiet {
                        eprintln!("[telemetry] WARN: failed to bind --status-http {}: {}", addr, e);
                    }
                }
            }
        }

        Some(hub)
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn shutdown(&self) {
        self.http_stop.store(true, Ordering::SeqCst);
        if let Ok(mut g) = self.http_server.lock() {
            if let Some(srv) = g.take() {
                srv.unblock();
            }
        }
        if let Ok(mut g) = self.http_handle.lock() {
            if let Some(h) = g.take() {
                let _ = h.join();
            }
        }
    }

    pub fn snapshot_json(&self) -> String {
        let now = Instant::now();
        if let Ok(mut g) = self.inner.lock() {
            g.render_json(now)
        } else {
            "{}\n".to_string()
        }
    }

    pub fn snapshot_prometheus(&self) -> String {
        let now = Instant::now();
        if let Ok(mut g) = self.inner.lock() {
            g.render_prometheus(now)
        } else {
            String::new()
        }
    }

    pub fn is_critical(&self) -> bool {
        let now = Instant::now();
        self.inner
            .lock()
            .map(|mut g| g.is_critical(now))
            .unwrap_or(false)
    }

    fn flush_file_if_needed(&self, force: bool) {
        let Some(ref path) = self.status_file else {
            return;
        };
        let now = Instant::now();
        let body = {
            let Ok(mut g) = self.inner.lock() else {
                return;
            };
            if !force {
                if let Some(last) = g.last_file_flush {
                    if now.saturating_duration_since(last) < TELEMETRY_MIN_FILE_FLUSH_GAP {
                        return;
                    }
                }
            }
            g.last_file_flush = Some(now);
            g.render_json(now)
        };
        let _guard = self.file_write_lock.lock();
        let _ = write_atomic_file(path, &body);
    }

    /// Push a worker's periodic counter snapshot (called every `interval`, NEVER per data packet).
    /// Throughput rates (`tx_mbps` / `rx_mbps`) are computed ONLY here when fresh worker byte
    /// counters arrive, so read-only `/status` or `/metrics` scrapes between ticks never zero them.
    pub fn update_worker(&self, worker_id: usize, snap: WorkerSnapshot) {
        if let Ok(mut g) = self.inner.lock() {
            if worker_id >= g.workers.len() {
                g.workers.resize_with(worker_id + 1, WorkerSnapshot::default);
            }
            g.workers[worker_id] = snap;
            let now = Instant::now();
            let total_tx: u64 = g
                .workers
                .iter()
                .fold(0u64, |acc, w| acc.saturating_add(w.tx_bytes_total));
            let total_rx: u64 = g
                .workers
                .iter()
                .fold(0u64, |acc, w| acc.saturating_add(w.rx_bytes_total));
            let dt_s = now.saturating_duration_since(g.rate_prev_at).as_secs_f64();
            if dt_s >= TELEMETRY_MIN_RATE_DT_SECS {
                let dtx = total_tx.saturating_sub(g.rate_prev_tx_bytes);
                let drx = total_rx.saturating_sub(g.rate_prev_rx_bytes);
                g.tx_mbps = (dtx as f64 * 8.0) / dt_s / 1_000_000.0;
                g.rx_mbps = (drx as f64 * 8.0) / dt_s / 1_000_000.0;
                g.rate_prev_at = now;
                g.rate_prev_tx_bytes = total_tx;
                g.rate_prev_rx_bytes = total_rx;
            }
        }
        self.flush_file_if_needed(true);
    }

    /// Record a completed STUN handshake or consent keepalive RTT sample + any retries lost before success.
    pub fn record_stun_ok(&self, rtt_ms: f64, retries_before_ok: u8, mapped: Option<SocketAddr>) {
        if let Ok(mut g) = self.inner.lock() {
            if rtt_ms.is_finite() && rtt_ms >= 0.0 && rtt_ms < TELEMETRY_MAX_VALID_RTT_MS {
                if let Some(prev) = g.stun_rtt_ms {
                    let d = (rtt_ms - prev).abs();
                    let div = if g.stun_rtt_samples < 4 { 4.0 } else { 16.0 };
                    g.stun_jitter_ms += (d - g.stun_jitter_ms) / div;
                }
                g.stun_rtt_ms = Some(rtt_ms);
                g.stun_rtt_ewma_ms = Some(match g.stun_rtt_ewma_ms {
                    Some(prev) => {
                        prev * (1.0 - TELEMETRY_RTT_EWMA_ALPHA)
                            + rtt_ms * TELEMETRY_RTT_EWMA_ALPHA
                    }
                    None => rtt_ms,
                });
                g.stun_rtt_samples += 1;
            }
            if let Some(addr) = mapped {
                g.mapped_nat = Some(addr.to_string());
            }
            for _ in 0..retries_before_ok {
                if g.stun_outcomes.len() >= TELEMETRY_STUN_LOSS_WINDOW {
                    g.stun_outcomes.pop_front();
                }
                g.stun_outcomes.push_back(false);
                g.stun_probes_lost_total += 1;
            }
            if g.stun_outcomes.len() >= TELEMETRY_STUN_LOSS_WINDOW {
                g.stun_outcomes.pop_front();
            }
            g.stun_outcomes.push_back(true);
            g.stun_probes_ok_total += 1;
        }
    }

    /// Record a confirmed outer STUN consent blackhole (all `attempts` unanswered).
    pub fn record_blackhole(&self, attempts: u8, detail: String) {
        let now = Instant::now();
        if let Ok(mut g) = self.inner.lock() {
            for _ in 0..attempts.max(1) {
                if g.stun_outcomes.len() >= TELEMETRY_STUN_LOSS_WINDOW {
                    g.stun_outcomes.pop_front();
                }
                g.stun_outcomes.push_back(false);
                g.stun_probes_lost_total += 1;
            }
            g.blackholes_total += 1;
            g.blackhole_times.push_back(now);
            prune_times(&mut g.blackhole_times, now);
            Self::push_event_locked(&mut g, "blackhole", detail);
        }
        self.flush_file_if_needed(false);
    }

    pub fn record_migration_1rtt(&self, detail: String) {
        let now = Instant::now();
        if let Ok(mut g) = self.inner.lock() {
            g.migrations_1rtt_total += 1;
            g.migration_times.push_back(now);
            prune_times(&mut g.migration_times, now);
            Self::push_event_locked(&mut g, "migration_1rtt", detail);
        }
        self.flush_file_if_needed(false);
    }

    pub fn record_mbb_rotation(&self, detail: String) {
        if let Ok(mut g) = self.inner.lock() {
            g.mbb_rotations_total += 1;
            Self::push_event_locked(&mut g, "mbb_handover", detail);
        }
        self.flush_file_if_needed(false);
    }

    pub fn record_graceful_reconnect(&self, detail: String) {
        if let Ok(mut g) = self.inner.lock() {
            g.graceful_reconnects_total += 1;
            Self::push_event_locked(&mut g, "graceful_reconnect", detail);
        }
        self.flush_file_if_needed(false);
    }

    fn push_event_locked(g: &mut TelemetryInner, event: &'static str, detail: String) {
        let ts = unix_now_secs();
        g.last_event = event;
        g.last_event_unix = ts;
        if g.recent_events.len() >= TELEMETRY_RECENT_EVENT_CAP {
            g.recent_events.pop_front();
        }
        g.recent_events.push_back(TelemetryEvent {
            ts_unix: ts,
            event,
            detail,
        });
    }
}
