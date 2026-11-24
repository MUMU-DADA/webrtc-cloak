//! Zero-dependency outer-path health telemetry for `webrtc-cloak` (`v0.4.1`):
//!   - Exposes real outer link quality (STUN RTT / EWMA / RFC 3550 jitter / rolling packet loss %,
//!     smoothed Mbps throughput, 10-minute blackhole & 1-RTT migration counters, MBB rotations,
//!     and server unauthenticated silent-drop scan counters) while keeping the data plane 100%
//!     transparent and decoupled from inner protocols.
//!   - Supports BOTH:
//!       1. `--status-file <PATH>`: atomic `tmp + rename` JSON snapshot (ideal for tmpfs / OpenWrt
//!          `jsonfilter` / shell watchdogs with zero open ports and zero flash wear).
//!       2. `--status-http <IP:PORT>`: minimal pure-std read-only HTTP server serving JSON at
//!          `/`, `/status`, `/health`, `/healthz` (503 when critical) and Prometheus text metrics
//!          at `/metrics` (strict timeouts, bounded reads, zero external crates).
//!   - Strictly zero overhead on the SRTP hot path (`Option<Arc<TelemetryHub>>`, updated only on
//!     slow periodic timers and rare control-plane transitions) and 32-bit `armv5te`-safe (no `AtomicU64`).

use serde::Serialize;
use std::collections::VecDeque;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Request, Response, Server as HttpServer, StatusCode};

const STUN_LOSS_WINDOW: usize = 20;
const RECENT_EVENT_CAP: usize = 8;
const WINDOW_10M: Duration = Duration::from_secs(600);
const MIN_FILE_FLUSH_GAP: Duration = Duration::from_millis(250);

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
            5
        } else {
            self.status_interval_secs.clamp(1, 60)
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
struct TelemetryEvent {
    #[serde(rename = "ts")]
    ts_unix: u64,
    event: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct LinkPayload {
    stun_rtt_ms: Option<f64>,
    stun_rtt_ewma_ms: Option<f64>,
    stun_jitter_ms: f64,
    stun_loss_pct: f64,
    tx_mbps: f64,
    rx_mbps: f64,
    tx_bytes_total: u64,
    rx_bytes_total: u64,
    tx_pkts_total: u64,
    rx_pkts_total: u64,
}

#[derive(Serialize)]
struct EventsPayload {
    blackholes_total: u64,
    blackholes_last_10m: usize,
    migrations_1rtt_total: u64,
    migrations_1rtt_last_10m: usize,
    mbb_rotations_total: u64,
    graceful_reconnects_total: u64,
    stun_probes_ok_total: u64,
    stun_probes_lost_total: u64,
    last_event: &'static str,
    last_event_unix: u64,
    recent: Vec<TelemetryEvent>,
}

#[derive(Serialize)]
struct SessionsPayload {
    active: usize,
    handshaking: usize,
    migrating: usize,
    up_sport: u16,
    backend_sport: u16,
    mapped_nat: Option<String>,
    auth_drops_total: u64,
    unauth_silent_drops_total: u64,
    unauth_silent_drops_last_10m: u64,
}

#[derive(Serialize)]
struct StatusPayload {
    version: &'static str,
    role: &'static str,
    updated_at_unix: u64,
    uptime_secs: u64,
    health: &'static str,
    dtls_version: &'static str,
    cipher: &'static str,
    dual_ssrc: bool,
    mtu: usize,
    workers: usize,
    link: LinkPayload,
    events: EventsPayload,
    sessions: SessionsPayload,
}

struct TelemetryInner {
    role: &'static str,
    started_at: Instant,
    wan_mtu: usize,
    workers: Vec<WorkerSnapshot>,
    // Rate tracking
    rate_prev_at: Instant,
    rate_prev_tx_bytes: u64,
    rate_prev_rx_bytes: u64,
    tx_mbps: f64,
    rx_mbps: f64,
    // Client outer STUN link quality
    stun_rtt_ms: Option<f64>,
    stun_rtt_ewma_ms: Option<f64>,
    stun_jitter_ms: f64,
    stun_rtt_samples: u64,
    stun_outcomes: VecDeque<bool>,
    stun_probes_ok_total: u64,
    stun_probes_lost_total: u64,
    mapped_nat: Option<String>,
    // Outer lifecycle events & 10-minute sliding windows
    blackholes_total: u64,
    blackhole_times: VecDeque<Instant>,
    migrations_1rtt_total: u64,
    migration_times: VecDeque<Instant>,
    mbb_rotations_total: u64,
    graceful_reconnects_total: u64,
    unauth_prev_total: u64,
    unauth_deltas_10m: VecDeque<(Instant, u64)>,
    last_event: &'static str,
    last_event_unix: u64,
    recent_events: VecDeque<TelemetryEvent>,
    // Atomic file write throttle
    last_file_flush: Option<Instant>,
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
fn round_n(v: f64, scale: f64) -> f64 {
    if v.is_finite() {
        (v * scale).round() / scale
    } else {
        0.0
    }
}

fn prune_times(q: &mut VecDeque<Instant>, now: Instant) {
    while let Some(&t) = q.front() {
        if now.saturating_duration_since(t) > WINDOW_10M {
            q.pop_front();
        } else {
            break;
        }
    }
}

fn prune_unauth(q: &mut VecDeque<(Instant, u64)>, now: Instant) {
    while let Some(&(t, _)) = q.front() {
        if now.saturating_duration_since(t) > WINDOW_10M {
            q.pop_front();
        } else {
            break;
        }
    }
}

struct AggregatedView {
    updated_at_unix: u64,
    uptime_secs: u64,
    health: &'static str,
    health_code: u8,
    dtls_version: &'static str,
    cipher: &'static str,
    dual_ssrc: bool,
    active_sessions: usize,
    handshaking_sessions: usize,
    migrating_sessions: usize,
    tx_bytes_total: u64,
    rx_bytes_total: u64,
    tx_pkts_total: u64,
    rx_pkts_total: u64,
    auth_drops_total: u64,
    unauth_drops_total: u64,
    unauth_drops_last_10m: u64,
    active_up_sport: u16,
    active_backend_sport: u16,
    stun_loss_pct: f64,
    blackholes_last_10m: usize,
    migrations_1rtt_last_10m: usize,
}

impl TelemetryInner {
    fn compute_view(&mut self, now: Instant) -> AggregatedView {
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
            ("idle", 1u8)
        } else if migrating_sessions > 0
            || blackholes_last_10m >= 2
            || stun_loss_pct >= 15.0
        {
            ("critical", 0u8)
        } else if blackholes_last_10m == 1
            || stun_loss_pct >= 2.0
            || self.stun_jitter_ms >= 30.0
            || (active_sessions == 0 && handshaking_sessions > 0)
        {
            ("degraded", 2u8)
        } else {
            ("good", 3u8)
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

    fn render_json(&mut self, now: Instant) -> String {
        let v = self.compute_view(now);
        let payload = StatusPayload {
            version: env!("CARGO_PKG_VERSION"),
            role: self.role,
            updated_at_unix: v.updated_at_unix,
            uptime_secs: v.uptime_secs,
            health: v.health,
            dtls_version: v.dtls_version,
            cipher: v.cipher,
            dual_ssrc: v.dual_ssrc,
            mtu: self.wan_mtu,
            workers: self.workers.len(),
            link: LinkPayload {
                stun_rtt_ms: self.stun_rtt_ms.map(|x| round_n(x, 100.0)),
                stun_rtt_ewma_ms: self.stun_rtt_ewma_ms.map(|x| round_n(x, 100.0)),
                stun_jitter_ms: round_n(self.stun_jitter_ms, 100.0),
                stun_loss_pct: round_n(v.stun_loss_pct, 100.0),
                tx_mbps: round_n(self.tx_mbps, 1000.0),
                rx_mbps: round_n(self.rx_mbps, 1000.0),
                tx_bytes_total: v.tx_bytes_total,
                rx_bytes_total: v.rx_bytes_total,
                tx_pkts_total: v.tx_pkts_total,
                rx_pkts_total: v.rx_pkts_total,
            },
            events: EventsPayload {
                blackholes_total: self.blackholes_total,
                blackholes_last_10m: v.blackholes_last_10m,
                migrations_1rtt_total: self.migrations_1rtt_total,
                migrations_1rtt_last_10m: v.migrations_1rtt_last_10m,
                mbb_rotations_total: self.mbb_rotations_total,
                graceful_reconnects_total: self.graceful_reconnects_total,
                stun_probes_ok_total: self.stun_probes_ok_total,
                stun_probes_lost_total: self.stun_probes_lost_total,
                last_event: self.last_event,
                last_event_unix: self.last_event_unix,
                recent: self.recent_events.iter().cloned().collect(),
            },
            sessions: SessionsPayload {
                active: v.active_sessions,
                handshaking: v.handshaking_sessions,
                migrating: v.migrating_sessions,
                up_sport: v.active_up_sport,
                backend_sport: v.active_backend_sport,
                mapped_nat: self.mapped_nat.clone(),
                auth_drops_total: v.auth_drops_total,
                unauth_silent_drops_total: v.unauth_drops_total,
                unauth_silent_drops_last_10m: v.unauth_drops_last_10m,
            },
        };
        let mut s = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
        s.push('\n');
        s
    }

    fn render_prometheus(&mut self, now: Instant) -> String {
        let v = self.compute_view(now);
        let r = self.role;
        let mut s = String::with_capacity(1400);
        s.push_str("# HELP webrtc_cloak_up 1 while process is running\n# TYPE webrtc_cloak_up gauge\n");
        s.push_str(&format!("webrtc_cloak_up{{role=\"{}\"}} 1\n", r));
        s.push_str("# HELP webrtc_cloak_uptime_seconds Process uptime in seconds\n# TYPE webrtc_cloak_uptime_seconds gauge\n");
        s.push_str(&format!("webrtc_cloak_uptime_seconds{{role=\"{}\"}} {}\n", r, v.uptime_secs));
        s.push_str("# HELP webrtc_cloak_health_code 3=good 2=degraded 1=idle 0=critical\n# TYPE webrtc_cloak_health_code gauge\n");
        s.push_str(&format!("webrtc_cloak_health_code{{role=\"{}\",health=\"{}\"}} {}\n", r, v.health, v.health_code));
        if let Some(rtt) = self.stun_rtt_ms {
            s.push_str(&format!("webrtc_cloak_stun_rtt_ms{{role=\"{}\"}} {:.2}\n", r, rtt));
        }
        if let Some(ewma) = self.stun_rtt_ewma_ms {
            s.push_str(&format!("webrtc_cloak_stun_rtt_ewma_ms{{role=\"{}\"}} {:.2}\n", r, ewma));
        }
        s.push_str(&format!("webrtc_cloak_stun_jitter_ms{{role=\"{}\"}} {:.2}\n", r, self.stun_jitter_ms));
        s.push_str(&format!("webrtc_cloak_stun_loss_percent{{role=\"{}\"}} {:.2}\n", r, v.stun_loss_pct));
        s.push_str(&format!("webrtc_cloak_tx_mbps{{role=\"{}\"}} {:.3}\n", r, self.tx_mbps));
        s.push_str(&format!("webrtc_cloak_rx_mbps{{role=\"{}\"}} {:.3}\n", r, self.rx_mbps));
        s.push_str(&format!("webrtc_cloak_tx_bytes_total{{role=\"{}\"}} {}\n", r, v.tx_bytes_total));
        s.push_str(&format!("webrtc_cloak_rx_bytes_total{{role=\"{}\"}} {}\n", r, v.rx_bytes_total));
        s.push_str(&format!("webrtc_cloak_tx_pkts_total{{role=\"{}\"}} {}\n", r, v.tx_pkts_total));
        s.push_str(&format!("webrtc_cloak_rx_pkts_total{{role=\"{}\"}} {}\n", r, v.rx_pkts_total));
        s.push_str(&format!("webrtc_cloak_active_sessions{{role=\"{}\"}} {}\n", r, v.active_sessions));
        s.push_str(&format!("webrtc_cloak_migrating_sessions{{role=\"{}\"}} {}\n", r, v.migrating_sessions));
        s.push_str(&format!("webrtc_cloak_blackholes_total{{role=\"{}\"}} {}\n", r, self.blackholes_total));
        s.push_str(&format!("webrtc_cloak_blackholes_last_10m{{role=\"{}\"}} {}\n", r, v.blackholes_last_10m));
        s.push_str(&format!("webrtc_cloak_migrations_1rtt_total{{role=\"{}\"}} {}\n", r, self.migrations_1rtt_total));
        s.push_str(&format!("webrtc_cloak_migrations_1rtt_last_10m{{role=\"{}\"}} {}\n", r, v.migrations_1rtt_last_10m));
        s.push_str(&format!("webrtc_cloak_mbb_rotations_total{{role=\"{}\"}} {}\n", r, self.mbb_rotations_total));
        s.push_str(&format!("webrtc_cloak_graceful_reconnects_total{{role=\"{}\"}} {}\n", r, self.graceful_reconnects_total));
        s.push_str(&format!("webrtc_cloak_auth_drops_total{{role=\"{}\"}} {}\n", r, v.auth_drops_total));
        s.push_str(&format!("webrtc_cloak_unauth_silent_drops_total{{role=\"{}\"}} {}\n", r, v.unauth_drops_total));
        s.push_str(&format!("webrtc_cloak_unauth_silent_drops_last_10m{{role=\"{}\"}} {}\n", r, v.unauth_drops_last_10m));
        s
    }

    fn is_critical(&mut self, now: Instant) -> bool {
        self.compute_view(now).health_code == 0
    }
}

fn write_atomic_file(path: &str, body: &str) -> std::io::Result<()> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let tmp = format!("{}.tmp.{}", path, std::process::id());
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            #[cfg(windows)]
            {
                let _ = std::fs::remove_file(path);
                if std::fs::rename(&tmp, path).is_ok() {
                    return Ok(());
                }
            }
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn handle_http_request(req: Request, hub: &TelemetryHub) {
    let method = req.method().clone();
    let raw_url = req.url().to_string();
    let path = raw_url.split('?').next().unwrap_or("/");

    if method != Method::Get && method != Method::Head {
        let mut resp = Response::from_string("").with_status_code(StatusCode(405));
        if let Ok(h) = Header::from_bytes(&b"Allow"[..], &b"GET, HEAD"[..]) {
            resp.add_header(h);
        }
        let _ = req.respond(resp);
        return;
    }

    let (status_code, ctype, body) = match path {
        "/" | "/status" | "/health" => (
            200u16,
            "application/json; charset=utf-8",
            hub.snapshot_json(),
        ),
        "/healthz" => {
            let crit = hub.is_critical();
            (
                if crit { 503u16 } else { 200u16 },
                "application/json; charset=utf-8",
                hub.snapshot_json(),
            )
        }
        "/metrics" => (
            200u16,
            "text/plain; version=0.0.4; charset=utf-8",
            hub.snapshot_prometheus(),
        ),
        _ => (
            404u16,
            "text/plain; charset=utf-8",
            "not found (use /status, /health, /healthz, or /metrics)\n".to_string(),
        ),
    };

    let mut resp = Response::from_string(body).with_status_code(StatusCode(status_code));
    if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], ctype.as_bytes()) {
        resp.add_header(h);
    }
    if let Ok(h) = Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]) {
        resp.add_header(h);
    }
    let _ = req.respond(resp);
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
            stun_outcomes: VecDeque::with_capacity(STUN_LOSS_WINDOW),
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
            recent_events: VecDeque::with_capacity(RECENT_EVENT_CAP),
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
                            match server.recv_timeout(Duration::from_millis(100)) {
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
                    if now.saturating_duration_since(last) < MIN_FILE_FLUSH_GAP {
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
            if dt_s >= 0.5 {
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
            if rtt_ms.is_finite() && rtt_ms >= 0.0 && rtt_ms < 60_000.0 {
                if let Some(prev) = g.stun_rtt_ms {
                    let d = (rtt_ms - prev).abs();
                    let div = if g.stun_rtt_samples < 4 { 4.0 } else { 16.0 };
                    g.stun_jitter_ms += (d - g.stun_jitter_ms) / div;
                }
                g.stun_rtt_ms = Some(rtt_ms);
                g.stun_rtt_ewma_ms = Some(match g.stun_rtt_ewma_ms {
                    Some(prev) => prev * 0.75 + rtt_ms * 0.25,
                    None => rtt_ms,
                });
                g.stun_rtt_samples += 1;
            }
            if let Some(addr) = mapped {
                g.mapped_nat = Some(addr.to_string());
            }
            for _ in 0..retries_before_ok {
                if g.stun_outcomes.len() >= STUN_LOSS_WINDOW {
                    g.stun_outcomes.pop_front();
                }
                g.stun_outcomes.push_back(false);
                g.stun_probes_lost_total += 1;
            }
            if g.stun_outcomes.len() >= STUN_LOSS_WINDOW {
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
                if g.stun_outcomes.len() >= STUN_LOSS_WINDOW {
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
        if g.recent_events.len() >= RECENT_EVENT_CAP {
            g.recent_events.pop_front();
        }
        g.recent_events.push_back(TelemetryEvent {
            ts_unix: ts,
            event,
            detail,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};

    #[test]
    fn telemetry_health_state_machine_atomic_file_and_http_endpoints() {
        let probe_sock = TcpListener::bind("127.0.0.1:0").unwrap();
        let http_addr = probe_sock.local_addr().unwrap();
        drop(probe_sock);

        let tmp_path = std::env::temp_dir()
            .join(format!("wc_telemetry_unit_{}.json", std::process::id()))
            .to_string_lossy()
            .to_string();

        let cfg = TelemetryConfig {
            status_file: Some(tmp_path.clone()),
            status_http: Some(http_addr),
            status_interval_secs: 1,
        };
        let hub = TelemetryHub::start("client", &cfg, 1, 1488, true, None).unwrap();

        // 1. Initially idle (0 active sessions)
        let j0 = std::fs::read_to_string(&tmp_path).expect("initial status file");
        assert!(j0.contains("\"health\": \"idle\""), "expected idle: {}", j0);

        // 2. Active session + clean STUN samples -> good
        hub.update_worker(
            0,
            WorkerSnapshot {
                active_sessions: 1,
                tx_bytes_total: 100_000,
                rx_bytes_total: 500_000,
                tx_pkts_total: 100,
                rx_pkts_total: 400,
                active_up_sport: 45678,
                dtls_version: "1.3",
                cipher: "aes-128-gcm",
                dual_ssrc: true,
                ..Default::default()
            },
        );
        for rtt in [160.0, 161.0, 159.5, 160.5] {
            hub.record_stun_ok(
                rtt,
                0,
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 4444)),
            );
        }
        hub.record_mbb_rotation("45678->45999".to_string());
        let j1 = hub.snapshot_json();
        let v1: serde_json::Value = serde_json::from_str(&j1).expect("valid serde JSON");
        assert_eq!(v1["health"], "good");
        assert_eq!(v1["link"]["stun_loss_pct"], 0.0);
        assert_eq!(v1["events"]["mbb_rotations_total"], 1);
        assert_eq!(v1["sessions"]["mapped_nat"], "198.51.100.10:4444");

        // 3. HTTP /status, /metrics, /healthz, 404, 405 checks
        let http_get = |req: &str| -> String {
            let mut s = TcpStream::connect(http_addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            s.write_all(req.as_bytes()).unwrap();
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            buf
        };
        let r_status = http_get("GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert!(r_status.starts_with("HTTP/1.1 200 OK"));
        assert!(r_status.contains("application/json"));
        assert!(r_status.contains("\"health\": \"good\""));

        let r_metrics = http_get("GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert!(r_metrics.starts_with("HTTP/1.1 200 OK"));
        assert!(r_metrics.contains("webrtc_cloak_health_code{role=\"client\",health=\"good\"} 3"));
        assert!(r_metrics.contains("webrtc_cloak_mbb_rotations_total{role=\"client\"} 1"));

        let r_404 = http_get("GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert!(r_404.starts_with("HTTP/1.1 404 Not Found"));

        let r_405 = http_get("POST /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert!(r_405.starts_with("HTTP/1.1 405 Method Not Allowed"));

        // 3b. Read-only scrapes between worker ticks MUST preserve non-zero tx_mbps / rx_mbps!
        thread::sleep(Duration::from_millis(550));
        hub.update_worker(
            0,
            WorkerSnapshot {
                active_sessions: 1,
                tx_bytes_total: 600_000,
                rx_bytes_total: 2_500_000,
                tx_pkts_total: 600,
                rx_pkts_total: 2000,
                active_up_sport: 45678,
                dtls_version: "1.3",
                cipher: "aes-128-gcm",
                dual_ssrc: true,
                ..Default::default()
            },
        );
        thread::sleep(Duration::from_millis(550));
        let r_rate1 = http_get("GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let b_rate1 = r_rate1.split_once("\r\n\r\n").unwrap().1;
        let vr1: serde_json::Value = serde_json::from_str(b_rate1).unwrap();
        assert!(vr1["link"]["rx_mbps"].as_f64().unwrap() > 10.0);
        let r_rate2 = http_get("GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let b_rate2 = r_rate2.split_once("\r\n\r\n").unwrap().1;
        let vr2: serde_json::Value = serde_json::from_str(b_rate2).unwrap();
        assert_eq!(vr1["link"]["rx_mbps"], vr2["link"]["rx_mbps"]);

        // 4. Two blackholes in 10m -> critical -> /healthz returns 503!
        hub.record_blackhole(3, "bh#1".to_string());
        assert!(hub.snapshot_json().contains("\"health\": \"critical\"") || hub.snapshot_json().contains("\"health\": \"degraded\""));
        hub.record_blackhole(3, "bh#2".to_string());
        let r_hz = http_get("GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert!(r_hz.starts_with("HTTP/1.1 503 Service Unavailable"), "got: {}", r_hz);

        hub.shutdown();
        let _ = std::fs::remove_file(&tmp_path);
    }
}
