//! 遥测 JSON 原子落盘、HTTP 只读接口与 Prometheus 指标渲染。

use super::{
    round_n, EventsPayload, LinkPayload, SessionsPayload, StatusPayload, TelemetryHub,
    TelemetryInner, HEALTH_CODE_CRITICAL,
};
use std::io::Write;
use std::path::Path;
use std::time::Instant;
use tiny_http::{Header, Method, Request, Response, StatusCode};

impl TelemetryInner {
    pub(super) fn render_json(&mut self, now: Instant) -> String {
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

    pub(super) fn render_prometheus(&mut self, now: Instant) -> String {
        let v = self.compute_view(now);
        let r = self.role;
        let mut s = String::with_capacity(1400);
        s.push_str(
            "# HELP webrtc_cloak_up 1 while process is running\n# TYPE webrtc_cloak_up gauge\n",
        );
        s.push_str(&format!("webrtc_cloak_up{{role=\"{}\"}} 1\n", r));
        s.push_str("# HELP webrtc_cloak_uptime_seconds Process uptime in seconds\n# TYPE webrtc_cloak_uptime_seconds gauge\n");
        s.push_str(&format!(
            "webrtc_cloak_uptime_seconds{{role=\"{}\"}} {}\n",
            r, v.uptime_secs
        ));
        s.push_str("# HELP webrtc_cloak_health_code 3=good 2=degraded 1=idle 0=critical\n# TYPE webrtc_cloak_health_code gauge\n");
        s.push_str(&format!(
            "webrtc_cloak_health_code{{role=\"{}\",health=\"{}\"}} {}\n",
            r, v.health, v.health_code
        ));
        if let Some(rtt) = self.stun_rtt_ms {
            s.push_str(&format!(
                "webrtc_cloak_stun_rtt_ms{{role=\"{}\"}} {:.2}\n",
                r, rtt
            ));
        }
        if let Some(ewma) = self.stun_rtt_ewma_ms {
            s.push_str(&format!(
                "webrtc_cloak_stun_rtt_ewma_ms{{role=\"{}\"}} {:.2}\n",
                r, ewma
            ));
        }
        s.push_str(&format!(
            "webrtc_cloak_stun_jitter_ms{{role=\"{}\"}} {:.2}\n",
            r, self.stun_jitter_ms
        ));
        s.push_str(&format!(
            "webrtc_cloak_stun_loss_percent{{role=\"{}\"}} {:.2}\n",
            r, v.stun_loss_pct
        ));
        s.push_str(&format!(
            "webrtc_cloak_tx_mbps{{role=\"{}\"}} {:.3}\n",
            r, self.tx_mbps
        ));
        s.push_str(&format!(
            "webrtc_cloak_rx_mbps{{role=\"{}\"}} {:.3}\n",
            r, self.rx_mbps
        ));
        s.push_str(&format!(
            "webrtc_cloak_tx_bytes_total{{role=\"{}\"}} {}\n",
            r, v.tx_bytes_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_rx_bytes_total{{role=\"{}\"}} {}\n",
            r, v.rx_bytes_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_tx_pkts_total{{role=\"{}\"}} {}\n",
            r, v.tx_pkts_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_rx_pkts_total{{role=\"{}\"}} {}\n",
            r, v.rx_pkts_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_active_sessions{{role=\"{}\"}} {}\n",
            r, v.active_sessions
        ));
        s.push_str(&format!(
            "webrtc_cloak_migrating_sessions{{role=\"{}\"}} {}\n",
            r, v.migrating_sessions
        ));
        s.push_str(&format!(
            "webrtc_cloak_blackholes_total{{role=\"{}\"}} {}\n",
            r, self.blackholes_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_blackholes_last_10m{{role=\"{}\"}} {}\n",
            r, v.blackholes_last_10m
        ));
        s.push_str(&format!(
            "webrtc_cloak_migrations_1rtt_total{{role=\"{}\"}} {}\n",
            r, self.migrations_1rtt_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_migrations_1rtt_last_10m{{role=\"{}\"}} {}\n",
            r, v.migrations_1rtt_last_10m
        ));
        s.push_str(&format!(
            "webrtc_cloak_mbb_rotations_total{{role=\"{}\"}} {}\n",
            r, self.mbb_rotations_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_graceful_reconnects_total{{role=\"{}\"}} {}\n",
            r, self.graceful_reconnects_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_auth_drops_total{{role=\"{}\"}} {}\n",
            r, v.auth_drops_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_unauth_silent_drops_total{{role=\"{}\"}} {}\n",
            r, v.unauth_drops_total
        ));
        s.push_str(&format!(
            "webrtc_cloak_unauth_silent_drops_last_10m{{role=\"{}\"}} {}\n",
            r, v.unauth_drops_last_10m
        ));
        s
    }

    pub(super) fn is_critical(&mut self, now: Instant) -> bool {
        self.compute_view(now).health_code == HEALTH_CODE_CRITICAL
    }
}

pub(super) fn write_atomic_file(path: &str, body: &str) -> std::io::Result<()> {
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

pub(super) fn handle_http_request(req: Request, hub: &TelemetryHub) {
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
