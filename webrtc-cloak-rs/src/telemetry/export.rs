//! 遥测 JSON 原子落盘、零外部依赖 HTTP 只读接口与 Prometheus 指标渲染。

use super::{round_n, TelemetryHub, TelemetryInner, HEALTH_CODE_CRITICAL};
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// 本地遥测 HTTP 单连接读写超时（毫秒），防止异常客户端阻塞监听线程。
const HTTP_IO_TIMEOUT: Duration = Duration::from_millis(500);
/// 本地遥测 HTTP 单请求头读取缓冲区上限（字节）。
const HTTP_REQ_BUF_LEN: usize = 2048;

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_json_opt_str(out: &mut String, opt: Option<&str>) {
    match opt {
        Some(s) => push_json_str(out, s),
        None => out.push_str("null"),
    }
}

fn push_json_f64(out: &mut String, v: f64) {
    let v = if v.is_finite() { v } else { 0.0 };
    let v = if v == 0.0 { 0.0 } else { v };
    let start = out.len();
    let _ = write!(out, "{}", v);
    if !out[start..].contains(['.', 'e', 'E']) {
        out.push_str(".0");
    }
}

fn push_json_opt_f64(out: &mut String, opt: Option<f64>, scale: f64) {
    match opt {
        Some(v) => push_json_f64(out, round_n(v, scale)),
        None => out.push_str("null"),
    }
}

impl TelemetryInner {
    pub(super) fn render_json(&mut self, now: Instant) -> String {
        let v = self.compute_view(now);
        let mut s = String::with_capacity(1400);
        s.push_str("{\n");
        let _ = writeln!(s, "  \"version\": \"{}\",", env!("CARGO_PKG_VERSION"));
        let _ = writeln!(s, "  \"role\": \"{}\",", self.role);
        let _ = writeln!(s, "  \"updated_at_unix\": {},", v.updated_at_unix);
        let _ = writeln!(s, "  \"uptime_secs\": {},", v.uptime_secs);
        let _ = writeln!(s, "  \"health\": \"{}\",", v.health);
        let _ = writeln!(s, "  \"dtls_version\": \"{}\",", v.dtls_version);
        let _ = writeln!(s, "  \"cipher\": \"{}\",", v.cipher);
        let _ = writeln!(s, "  \"dual_ssrc\": {},", v.dual_ssrc);
        let _ = writeln!(s, "  \"mtu\": {},", self.wan_mtu);
        let _ = writeln!(s, "  \"workers\": {},", self.workers.len());

        // link
        s.push_str("  \"link\": {\n");
        s.push_str("    \"stun_rtt_ms\": ");
        push_json_opt_f64(&mut s, self.stun_rtt_ms, 100.0);
        s.push_str(",\n    \"stun_rtt_ewma_ms\": ");
        push_json_opt_f64(&mut s, self.stun_rtt_ewma_ms, 100.0);
        s.push_str(",\n    \"stun_jitter_ms\": ");
        push_json_f64(&mut s, round_n(self.stun_jitter_ms, 100.0));
        s.push_str(",\n    \"stun_loss_pct\": ");
        push_json_f64(&mut s, round_n(v.stun_loss_pct, 100.0));
        s.push_str(",\n    \"tx_mbps\": ");
        push_json_f64(&mut s, round_n(self.tx_mbps, 1000.0));
        s.push_str(",\n    \"rx_mbps\": ");
        push_json_f64(&mut s, round_n(self.rx_mbps, 1000.0));
        s.push_str(",\n");
        let _ = writeln!(s, "    \"tx_bytes_total\": {},", v.tx_bytes_total);
        let _ = writeln!(s, "    \"rx_bytes_total\": {},", v.rx_bytes_total);
        let _ = writeln!(s, "    \"tx_pkts_total\": {},", v.tx_pkts_total);
        let _ = writeln!(s, "    \"rx_pkts_total\": {}", v.rx_pkts_total);
        s.push_str("  },\n");

        // events
        s.push_str("  \"events\": {\n");
        let _ = writeln!(s, "    \"blackholes_total\": {},", self.blackholes_total);
        let _ = writeln!(s, "    \"blackholes_last_10m\": {},", v.blackholes_last_10m);
        let _ = writeln!(
            s,
            "    \"migrations_1rtt_total\": {},",
            self.migrations_1rtt_total
        );
        let _ = writeln!(
            s,
            "    \"migrations_1rtt_last_10m\": {},",
            v.migrations_1rtt_last_10m
        );
        let _ = writeln!(
            s,
            "    \"mbb_rotations_total\": {},",
            self.mbb_rotations_total
        );
        let _ = writeln!(
            s,
            "    \"graceful_reconnects_total\": {},",
            self.graceful_reconnects_total
        );
        let _ = writeln!(
            s,
            "    \"stun_probes_ok_total\": {},",
            self.stun_probes_ok_total
        );
        let _ = writeln!(
            s,
            "    \"stun_probes_lost_total\": {},",
            self.stun_probes_lost_total
        );
        let _ = writeln!(s, "    \"last_event\": \"{}\",", self.last_event);
        let _ = writeln!(s, "    \"last_event_unix\": {},", self.last_event_unix);
        if self.recent_events.is_empty() {
            s.push_str("    \"recent\": []\n");
        } else {
            s.push_str("    \"recent\": [\n");
            for (idx, ev) in self.recent_events.iter().enumerate() {
                s.push_str("      {\n");
                let _ = writeln!(s, "        \"ts\": {},", ev.ts_unix);
                let _ = writeln!(s, "        \"event\": \"{}\",", ev.event);
                s.push_str("        \"detail\": ");
                push_json_str(&mut s, &ev.detail);
                s.push('\n');
                if idx + 1 < self.recent_events.len() {
                    s.push_str("      },\n");
                } else {
                    s.push_str("      }\n");
                }
            }
            s.push_str("    ]\n");
        }
        s.push_str("  },\n");

        // sessions
        s.push_str("  \"sessions\": {\n");
        let _ = writeln!(s, "    \"active\": {},", v.active_sessions);
        let _ = writeln!(s, "    \"handshaking\": {},", v.handshaking_sessions);
        let _ = writeln!(s, "    \"migrating\": {},", v.migrating_sessions);
        let _ = writeln!(s, "    \"up_sport\": {},", v.active_up_sport);
        let _ = writeln!(s, "    \"backend_sport\": {},", v.active_backend_sport);
        s.push_str("    \"mapped_nat\": ");
        push_json_opt_str(&mut s, self.mapped_nat.as_deref());
        s.push_str(",\n");
        let _ = writeln!(s, "    \"auth_drops_total\": {},", v.auth_drops_total);
        let _ = writeln!(
            s,
            "    \"unauth_silent_drops_total\": {},",
            v.unauth_drops_total
        );
        let _ = writeln!(
            s,
            "    \"unauth_silent_drops_last_10m\": {}",
            v.unauth_drops_last_10m
        );
        s.push_str("  }\n}\n");
        s
    }

    pub(super) fn render_prometheus(&mut self, now: Instant) -> String {
        let v = self.compute_view(now);
        let r = self.role;
        let mut s = String::with_capacity(1400);
        s.push_str(
            "# HELP webrtc_cloak_up 1 while process is running\n# TYPE webrtc_cloak_up gauge\n",
        );
        let _ = writeln!(s, "webrtc_cloak_up{{role=\"{}\"}} 1", r);
        s.push_str("# HELP webrtc_cloak_uptime_seconds Process uptime in seconds\n# TYPE webrtc_cloak_uptime_seconds gauge\n");
        let _ = writeln!(
            s,
            "webrtc_cloak_uptime_seconds{{role=\"{}\"}} {}",
            r, v.uptime_secs
        );
        s.push_str("# HELP webrtc_cloak_health_code 3=good 2=degraded 1=idle 0=critical\n# TYPE webrtc_cloak_health_code gauge\n");
        let _ = writeln!(
            s,
            "webrtc_cloak_health_code{{role=\"{}\",health=\"{}\"}} {}",
            r, v.health, v.health_code
        );
        if let Some(rtt) = self.stun_rtt_ms {
            let _ = writeln!(s, "webrtc_cloak_stun_rtt_ms{{role=\"{}\"}} {:.2}", r, rtt);
        }
        if let Some(ewma) = self.stun_rtt_ewma_ms {
            let _ = writeln!(
                s,
                "webrtc_cloak_stun_rtt_ewma_ms{{role=\"{}\"}} {:.2}",
                r, ewma
            );
        }
        let _ = writeln!(
            s,
            "webrtc_cloak_stun_jitter_ms{{role=\"{}\"}} {:.2}",
            r, self.stun_jitter_ms
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_stun_loss_percent{{role=\"{}\"}} {:.2}",
            r, v.stun_loss_pct
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_tx_mbps{{role=\"{}\"}} {:.3}",
            r, self.tx_mbps
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_rx_mbps{{role=\"{}\"}} {:.3}",
            r, self.rx_mbps
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_tx_bytes_total{{role=\"{}\"}} {}",
            r, v.tx_bytes_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_rx_bytes_total{{role=\"{}\"}} {}",
            r, v.rx_bytes_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_tx_pkts_total{{role=\"{}\"}} {}",
            r, v.tx_pkts_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_rx_pkts_total{{role=\"{}\"}} {}",
            r, v.rx_pkts_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_active_sessions{{role=\"{}\"}} {}",
            r, v.active_sessions
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_migrating_sessions{{role=\"{}\"}} {}",
            r, v.migrating_sessions
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_blackholes_total{{role=\"{}\"}} {}",
            r, self.blackholes_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_blackholes_last_10m{{role=\"{}\"}} {}",
            r, v.blackholes_last_10m
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_migrations_1rtt_total{{role=\"{}\"}} {}",
            r, self.migrations_1rtt_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_migrations_1rtt_last_10m{{role=\"{}\"}} {}",
            r, v.migrations_1rtt_last_10m
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_mbb_rotations_total{{role=\"{}\"}} {}",
            r, self.mbb_rotations_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_graceful_reconnects_total{{role=\"{}\"}} {}",
            r, self.graceful_reconnects_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_auth_drops_total{{role=\"{}\"}} {}",
            r, v.auth_drops_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_unauth_silent_drops_total{{role=\"{}\"}} {}",
            r, v.unauth_drops_total
        );
        let _ = writeln!(
            s,
            "webrtc_cloak_unauth_silent_drops_last_10m{{role=\"{}\"}} {}",
            r, v.unauth_drops_last_10m
        );
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

fn write_http_response(
    stream: &mut TcpStream,
    status_line: &str,
    ctype: Option<&str>,
    extra_hdr: Option<&str>,
    body: &[u8],
    head_only: bool,
) {
    let mut hdr = String::with_capacity(192);
    let _ = write!(hdr, "HTTP/1.1 {}\r\n", status_line);
    if let Some(ct) = ctype {
        let _ = write!(hdr, "Content-Type: {}\r\n", ct);
    }
    if let Some(eh) = extra_hdr {
        let _ = write!(hdr, "{}\r\n", eh);
    }
    let _ = write!(
        hdr,
        "Cache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(hdr.as_bytes());
    if !head_only && !body.is_empty() {
        let _ = stream.write_all(body);
    }
    let _ = stream.flush();
}

pub(super) fn handle_http_connection(mut stream: TcpStream, hub: &TelemetryHub) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(HTTP_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HTTP_IO_TIMEOUT));
    let _ = stream.set_nodelay(true);

    let mut buf = [0u8; HTTP_REQ_BUF_LEN];
    let mut used = 0usize;
    while used < buf.len() {
        match stream.read(&mut buf[used..]) {
            Ok(0) => break,
            Ok(n) => {
                used += n;
                if buf[..used].windows(4).any(|w| w == b"\r\n\r\n")
                    || buf[..used].windows(2).any(|w| w == b"\n\n")
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if used == 0 {
        return;
    }

    let Ok(req_text) = std::str::from_utf8(&buf[..used]) else {
        write_http_response(&mut stream, "400 Bad Request", None, None, b"", false);
        return;
    };
    let first_line = req_text.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_target = parts.next().unwrap_or("/");
    let path = raw_target.split('?').next().unwrap_or("/");

    if method != "GET" && method != "HEAD" {
        write_http_response(
            &mut stream,
            "405 Method Not Allowed",
            None,
            Some("Allow: GET, HEAD"),
            b"",
            false,
        );
        return;
    }
    let head_only = method == "HEAD";

    let (status_line, ctype, body) = match path {
        "/" | "/status" | "/health" => (
            "200 OK",
            "application/json; charset=utf-8",
            hub.snapshot_json(),
        ),
        "/healthz" => {
            let crit = hub.is_critical();
            (
                if crit {
                    "503 Service Unavailable"
                } else {
                    "200 OK"
                },
                "application/json; charset=utf-8",
                hub.snapshot_json(),
            )
        }
        "/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            hub.snapshot_prometheus(),
        ),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found (use /status, /health, /healthz, or /metrics)\n".to_string(),
        ),
    };

    write_http_response(
        &mut stream,
        status_line,
        Some(ctype),
        None,
        body.as_bytes(),
        head_only,
    );
}
