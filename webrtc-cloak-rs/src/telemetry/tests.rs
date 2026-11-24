//! 遥测健康状态机、原子写盘与 HTTP 端点单元测试。

use super::*;
use std::io::{Read, Write};
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
