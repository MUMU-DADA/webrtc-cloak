use super::{run_relay, RelayConfig, RelayUpstreamConfig};
use crate::bypass::{run_bypass_responder, BypassConfig, BypassResponderConfig};
use crate::client::{run_client, ClientConfig, LaneHuntConfig};
use crate::constants::{DEFAULT_WAN_MTU, STUN_HDR_LEN};
use crate::protocol::{CipherPref, CipherSuite, DtlsMinVersion};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn free_udp_port_v4() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp_port_v4() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn http_get_json(addr: SocketAddr) -> Value {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    s.write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("{}");
    serde_json::from_str(body).unwrap()
}

fn wait_for_status(addr: SocketAddr, pred: impl Fn(&Value) -> bool, timeout: Duration) -> Value {
    let deadline = Instant::now() + timeout;
    let mut last = Value::Null;
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
            if s.write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .is_ok()
            {
                let mut raw = String::new();
                if s.read_to_string(&mut raw).is_ok() {
                    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("{}");
                    if let Ok(v) = serde_json::from_str::<Value>(body) {
                        if pred(&v) {
                            return v;
                        }
                        last = v;
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(120));
    }
    last
}

#[test]
fn relay_bypass_end_to_end_lane_hunt_mbb_blackhole_and_telemetry() {
    let psk_leg1 = b"test-relay-bypass-leg1-psk".to_vec();
    let psk_leg2 = b"test-relay-bypass-leg2-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    // 1. Out-of-band authenticated STUN responder (simulates exit-side RFC 7983 demux)
    let resp_port = free_udp_port_v4();
    let resp_addr = SocketAddr::from(([127, 0, 0, 1], resp_port));
    let resp_cfg = BypassResponderConfig {
        listen_addr: resp_addr,
        psk: psk_leg2.clone(),
        stun_scope: None,
        workers: 1,
        wan_mtu: DEFAULT_WAN_MTU,
        udp_batch: 0,
        stats_interval_secs: 0,
        telemetry: TelemetryConfig::default(),
        quiet: true,
        stop: Some(Arc::clone(&stop)),
    };
    let resp_handle = thread::spawn(move || run_bypass_responder(resp_cfg).unwrap());

    // 2. Raw QUIC-like echo backend (must never receive STUN frames)
    let echo_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo_sock.local_addr().unwrap();
    echo_sock
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let stop_echo = Arc::clone(&stop);
    let echo_handle = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !stop_echo.load(Ordering::Acquire) {
            if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                assert!(
                    !(n >= STUN_HDR_LEN && buf[0] <= 3),
                    "STUN frame leaked into raw backend!"
                );
                let _ = echo_sock.send_to(&buf[..n], peer);
            }
        }
    });

    // 3. Simulated ECMP + RFC 7983 first-byte demux router (even port 2ms fast, odd 85ms slow)
    let mux_front = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mux_addr = mux_front.local_addr().unwrap();
    mux_front
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let blocked_port = Arc::new(AtomicU16::new(0));
    let blocked_c = Arc::clone(&blocked_port);
    let stop_mux = Arc::clone(&stop);
    let mux_handle = thread::spawn(move || {
        let mut pipes: HashMap<SocketAddr, (UdpSocket, UdpSocket)> = HashMap::new();
        let mut delayed: Vec<(Instant, SocketAddr, Vec<u8>)> = Vec::new();
        let mut buf = [0u8; 2048];
        while !stop_mux.load(Ordering::Acquire) {
            if let Ok((n, caddr)) = mux_front.recv_from(&mut buf) {
                if caddr.port() == blocked_c.load(Ordering::Acquire) && caddr.port() != 0 {
                    continue;
                }
                let (stun_s, data_s) = pipes.entry(caddr).or_insert_with(|| {
                    let s1 = UdpSocket::bind("127.0.0.1:0").unwrap();
                    s1.set_nonblocking(true).unwrap();
                    let s2 = UdpSocket::bind("127.0.0.1:0").unwrap();
                    s2.set_nonblocking(true).unwrap();
                    (s1, s2)
                });
                let is_stun = n >= STUN_HDR_LEN && buf[0] <= 3;
                if is_stun {
                    let _ = stun_s.send_to(&buf[..n], resp_addr);
                } else {
                    let _ = data_s.send_to(&buf[..n], echo_addr);
                }
            }

            let now = Instant::now();
            for (&caddr, (stun_s, data_s)) in &pipes {
                let lane_delay = if caddr.port() % 2 == 0 {
                    Duration::from_millis(2)
                } else {
                    Duration::from_millis(85)
                };
                for s in [stun_s, data_s] {
                    while let Ok((n, _)) = s.recv_from(&mut buf) {
                        delayed.push((now + lane_delay, caddr, buf[..n].to_vec()));
                    }
                }
            }

            let mut i = 0;
            while i < delayed.len() {
                if now >= delayed[i].0 {
                    let (_, dst, pkt) = delayed.swap_remove(i);
                    let _ = mux_front.send_to(&pkt, dst);
                } else {
                    i += 1;
                }
            }
        }
    });

    // 4. Native single-process zero-loopback Relay (--upstream-mode bypass, batched)
    let relay_port = free_udp_port_v4();
    let relay_addr = SocketAddr::from(([127, 0, 0, 1], relay_port));
    let relay_status_addr = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let relay_cfg = RelayConfig {
        ingress: ServerConfig {
            listen_addr: relay_addr,
            backend_addr: mux_addr,
            psk: psk_leg1.clone(),
            stun_scope: None,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 64,
            wan_mtu: DEFAULT_WAN_MTU,
            udp_batch: 16,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            wire_audit_file: None,
            telemetry: TelemetryConfig {
                status_file: None,
                status_http: Some(relay_status_addr),
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        },
        upstream: RelayUpstreamConfig::Bypass(BypassConfig {
            listen_addr: relay_addr,
            server_addr: mux_addr,
            psk: psk_leg2,
            stun_scope: Some(resp_port.to_string()),
            rotate_interval_secs: 0,
            workers: 1,
            max_sessions: 64,
            wan_mtu: DEFAULT_WAN_MTU,
            udp_batch: 16,
            retry_ms: 120,
            max_retries: 2,
            keepalive_secs: 1,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            lane_hunt: LaneHuntConfig {
                enabled: true,
                probes: 6,
                max_rounds: 3,
                target_rtt_ms: 30,
                degrade_cooldown_secs: 5,
            },
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        }),
    };
    let relay_handle = thread::spawn(move || run_relay(relay_cfg).unwrap());

    // 5. Leg 1 Client with fast MBB rotation (2s) so we verify 0xFFFC RelayFlow handover!
    let client_port = free_udp_port_v4();
    let client_addr = SocketAddr::from(([127, 0, 0, 1], client_port));
    let client_status_addr = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let client_cfg = ClientConfig {
        listen_addr: client_addr,
        server_addr: relay_addr,
        psk: psk_leg1,
        stun_scope: None,
        cipher_pref: CipherPref::Auto,
        dtls_decoy: true,
        dtls_min_version: DtlsMinVersion::V13Only,
        rotate_interval_secs: 2,
        rotate_max_bytes: 0,
        rotate_cooldown_secs: 1,
        workers: 1,
        max_sessions: 64,
        wan_mtu: DEFAULT_WAN_MTU,
        udp_batch: 16,
        retry_ms: 150,
        max_retries: 8,
        keepalive_secs: 2,
        idle_timeout_secs: 30,
        stats_interval_secs: 0,
        lane_hunt: LaneHuntConfig::default(),
        telemetry: TelemetryConfig {
            status_file: None,
            status_http: Some(client_status_addr),
            status_interval_secs: 1,
        },
        quiet: true,
        stop: Some(Arc::clone(&stop)),
    };
    let client_handle = thread::spawn(move || run_client(client_cfg).unwrap());

    let _ = wait_for_status(relay_status_addr, |_| true, Duration::from_secs(5));
    let _ = wait_for_status(client_status_addr, |_| true, Duration::from_secs(5));

    // Send 24 packets (1200B QUIC-like) through Client -> Relay(bypass) -> Mux -> Echo
    // Warm up with a distinct probe first so slow CI runners finish UDP socket bind cleanly.
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let warm_deadline = Instant::now() + Duration::from_secs(6);
    let warm_pkt = b"relay-bypass-warmup-probe";
    let mut rbuf = [0u8; 1500];
    let mut warm_ok = false;
    while Instant::now() < warm_deadline {
        let _ = app.send_to(warm_pkt, client_addr);
        if let Ok((n, _)) = app.recv_from(&mut rbuf) {
            if &rbuf[..n] == warm_pkt {
                warm_ok = true;
                break;
            }
        }
    }
    assert!(warm_ok, "relay-bypass did not echo warmup packet within 6s");
    app.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for seq in 0u32..24 {
        let mut payload = vec![0x43u8; 1200];
        payload[1..5].copy_from_slice(&seq.to_be_bytes());
        app.send_to(&payload, client_addr).unwrap();
        loop {
            let (n, _) = app.recv_from(&mut rbuf).unwrap();
            if &rbuf[..n] == warm_pkt {
                continue;
            }
            assert_eq!(&rbuf[..n], &payload[..], "payload mismatch on seq {}", seq);
            break;
        }
    }

    // Verify unified relay telemetry (Leg 1 DTLS 1.3 + Leg 2 fast even ECMP lane)
    let st1 = wait_for_status(
        relay_status_addr,
        |v| {
            v["sessions"]["active"].as_u64().unwrap_or(0) >= 1
                && v["sessions"]["up_sport"].as_u64().unwrap_or(0) != 0
                && v["link"]["rx_bytes_total"].as_u64().unwrap_or(0) >= 24 * 1200
                && v["link"]["tx_bytes_total"].as_u64().unwrap_or(0) >= 24 * 1200
        },
        Duration::from_secs(4),
    );
    assert_eq!(st1["role"], "relay-bypass");
    assert_eq!(st1["dtls_version"], "1.3");
    assert_eq!(st1["dual_ssrc"], true);
    assert!(st1["link"]["rx_bytes_total"].as_u64().unwrap_or(0) >= 24 * 1200);
    assert!(st1["link"]["tx_bytes_total"].as_u64().unwrap_or(0) >= 24 * 1200);
    let sport1 = st1["sessions"]["up_sport"].as_u64().unwrap() as u16;
    assert_ne!(sport1, 0);
    assert_eq!(
        sport1 % 2,
        0,
        "expected relay-bypass to pick even 2ms fast lane, got {}",
        sport1
    );

    // Keep flowing data until Leg 1 completes at least one MBB 0xFFFC rotation;
    // verify Leg 2 upstream source port stays IDENTICAL (zero disruption to exit peer!).
    let mbb_deadline = Instant::now() + Duration::from_secs(8);
    let mut seq = 100u32;
    let mut mbb_done = false;
    while Instant::now() < mbb_deadline {
        let mut payload = vec![0x47u8; 1024];
        payload[1..5].copy_from_slice(&seq.to_be_bytes());
        seq += 1;
        app.send_to(&payload, client_addr).unwrap();
        let mut rbuf = [0u8; 1500];
        let (n, _) = app.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[..n], &payload[..]);

        let cst = http_get_json(client_status_addr);
        if cst["events"]["mbb_rotations_total"].as_u64().unwrap_or(0) >= 1 {
            mbb_done = true;
            break;
        }
        thread::sleep(Duration::from_millis(120));
    }
    assert!(mbb_done, "Leg 1 client did not complete MBB rotation");
    let st_after_mbb = http_get_json(relay_status_addr);
    let sport_after_mbb = st_after_mbb["sessions"]["up_sport"].as_u64().unwrap() as u16;
    assert_eq!(
        sport_after_mbb, sport1,
        "Leg 1 MBB handover disrupted Leg 2 upstream port ({} -> {})!",
        sport1, sport_after_mbb
    );

    // Now blackhole Leg 2 `sport1` and verify Relay escapes automatically while Leg 1 stays alive!
    blocked_port.store(sport1, Ordering::Release);
    let bh_deadline = Instant::now() + Duration::from_secs(7);
    let mut escaped = false;
    while Instant::now() < bh_deadline {
        thread::sleep(Duration::from_millis(200));
        let mut probe = vec![0x51u8; 320];
        probe[1..5].copy_from_slice(&seq.to_be_bytes());
        seq += 1;
        let _ = app.send_to(&probe, client_addr);
        let mut rbuf = [0u8; 640];
        let _ = app.set_read_timeout(Some(Duration::from_millis(250)));
        if let Ok((n, _)) = app.recv_from(&mut rbuf) {
            if rbuf[..n] == probe[..] {
                let st2 = http_get_json(relay_status_addr);
                let sport2 = st2["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
                if sport2 != 0 && sport2 != sport1 {
                    escaped = true;
                    break;
                }
            }
        }
    }
    assert!(
        escaped,
        "relay-bypass failed to escape Leg 2 blackholed source port {}",
        sport1
    );

    stop.store(true, Ordering::SeqCst);
    client_handle.join().unwrap();
    relay_handle.join().unwrap();
    mux_handle.join().unwrap();
    resp_handle.join().unwrap();
    echo_handle.join().unwrap();
}

#[test]
fn relay_cloak_end_to_end_double_dtls_dual_stack_and_mbb() {
    let psk_leg1 = b"test-relay-cloak-leg1-psk".to_vec();
    let psk_leg2 = b"test-relay-cloak-leg2-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    // Use IPv6 loopback on Leg 1 if supported (proving zero-loopback IPv6 -> IPv4 relay)
    let leg1_addr = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
        Ok(s) => s.local_addr().unwrap(),
        Err(_) => SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4())),
    };

    // 1. Final UDP echo backend behind Leg 2 Server
    let echo_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo_sock.local_addr().unwrap();
    echo_sock
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let stop_echo = Arc::clone(&stop);
    let echo_handle = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !stop_echo.load(Ordering::Acquire) {
            if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                let _ = echo_sock.send_to(&buf[..n], peer);
            }
        }
    });

    // 2. Exit Server (IPv4, Leg 2 distinct PSK + ChaCha20)
    let exit_addr = SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4()));
    let exit_status_addr = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let exit_cfg = ServerConfig {
        listen_addr: exit_addr,
        backend_addr: echo_addr,
        psk: psk_leg2.clone(),
        stun_scope: None,
        cipher_pref: CipherPref::Fixed(CipherSuite::ChaCha20Poly1305),
        dtls_required: true,
        dtls_min_version: DtlsMinVersion::V13Only,
        workers: 1,
        max_sessions: 64,
        wan_mtu: DEFAULT_WAN_MTU,
        udp_batch: 16,
        idle_timeout_secs: 30,
        stats_interval_secs: 0,
        wire_audit_file: None,
        telemetry: TelemetryConfig {
            status_file: None,
            status_http: Some(exit_status_addr),
            status_interval_secs: 1,
        },
        quiet: true,
        stop: Some(Arc::clone(&stop)),
    };
    let exit_handle = thread::spawn(move || run_server(exit_cfg).unwrap());

    // 3. Native Relay (--upstream-mode cloak, IPv6/IPv4 Leg 1 AES-GCM -> IPv4 Leg 2 ChaCha20)
    let relay_status_addr = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let relay_cfg = RelayConfig {
        ingress: ServerConfig {
            listen_addr: leg1_addr,
            backend_addr: exit_addr,
            psk: psk_leg1.clone(),
            stun_scope: None,
            cipher_pref: CipherPref::Fixed(CipherSuite::Aes128Gcm),
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 64,
            wan_mtu: DEFAULT_WAN_MTU,
            udp_batch: 16,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            wire_audit_file: None,
            telemetry: TelemetryConfig {
                status_file: None,
                status_http: Some(relay_status_addr),
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        },
        upstream: RelayUpstreamConfig::Cloak(ClientConfig {
            listen_addr: leg1_addr,
            server_addr: exit_addr,
            psk: psk_leg2,
            stun_scope: None,
            cipher_pref: CipherPref::Fixed(CipherSuite::ChaCha20Poly1305),
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 10,
            workers: 1,
            max_sessions: 64,
            wan_mtu: DEFAULT_WAN_MTU,
            udp_batch: 16,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 2,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            lane_hunt: LaneHuntConfig::default(),
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        }),
    };
    let relay_handle = thread::spawn(move || run_relay(relay_cfg).unwrap());

    // 4. Entry Client (Leg 1 AES-GCM, 2s MBB rotation)
    let client_listen = SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4()));
    let client_status_addr = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let client_cfg = ClientConfig {
        listen_addr: client_listen,
        server_addr: leg1_addr,
        psk: psk_leg1,
        stun_scope: None,
        cipher_pref: CipherPref::Fixed(CipherSuite::Aes128Gcm),
        dtls_decoy: true,
        dtls_min_version: DtlsMinVersion::V13Only,
        rotate_interval_secs: 2,
        rotate_max_bytes: 0,
        rotate_cooldown_secs: 1,
        workers: 1,
        max_sessions: 64,
        wan_mtu: DEFAULT_WAN_MTU,
        udp_batch: 16,
        retry_ms: 150,
        max_retries: 8,
        keepalive_secs: 2,
        idle_timeout_secs: 30,
        stats_interval_secs: 0,
        lane_hunt: LaneHuntConfig::default(),
        telemetry: TelemetryConfig {
            status_file: None,
            status_http: Some(client_status_addr),
            status_interval_secs: 1,
        },
        quiet: true,
        stop: Some(Arc::clone(&stop)),
    };
    let client_handle = thread::spawn(move || run_client(client_cfg).unwrap());

    let _ = wait_for_status(exit_status_addr, |_| true, Duration::from_secs(5));
    let _ = wait_for_status(relay_status_addr, |_| true, Duration::from_secs(5));
    let _ = wait_for_status(client_status_addr, |_| true, Duration::from_secs(5));

    // Warm up double-DTLS 1.3 handshake with a distinct probe to eliminate slow-CI startup bind races.
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let warm_deadline = Instant::now() + Duration::from_secs(8);
    let warm_pkt = b"relay-cloak-warmup-probe";
    let mut rbuf = [0u8; 1500];
    let mut warm_ok = false;
    while Instant::now() < warm_deadline {
        let _ = app.send_to(warm_pkt, client_listen);
        if let Ok((n, _)) = app.recv_from(&mut rbuf) {
            if &rbuf[..n] == warm_pkt {
                warm_ok = true;
                break;
            }
        }
    }
    assert!(
        warm_ok,
        "double-DTLS relay-cloak did not echo warmup packet within 8s"
    );
    app.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for seq in 0u32..24 {
        let mut payload = vec![0x62u8; 1100];
        payload[1..5].copy_from_slice(&seq.to_be_bytes());
        app.send_to(&payload, client_listen).unwrap();
        loop {
            let (n, _) = app.recv_from(&mut rbuf).unwrap();
            if &rbuf[..n] == warm_pkt {
                continue;
            }
            assert_eq!(&rbuf[..n], &payload[..], "double-DTLS payload mismatch");
            break;
        }
    }

    let rst = wait_for_status(
        relay_status_addr,
        |v| {
            v["sessions"]["active"].as_u64().unwrap_or(0) >= 1
                && v["sessions"]["up_sport"].as_u64().unwrap_or(0) != 0
                && v["link"]["rx_bytes_total"].as_u64().unwrap_or(0) >= 24 * 1100
                && v["link"]["tx_bytes_total"].as_u64().unwrap_or(0) >= 24 * 1100
        },
        Duration::from_secs(4),
    );
    assert_eq!(rst["role"], "relay-cloak");
    assert_eq!(rst["dtls_version"], "1.3");
    assert_eq!(rst["cipher"], "aes-128-gcm");
    assert_eq!(rst["dual_ssrc"], true);
    assert!(rst["link"]["rx_bytes_total"].as_u64().unwrap_or(0) >= 24 * 1100);
    assert!(rst["link"]["tx_bytes_total"].as_u64().unwrap_or(0) >= 24 * 1100);
    let leg2_sport_before = rst["sessions"]["up_sport"].as_u64().unwrap() as u16;
    assert_ne!(leg2_sport_before, 0);

    let est1 = wait_for_status(
        exit_status_addr,
        |v| v["sessions"]["backend_sport"].as_u64().unwrap_or(0) != 0,
        Duration::from_secs(4),
    );
    assert_eq!(est1["cipher"], "chacha20-poly1305");
    let exit_backend_sport = est1["sessions"]["backend_sport"].as_u64().unwrap() as u16;

    // Wait for Leg 1 MBB rotation and prove Leg 2 tunnel + exit backend port stay completely intact
    let mbb_deadline = Instant::now() + Duration::from_secs(8);
    let mut seq = 200u32;
    let mut mbb_done = false;
    while Instant::now() < mbb_deadline {
        let mut payload = vec![0x65u8; 900];
        payload[1..5].copy_from_slice(&seq.to_be_bytes());
        seq += 1;
        app.send_to(&payload, client_listen).unwrap();
        let mut rbuf = [0u8; 1500];
        let (n, _) = app.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[..n], &payload[..]);
        let cst = http_get_json(client_status_addr);
        if cst["events"]["mbb_rotations_total"].as_u64().unwrap_or(0) >= 1 {
            mbb_done = true;
            break;
        }
        thread::sleep(Duration::from_millis(120));
    }
    assert!(mbb_done, "Leg 1 MBB rotation did not occur in relay-cloak");

    let rst2 = http_get_json(relay_status_addr);
    assert_eq!(
        rst2["sessions"]["up_sport"].as_u64().unwrap() as u16,
        leg2_sport_before,
        "Leg 1 MBB disrupted Leg 2 Cloak session!"
    );
    let est2 = http_get_json(exit_status_addr);
    assert_eq!(
        est2["sessions"]["backend_sport"].as_u64().unwrap() as u16,
        exit_backend_sport,
        "Exit server backend socket changed across Leg 1 MBB!"
    );

    stop.store(true, Ordering::SeqCst);
    client_handle.join().unwrap();
    relay_handle.join().unwrap();
    exit_handle.join().unwrap();
    echo_handle.join().unwrap();
}

#[test]
fn relay_single_packet_mode_and_unauth_silent_drop() {
    let psk = b"test-relay-single-pkt-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    // Direct echo backend with inline STUN responder for Leg 2 bypass (single-packet udp_batch=0)
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    echo.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let stop_e = Arc::clone(&stop);
    let psk_e = psk.clone();
    let eh = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !stop_e.load(Ordering::Acquire) {
            if let Ok((n, peer)) = echo.recv_from(&mut buf) {
                if n >= STUN_HDR_LEN && buf[0] <= 3 {
                    if let Some(p) = crate::protocol::parse_stun(&buf[..n], &psk_e) {
                        if p.authenticated {
                            let resp =
                                crate::protocol::build_stun_success_response(&p.txid, peer, &psk_e);
                            let _ = echo.send_to(&resp, peer);
                        }
                    }
                } else {
                    let _ = echo.send_to(&buf[..n], peer);
                }
            }
        }
    });

    let relay_addr = SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4()));
    let relay_status_addr = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let relay_cfg = RelayConfig {
        ingress: ServerConfig {
            listen_addr: relay_addr,
            backend_addr: echo_addr,
            psk: psk.clone(),
            stun_scope: None,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: DEFAULT_WAN_MTU,
            udp_batch: 0,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            wire_audit_file: None,
            telemetry: TelemetryConfig {
                status_file: None,
                status_http: Some(relay_status_addr),
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        },
        upstream: RelayUpstreamConfig::Bypass(BypassConfig {
            listen_addr: relay_addr,
            server_addr: echo_addr,
            psk: psk.clone(),
            stun_scope: None,
            rotate_interval_secs: 0,
            workers: 1,
            max_sessions: 32,
            wan_mtu: DEFAULT_WAN_MTU,
            udp_batch: 0,
            retry_ms: 150,
            max_retries: 2,
            keepalive_secs: 5,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            lane_hunt: LaneHuntConfig {
                enabled: false,
                ..LaneHuntConfig::default()
            },
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        }),
    };
    let rh = thread::spawn(move || run_relay(relay_cfg).unwrap());

    let client_listen = SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4()));
    let client_cfg = ClientConfig {
        listen_addr: client_listen,
        server_addr: relay_addr,
        psk,
        stun_scope: None,
        cipher_pref: CipherPref::Auto,
        dtls_decoy: true,
        dtls_min_version: DtlsMinVersion::V13Only,
        rotate_interval_secs: 0,
        rotate_max_bytes: 0,
        rotate_cooldown_secs: 10,
        workers: 1,
        max_sessions: 32,
        wan_mtu: DEFAULT_WAN_MTU,
        udp_batch: 0,
        retry_ms: 150,
        max_retries: 8,
        keepalive_secs: 5,
        idle_timeout_secs: 30,
        stats_interval_secs: 0,
        lane_hunt: LaneHuntConfig::default(),
        telemetry: TelemetryConfig::default(),
        quiet: true,
        stop: Some(Arc::clone(&stop)),
    };
    let ch = thread::spawn(move || run_client(client_cfg).unwrap());

    let _ = wait_for_status(relay_status_addr, |_| true, Duration::from_secs(5));

    // Unauthenticated junk sent directly to relay ingress must be silently dropped
    let scanner = UdpSocket::bind("127.0.0.1:0").unwrap();
    scanner
        .set_read_timeout(Some(Duration::from_millis(80)))
        .unwrap();
    scanner
        .send_to(b"\x00\x01unauth-relay-probe-packet", relay_addr)
        .unwrap();
    let mut sbuf = [0u8; 128];
    assert!(scanner.recv_from(&mut sbuf).is_err());

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let warm_deadline = Instant::now() + Duration::from_secs(6);
    let warm_pkt = b"relay-single-warmup-probe";
    let mut out = [0u8; 1024];
    let mut warm_ok = false;
    while Instant::now() < warm_deadline {
        let _ = app.send_to(warm_pkt, client_listen);
        if let Ok((n, _)) = app.recv_from(&mut out) {
            if &out[..n] == warm_pkt {
                warm_ok = true;
                break;
            }
        }
    }
    assert!(
        warm_ok,
        "relay single-packet mode did not echo warmup packet"
    );
    app.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for i in 0u16..16 {
        let mut pkt = vec![0x77u8; 700];
        pkt[2..4].copy_from_slice(&i.to_be_bytes());
        app.send_to(&pkt, client_listen).unwrap();
        loop {
            let (n, _) = app.recv_from(&mut out).unwrap();
            if &out[..n] == warm_pkt {
                continue;
            }
            assert_eq!(&out[..n], &pkt[..]);
            break;
        }
    }

    let st = wait_for_status(
        relay_status_addr,
        |v| {
            v["sessions"]["unauth_silent_drops_total"]
                .as_u64()
                .unwrap_or(0)
                >= 1
                && v["link"]["rx_bytes_total"].as_u64().unwrap_or(0) >= 16 * 700
                && v["link"]["tx_bytes_total"].as_u64().unwrap_or(0) >= 16 * 700
        },
        Duration::from_secs(4),
    );
    assert!(
        st["sessions"]["unauth_silent_drops_total"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
    assert!(st["link"]["rx_bytes_total"].as_u64().unwrap_or(0) >= 16 * 700);
    assert!(st["link"]["tx_bytes_total"].as_u64().unwrap_or(0) >= 16 * 700);

    stop.store(true, Ordering::SeqCst);
    ch.join().unwrap();
    rh.join().unwrap();
    eh.join().unwrap();
}
