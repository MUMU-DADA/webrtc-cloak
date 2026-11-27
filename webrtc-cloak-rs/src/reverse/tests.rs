use super::{run_reverse_agent, run_reverse_entry, ReverseAgentConfig, ReverseEntryConfig};
use crate::client::{ClientConfig, LaneHuntConfig};
use crate::constants::{DEFAULT_WAN_MTU, REV_OP_FLOW_CLOSE, REV_OP_HELLO, REV_PROTO_VERSION};
use crate::protocol::{
    combine_session_key, derive_stun_material, CipherPref, CipherSuite, DtlsMinVersion,
    SrtpCloakCipher, SrtpFrame,
};
use crate::server::ServerConfig;
use crate::telemetry::TelemetryConfig;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
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
        thread::sleep(Duration::from_millis(100));
    }
    last
}

#[test]
fn srtp_reverse_data_and_ctrl_frame_roundtrip() {
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(b"rev-frame-psk", &[7u8; 12], "u1:u2");
    let skey = combine_session_key(&stun_key, None);
    for suite in [
        CipherSuite::Aes128Gcm,
        CipherSuite::ChaCha20Poly1305,
        CipherSuite::Blake2b,
    ] {
        let mut tx = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
        let mut rx = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);
        tx.set_dual_ssrc(true);
        rx.set_dual_ssrc(true);

        let mut wire = vec![0u8; 2048];
        let mut out = vec![0u8; 2048];

        // 1. ReverseData frame roundtrip
        let payload = b"wireguard-reverse-payload-0123456789";
        let wn = tx
            .wrap_reverse_data_into(0x0102_0304, payload, &mut wire)
            .unwrap();
        assert_eq!(
            rx.unwrap_into_ex(&wire[..wn], &mut out),
            Some(SrtpFrame::ReverseData {
                flow_id: 0x0102_0304,
                len: payload.len()
            })
        );
        assert_eq!(&out[..payload.len()], payload);

        // 2. ReverseCtrl HELLO + FLOW_CLOSE roundtrip
        let hello = [REV_OP_HELLO, REV_PROTO_VERSION];
        let wn2 = tx.wrap_reverse_ctrl_into(&hello, &mut wire).unwrap();
        assert_eq!(
            rx.unwrap_into_ex(&wire[..wn2], &mut out),
            Some(SrtpFrame::ReverseCtrl(hello.len()))
        );
        assert_eq!(&out[..hello.len()], &hello);

        let mut close_msg = [0u8; 5];
        close_msg[0] = REV_OP_FLOW_CLOSE;
        close_msg[1..5].copy_from_slice(&42u32.to_be_bytes());
        let wn3 = tx.wrap_reverse_ctrl_into(&close_msg, &mut wire).unwrap();
        assert_eq!(
            rx.unwrap_into_ex(&wire[..wn3], &mut out),
            Some(SrtpFrame::ReverseCtrl(5))
        );
        assert_eq!(&out[..5], &close_msg);
    }
}

#[test]
fn reverse_tunnel_multi_peer_pinned_ports_and_mbb_zero_loss() {
    let psk = b"test-reverse-mbb-psk-2026".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    // 1. Local UDP Echo backend behind NAT Agent that records the exact backend source port seen per tag!
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let backend_addr = echo.local_addr().unwrap();
    echo.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let seen_ports: Arc<Mutex<HashMap<u8, Vec<u16>>>> = Arc::new(Mutex::new(HashMap::new()));
    let seen_c = Arc::clone(&seen_ports);
    let stop_e = Arc::clone(&stop);
    let echo_handle = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !stop_e.load(Ordering::Acquire) {
            if let Ok((n, peer)) = echo.recv_from(&mut buf) {
                if n > 0 {
                    let mut map = seen_c.lock().unwrap();
                    let entry = map.entry(buf[0]).or_default();
                    if !entry.contains(&peer.port()) {
                        entry.push(peer.port());
                    }
                }
                let _ = echo.send_to(&buf[..n], peer);
            }
        }
    });

    // 2. Start Reverse Entry (public side: tunnel_addr + expose_addr, batched)
    let tunnel_addr = SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4()));
    let expose_addr = SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4()));
    let entry_status = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let entry_cfg = ReverseEntryConfig {
        server: ServerConfig {
            listen_addr: tunnel_addr,
            backend_addr: expose_addr,
            psk: psk.clone(),
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
                status_http: Some(entry_status),
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        },
        expose_addr,
    };
    let entry_handle = thread::spawn(move || run_reverse_entry(entry_cfg).unwrap());

    // 3. Start Reverse Agent (NAT side: 0 open ports, dials Entry immediately, 2s MBB rotation)
    let agent_status = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let agent_cfg = ReverseAgentConfig {
        client: ClientConfig {
            listen_addr: backend_addr,
            server_addr: tunnel_addr,
            psk,
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
                status_http: Some(agent_status),
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        },
        backend_addr,
    };
    let agent_handle = thread::spawn(move || run_reverse_agent(agent_cfg).unwrap());

    // Wait for Agent to register automatically (even with 0 user traffic!)
    let ast0 = wait_for_status(
        agent_status,
        |v| v["sessions"]["active"].as_u64().unwrap_or(0) >= 1,
        Duration::from_secs(4),
    );
    assert_eq!(ast0["role"], "reverse-agent");
    assert_eq!(ast0["dtls_version"], "1.3");
    assert_eq!(ast0["dual_ssrc"], true);

    // 4. Two concurrent entry peers talk through Entry's expose_addr -> Agent -> backend
    let peer_a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_b = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer_a
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    peer_b
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // Stream continuously until MBB rotation completes on the persistent reverse tunnel!
    let mbb_deadline = Instant::now() + Duration::from_secs(8);
    let mut seq = 0u32;
    let mut mbb_done = false;
    let mut rbuf = [0u8; 2048];
    while Instant::now() < mbb_deadline {
        let mut pa = vec![0xAAu8; 900];
        pa[1..5].copy_from_slice(&seq.to_be_bytes());
        peer_a.send_to(&pa, expose_addr).unwrap();
        let (na, _) = peer_a.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[..na], &pa[..], "peer_a echo mismatch on seq {}", seq);

        let mut pb = vec![0xBBu8; 900];
        pb[1..5].copy_from_slice(&seq.to_be_bytes());
        peer_b.send_to(&pb, expose_addr).unwrap();
        let (nb, _) = peer_b.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[..nb], &pb[..], "peer_b echo mismatch on seq {}", seq);

        seq += 1;
        if seq >= 12 {
            let ast = http_get_json(agent_status);
            if ast["events"]["mbb_rotations_total"].as_u64().unwrap_or(0) >= 1 {
                mbb_done = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(80));
    }
    assert!(
        mbb_done,
        "reverse agent did not complete MBB 0xFFFC rotation"
    );

    // Verify backend saw EXACTLY 1 pinned port per entry peer and 2 distinct ports across peers!
    {
        let map = seen_ports.lock().unwrap();
        let ports_a = map.get(&0xAA).expect("peer_a packets must reach backend");
        let ports_b = map.get(&0xBB).expect("peer_b packets must reach backend");
        assert_eq!(
            ports_a.len(),
            1,
            "peer_a backend source port drifted across MBB rotation: {:?}",
            ports_a
        );
        assert_eq!(
            ports_b.len(),
            1,
            "peer_b backend source port drifted across MBB rotation: {:?}",
            ports_b
        );
        assert_ne!(
            ports_a[0], ports_b[0],
            "distinct entry peers must map to distinct pinned backend sockets"
        );
    }

    let est = wait_for_status(
        entry_status,
        |v| {
            v["sessions"]["active"].as_u64().unwrap_or(0) >= 1
                && v["link"]["rx_bytes_total"].as_u64().unwrap_or(0) > 0
                && v["link"]["tx_bytes_total"].as_u64().unwrap_or(0) > 0
        },
        Duration::from_secs(3),
    );
    assert_eq!(est["role"], "reverse-entry");
    assert_eq!(est["dtls_version"], "1.3");
    assert_eq!(est["dual_ssrc"], true);

    stop.store(true, Ordering::SeqCst);
    agent_handle.join().unwrap();
    entry_handle.join().unwrap();
    echo_handle.join().unwrap();
}

#[test]
fn reverse_tunnel_1rtt_blackhole_escape_and_agent_reconnect() {
    let psk = b"test-reverse-bh-reconnect-psk".to_vec();
    let stop_all = Arc::new(AtomicBool::new(false));
    let stop_agent1 = Arc::new(AtomicBool::new(false));

    // 1. Local echo backend behind Agent
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let backend_addr = echo.local_addr().unwrap();
    echo.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let stop_e = Arc::clone(&stop_all);
    let echo_handle = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !stop_e.load(Ordering::Acquire) {
            if let Ok((n, peer)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], peer);
            }
        }
    });

    // 2. Entry node
    let entry_tunnel_addr = SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4()));
    let expose_addr = SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4()));
    let entry_cfg = ReverseEntryConfig {
        server: ServerConfig {
            listen_addr: entry_tunnel_addr,
            backend_addr: expose_addr,
            psk: psk.clone(),
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: DEFAULT_WAN_MTU,
            udp_batch: 8,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(Arc::clone(&stop_all)),
        },
        expose_addr,
    };
    let entry_handle = thread::spawn(move || run_reverse_entry(entry_cfg).unwrap());

    // 3. Programmable WAN blackhole proxy between Agent and Entry
    let proxy_front = UdpSocket::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_front.local_addr().unwrap();
    proxy_front
        .set_read_timeout(Some(Duration::from_millis(15)))
        .unwrap();
    let blocked_port = Arc::new(AtomicU16::new(0));
    let blocked_c = Arc::clone(&blocked_port);
    let stop_p = Arc::clone(&stop_all);
    let proxy_handle = thread::spawn(move || {
        let mut back_socks: HashMap<SocketAddr, UdpSocket> = HashMap::new();
        let mut buf = [0u8; 2048];
        while !stop_p.load(Ordering::Acquire) {
            if let Ok((n, caddr)) = proxy_front.recv_from(&mut buf) {
                if caddr.port() == blocked_c.load(Ordering::Acquire) && caddr.port() != 0 {
                    continue;
                }
                let bs = back_socks.entry(caddr).or_insert_with(|| {
                    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                    s.set_nonblocking(true).unwrap();
                    s
                });
                let _ = bs.send_to(&buf[..n], entry_tunnel_addr);
            }
            for (&caddr, bs) in &back_socks {
                while let Ok((n, _)) = bs.recv_from(&mut buf) {
                    if caddr.port() != blocked_c.load(Ordering::Acquire) {
                        let _ = proxy_front.send_to(&buf[..n], caddr);
                    }
                }
            }
        }
    });

    // 4. Agent #1 (fast keepalive=1s so blackhole triggers 1-RTT migration quickly)
    let agent1_status = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let agent1_cfg = ReverseAgentConfig {
        client: ClientConfig {
            listen_addr: backend_addr,
            server_addr: proxy_addr,
            psk: psk.clone(),
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 10,
            workers: 1,
            max_sessions: 32,
            wan_mtu: DEFAULT_WAN_MTU,
            udp_batch: 8,
            retry_ms: 120,
            max_retries: 8,
            keepalive_secs: 1,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            lane_hunt: LaneHuntConfig::default(),
            telemetry: TelemetryConfig {
                status_file: None,
                status_http: Some(agent1_status),
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(Arc::clone(&stop_agent1)),
        },
        backend_addr,
    };
    let agent1_handle = thread::spawn(move || run_reverse_agent(agent1_cfg).unwrap());

    let ast1 = wait_for_status(
        agent1_status,
        |v| {
            v["sessions"]["active"].as_u64().unwrap_or(0) >= 1
                && v["sessions"]["up_sport"].as_u64().unwrap_or(0) != 0
        },
        Duration::from_secs(4),
    );
    let sport1 = ast1["sessions"]["up_sport"].as_u64().unwrap() as u16;
    assert_ne!(sport1, 0);

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut rbuf = [0u8; 1024];

    // Verify initial flow works
    let msg1 = b"before-blackhole-reverse-packet";
    app.send_to(msg1, expose_addr).unwrap();
    let (n1, _) = app.recv_from(&mut rbuf).unwrap();
    assert_eq!(&rbuf[..n1], msg1);

    // Trigger sudden blackhole on Agent #1's upstream port -> verify 1-RTT ICE migration recovers!
    blocked_port.store(sport1, Ordering::Release);
    let bh_deadline = Instant::now() + Duration::from_secs(8);
    let mut migrated = false;
    while Instant::now() < bh_deadline {
        thread::sleep(Duration::from_millis(200));
        let probe = b"after-blackhole-1rtt-probe";
        let _ = app.send_to(probe, expose_addr);
        let _ = app.set_read_timeout(Some(Duration::from_millis(250)));
        if let Ok((n, _)) = app.recv_from(&mut rbuf) {
            if &rbuf[..n] == probe {
                let st2 = http_get_json(agent1_status);
                let sport2 = st2["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
                if sport2 != 0 && sport2 != sport1 {
                    migrated = true;
                    break;
                }
            }
        }
    }
    assert!(
        migrated,
        "reverse agent failed to escape blackholed port {} via 1-RTT migration",
        sport1
    );

    // 5. Simulate complete Agent reboot: shut down Agent #1 and start Agent #2 against the SAME Entry!
    stop_agent1.store(true, Ordering::SeqCst);
    agent1_handle.join().unwrap();
    blocked_port.store(0, Ordering::Release);

    let agent2_cfg = ReverseAgentConfig {
        client: ClientConfig {
            listen_addr: backend_addr,
            server_addr: entry_tunnel_addr,
            psk,
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
            retry_ms: 120,
            max_retries: 8,
            keepalive_secs: 5,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            lane_hunt: LaneHuntConfig::default(),
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(Arc::clone(&stop_all)),
        },
        backend_addr,
    };
    let agent2_handle = thread::spawn(move || run_reverse_agent(agent2_cfg).unwrap());

    let rebind_deadline = Instant::now() + Duration::from_secs(4);
    let mut rebound = false;
    while Instant::now() < rebind_deadline {
        let msg2 = b"after-agent-reboot-rebind-ok";
        let _ = app.send_to(msg2, expose_addr);
        let _ = app.set_read_timeout(Some(Duration::from_millis(250)));
        if let Ok((n, _)) = app.recv_from(&mut rbuf) {
            if &rbuf[..n] == msg2 {
                rebound = true;
                break;
            }
        }
    }
    assert!(
        rebound,
        "fresh reverse agent failed to seamlessly rebind running reverse entry"
    );

    stop_all.store(true, Ordering::SeqCst);
    agent2_handle.join().unwrap();
    entry_handle.join().unwrap();
    proxy_handle.join().unwrap();
    echo_handle.join().unwrap();
}

#[test]
fn reverse_tunnel_ipv6_cross_family_preconnect_buffer_and_silent_drop() {
    let psk = b"test-reverse-v6-cross-family-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    // Use IPv6 loopback for outer tunnel if available (IPv4 exposed flows over IPv6 tunnel!)
    let tunnel_addr = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
        Ok(s) => s.local_addr().unwrap(),
        Err(_) => SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4())),
    };

    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let backend_addr = echo.local_addr().unwrap();
    echo.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let stop_e = Arc::clone(&stop);
    let echo_handle = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !stop_e.load(Ordering::Acquire) {
            if let Ok((n, peer)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], peer);
            }
        }
    });

    // Start Entry FIRST (before Agent!) in single-packet mode (`udp_batch: 0`)
    let expose_addr = SocketAddr::from(([127, 0, 0, 1], free_udp_port_v4()));
    let entry_status = SocketAddr::from(([127, 0, 0, 1], free_tcp_port_v4()));
    let entry_cfg = ReverseEntryConfig {
        server: ServerConfig {
            listen_addr: tunnel_addr,
            backend_addr: expose_addr,
            psk: psk.clone(),
            cipher_pref: CipherPref::Fixed(CipherSuite::ChaCha20Poly1305),
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
                status_http: Some(entry_status),
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        },
        expose_addr,
    };
    let entry_handle = thread::spawn(move || run_reverse_entry(entry_cfg).unwrap());
    let _ = wait_for_status(entry_status, |_| true, Duration::from_secs(5));
    thread::sleep(Duration::from_millis(120));

    // 1. Unauthenticated scanner probe sent to Entry tunnel port MUST be 100% silently dropped
    let scanner = if tunnel_addr.is_ipv6() {
        UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap()
    } else {
        UdpSocket::bind("127.0.0.1:0").unwrap()
    };
    scanner
        .set_read_timeout(Some(Duration::from_millis(80)))
        .unwrap();
    scanner
        .send_to(b"\x00\x01unauth-reverse-probe-packet", tunnel_addr)
        .unwrap();
    let mut sbuf = [0u8; 64];
    assert!(scanner.recv_from(&mut sbuf).is_err());

    // 2. Send an app packet to Entry expose_addr BEFORE Agent connects (tests pre-connect burst buffer!)
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let early_msg = b"early-buffered-packet-before-agent-online";
    app.send_to(early_msg, expose_addr).unwrap();

    // 3. Now start Agent (ChaCha20-Poly1305, single-packet mode) -> early packet MUST flush & echo back!
    let agent_cfg = ReverseAgentConfig {
        client: ClientConfig {
            listen_addr: backend_addr,
            server_addr: tunnel_addr,
            psk,
            cipher_pref: CipherPref::Fixed(CipherSuite::ChaCha20Poly1305),
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
        },
        backend_addr,
    };
    let agent_handle = thread::spawn(move || run_reverse_agent(agent_cfg).unwrap());

    let mut rbuf = [0u8; 1024];
    let (n0, _) = app.recv_from(&mut rbuf).unwrap();
    assert_eq!(&rbuf[..n0], early_msg, "pre-connect buffered packet lost!");

    for i in 0u16..16 {
        let mut pkt = vec![0x55u8; 800];
        pkt[2..4].copy_from_slice(&i.to_be_bytes());
        app.send_to(&pkt, expose_addr).unwrap();
        let (n, _) = app.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[..n], &pkt[..]);
    }

    let st = wait_for_status(
        entry_status,
        |v| {
            v["sessions"]["unauth_silent_drops_total"]
                .as_u64()
                .unwrap_or(0)
                >= 1
                && v["cipher"].as_str() == Some("chacha20-poly1305")
        },
        Duration::from_secs(3),
    );
    assert!(
        st["sessions"]["unauth_silent_drops_total"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
    assert_eq!(st["cipher"], "chacha20-poly1305");

    stop.store(true, Ordering::SeqCst);
    agent_handle.join().unwrap();
    entry_handle.join().unwrap();
    echo_handle.join().unwrap();
}
