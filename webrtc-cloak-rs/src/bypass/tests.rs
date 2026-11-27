use super::{run_bypass, run_bypass_responder, BypassConfig, BypassResponderConfig};
use crate::client::LaneHuntConfig;
use crate::constants::{DEFAULT_WAN_MTU, STUN_HDR_LEN};
use crate::telemetry::TelemetryConfig;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
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

#[test]
fn bypass_selects_fast_lane_forwards_raw_payload_and_heals_blackhole() {
    let psk = b"test-bypass-ecmp-psk-v050".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    // 1. Start `bypass --responder` (out-of-band redirected STUN responder)
    let resp_port = free_udp_port_v4();
    let resp_status_port = free_udp_port_v4();
    let resp_cfg = BypassResponderConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], resp_port)),
        psk: psk.clone(),
        workers: 1,
        wan_mtu: DEFAULT_WAN_MTU,
        udp_batch: 0,
        stats_interval_secs: 0,
        telemetry: TelemetryConfig {
            status_file: None,
            status_http: Some(SocketAddr::from(([127, 0, 0, 1], resp_status_port))),
            status_interval_secs: 1,
        },
        quiet: true,
        stop: Some(Arc::clone(&stop)),
    };
    let resp_handle = thread::spawn(move || run_bypass_responder(resp_cfg).unwrap());

    // 2. Start raw QUIC-like echo backend (`first_byte >= 0x40`, simulating Hysteria 2 direct)
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
                // Assert NO STUN frame ever leaks into the raw QUIC backend!
                assert!(
                    !(n >= STUN_HDR_LEN && buf[0] <= 3),
                    "STUN frame leaked into raw backend!"
                );
                let _ = echo_sock.send_to(&buf[..n], peer);
            }
        }
    });

    // 3. Simulated ECMP + RFC 7983 first-byte split router:
    //    - Even client source ports get 2ms fast lane; odd ports get 85ms slow lane
    //    - `blocked_port` (when non-zero) simulates sudden mid-session port blackhole!
    let mux_front = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mux_addr = mux_front.local_addr().unwrap();
    mux_front
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let blocked_port = Arc::new(std::sync::atomic::AtomicU16::new(0));
    let blocked_c = Arc::clone(&blocked_port);
    let stop_mux = Arc::clone(&stop);
    let resp_addr = SocketAddr::from(([127, 0, 0, 1], resp_port));

    let mux_handle = thread::spawn(move || {
        let mut pipes: std::collections::HashMap<SocketAddr, (UdpSocket, UdpSocket)> =
            std::collections::HashMap::new();
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

    // 4. Start `webrtc-cloak bypass` forwarder
    let bypass_port = free_udp_port_v4();
    let status_port = free_udp_port_v4();
    let bypass_cfg = BypassConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], bypass_port)),
        server_addr: mux_addr,
        psk: psk.clone(),
        rotate_interval_secs: 0,
        workers: 1,
        max_sessions: 64,
        wan_mtu: DEFAULT_WAN_MTU,
        udp_batch: 8,
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
        telemetry: TelemetryConfig {
            status_file: None,
            status_http: Some(SocketAddr::from(([127, 0, 0, 1], status_port))),
            status_interval_secs: 1,
        },
        quiet: true,
        stop: Some(Arc::clone(&stop)),
    };
    let bypass_handle = thread::spawn(move || run_bypass(bypass_cfg).unwrap());

    thread::sleep(Duration::from_millis(350));

    // Verify unauthenticated junk sent directly to responder is 100% silently dropped
    let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
    attacker
        .set_read_timeout(Some(Duration::from_millis(80)))
        .unwrap();
    attacker
        .send_to(b"\x00\x01garbage-probe-frame-1234", resp_addr)
        .unwrap();
    let mut abuf = [0u8; 128];
    assert!(attacker.recv_from(&mut abuf).is_err());

    // 5. Send raw QUIC-like frames (`0x43 ...`) through `bypass` and verify 100% untouched echo!
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let bypass_addr = SocketAddr::from(([127, 0, 0, 1], bypass_port));

    for seq in 0u32..16 {
        let mut payload = vec![0x43u8; 1200];
        payload[1..5].copy_from_slice(&seq.to_be_bytes());
        app.send_to(&payload, bypass_addr).unwrap();
        let mut rbuf = [0u8; 1500];
        let (n, _) = app.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[..n], &payload[..], "raw payload mutated in bypass!");
    }

    thread::sleep(Duration::from_millis(1100));
    let st1 = http_get_json(SocketAddr::from(([127, 0, 0, 1], status_port)));
    assert_eq!(st1["role"], "bypass");
    assert_eq!(st1["cipher"], "bypass-raw");
    let sport1 = st1["sessions"]["up_sport"].as_u64().unwrap() as u16;
    assert_ne!(sport1, 0);
    // With 6 probes x 3 rounds, probability of hitting an even (2ms) fast port is 1 - 0.5^18 > 99.999%!
    assert_eq!(sport1 % 2, 0, "expected even 2ms fast lane, got {}", sport1);

    // 6. Trigger blackhole on `sport1` and verify automatic escape to a new working port!
    blocked_port.store(sport1, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut switched = false;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(250));
        let mut probe = vec![0x51u8; 256];
        probe[1..5].copy_from_slice(&999u32.to_be_bytes());
        let _ = app.send_to(&probe, bypass_addr);
        let mut rbuf = [0u8; 512];
        if let Ok((n, _)) = app.recv_from(&mut rbuf) {
            if rbuf[..n] == probe[..] {
                let st2 = http_get_json(SocketAddr::from(([127, 0, 0, 1], status_port)));
                let sport2 = st2["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
                if sport2 != 0 && sport2 != sport1 {
                    switched = true;
                    break;
                }
            }
        }
    }
    assert!(
        switched,
        "bypass failed to escape blackholed source port {}",
        sport1
    );

    let resp_st = http_get_json(SocketAddr::from(([127, 0, 0, 1], resp_status_port)));
    assert_eq!(resp_st["role"], "bypass-responder");
    assert!(
        resp_st["sessions"]["unauth_silent_drops_total"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );

    stop.store(true, Ordering::SeqCst);
    bypass_handle.join().unwrap();
    resp_handle.join().unwrap();
    mux_handle.join().unwrap();
    echo_handle.join().unwrap();
}

#[test]
fn bypass_ipv6_loopback_batch_roundtrip() {
    let Ok(probe_v6) = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) else {
        return;
    };
    drop(probe_v6);

    let psk = b"test-bypass-ipv6-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    let echo = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
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

    let listen_v6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap();
    let bh = {
        let cfg = BypassConfig {
            listen_addr: listen_v6,
            server_addr: echo_addr,
            psk,
            rotate_interval_secs: 0,
            workers: 1,
            max_sessions: 16,
            wan_mtu: DEFAULT_WAN_MTU,
            udp_batch: 16,
            retry_ms: 200,
            max_retries: 2,
            keepalive_secs: 5,
            idle_timeout_secs: 30,
            stats_interval_secs: 0,
            lane_hunt: LaneHuntConfig {
                enabled: true,
                probes: 3,
                max_rounds: 2,
                target_rtt_ms: 0,
                degrade_cooldown_secs: 30,
            },
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(Arc::clone(&stop)),
        };
        thread::spawn(move || run_bypass(cfg).unwrap())
    };

    thread::sleep(Duration::from_millis(250));
    let app = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    app.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for i in 0u16..32 {
        let mut pkt = vec![0x60u8; 600];
        pkt[2..4].copy_from_slice(&i.to_be_bytes());
        app.send_to(&pkt, listen_v6).unwrap();
        let mut out = [0u8; 1024];
        let (n, _) = app.recv_from(&mut out).unwrap();
        assert_eq!(&out[..n], &pkt[..]);
    }

    stop.store(true, Ordering::SeqCst);
    bh.join().unwrap();
    eh.join().unwrap();
}
