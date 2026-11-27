//! 内嵌类 Hy2 代理模式全链路单元测试与弱网/中继集成测试。

use super::brutal::{BrutalConfig, BrutalController, BrutalRateHandle};
use super::proto::{
    decode_udp_datagram, encode_udp_datagrams, parse_bandwidth_bps, parse_tcp_forward_rule,
    AclConfig, AclRule, TargetAddr, UdpFragReassembler,
};
use super::quic_crypto::{
    build_endpoint_config, build_quic_client_config, build_quic_server_config,
    build_transport_config, compute_inner_quic_mtu, DEFAULT_PROXY_INNER_MTU,
};
use super::{
    run_proxy_client, run_proxy_client_reverse, run_proxy_server, run_proxy_server_reverse,
    ProxyClientConfig, ProxyServerConfig, ReverseProxyClientConfig, ReverseProxyServerConfig,
};
use crate::client::{ClientConfig, LaneHuntConfig};
use crate::protocol::{CipherPref, DtlsMinVersion};
use crate::relay::{run_relay, RelayConfig, RelayUpstreamConfig};
use crate::server::ServerConfig;
use crate::telemetry::TelemetryConfig;
use bytes::{Bytes, BytesMut};
use quinn_proto::congestion::Controller;
use quinn_proto::{DatagramEvent, Dir, Endpoint, Event};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_tcp_ready(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("TCP listener {} never became ready", addr);
}

#[test]
fn test_noop_quic_handshake_stream_and_datagram() {
    let now = Instant::now();
    let mtu = 1380u16;

    let c_brutal = Arc::new(BrutalConfig::new(50_000_000));
    let s_brutal = Arc::new(BrutalConfig::new(50_000_000));
    let c_transport = build_transport_config(mtu, c_brutal, 30, Some(10));
    let s_transport = build_transport_config(mtu, s_brutal, 30, None);

    let mut c_ep = Endpoint::new(Arc::new(build_endpoint_config(mtu)), None, true, None);
    let mut s_ep = Endpoint::new(
        Arc::new(build_endpoint_config(mtu)),
        Some(build_quic_server_config(s_transport)),
        true,
        None,
    );

    let c_addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let s_addr: SocketAddr = "127.0.0.1:40002".parse().unwrap();

    let (c_handle, mut c_conn) = c_ep
        .connect(now, build_quic_client_config(c_transport), s_addr, "test")
        .unwrap();
    let mut s_conn_opt = None;
    let mut s_handle_opt = None;

    let mut c_connected = false;
    let mut s_connected = false;
    let mut tx_buf = Vec::new();
    let mut resp_buf = Vec::new();

    for step in 0..40 {
        let t = now + Duration::from_millis(step * 5);

        // Client -> Server
        loop {
            tx_buf.clear();
            let Some(tr) = c_conn.poll_transmit(t, 1, &mut tx_buf) else {
                break;
            };
            resp_buf.clear();
            match s_ep.handle(
                t,
                c_addr,
                None,
                None,
                BytesMut::from(&tx_buf[..tr.size]),
                &mut resp_buf,
            ) {
                Some(DatagramEvent::NewConnection(inc)) => {
                    resp_buf.clear();
                    let (sh, sc) = s_ep.accept(inc, t, &mut resp_buf, None).unwrap();
                    s_handle_opt = Some(sh);
                    s_conn_opt = Some(sc);
                }
                Some(DatagramEvent::ConnectionEvent(_, cev)) => {
                    if let Some(ref mut sc) = s_conn_opt {
                        sc.handle_event(cev);
                    }
                }
                _ => {}
            }
        }
        while let Some(ev) = c_conn.poll_endpoint_events() {
            if let Some(cev) = c_ep.handle_event(c_handle, ev) {
                c_conn.handle_event(cev);
            }
        }
        while let Some(ev) = c_conn.poll() {
            match ev {
                Event::Connected => c_connected = true,
                Event::ConnectionLost { reason } => panic!("client lost: {:?}", reason),
                _ => {}
            }
        }

        // Server -> Client
        if let (Some(sh), Some(ref mut sc)) = (s_handle_opt, s_conn_opt.as_mut()) {
            loop {
                tx_buf.clear();
                let Some(tr) = sc.poll_transmit(t, 1, &mut tx_buf) else {
                    break;
                };
                resp_buf.clear();
                if let Some(DatagramEvent::ConnectionEvent(_, cev)) = c_ep.handle(
                    t,
                    s_addr,
                    None,
                    None,
                    BytesMut::from(&tx_buf[..tr.size]),
                    &mut resp_buf,
                ) {
                    c_conn.handle_event(cev);
                }
            }
            while let Some(ev) = sc.poll_endpoint_events() {
                if let Some(cev) = s_ep.handle_event(sh, ev) {
                    sc.handle_event(cev);
                }
            }
            while let Some(ev) = sc.poll() {
                match ev {
                    Event::Connected => s_connected = true,
                    Event::ConnectionLost { reason } => panic!("server lost: {:?}", reason),
                    _ => {}
                }
            }
        }

        if c_connected && s_connected {
            break;
        }
    }

    assert!(c_connected, "No-op QUIC client did not connect");
    assert!(s_connected, "No-op QUIC server did not connect");

    // Verify zero-tag 1-RTT bidirectional stream + RFC 9221 Datagram delivery
    let mut s_conn = s_conn_opt.unwrap();
    let payload: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
    let sid = c_conn.streams().open(Dir::Bi).unwrap();
    let mut sent = 0usize;
    let mut received = Vec::new();
    c_conn
        .datagrams()
        .send(Bytes::from_static(b"hello-dgram-9221"), false)
        .unwrap();
    let mut got_dgram: Option<Bytes> = None;

    for step in 40..400 {
        let t = now + Duration::from_millis(step * 2);
        if sent < payload.len() {
            if let Ok(n) = c_conn.send_stream(sid).write(&payload[sent..]) {
                sent += n;
                if sent == payload.len() {
                    let _ = c_conn.send_stream(sid).finish();
                }
            }
        }
        loop {
            tx_buf.clear();
            let Some(tr) = c_conn.poll_transmit(t, 1, &mut tx_buf) else {
                break;
            };
            resp_buf.clear();
            if let Some(DatagramEvent::ConnectionEvent(_, cev)) = s_ep.handle(
                t,
                c_addr,
                None,
                None,
                BytesMut::from(&tx_buf[..tr.size]),
                &mut resp_buf,
            ) {
                s_conn.handle_event(cev);
            }
        }
        while let Some(d) = s_conn.datagrams().recv() {
            got_dgram = Some(d);
        }
        while s_conn.streams().accept(Dir::Bi).is_some() {}
        if let Ok(mut chunks) = s_conn.recv_stream(sid).read(true) {
            while let Ok(Some(ch)) = chunks.next(32 * 1024) {
                received.extend_from_slice(&ch.bytes);
            }
            let _ = chunks.finalize();
        }
        loop {
            tx_buf.clear();
            let Some(tr) = s_conn.poll_transmit(t, 1, &mut tx_buf) else {
                break;
            };
            resp_buf.clear();
            if let Some(DatagramEvent::ConnectionEvent(_, cev)) = c_ep.handle(
                t,
                s_addr,
                None,
                None,
                BytesMut::from(&tx_buf[..tr.size]),
                &mut resp_buf,
            ) {
                c_conn.handle_event(cev);
            }
        }
        if received.len() == payload.len() && got_dgram.is_some() {
            break;
        }
    }

    assert_eq!(received, payload);
    assert_eq!(got_dgram.as_deref(), Some(b"hello-dgram-9221".as_slice()));
}

#[test]
fn test_proxy_inner_mtu_camouflage_default_and_override_clamping() {
    // Default converges to 1200B (outer ~1238..1269B, aligned with Hy2/WebRTC + full 0..31B SRTP pad)
    assert_eq!(
        compute_inner_quic_mtu(1488, 28, None),
        DEFAULT_PROXY_INNER_MTU
    );
    assert_eq!(
        compute_inner_quic_mtu(1488, 48, None),
        DEFAULT_PROXY_INNER_MTU
    );
    assert_eq!(compute_inner_quic_mtu(0, 28, None), DEFAULT_PROXY_INNER_MTU);
    // Explicit --proxy-mtu override works up to safe anti-fragmentation ceiling
    assert_eq!(compute_inner_quic_mtu(1488, 28, Some(1380)), 1380);
    assert_eq!(compute_inner_quic_mtu(1488, 28, Some(1500)), 1414);
    assert_eq!(compute_inner_quic_mtu(1488, 48, Some(1500)), 1394);
    assert_eq!(compute_inner_quic_mtu(1488, 28, Some(900)), 1200);
}

#[test]
fn test_brutal_loss_compensation_and_dynamic_rate() {
    let start = Instant::now();
    let rate = Arc::new(BrutalRateHandle::new(50_000_000)); // 400 Mbps = 50 MB/s
    let mut ctrl = BrutalController::new(Arc::clone(&rate), 0.70, start, 1380);
    let rtt = Duration::from_millis(100);

    // 0% loss baseline (100 acked pkts)
    for _ in 0..100 {
        ctrl.record_test_ack(start + Duration::from_millis(500), 1380, rtt);
    }
    let cwnd_clean = ctrl.window();

    // 10% loss (11 lost pkts out of ~111 total) -> cwnd MUST INCREASE (never collapse!)
    for _ in 0..11 {
        ctrl.on_congestion_event(start + Duration::from_millis(600), start, false, 1380);
    }
    let cwnd_loss10 = ctrl.window();
    assert!(
        cwnd_loss10 > cwnd_clean,
        "Brutal must compensate loss, not collapse: clean={} loss10={}",
        cwnd_clean,
        cwnd_loss10
    );

    // Extreme 60% loss -> clamped cleanly at 1 / 0.70 ≈ 1.43x
    for _ in 0..200 {
        ctrl.on_congestion_event(start + Duration::from_millis(700), start, true, 1380);
    }
    let cwnd_clamped = ctrl.window();
    let ratio = cwnd_clamped as f64 / cwnd_clean as f64;
    assert!(
        (1.38..=1.48).contains(&ratio),
        "Brutal clamp ratio out of expected 1/0.70 range: {:.3}",
        ratio
    );

    // Dynamic rate update via shared handle takes effect immediately
    rate.store(12_500_000); // 100 Mbps
    let cwnd_quarter = ctrl.window();
    assert!(
        cwnd_quarter < cwnd_clamped / 3,
        "Dynamic rate decrease did not immediately reduce cwnd"
    );
}

#[test]
fn test_proto_bandwidth_acl_and_udp_frag() {
    assert_eq!(parse_bandwidth_bps("420 Mbps").unwrap(), 420_000_000);
    assert_eq!(parse_bandwidth_bps("100m").unwrap(), 100_000_000);
    assert_eq!(parse_bandwidth_bps("1g").unwrap(), 1_000_000_000);
    assert_eq!(parse_bandwidth_bps("500kbps").unwrap(), 512_000); // min clamp

    let fwd = parse_tcp_forward_rule("127.0.0.1:19443=10.0.0.10:8443").unwrap();
    assert_eq!(fwd.listen, "127.0.0.1:19443".parse::<SocketAddr>().unwrap());
    assert_eq!(
        fwd.target,
        TargetAddr::V4(Ipv4Addr::new(10, 0, 0, 10), 8443)
    );

    let acl = AclConfig {
        allow: vec![
            AclRule::parse("10.0.0.10/32:8443").unwrap(),
            AclRule::parse("198.51.100.10:2222").unwrap(),
        ],
        deny: vec![AclRule::parse("198.51.100.0/24").unwrap()],
        reject_private: true,
        outbound_ipv4_only: true,
    };
    assert!(acl.is_allowed("10.0.0.10:8443".parse().unwrap()));
    assert!(!acl.is_allowed("10.0.0.10:8444".parse().unwrap()));
    assert!(acl.is_allowed("198.51.100.10:2222".parse().unwrap()));
    assert!(!acl.is_allowed("198.51.100.10:443".parse().unwrap()));
    assert!(!acl.is_allowed("127.0.0.1:80".parse().unwrap()));
    assert!(!acl.is_allowed("172.16.0.1:80".parse().unwrap()));
    assert!(!acl.is_allowed("10.0.0.20:80".parse().unwrap()));
    assert!(acl.is_allowed("1.1.1.1:443".parse().unwrap()));

    // Out-of-order 2-fragment UDP reassembly
    let big: Vec<u8> = (0..1800).map(|i| (i % 251) as u8).collect();
    let dst = TargetAddr::V4(Ipv4Addr::new(8, 8, 8, 8), 53);
    let frags = encode_udp_datagrams(7, 42, &dst, &big, 1200);
    assert_eq!(frags.len(), 2);
    let mut reasm = UdpFragReassembler::default();
    let now = Instant::now();
    assert!(reasm
        .push(decode_udp_datagram(&frags[1]).unwrap(), now)
        .is_none());
    let (sid, addr, got) = reasm
        .push(decode_udp_datagram(&frags[0]).unwrap(), now)
        .unwrap();
    assert_eq!(sid, 7);
    assert_eq!(addr, dst);
    assert_eq!(got, big);
}

fn spawn_tcp_echo_server() -> (SocketAddr, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop);
    thread::spawn(move || {
        while !stop_c.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_nodelay(true);
                    thread::spawn(move || {
                        let mut buf = [0u8; 32 * 1024];
                        loop {
                            match s.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if s.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (addr, stop)
}

fn spawn_udp_echo_server() -> (SocketAddr, Arc<AtomicBool>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop);
    thread::spawn(move || {
        let mut buf = [0u8; 65_536];
        while !stop_c.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(&buf[..n], peer);
            }
        }
    });
    (addr, stop)
}

fn socks5_connect(socks_addr: SocketAddr, target: &TargetAddr) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(socks_addr).unwrap();
    s.set_nodelay(true).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut g = [0u8; 2];
    s.read_exact(&mut g).unwrap();
    assert_eq!(g, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00];
    target.encode(&mut req);
    s.write_all(&req).unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(rep[0], 0x05);
    (s, rep[1])
}

fn assert_tcp_echo_payload(mut s: TcpStream, payload: &[u8]) {
    let expected_hash = Sha256::digest(payload);
    let mut s_read = s.try_clone().unwrap();
    let total = payload.len();
    let reader = thread::spawn(move || {
        let mut h = Sha256::new();
        let mut buf = [0u8; 32 * 1024];
        let mut got = 0usize;
        while got < total {
            let n = s_read.read(&mut buf).unwrap();
            assert!(n > 0, "unexpected EOF at {}/{}", got, total);
            h.update(&buf[..n]);
            got += n;
        }
        h.finalize()
    });
    s.write_all(payload).unwrap();
    let got_hash = reader.join().unwrap();
    assert_eq!(got_hash, expected_hash);
}

#[test]
fn test_proxy_e2e_socks5_tcp_udp_forward_and_acl() {
    let (tcp_echo_addr, stop_tcp_echo) = spawn_tcp_echo_server();
    let (blocked_tcp_addr, stop_blocked) = spawn_tcp_echo_server();
    let (udp_echo_addr, stop_udp_echo) = spawn_udp_echo_server();

    let server_port = free_udp_port();
    let socks_port = free_tcp_port();
    let fwd_port = free_tcp_port();
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", socks_port).parse().unwrap();
    let fwd_addr: SocketAddr = format!("127.0.0.1:{}", fwd_port).parse().unwrap();
    let psk = b"proxy-e2e-test-psk-001".to_vec();

    let stop = Arc::new(AtomicBool::new(false));
    let s_stop = Arc::clone(&stop);
    let s_psk = psk.clone();
    let srv_h = thread::spawn(move || {
        run_proxy_server(ProxyServerConfig {
            server: ServerConfig {
                listen_addr: server_addr,
                backend_addr: server_addr,
                psk: s_psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 64,
                wan_mtu: 1488,
                udp_batch: 16,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(s_stop),
            },
            max_up_bps: 500_000_000,
            max_down_bps: 500_000_000,
            acl: AclConfig {
                allow: vec![
                    AclRule::parse(&format!("127.0.0.1/32:{}", tcp_echo_addr.port())).unwrap(),
                    AclRule::parse(&format!("127.0.0.1/32:{}", udp_echo_addr.port())).unwrap(),
                ],
                deny: Vec::new(),
                reject_private: true,
                outbound_ipv4_only: true,
            },
            proxy_mtu: None,
        })
        .unwrap();
    });

    thread::sleep(Duration::from_millis(80));

    let c_stop = Arc::clone(&stop);
    let cli_h = thread::spawn(move || {
        run_proxy_client(ProxyClientConfig {
            client: ClientConfig {
                listen_addr: socks_addr,
                server_addr,
                psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 64,
                wan_mtu: 1488,
                udp_batch: 16,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 5,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                lane_hunt: LaneHuntConfig::default(),
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(c_stop),
            },
            socks_listen: Some(socks_addr),
            tcp_forwards: vec![super::TcpForwardRule {
                listen: fwd_addr,
                target: TargetAddr::from_socket_addr(tcp_echo_addr),
            }],
            up_bps: 200_000_000,
            down_bps: 420_000_000,
            proxy_mtu: None,
        })
        .unwrap();
    });

    wait_tcp_ready(socks_addr);
    wait_tcp_ready(fwd_addr);

    // 1) SOCKS5 IPv4 TCP CONNECT — 1 MiB bidirectional echo
    let big_payload: Vec<u8> = (0..1024 * 1024).map(|i| ((i * 31) % 251) as u8).collect();
    let (s1, rep1) = socks5_connect(socks_addr, &TargetAddr::from_socket_addr(tcp_echo_addr));
    assert_eq!(rep1, 0x00, "allowed SOCKS5 IPv4 target should succeed");
    assert_tcp_echo_payload(s1, &big_payload);

    // 2) SOCKS5 Domain ("localhost") TCP CONNECT — tests async DNS pool + post-DNS ACL
    let (s2, rep2) = socks5_connect(
        socks_addr,
        &TargetAddr::Domain("localhost".to_string(), tcp_echo_addr.port()),
    );
    assert_eq!(rep2, 0x00, "allowed SOCKS5 domain target should succeed");
    assert_tcp_echo_payload(s2, &big_payload[..256 * 1024]);

    // 3) ACL rejection on unlisted loopback port -> SOCKS5 REP 0x02
    let (_s3, rep3) = socks5_connect(socks_addr, &TargetAddr::from_socket_addr(blocked_tcp_addr));
    assert_eq!(rep3, 0x02, "unlisted private port must be rejected by ACL");

    // 4) L4 --tcp-forward — 512 KiB transparent echo (zero SOCKS5)
    let f_stream = TcpStream::connect(fwd_addr).unwrap();
    f_stream.set_nodelay(true).unwrap();
    f_stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_tcp_echo_payload(f_stream, &big_payload[..512 * 1024]);

    // 5) SOCKS5 UDP ASSOCIATE — normal + oversized 2-fragment datagram
    let mut u_ctrl = TcpStream::connect(socks_addr).unwrap();
    u_ctrl
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    u_ctrl.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut g = [0u8; 2];
    u_ctrl.read_exact(&mut g).unwrap();
    assert_eq!(g, [0x05, 0x00]);
    u_ctrl
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let mut urep = [0u8; 10];
    u_ctrl.read_exact(&mut urep).unwrap();
    assert_eq!(urep[1], 0x00);
    let relay_ip = Ipv4Addr::new(urep[4], urep[5], urep[6], urep[7]);
    let relay_port = u16::from_be_bytes([urep[8], urep[9]]);
    let udp_relay_addr = SocketAddr::new(IpAddr::V4(relay_ip), relay_port);

    let local_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    local_udp
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for msg in [
        b"small-udp-echo-payload".to_vec(),
        (0..1700).map(|i| (i % 239) as u8).collect::<Vec<u8>>(),
    ] {
        let mut pkt = vec![0x00, 0x00, 0x00];
        TargetAddr::from_socket_addr(udp_echo_addr).encode(&mut pkt);
        pkt.extend_from_slice(&msg);
        local_udp.send_to(&pkt, udp_relay_addr).unwrap();
        let mut rbuf = [0u8; 4096];
        let (rn, _) = local_udp.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[..3], &[0, 0, 0]);
        let (src, alen) = TargetAddr::decode(&rbuf[3..rn]).unwrap().unwrap();
        assert_eq!(src, TargetAddr::from_socket_addr(udp_echo_addr));
        assert_eq!(&rbuf[3 + alen..rn], &msg[..]);
    }
    drop(u_ctrl);

    stop.store(true, Ordering::Relaxed);
    stop_tcp_echo.store(true, Ordering::Relaxed);
    stop_blocked.store(true, Ordering::Relaxed);
    stop_udp_echo.store(true, Ordering::Relaxed);
    cli_h.join().unwrap();
    srv_h.join().unwrap();
}

#[test]
fn test_proxy_e2e_over_relay_cloak_with_8pct_loss() {
    let (tcp_echo_addr, stop_tcp_echo) = spawn_tcp_echo_server();

    let server_port = free_udp_port();
    let relay_port = free_udp_port();
    let lossy_port = free_udp_port();
    let socks_port = free_tcp_port();

    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    let relay_addr: SocketAddr = format!("127.0.0.1:{}", relay_port).parse().unwrap();
    let lossy_addr: SocketAddr = format!("127.0.0.1:{}", lossy_port).parse().unwrap();
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", socks_port).parse().unwrap();

    let psk_leg1 = b"proxy-relay-leg1-psk".to_vec();
    let psk_leg2 = b"proxy-relay-leg2-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    // Deterministic 8% packet loss shim (drops 1 of every 12 data packets after initial handshake)
    let loss_stop = Arc::clone(&stop);
    let loss_h = thread::spawn(move || {
        let sock = UdpSocket::bind(lossy_addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let mut client_peer: Option<SocketAddr> = None;
        let mut buf = [0u8; 4096];
        let mut seq = 0u64;
        while !loss_stop.load(Ordering::Relaxed) {
            if let Ok((n, src)) = sock.recv_from(&mut buf) {
                if src == relay_addr {
                    if let Some(cp) = client_peer {
                        seq += 1;
                        // Keep initial STUN/DTLS handshake packets intact, drop ~8% of SRTP traffic
                        let is_srtp = buf[0] >= 128 && buf[0] <= 191;
                        if is_srtp && seq > 20 && seq.is_multiple_of(12) {
                            continue;
                        }
                        let _ = sock.send_to(&buf[..n], cp);
                    }
                } else {
                    client_peer = Some(src);
                    seq += 1;
                    let is_srtp = buf[0] >= 128 && buf[0] <= 191;
                    if is_srtp && seq > 20 && seq.is_multiple_of(13) {
                        continue;
                    }
                    let _ = sock.send_to(&buf[..n], relay_addr);
                }
            }
        }
    });

    // Hop 3: proxy --server (exit node)
    let s_stop = Arc::clone(&stop);
    let s_psk = psk_leg2.clone();
    let srv_h = thread::spawn(move || {
        run_proxy_server(ProxyServerConfig {
            server: ServerConfig {
                listen_addr: server_addr,
                backend_addr: server_addr,
                psk: s_psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 16,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(s_stop),
            },
            max_up_bps: 300_000_000,
            max_down_bps: 300_000_000,
            acl: AclConfig {
                allow: vec![
                    AclRule::parse(&format!("127.0.0.1/32:{}", tcp_echo_addr.port())).unwrap(),
                ],
                deny: Vec::new(),
                reject_private: true,
                outbound_ipv4_only: true,
            },
            proxy_mtu: None,
        })
        .unwrap();
    });

    // Hop 2: untouched relay --upstream-mode cloak (middle hop)
    let r_stop = Arc::clone(&stop);
    let r_psk1 = psk_leg1.clone();
    let r_psk2 = psk_leg2.clone();
    let rel_h = thread::spawn(move || {
        run_relay(RelayConfig {
            ingress: ServerConfig {
                listen_addr: relay_addr,
                backend_addr: server_addr,
                psk: r_psk1,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 16,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(r_stop.clone()),
            },
            upstream: RelayUpstreamConfig::Cloak(ClientConfig {
                listen_addr: relay_addr,
                server_addr,
                psk: r_psk2,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 16,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 5,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                lane_hunt: LaneHuntConfig::default(),
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(r_stop),
            }),
        })
        .unwrap();
    });

    thread::sleep(Duration::from_millis(120));

    // Hop 1: proxy --client traversing lossy link -> relay -> exit
    let c_stop = Arc::clone(&stop);
    let cli_h = thread::spawn(move || {
        run_proxy_client(ProxyClientConfig {
            client: ClientConfig {
                listen_addr: socks_addr,
                server_addr: lossy_addr,
                psk: psk_leg1,
                stun_scope: Some(relay_addr.port().to_string()),
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 16,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 5,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                lane_hunt: LaneHuntConfig::default(),
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(c_stop),
            },
            socks_listen: Some(socks_addr),
            tcp_forwards: Vec::new(),
            up_bps: 100_000_000,
            down_bps: 300_000_000,
            proxy_mtu: None,
        })
        .unwrap();
    });

    wait_tcp_ready(socks_addr);

    let payload: Vec<u8> = (0..512 * 1024)
        .map(|i| ((i * 17 + 3) % 251) as u8)
        .collect();
    let (s, rep) = socks5_connect(socks_addr, &TargetAddr::from_socket_addr(tcp_echo_addr));
    assert_eq!(rep, 0x00);
    assert_tcp_echo_payload(s, &payload);

    stop.store(true, Ordering::Relaxed);
    stop_tcp_echo.store(true, Ordering::Relaxed);
    cli_h.join().unwrap();
    rel_h.join().unwrap();
    srv_h.join().unwrap();
    loss_h.join().unwrap();
}

#[test]
fn test_proxy_e2e_concurrent_4_streams_and_outer_mbb() {
    let (tcp_echo_addr, stop_tcp_echo) = spawn_tcp_echo_server();
    let server_port = free_udp_port();
    let socks_port = free_tcp_port();
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", socks_port).parse().unwrap();
    let psk = b"proxy-concurrent-mbb-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    let s_stop = Arc::clone(&stop);
    let s_psk = psk.clone();
    let srv_h = thread::spawn(move || {
        run_proxy_server(ProxyServerConfig {
            server: ServerConfig {
                listen_addr: server_addr,
                backend_addr: server_addr,
                psk: s_psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 32,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(s_stop),
            },
            max_up_bps: 1_000_000_000,
            max_down_bps: 1_000_000_000,
            acl: AclConfig {
                allow: vec![
                    AclRule::parse(&format!("127.0.0.1/32:{}", tcp_echo_addr.port())).unwrap(),
                ],
                deny: Vec::new(),
                reject_private: true,
                outbound_ipv4_only: true,
            },
            proxy_mtu: None,
        })
        .unwrap();
    });

    thread::sleep(Duration::from_millis(80));

    let c_stop = Arc::clone(&stop);
    let cli_h = thread::spawn(move || {
        run_proxy_client(ProxyClientConfig {
            client: ClientConfig {
                listen_addr: socks_addr,
                server_addr,
                psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                // Enable aggressive byte-budget MBB rotation (2 MiB, 0s cooldown) to verify
                // live 0ms outer 5-tuple handover while 4 inner QUIC streams transfer 8 MiB!
                rotate_interval_secs: 0,
                rotate_max_bytes: 2 * 1024 * 1024,
                rotate_cooldown_secs: 0,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 32,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 5,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                lane_hunt: LaneHuntConfig::default(),
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(c_stop),
            },
            socks_listen: Some(socks_addr),
            tcp_forwards: Vec::new(),
            up_bps: 1_000_000_000,
            down_bps: 1_000_000_000,
            proxy_mtu: None,
        })
        .unwrap();
    });

    wait_tcp_ready(socks_addr);

    let t0 = Instant::now();
    let per_stream_bytes = 2 * 1024 * 1024usize;
    let mut workers = Vec::new();
    for idx in 0..4u8 {
        workers.push(thread::spawn(move || {
            let data: Vec<u8> = (0..per_stream_bytes)
                .map(|i| ((i.wrapping_mul(29) + idx as usize * 7) % 251) as u8)
                .collect();
            let (s, rep) = socks5_connect(socks_addr, &TargetAddr::from_socket_addr(tcp_echo_addr));
            assert_eq!(rep, 0x00);
            assert_tcp_echo_payload(s, &data);
        }));
    }
    for w in workers {
        w.join().unwrap();
    }
    let dt = t0.elapsed().as_secs_f64();
    let total_bidir_mb = (per_stream_bytes * 4 * 2) as f64 / 1e6;
    eprintln!(
        "[proxy-test] 4 concurrent streams + live MBB handover: {:.1} MB bidir in {:.2}s ({:.1} Mbps)",
        total_bidir_mb,
        dt,
        total_bidir_mb * 8.0 / dt.max(0.001)
    );

    stop.store(true, Ordering::Relaxed);
    stop_tcp_echo.store(true, Ordering::Relaxed);
    cli_h.join().unwrap();
    srv_h.join().unwrap();
}

#[test]
fn test_proxy_reverse_direct_e2e_socks5_udp_forward_mbb_and_reconnect() {
    let (tcp_echo_addr, stop_tcp_echo) = spawn_tcp_echo_server();
    let (blocked_tcp_addr, stop_blocked) = spawn_tcp_echo_server();
    let (udp_echo_addr, stop_udp_echo) = spawn_udp_echo_server();

    let entry_udp_port = free_udp_port();
    let socks_port = free_tcp_port();
    let fwd_port = free_tcp_port();
    let entry_addr: SocketAddr = format!("127.0.0.1:{}", entry_udp_port).parse().unwrap();
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", socks_port).parse().unwrap();
    let fwd_addr: SocketAddr = format!("127.0.0.1:{}", fwd_port).parse().unwrap();
    let psk = b"proxy-rev-direct-psk-001".to_vec();

    let entry_stop = Arc::new(AtomicBool::new(false));
    let e_stop = Arc::clone(&entry_stop);
    let e_psk = psk.clone();
    let entry_h = thread::spawn(move || {
        run_proxy_client_reverse(ReverseProxyClientConfig {
            server: ServerConfig {
                listen_addr: entry_addr,
                backend_addr: entry_addr,
                psk: e_psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 16,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(e_stop),
            },
            socks_listen: Some(socks_addr),
            tcp_forwards: vec![
                parse_tcp_forward_rule(&format!("{}={}", fwd_addr, tcp_echo_addr)).unwrap(),
            ],
            up_bps: 500_000_000,
            down_bps: 500_000_000,
            proxy_mtu: None,
        })
        .unwrap();
    });

    wait_tcp_ready(socks_addr);

    let spawn_exit = |agent_stop: Arc<AtomicBool>, rotate_bytes: u64| {
        let a_psk = psk.clone();
        thread::spawn(move || {
            run_proxy_server_reverse(ReverseProxyServerConfig {
                client: ClientConfig {
                    listen_addr: entry_addr,
                    server_addr: entry_addr,
                    psk: a_psk,
                    stun_scope: None,
                    cipher_pref: CipherPref::Auto,
                    dtls_decoy: true,
                    dtls_min_version: DtlsMinVersion::V13Only,
                    rotate_interval_secs: 0,
                    rotate_max_bytes: rotate_bytes,
                    rotate_cooldown_secs: 0,
                    workers: 1,
                    max_sessions: 32,
                    wan_mtu: 1488,
                    udp_batch: 16,
                    retry_ms: 100,
                    max_retries: 8,
                    keepalive_secs: 5,
                    idle_timeout_secs: 60,
                    stats_interval_secs: 0,
                    lane_hunt: LaneHuntConfig::default(),
                    telemetry: TelemetryConfig::default(),
                    quiet: true,
                    stop: Some(agent_stop),
                },
                max_up_bps: 500_000_000,
                max_down_bps: 500_000_000,
                acl: AclConfig {
                    allow: vec![
                        AclRule::parse(&format!("127.0.0.1/32:{}", tcp_echo_addr.port())).unwrap(),
                        AclRule::parse(&format!("127.0.0.1/32:{}", udp_echo_addr.port())).unwrap(),
                    ],
                    deny: Vec::new(),
                    reject_private: true,
                    outbound_ipv4_only: true,
                },
                proxy_mtu: None,
            })
            .unwrap();
        })
    };

    // Exit Agent #1 with aggressive 1 MiB MBB byte-budget rotation
    let agent1_stop = Arc::new(AtomicBool::new(false));
    let agent1_h = spawn_exit(Arc::clone(&agent1_stop), 1024 * 1024);

    // 1) SOCKS5 TCP echo + ACL check
    let (s_ok, rep_ok) = socks5_connect(socks_addr, &TargetAddr::from_socket_addr(tcp_echo_addr));
    assert_eq!(rep_ok, 0x00);
    assert_tcp_echo_payload(s_ok, &vec![0x5Au8; 256 * 1024]);

    let (_s_deny, rep_deny) =
        socks5_connect(socks_addr, &TargetAddr::from_socket_addr(blocked_tcp_addr));
    assert_eq!(
        rep_deny, 0x02,
        "reverse exit ACL must reject disallowed private target"
    );

    // 2) --tcp-forward L4 echo
    let fwd_s = TcpStream::connect(fwd_addr).unwrap();
    fwd_s.set_nodelay(true).unwrap();
    fwd_s
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_tcp_echo_payload(fwd_s, &vec![0xA5u8; 256 * 1024]);

    // 3) SOCKS5 UDP ASSOCIATE (small + 2000B fragmented datagram)
    {
        let mut ctrl = TcpStream::connect(socks_addr).unwrap();
        ctrl.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        ctrl.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut g = [0u8; 2];
        ctrl.read_exact(&mut g).unwrap();
        assert_eq!(g, [0x05, 0x00]);
        ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let mut rep = [0u8; 10];
        ctrl.read_exact(&mut rep).unwrap();
        assert_eq!(&rep[..4], &[0x05, 0x00, 0x00, 0x01]);
        let relay_udp = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7])),
            u16::from_be_bytes([rep[8], rep[9]]),
        );
        let cli_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        cli_udp
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        for payload in [b"rev-udp-hello".to_vec(), vec![0x3Cu8; 2000]] {
            let mut pkt = vec![0u8, 0, 0];
            TargetAddr::from_socket_addr(udp_echo_addr).encode(&mut pkt);
            pkt.extend_from_slice(&payload);
            cli_udp.send_to(&pkt, relay_udp).unwrap();
            let mut rbuf = [0u8; 4096];
            let (rn, _) = cli_udp.recv_from(&mut rbuf).unwrap();
            assert_eq!(&rbuf[10..rn], &payload[..]);
        }
    }

    // 4) 4 concurrent streams x 1 MiB to trigger live 0ms outer MBB from NAT exit side!
    let mut workers = Vec::new();
    for idx in 0..4u8 {
        workers.push(thread::spawn(move || {
            let data: Vec<u8> = (0usize..1024 * 1024)
                .map(|i| ((i.wrapping_mul(17) + idx as usize * 13) % 251) as u8)
                .collect();
            let (s, rep) = socks5_connect(socks_addr, &TargetAddr::from_socket_addr(tcp_echo_addr));
            assert_eq!(rep, 0x00);
            assert_tcp_echo_payload(s, &data);
        }));
    }
    for w in workers {
        w.join().unwrap();
    }

    // 5) Kill Exit Agent #1 and start fresh Exit Agent #2 -> verify seamless auto-reattach!
    agent1_stop.store(true, Ordering::Relaxed);
    agent1_h.join().unwrap();

    let agent2_stop = Arc::new(AtomicBool::new(false));
    let agent2_h = spawn_exit(Arc::clone(&agent2_stop), 0);
    thread::sleep(Duration::from_millis(200));

    let (s_after, rep_after) =
        socks5_connect(socks_addr, &TargetAddr::from_socket_addr(tcp_echo_addr));
    assert_eq!(rep_after, 0x00);
    assert_tcp_echo_payload(s_after, &vec![0x77u8; 128 * 1024]);

    agent2_stop.store(true, Ordering::Relaxed);
    entry_stop.store(true, Ordering::Relaxed);
    stop_tcp_echo.store(true, Ordering::Relaxed);
    stop_blocked.store(true, Ordering::Relaxed);
    stop_udp_echo.store(true, Ordering::Relaxed);
    agent2_h.join().unwrap();
    entry_h.join().unwrap();
}

#[test]
fn test_proxy_reverse_3hop_nat_to_nat_via_relay_reverse() {
    let (tcp_echo_addr, stop_tcp_echo) = spawn_tcp_echo_server();
    let (blocked_tcp_addr, stop_blocked) = spawn_tcp_echo_server();
    let (udp_echo_addr, stop_udp_echo) = spawn_udp_echo_server();

    let relay_in_addr: SocketAddr = format!("127.0.0.1:{}", free_udp_port()).parse().unwrap();
    let relay_rev_addr: SocketAddr = format!("127.0.0.1:{}", free_udp_port()).parse().unwrap();
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", free_tcp_port()).parse().unwrap();
    let fwd_addr: SocketAddr = format!("127.0.0.1:{}", free_tcp_port()).parse().unwrap();

    let psk_leg1 = b"nat-client-to-relay-psk-001".to_vec();
    let psk_leg2 = b"nat-exit-to-relay-psk-002".to_vec();
    let stop = Arc::new(AtomicBool::new(false));

    // Hop 2 (center): Public VPS running `relay --upstream-mode reverse`
    let r_stop = Arc::clone(&stop);
    let r_psk1 = psk_leg1.clone();
    let r_psk2 = psk_leg2.clone();
    let relay_h = thread::spawn(move || {
        run_relay(RelayConfig {
            ingress: ServerConfig {
                listen_addr: relay_in_addr,
                backend_addr: relay_rev_addr,
                psk: r_psk1,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 16,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(Arc::clone(&r_stop)),
            },
            upstream: RelayUpstreamConfig::Reverse(ServerConfig {
                listen_addr: relay_rev_addr,
                backend_addr: relay_in_addr,
                psk: r_psk2,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 16,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(r_stop),
            }),
        })
        .unwrap();
    });

    thread::sleep(Duration::from_millis(80));

    // Hop 3 (NAT B exit): `proxy --server --reverse` dialing relay's reverse listener
    let s_stop = Arc::clone(&stop);
    let s_psk = psk_leg2;
    let exit_h = thread::spawn(move || {
        run_proxy_server_reverse(ReverseProxyServerConfig {
            client: ClientConfig {
                listen_addr: relay_rev_addr,
                server_addr: relay_rev_addr,
                psk: s_psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 16,
                retry_ms: 100,
                max_retries: 8,
                keepalive_secs: 5,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                lane_hunt: LaneHuntConfig::default(),
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(s_stop),
            },
            max_up_bps: 500_000_000,
            max_down_bps: 500_000_000,
            acl: AclConfig {
                allow: vec![
                    AclRule::parse(&format!("127.0.0.1/32:{}", tcp_echo_addr.port())).unwrap(),
                    AclRule::parse(&format!("127.0.0.1/32:{}", udp_echo_addr.port())).unwrap(),
                ],
                deny: Vec::new(),
                reject_private: true,
                outbound_ipv4_only: true,
            },
            proxy_mtu: None,
        })
        .unwrap();
    });

    thread::sleep(Duration::from_millis(120));

    // Hop 1 (NAT A client): `proxy --client` dialing relay's ingress listener
    let c_stop = Arc::clone(&stop);
    let c_psk = psk_leg1;
    let cli_h = thread::spawn(move || {
        run_proxy_client(ProxyClientConfig {
            client: ClientConfig {
                listen_addr: socks_addr,
                server_addr: relay_in_addr,
                psk: c_psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 16,
                retry_ms: 100,
                max_retries: 8,
                keepalive_secs: 5,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                lane_hunt: LaneHuntConfig::default(),
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(c_stop),
            },
            socks_listen: Some(socks_addr),
            tcp_forwards: vec![
                parse_tcp_forward_rule(&format!("{}={}", fwd_addr, tcp_echo_addr)).unwrap(),
            ],
            up_bps: 500_000_000,
            down_bps: 500_000_000,
            proxy_mtu: None,
        })
        .unwrap();
    });

    wait_tcp_ready(socks_addr);

    // 1) SOCKS5 TCP 1 MiB echo through NAT A -> VPS relay-reverse <- NAT B
    let payload: Vec<u8> = (0..1024 * 1024)
        .map(|i| ((i * 19 + 3) % 251) as u8)
        .collect();
    let (s_ok, rep_ok) = socks5_connect(socks_addr, &TargetAddr::from_socket_addr(tcp_echo_addr));
    assert_eq!(rep_ok, 0x00);
    assert_tcp_echo_payload(s_ok, &payload);

    // 2) ACL denial on NAT B exit
    let (_s_deny, rep_deny) =
        socks5_connect(socks_addr, &TargetAddr::from_socket_addr(blocked_tcp_addr));
    assert_eq!(rep_deny, 0x02);

    // 3) --tcp-forward L4 TCP through 3-hop reverse relay
    let fwd_s = TcpStream::connect(fwd_addr).unwrap();
    fwd_s.set_nodelay(true).unwrap();
    fwd_s
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_tcp_echo_payload(fwd_s, &vec![0x42u8; 256 * 1024]);

    // 4) SOCKS5 UDP ASSOCIATE through 3-hop reverse relay
    {
        let mut ctrl = TcpStream::connect(socks_addr).unwrap();
        ctrl.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        ctrl.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut g = [0u8; 2];
        ctrl.read_exact(&mut g).unwrap();
        assert_eq!(g, [0x05, 0x00]);
        ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let mut rep = [0u8; 10];
        ctrl.read_exact(&mut rep).unwrap();
        assert_eq!(&rep[..4], &[0x05, 0x00, 0x00, 0x01]);
        let relay_udp = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7])),
            u16::from_be_bytes([rep[8], rep[9]]),
        );
        let cli_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        cli_udp
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut pkt = vec![0u8, 0, 0];
        TargetAddr::from_socket_addr(udp_echo_addr).encode(&mut pkt);
        pkt.extend_from_slice(b"nat-to-nat-3hop-udp-ok");
        cli_udp.send_to(&pkt, relay_udp).unwrap();
        let mut rbuf = [0u8; 2048];
        let (rn, _) = cli_udp.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[10..rn], b"nat-to-nat-3hop-udp-ok");
    }

    stop.store(true, Ordering::Relaxed);
    stop_tcp_echo.store(true, Ordering::Relaxed);
    stop_blocked.store(true, Ordering::Relaxed);
    stop_udp_echo.store(true, Ordering::Relaxed);
    cli_h.join().unwrap();
    exit_h.join().unwrap();
    relay_h.join().unwrap();
}

/// v0.7 P0-2 regression test:
/// 1) With short `idle_timeout_secs = 2`, an idle SOCKS5 TCP connection held silent for 3.2s MUST
///    stay alive (both existing TCP stream AND new SOCKS5 connections succeed without QUIC keepalive beacons!).
/// 2) When `proxy --server` restarts on the same port (tearing down the outer Cloak tunnel),
///    forward `proxy --client` MUST immediately reset its inner QUIC connection instead of
///    permanently deadlocking new SOCKS5 dials!
#[test]
fn test_proxy_v70_idle_timeout_survival_and_server_restart_quic_reset() {
    let psk = b"proxy-v70-p0-2-idle-and-restart-psk".to_vec();
    let (tcp_echo_addr, stop_tcp_echo) = spawn_tcp_echo_server();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), free_udp_port());
    let socks_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), free_tcp_port());

    let stop_cli = Arc::new(AtomicBool::new(false));
    let stop_srv1 = Arc::new(AtomicBool::new(false));

    let spawn_srv = |stop_flag: Arc<AtomicBool>| {
        let s_psk = psk.clone();
        thread::spawn(move || {
            run_proxy_server(ProxyServerConfig {
                server: ServerConfig {
                    listen_addr: server_addr,
                    backend_addr: server_addr,
                    psk: s_psk,
                    stun_scope: None,
                    cipher_pref: CipherPref::Auto,
                    dtls_required: true,
                    dtls_min_version: DtlsMinVersion::V13Only,
                    workers: 1,
                    max_sessions: 32,
                    wan_mtu: 1488,
                    udp_batch: 0,
                    idle_timeout_secs: 2,
                    stats_interval_secs: 0,
                    wire_audit_file: None,
                    telemetry: TelemetryConfig::default(),
                    quiet: true,
                    stop: Some(stop_flag),
                },
                max_up_bps: 300_000_000,
                max_down_bps: 300_000_000,
                acl: AclConfig {
                    allow: vec![
                        AclRule::parse(&format!("127.0.0.1/32:{}", tcp_echo_addr.port())).unwrap(),
                    ],
                    deny: Vec::new(),
                    reject_private: true,
                    outbound_ipv4_only: true,
                },
                proxy_mtu: None,
            })
            .unwrap();
        })
    };

    let srv1_h = spawn_srv(Arc::clone(&stop_srv1));
    let cli_stop = Arc::clone(&stop_cli);
    let c_psk = psk.clone();
    let cli_h = thread::spawn(move || {
        run_proxy_client(ProxyClientConfig {
            client: ClientConfig {
                listen_addr: socks_addr,
                server_addr,
                psk: c_psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 0,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 1,
                idle_timeout_secs: 2,
                stats_interval_secs: 0,
                lane_hunt: LaneHuntConfig::default(),
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(cli_stop),
            },
            socks_listen: Some(socks_addr),
            tcp_forwards: Vec::new(),
            up_bps: 100_000_000,
            down_bps: 300_000_000,
            proxy_mtu: None,
        })
        .unwrap();
    });

    wait_tcp_ready(socks_addr);

    // 1. Open SOCKS5 TCP stream #1, exchange data, then stay 100% silent for 3.2s (> idle_timeout=2s!)
    let (mut s1, rep1) = socks5_connect(socks_addr, &TargetAddr::from_socket_addr(tcp_echo_addr));
    assert_eq!(rep1, 0x00);
    s1.write_all(b"BEFORE_IDLE_OK").unwrap();
    let mut rb = [0u8; 64];
    s1.read_exact(&mut rb[..14]).unwrap();
    assert_eq!(&rb[..14], b"BEFORE_IDLE_OK");

    thread::sleep(Duration::from_millis(3200));

    // Existing idle TCP flow MUST survive untouched!
    s1.write_all(b"AFTER_IDLE_ALIVE").unwrap();
    s1.read_exact(&mut rb[..16]).unwrap();
    assert_eq!(
        &rb[..16],
        b"AFTER_IDLE_ALIVE",
        "Idle embedded proxy TCP flow MUST survive past idle_timeout_secs!"
    );
    drop(s1);

    // Brand-new SOCKS5 connection after idle MUST also succeed!
    let (s2, rep2) = socks5_connect(socks_addr, &TargetAddr::from_socket_addr(tcp_echo_addr));
    assert_eq!(rep2, 0x00);
    assert_tcp_echo_payload(s2, &vec![0x5Au8; 64 * 1024]);

    // 2. Restart proxy --server (graceful BYE + close_notify -> outer tunnel disconnect)
    stop_srv1.store(true, Ordering::SeqCst);
    srv1_h.join().unwrap();
    let stop_srv2 = Arc::new(AtomicBool::new(false));
    let srv2_h = spawn_srv(Arc::clone(&stop_srv2));

    // Forward proxy --client MUST reset inner QUIC and serve new SOCKS5 dials cleanly!
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut recovered = false;
    while Instant::now() < deadline {
        if let Ok(mut s3) = TcpStream::connect_timeout(&socks_addr, Duration::from_secs(1)) {
            let _ = s3.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s3.set_write_timeout(Some(Duration::from_secs(2)));
            if s3.write_all(&[0x05, 0x01, 0x00]).is_ok() {
                let mut g = [0u8; 2];
                if s3.read_exact(&mut g).is_ok() && g == [0x05, 0x00] {
                    let mut req = vec![0x05, 0x01, 0x00];
                    TargetAddr::from_socket_addr(tcp_echo_addr).encode(&mut req);
                    if s3.write_all(&req).is_ok() {
                        let mut rep = [0u8; 10];
                        if s3.read_exact(&mut rep).is_ok()
                            && rep[1] == 0x00
                            && s3.write_all(b"POST_RESTART_OK").is_ok()
                            && s3.read_exact(&mut rb[..15]).is_ok()
                            && &rb[..15] == b"POST_RESTART_OK"
                        {
                            recovered = true;
                            break;
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(150));
    }
    assert!(
        recovered,
        "Forward proxy client MUST reset inner QUIC and recover SOCKS5 after server restart!"
    );

    stop_cli.store(true, Ordering::SeqCst);
    stop_srv2.store(true, Ordering::SeqCst);
    stop_tcp_echo.store(true, Ordering::SeqCst);
    cli_h.join().unwrap();
    srv2_h.join().unwrap();
}
