//! 黑洞自动轮换、DTLS 1.3 Flight 5 重传与优雅关闭快连集成测试。

use super::reserve_free_port;
use crate::client::{run_client, ClientConfig, KA_MAX_RETRIES};
use crate::constants::STUN_BINDING_REQUEST;
use crate::protocol::{demux_rfc7983, parse_stun, CipherPref, DtlsMinVersion, PacketKind};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn asymmetric_uplink_blackhole_auto_rotates_and_single_stun_loss_retransmits_same_txid() {
    let psk = b"v034-asymmetric-blackhole-test-psk".to_vec();
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let relay_port = reserve_free_port();
    let client_port = reserve_free_port();

    // 1. Local UDP echo backend (simulating Hysteria2 / QUIC backend accepting migrated source ports)
    let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                let _ = echo_sock.send_to(&buf[..n], peer);
            }
        }
    });

    // 2. Real webrtc-cloak server
    let srv_psk = psk.clone();
    thread::spawn(move || {
        let _ = run_server(ServerConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: srv_psk,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::Auto,
            workers: 1,
            max_sessions: 64,
            wan_mtu: 1488,
            idle_timeout_secs: 120,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: false,
            stop: None,
        });
    });

    // 3. Fault-injecting UDP relay between client and server (tracks per-client-port upstream sockets)
    let drop_first_ka = Arc::new(AtomicBool::new(true));
    let blackhole_port = Arc::new(AtomicU16::new(0));
    let first_port = Arc::new(AtomicU16::new(0));
    let latest_port = Arc::new(AtomicU16::new(0));
    let same_txid_retransmits = Arc::new(AtomicUsize::new(0));
    let blackholed_ka_txids_matched = Arc::new(AtomicUsize::new(0));
    let downlink_srtcp_during_blackhole = Arc::new(AtomicUsize::new(0));

    let relay_drop_first = Arc::clone(&drop_first_ka);
    let relay_bh_port = Arc::clone(&blackhole_port);
    let relay_first_port = Arc::clone(&first_port);
    let relay_latest_port = Arc::clone(&latest_port);
    let relay_same_txid = Arc::clone(&same_txid_retransmits);
    let relay_bh_txid_match = Arc::clone(&blackholed_ka_txids_matched);
    let relay_dl_srtcp = Arc::clone(&downlink_srtcp_during_blackhole);
    let relay_psk = psk.clone();

    let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
    relay_front.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
        let mut dropped_ka_txid: Option<[u8; 12]> = None;
        let mut bh_first_ka_txid: Option<[u8; 12]> = None;
        let mut buf = [0u8; 4096];

        loop {
            // Client -> Server direction
            while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                let cport = cli_addr.port();
                let _ =
                    relay_first_port.compare_exchange(0, cport, Ordering::SeqCst, Ordering::SeqCst);
                relay_latest_port.store(cport, Ordering::SeqCst);

                let pkt = &buf[..n];
                let is_ka_stun = demux_rfc7983(pkt) == PacketKind::Stun
                    && parse_stun(pkt, &relay_psk)
                        .map(|p| {
                            p.authenticated
                                && p.msg_type == STUN_BINDING_REQUEST
                                && !p.use_candidate
                        })
                        .unwrap_or(false);

                // Phase 2: Asymmetric uplink blackhole on blackhole_port (0% uplink reaches server!)
                let bh = relay_bh_port.load(Ordering::SeqCst);
                if bh != 0 && cport == bh {
                    if is_ka_stun {
                        if let Some(p) = parse_stun(pkt, &relay_psk) {
                            match bh_first_ka_txid {
                                None => bh_first_ka_txid = Some(p.txid),
                                Some(prev) if prev == p.txid => {
                                    relay_bh_txid_match.fetch_add(1, Ordering::SeqCst);
                                }
                                _ => {}
                            }
                        }
                    }
                    continue; // Drop 100% uplink for blackholed 5-tuple!
                }

                // Phase 1: Drop exactly ONE STUN keepalive to verify RFC 5389 same-txid retry without rotation
                if is_ka_stun {
                    if let Some(p) = parse_stun(pkt, &relay_psk) {
                        if relay_drop_first.swap(false, Ordering::SeqCst) {
                            dropped_ka_txid = Some(p.txid);
                            continue;
                        }
                        if dropped_ka_txid == Some(p.txid) {
                            relay_same_txid.fetch_add(1, Ordering::SeqCst);
                            dropped_ka_txid = None;
                        }
                    }
                }

                let entry = upstreams.entry(cport).or_insert_with(|| {
                    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                    s.set_nonblocking(true).unwrap();
                    s.connect(srv_addr).unwrap();
                    (s, cli_addr)
                });
                let _ = entry.0.send(pkt);
            }

            // Server -> Client direction (ALWAYS passed — even during uplink blackhole!)
            for (&cport, (usock, cli_addr)) in upstreams.iter() {
                while let Ok(n) = usock.recv(&mut buf) {
                    let pkt = &buf[..n];
                    let bh = relay_bh_port.load(Ordering::SeqCst);
                    if bh != 0 && cport == bh && demux_rfc7983(pkt) == PacketKind::Srtcp {
                        relay_dl_srtcp.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = relay_front.send_to(pkt, *cli_addr);
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    // 4. Real webrtc-cloak client pointing to relay (--keepalive 1 so test completes in ~8s)
    let cli_psk = psk.clone();
    thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
            psk: cli_psk,
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::Auto,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 64,
            wan_mtu: 1488,
            retry_ms: 200,
            max_retries: 8,
            keepalive_secs: 1,
            idle_timeout_secs: 120,
            stats_interval_secs: 3600,
            lane_hunt: Default::default(),
            telemetry: TelemetryConfig::default(),
            quiet: false,
            stop: None,
        });
    });

    thread::sleep(Duration::from_millis(120));

    // 5. Local app socket (simulating mihomo Hysteria2 client staying on ONE fixed local port)
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();

    let mut rbuf = [0u8; 256];
    let mut ready = false;
    let t_init = Instant::now();
    while t_init.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"PING_INIT");
        match app.recv(&mut rbuf) {
            Ok(n) if &rbuf[..n] == b"PING_INIT" => {
                ready = true;
                break;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            _ => {
                // Linux returns immediate ECONNREFUSED before client thread binds listen_port
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    assert!(ready, "initial STUN+DTLS tunnel should come up");
    let port1 = first_port.load(Ordering::SeqCst);
    assert_ne!(port1, 0);

    // Phase 1: Wait for the 1st STUN keepalive drop + RFC 5389 same-txid retransmission recovery
    let t_p1 = Instant::now();
    while same_txid_retransmits.load(Ordering::SeqCst) == 0
        && t_p1.elapsed() < Duration::from_secs(5)
    {
        let _ = app.send(b"PING_P1");
        let _ = app.recv(&mut rbuf);
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        same_txid_retransmits.load(Ordering::SeqCst),
        1,
        "single dropped STUN keepalive MUST trigger RFC 5389 same-txid retransmission"
    );
    assert_eq!(
        latest_port.load(Ordering::SeqCst),
        port1,
        "single dropped STUN keepalive MUST NOT cause false 5-tuple rotation"
    );

    // Phase 2: Inject 100% asymmetric uplink blackhole on port1 while downlink SRTCP continues!
    blackhole_port.store(port1, Ordering::SeqCst);
    let t_bh = Instant::now();
    let mut recovered = false;
    while t_bh.elapsed() < Duration::from_secs(10) {
        let _ = app.send(b"PING_AFTER_BH");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"PING_AFTER_BH" && latest_port.load(Ordering::SeqCst) != port1 {
                recovered = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(150));
    }
    assert!(
        recovered,
        "client MUST detect asymmetric uplink blackhole despite downlink SRTCP (dl_srtcp={}) and rotate off port {}",
        downlink_srtcp_during_blackhole.load(Ordering::SeqCst),
        port1
    );
    assert_ne!(latest_port.load(Ordering::SeqCst), port1);
    assert_eq!(
        blackholed_ka_txids_matched.load(Ordering::SeqCst),
        KA_MAX_RETRIES as usize,
        "blackhole probe MUST perform exactly {} RFC 5389 same-txid retransmits before rotating",
        KA_MAX_RETRIES
    );
    assert!(
        downlink_srtcp_during_blackhole.load(Ordering::SeqCst) >= 1,
        "test should verify server was still sending downlink SRTCP during asymmetric blackhole"
    );
}

/// H-01 regression test: drop the client's DTLS 1.3 Flight 5 (0x2e encrypted Cert+CV+Fin) packet
/// ONCE on the wire — client is ALREADY in HandshakeState::Ready and MUST drive dtls_next_timeout
/// to retransmit Flight 5 and complete the tunnel within ~1.5s (not 25s blackout!).
#[test]
fn dtls13_flight5_packet_loss_retransmits_from_ready_state() {
    let psk = b"v036-h01-flight5-loss-regression-psk".to_vec();
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let relay_port = reserve_free_port();
    let client_port = reserve_free_port();

    let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                let _ = echo_sock.send_to(&buf[..n], peer);
            }
        }
    });

    let srv_psk = psk.clone();
    thread::spawn(move || {
        let _ = run_server(ServerConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: srv_psk,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 16,
            wan_mtu: 1488,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: None,
        });
    });

    // Relay that drops the VERY FIRST client->server DTLS 1.3 Unified Ciphertext packet (0x20..=0x3F = Flight 5!)
    let dropped_f5 = Arc::new(AtomicBool::new(false));
    let relay_dropped_f5 = Arc::clone(&dropped_f5);
    let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
    relay_front.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let usock = UdpSocket::bind("127.0.0.1:0").unwrap();
        usock.set_nonblocking(true).unwrap();
        usock.connect(srv_addr).unwrap();
        let mut cli_addr: Option<SocketAddr> = None;
        let mut buf = [0u8; 4096];
        loop {
            while let Ok((n, peer)) = relay_front.recv_from(&mut buf) {
                cli_addr = Some(peer);
                let pkt = &buf[..n];
                // Drop the first DTLS 1.3 Unified Ciphertext (b0 in 0x20..=0x3F) from client = Flight 5!
                if !pkt.is_empty()
                    && (pkt[0] & 0xE0) == 0x20
                    && !relay_dropped_f5.swap(true, Ordering::SeqCst)
                {
                    continue;
                }
                let _ = usock.send(pkt);
            }
            if let Some(ca) = cli_addr {
                while let Ok(n) = usock.recv(&mut buf) {
                    let _ = relay_front.send_to(&buf[..n], ca);
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let cli_psk = psk.clone();
    thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
            psk: cli_psk,
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 16,
            wan_mtu: 1488,
            retry_ms: 200,
            max_retries: 8,
            keepalive_secs: 5,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            lane_hunt: Default::default(),
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: None,
        });
    });

    thread::sleep(Duration::from_millis(80));
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();

    let t0 = Instant::now();
    let mut ok = false;
    let mut rbuf = [0u8; 256];
    while t0.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"PING_F5_RECOVER");
        match app.recv(&mut rbuf) {
            Ok(n) if &rbuf[..n] == b"PING_F5_RECOVER" => {
                ok = true;
                break;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            _ => {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    assert!(
        dropped_f5.load(Ordering::SeqCst),
        "relay should have intercepted DTLS 1.3 Flight 5"
    );
    assert!(
        ok,
        "client MUST retransmit dropped DTLS 1.3 Flight 5 from Ready state and recover within 3s!"
    );
}

/// v0.3.7 #7 regression test: graceful server shutdown (stop flag / SIGTERM) broadcasts
/// encrypted SRTCP BYE + DTLS close_notify so client fast-reconnects in <1.5s (not 5-7s!).
#[test]
fn graceful_server_shutdown_bye_triggers_subsecond_reconnect() {
    let psk = b"v037-sigterm-bye-fast-reconnect-psk".to_vec();
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let relay_port = reserve_free_port();
    let client_port = reserve_free_port();

    let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                let _ = echo_sock.send_to(&buf[..n], peer);
            }
        }
    });

    let stop1 = Arc::new(AtomicBool::new(false));
    let stop1_c = Arc::clone(&stop1);
    let srv_psk1 = psk.clone();
    let srv1_handle = thread::spawn(move || {
        let _ = run_server(ServerConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: srv_psk1,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::Auto,
            workers: 1,
            max_sessions: 16,
            wan_mtu: 1488,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(stop1_c),
        });
    });

    let first_port = Arc::new(AtomicU16::new(0));
    let latest_port = Arc::new(AtomicU16::new(0));
    let r_first = Arc::clone(&first_port);
    let r_latest = Arc::clone(&latest_port);
    let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
    relay_front.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
        let mut buf = [0u8; 4096];
        loop {
            while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                let cport = cli_addr.port();
                let _ = r_first.compare_exchange(0, cport, Ordering::SeqCst, Ordering::SeqCst);
                r_latest.store(cport, Ordering::SeqCst);
                let entry = upstreams.entry(cport).or_insert_with(|| {
                    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                    s.set_nonblocking(true).unwrap();
                    s.connect(srv_addr).unwrap();
                    (s, cli_addr)
                });
                let _ = entry.0.send(&buf[..n]);
            }
            for (usock, cli_addr) in upstreams.values() {
                while let Ok(n) = usock.recv(&mut buf) {
                    let _ = relay_front.send_to(&buf[..n], *cli_addr);
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    });

    let cli_psk = psk.clone();
    // Long keepalive (30s) proves recovery comes from server BYE/close_notify, NOT STUN consent timeout!
    thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
            psk: cli_psk,
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::Auto,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 16,
            wan_mtu: 1488,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 30,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            lane_hunt: Default::default(),
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: None,
        });
    });

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();

    let mut rbuf = [0u8; 256];
    let mut ready = false;
    let t_init = Instant::now();
    while t_init.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"PING_BEFORE_SHUTDOWN");
        match app.recv(&mut rbuf) {
            Ok(n) if &rbuf[..n] == b"PING_BEFORE_SHUTDOWN" => {
                ready = true;
                break;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            _ => thread::sleep(Duration::from_millis(40)),
        }
    }
    assert!(ready, "initial tunnel should come up");
    let port1 = first_port.load(Ordering::SeqCst);
    assert_ne!(port1, 0);

    // Trigger graceful server shutdown (SIGTERM equivalent) and spawn replacement server on same port
    let t_restart = Instant::now();
    stop1.store(true, Ordering::SeqCst);
    let _ = srv1_handle.join();

    let srv_psk2 = psk.clone();
    thread::spawn(move || {
        let _ = run_server(ServerConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port),
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: srv_psk2,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::Auto,
            workers: 1,
            max_sessions: 16,
            wan_mtu: 1488,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: None,
        });
    });

    // Must recover via graceful BYE fast-reconnect well before the 30s keepalive!
    let mut recovered = false;
    while t_restart.elapsed() < Duration::from_secs(3) {
        let _ = app.send(b"PING_AFTER_BYE");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"PING_AFTER_BYE" && latest_port.load(Ordering::SeqCst) != port1 {
                recovered = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert!(
        recovered,
        "client MUST fast-reconnect on server graceful BYE well under 3s (keepalive=30s)!"
    );
}
