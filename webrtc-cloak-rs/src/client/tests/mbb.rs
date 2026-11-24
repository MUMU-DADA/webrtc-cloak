//! 主动 MBB 轮换、流量预算触发与闲时退避集成测试。

use super::reserve_free_port;
use crate::client::{run_client, ClientConfig};
use crate::protocol::{demux_rfc7983, CipherPref, DtlsMinVersion, PacketKind};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// v0.3.7 #8 regression test: proactive Make-Before-Break scheduled 5-tuple rotation
/// (`--rotate-interval 2`) switches to a fresh UDP port with ZERO dropped packets!
#[test]
fn proactive_mbb_scheduled_rotation_zero_loss() {
    let psk = b"v037-mbb-zero-loss-rotation-psk".to_vec();
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
            dtls_min_version: DtlsMinVersion::Auto,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: None,
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
    thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
            psk: cli_psk,
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::Auto,
            rotate_interval_secs: 2, // log-normal MBB rotation in 0.7s..5.6s!
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 30,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: None,
        });
    });

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();

    let mut rbuf = [0u8; 256];
    let mut ready = false;
    let t_init = Instant::now();
    while t_init.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"MBB_WARMUP");
        match app.recv(&mut rbuf) {
            Ok(n) if &rbuf[..n] == b"MBB_WARMUP" => {
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

    // Stream continuously across the log-normal [0.7s..5.6s] MBB cutover window + 30 packets post-cutover!
    let mut ok_cnt = 0usize;
    let mut post_cutover = 0usize;
    let t_stream = Instant::now();
    let mut seq = 0u32;
    while t_stream.elapsed() < Duration::from_secs(7) {
        let msg = format!("MBB_SEQ_{:04}", seq);
        seq += 1;
        app.send(msg.as_bytes()).unwrap();
        let n = app.recv(&mut rbuf).expect("MBB rotation MUST deliver with zero packet loss!");
        assert_eq!(&rbuf[..n], msg.as_bytes());
        ok_cnt += 1;
        if latest_port.load(Ordering::SeqCst) != port1 {
            post_cutover += 1;
            if post_cutover >= 30 {
                break;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    let port2 = latest_port.load(Ordering::SeqCst);
    assert!(ok_cnt >= 35);
    assert_ne!(
        port2, port1,
        "proactive MBB rotation MUST switch off port {} to a fresh 5-tuple within 7s!",
        port1
    );
}

/// v0.3.8 regression test:
/// 1) Byte-volume budget triggers zero-loss MBB rotation after cooldown;
/// 2) Delayed old-session BYE (2-10s) keeps old server session Ready during overlap so slow
///    backend replies (500ms) arrive intact instead of being dropped in ServerState::Closing!
/// 3) Old-session BYE is NOT emitted immediately (<1.5s) after new port goes live.
#[test]
fn v38_byte_budget_mbb_and_delayed_bye_delivers_slow_backend_replies() {
    let psk = b"v038-byte-budget-delayed-bye-psk".to_vec();
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let relay_port = reserve_free_port();
    let client_port = reserve_free_port();

    // Echo backend that delays packets starting with "SLOW:" by 500ms (simulating slow DNS/TCP reply)
    let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
    let echo_tx = echo_sock.try_clone().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                let data = buf[..n].to_vec();
                if data.starts_with(b"SLOW:") {
                    let tx = echo_tx.try_clone().unwrap();
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(500));
                        let _ = tx.send_to(&data, peer);
                    });
                } else {
                    let _ = echo_sock.send_to(&data, peer);
                }
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
            max_sessions: 32,
            wan_mtu: 1488,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: None,
        });
    });

    let first_port = Arc::new(AtomicU16::new(0));
    let latest_port = Arc::new(AtomicU16::new(0));
    let port1_srtcp_after_cutover_ms = Arc::new(std::sync::Mutex::new(Option::<u128>::None));
    let r_first = Arc::clone(&first_port);
    let r_latest = Arc::clone(&latest_port);
    let r_bye_ms = Arc::clone(&port1_srtcp_after_cutover_ms);
    let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
    relay_front.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
        let mut cutover_at: Option<Instant> = None;
        let mut buf = [0u8; 4096];
        loop {
            while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                let cport = cli_addr.port();
                let _ = r_first.compare_exchange(0, cport, Ordering::SeqCst, Ordering::SeqCst);
                r_latest.store(cport, Ordering::SeqCst);
                let p1 = r_first.load(Ordering::SeqCst);
                let kind = demux_rfc7983(&buf[..n]);
                if p1 != 0 && cport != p1 && kind == PacketKind::Srtp && cutover_at.is_none() {
                    cutover_at = Some(Instant::now());
                }
                if let Some(ct) = cutover_at {
                    if cport == p1 && kind == PacketKind::Srtcp {
                        let mut guard = r_bye_ms.lock().unwrap();
                        if guard.is_none() {
                            *guard = Some(ct.elapsed().as_millis());
                        }
                    }
                }
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
    thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
            psk: cli_psk,
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,      // time trigger disabled -> pure byte-budget test!
            rotate_max_bytes: 20 * 1024,  // 20KB base -> random 10..37KB budget!
            rotate_cooldown_secs: 1,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 30,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: None,
        });
    });

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();

    let mut rbuf = [0u8; 2048];
    let mut ready = false;
    let t_init = Instant::now();
    while t_init.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"BYTE_WARMUP");
        match app.recv(&mut rbuf) {
            Ok(n) if &rbuf[..n] == b"BYTE_WARMUP" => {
                ready = true;
                break;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            _ => thread::sleep(Duration::from_millis(40)),
        }
    }
    assert!(ready, "initial tunnel should come up");
    let port1 = first_port.load(Ordering::SeqCst);

    // Wait past the 1s cooldown while streaming 1000B packets + SLOW:500ms probes across the byte-budget cutover!
    let mut slow_sent = std::collections::HashSet::<u32>::new();
    let mut slow_recvd = std::collections::HashSet::<u32>::new();
    let mut cutover_seen = false;
    app.set_nonblocking(true).unwrap();

    let t_run = Instant::now();
    let mut seq = 0u32;
    while t_run.elapsed() < Duration::from_secs(5) {
        let mut bulk = vec![0x41u8; 1000];
        bulk[..4].copy_from_slice(b"BLK:");
        let _ = app.send(&bulk);

        // Every 4th packet is a 500ms-delayed SLOW backend reply to prove old_sess does NOT drop it on cutover!
        if seq % 4 == 0 {
            let slow_msg = format!("SLOW:{:04}", seq);
            let _ = app.send(slow_msg.as_bytes());
            slow_sent.insert(seq);
        }
        seq += 1;

        while let Ok(n) = app.recv(&mut rbuf) {
            if n >= 9 && &rbuf[..5] == b"SLOW:" {
                if let Ok(s) = std::str::from_utf8(&rbuf[5..9]) {
                    if let Ok(id) = s.parse::<u32>() {
                        slow_recvd.insert(id);
                    }
                }
            }
        }
        if latest_port.load(Ordering::SeqCst) != port1 {
            cutover_seen = true;
            // Keep sending a few packets on new port so cutover_at triggers in relay
            for _ in 0..5 {
                let _ = app.send(&bulk);
                thread::sleep(Duration::from_millis(20));
            }
            break;
        }
        thread::sleep(Duration::from_millis(40));
    }
    assert!(cutover_seen, "byte-budget MBB rotation MUST trigger off port {}", port1);

    // Drain all in-flight 500ms SLOW backend replies (proves old session stayed Ready on server!)
    let t_drain = Instant::now();
    while t_drain.elapsed() < Duration::from_secs(1) {
        while let Ok(n) = app.recv(&mut rbuf) {
            if n >= 9 && &rbuf[..5] == b"SLOW:" {
                if let Ok(s) = std::str::from_utf8(&rbuf[5..9]) {
                    if let Ok(id) = s.parse::<u32>() {
                        slow_recvd.insert(id);
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        slow_recvd.len(),
        slow_sent.len(),
        "ALL slow 500ms backend replies MUST survive MBB cutover via delayed BYE overlap ({}/{})",
        slow_recvd.len(),
        slow_sent.len()
    );

    // Verify old-session BYE was NOT sent immediately (<1.5s) after cutover!
    let early_bye = *port1_srtcp_after_cutover_ms.lock().unwrap();
    if let Some(ms) = early_bye {
        assert!(
            ms >= 1_500,
            "old-session BYE MUST be delayed 2..10s after MBB cutover (saw {}ms!)",
            ms
        );
    }
}

/// v0.3.8 regression test: overnight background trickle (<64KB/5min ≈ 218 B/s) MUST suspend
/// proactive MBB rotation so idle keepalives don't churn full DTLS handshakes all night.
#[test]
fn v38_background_trickle_suspends_proactive_mbb_rotation() {
    let psk = b"v038-trickle-mbb-suspend-psk".to_vec();
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
    thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
            psk: cli_psk,
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 1, // median 1s -> max lognormal 2.8s, hard cap 6s
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
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: None,
        });
    });

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();

    let mut rbuf = [0u8; 256];
    let mut ready = false;
    let t_init = Instant::now();
    while t_init.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"KA_INIT");
        match app.recv(&mut rbuf) {
            Ok(n) if &rbuf[..n] == b"KA_INIT" => {
                ready = true;
                break;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            _ => thread::sleep(Duration::from_millis(40)),
        }
    }
    assert!(ready, "initial tunnel should come up");
    let port1 = first_port.load(Ordering::SeqCst);

    // Send only tiny 32B inner keepalives every 1s (64 B/s << 218 B/s threshold) across 3.8s
    // (well past max 2.8s lognormal rotate_at, before 6s hard cap) -> MUST stay on port1!
    for _ in 0..4 {
        thread::sleep(Duration::from_millis(950));
        let ka = [0x5Au8; 32];
        app.send(&ka).unwrap();
        let n = app.recv(&mut rbuf).unwrap();
        assert_eq!(n, 32);
    }
    assert_eq!(
        latest_port.load(Ordering::SeqCst),
        port1,
        "background trickle keepalives (<64KB/5min) MUST suspend proactive MBB rotation!"
    );
}

