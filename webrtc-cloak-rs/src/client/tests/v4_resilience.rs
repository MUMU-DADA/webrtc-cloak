//! V4 P0 边界恢复回归测试与外层健康遥测端到端测试。

use super::reserve_free_port;
use crate::client::{run_client, ClientConfig};
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

/// Carbon Audit P0-1 + P0-2 + P0-5 Regression Test:
///   - Part A (P0-1 + P0-2): Drop the server's VERY FIRST `0xFFFD(0x01)` PathChallenge during
///     1-RTT migration AND replay a reordered earlier migration STUN; client MUST recover cleanly
///     on the migrated port with 0 backend port changes (proving no `token_by_peer` self-lockout
///     and idempotent nonce reuse across the 4-slot candidate table).
///   - Part B (P0-5): When a legacy `v0.3.8` server ignores `mi_key_mig`-signed migration STUN,
///     `Migrating` timeout fallback (`to_rotate`) MUST preserve `old_sess.pending` app packets
///     into the replacement DTLS session without silently dropping them!
#[test]
fn v40_p0_dropped_challenge_reordered_stun_and_legacy_pending_fallback() {
    // ---- Part A: P0-1 (dropped 1st 0xFFFD challenge) + P0-2 (reordered dup migration STUN) ----
    {
        let psk = b"v040-carbon-p01-p02-regression-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        let stop_all = Arc::new(AtomicBool::new(false));
        let port_violations = Arc::new(AtomicUsize::new(0));
        let b_stop = Arc::clone(&stop_all);
        let b_viol = Arc::clone(&port_violations);

        let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        backend_sock
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut locked: Option<SocketAddr> = None;
            while !b_stop.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = backend_sock.recv_from(&mut buf) {
                    match locked {
                        None => locked = Some(peer),
                        Some(lp) if lp != peer => {
                            b_viol.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    if let Some(lp) = locked {
                        let _ = backend_sock.send_to(&buf[..n], lp);
                    }
                }
            }
        });

        let srv_psk = psk.clone();
        let s_stop = Arc::clone(&stop_all);
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
                udp_batch: 0,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(s_stop),
            });
        });

        let blackhole_port = Arc::new(AtomicU16::new(0));
        let latest_port = Arc::new(AtomicU16::new(0));
        let dropped_first_challenge = Arc::new(AtomicBool::new(false));
        let replayed_reordered_stun = Arc::new(AtomicBool::new(false));
        let r_bh = Arc::clone(&blackhole_port);
        let r_latest = Arc::clone(&latest_port);
        let r_drop_ch = Arc::clone(&dropped_first_challenge);
        let r_replay = Arc::clone(&replayed_reordered_stun);
        let r_stop = Arc::clone(&stop_all);

        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut saved_mig_stun: Option<(u16, Vec<u8>)> = None;
            let mut mig_stun_count: usize = 0;
            let mut buf = [0u8; 4096];
            while !r_stop.load(Ordering::Relaxed) {
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    r_latest.store(cport, Ordering::SeqCst);
                    let pkt = &buf[..n];
                    let bh = r_bh.load(Ordering::SeqCst);
                    if bh != 0 && cport == bh {
                        continue; // 100% uplink blackhole on old port
                    }
                    let entry = upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });
                    if bh != 0 && cport != bh && demux_rfc7983(pkt) == PacketKind::Stun {
                        mig_stun_count += 1;
                        if mig_stun_count == 1 {
                            saved_mig_stun = Some((cport, pkt.to_vec()));
                        }
                        let _ = entry.0.send(pkt);
                        // On the 2nd migration STUN, immediately inject a reordered copy of the 1st STUN
                        // to verify P0-2 idempotent nonce reuse!
                        if mig_stun_count == 2 {
                            if let Some((sp, ref first_pkt)) = saved_mig_stun {
                                if sp == cport {
                                    let _ = entry.0.send(first_pkt);
                                    r_replay.store(true, Ordering::SeqCst);
                                }
                            }
                        }
                    } else {
                        let _ = entry.0.send(pkt);
                    }
                }
                let bh = r_bh.load(Ordering::SeqCst);
                for (&cport, (usock, cli_addr)) in upstreams.iter() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let pkt = &buf[..n];
                        // P0-1 fault injection: drop the VERY FIRST 0xFFFD SRTP challenge
                        // sent to the migrated port (57B unpadded SRTP)!
                        if bh != 0
                            && cport != bh
                            && demux_rfc7983(pkt) == PacketKind::Srtp
                            && !r_drop_ch.swap(true, Ordering::SeqCst)
                        {
                            continue;
                        }
                        let _ = relay_front.send_to(pkt, *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        let c_stop = Arc::clone(&stop_all);
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
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 0,
                retry_ms: 150,
                max_retries: 8,
                keepalive_secs: 1,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                lane_hunt: Default::default(),
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(c_stop),
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();
        let mut rbuf = [0u8; 512];
        let mut ready = false;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"P01_INIT");
            match app.recv(&mut rbuf) {
                Ok(n) if &rbuf[..n] == b"P01_INIT" => {
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                _ => thread::sleep(Duration::from_millis(30)),
            }
        }
        assert!(ready, "initial tunnel must come up");
        let port1 = latest_port.load(Ordering::SeqCst);

        blackhole_port.store(port1, Ordering::SeqCst);
        let mut recovered = false;
        let t_bh = Instant::now();
        while t_bh.elapsed() < Duration::from_secs(9) {
            let _ = app.send(b"P01_HEALED");
            if let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"P01_HEALED" && latest_port.load(Ordering::SeqCst) != port1 {
                    recovered = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(60));
        }
        stop_all.store(true, Ordering::SeqCst);

        assert!(
            dropped_first_challenge.load(Ordering::SeqCst),
            "fault injector must have dropped the 1st 0xFFFD challenge"
        );
        assert!(
            replayed_reordered_stun.load(Ordering::SeqCst),
            "fault injector must have replayed reordered 1st migration STUN"
        );
        assert!(
            recovered,
            "P0-1/P0-2: client MUST recover after dropped 1st 0xFFFD challenge + reordered STUN!"
        );
        assert_eq!(
            port_violations.load(Ordering::SeqCst),
            0,
            "P0-1/P0-2: StrictPinnedUdpBackend MUST keep exact same backend_lport!"
        );
    }

    // ---- Part B: P0-5 (`Migrating` fallback to legacy server preserves `old_sess.pending`) ----
    {
        let psk = b"v040-carbon-p05-pending-fallback-psk".to_vec();
        let backend_port = reserve_free_port();
        let server_port = reserve_free_port();
        let relay_port = reserve_free_port();
        let client_port = reserve_free_port();

        let stop_all = Arc::new(AtomicBool::new(false));
        let b_stop = Arc::clone(&stop_all);
        let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
        echo_sock
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while !b_stop.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                    let _ = echo_sock.send_to(&buf[..n], peer);
                }
            }
        });

        let srv_psk = psk.clone();
        let s_stop = Arc::clone(&stop_all);
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
                udp_batch: 0,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(s_stop),
            });
        });

        let blackhole_port = Arc::new(AtomicU16::new(0));
        let mig_port_seen = Arc::new(AtomicU16::new(0));
        let latest_port = Arc::new(AtomicU16::new(0));
        let r_bh = Arc::clone(&blackhole_port);
        let r_mig = Arc::clone(&mig_port_seen);
        let r_latest = Arc::clone(&latest_port);
        let r_stop = Arc::clone(&stop_all);
        let relay_psk = psk.clone();

        let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
        relay_front.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut buf = [0u8; 4096];
            while !r_stop.load(Ordering::Relaxed) {
                while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                    let cport = cli_addr.port();
                    r_latest.store(cport, Ordering::SeqCst);
                    let pkt = &buf[..n];
                    let bh = r_bh.load(Ordering::SeqCst);
                    if bh != 0 && cport == bh {
                        continue;
                    }
                    // Emulate a v0.3.8 legacy server: drop migration STUNs that are NOT signed with global PSK!
                    // (Fresh fallback DTLS STUN IS signed with global PSK and passes cleanly!)
                    if bh != 0 && cport != bh && demux_rfc7983(pkt) == PacketKind::Stun {
                        let is_global_psk = parse_stun(pkt, &relay_psk)
                            .map(|p| p.authenticated)
                            .unwrap_or(false);
                        if !is_global_psk {
                            let _ = r_mig.compare_exchange(
                                0,
                                cport,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            );
                            continue;
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
                for (usock, cli_addr) in upstreams.values() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        let _ = relay_front.send_to(&buf[..n], *cli_addr);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        let cli_psk = psk.clone();
        let c_stop = Arc::clone(&stop_all);
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
                max_sessions: 32,
                wan_mtu: 1488,
                udp_batch: 0,
                retry_ms: 120,
                max_retries: 8,
                keepalive_secs: 1,
                idle_timeout_secs: 60,
                stats_interval_secs: 3600,
                lane_hunt: Default::default(),
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(c_stop),
            });
        });

        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_millis(120)))
            .unwrap();
        app.connect(("127.0.0.1", client_port)).unwrap();
        let mut rbuf = [0u8; 512];
        let mut ready = false;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            let _ = app.send(b"P05_INIT");
            match app.recv(&mut rbuf) {
                Ok(n) if &rbuf[..n] == b"P05_INIT" => {
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                _ => thread::sleep(Duration::from_millis(30)),
            }
        }
        assert!(ready, "initial tunnel must come up");
        let port1 = latest_port.load(Ordering::SeqCst);

        // Blackhole port1 and wait until client enters `Migrating` (observed via first per-session STUN)
        blackhole_port.store(port1, Ordering::SeqCst);
        let t_wait_mig = Instant::now();
        while mig_port_seen.load(Ordering::SeqCst) == 0
            && t_wait_mig.elapsed() < Duration::from_secs(8)
        {
            thread::sleep(Duration::from_millis(20));
        }
        assert_ne!(
            mig_port_seen.load(Ordering::SeqCst),
            0,
            "client must attempt V4 1-RTT migration first"
        );

        // Send a SINGLE app packet while client is in `Migrating`; it MUST be buffered in
        // `old_sess.pending`, carried across `to_rotate` fallback into the fresh DTLS session,
        // and echoed back WITHOUT the app ever re-sending it!
        let _ = app.send(b"PRESERVE_ME_P05");
        let mut got_preserved = false;
        let t_fb = Instant::now();
        while t_fb.elapsed() < Duration::from_secs(6) {
            if let Ok(n) = app.recv(&mut rbuf) {
                if &rbuf[..n] == b"PRESERVE_ME_P05" {
                    got_preserved = true;
                    break;
                }
            }
        }
        stop_all.store(true, Ordering::SeqCst);
        assert!(
            got_preserved,
            "P0-5: app packet buffered during Migrating MUST survive fallback to fresh DTLS session!"
        );
    }
}

/// v0.4.1 End-to-End Outer Health Telemetry Test:
/// Verifies BOTH `--status-file` (atomic JSON) AND `--status-http` (`/status`, `/metrics`)
/// on BOTH `client` and `server` across live SRTP traffic, an active-probe unauth drop on server,
/// and a live asymmetric uplink blackhole -> 1-RTT ICE path migration!
#[test]
fn v41_outer_health_telemetry_file_and_http_live_migration() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    let psk = b"v041-outer-health-telemetry-e2e-psk".to_vec();
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let relay_port = reserve_free_port();
    let client_port = reserve_free_port();

    let reserve_tcp = || {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let cli_http_addr = reserve_tcp();
    let srv_http_addr = reserve_tcp();
    let cli_status_file = std::env::temp_dir()
        .join(format!("wc_e2e_cli_status_{}.json", std::process::id()))
        .to_string_lossy()
        .to_string();
    let srv_status_file = std::env::temp_dir()
        .join(format!("wc_e2e_srv_status_{}.json", std::process::id()))
        .to_string_lossy()
        .to_string();

    let stop_all = Arc::new(AtomicBool::new(false));
    let b_stop = Arc::clone(&stop_all);
    let echo_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
    echo_sock
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while !b_stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = echo_sock.recv_from(&mut buf) {
                let _ = echo_sock.send_to(&buf[..n], peer);
            }
        }
    });

    let srv_psk = psk.clone();
    let s_stop = Arc::clone(&stop_all);
    let s_file = srv_status_file.clone();
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
            udp_batch: 0,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig {
                status_file: Some(s_file),
                status_http: Some(srv_http_addr),
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(s_stop),
        });
    });

    let blackhole_port = Arc::new(AtomicU16::new(0));
    let latest_port = Arc::new(AtomicU16::new(0));
    let r_bh = Arc::clone(&blackhole_port);
    let r_latest = Arc::clone(&latest_port);
    let r_stop = Arc::clone(&stop_all);
    let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
    relay_front.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
        let mut buf = [0u8; 4096];
        while !r_stop.load(Ordering::Relaxed) {
            while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                let cport = cli_addr.port();
                r_latest.store(cport, Ordering::SeqCst);
                let bh = r_bh.load(Ordering::SeqCst);
                if bh != 0 && cport == bh {
                    continue;
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
    let c_stop = Arc::clone(&stop_all);
    let c_file = cli_status_file.clone();
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
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 1,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            lane_hunt: Default::default(),
            telemetry: TelemetryConfig {
                status_file: Some(c_file),
                status_http: Some(cli_http_addr),
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(c_stop),
        });
    });

    let http_get_body = |addr: SocketAddr, path: &str| -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = String::new();
        let _ = s.read_to_string(&mut raw);
        raw.split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default()
    };

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();
    let mut rbuf = [0u8; 512];
    let mut ready = false;
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"TEL_PING_INIT");
        match app.recv(&mut rbuf) {
            Ok(n) if &rbuf[..n] == b"TEL_PING_INIT" => {
                ready = true;
                break;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            _ => thread::sleep(Duration::from_millis(30)),
        }
    }
    assert!(ready, "tunnel must come up");

    // Send 2 unauthenticated junk probes directly to server so server telemetry counts them
    let junk = UdpSocket::bind("127.0.0.1:0").unwrap();
    let _ = junk.send_to(b"HOSTILE_PROBE_1", ("127.0.0.1", server_port));
    let _ = junk.send_to(b"HOSTILE_PROBE_2", ("127.0.0.1", server_port));

    // Wait >=1.2s for 1s telemetry flush & healthy state
    thread::sleep(Duration::from_millis(1200));
    let cj: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cli_status_file).unwrap()).unwrap();
    assert_eq!(cj["role"], "client");
    assert_eq!(cj["health"], "good");
    assert_eq!(cj["dtls_version"], "1.3");
    assert!(cj["link"]["stun_rtt_ms"].as_f64().is_some());
    assert!(cj["link"]["tx_bytes_total"].as_u64().unwrap() >= 13);

    // Trigger uplink blackhole -> 1-RTT ICE migration!
    let port1 = latest_port.load(Ordering::SeqCst);
    blackhole_port.store(port1, Ordering::SeqCst);
    let mut healed = false;
    let t_bh = Instant::now();
    while t_bh.elapsed() < Duration::from_secs(9) {
        let _ = app.send(b"TEL_AFTER_BH");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"TEL_AFTER_BH" && latest_port.load(Ordering::SeqCst) != port1 {
                healed = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(60));
    }
    assert!(healed, "tunnel must heal via 1-RTT migration");
    thread::sleep(Duration::from_millis(1150));

    // Verify client & server HTTP JSON + Prometheus endpoints reflect exact outer events!
    let cli_http_json: serde_json::Value =
        serde_json::from_str(&http_get_body(cli_http_addr, "/status")).unwrap();
    assert!(
        cli_http_json["events"]["blackholes_total"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(
        cli_http_json["events"]["migrations_1rtt_total"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert_eq!(
        cli_http_json["events"]["blackholes_last_10m"]
            .as_u64()
            .unwrap(),
        1
    );
    assert!(cli_http_json["link"]["stun_loss_pct"].as_f64().unwrap() > 0.0);
    assert!(matches!(
        cli_http_json["health"].as_str(),
        Some("degraded" | "critical")
    ));

    let cli_prom = http_get_body(cli_http_addr, "/metrics");
    assert!(cli_prom.contains("webrtc_cloak_blackholes_total{role=\"client\"} 1"));
    assert!(cli_prom.contains("webrtc_cloak_migrations_1rtt_total{role=\"client\"} 1"));

    let srv_http_json: serde_json::Value =
        serde_json::from_str(&http_get_body(srv_http_addr, "/status")).unwrap();
    assert_eq!(srv_http_json["role"], "server");
    assert!(
        srv_http_json["events"]["migrations_1rtt_total"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(
        srv_http_json["sessions"]["unauth_silent_drops_total"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert!(srv_http_json["sessions"]["backend_sport"].as_u64().unwrap() > 0);
    let srv_file_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&srv_status_file).unwrap()).unwrap();
    assert_eq!(srv_file_json["role"], "server");

    stop_all.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(100));
    let _ = std::fs::remove_file(&cli_status_file);
    let _ = std::fs::remove_file(&srv_status_file);
}
