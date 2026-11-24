//! V4 高 BDP 乱序线缆审计与 Linux 多 worker 跨线程迁移测试。

use super::reserve_free_port;
use crate::client::{run_client, ClientConfig};
use crate::protocol::{demux_rfc7983, CipherPref, DtlsMinVersion, PacketKind};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// V4.0 Scenario #3 & #6 (Carbon): High-BDP Trans-Pacific (160ms RTT + 3% loss + 20% reorder)
/// mid-flight cutover with StrictPinnedUdpBackend + Outer Wire DPI Statistical Audit!
#[test]
fn v40_high_bdp_loss_reorder_cutover_and_outer_dpi_wire_audit() {
    let psk = b"v040-high-bdp-dpi-audit-psk".to_vec();
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let relay_port = reserve_free_port();
    let client_port = reserve_free_port();

    let stop_all = Arc::new(AtomicBool::new(false));
    let pinned_port = Arc::new(AtomicU16::new(0));
    let port_violations = Arc::new(AtomicUsize::new(0));
    let b_stop = Arc::clone(&stop_all);
    let b_pinned = Arc::clone(&pinned_port);
    let b_viol = Arc::clone(&port_violations);

    let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
    backend_sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut locked: Option<SocketAddr> = None;
        while !b_stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = backend_sock.recv_from(&mut buf) {
                match locked {
                    None => {
                        locked = Some(peer);
                        b_pinned.store(peer.port(), Ordering::SeqCst);
                    }
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
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(s_stop),
        });
    });

    // Delay + 3% loss + 20% reorder relay WITH live DPI wire-statistics collector!
    let latest_port = Arc::new(AtomicU16::new(0));
    let max_wire_udp = Arc::new(AtomicUsize::new(0));
    let video_lens = Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));
    let audio_burst_violations = Arc::new(AtomicUsize::new(0));
    let r_latest = Arc::clone(&latest_port);
    let r_maxw = Arc::clone(&max_wire_udp);
    let r_vlens = Arc::clone(&video_lens);
    let r_aviol = Arc::clone(&audio_burst_violations);
    let r_stop = Arc::clone(&stop_all);

    let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
    relay_front.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
        let mut queue: VecDeque<(Instant, bool, u16, SocketAddr, Vec<u8>)> = VecDeque::new();
        let mut prng: u64 = 0xDEAD_BEEF_CAFE_0040;
        let mut next_r = || -> u64 {
            prng ^= prng << 13;
            prng ^= prng >> 7;
            prng ^= prng << 17;
            prng
        };
        let mut last_audio_ts_c2s: Option<(u32, Instant)> = None;
        let mut buf = [0u8; 4096];
        while !r_stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                let cport = cli_addr.port();
                r_latest.store(cport, Ordering::SeqCst);
                r_maxw.fetch_max(n, Ordering::SeqCst);
                let pkt = &buf[..n];
                if demux_rfc7983(pkt) == PacketKind::Srtp && n >= 12 {
                    let pt = pkt[1] & 0x7F;
                    if pt == crate::protocol::RTP_VIDEO_PT {
                        r_vlens.lock().unwrap().push(n);
                    } else if pt == crate::protocol::RTP_AUDIO_PT {
                        let ts = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
                        if let Some((prev_ts, prev_t)) = last_audio_ts_c2s {
                            if prev_ts == ts && now.duration_since(prev_t) < Duration::from_millis(18) {
                                r_aviol.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        last_audio_ts_c2s = Some((ts, now));
                    }
                }
                upstreams.entry(cport).or_insert_with(|| {
                    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                    s.set_nonblocking(true).unwrap();
                    s.connect(srv_addr).unwrap();
                    (s, cli_addr)
                });
                // 3% random loss on SRTP data only (keep test deterministic), 80ms one-way + 20% reorder
                if demux_rfc7983(pkt) == PacketKind::Srtp && (next_r() % 100) < 3 {
                    continue;
                }
                let mut delay = 40u64; // 80ms RTT
                if (next_r() % 100) < 20 {
                    delay += 15 + (next_r() % 20);
                }
                queue.push_back((now + Duration::from_millis(delay), true, cport, cli_addr, pkt.to_vec()));
            }
            for (&cport, (usock, cli_addr)) in upstreams.iter() {
                while let Ok(n) = usock.recv(&mut buf) {
                    r_maxw.fetch_max(n, Ordering::SeqCst);
                    let pkt = &buf[..n];
                    let mut delay = 40u64;
                    if (next_r() % 100) < 20 {
                        delay += 15 + (next_r() % 20);
                    }
                    queue.push_back((now + Duration::from_millis(delay), false, cport, *cli_addr, pkt.to_vec()));
                }
            }
            let mut i = 0;
            while i < queue.len() {
                if queue[i].0 <= now {
                    let (_, c2s, cp, ca, data) = queue.remove(i).unwrap();
                    if c2s {
                        if let Some((us, _)) = upstreams.get(&cp) {
                            let _ = us.send(&data);
                        }
                    } else {
                        let _ = relay_front.send_to(&data, ca);
                    }
                } else {
                    i += 1;
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
            rotate_max_bytes: 50 * 1024, // mid-flight byte-budget MBB handover during burst!
            rotate_cooldown_secs: 1,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            retry_ms: 250,
            max_retries: 8,
            keepalive_secs: 5,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(c_stop),
        });
    });

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();
    let mut rbuf = [0u8; 2048];
    let mut ready = false;
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"BDP_INIT");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"BDP_INIT" {
                ready = true;
                break;
            }
        }
    }
    assert!(ready);
    let port1 = latest_port.load(Ordering::SeqCst);

    // Stream 120 x 1200B packets (~144KB each way) across the 1s cooldown + byte-budget MBB cutover!
    app.set_nonblocking(true).unwrap();
    let mut rx_seqs = std::collections::HashSet::<u32>::new();
    let mut payload = vec![0x55u8; 1200];
    for seq in 0..120u32 {
        payload[..4].copy_from_slice(&seq.to_be_bytes());
        let _ = app.send(&payload);
        while let Ok(n) = app.recv(&mut rbuf) {
            if n == 1200 {
                rx_seqs.insert(u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]));
            }
        }
        thread::sleep(Duration::from_millis(18));
    }
    let t_drain = Instant::now();
    while t_drain.elapsed() < Duration::from_millis(400) {
        while let Ok(n) = app.recv(&mut rbuf) {
            if n == 1200 {
                rx_seqs.insert(u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]));
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    stop_all.store(true, Ordering::SeqCst);

    let port2 = latest_port.load(Ordering::SeqCst);
    assert_ne!(port2, port1, "byte-budget MBB cutover must fire during high-BDP burst!");
    assert_eq!(
        port_violations.load(Ordering::SeqCst),
        0,
        "StrictPinnedUdpBackend MUST see ZERO port changes even under 80ms RTT + 3% loss + 20% reorder!"
    );
    assert!(
        rx_seqs.len() >= 100,
        "delivery under 3% loss + 20% reorder + mid-flight handover must stay >=83% (got {}/120)",
        rx_seqs.len()
    );
    // Outer Wire DPI Audit (Carbon Scenario #6):
    assert!(max_wire_udp.load(Ordering::SeqCst) <= 1460, "outer wire UDP MUST never exceed 1460B!");
    assert_eq!(
        audio_burst_violations.load(Ordering::SeqCst),
        0,
        "PT=111 Opus MUST NEVER exceed 1 packet per 20ms frame!"
    );
    let vlens = video_lens.lock().unwrap();
    assert!(vlens.len() >= 50);
    let mean = vlens.iter().map(|&x| x as f64).sum::<f64>() / (vlens.len() as f64);
    let var = vlens.iter().map(|&x| { let d = x as f64 - mean; d * d }).sum::<f64>() / (vlens.len() as f64);
    let stddev = var.sqrt();
    assert!(
        stddev > 4.0,
        "PT=96 video outer packet-length stddev MUST exceed 4.0B for padding entropy (got {:.2}B)!",
        stddev
    );
}

/// V4.0 Linux Multi-Worker (`--workers 4` SO_REUSEPORT) cross-thread ownership transfer test:
/// Exercises real kernel 4-tuple hashing across 4 workers during BOTH scheduled DTLS 1.3 MBB
/// `0xFFFC` handover AND 1-RTT ICE blackhole migration, asserting ZERO `backend_lport` changes!
#[cfg(target_os = "linux")]
#[test]
fn v40_linux_multiworker_reuseport_cross_thread_migration_and_handover() {
    let psk = b"v040-linux-4worker-reuseport-psk".to_vec();
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let relay_port = reserve_free_port();
    let client_port = reserve_free_port();

    let stop_all = Arc::new(AtomicBool::new(false));
    let port_violations = Arc::new(AtomicUsize::new(0));
    let b_stop = Arc::clone(&stop_all);
    let b_viol = Arc::clone(&port_violations);

    let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
    backend_sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
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
            workers: 4, // Real Linux SO_REUSEPORT 4-worker hash distribution!
            max_sessions: 64,
            wan_mtu: 1488,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(s_stop),
        });
    });

    let latest_port = Arc::new(AtomicU16::new(0));
    let blackhole_port = Arc::new(AtomicU16::new(0));
    let r_latest = Arc::clone(&latest_port);
    let r_bh = Arc::clone(&blackhole_port);
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
    thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
            psk: cli_psk,
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 14 * 1024,
            rotate_cooldown_secs: 1,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 1,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(c_stop),
        });
    });

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();
    let mut rbuf = [0u8; 2048];
    let mut ready = false;
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"MW_INIT");
        match app.recv(&mut rbuf) {
            Ok(n) if &rbuf[..n] == b"MW_INIT" => {
                ready = true;
                break;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            _ => thread::sleep(Duration::from_millis(40)),
        }
    }
    assert!(ready);
    let p1 = latest_port.load(Ordering::SeqCst);

    // Trigger MBB handover across 4 workers
    let mut p2 = 0u16;
    let t_mbb = Instant::now();
    while t_mbb.elapsed() < Duration::from_secs(5) {
        let bulk = vec![0x7Au8; 900];
        let _ = app.send(&bulk);
        let _ = app.recv(&mut rbuf);
        let cur = latest_port.load(Ordering::SeqCst);
        if cur != p1 {
            p2 = cur;
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert_ne!(p2, 0);

    // Trigger 1-RTT blackhole migration across 4 workers
    blackhole_port.store(p2, Ordering::SeqCst);
    let mut healed = false;
    let t_bh = Instant::now();
    while t_bh.elapsed() < Duration::from_secs(9) {
        let _ = app.send(b"MW_POST_BH");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"MW_POST_BH" && latest_port.load(Ordering::SeqCst) != p2 {
                healed = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(60));
    }
    stop_all.store(true, Ordering::SeqCst);
    assert!(healed, "4-worker SO_REUSEPORT 1-RTT blackhole migration MUST heal!");
    assert_eq!(
        port_violations.load(Ordering::SeqCst),
        0,
        "4-worker SO_REUSEPORT migration + handover MUST keep backend_lport 100% unchanged!"
    );
}

