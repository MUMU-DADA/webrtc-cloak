//! V4 严格源端口绑定无感迁移与红队安全对抗集成测试。

use super::reserve_free_port;
use crate::client::{run_client, ClientConfig};
use crate::constants::SRTP_HANDOVER_MAGIC;
use crate::protocol::{
    build_dimpl_config_pool, build_ice_stun_request, combine_session_key, demux_rfc7983,
    derive_stun_material, detect_cpu_accel, new_dtls_instance, parse_stun, CipherPref, CipherSuite,
    DtlsMinVersion, PacketKind, SessionIceParams, SrtpCloakCipher, SrtpFrame,
};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use dimpl::Output as DtlsOutput;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// V4.0 Scenario #1 (Carbon): Strict source-port-pinned stateful UDP backend (simulating
/// legacy game server / SIP / OpenVPN that breaks if server backend_lport EVER changes!)
/// MUST see ZERO backend port changes across BOTH:
///   1) Scheduled DTLS 1.3 MBB rotation (unlinkable new ufrag/SSRC + encrypted 0xFFFC handover), AND
///   2) Asymmetric uplink blackhole 1-RTT ICE path migration (ZERO DTLS packets on migrated port!).
#[test]
fn v40_strict_pinned_udp_backend_survives_mbb_handover_and_1rtt_blackhole_migration() {
    let psk = b"v040-strict-pinned-udp-test-psk".to_vec();
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let relay_port = reserve_free_port();
    let client_port = reserve_free_port();

    // StrictPinnedUdpBackend: locks onto first backend_lport; records any violation; pushes async ticks!
    let pinned_port = Arc::new(AtomicU16::new(0));
    let port_violations = Arc::new(AtomicUsize::new(0));
    let stop_backend = Arc::new(AtomicBool::new(false));
    let b_pinned = Arc::clone(&pinned_port);
    let b_viol = Arc::clone(&port_violations);
    let b_stop = Arc::clone(&stop_backend);

    let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
    backend_sock
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut locked_peer: Option<SocketAddr> = None;
        let mut tick_seq = 0u32;
        let mut last_tick = Instant::now();
        while !b_stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = backend_sock.recv_from(&mut buf) {
                match locked_peer {
                    None => {
                        locked_peer = Some(peer);
                        b_pinned.store(peer.port(), Ordering::SeqCst);
                    }
                    Some(p) if p != peer => {
                        b_viol.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }
                // Always reply ONLY to locked_peer!
                if let Some(lp) = locked_peer {
                    let _ = backend_sock.send_to(&buf[..n], lp);
                }
            }
            if let Some(lp) = locked_peer {
                if last_tick.elapsed() >= Duration::from_millis(35) {
                    last_tick = Instant::now();
                    let msg = format!("TICK:{:05}", tick_seq);
                    tick_seq += 1;
                    let _ = backend_sock.send_to(msg.as_bytes(), lp);
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
            stun_scope: None,
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
            stop: None,
        });
    });

    let latest_port = Arc::new(AtomicU16::new(0));
    let blackhole_port = Arc::new(AtomicU16::new(0));
    let dtls_by_port = Arc::new(std::sync::Mutex::new(HashMap::<u16, usize>::new()));
    let r_latest = Arc::clone(&latest_port);
    let r_bh = Arc::clone(&blackhole_port);
    let r_dtls = Arc::clone(&dtls_by_port);

    let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
    relay_front.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
        let mut buf = [0u8; 4096];
        loop {
            while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                let cport = cli_addr.port();
                r_latest.store(cport, Ordering::SeqCst);
                let bh = r_bh.load(Ordering::SeqCst);
                if bh != 0 && cport == bh {
                    continue; // 100% asymmetric uplink blackhole!
                }
                if demux_rfc7983(&buf[..n]) == PacketKind::Dtls {
                    *r_dtls.lock().unwrap().entry(cport).or_insert(0) += 1;
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
            stun_scope: Some(server_port.to_string()),
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 16 * 1024, // triggers full DTLS 1.3 MBB + 0xFFFC handover!
            rotate_cooldown_secs: 1,
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
            stop: None,
        });
    });

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();

    let mut rbuf = [0u8; 2048];
    let mut ready = false;
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"PIN_INIT");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"PIN_INIT" {
                ready = true;
                break;
            }
        } else {
            thread::sleep(Duration::from_millis(30));
        }
    }
    assert!(ready, "initial tunnel must come up");
    let port1 = latest_port.load(Ordering::SeqCst);
    let initial_backend_port = pinned_port.load(Ordering::SeqCst);
    assert_ne!(initial_backend_port, 0);

    // Phase 1: Trigger full DTLS 1.3 MBB rotation via byte budget (port1 -> port2)
    // Verify unlinkable DTLS handshake happened on port2 AND backend_lport stayed 100% IDENTICAL!
    app.set_nonblocking(true).unwrap();
    let mut ticks_seen = 0usize;
    let t_mbb = Instant::now();
    let mut port2 = 0u16;
    while t_mbb.elapsed() < Duration::from_secs(5) {
        let bulk = vec![0x42u8; 900];
        let _ = app.send(&bulk);
        while let Ok(n) = app.recv(&mut rbuf) {
            if rbuf[..n].starts_with(b"TICK:") {
                ticks_seen += 1;
            }
        }
        let cur = latest_port.load(Ordering::SeqCst);
        if cur != port1 {
            port2 = cur;
            // Send a few more packets on port2 to confirm StrictPinnedUdpBackend accepts them!
            for i in 0..5u32 {
                let p = format!("POST_MBB_{}", i);
                let _ = app.send(p.as_bytes());
                thread::sleep(Duration::from_millis(25));
                while let Ok(n) = app.recv(&mut rbuf) {
                    if rbuf[..n].starts_with(b"TICK:") {
                        ticks_seen += 1;
                    }
                }
            }
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert_ne!(
        port2, 0,
        "MBB byte-budget rotation must switch off port {}",
        port1
    );
    assert!(
        *dtls_by_port.lock().unwrap().get(&port2).unwrap_or(&0) >= 2,
        "scheduled MBB rotation MUST run fresh DTLS 1.3 handshake on port2 (unlinkable outer identity!)"
    );
    assert_eq!(
        port_violations.load(Ordering::SeqCst),
        0,
        "scheduled DTLS 1.3 MBB + 0xFFFC handover MUST NEVER change server backend_lport!"
    );

    // Phase 2: Inject 100% asymmetric uplink blackhole on port2 -> triggers V4 1-RTT ICE migration (port2 -> port3)!
    blackhole_port.store(port2, Ordering::SeqCst);
    let t_mig = Instant::now();
    let mut recovered_after_mig = false;
    let mut port3 = 0u16;
    while t_mig.elapsed() < Duration::from_secs(9) {
        let _ = app.send(b"PING_POST_1RTT_MIG");
        while let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"PING_POST_1RTT_MIG" {
                let cur = latest_port.load(Ordering::SeqCst);
                if cur != port2 && cur != port1 {
                    port3 = cur;
                    recovered_after_mig = true;
                }
            } else if rbuf[..n].starts_with(b"TICK:") {
                ticks_seen += 1;
            }
        }
        if recovered_after_mig {
            break;
        }
        thread::sleep(Duration::from_millis(80));
    }
    stop_backend.store(true, Ordering::SeqCst);

    assert!(
        recovered_after_mig,
        "1-RTT ICE migration MUST recover from asymmetric blackhole on port {}",
        port2
    );
    assert_eq!(
        *dtls_by_port.lock().unwrap().get(&port3).unwrap_or(&0),
        0,
        "1-RTT ICE blackhole migration on port {} MUST NOT run any DTLS handshake!",
        port3
    );
    assert_eq!(
        port_violations.load(Ordering::SeqCst),
        0,
        "StrictPinnedUdpBackend MUST see ZERO backend_lport changes across BOTH MBB handover AND 1-RTT migration!"
    );
    assert!(
        ticks_seen >= 5,
        "async backend ticks must keep flowing across cutovers (got {})",
        ticks_seen
    );
}

/// V4.0 Scenario #2 (Carbon Red-Team):
/// 1) Spoofed-IP reflection DDoS: attacker clones legitimate migration STUN from `victim_sock`
///    while backend streams heavy downlink SRTP -> `victim_sock` MUST receive <200B total (0 business SRTP!);
/// 2) Same-PSK cross-session hijack: evil peer with SAME PSK tries (a) global-PSK STUN migration
///    using victim's plaintext ufrag, and (b) encrypted 0xFFFC handover with forged proof -> BOTH 100% blocked!
#[test]
fn v40_redteam_spoofed_ip_reflection_and_same_psk_hijack_blocked() {
    let psk = b"v040-redteam-anti-reflection-psk".to_vec();
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let relay_port = reserve_free_port();
    let client_port = reserve_free_port();

    // Heavy downlink echo backend (amplifies replies 20x to make any reflection leak unmistakable!)
    let stop_all = Arc::new(AtomicBool::new(false));
    let b_stop = Arc::clone(&stop_all);
    let backend_sock = UdpSocket::bind(("127.0.0.1", backend_port)).unwrap();
    backend_sock
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let big = vec![0xEEu8; 1000];
        while !b_stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = backend_sock.recv_from(&mut buf) {
                if &buf[..n] == b"BLAST" {
                    for _ in 0..12 {
                        let _ = backend_sock.send_to(&big, peer);
                    }
                } else {
                    let _ = backend_sock.send_to(&buf[..n], peer);
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
            stun_scope: None,
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

    let captured_ufrag = Arc::new(std::sync::Mutex::new(Option::<String>::None));
    let blackhole_port = Arc::new(AtomicU16::new(0));
    let latest_port = Arc::new(AtomicU16::new(0));
    let victim_rx_bytes = Arc::new(AtomicUsize::new(0));
    let spoof_fired = Arc::new(AtomicBool::new(false));

    let r_ufrag = Arc::clone(&captured_ufrag);
    let r_bh = Arc::clone(&blackhole_port);
    let r_latest = Arc::clone(&latest_port);
    let r_vbytes = Arc::clone(&victim_rx_bytes);
    let r_spoof = Arc::clone(&spoof_fired);
    let r_stop = Arc::clone(&stop_all);

    let relay_front = UdpSocket::bind(("127.0.0.1", relay_port)).unwrap();
    relay_front.set_nonblocking(true).unwrap();
    let victim_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    victim_sock.set_nonblocking(true).unwrap();
    victim_sock.connect(("127.0.0.1", server_port)).unwrap();

    thread::spawn(move || {
        let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
        let mut buf = [0u8; 4096];
        while !r_stop.load(Ordering::Relaxed) {
            while let Ok((n, cli_addr)) = relay_front.recv_from(&mut buf) {
                let cport = cli_addr.port();
                r_latest.store(cport, Ordering::SeqCst);
                let pkt = &buf[..n];
                if demux_rfc7983(pkt) == PacketKind::Stun {
                    if let Some(u) = crate::protocol::peek_stun_request_username(pkt) {
                        let mut g = r_ufrag.lock().unwrap();
                        if g.is_none() {
                            *g = Some(u.to_string());
                        }
                    }
                }
                let bh = r_bh.load(Ordering::SeqCst);
                if bh != 0 && cport == bh {
                    continue;
                }
                // When client opens migrated port (cport != bh && bh != 0), attacker intercepts first
                // migration STUN and races it from victim_sock BEFORE forwarding!
                if bh != 0
                    && cport != bh
                    && demux_rfc7983(pkt) == PacketKind::Stun
                    && !r_spoof.swap(true, Ordering::SeqCst)
                {
                    let _ = victim_sock.send(pkt);
                    thread::sleep(Duration::from_millis(5));
                }
                let entry = upstreams.entry(cport).or_insert_with(|| {
                    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                    s.set_nonblocking(true).unwrap();
                    s.connect(srv_addr).unwrap();
                    (s, cli_addr)
                });
                let _ = entry.0.send(pkt);
            }
            while let Ok(vn) = victim_sock.recv(&mut buf) {
                r_vbytes.fetch_add(vn, Ordering::SeqCst);
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
            stun_scope: Some(server_port.to_string()),
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
    app.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    app.connect(("127.0.0.1", client_port)).unwrap();
    let mut rbuf = [0u8; 2048];
    let mut ready = false;
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"REDTEAM_INIT");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"REDTEAM_INIT" {
                ready = true;
                break;
            }
        } else {
            thread::sleep(Duration::from_millis(30));
        }
    }
    assert!(ready);
    let port1 = latest_port.load(Ordering::SeqCst);
    let victim_ufrag = captured_ufrag
        .lock()
        .unwrap()
        .clone()
        .expect("ufrag captured");

    // Attack 2a: Same-PSK attacker tries forging STUN migration with victim's plaintext ufrag using global PSK!
    let evil_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    evil_sock
        .set_read_timeout(Some(Duration::from_millis(120)))
        .unwrap();
    evil_sock.connect(("127.0.0.1", server_port)).unwrap();
    let parts: Vec<&str> = victim_ufrag.split(':').collect();
    let mut evil_ice = SessionIceParams::generate();
    evil_ice.ufrag_remote = parts[0].to_string();
    evil_ice.ufrag_local = parts[1].to_string();
    let scoped_psk = crate::protocol::derive_stun_scope_key(&psk, server_port);
    let (forged_mig, _) = build_ice_stun_request(&scoped_psk, &evil_ice, None, true);
    let _ = evil_sock.send(&forged_mig);
    assert!(
        evil_sock.recv(&mut rbuf).is_err(),
        "global-PSK forged STUN migration for active ufrag MUST be 100% silent-dropped!"
    );

    // Attack 2b: Same-PSK attacker opens a real DTLS session and sends encrypted 0xFFFC handover with forged proof!
    let evil_ice2 = SessionIceParams::generate();
    let (evil_stun, evil_txid) = build_ice_stun_request(&scoped_psk, &evil_ice2, None, true);
    let _ = evil_sock.send(&evil_stun);
    let sn = evil_sock.recv(&mut rbuf).expect("evil legit STUN");
    let parsed_e = parse_stun(&rbuf[..sn], &scoped_psk).unwrap();
    assert!(parsed_e.authenticated);
    // Complete evil DTLS 1.3 handshake to get real encrypted SRTP channel
    let cpu = detect_cpu_accel();
    let dcfg = build_dimpl_config_pool(CipherPref::Auto, &cpu, true, 1488).pick();
    let mut edtls = new_dtls_instance(
        DtlsMinVersion::V13Only,
        dcfg,
        crate::protocol::generate_ephemeral_webrtc_cert(),
        Instant::now(),
    );
    edtls.set_active(true);
    let _ = edtls.handle_timeout(Instant::now());
    let mut dbuf = vec![0u8; 4096];
    let mut ekm = None;
    let mut e_conn = false;
    let t_hs = Instant::now();
    while !e_conn && t_hs.elapsed() < Duration::from_secs(3) {
        loop {
            match edtls.poll_output(&mut dbuf) {
                DtlsOutput::Packet(p) => {
                    let _ = evil_sock.send(p);
                }
                DtlsOutput::KeyingMaterial(km, _) => ekm = Some(km.to_vec()),
                DtlsOutput::Connected => e_conn = true,
                DtlsOutput::Timeout(_) => break,
                _ => {}
            }
        }
        if !e_conn {
            if let Ok(rn) = evil_sock.recv(&mut rbuf) {
                if demux_rfc7983(&rbuf[..rn]) == PacketKind::Dtls {
                    let _ = edtls.handle_packet(&rbuf[..rn]);
                }
            }
        }
    }
    assert!(e_conn && ekm.is_some());
    let (esk, es_c2s, es_s2c) =
        derive_stun_material(&scoped_psk, &evil_txid, &evil_ice2.username());
    let efk = combine_session_key(&esk, ekm.as_deref());
    let mut ecipher = SrtpCloakCipher::new(&efk, es_c2s, es_s2c, true, CipherSuite::Aes128Gcm);
    ecipher.set_dual_ssrc(true);
    let mut forged_ho = Vec::new();
    forged_ho.push(0x01);
    forged_ho.push(victim_ufrag.len() as u8);
    forged_ho.extend_from_slice(victim_ufrag.as_bytes());
    forged_ho.extend_from_slice(&[0xAAu8; 32]); // Forged proof!
    let mut wbuf = [0u8; 512];
    let wn = ecipher
        .wrap_control_into(SRTP_HANDOVER_MAGIC, &forged_ho, &mut wbuf)
        .unwrap();
    let _ = evil_sock.send(&wbuf[..wn]);
    let mut saw_reject_ack = false;
    for _ in 0..5 {
        if let Ok(rn) = evil_sock.recv(&mut rbuf) {
            if demux_rfc7983(&rbuf[..rn]) == PacketKind::Srtp {
                if let Some(SrtpFrame::Handover(hn)) =
                    ecipher.unwrap_into_ex(&rbuf[..rn], &mut wbuf)
                {
                    if hn >= 2 && wbuf[0] == 0x02 && wbuf[1] == 0x00 {
                        saw_reject_ack = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(
        saw_reject_ack,
        "forged 0xFFFC handover proof MUST be rejected (status=0x00)!"
    );

    // Attack 1: Trigger blackhole migration while spoofing victim_sock + blasting heavy downlink!
    blackhole_port.store(port1, Ordering::SeqCst);
    let t_mig = Instant::now();
    let mut healed = false;
    while t_mig.elapsed() < Duration::from_secs(9) {
        let _ = app.send(b"BLAST");
        if let Ok(n) = app.recv(&mut rbuf) {
            if n == 1000 && latest_port.load(Ordering::SeqCst) != port1 {
                healed = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(80));
    }
    stop_all.store(true, Ordering::SeqCst);

    assert!(
        spoof_fired.load(Ordering::SeqCst),
        "spoof race must have been injected"
    );
    assert!(
        healed,
        "legitimate client MUST still recover via fresh-txid retry despite spoofed racer!"
    );
    let vbytes = victim_rx_bytes.load(Ordering::SeqCst);
    assert!(
        vbytes < 250,
        "victim_sock MUST NEVER receive reflected backend SRTP (received {}B, expected <250B bounded STUN+Challenge!)",
        vbytes
    );
}
