//! 本地黑洞自愈、服务端重启、主动探测防御与多核 CPU 算力基准测试。

use super::harness::{
    connect_app, handshake_app, EchoBackend, ImpairmentProxy, ManagedClient, ManagedServer,
    NetProfile,
};
use super::{reserve_free_port, Highlights, ScenarioResult, ScenarioStatus, SelftestOptions};
use crate::constants::{
    CTRL_FRAME_BUF_LEN, DTLS_CT_HANDSHAKE, DTLS_HS_CLIENT_HELLO, DTLS_VER_MAJOR, DTLS_VER_MINOR_12,
    PROBE_IO_BUF_LEN, RTP_V2_EXT_BYTE, RTP_VIDEO_PT, STUN_HDR_LEN,
};
use crate::protocol::{
    build_ice_stun_request, combine_session_key, derive_stun_material, detect_cpu_accel,
    fill_random, generate_ephemeral_webrtc_cert, CipherPref, CipherSuite, SessionIceParams,
    SrtpCloakCipher,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

pub(super) fn test_07_asymmetric_blackhole(
    opts: &SelftestOptions,
    hi: &mut Highlights,
) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-07-blackhole-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(
        server_port,
        backend.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
    );
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), false);
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 1, 200);

    let app = connect_app(client.port, 200);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 7,
            code: "uplink_blackhole",
            name: "Asymmetric Uplink Blackhole",
            condition: "100% C2S cut, S2C live",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let port1 = proxy.first_port.load(Ordering::SeqCst);
    // Cut 100% uplink on port1 while downlink SRTCP continues flowing!
    proxy.blackhole_port.store(port1, Ordering::SeqCst);
    let bh_t0 = Instant::now();
    let mut rbuf = [0u8; CTRL_FRAME_BUF_LEN];
    let mut recovered_s: Option<f64> = None;

    while bh_t0.elapsed() < Duration::from_secs(10) {
        let _ = app.send(b"PROBE_AFTER_BLACKHOLE");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"PROBE_AFTER_BLACKHOLE"
                && proxy.latest_port.load(Ordering::SeqCst) != port1
            {
                recovered_s = Some(bh_t0.elapsed().as_secs_f64());
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);
    hi.blackhole_recover_s = recovered_s;

    let port2 = proxy.latest_port.load(Ordering::SeqCst);
    let passed = recovered_s.is_some()
        && port2 != port1
        && snap.ports_seen.len() == 2
        && snap.blackhole_ka_retransmits == 2
        && snap.dl_srtcp_during_blackhole >= 1;

    let rec_str = recovered_s
        .map(|v| format!("{:.2}s", v))
        .unwrap_or_else(|| "TIMEOUT".into());

    ScenarioResult {
        id: 7,
        code: "uplink_blackhole",
        name: "Asymmetric Uplink Blackhole",
        condition: "100% C2S cut, S2C live",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "heal {} | {}->{} | dl_rtcp={} | ka_retx={}",
            rec_str, port1, port2, snap.dl_srtcp_during_blackhole, snap.blackhole_ka_retransmits
        ),
        detail: format!(
            "ports_seen={:?} uplink_dropped={}",
            snap.ports_seen, snap.dropped_by_proxy
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

pub(super) fn test_08_server_restart(
    opts: &SelftestOptions,
    hi: &mut Highlights,
) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-08-srv-restart-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let server1 = ManagedServer::start(
        server_port,
        backend.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
    );
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), false);
    let client = ManagedClient::start(
        proxy.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
        1,
        200,
    );

    let app = connect_app(client.port, 200);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 8,
            code: "server_restart",
            name: "Server Restart Recovery",
            condition: "Kill & respawn server",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Initial tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let port1 = proxy.first_port.load(Ordering::SeqCst);

    // Stop server #1 cleanly and immediately start server #2 on the EXACT SAME port!
    server1.shutdown();
    let _server2 = ManagedServer::start(
        server_port,
        backend.port,
        psk,
        opts.cipher_pref,
        opts.wan_mtu,
    );
    let rs_t0 = Instant::now();

    let mut rbuf = [0u8; CTRL_FRAME_BUF_LEN];
    let mut recovered_s: Option<f64> = None;
    while rs_t0.elapsed() < Duration::from_secs(10) {
        let _ = app.send(b"PROBE_AFTER_RESTART");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"PROBE_AFTER_RESTART"
                && proxy.latest_port.load(Ordering::SeqCst) != port1
            {
                recovered_s = Some(rs_t0.elapsed().as_secs_f64());
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);
    hi.restart_recover_s = recovered_s;

    let port2 = proxy.latest_port.load(Ordering::SeqCst);
    let passed = recovered_s.is_some() && port2 != port1 && snap.ports_seen.len() == 2;
    let rec_str = recovered_s
        .map(|v| format!("{:.2}s", v))
        .unwrap_or_else(|| "TIMEOUT".into());

    ScenarioResult {
        id: 8,
        code: "server_restart",
        name: "Server Restart Recovery",
        condition: "Kill & respawn server",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "heal {} | rekey {}->{} | NEW-M-01 OK",
            rec_str, port1, port2
        ),
        detail: format!(
            "server_port={} ports_seen={:?}",
            server_port, snap.ports_seen
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn send_probe_expect_silence(server_addr: SocketAddr, payload: &[u8]) -> usize {
    let atk = UdpSocket::bind("127.0.0.1:0").expect("bind attacker");
    atk.set_read_timeout(Some(Duration::from_millis(110)))
        .unwrap();
    atk.connect(server_addr).unwrap();
    let _ = atk.send(payload);
    let mut buf = [0u8; PROBE_IO_BUF_LEN];
    atk.recv(&mut buf).unwrap_or_default()
}

pub(super) fn test_09_active_probing_defense(
    opts: &SelftestOptions,
    hi: &mut Highlights,
) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-09-security-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    let _server = ManagedServer::start(
        server_port,
        backend.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
    );
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), false);
    let client = ManagedClient::start(
        proxy.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
        5,
        250,
    );

    // Bring up a legitimate tunnel concurrently to verify probes don't disrupt real sessions
    // AND to capture a real valid STUN request for cross-port replay testing!
    let app = connect_app(client.port, 400);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 9,
            code: "active_probe",
            name: "Active Probe & Replay Defense",
            condition: "8 hostile vectors",
            status: ScenarioStatus::Fail,
            metrics: "Legit setup FAILED".into(),
            detail: "Legitimate baseline session failed to establish".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let captured_stun = proxy.snapshot().captured_valid_stun.unwrap_or_default();
    let ice = SessionIceParams::generate();

    // 1. Random UDP garbage
    let mut rand_junk = [0u8; 64];
    fill_random(&mut rand_junk);

    // 2. Forged DTLS 1.2 ClientHello without prior STUN authentication
    let mut forged_dtls = vec![0u8; 64];
    forged_dtls[0] = DTLS_CT_HANDSHAKE; // Handshake
    forged_dtls[1] = DTLS_VER_MAJOR;
    forged_dtls[2] = DTLS_VER_MINOR_12; // DTLS 1.2
    forged_dtls[11] = 0;
    forged_dtls[12] = 51;
    forged_dtls[13] = DTLS_HS_CLIENT_HELLO; // ClientHello

    // 3. Valid-format STUN signed with WRONG PSK
    let (wrong_psk_stun, _) = build_ice_stun_request(b"wrong-attacker-psk", &ice, None, true);

    // 4. Real STUN with 1 bit flipped inside MESSAGE-INTEGRITY HMAC
    let (mut tampered_mi_stun, _) = build_ice_stun_request(&psk, &ice, None, true);
    let mi_idx = tampered_mi_stun.len().saturating_sub(14);
    tampered_mi_stun[mi_idx] ^= 0x01;

    // 5. Real STUN with injected trailing attribute after FINGERPRINT (smuggling)
    let (mut smuggled_stun, _) = build_ice_stun_request(&psk, &ice, None, true);
    smuggled_stun.extend_from_slice(&[0x80, 0x22, 0x00, 0x04, b'E', b'V', b'I', b'L']);
    let new_body_len = (smuggled_stun.len() - STUN_HDR_LEN) as u16;
    smuggled_stun[2..4].copy_from_slice(&new_body_len.to_be_bytes());

    // 6. Cross-port replay of real captured authenticated client STUN packet
    let replay_stun = captured_stun;

    // 7. Orphan STUN keepalive (valid PSK + fresh txid, USE-CANDIDATE=false, unknown peer -> NEW-M-01)
    let (orphan_ka_stun, _) = build_ice_stun_request(&psk, &ice, None, false);

    // 8. Forged/tampered SRTP packet (0x90 RTP header + random payload/tag)
    let mut forged_srtp = vec![0u8; 96];
    fill_random(&mut forged_srtp);
    forged_srtp[0] = RTP_V2_EXT_BYTE;
    forged_srtp[1] = RTP_VIDEO_PT;

    let probes: [(&str, &[u8]); 8] = [
        ("junk", &rand_junk),
        ("dtls_no_stun", &forged_dtls),
        ("wrong_psk", &wrong_psk_stun),
        ("bad_mi", &tampered_mi_stun),
        ("tail_smuggle", &smuggled_stun),
        ("cross_replay", &replay_stun),
        ("orphan_ka", &orphan_ka_stun),
        ("bad_srtp", &forged_srtp),
    ];

    let mut blocked = 0usize;
    let mut leaked_bytes = 0usize;
    let mut leaked_names = Vec::new();
    for (label, payload) in probes {
        let rx = send_probe_expect_silence(server_addr, payload);
        if rx == 0 {
            blocked += 1;
        } else {
            leaked_bytes += rx;
            leaked_names.push(format!("{}({}B)", label, rx));
        }
    }

    // Verify legitimate tunnel is completely undisturbed after active attack wave
    let mut rbuf = [0u8; CTRL_FRAME_BUF_LEN];
    let _ = app.send(b"LEGIT_POST_ATTACK_OK");
    let legit_ok = app
        .recv(&mut rbuf)
        .map(|n| &rbuf[..n] == b"LEGIT_POST_ATTACK_OK")
        .unwrap_or(false);

    hi.probes_blocked = blocked;
    hi.probes_total = probes.len();

    let passed =
        blocked == probes.len() && leaked_bytes == 0 && legit_ok && !replay_stun.is_empty();
    ScenarioResult {
        id: 9,
        code: "active_probe",
        name: "Active Probe & Replay Defense",
        condition: "8 hostile vectors",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "silent_drop {}/{} ({}B leaked) | legit {}",
            blocked,
            probes.len(),
            leaked_bytes,
            if legit_ok { "OK" } else { "FAIL" }
        ),
        detail: if leaked_names.is_empty() {
            "All 8 vectors (junk/DTLS/PSK/MI/smuggle/replay/orphanKA/SRTP) 100% dropped".into()
        } else {
            format!("Leaked responses on: {}", leaked_names.join(", "))
        },
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

pub(super) fn test_10_multistream_throughput(
    opts: &SelftestOptions,
    hi: &mut Highlights,
) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-10-throughput-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(
        server_port,
        backend.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
    );
    // Direct client -> server (no impairment proxy) to measure true tunnel forwarding engine
    let client = ManagedClient::start(server_port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    // Phase A: 4 concurrent independent UDP sessions handshaking simultaneously
    let streams = 4usize;
    let barrier = Arc::new(Barrier::new(streams));
    let mut handles = Vec::with_capacity(streams);
    for sid in 0..streams {
        let cport = client.port;
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let sock = connect_app(cport, 300);
            bar.wait();
            let msg = format!("STREAM_ISOLATION_TOKEN_{:02}", sid);
            let mut rb = [0u8; CTRL_FRAME_BUF_LEN];
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut ok = false;
            while Instant::now() < deadline {
                let _ = sock.send(msg.as_bytes());
                if let Ok(n) = sock.recv(&mut rb) {
                    if &rb[..n] == msg.as_bytes() {
                        ok = true;
                        break;
                    }
                }
            }
            ok
        }));
    }
    let streams_ok = handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .filter(|&ok| ok)
        .count();

    // Phase B: Single-core end-to-end encrypted SRTP goodput burst (12,000 x 1200B = 14.4 MB)
    backend.reset();
    let app = connect_app(client.port, 300);
    let hs_ok = handshake_app(&app, Duration::from_secs(3)).is_some();

    let burst_pkts = 12_000u64;
    let payload_sz = 1200usize;
    let mut blk = vec![0u8; payload_sz];
    blk[..5].copy_from_slice(b"SINK:");
    fill_random(&mut blk[5..]);

    // Gentle micro-yield every 32 packets keeps macOS loopback socket buffer lossless
    for i in 0..burst_pkts {
        let _ = app.send(&blk);
        if (i + 1) % 32 == 0 {
            thread::yield_now();
        }
    }
    thread::sleep(Duration::from_millis(80));

    let bst = backend.snapshot();
    let dur = match (bst.sink_first, bst.sink_last) {
        (Some(f), Some(l)) if l > f => l.duration_since(f).as_secs_f64(),
        _ => 0.001,
    };
    let mbps = (bst.sink_bytes as f64 * 8.0) / dur / 1e6;
    let kpps = (bst.sink_pkts as f64) / dur / 1e3;
    let delivery_pct = (bst.sink_pkts as f64 / burst_pkts as f64) * 100.0;

    hi.goodput_mbps = Some(mbps);
    hi.goodput_kpps = Some(kpps);

    let passed = streams_ok == streams && hs_ok && delivery_pct >= 90.0 && mbps >= 80.0;
    ScenarioResult {
        id: 10,
        code: "throughput",
        name: "Multi-Stream & Loopback Speed",
        condition: "4 streams + 12k x 1200B",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "{}/{} streams | {:.0} Mbps ({:.1} kpps) | {:.1}% rx",
            streams_ok, streams, mbps, kpps, delivery_pct
        ),
        detail: format!(
            "rx={}/{} pkts ({:.2} MB) in {:.3}s",
            bst.sink_pkts,
            burst_pkts,
            bst.sink_bytes as f64 / 1e6,
            dur
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn bench_single_suite(suite: CipherSuite, count: usize, payload_bytes: usize) -> (f64, f64, bool) {
    let psk = b"selftest-cpu-bench-psk-2026";
    let mut txid = [0u8; 12];
    fill_random(&mut txid);
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, "cpu1:cpu2");
    let skey = combine_session_key(&stun_key, None);
    let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
    let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);

    let mut plain = vec![0u8; payload_bytes];
    fill_random(&mut plain);
    let mut wbuf = vec![0u8; payload_bytes + 128];
    let mut rbuf = vec![0u8; payload_bytes + 128];

    // Warmup + exact byte-integrity check
    let mut integrity_ok = true;
    for _ in 0..200 {
        let wn = match cli.wrap_into(&plain, &mut wbuf) {
            Some(n) => n,
            None => return (0.0, 0.0, false),
        };
        let rn = match srv.unwrap_into(&wbuf[..wn], &mut rbuf) {
            Some(n) => n,
            None => return (0.0, 0.0, false),
        };
        if rn != payload_bytes || rbuf[..rn] != plain[..] {
            integrity_ok = false;
        }
    }

    let t0 = Instant::now();
    for _ in 0..count {
        let wn = cli.wrap_into(&plain, &mut wbuf).unwrap();
        let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
        std::hint::black_box(rn);
    }
    let dt = t0.elapsed().as_secs_f64().max(0.000_001);
    let mbps = (((count as u64) * (payload_bytes as u64) * 8) as f64) / dt / 1e6;
    let kpps = (count as f64) / dt / 1e3;
    (mbps, kpps, integrity_ok)
}

pub(super) fn test_11_cpu_single_core_crypto(
    _opts: &SelftestOptions,
    hi: &mut Highlights,
) -> ScenarioResult {
    let t0 = Instant::now();
    let count = 40_000usize;
    let payload_bytes = 1200usize;

    let (aes_mbps, aes_kpps, aes_ok) =
        bench_single_suite(CipherSuite::Aes128Gcm, count, payload_bytes);
    let (chacha_mbps, chacha_kpps, chacha_ok) =
        bench_single_suite(CipherSuite::ChaCha20Poly1305, count, payload_bytes);
    let (b2b_mbps, b2b_kpps, b2b_ok) =
        bench_single_suite(CipherSuite::Blake2b, count, payload_bytes);

    hi.cpu_aes_mbps = Some(aes_mbps);
    hi.cpu_chacha_mbps = Some(chacha_mbps);
    hi.cpu_blake2b_mbps = Some(b2b_mbps);

    let passed =
        aes_ok && chacha_ok && b2b_ok && aes_mbps > 50.0 && chacha_mbps > 50.0 && b2b_mbps > 50.0;

    ScenarioResult {
        id: 11,
        code: "cpu_crypto_1c",
        name: "CPU Single-Core Crypto Bench",
        condition: "3 suites x 40k x 1200B",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "AES {:.0} | ChaCha {:.0} | B2B {:.0} Mbps (1C)",
            aes_mbps, chacha_mbps, b2b_mbps
        ),
        detail: format!(
            "kpps: AES={:.1} ChaCha={:.1} B2B={:.1} (wrap+unwrap 1200B)",
            aes_kpps, chacha_kpps, b2b_kpps
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

pub(super) fn test_12_cpu_multicore_and_p256(
    opts: &SelftestOptions,
    hi: &mut Highlights,
) -> ScenarioResult {
    let t0 = Instant::now();
    let cpu = detect_cpu_accel();
    let suite = match opts.cipher_pref {
        CipherPref::Auto => cpu.recommended,
        CipherPref::Fixed(s) => s,
    };
    let cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1);
    hi.cpu_cores = cores;

    // Phase A: All-core parallel SRTP AEAD wrap+unwrap scaling test
    let per_core_pkts = 25_000usize;
    let payload_bytes = 1200usize;
    let barrier = Arc::new(Barrier::new(cores));
    let mut handles = Vec::with_capacity(cores);

    for tid in 0..cores {
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let psk = b"selftest-cpu-mc-psk";
            let mut txid = [0u8; 12];
            fill_random(&mut txid);
            let uname = format!("mc{:02}:mc{:02}", tid, tid);
            let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, &uname);
            let skey = combine_session_key(&stun_key, None);
            let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
            let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);
            let mut plain = vec![0u8; payload_bytes];
            fill_random(&mut plain);
            let mut wbuf = vec![0u8; payload_bytes + 128];
            let mut rbuf = vec![0u8; payload_bytes + 128];

            for _ in 0..100 {
                let wn = cli.wrap_into(&plain, &mut wbuf).unwrap();
                let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
                std::hint::black_box(rn);
            }

            bar.wait();
            let ts = Instant::now();
            for _ in 0..per_core_pkts {
                let wn = cli.wrap_into(&plain, &mut wbuf).unwrap();
                let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
                std::hint::black_box(rn);
            }
            ts.elapsed().as_secs_f64()
        }));
    }

    let mut max_dt = 0.000_001f64;
    let mut joined = 0usize;
    for h in handles {
        if let Ok(dt) = h.join() {
            joined += 1;
            if dt > max_dt {
                max_dt = dt;
            }
        }
    }
    let total_bits = ((joined as u64) * (per_core_pkts as u64) * (payload_bytes as u64) * 8) as f64;
    let agg_gbps = total_bits / max_dt / 1e9;
    hi.cpu_multicore_gbps = Some(agg_gbps);

    // Phase B: P-256 ECDSA ephemeral DTLS certificate generation throughput
    let cert_iters = 60usize;
    let tc = Instant::now();
    let mut cert_ok = true;
    for _ in 0..cert_iters {
        let cert = generate_ephemeral_webrtc_cert();
        if cert.certificate.is_empty() || cert.private_key.is_empty() {
            cert_ok = false;
        }
        std::hint::black_box(cert.certificate.len());
    }
    let cert_dt = tc.elapsed().as_secs_f64().max(0.000_001);
    let certs_per_s = (cert_iters as f64) / cert_dt;
    hi.cpu_p256_certs_per_s = Some(certs_per_s);

    let passed = joined == cores && cert_ok && agg_gbps > 0.1 && certs_per_s > 5.0;
    ScenarioResult {
        id: 12,
        code: "cpu_crypto_mc",
        name: "CPU Multi-Core & P-256 Certs",
        condition: "All cores + P-256 certs",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "{}C {}: {:.2} Gbps | P-256 {:.0} certs/s",
            cores,
            suite.name(),
            agg_gbps,
            certs_per_s
        ),
        detail: format!(
            "cores={} per_core={}pkts wall={:.3}s certs={} in {:.3}s",
            cores, per_core_pkts, max_dt, cert_iters, cert_dt
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}
