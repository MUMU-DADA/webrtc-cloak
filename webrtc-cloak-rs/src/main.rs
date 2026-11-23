mod client;
mod protocol;
mod server;

use crate::client::{run_client, ClientConfig};
use crate::protocol::{
    combine_session_key, derive_stun_material, detect_cpu_accel, fill_random, CipherPref,
    CipherSuite, SrtpCloakCipher,
};
use crate::server::{run_server, ServerConfig};
use std::env;
use std::net::{SocketAddr, UdpSocket};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

fn parse_workers(s: &str) -> usize {
    if s == "auto" {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        s.parse::<usize>().unwrap_or(1).max(1)
    }
}

fn parse_cipher_pref(s: &str) -> CipherPref {
    match s {
        "auto" => CipherPref::Auto,
        "aes-gcm" | "aes128-gcm" | "gcm" => CipherPref::Fixed(CipherSuite::Aes128Gcm),
        "chacha20" | "chacha20-poly1305" | "chacha" => {
            CipherPref::Fixed(CipherSuite::ChaCha20Poly1305)
        }
        "blake2b" | "b2b" => CipherPref::Fixed(CipherSuite::Blake2b),
        other => {
            eprintln!(
                "Unknown cipher: {} (expected auto, aes-gcm, chacha20, or blake2b)",
                other
            );
            process::exit(2);
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "Usage:\n  \
         webrtc-cloak cpu\n  \
         webrtc-cloak client --listen-host 127.0.0.1 --listen-port 19543 --server-host <IP> --server-port 19643 (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--cipher auto|aes-gcm|chacha20|blake2b] [--workers 1|auto] [--max-sessions 4096] [--keepalive 5] [--idle-timeout 120] [--no-dtls-decoy]\n  \
         webrtc-cloak server --listen-host 0.0.0.0 --listen-port 19643 --backend-host 127.0.0.1 --backend-port <PORT> (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--cipher auto|aes-gcm|chacha20|blake2b] [--workers 1|auto] [--max-sessions 4096] [--idle-timeout 120] [--no-dtls-decoy]\n  \
         webrtc-cloak bench [count] [payload_bytes] [all|aes-gcm|chacha20|blake2b]"
    );
    process::exit(2);
}

fn resolve_psk(psk_arg: String, psk_file: Option<String>) -> Vec<u8> {
    if let Some(path) = psk_file {
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return trimmed.as_bytes().to_vec();
                }
            }
            Err(e) => {
                eprintln!("Failed to read --psk-file {}: {}", path, e);
                process::exit(2);
            }
        }
    }
    if !psk_arg.is_empty() {
        return psk_arg.into_bytes();
    }
    if let Ok(env_k) = env::var("WEBRTC_CLOAK_PSK") {
        let trimmed = env_k.trim();
        if !trimmed.is_empty() {
            return trimmed.as_bytes().to_vec();
        }
    }
    usage();
}

fn print_cpu_info() {
    let info = detect_cpu_accel();
    println!("arch        : {}", info.arch);
    println!(
        "hw_accel    : {}",
        if info.features.is_empty() {
            "(none - pure scalar fallback)".to_string()
        } else {
            info.features.join(", ")
        }
    );
    println!("hw_aes_gcm  : {}", info.has_hw_aes_gcm);
    println!("recommended : {}", info.recommended.name());
}

fn run_bench(count: usize, payload_bytes: usize, suite: CipherSuite) {
    let psk = b"bench-psk-2026";
    let mut txid = [0u8; 12];
    fill_random(&mut txid);
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, "r1a2:l3b4");
    let skey = combine_session_key(&stun_key, None);
    let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
    let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);

    let mut plain = vec![0u8; payload_bytes];
    fill_random(&mut plain);
    let mut wbuf = vec![0u8; payload_bytes + 128];
    let mut rbuf = vec![0u8; payload_bytes + 128];

    for _ in 0..200 {
        let wn = cli.wrap_into(&plain, &mut wbuf).unwrap();
        let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
        assert_eq!(rn, payload_bytes);
    }

    let t0 = Instant::now();
    for _ in 0..count {
        let wn = cli.wrap_into(&plain, &mut wbuf).unwrap();
        let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
        std::hint::black_box(rn);
    }
    let dt = t0.elapsed().as_secs_f64();
    let total_mb = (count * payload_bytes) as f64 / 1e6;
    let mbps = ((count * payload_bytes * 8) as f64) / dt / 1e6;
    let kpps = (count as f64) / dt / 1e3;
    println!(
        "[bench-rs/{:17}] wrap+unwrap {}x{}B ({:.2} MB) in {:.4}s -> {:7.1} Mbps ({:6.1} kpps)",
        suite.name(),
        count,
        payload_bytes,
        total_mb,
        dt,
        mbps,
        kpps
    );
}

fn run_sink(listen: &str, workers: usize) {
    let workers = workers.max(1);
    let addr: SocketAddr = listen.parse().expect("sink addr");
    let cnt = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let start_epoch = Instant::now();
    let first_ns = Arc::new(AtomicU64::new(0));
    let last_ns = Arc::new(AtomicU64::new(0));

    println!("[sink-rs] listening on {} (workers={})", listen, workers);

    let spawn_one = |reuse: bool| {
        let cnt = Arc::clone(&cnt);
        let bytes = Arc::clone(&bytes);
        let first_ns = Arc::clone(&first_ns);
        let last_ns = Arc::clone(&last_ns);
        move || {
            let s = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .expect("sink socket");
            let _ = s.set_reuse_address(true);
            #[cfg(unix)]
            if reuse {
                let _ = s.set_reuse_port(true);
            }
            #[cfg(not(unix))]
            let _ = reuse;
            let _ = s.set_recv_buffer_size(8 * 1024 * 1024);
            let _ = s.set_send_buffer_size(8 * 1024 * 1024);
            s.bind(&addr.into()).expect("bind sink");
            let sock: UdpSocket = s.into();
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let pkt = &buf[..n];
                if pkt.starts_with(b"SINK:") {
                    let ns = start_epoch.elapsed().as_nanos() as u64;
                    let _ = first_ns.compare_exchange(0, ns, Ordering::Relaxed, Ordering::Relaxed);
                    last_ns.store(ns, Ordering::Relaxed);
                    cnt.fetch_add(1, Ordering::Relaxed);
                    bytes.fetch_add(n as u64, Ordering::Relaxed);
                } else if pkt.starts_with(b"RESET") {
                    cnt.store(0, Ordering::Relaxed);
                    bytes.store(0, Ordering::Relaxed);
                    first_ns.store(0, Ordering::Relaxed);
                    last_ns.store(0, Ordering::Relaxed);
                    let _ = sock.send_to(b"RESET_OK", peer);
                } else if pkt.starts_with(b"STAT") {
                    let f = first_ns.load(Ordering::Relaxed);
                    let l = last_ns.load(Ordering::Relaxed);
                    let dur = if f > 0 && l > f {
                        ((l - f) as f64) / 1e9
                    } else {
                        0.000_001
                    };
                    let msg = format!(
                        "STAT:{}:{}:{:.6}",
                        cnt.load(Ordering::Relaxed),
                        bytes.load(Ordering::Relaxed),
                        dur
                    );
                    let _ = sock.send_to(msg.as_bytes(), peer);
                } else {
                    let _ = sock.send_to(pkt, peer);
                }
            }
        }
    };

    if workers == 1 {
        spawn_one(false)();
        return;
    }
    let mut handles = Vec::with_capacity(workers - 1);
    for _ in 1..workers {
        handles.push(std::thread::spawn(spawn_one(true)));
    }
    spawn_one(true)();
    for h in handles {
        let _ = h.join();
    }
}

fn run_loadgen(target: &str, packets: u64, size: usize, rate_mbps: f64, rtt_iters: usize, streams: usize) {
    let streams = streams.max(1);
    if streams == 1 {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind loadgen");
        let s2 = socket2::SockRef::from(&sock);
        let _ = s2.set_recv_buffer_size(8 * 1024 * 1024);
        let _ = s2.set_send_buffer_size(8 * 1024 * 1024);
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.connect(target).expect("connect target");

        let mut rbuf = vec![0u8; 65536];
        let hello = b"HELLO_LOADGEN_WARMUP";
        let t0 = Instant::now();
        sock.send(hello).unwrap();
        let n = sock.recv(&mut rbuf).expect("handshake recv");
        assert_eq!(&rbuf[..n], hello);
        let hs_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let mut rtt_pkt = vec![0u8; size];
        rtt_pkt[..4].copy_from_slice(b"RTT:");
        fill_random(&mut rtt_pkt[4..]);
        let mut rtts_us = Vec::with_capacity(rtt_iters);
        for _ in 0..rtt_iters {
            let tr = Instant::now();
            sock.send(&rtt_pkt).unwrap();
            let rn = sock.recv(&mut rbuf).expect("rtt recv");
            assert_eq!(rn, size);
            rtts_us.push(tr.elapsed().as_secs_f64() * 1e6);
        }
        rtts_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let rtt_min = rtts_us[0];
        let rtt_p50 = rtts_us[rtts_us.len() / 2];
        let rtt_p95 = rtts_us[(rtts_us.len() * 95) / 100];
        let rtt_p99 = rtts_us[(rtts_us.len() * 99) / 100];

        sock.send(b"RESET").unwrap();
        let rn = sock.recv(&mut rbuf).expect("reset recv");
        assert_eq!(&rbuf[..rn], b"RESET_OK");

        let mut blk = vec![0u8; size];
        blk[..5].copy_from_slice(b"SINK:");
        fill_random(&mut blk[5..]);

        let ts = Instant::now();
        if rate_mbps > 0.0 {
            let bytes_per_sec = (rate_mbps * 1e6) / 8.0;
            let batch: u64 = 16;
            let mut sent_bytes: f64 = 0.0;
            for i in 0..packets {
                let _ = sock.send(&blk);
                sent_bytes += size as f64;
                if (i + 1) % batch == 0 {
                    let target_elapsed = sent_bytes / bytes_per_sec;
                    let cur = ts.elapsed().as_secs_f64();
                    if target_elapsed > cur {
                        let wait_us = ((target_elapsed - cur) * 1e6) as u64;
                        if wait_us >= 50 {
                            std::thread::sleep(Duration::from_micros(wait_us));
                        } else {
                            while ts.elapsed().as_secs_f64() < target_elapsed {
                                std::hint::spin_loop();
                            }
                        }
                    }
                }
            }
        } else {
            for _ in 0..packets {
                let _ = sock.send(&blk);
            }
        }
        let send_dt = ts.elapsed().as_secs_f64();
        std::thread::sleep(Duration::from_millis(120));

        sock.send(b"STAT").unwrap();
        let sn = sock.recv(&mut rbuf).expect("stat recv");
        let stat_s = std::str::from_utf8(&rbuf[..sn]).unwrap();
        let parts: Vec<&str> = stat_s.split(':').collect();
        let rx_cnt: u64 = parts[1].parse().unwrap();
        let rx_bytes: u64 = parts[2].parse().unwrap();
        let rx_dur: f64 = parts[3].parse().unwrap();
        let loss = (1.0 - (rx_cnt as f64 / packets as f64)) * 100.0;
        let rx_mbps = (rx_bytes as f64 * 8.0) / rx_dur.max(0.000_001) / 1e6;
        let rx_kpps = (rx_cnt as f64) / rx_dur.max(0.000_001) / 1e3;
        let tx_mbps = ((packets * size as u64) as f64 * 8.0) / send_dt.max(0.000_001) / 1e6;

        println!(
            "hs={:.2}ms rtt_us(min/p50/p95/p99)={:.0}/{:.0}/{:.0}/{:.0} tx={:.1}Mbps rx={}/{} ({:.2}% loss) goodput={:.1}Mbps ({:.1}kpps) dur={:.3}s",
            hs_ms, rtt_min, rtt_p50, rtt_p95, rtt_p99, tx_mbps, rx_cnt, packets, loss, rx_mbps, rx_kpps, rx_dur
        );
        return;
    }

    // Multi-stream concurrent loadgen: each stream opens its own independent UDP 5-tuple!
    let target_s = target.to_string();
    let per_stream_pkts = packets / (streams as u64);
    let total_pkts = per_stream_pkts * (streams as u64);
    let per_stream_rate = if rate_mbps > 0.0 {
        rate_mbps / (streams as f64)
    } else {
        0.0
    };

    // Reset sink first via a control socket
    let ctrl = UdpSocket::bind("127.0.0.1:0").expect("ctrl bind");
    ctrl.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    ctrl.connect(target).expect("ctrl connect");
    let mut rbuf = vec![0u8; 4096];
    ctrl.send(b"RESET").unwrap();
    let rn = ctrl.recv(&mut rbuf).expect("ctrl reset");
    assert_eq!(&rbuf[..rn], b"RESET_OK");

    let barrier = Arc::new(Barrier::new(streams));
    let mut handles = Vec::with_capacity(streams);

    for sid in 0..streams {
        let tgt = target_s.clone();
        let bar = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("stream bind");
            let s2 = socket2::SockRef::from(&sock);
            let _ = s2.set_send_buffer_size(8 * 1024 * 1024);
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            sock.connect(&tgt).expect("stream connect");

            // Complete independent STUN + DTLS handshake on this 5-tuple first (with retry)
            let mut rb = [0u8; 256];
            let hi = format!("HI_STREAM_{}", sid);
            sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            let mut ok = false;
            for _ in 0..6 {
                let _ = sock.send(hi.as_bytes());
                if let Ok(n) = sock.recv(&mut rb) {
                    if &rb[..n] == hi.as_bytes() {
                        ok = true;
                        break;
                    }
                }
            }
            assert!(ok, "stream {} handshake failed", sid);

            let mut blk = vec![0u8; size];
            blk[..5].copy_from_slice(b"SINK:");
            fill_random(&mut blk[5..]);

            bar.wait();
            let ts = Instant::now();
            if per_stream_rate > 0.0 {
                let bps = (per_stream_rate * 1e6) / 8.0;
                let mut sent_b = 0.0f64;
                for i in 0..per_stream_pkts {
                    let _ = sock.send(&blk);
                    sent_b += size as f64;
                    if (i + 1) % 64 == 0 {
                        let tgt_t = sent_b / bps;
                        let cur = ts.elapsed().as_secs_f64();
                        if tgt_t > cur {
                            let w_us = ((tgt_t - cur) * 1e6) as u64;
                            if w_us >= 200 {
                                std::thread::sleep(Duration::from_micros(w_us));
                            } else {
                                std::thread::yield_now();
                            }
                        }
                    }
                }
            } else {
                for _ in 0..per_stream_pkts {
                    let _ = sock.send(&blk);
                }
            }
            ts.elapsed().as_secs_f64()
        }));
    }

    let mut max_dt = 0.000_001f64;
    for h in handles {
        let dt = h.join().unwrap();
        if dt > max_dt {
            max_dt = dt;
        }
    }
    std::thread::sleep(Duration::from_millis(150));

    ctrl.send(b"STAT").unwrap();
    let sn = ctrl.recv(&mut rbuf).expect("ctrl stat");
    let stat_s = std::str::from_utf8(&rbuf[..sn]).unwrap();
    let parts: Vec<&str> = stat_s.split(':').collect();
    let rx_cnt: u64 = parts[1].parse().unwrap();
    let rx_bytes: u64 = parts[2].parse().unwrap();
    let rx_dur: f64 = parts[3].parse().unwrap();
    let loss = (1.0 - (rx_cnt as f64 / total_pkts as f64)) * 100.0;
    let rx_mbps = (rx_bytes as f64 * 8.0) / rx_dur.max(0.000_001) / 1e6;
    let rx_kpps = (rx_cnt as f64) / rx_dur.max(0.000_001) / 1e3;
    let tx_mbps = ((total_pkts * size as u64) as f64 * 8.0) / max_dt / 1e6;
    println!(
        "streams={} tx={:.1}Mbps rx={}/{} ({:.2}% loss) goodput={:.1}Mbps ({:.1}kpps) dur={:.3}s",
        streams, tx_mbps, rx_cnt, total_pkts, loss, rx_mbps, rx_kpps, rx_dur
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "cpu" => {
            print_cpu_info();
        }
        "sink" => {
            let listen = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:19760");
            let workers = args.get(3).map(|s| parse_workers(s)).unwrap_or(1);
            run_sink(listen, workers);
        }
        "loadgen" => {
            let target = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:19560");
            let packets: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(50_000);
            let size: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1260);
            let rate_mbps: f64 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let rtt_iters: usize = args.get(6).and_then(|s| s.parse().ok()).unwrap_or(500);
            let streams: usize = args.get(7).and_then(|s| s.parse().ok()).unwrap_or(1);
            run_loadgen(target, packets, size, rate_mbps, rtt_iters, streams);
        }
        "bench" => {
            let count = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(50_000);
            let sz = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1260);
            let mode = args.get(4).map(|s| s.as_str()).unwrap_or("all");
            print_cpu_info();
            if mode == "all" {
                run_bench(count, sz, CipherSuite::Aes128Gcm);
                run_bench(count, sz, CipherSuite::ChaCha20Poly1305);
                run_bench(count, sz, CipherSuite::Blake2b);
            } else {
                match parse_cipher_pref(mode) {
                    CipherPref::Fixed(s) => run_bench(count, sz, s),
                    CipherPref::Auto => run_bench(count, sz, detect_cpu_accel().recommended),
                }
            }
        }
        "client" => {
            let mut listen_host = "127.0.0.1".to_string();
            let mut listen_port: u16 = 19543;
            let mut server_host = String::new();
            let mut server_port: u16 = 19643;
            let mut psk = String::new();
            let mut psk_file: Option<String> = None;
            let mut cipher_pref = CipherPref::Auto;
            let mut dtls_decoy = true;
            let mut workers: usize = 1;
            let mut max_sessions: usize = 4096;
            let mut retry_ms: u64 = 300;
            let mut max_retries: u32 = 8;
            let mut keepalive_secs: u64 = 5; // RFC 7675 §5.1 Consent Freshness (5s ± 20%)
            let mut idle_timeout_secs: u64 = 120;
            let mut stats_interval_secs: u64 = 10;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--listen-host" => { i += 1; listen_host = args[i].clone(); }
                    "--listen-port" => { i += 1; listen_port = args[i].parse().unwrap(); }
                    "--server-host" => { i += 1; server_host = args[i].clone(); }
                    "--server-port" => { i += 1; server_port = args[i].parse().unwrap(); }
                    "--psk" => { i += 1; psk = args[i].clone(); }
                    "--psk-file" => { i += 1; psk_file = Some(args[i].clone()); }
                    "--cipher" => { i += 1; cipher_pref = parse_cipher_pref(&args[i]); }
                    "--workers" => { i += 1; workers = parse_workers(&args[i]); }
                    "--max-sessions" => { i += 1; max_sessions = args[i].parse::<usize>().unwrap().max(1); }
                    "--no-dtls-decoy" => { dtls_decoy = false; }
                    "--retry-ms" => { i += 1; retry_ms = args[i].parse().unwrap(); }
                    "--max-retries" => { i += 1; max_retries = args[i].parse().unwrap(); }
                    "--keepalive" => { i += 1; keepalive_secs = args[i].parse().unwrap(); }
                    "--idle-timeout" => { i += 1; idle_timeout_secs = args[i].parse().unwrap(); }
                    "--stats-interval" => { i += 1; stats_interval_secs = args[i].parse().unwrap(); }
                    other => { eprintln!("Unknown flag: {}", other); usage(); }
                }
                i += 1;
            }
            if server_host.is_empty() {
                usage();
            }
            let psk_bytes = resolve_psk(psk, psk_file);
            let listen_addr: SocketAddr = format!("{}:{}", listen_host, listen_port).parse().unwrap();
            let server_addr: SocketAddr = format!("{}:{}", server_host, server_port).parse().unwrap();
            if let Err(e) = run_client(ClientConfig {
                listen_addr,
                server_addr,
                psk: psk_bytes,
                cipher_pref,
                dtls_decoy,
                workers,
                max_sessions,
                retry_ms,
                max_retries,
                keepalive_secs,
                idle_timeout_secs,
                stats_interval_secs,
            }) {
                eprintln!("client error: {}", e);
                process::exit(1);
            }
        }
        "server" => {
            let mut listen_host = "0.0.0.0".to_string();
            let mut listen_port: u16 = 19643;
            let mut backend_host = "127.0.0.1".to_string();
            let mut backend_port: u16 = 0;
            let mut psk = String::new();
            let mut psk_file: Option<String> = None;
            let mut cipher_pref = CipherPref::Auto;
            let mut dtls_required = true;
            let mut workers: usize = 1;
            let mut max_sessions: usize = 4096;
            let mut idle_timeout_secs: u64 = 120;
            let mut stats_interval_secs: u64 = 10;
            let mut wire_audit_file: Option<String> = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--listen-host" => { i += 1; listen_host = args[i].clone(); }
                    "--listen-port" => { i += 1; listen_port = args[i].parse().unwrap(); }
                    "--backend-host" => { i += 1; backend_host = args[i].clone(); }
                    "--backend-port" => { i += 1; backend_port = args[i].parse().unwrap(); }
                    "--psk" => { i += 1; psk = args[i].clone(); }
                    "--psk-file" => { i += 1; psk_file = Some(args[i].clone()); }
                    "--cipher" => { i += 1; cipher_pref = parse_cipher_pref(&args[i]); }
                    "--workers" => { i += 1; workers = parse_workers(&args[i]); }
                    "--max-sessions" => { i += 1; max_sessions = args[i].parse::<usize>().unwrap().max(1); }
                    "--no-dtls-decoy" => { dtls_required = false; }
                    "--idle-timeout" => { i += 1; idle_timeout_secs = args[i].parse().unwrap(); }
                    "--stats-interval" => { i += 1; stats_interval_secs = args[i].parse().unwrap(); }
                    "--wire-audit-file" => { i += 1; wire_audit_file = Some(args[i].clone()); }
                    other => { eprintln!("Unknown flag: {}", other); usage(); }
                }
                i += 1;
            }
            if backend_port == 0 {
                usage();
            }
            let psk_bytes = resolve_psk(psk, psk_file);
            let listen_addr: SocketAddr = format!("{}:{}", listen_host, listen_port).parse().unwrap();
            let backend_addr: SocketAddr = format!("{}:{}", backend_host, backend_port).parse().unwrap();
            if let Err(e) = run_server(ServerConfig {
                listen_addr,
                backend_addr,
                psk: psk_bytes,
                cipher_pref,
                dtls_required,
                workers,
                max_sessions,
                idle_timeout_secs,
                stats_interval_secs,
                wire_audit_file,
            }) {
                eprintln!("server error: {}", e);
                process::exit(1);
            }
        }
        _ => usage(),
    }
}
