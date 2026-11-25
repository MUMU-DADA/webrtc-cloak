//! CPU 加速探测、密码学基准测试与 UDP 压测辅助工具。

use crate::constants::{CTRL_FRAME_BUF_LEN, DTLS_IO_BUF_LEN, SOCK_BUF_8MIB, UDP_RECV_BUF_LEN};
use crate::protocol::{
    combine_session_key, derive_stun_material, detect_cpu_accel, fill_random, CipherSuite,
    SrtpCloakCipher,
};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

pub(crate) fn print_cpu_info() {
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

pub(crate) fn run_bench(count: usize, payload_bytes: usize, suite: CipherSuite) {
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
    let total_bytes = (count as u64) * (payload_bytes as u64);
    let total_mb = (total_bytes as f64) / 1e6;
    let mbps = ((total_bytes as f64) * 8.0) / dt / 1e6;
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

pub(crate) fn run_sink(listen: &str, workers: usize) {
    let workers = workers.max(1);
    let addr: SocketAddr = listen.parse().expect("sink addr");
    // (cnt, bytes, first_ns, last_ns) — Mutex avoids AtomicU64 for 32-bit targets like armv5te
    let stats = Arc::new(Mutex::new((0u64, 0u64, 0u64, 0u64)));
    let start_epoch = Instant::now();

    println!("[sink-rs] listening on {} (workers={})", listen, workers);

    let spawn_one = |reuse: bool| {
        let stats = Arc::clone(&stats);
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
            let _ = s.set_recv_buffer_size(SOCK_BUF_8MIB);
            let _ = s.set_send_buffer_size(SOCK_BUF_8MIB);
            s.bind(&addr.into()).expect("bind sink");
            let sock: UdpSocket = s.into();
            let mut buf = vec![0u8; UDP_RECV_BUF_LEN];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let pkt = &buf[..n];
                if pkt.starts_with(b"SINK:") {
                    let ns = start_epoch.elapsed().as_nanos() as u64;
                    let mut st = stats.lock().unwrap();
                    if st.2 == 0 {
                        st.2 = ns;
                    }
                    st.3 = ns;
                    st.0 += 1;
                    st.1 += n as u64;
                } else if pkt.starts_with(b"RESET") {
                    *stats.lock().unwrap() = (0, 0, 0, 0);
                    let _ = sock.send_to(b"RESET_OK", peer);
                } else if pkt.starts_with(b"STAT") {
                    let (c, b, f, l) = *stats.lock().unwrap();
                    let dur = if f > 0 && l > f {
                        ((l - f) as f64) / 1e9
                    } else {
                        0.000_001
                    };
                    let msg = format!("STAT:{}:{}:{:.6}", c, b, dur);
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

pub(crate) fn run_loadgen(
    target: &str,
    packets: u64,
    size: usize,
    rate_mbps: f64,
    rtt_iters: usize,
    streams: usize,
) {
    let streams = streams.max(1);
    if streams == 1 {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind loadgen");
        let s2 = socket2::SockRef::from(&sock);
        let _ = s2.set_recv_buffer_size(SOCK_BUF_8MIB);
        let _ = s2.set_send_buffer_size(SOCK_BUF_8MIB);
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.connect(target).expect("connect target");

        let mut rbuf = vec![0u8; UDP_RECV_BUF_LEN];
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
    let mut rbuf = vec![0u8; DTLS_IO_BUF_LEN];
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
            let _ = s2.set_send_buffer_size(SOCK_BUF_8MIB);
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            sock.connect(&tgt).expect("stream connect");

            // Complete independent STUN + DTLS handshake on this 5-tuple first (with retry)
            let mut rb = [0u8; CTRL_FRAME_BUF_LEN];
            let hi = format!("HI_STREAM_{}", sid);
            sock.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
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
