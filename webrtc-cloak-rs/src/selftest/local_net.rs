//! 本地离线基础吞吐、跨洋延迟、丢包、乱序与 MTU 防分片场景测试。

use super::harness::{
    connect_app, handshake_app, EchoBackend, ImpairmentProxy, ManagedClient, ManagedServer,
    NetProfile,
};
use super::{
    percentile, reserve_free_port, Highlights, ScenarioResult, ScenarioStatus, SelftestOptions,
};
use crate::constants::{
    CTRL_FRAME_BUF_LEN, DTLS_IO_BUF_LEN, IPV4_UDP_HDR_LEN, SRTP_DATA_MIN_WIRE_LEN,
};
use crate::protocol::fill_random;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

pub(super) fn test_01_baseline(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-01-baseline-psk".to_vec();
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
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    let app = connect_app(client.port, 500);
    let hs_ms = match handshake_app(&app, Duration::from_secs(3)) {
        Some(v) => v,
        None => {
            return ScenarioResult {
                id: 1,
                code: "baseline",
                name: "Baseline & Wire Overhead",
                condition: "0ms / 0% loss",
                status: ScenarioStatus::Fail,
                metrics: "Handshake FAILED".into(),
                detail: "Initial STUN+DTLS handshake did not complete within 3s".into(),
                elapsed_s: t0.elapsed().as_secs_f64(),
            };
        }
    };

    // Wait briefly so handshake packets finish, then reset wire baseline by snapshotting delta
    thread::sleep(Duration::from_millis(30));
    let before = proxy.snapshot();

    let payload_len = 1200usize;
    let count = 60usize;
    let mut pkt = vec![0u8; payload_len];
    let mut rbuf = vec![0u8; DTLS_IO_BUF_LEN];
    let mut rtts_ms = Vec::with_capacity(count);
    let mut ok = 0usize;
    app.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();

    for i in 0..count {
        pkt[..4].copy_from_slice(b"RTT:");
        pkt[4..12].copy_from_slice(&(i as u64).to_be_bytes());
        fill_random(&mut pkt[12..]);
        let ts = Instant::now();
        let _ = app.send(&pkt);
        if let Ok(n) = app.recv(&mut rbuf) {
            if n == payload_len && rbuf[..12] == pkt[..12] {
                rtts_ms.push(ts.elapsed().as_secs_f64() * 1000.0);
                ok += 1;
            }
        }
    }

    let after = proxy.snapshot();
    let srtp_pkts_delta = after.srtp_pkts.saturating_sub(before.srtp_pkts);
    let srtp_bytes_delta = after.srtp_bytes.saturating_sub(before.srtp_bytes);
    let avg_wire = if srtp_pkts_delta > 0 {
        srtp_bytes_delta as f64 / srtp_pkts_delta as f64
    } else {
        0.0
    };
    let delta_b = (avg_wire - payload_len as f64).max(0.0);
    let overhead_pct = (delta_b / payload_len as f64) * 100.0;

    rtts_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = percentile(&rtts_ms, 50);
    let p95 = percentile(&rtts_ms, 95);

    hi.overhead_pct = Some(overhead_pct);
    hi.overhead_bytes = Some(delta_b);
    hi.max_wire_udp = hi.max_wire_udp.max(after.max_wire_udp);

    let max_allowed = opts.wan_mtu.saturating_sub(IPV4_UDP_HDR_LEN);
    let passed = ok == count
        && after.stun_pkts >= 2
        && after.dtls_pkts >= 4
        && after.max_wire_udp <= max_allowed
        && overhead_pct > 2.5
        && overhead_pct < 7.0;

    ScenarioResult {
        id: 1,
        code: "baseline",
        name: "Baseline & Wire Overhead",
        condition: "0ms / 0% loss",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "hs {:.1}ms | p50 {:.2}ms | {}/{} | +{:.1}B (+{:.2}%)",
            hs_ms, p50, ok, count, delta_b, overhead_pct
        ),
        detail: format!(
            "STUN={} DTLS={} SRTP={} SRTCP={} max_wire={}B p95={:.2}ms",
            after.stun_pkts,
            after.dtls_pkts,
            srtp_pkts_delta,
            after.srtcp_pkts,
            after.max_wire_udp,
            p95
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

pub(super) fn test_02_transpacific_latency(
    opts: &SelftestOptions,
    hi: &mut Highlights,
) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-02-wan-rtt-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(
        server_port,
        backend.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
    );
    let proxy = ImpairmentProxy::start(
        server_port,
        psk.clone(),
        NetProfile {
            base_delay_ms: 80,
            jitter_ms: 12,
            seed: 202_602,
            ..Default::default()
        },
        false,
    );
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 600);

    let app = connect_app(client.port, 1000);
    // Avoid double-sending during slow WAN handshake: wait up to 4s with 1s read timeout
    let hs_t0 = Instant::now();
    let ping = b"WAN_HANDSHAKE_PROBE";
    let mut rbuf = vec![0u8; DTLS_IO_BUF_LEN];
    let mut hs_ms = None;
    let _ = app.send(ping);
    while hs_t0.elapsed() < Duration::from_secs(4) {
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == ping {
                hs_ms = Some(hs_t0.elapsed().as_secs_f64() * 1000.0);
                break;
            }
        } else {
            let _ = app.send(ping);
        }
    }

    let Some(hs_val) = hs_ms else {
        return ScenarioResult {
            id: 2,
            code: "wan_latency",
            name: "Trans-Pacific RTT & Jitter",
            condition: "160ms +/-24ms RTT",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "STUN+DTLS handshake timed out under 160ms WAN RTT".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    };

    let count = 12usize;
    let mut pkt = vec![0u8; 1000];
    let mut rtts_ms = Vec::with_capacity(count);
    let mut ok = 0usize;
    app.set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();

    for i in 0..count {
        pkt[..4].copy_from_slice(b"WAN:");
        pkt[4..12].copy_from_slice(&(i as u64).to_be_bytes());
        fill_random(&mut pkt[12..]);
        let ts = Instant::now();
        let _ = app.send(&pkt);
        if let Ok(n) = app.recv(&mut rbuf) {
            if n == pkt.len() && rbuf[..12] == pkt[..12] {
                rtts_ms.push(ts.elapsed().as_secs_f64() * 1000.0);
                ok += 1;
            }
        }
    }

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);
    rtts_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = percentile(&rtts_ms, 50);
    let p95 = percentile(&rtts_ms, 95);

    let passed = ok == count && (130.0..=210.0).contains(&p50) && snap.ports_seen.len() == 1;
    ScenarioResult {
        id: 2,
        code: "wan_latency",
        name: "Trans-Pacific RTT & Jitter",
        condition: "160ms +/-24ms RTT",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "hs {:.0}ms | p50 {:.0}ms | p95 {:.0}ms | {}/{}",
            hs_val, p50, p95, ok, count
        ),
        detail: format!(
            "ports={} c2s={} s2c={}",
            snap.ports_seen.len(),
            snap.c2s_pkts,
            snap.s2c_pkts
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

pub(super) fn test_03_random_loss(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-03-random-loss-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(
        server_port,
        backend.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
    );
    let proxy = ImpairmentProxy::start(
        server_port,
        psk.clone(),
        NetProfile {
            base_delay_ms: 8,
            jitter_ms: 3,
            loss_c2s_pct: 8,
            loss_s2c_pct: 8,
            seed: 202_603,
            ..Default::default()
        },
        false,
    );
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    let app = connect_app(client.port, 400);
    let Some(hs_ms) = handshake_app(&app, Duration::from_secs(5)) else {
        return ScenarioResult {
            id: 3,
            code: "random_loss",
            name: "Bidirectional Random Loss",
            condition: "8% C2S + 8% S2C",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel could not establish under 8% bidirectional packet loss".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    };

    backend.reset();
    let total = 100u64;
    let mut pkt = vec![0u8; 900];
    pkt[..4].copy_from_slice(b"SEQ:");
    app.set_nonblocking(true).unwrap();

    let mut received = HashSet::<u64>::new();
    let mut rbuf = vec![0u8; DTLS_IO_BUF_LEN];

    for seq in 0..total {
        pkt[4..12].copy_from_slice(&seq.to_be_bytes());
        fill_random(&mut pkt[12..]);
        let _ = app.send(&pkt);
        while let Ok(n) = app.recv(&mut rbuf) {
            if n == pkt.len() && &rbuf[..4] == b"SEQ:" {
                let s = u64::from_be_bytes(rbuf[4..12].try_into().unwrap());
                received.insert(s);
            }
        }
        thread::sleep(Duration::from_millis(6));
    }

    let drain_end = Instant::now() + Duration::from_millis(250);
    while Instant::now() < drain_end {
        while let Ok(n) = app.recv(&mut rbuf) {
            if n == pkt.len() && &rbuf[..4] == b"SEQ:" {
                let s = u64::from_be_bytes(rbuf[4..12].try_into().unwrap());
                received.insert(s);
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let snap = proxy.snapshot();
    let bst = backend.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);

    // Expected two-way delivery ~ (0.92)^2 = 84.6%; require >= 68% and 0 false port rotations
    let passed = received.len() >= 68
        && bst.dup_seqs == 0
        && snap.ports_seen.len() == 1
        && snap.dropped_by_proxy >= 5;

    ScenarioResult {
        id: 3,
        code: "random_loss",
        name: "Bidirectional Random Loss",
        condition: "8% C2S + 8% S2C",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "hs {:.0}ms | echo {}/{} | drops={} | ports={}",
            hs_ms,
            received.len(),
            total,
            snap.dropped_by_proxy,
            snap.ports_seen.len()
        ),
        detail: format!(
            "backend_unique={} backend_dup={}",
            bst.unique_seqs, bst.dup_seqs
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

pub(super) fn test_04_reorder_and_replay(
    opts: &SelftestOptions,
    hi: &mut Highlights,
) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-04-reorder-dup-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(
        server_port,
        backend.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
    );
    let proxy = ImpairmentProxy::start(
        server_port,
        psk.clone(),
        NetProfile {
            base_delay_ms: 5,
            jitter_ms: 2,
            reorder_pct: 35,
            duplicate_pct: 30,
            seed: 202_604,
            ..Default::default()
        },
        false,
    );
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    let app = connect_app(client.port, 500);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 4,
            code: "reorder_replay",
            name: "ECMP Reorder & Replay Guard",
            condition: "35% reorder + 30% dup",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    backend.reset();
    let total = 120u64;
    let mut pkt = vec![0u8; 800];
    pkt[..4].copy_from_slice(b"SEQ:");
    app.set_nonblocking(true).unwrap();

    let mut rx_unique = HashSet::<u64>::new();
    let mut rx_client_dups = 0u64;
    let mut rx_out_of_order = 0u64;
    let mut max_seq_seen: Option<u64> = None;
    let mut rbuf = vec![0u8; DTLS_IO_BUF_LEN];

    let pkt_len = pkt.len();
    let mut drain_app =
        |rx_u: &mut HashSet<u64>, dups: &mut u64, ooo: &mut u64, max_s: &mut Option<u64>| {
            while let Ok(n) = app.recv(&mut rbuf) {
                if n == pkt_len && &rbuf[..4] == b"SEQ:" {
                    let s = u64::from_be_bytes(rbuf[4..12].try_into().unwrap());
                    if !rx_u.insert(s) {
                        *dups += 1;
                    }
                    if let Some(m) = *max_s {
                        if s < m {
                            *ooo += 1;
                        } else {
                            *max_s = Some(s);
                        }
                    } else {
                        *max_s = Some(s);
                    }
                }
            }
        };

    for seq in 0..total {
        pkt[4..12].copy_from_slice(&seq.to_be_bytes());
        fill_random(&mut pkt[12..]);
        let _ = app.send(&pkt);
        drain_app(
            &mut rx_unique,
            &mut rx_client_dups,
            &mut rx_out_of_order,
            &mut max_seq_seen,
        );
        thread::sleep(Duration::from_millis(5));
    }

    let drain_end = Instant::now() + Duration::from_millis(350);
    while Instant::now() < drain_end {
        drain_app(
            &mut rx_unique,
            &mut rx_client_dups,
            &mut rx_out_of_order,
            &mut max_seq_seen,
        );
        thread::sleep(Duration::from_millis(5));
    }

    let snap = proxy.snapshot();
    let bst = backend.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);

    let passed = rx_unique.len() as u64 == total
        && bst.unique_seqs == total
        && bst.dup_seqs == 0
        && rx_client_dups == 0
        && snap.reordered_pkts >= 20
        && snap.duplicated_pkts >= 20;

    ScenarioResult {
        id: 4,
        code: "reorder_replay",
        name: "ECMP Reorder & Replay Guard",
        condition: "35% reorder + 30% dup",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "unique {}/{} | ooo={} | dup_inj={} -> leaked=0",
            rx_unique.len(),
            total,
            rx_out_of_order,
            snap.duplicated_pkts
        ),
        detail: format!(
            "backend_dup={} client_dup={} proxy_reordered={}",
            bst.dup_seqs, rx_client_dups, snap.reordered_pkts
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

pub(super) fn test_05_mtu_guard(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-05-mtu-guard-psk".to_vec();
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
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    let app = connect_app(client.port, 400);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 5,
            code: "mtu_guard",
            name: "PPPoE MTU 1488 Anti-Frag",
            condition: "1200..1452B probes",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let max_wire_allowed = opts.wan_mtu.saturating_sub(IPV4_UDP_HDR_LEN);
    // Exact max inner payload = max_wire_allowed - 38 (20B RTP+BEDE + 2B len + 16B tag)
    let exact_edge = max_wire_allowed.saturating_sub(SRTP_DATA_MIN_WIRE_LEN);
    let oversize = exact_edge + 30; // e.g., 1452B when WAN MTU = 1488

    let probe = |len: usize| -> bool {
        let mut p = vec![0u8; len];
        p[..4].copy_from_slice(b"MTU:");
        fill_random(&mut p[4..]);
        let mut rb = vec![0u8; DTLS_IO_BUF_LEN];
        app.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let _ = app.send(&p);
        match app.recv(&mut rb) {
            Ok(n) => n == len && rb[..16] == p[..16],
            Err(_) => false,
        }
    };

    let ok_1200 = probe(1200);
    let ok_1400 = probe(1400.min(exact_edge));
    let ok_edge = probe(exact_edge);
    let ok_over = probe(oversize); // MUST be false (silently dropped to prevent IPv4 fragmentation)
    let ok_after = probe(256); // Tunnel MUST stay healthy after oversized drop

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);

    let passed = ok_1200
        && ok_1400
        && ok_edge
        && !ok_over
        && ok_after
        && snap.max_wire_udp <= max_wire_allowed;

    ScenarioResult {
        id: 5,
        code: "mtu_guard",
        name: "PPPoE MTU 1488 Anti-Frag",
        condition: "1200..1452B probes",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "{}B PASS | {}B DROP | max_wire={}B/{}B",
            exact_edge, oversize, snap.max_wire_udp, max_wire_allowed
        ),
        detail: format!(
            "1200={} 1400={} edge({})={} over({})={} post_health={}",
            ok_1200, ok_1400, exact_edge, ok_edge, oversize, ok_over, ok_after
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

pub(super) fn test_06_single_stun_drop(
    opts: &SelftestOptions,
    hi: &mut Highlights,
) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-06-single-ka-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(
        server_port,
        backend.port,
        psk.clone(),
        opts.cipher_pref,
        opts.wan_mtu,
    );
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), true);
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 1, 200);

    let app = connect_app(client.port, 250);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 6,
            code: "single_ka_drop",
            name: "Single STUN Drop Immunity",
            condition: "Drop 1 KA STUN",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let port1 = proxy.first_port.load(Ordering::SeqCst);
    let mut rbuf = [0u8; CTRL_FRAME_BUF_LEN];
    let wait_t0 = Instant::now();
    let mut ping_ok = 0u64;
    while wait_t0.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"KEEP_DATA_ALIVE");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"KEEP_DATA_ALIVE" {
                ping_ok += 1;
            }
        }
        if proxy.snapshot().same_txid_ka_retransmits >= 1 {
            break;
        }
        thread::sleep(Duration::from_millis(80));
    }

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);
    let latest = proxy.latest_port.load(Ordering::SeqCst);
    let passed = snap.same_txid_ka_retransmits == 1
        && snap.ports_seen.len() == 1
        && latest == port1
        && ping_ok >= 3;

    ScenarioResult {
        id: 6,
        code: "single_ka_drop",
        name: "Single STUN Drop Immunity",
        condition: "Drop 1 KA STUN",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "same_txid_retry={} | ports={} (no rotate)",
            snap.same_txid_ka_retransmits,
            snap.ports_seen.len()
        ),
        detail: format!(
            "port={} pings_ok={} dropped={}",
            port1, ping_ok, snap.dropped_by_proxy
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}
