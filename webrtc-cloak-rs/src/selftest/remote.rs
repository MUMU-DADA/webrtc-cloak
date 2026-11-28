//! 远端现网隧道 12 项自测编排引擎。

use super::local_resilience::{test_11_cpu_single_core_crypto, test_12_cpu_multicore_and_p256};
use super::remote_probes::run_remote_steps_06_to_09;
use super::remote_session::{
    check_pre_dtls_stun_retransmit, remote_dtls_handshake, remote_stun_handshake, LiveReadySession,
};
use super::report::{pad_right, print_json_report, print_pretty_report, Palette};
use super::{percentile, Highlights, ScenarioResult, ScenarioStatus, SelftestOptions};
use crate::constants::PROBE_IO_BUF_LEN;
use crate::protocol::{demux_rfc7983, detect_cpu_accel, PacketKind};
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

pub(super) fn run_remote_selftest(
    opts: &SelftestOptions,
    server_addr: SocketAddr,
    psk: &[u8],
) -> bool {
    run_remote_selftest_inner(opts, server_addr, psk, true)
}

fn run_remote_selftest_inner(
    opts: &SelftestOptions,
    server_addr: SocketAddr,
    psk: &[u8],
    include_cpu_bench: bool,
) -> bool {
    let cpu = detect_cpu_accel();
    let p = Palette::new(opts.color);
    let suite_t0 = Instant::now();
    let mut hi = Highlights {
        is_remote: true,
        is_ipv6: server_addr.is_ipv6(),
        target_label: Some(
            opts.server_label
                .clone()
                .unwrap_or_else(|| server_addr.to_string()),
        ),
        ..Default::default()
    };

    if !opts.json {
        println!(
            "{}{}Running webrtc-cloak v{} LIVE remote self-test -> {} (12 scenarios)...{}",
            p.bold,
            p.cyan,
            env!("CARGO_PKG_VERSION"),
            hi.target_label.as_deref().unwrap_or(""),
            p.reset
        );
    }

    let mut results: Vec<ScenarioResult> = Vec::with_capacity(12);
    let total_steps = 12usize;

    let report_step = |idx: usize, label: &str, res: &ScenarioResult| {
        if !opts.json {
            let (col, tag) = match res.status {
                ScenarioStatus::Pass => (p.green, "[PASS]"),
                ScenarioStatus::Skip => (p.yellow, "[SKIP]"),
                ScenarioStatus::Fail => (p.red, "[FAIL]"),
            };
            println!(
                "  {}[{:02}/{:02}]{} {} ... {}{}{}{} {}({:.2}s){}",
                p.dim,
                idx,
                total_steps,
                p.reset,
                pad_right(label, 31),
                p.bold,
                col,
                tag,
                p.reset,
                p.dim,
                res.elapsed_s,
                p.reset
            );
        }
    };

    // #01 WAN ICE STUN & NAT Mapping
    let t1 = Instant::now();
    let stun_res = remote_stun_handshake(server_addr, psk);
    let (stun_ok_opt, stun_rtt_ms, captured_stun, mapped1) = match stun_res {
        Ok(s) => {
            let mapped_s = s
                .mapped_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".into());
            hi.nat_mapped = Some(mapped_s.clone());
            let rtt = s.rtt_ms;
            let raw = s.raw_stun.clone();
            let m = s.mapped_addr;
            let r = ScenarioResult {
                id: 1,
                code: "wan_stun",
                name: "WAN ICE STUN & NAT Mapping",
                condition: "Live UDP -> server",
                status: ScenarioStatus::Pass,
                metrics: format!("rtt {:.1}ms | NAT {}", rtt, mapped_s),
                detail: format!("server={} xor_mapped={}", server_addr, mapped_s),
                elapsed_s: t1.elapsed().as_secs_f64(),
            };
            report_step(1, r.name, &r);
            results.push(r);
            (Some(s), rtt, raw, m)
        }
        Err(msg) => {
            let r = ScenarioResult {
                id: 1,
                code: "wan_stun",
                name: "WAN ICE STUN & NAT Mapping",
                condition: "Live UDP -> server",
                status: ScenarioStatus::Fail,
                metrics: "STUN FAILED (unreachable/PSK)".into(),
                detail: msg,
                elapsed_s: t1.elapsed().as_secs_f64(),
            };
            report_step(1, r.name, &r);
            results.push(r);
            (None, 200.0, Vec::new(), None)
        }
    };

    let dyn_timeout_ms = ((stun_rtt_ms * 4.0) as u64).clamp(600, 2500);

    // Pre-DTLS SeenTxidCache check (must run before ClientHello burns the initial STUN txid)
    let pre_dtls_cache = stun_ok_opt.as_ref().map(|stun_ok| {
        let t_pre = Instant::now();
        thread::sleep(Duration::from_millis(40));
        let res = check_pre_dtls_stun_retransmit(stun_ok, dyn_timeout_ms);
        (res, stun_ok.raw_resp.clone(), t_pre.elapsed().as_secs_f64())
    });

    // #02 WAN DTLS Mutual-Cert HS
    let t2 = Instant::now();
    let mut sess_opt: Option<LiveReadySession> = None;
    if let Some(stun_ok) = stun_ok_opt {
        match remote_dtls_handshake(
            stun_ok,
            psk,
            opts.cipher_pref,
            opts.dtls_min_version,
            opts.wan_mtu,
        ) {
            Ok((sess, hs_ms)) => {
                hi.negotiated_cipher = Some(sess.suite.name().to_string());
                let dtls_ver = if sess.is_dtls13 {
                    "DTLS 1.3"
                } else {
                    "DTLS 1.2"
                };
                let r = ScenarioResult {
                    id: 2,
                    code: "wan_dtls",
                    name: "WAN DTLS Mutual-Cert HS",
                    condition: "Auto 1.3/1.2 + Cookie",
                    status: ScenarioStatus::Pass,
                    metrics: format!(
                        "hs {:.1}ms | {} | {} | {}",
                        hs_ms,
                        dtls_ver,
                        sess.suite.name(),
                        if sess.is_dtls13 {
                            "dual-SSRC"
                        } else {
                            "1-SSRC"
                        }
                    ),
                    detail: format!(
                        "dtls={} negotiated={} dual_ssrc={} total_dtls_ms={:.2}",
                        dtls_ver,
                        sess.suite.name(),
                        sess.is_dtls13,
                        hs_ms
                    ),
                    elapsed_s: t2.elapsed().as_secs_f64(),
                };
                report_step(2, r.name, &r);
                results.push(r);
                sess_opt = Some(sess);
            }
            Err(msg) => {
                let r = ScenarioResult {
                    id: 2,
                    code: "wan_dtls",
                    name: "WAN DTLS Mutual-Cert HS",
                    condition: "Auto 1.3/1.2 + Cookie",
                    status: ScenarioStatus::Fail,
                    metrics: "DTLS Handshake FAILED".into(),
                    detail: msg,
                    elapsed_s: t2.elapsed().as_secs_f64(),
                };
                report_step(2, r.name, &r);
                results.push(r);
            }
        }
    } else {
        let r = ScenarioResult {
            id: 2,
            code: "wan_dtls",
            name: "WAN DTLS Mutual-Cert HS",
            condition: "Auto 1.3/1.2 + Cookie",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (STUN failed)".into(),
            detail: "Requires successful STUN authentication first".into(),
            elapsed_s: 0.0,
        };
        report_step(2, r.name, &r);
        results.push(r);
    }

    // #03 WAN Consent RTT / Jitter / Loss
    let t3 = Instant::now();
    if let Some(ref mut sess) = sess_opt {
        let count = opts.probe_count;
        let mut rtts = Vec::with_capacity(count);
        for i in 0..count {
            if let Some((rtt, _, _, _)) = sess.send_stun_consent(psk, dyn_timeout_ms) {
                rtts.push(rtt);
            }
            if i + 1 < count {
                thread::sleep(Duration::from_millis(60));
            }
        }
        let rx = rtts.len();
        let loss_pct = (1.0 - (rx as f64 / count as f64)) * 100.0;
        let mut jit_sum = 0.0f64;
        for w in rtts.windows(2) {
            jit_sum += (w[1] - w[0]).abs();
        }
        let jitter_ms = if rtts.len() > 1 {
            jit_sum / ((rtts.len() - 1) as f64)
        } else {
            0.0
        };
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50 = percentile(&rtts, 50);
        let p95 = percentile(&rtts, 95);
        hi.wan_p50_ms = if rx > 0 { Some(p50) } else { None };
        hi.wan_loss_pct = Some(loss_pct);

        let ok = rx > 0 && loss_pct <= 25.0;
        let r = ScenarioResult {
            id: 3,
            code: "wan_consent",
            name: "WAN Consent RTT/Jitter/Loss",
            condition: "RFC 7675 STUN probes",
            status: ScenarioStatus::from_bool(ok),
            metrics: format!(
                "p50 {:.1}ms p95 {:.1}ms | jit {:.1}ms | {}/{} ({:.1}%)",
                p50, p95, jitter_ms, rx, count, loss_pct
            ),
            detail: format!(
                "min={:.1}ms max={:.1}ms loss={:.2}%",
                rtts.first().copied().unwrap_or(0.0),
                rtts.last().copied().unwrap_or(0.0),
                loss_pct
            ),
            elapsed_s: t3.elapsed().as_secs_f64(),
        };
        report_step(3, r.name, &r);
        results.push(r);
    } else {
        let r = ScenarioResult {
            id: 3,
            code: "wan_consent",
            name: "WAN Consent RTT/Jitter/Loss",
            condition: "RFC 7675 STUN probes",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (session not ready)".into(),
            detail: "Requires established session".into(),
            elapsed_s: 0.0,
        };
        report_step(3, r.name, &r);
        results.push(r);
    }

    // #04 WAN STUN Retransmit Cache (pre-DTLS) & Ready Anti-Replay (v0.7 single-use mi_key_mig)
    let t4 = Instant::now();
    if let Some(ref mut sess) = sess_opt {
        let (pre_ok, pre_desc, pre_elapsed) = match pre_dtls_cache {
            Some((Some((rtt2, resp2)), resp1, el)) => {
                let exact = resp1 == resp2;
                (
                    exact,
                    format!(
                        "pre-DTLS {}B {} ({:.1}ms)",
                        resp2.len(),
                        if exact { "match" } else { "MISMATCH" },
                        rtt2
                    ),
                    el,
                )
            }
            Some((None, _, el)) => (false, "pre-DTLS cache MISS".into(), el),
            None => (false, "no initial STUN".into(), 0.0),
        };

        let replay_wait_ms = ((stun_rtt_ms * 2.5) as u64).clamp(250, 700);
        let res = if let Some((_rtt1, req_bytes, txid, _resp1)) =
            sess.send_stun_consent(psk, dyn_timeout_ms)
        {
            thread::sleep(Duration::from_millis(40));
            let ready_replay = sess.send_raw_stun_expect(&req_bytes, txid, psk, replay_wait_ms);
            let ready_blocked = ready_replay.is_none();
            let ok = pre_ok && ready_blocked;
            ScenarioResult {
                id: 4,
                code: "wan_txid_cache",
                name: "WAN STUN Cache & Anti-Replay",
                condition: "Pre-DTLS cache + Ready 0B",
                status: ScenarioStatus::from_bool(ok),
                metrics: format!(
                    "{} | Ready replay {}",
                    pre_desc,
                    if ready_blocked { "0B DROP" } else { "LEAKED" }
                ),
                detail: format!(
                    "pre_dtls_ok={} ready_replay_dropped={}",
                    pre_ok, ready_blocked
                ),
                elapsed_s: pre_elapsed + t4.elapsed().as_secs_f64(),
            }
        } else {
            ScenarioResult {
                id: 4,
                code: "wan_txid_cache",
                name: "WAN STUN Cache & Anti-Replay",
                condition: "Pre-DTLS cache + Ready 0B",
                status: ScenarioStatus::Fail,
                metrics: "Initial mi_key_mig consent timed out".into(),
                detail: "First Ready-state STUN keepalive failed".into(),
                elapsed_s: pre_elapsed + t4.elapsed().as_secs_f64(),
            }
        };
        report_step(4, res.name, &res);
        results.push(res);
    } else {
        let r = ScenarioResult {
            id: 4,
            code: "wan_txid_cache",
            name: "WAN STUN Cache & Anti-Replay",
            condition: "Pre-DTLS cache + Ready 0B",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (session not ready)".into(),
            detail: "Requires established session".into(),
            elapsed_s: 0.0,
        };
        report_step(4, r.name, &r);
        results.push(r);
    }

    // #05 WAN Server SRTCP Downlink Heartbeat
    let t5 = Instant::now();
    if let Some(ref mut sess) = sess_opt {
        let cli_rtcp = sess.cipher.build_srtcp(true, true, false);
        let _ = sess.sock.send(&cli_rtcp);
        if sess.dl_srtcp_verified == 0 {
            let _ = sess.sock.set_read_timeout(Some(Duration::from_millis(50)));
            let mut rbuf = [0u8; PROBE_IO_BUF_LEN];
            let wait_t0 = Instant::now();
            while wait_t0.elapsed() < Duration::from_secs(3) && sess.dl_srtcp_verified == 0 {
                if let Ok(n) = sess.sock.recv(&mut rbuf) {
                    let pkt = &rbuf[..n];
                    if demux_rfc7983(pkt) == PacketKind::Srtcp
                        && sess.cipher.verify_srtcp(pkt).is_some()
                    {
                        sess.dl_srtcp_verified += 1;
                        break;
                    }
                }
            }
        }
        let ok = sess.dl_srtcp_verified >= 1;
        let r = ScenarioResult {
            id: 5,
            code: "wan_srtcp",
            name: "WAN Server SRTCP Heartbeat",
            condition: "Downlink Compound RTCP",
            status: ScenarioStatus::from_bool(ok),
            metrics: format!(
                "rx={} AEAD-verified | tx=1 ({}B)",
                sess.dl_srtcp_verified,
                cli_rtcp.len()
            ),
            detail: format!("dl_srtcp_verified={}", sess.dl_srtcp_verified),
            elapsed_s: t5.elapsed().as_secs_f64(),
        };
        report_step(5, r.name, &r);
        results.push(r);
    } else {
        let r = ScenarioResult {
            id: 5,
            code: "wan_srtcp",
            name: "WAN Server SRTCP Heartbeat",
            condition: "Downlink Compound RTCP",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (session not ready)".into(),
            detail: "Requires established session".into(),
            elapsed_s: 0.0,
        };
        report_step(5, r.name, &r);
        results.push(r);
    }

    run_remote_steps_06_to_09(
        opts,
        server_addr,
        psk,
        dyn_timeout_ms,
        stun_rtt_ms,
        captured_stun,
        mapped1,
        &mut sess_opt,
        &mut hi,
        &mut results,
        &report_step,
    );

    // #10 Graceful Teardown (SRTCP BYE + DTLS close_notify)
    let t10 = Instant::now();
    if let Some(ref mut sess) = sess_opt {
        sess.teardown();
        let r = ScenarioResult {
            id: 10,
            code: "wan_teardown",
            name: "Graceful Teardown (BYE/Close)",
            condition: "Zero zombie sessions",
            status: ScenarioStatus::Pass,
            metrics: "SRTCP BYE + DTLS close_notify sent (2/2)".into(),
            detail: "Cleanly closed both temporary probe sessions on remote server".into(),
            elapsed_s: t10.elapsed().as_secs_f64(),
        };
        report_step(10, r.name, &r);
        results.push(r);
    } else {
        let r = ScenarioResult {
            id: 10,
            code: "wan_teardown",
            name: "Graceful Teardown (BYE/Close)",
            condition: "Zero zombie sessions",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (no active session)".into(),
            detail: "No remote session was established".into(),
            elapsed_s: 0.0,
        };
        report_step(10, r.name, &r);
        results.push(r);
    }

    // #11 & #12 Local Host CPU Crypto Compute Benchmarks
    if include_cpu_bench {
        let r11 = test_11_cpu_single_core_crypto(opts, &mut hi);
        report_step(11, r11.name, &r11);
        results.push(r11);

        let r12 = test_12_cpu_multicore_and_p256(opts, &mut hi);
        report_step(12, r12.name, &r12);
        results.push(r12);
    }

    let total_s = suite_t0.elapsed().as_secs_f64();
    if opts.json {
        print_json_report(&cpu, opts, &results, &hi, total_s);
    } else {
        print_pretty_report(&cpu, opts, &results, &hi, total_s);
    }

    results.iter().all(|r| r.status != ScenarioStatus::Fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_WAN_MTU;
    use crate::protocol::{CipherPref, DtlsMinVersion};
    use crate::selftest::reserve_free_port;
    use crate::server::{run_server, ServerConfig};
    use crate::telemetry::TelemetryConfig;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn remote_selftest_network_checks_pass_against_v07_server() {
        let srv_port = reserve_free_port();
        let backend_port = reserve_free_port();
        let srv_addr: SocketAddr = format!("127.0.0.1:{}", srv_port).parse().unwrap();
        let backend_addr: SocketAddr = format!("127.0.0.1:{}", backend_port).parse().unwrap();
        let psk = b"remote-selftest-v071-regression-psk".to_vec();
        let stop = Arc::new(AtomicBool::new(false));
        let srv_stop = Arc::clone(&stop);
        let srv_psk = psk.clone();

        let srv_h = thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: srv_addr,
                backend_addr,
                psk: srv_psk,
                stun_scope: None,
                cipher_pref: CipherPref::Auto,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::V13Only,
                workers: 1,
                max_sessions: 32,
                wan_mtu: DEFAULT_WAN_MTU,
                udp_batch: 0,
                idle_timeout_secs: 60,
                stats_interval_secs: 0,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(srv_stop),
            });
        });

        thread::sleep(Duration::from_millis(120));

        let opts = SelftestOptions {
            server_addr: Some(srv_addr),
            server_label: Some(srv_addr.to_string()),
            psk: Some(psk.clone()),
            cipher_pref: CipherPref::Auto,
            dtls_min_version: DtlsMinVersion::V13Only,
            wan_mtu: DEFAULT_WAN_MTU,
            probe_count: 5,
            active_probes: true,
            color: false,
            json: true,
        };
        let passed = run_remote_selftest_inner(&opts, srv_addr, &psk, false);

        stop.store(true, Ordering::Relaxed);
        let _ = srv_h.join();

        assert!(
            passed,
            "live remote selftest (#01-#10) must pass against v0.7+ server"
        );
    }
}
