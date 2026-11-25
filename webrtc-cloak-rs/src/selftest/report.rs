//! 自测结果终端美化表格渲染与 JSON 报告输出。

use super::{Highlights, ScenarioResult, ScenarioStatus, SelftestOptions};
use crate::constants::IPV4_UDP_HDR_LEN;
use crate::protocol::CipherPref;

pub(super) struct Palette {
    pub(super) reset: &'static str,
    pub(super) bold: &'static str,
    pub(super) dim: &'static str,
    pub(super) cyan: &'static str,
    pub(super) green: &'static str,
    pub(super) red: &'static str,
    pub(super) yellow: &'static str,
    pub(super) white: &'static str,
}

impl Palette {
    pub(super) fn new(enabled: bool) -> Self {
        if enabled {
            Self {
                reset: "\x1b[0m",
                bold: "\x1b[1m",
                dim: "\x1b[2m",
                cyan: "\x1b[36m",
                green: "\x1b[32m",
                red: "\x1b[31m",
                yellow: "\x1b[33m",
                white: "\x1b[97m",
            }
        } else {
            Self {
                reset: "",
                bold: "",
                dim: "",
                cyan: "",
                green: "",
                red: "",
                yellow: "",
                white: "",
            }
        }
    }
}

pub(super) fn pad_right(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.chars().take(width).collect()
    } else {
        format!("{}{}", s, " ".repeat(width - len))
    }
}

fn pad_left(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.chars().take(width).collect()
    } else {
        format!("{}{}", " ".repeat(width - len), s)
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

pub(super) fn print_json_report(
    cpu: &crate::protocol::CpuAccelInfo,
    opts: &SelftestOptions,
    results: &[ScenarioResult],
    hi: &Highlights,
    total_s: f64,
) {
    let passed_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Pass).count();
    let skipped_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Skip).count();
    let failed_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Fail).count();
    println!("{{");
    println!("  \"version\": \"{}\",", env!("CARGO_PKG_VERSION"));
    println!("  \"mode\": \"{}\",", if hi.is_remote { "remote" } else { "local" });
    if let Some(ref tgt) = hi.target_label {
        println!("  \"target\": \"{}\",", json_escape(tgt));
    }
    println!("  \"arch\": \"{}\",", cpu.arch);
    println!("  \"hw_accel\": \"{}\",", cpu.features.join(", "));
    println!("  \"cipher_pref\": \"{:?}\",", opts.cipher_pref);
    println!("  \"recommended_cipher\": \"{}\",", cpu.recommended.name());
    println!("  \"wan_mtu\": {},", opts.wan_mtu);
    println!("  \"passed\": {},", passed_cnt);
    println!("  \"skipped\": {},", skipped_cnt);
    println!("  \"failed\": {},", failed_cnt);
    println!("  \"total\": {},", results.len());
    println!("  \"all_passed\": {},", failed_cnt == 0);
    println!("  \"total_elapsed_s\": {:.3},", total_s);
    println!("  \"highlights\": {{");
    println!(
        "    \"nat_mapped\": {},",
        hi.nat_mapped
            .as_ref()
            .map(|v| format!("\"{}\"", json_escape(v)))
            .unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"negotiated_cipher\": {},",
        hi.negotiated_cipher
            .as_ref()
            .map(|v| format!("\"{}\"", json_escape(v)))
            .unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"wan_p50_ms\": {},",
        hi.wan_p50_ms.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"wan_loss_pct\": {},",
        hi.wan_loss_pct.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"wan_mtu_verified\": {},",
        hi.wan_mtu_pass.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"wire_overhead_1200b_pct\": {},",
        hi.overhead_pct.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!("    \"max_wire_udp_bytes\": {},", hi.max_wire_udp);
    println!(
        "    \"blackhole_recovery_s\": {},",
        hi.blackhole_recover_s.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"server_restart_recovery_s\": {},",
        hi.restart_recover_s.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!("    \"active_probes_blocked\": {},", hi.probes_blocked);
    println!("    \"active_probes_total\": {},", hi.probes_total);
    println!(
        "    \"loopback_goodput_mbps\": {},",
        hi.goodput_mbps.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!("    \"cpu_cores\": {},", hi.cpu_cores);
    println!(
        "    \"cpu_1c_aes128_gcm_mbps\": {},",
        hi.cpu_aes_mbps.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"cpu_1c_chacha20_mbps\": {},",
        hi.cpu_chacha_mbps.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"cpu_1c_blake2b_mbps\": {},",
        hi.cpu_blake2b_mbps.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"cpu_multicore_gbps\": {},",
        hi.cpu_multicore_gbps.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"cpu_p256_certs_per_s\": {}",
        hi.cpu_p256_certs_per_s.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!("  }},");
    println!("  \"scenarios\": [");
    for (idx, r) in results.iter().enumerate() {
        let comma = if idx + 1 < results.len() { "," } else { "" };
        println!(
            "    {{\"id\": {}, \"code\": \"{}\", \"name\": \"{}\", \"condition\": \"{}\", \"status\": \"{}\", \"passed\": {}, \"elapsed_s\": {:.3}, \"metrics\": \"{}\", \"detail\": \"{}\"}}{}",
            r.id,
            json_escape(r.code),
            json_escape(r.name),
            json_escape(r.condition),
            r.status.as_str(),
            r.status == ScenarioStatus::Pass,
            r.elapsed_s,
            json_escape(&r.metrics),
            json_escape(&r.detail),
            comma
        );
    }
    println!("  ]");
    println!("}}");
}

pub(super) fn print_pretty_report(
    cpu: &crate::protocol::CpuAccelInfo,
    opts: &SelftestOptions,
    results: &[ScenarioResult],
    hi: &Highlights,
    total_s: f64,
) {
    let p = Palette::new(opts.color);
    let passed_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Pass).count();
    let skipped_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Skip).count();
    let failed_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Fail).count();
    let total_cnt = results.len();
    let all_ok = failed_cnt == 0;

    // Column inner widths (pure ASCII contents -> exact 1:1 terminal cell alignment!)
    let w_id = 4;
    let w_name = 29;
    let w_cond = 23;
    let w_stat = 6;
    let w_met = results
        .iter()
        .map(|r| r.metrics.chars().count())
        .max()
        .unwrap_or(50)
        .max(54);
    let w_time = 6;
    let inner_total = (w_id + 2)
        + 1
        + (w_name + 2)
        + 1
        + (w_cond + 2)
        + 1
        + (w_stat + 2)
        + 1
        + (w_met + 2)
        + 1
        + (w_time + 2);

    let cipher_label = if let Some(ref neg) = hi.negotiated_cipher {
        format!("{} (negotiated)", neg)
    } else {
        match opts.cipher_pref {
            CipherPref::Auto => format!("auto -> {}", cpu.recommended.name()),
            CipherPref::Fixed(s) => s.name().to_string(),
        }
    };
    let accel_label = if cpu.features.is_empty() {
        "scalar".to_string()
    } else {
        cpu.features.join(", ")
    };

    let title = if hi.is_remote {
        format!(
            "webrtc-cloak v{}  |  LIVE Remote Tunnel Self-Test  ->  {}",
            env!("CARGO_PKG_VERSION"),
            hi.target_label.as_deref().unwrap_or("remote")
        )
    } else {
        format!(
            "webrtc-cloak v{}  |  Local Loopback Fault-Injection & CPU Self-Test Report",
            env!("CARGO_PKG_VERSION")
        )
    };
    let env_line = format!(
        "CPU: {} [{}]  |  Cipher: {}  |  MTU: {}B",
        cpu.arch, accel_label, cipher_label, opts.wan_mtu
    );
    let cond_col_hdr = if hi.is_remote {
        "Probe Scope"
    } else {
        "Simulated Condition"
    };

    println!();
    println!("{}╭{}╮{}", p.cyan, "─".repeat(inner_total), p.reset);
    println!(
        "{}│{} {}{}{} {}│{}",
        p.cyan,
        p.reset,
        p.bold,
        pad_right(&title, inner_total - 2),
        p.reset,
        p.cyan,
        p.reset
    );
    println!(
        "{}│{} {}{}{} {}│{}",
        p.cyan,
        p.reset,
        p.dim,
        pad_right(&env_line, inner_total - 2),
        p.reset,
        p.cyan,
        p.reset
    );

    println!(
        "{}├{}┬{}┬{}┬{}┬{}┬{}┤{}",
        p.cyan,
        "─".repeat(w_id + 2),
        "─".repeat(w_name + 2),
        "─".repeat(w_cond + 2),
        "─".repeat(w_stat + 2),
        "─".repeat(w_met + 2),
        "─".repeat(w_time + 2),
        p.reset
    );
    println!(
        "{}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{}",
        p.cyan, p.reset, p.bold, pad_right("ID", w_id), p.reset,
        p.cyan, p.reset, p.bold, pad_right("Scenario", w_name), p.reset,
        p.cyan, p.reset, p.bold, pad_right(cond_col_hdr, w_cond), p.reset,
        p.cyan, p.reset, p.bold, pad_right("Status", w_stat), p.reset,
        p.cyan, p.reset, p.bold, pad_right("Key Measured Metrics", w_met), p.reset,
        p.cyan, p.reset, p.bold, pad_left("Time", w_time), p.reset,
        p.cyan, p.reset
    );
    println!(
        "{}├{}┼{}┼{}┼{}┼{}┼{}┤{}",
        p.cyan,
        "─".repeat(w_id + 2),
        "─".repeat(w_name + 2),
        "─".repeat(w_cond + 2),
        "─".repeat(w_stat + 2),
        "─".repeat(w_met + 2),
        "─".repeat(w_time + 2),
        p.reset
    );

    for r in results {
        let id_s = format!("#{:02}", r.id);
        let (st_col, st_txt) = match r.status {
            ScenarioStatus::Pass => (p.green, "[PASS]"),
            ScenarioStatus::Skip => (p.yellow, "[SKIP]"),
            ScenarioStatus::Fail => (p.red, "[FAIL]"),
        };
        let time_s = format!("{:.2}s", r.elapsed_s);
        println!(
            "{}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{}{} {}│{} {} {}│{} {}{}{} {}│{}",
            p.cyan, p.reset, p.dim, pad_right(&id_s, w_id), p.reset,
            p.cyan, p.reset, p.white, pad_right(r.name, w_name), p.reset,
            p.cyan, p.reset, p.dim, pad_right(r.condition, w_cond), p.reset,
            p.cyan, p.reset, p.bold, st_col, pad_right(st_txt, w_stat), p.reset,
            p.cyan, p.reset, pad_right(&r.metrics, w_met),
            p.cyan, p.reset, p.dim, pad_left(&time_s, w_time), p.reset,
            p.cyan, p.reset
        );
    }

    println!(
        "{}├{}┴{}┴{}┴{}┴{}┴{}┤{}",
        p.cyan,
        "─".repeat(w_id + 2),
        "─".repeat(w_name + 2),
        "─".repeat(w_cond + 2),
        "─".repeat(w_stat + 2),
        "─".repeat(w_met + 2),
        "─".repeat(w_time + 2),
        p.reset
    );

    let cpu_1c_str = match (hi.cpu_aes_mbps, hi.cpu_chacha_mbps, hi.cpu_blake2b_mbps) {
        (Some(a), Some(c), Some(b)) => format!("AES {:.0} / ChaCha {:.0} / B2B {:.0} Mbps", a, c, b),
        _ => "N/A".into(),
    };
    let cpu_mc_str = hi
        .cpu_multicore_gbps
        .map(|g| format!("{:.2} Gbps ({}C)", g, hi.cpu_cores))
        .unwrap_or_else(|| "N/A".into());
    let p256_str = hi
        .cpu_p256_certs_per_s
        .map(|v| format!("{:.0}/s", v))
        .unwrap_or_else(|| "N/A".into());

    let (summary_1, summary_2) = if hi.is_remote {
        let nat_s = hi.nat_mapped.as_deref().unwrap_or("N/A");
        let rtt_s = hi
            .wan_p50_ms
            .map(|v| format!("{:.1}ms", v))
            .unwrap_or_else(|| "N/A".into());
        let loss_s = hi
            .wan_loss_pct
            .map(|v| format!("{:.1}%", v))
            .unwrap_or_else(|| "N/A".into());
        let mtu_s = hi
            .wan_mtu_pass
            .map(|v| format!("IPv4 {}B verified", v))
            .unwrap_or_else(|| "N/A (server < v0.3.5)".into());
        let ov_s = match (hi.overhead_bytes, hi.overhead_pct) {
            (Some(b), Some(pct)) => format!("+{:.1}B (+{:.2}%)", b, pct),
            _ => "N/A".into(),
        };
        (
            format!(
                "Live WAN: NAT {}  |  P50 RTT {}  |  Loss {}  |  Path MTU: {}",
                nat_s, rtt_s, loss_s, mtu_s
            ),
            format!(
                "SRTP Overhead (1200B): {}  |  Silent-Drop Security: {}/{} blocked (0B leaked)",
                ov_s, hi.probes_blocked, hi.probes_total
            ),
        )
    } else {
        let ov_str = match (hi.overhead_bytes, hi.overhead_pct) {
            (Some(b), Some(pct)) => format!("+{:.1}B (+{:.2}%)", b, pct),
            _ => "N/A".into(),
        };
        let bh_str = hi
            .blackhole_recover_s
            .map(|v| format!("{:.2}s", v))
            .unwrap_or_else(|| "N/A".into());
        let rs_str = hi
            .restart_recover_s
            .map(|v| format!("{:.2}s", v))
            .unwrap_or_else(|| "N/A".into());
        let gp_str = match (hi.goodput_mbps, hi.goodput_kpps) {
            (Some(m), Some(k)) => format!("{:.0} Mbps ({:.1} kpps)", m, k),
            _ => "N/A".into(),
        };
        (
            format!(
                "Wire Overhead (1200B): {}  |  Max Wire UDP: {}B / {}B  |  Loopback Goodput: {}",
                ov_str,
                hi.max_wire_udp,
                opts.wan_mtu.saturating_sub(IPV4_UDP_HDR_LEN),
                gp_str
            ),
            format!(
                "Self-Heal: Blackhole {} / Restart {}  |  Silent-Drop Security: {}/{} blocked (0B leaked)",
                bh_str, rs_str, hi.probes_blocked, hi.probes_total
            ),
        )
    };
    let summary_3 = format!(
        "CPU Compute (1200B): 1C [{}]  |  All-Core: {}  |  P-256 Cert: {}",
        cpu_1c_str, cpu_mc_str, p256_str
    );

    for line in [&summary_1, &summary_2, &summary_3] {
        println!(
            "{}│{} {} {}│{}",
            p.cyan,
            p.reset,
            pad_right(line, inner_total - 2),
            p.cyan,
            p.reset
        );
    }
    println!("{}├{}┤{}", p.cyan, "─".repeat(inner_total), p.reset);

    let verdict_col = if all_ok { p.green } else { p.red };
    let footer_left = if !all_ok {
        format!(
            "VERDICT: CHECKS FAILED ({} passed, {} failed, {} skipped)",
            passed_cnt, failed_cnt, skipped_cnt
        )
    } else if skipped_cnt > 0 {
        format!(
            "VERDICT: ALL RUN CHECKS PASSED ({}/{} passed, {} skipped)",
            passed_cnt,
            total_cnt - skipped_cnt,
            skipped_cnt
        )
    } else {
        format!(
            "VERDICT: ALL CHECKS PASSED ({}/{} passed)",
            passed_cnt, total_cnt
        )
    };
    let footer_right = format!("Total Elapsed: {:.2}s", total_s);
    let gap = (inner_total - 2).saturating_sub(footer_left.len() + footer_right.len());

    println!(
        "{}│{} {}{}{}{}{}{}{}{} {}│{}",
        p.cyan,
        p.reset,
        p.bold,
        verdict_col,
        footer_left,
        p.reset,
        " ".repeat(gap),
        p.yellow,
        footer_right,
        p.reset,
        p.cyan,
        p.reset
    );
    println!("{}╰{}╯{}", p.cyan, "─".repeat(inner_total), p.reset);

    let failures: Vec<&ScenarioResult> = results
        .iter()
        .filter(|r| r.status == ScenarioStatus::Fail)
        .collect();
    if !failures.is_empty() {
        println!();
        println!("{}{}Failure Diagnostics:{}", p.bold, p.red, p.reset);
        for f in failures {
            println!("  #{:02} {} -> {}", f.id, f.name, f.detail);
        }
    }
    if !hi.is_remote {
        println!(
            "{}Tip: test a live remote tunnel with: webrtc-cloak selftest --server-host <IP> --server-port 19643 --psk-file <PATH>{}",
            p.dim, p.reset
        );
    }
    println!();
}
