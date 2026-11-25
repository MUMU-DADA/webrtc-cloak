//! 自测配置、结果汇总结构与本地/远端自测主入口。

mod harness;
mod local_net;
mod local_resilience;
mod remote;
mod remote_probes;
mod remote_session;
mod report;

use self::local_net::{
    test_01_baseline, test_02_transpacific_latency, test_03_random_loss,
    test_04_reorder_and_replay, test_05_mtu_guard, test_06_single_stun_drop,
};
use self::local_resilience::{
    test_07_asymmetric_blackhole, test_08_server_restart, test_09_active_probing_defense,
    test_10_multistream_throughput, test_11_cpu_single_core_crypto,
    test_12_cpu_multicore_and_p256,
};
use self::remote::run_remote_selftest;
use self::report::{pad_right, print_json_report, print_pretty_report, Palette};
use crate::constants::DEFAULT_WAN_MTU;
use crate::protocol::{detect_cpu_accel, CipherPref, DtlsMinVersion};
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

/// `selftest` 远端 STUN 探测默认发包数。
const DEFAULT_SELFTEST_PROBE_COUNT: usize = 20;
/// 自测辅助套接字收发内核缓冲大小（4 MiB）。
const SOCK_BUF_4MIB: usize = 4 * 1024 * 1024;
/// XorShift64 传入零种子时的非零兜底初始态。
const XORSHIFT64_FALLBACK_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

pub struct SelftestOptions {
    pub server_addr: Option<SocketAddr>,
    pub server_label: Option<String>,
    pub psk: Option<Vec<u8>>,
    pub cipher_pref: CipherPref,
    pub dtls_min_version: DtlsMinVersion,
    pub wan_mtu: usize,
    pub probe_count: usize,
    pub active_probes: bool,
    pub color: bool,
    pub json: bool,
}

impl Default for SelftestOptions {
    fn default() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Self {
            server_addr: None,
            server_label: None,
            psk: None,
            cipher_pref: CipherPref::Auto,
            dtls_min_version: DtlsMinVersion::Auto,
            wan_mtu: DEFAULT_WAN_MTU,
            probe_count: DEFAULT_SELFTEST_PROBE_COUNT,
            active_probes: true,
            color: !no_color,
            json: false,
        }
    }
}

pub(super) struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub(super) fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                XORSHIFT64_FALLBACK_SEED
            } else {
                seed
            },
        }
    }

    pub(super) fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub(super) fn chance_pct(&mut self, pct: u32) -> bool {
        if pct == 0 {
            return false;
        }
        if pct >= 100 {
            return true;
        }
        (self.next_u64() % 10_000) < (pct as u64 * 100)
    }

    pub(super) fn range_u64(&mut self, min_inclusive: u64, max_inclusive: u64) -> u64 {
        if max_inclusive <= min_inclusive {
            return min_inclusive;
        }
        min_inclusive + (self.next_u64() % (max_inclusive - min_inclusive + 1))
    }
}

pub(super) fn reserve_free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral port");
    s.local_addr().unwrap().port()
}

pub(super) fn tune_socket(sock: &UdpSocket) {
    let s2 = socket2::SockRef::from(sock);
    let _ = s2.set_recv_buffer_size(SOCK_BUF_4MIB);
    let _ = s2.set_send_buffer_size(SOCK_BUF_4MIB);
}

pub(super) fn percentile(sorted: &[f64], p: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len().saturating_sub(1)) * p) / 100;
    sorted[idx]
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ScenarioStatus {
    Pass,
    Skip,
    Fail,
}

impl ScenarioStatus {
    pub(super) fn from_bool(ok: bool) -> Self {
        if ok {
            Self::Pass
        } else {
            Self::Fail
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Skip => "skip",
            Self::Fail => "fail",
        }
    }
}

pub(super) struct ScenarioResult {
    pub(super) id: u8,
    pub(super) code: &'static str,
    pub(super) name: &'static str,
    pub(super) condition: &'static str,
    pub(super) status: ScenarioStatus,
    pub(super) metrics: String,
    pub(super) detail: String,
    pub(super) elapsed_s: f64,
}

#[derive(Default)]
pub(super) struct Highlights {
    pub(super) is_remote: bool,
    pub(super) target_label: Option<String>,
    pub(super) nat_mapped: Option<String>,
    pub(super) negotiated_cipher: Option<String>,
    pub(super) wan_p50_ms: Option<f64>,
    pub(super) wan_loss_pct: Option<f64>,
    pub(super) wan_mtu_pass: Option<usize>,
    pub(super) overhead_pct: Option<f64>,
    pub(super) overhead_bytes: Option<f64>,
    pub(super) max_wire_udp: usize,
    pub(super) blackhole_recover_s: Option<f64>,
    pub(super) restart_recover_s: Option<f64>,
    pub(super) probes_blocked: usize,
    pub(super) probes_total: usize,
    pub(super) goodput_mbps: Option<f64>,
    pub(super) goodput_kpps: Option<f64>,
    pub(super) cpu_cores: usize,
    pub(super) cpu_aes_mbps: Option<f64>,
    pub(super) cpu_chacha_mbps: Option<f64>,
    pub(super) cpu_blake2b_mbps: Option<f64>,
    pub(super) cpu_multicore_gbps: Option<f64>,
    pub(super) cpu_p256_certs_per_s: Option<f64>,
}

pub fn run_selftest(opts: SelftestOptions) -> bool {
    if let (Some(server_addr), Some(ref psk)) = (opts.server_addr, opts.psk.as_ref()) {
        return run_remote_selftest(&opts, server_addr, psk);
    }

    let cpu = detect_cpu_accel();
    let p = Palette::new(opts.color);
    let suite_t0 = Instant::now();
    let mut hi = Highlights::default();

    type TestFn = fn(&SelftestOptions, &mut Highlights) -> ScenarioResult;
    let tests: [(&str, TestFn); 12] = [
        ("Baseline & Wire Overhead", test_01_baseline),
        ("Trans-Pacific RTT & Jitter", test_02_transpacific_latency),
        ("Bidirectional Random Loss", test_03_random_loss),
        ("ECMP Reorder & Replay Guard", test_04_reorder_and_replay),
        ("PPPoE MTU 1488 Anti-Frag", test_05_mtu_guard),
        ("Single STUN Drop Immunity", test_06_single_stun_drop),
        ("Asymmetric Uplink Blackhole", test_07_asymmetric_blackhole),
        ("Server Restart Recovery", test_08_server_restart),
        ("Active Probe & Replay Defense", test_09_active_probing_defense),
        ("Multi-Stream & Loopback Speed", test_10_multistream_throughput),
        ("CPU Single-Core Crypto Bench", test_11_cpu_single_core_crypto),
        ("CPU Multi-Core & P-256 Certs", test_12_cpu_multicore_and_p256),
    ];

    if !opts.json {
        println!(
            "{}{}Running webrtc-cloak v{} local loopback self-test suite ({} scenarios)...{}",
            p.bold,
            p.cyan,
            env!("CARGO_PKG_VERSION"),
            tests.len(),
            p.reset
        );
    }

    let mut results = Vec::with_capacity(tests.len());
    for (idx, (label, func)) in tests.iter().enumerate() {
        if !opts.json {
            print!(
                "  {}[{:02}/{:02}]{} {} ... ",
                p.dim,
                idx + 1,
                tests.len(),
                p.reset,
                pad_right(label, 31)
            );
            let _ = std::io::stdout().flush();
        }
        let res = func(&opts, &mut hi);
        if !opts.json {
            match res.status {
                ScenarioStatus::Pass => println!(
                    "{}{}[PASS]{} {}({:.2}s){}",
                    p.bold, p.green, p.reset, p.dim, res.elapsed_s, p.reset
                ),
                ScenarioStatus::Skip => println!(
                    "{}{}[SKIP]{} {}({:.2}s){}",
                    p.bold, p.yellow, p.reset, p.dim, res.elapsed_s, p.reset
                ),
                ScenarioStatus::Fail => println!(
                    "{}{}[FAIL]{} {}({:.2}s) - {}{}",
                    p.bold, p.red, p.reset, p.dim, res.elapsed_s, res.metrics, p.reset
                ),
            }
        }
        results.push(res);
    }

    let total_s = suite_t0.elapsed().as_secs_f64();
    if opts.json {
        print_json_report(&cpu, &opts, &results, &hi, total_s);
    } else {
        print_pretty_report(&cpu, &opts, &results, &hi, total_s);
    }

    results.iter().all(|r| r.status != ScenarioStatus::Fail)
}
