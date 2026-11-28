//! 原生单进程零回环中继模式（`webrtc-cloak relay`）。
//!
//! 支持四种出站中继形态及不断网 `SIGHUP` 热切换（`--hot-config`）：
//! - `passthrough`：零解密 L4 UDP 透传中继（零加解密、零 PSK 依赖，支持 IPv6↔IPv4 双栈直通与 `recvmmsg`/`sendmmsg` 批量转发）；
//! - `bypass`：入站终止 DTLS 1.3 + SRTP，出站零封装 UDP + 带外认证 ICE STUN ECMP 抽卡；
//! - `cloak`：入站终止 Leg 1 并同进程 L1 缓存直连二跳 DTLS 1.3 + SRTP 隧道；
//! - `reverse`：公网被动会合 NAT 后反向出口的零回环中继；
//! - 热切换（`--hot-config` + `SIGHUP`）：支持不关闭主监听套接字、过渡期 `AB` 双模引流排空，实现 `cloak ↔ passthrough ↔ bypass` 与上游目标零丢包切换。

mod passthrough;
#[cfg(test)]
mod tests;
mod worker;

pub use self::passthrough::PassthroughConfig;
pub(crate) use self::passthrough::PassthroughTable;
use self::worker::run_relay_worker;
pub(crate) use self::worker::RelayEgress;
use crate::bypass::BypassConfig;
use crate::client::ClientConfig;
use crate::constants::outer_udp_hdr_len;
use crate::protocol::{build_dimpl_config_pool_for, detect_cpu_accel};
use crate::server::{SeenTxidCache, ServerConfig, SharedV4Registry};
use crate::telemetry::TelemetryHub;
use crate::udp_batch::format_udp_batch_mode;
use std::cell::Cell;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;

thread_local! {
    pub(super) static RELAY_QUIET: Cell<bool> = const { Cell::new(false) };
}

/// 中继节点出站侧（Leg 2）传输模式配置。
#[derive(Clone)]
pub enum RelayUpstreamConfig {
    /// 零解密 L4 UDP 透传中继（零加解密、零 PSK，客户端与出口端到端直连 DTLS 1.3 + SRTP）。
    Passthrough(PassthroughConfig),
    /// 零封装原始 UDP 直通 + 带外认证 ICE STUN 多候选 ECMP 选路与黑洞自愈。
    Bypass(BypassConfig),
    /// 完整二跳 DTLS 1.3 + SRTP 伪装隧道（同进程 L1 缓存直连解密→再加密，零回环）。
    Cloak(ClientConfig),
    /// 反向会合二跳 DTLS 1.3 + SRTP 隧道（公网监听等待 NAT 后反向出口主动连入，零回环内存直连）。
    Reverse(ServerConfig),
}

/// 原生单进程零回环中继节点配置（`webrtc-cloak relay`）。
#[derive(Clone)]
pub struct RelayConfig {
    pub ingress: ServerConfig,
    pub upstream: RelayUpstreamConfig,
    /// 可选热切换配置文件路径（收到 `SIGHUP` 或 `reload_trigger` 时原子读取并无感热切模式/目标）。
    pub hot_config_path: Option<String>,
    /// 可选测试/嵌入式代码触发热重载信号（生产 CLI 通过 Unix `SIGHUP` 自动触发）。
    pub reload_trigger: Option<Arc<AtomicBool>>,
    /// 是否在 `cloak`/`bypass` 模式下默认允许未通过入站 PSK 的 STUN 报文自动落入透传表（用于双模共存）。
    pub passthrough_fallback: bool,
}

pub(super) fn log(worker_id: usize, msg: &str) {
    if !RELAY_QUIET.with(|q| q.get()) {
        println!("[relay-rs#{}] {}", worker_id, msg);
    }
}

/// 启动原生单进程零回环中继（支持单线程或 `SO_REUSEPORT` 多工作线程）。
pub fn run_relay(mut cfg: RelayConfig) -> std::io::Result<()> {
    if matches!(cfg.upstream, RelayUpstreamConfig::Reverse(_)) && cfg.ingress.workers > 1 {
        if !cfg.ingress.quiet {
            eprintln!("[relay-rs] WARN: --upstream-mode reverse runs in single-thread rendezvous mode; clamping --workers to 1.");
        }
        cfg.ingress.workers = 1;
    }
    let workers = cfg.ingress.workers.max(1);
    let cpu = detect_cpu_accel();
    let ingress_dtls_pool = if matches!(cfg.upstream, RelayUpstreamConfig::Passthrough(_)) {
        None
    } else {
        Some(build_dimpl_config_pool_for(
            cfg.ingress.cipher_pref,
            &cpu,
            false,
            cfg.ingress.wan_mtu,
            outer_udp_hdr_len(cfg.ingress.listen_addr),
        ))
    };
    let (role, egress_dtls_pool, upstream_summary) = match &cfg.upstream {
        RelayUpstreamConfig::Passthrough(p) => (
            "relay-passthrough",
            None,
            format!(
                "passthrough(zero-crypto L4 UDP -> {}, max_sessions={})",
                p.target_addr, p.max_sessions
            ),
        ),
        RelayUpstreamConfig::Bypass(b) => {
            let lh_desc = if b.lane_hunt.enabled {
                let tgt = if b.lane_hunt.target_rtt_ms == 0 {
                    "auto".to_string()
                } else {
                    format!("{}ms", b.lane_hunt.target_rtt_ms)
                };
                format!(
                    "on(probes={},rounds={},target={},cooldown={}s)",
                    b.lane_hunt.probes,
                    b.lane_hunt.max_rounds,
                    tgt,
                    b.lane_hunt.degrade_cooldown_secs
                )
            } else {
                "off".to_string()
            };
            (
                "relay-bypass",
                None,
                format!(
                    "bypass(raw-udp+stun-ecmp -> {}, lane_hunt={})",
                    b.server_addr, lh_desc
                ),
            )
        }
        RelayUpstreamConfig::Cloak(c) => {
            let pool = build_dimpl_config_pool_for(
                c.cipher_pref,
                &cpu,
                true,
                c.wan_mtu,
                outer_udp_hdr_len(c.server_addr),
            );
            let lh_desc = if c.lane_hunt.enabled {
                format!(
                    "on(probes={},rounds={})",
                    c.lane_hunt.probes, c.lane_hunt.max_rounds
                )
            } else {
                "off".to_string()
            };
            (
                "relay-cloak",
                Some(pool),
                format!(
                    "cloak(dtls-{}, cipher={:?} -> {}, lane_hunt={})",
                    c.dtls_min_version.as_str(),
                    c.cipher_pref,
                    c.server_addr,
                    lh_desc
                ),
            )
        }
        RelayUpstreamConfig::Reverse(r) => {
            let pool = build_dimpl_config_pool_for(
                r.cipher_pref,
                &cpu,
                false,
                r.wan_mtu,
                outer_udp_hdr_len(r.listen_addr),
            );
            (
                "relay-reverse",
                Some(pool),
                format!(
                    "reverse(dtls-{}, cipher={:?} <- listen {})",
                    r.dtls_min_version.as_str(),
                    r.cipher_pref,
                    r.listen_addr
                ),
            )
        }
    };

    let seen_txids = Arc::new(Mutex::new(SeenTxidCache::new()));
    let registry = Arc::new(SharedV4Registry::new(workers));
    let telemetry = TelemetryHub::start(
        role,
        &cfg.ingress.telemetry,
        workers,
        cfg.ingress.wan_mtu,
        cfg.ingress.quiet,
        cfg.ingress.stop.clone(),
    );

    if !cfg.ingress.quiet {
        let hot_desc = cfg.hot_config_path.as_deref().unwrap_or("off");
        println!(
            "[relay-rs] zero-loopback CPU arch={} hw_accel=[{}] recommended={} workers={} ingress={} upstream={} udp_batch={} hot_config={}",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            workers,
            cfg.ingress.listen_addr,
            upstream_summary,
            format_udp_batch_mode(cfg.ingress.udp_batch),
            hot_desc,
        );
    }
    #[cfg(not(target_os = "linux"))]
    if workers > 1 {
        eprintln!("[relay-rs] WARN: SO_REUSEPORT UDP hash load-balancing is Linux-specific.");
    }

    if workers == 1 {
        let res = run_relay_worker(
            0,
            cfg,
            false,
            ingress_dtls_pool,
            egress_dtls_pool,
            seen_txids,
            registry,
            telemetry.clone(),
        );
        if let Some(ref th) = telemetry {
            th.shutdown();
        }
        return res;
    }

    let mut handles = Vec::with_capacity(workers - 1);
    for wid in 1..workers {
        let mut c = cfg.clone();
        c.ingress.wire_audit_file = None;
        let in_dp = ingress_dtls_pool.clone();
        let out_dp = egress_dtls_pool.clone();
        let cache = Arc::clone(&seen_txids);
        let reg = Arc::clone(&registry);
        let tel = telemetry.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = run_relay_worker(wid, c, true, in_dp, out_dp, cache, reg, tel) {
                eprintln!("[relay-rs#{}] error: {}", wid, e);
            }
        }));
    }
    let res = run_relay_worker(
        0,
        cfg,
        true,
        ingress_dtls_pool,
        egress_dtls_pool,
        seen_txids,
        registry,
        telemetry.clone(),
    );
    for h in handles {
        let _ = h.join();
    }
    if let Some(ref th) = telemetry {
        th.shutdown();
    }
    res
}
