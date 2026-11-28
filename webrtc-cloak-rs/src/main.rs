//! CLI 参数解析与子命令分发入口。

mod bench_tools;
mod bypass;
mod client;
mod constants;
mod hot_reload;
mod protocol;
#[cfg(feature = "embedded-proxy")]
mod proxy;
mod relay;
mod reverse;
mod selftest;
mod server;
mod telemetry;
mod udp_batch;

use crate::bench_tools::{print_cpu_info, run_bench, run_loadgen, run_sink};
use crate::bypass::{run_bypass, run_bypass_responder, BypassConfig, BypassResponderConfig};
use crate::client::{
    run_client, ClientConfig, LaneHuntConfig, DEFAULT_LANE_DEGRADE_COOLDOWN_SECS,
    DEFAULT_LANE_PROBES, DEFAULT_LANE_ROUNDS,
};
use crate::constants::{
    normalize_udp_batch, DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_ROTATE_COOLDOWN_SECS,
    DEFAULT_UDP_BATCH, DEFAULT_WAN_MTU,
};
use crate::protocol::{
    detect_cpu_accel, install_reload_handler, install_shutdown_handler, set_global_stun_scope,
    CipherPref, CipherSuite, DtlsMinVersion,
};
#[cfg(feature = "embedded-proxy")]
use crate::proxy::{
    parse_bandwidth_bps, parse_tcp_forward_rule, run_proxy_client, run_proxy_client_reverse,
    run_proxy_server, run_proxy_server_reverse, AclConfig, AclRule, ProxyClientConfig,
    ProxyServerConfig, ReverseProxyClientConfig, ReverseProxyServerConfig, TcpForwardRule,
};
use crate::relay::{run_relay, PassthroughConfig, RelayConfig, RelayUpstreamConfig};
use crate::reverse::{
    run_reverse_agent, run_reverse_entry, ReverseAgentConfig, ReverseEntryConfig,
};
use crate::selftest::{run_selftest, SelftestOptions};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use pico_args::Arguments;
use std::env;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process;

/// 1 MiB 字节数，用于将 `--rotate-bytes` 参数换算为字节。
const MIB: u64 = 1024 * 1024;
/// 客户端本地默认监听地址。
const DEFAULT_CLIENT_LISTEN_HOST: &str = "127.0.0.1";
/// 客户端本地默认监听端口。
const DEFAULT_CLIENT_LISTEN_PORT: u16 = 19543;
/// 内嵌代理客户端默认本地 SOCKS5 监听端口。
#[cfg(feature = "embedded-proxy")]
const DEFAULT_PROXY_SOCKS_PORT: u16 = 19548;
/// 内嵌代理客户端默认上行 Brutal 带宽（100 Mbps）。
#[cfg(feature = "embedded-proxy")]
const DEFAULT_PROXY_UP_BPS: u64 = 100_000_000;
/// 内嵌代理客户端默认下行 Brutal 带宽（300 Mbps）。
#[cfg(feature = "embedded-proxy")]
const DEFAULT_PROXY_DOWN_BPS: u64 = 300_000_000;
/// 内嵌代理服务端默认上下行最大 Brutal 带宽上限（500 Mbps）。
#[cfg(feature = "embedded-proxy")]
const DEFAULT_PROXY_MAX_BPS: u64 = 500_000_000;
/// 服务端公网默认监听地址。
const DEFAULT_SERVER_LISTEN_HOST: &str = "0.0.0.0";
/// 服务端公网默认监听端口。
const DEFAULT_SERVER_LISTEN_PORT: u16 = 19643;
/// 服务端转发后端默认地址。
const DEFAULT_BACKEND_HOST: &str = "127.0.0.1";
/// 默认工作线程数。
const DEFAULT_WORKERS: usize = 1;
/// 单工作线程默认最大并发会话数上限。
const DEFAULT_MAX_SESSIONS: usize = 4096;
/// 周期统计日志默认打印间隔（秒）。
const DEFAULT_STATS_INTERVAL_SECS: u64 = 10;
/// 客户端初始 STUN 握手默认重试间隔（毫秒）。
const DEFAULT_CLIENT_RETRY_MS: u64 = 300;
/// 客户端初始 STUN 握手默认最大重试次数。
const DEFAULT_CLIENT_MAX_RETRIES: u32 = 8;
/// 客户端 RFC 7675 STUN 保活探测默认基准间隔（秒）。
const DEFAULT_CLIENT_KEEPALIVE_SECS: u64 = 5;
/// 开启按时轮换但未显式指定 `--rotate-bytes` 时的默认单会话基准流量预算（MiB）。
const DEFAULT_ROTATE_BYTE_BUDGET_MIB: u64 = 1200;
/// `selftest --count` 允许的最小探测包数。
const SELFTEST_PROBE_COUNT_MIN: usize = 5;
/// `selftest --count` 允许的最大探测包数。
const SELFTEST_PROBE_COUNT_MAX: usize = 200;
/// `sink` 压测接收端默认监听地址。
const DEFAULT_SINK_LISTEN: &str = "127.0.0.1:19760";
/// `loadgen` 压测发包端默认目标地址。
const DEFAULT_LOADGEN_TARGET: &str = "127.0.0.1:19560";
/// `bench` / `loadgen` 默认测试报文总数。
const DEFAULT_BENCH_COUNT: usize = 50_000;
/// `bench` / `loadgen` 默认单包负载长度（字节）。
const DEFAULT_BENCH_PAYLOAD_BYTES: usize = 1260;
/// `loadgen` 默认 RTT 采样轮数。
const DEFAULT_LOADGEN_RTT_ITERS: usize = 500;
/// `loadgen` 默认并发流数量。
const DEFAULT_LOADGEN_STREAMS: usize = 1;

struct CommonTunnelArgs {
    psk: Vec<u8>,
    stun_scope: Option<String>,
    cipher_pref: CipherPref,
    dtls_min_version: DtlsMinVersion,
    workers: usize,
    max_sessions: usize,
    wan_mtu: usize,
    udp_batch: usize,
    dtls_enabled: bool,
    idle_timeout_secs: u64,
    stats_interval_secs: u64,
    telemetry: TelemetryConfig,
}

fn parse_workers(s: &str) -> Result<usize, String> {
    if s == "auto" {
        Ok(std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(DEFAULT_WORKERS))
    } else {
        s.parse::<usize>()
            .map(|n| n.max(1))
            .map_err(|_| format!("invalid --workers: {}", s))
    }
}

fn parse_cipher_pref(s: &str) -> Result<CipherPref, String> {
    match s {
        "auto" => Ok(CipherPref::Auto),
        "aes-gcm" | "aes128-gcm" | "gcm" => Ok(CipherPref::Fixed(CipherSuite::Aes128Gcm)),
        "chacha20" | "chacha20-poly1305" | "chacha" => {
            Ok(CipherPref::Fixed(CipherSuite::ChaCha20Poly1305))
        }
        "blake2b" | "b2b" => Ok(CipherPref::Fixed(CipherSuite::Blake2b)),
        other => Err(format!(
            "Unknown cipher: {} (expected auto, aes-gcm, chacha20, or blake2b)",
            other
        )),
    }
}

fn parse_dtls_min_version(s: &str) -> Result<DtlsMinVersion, String> {
    match s {
        "auto" | "1.2" => Ok(DtlsMinVersion::Auto),
        "1.3" => Ok(DtlsMinVersion::V13Only),
        other => Err(format!(
            "Unknown --dtls-min-version: {} (expected auto, 1.2, or 1.3)",
            other
        )),
    }
}

fn parse_status_http(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|_| format!("Invalid --status-http address: {} (expected IP:PORT)", s))
}

fn parse_socket_addr(host: &str, port: u16, label: &str) -> SocketAddr {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return SocketAddr::new(ip, port);
    }
    let spec = if trimmed.contains(':') {
        format!("[{}]:{}", trimmed, port)
    } else {
        format!("{}:{}", trimmed, port)
    };
    spec.to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .unwrap_or_else(|| {
            eprintln!("Invalid {} address {}:{}", label, host, port);
            process::exit(2);
        })
}

fn usage() -> ! {
    eprintln!(
        "Usage:\n  \
         webrtc-cloak cpu\n  \
         webrtc-cloak client --listen-host 127.0.0.1 --listen-port 19543 --server-host <IPv4|IPv6> --server-port 19643 (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--stun-scope <TAG>] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version 1.3|1.2|auto] [--lane-hunt] [--lane-probes 4] [--lane-rounds 3] [--lane-target-rtt <MS>] [--lane-cooldown 60] [--rotate-interval 0] [--rotate-bytes <MB>] [--workers 1|auto] [--max-sessions 4096] [--mtu 1488] [--udp-batch 0] [--keepalive 5] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak server --listen-host 0.0.0.0 --listen-port 19643 --backend-host 127.0.0.1 --backend-port <PORT> (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--stun-scope <TAG>] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version 1.3|1.2|auto] [--workers 1|auto] [--max-sessions 4096] [--mtu 1488] [--udp-batch 0] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak relay --listen-host 0.0.0.0 --listen-port 19643 [--upstream-mode passthrough|bypass|cloak|reverse] (--upstream-host <IPv4|IPv6> [--upstream-port 19643] | --reverse-listen-port <PORT> [--reverse-listen-host 0.0.0.0]) [--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK] [--upstream-psk <KEY> | --upstream-psk-file <PATH> | env WEBRTC_CLOAK_UPSTREAM_PSK] [--hot-config <PATH>] [--passthrough-fallback] [--stun-scope <TAG>] [--cipher auto|aes-gcm|chacha20|blake2b] [--upstream-cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version 1.3|1.2|auto] [--upstream-dtls-min-version 1.3|1.2|auto] [--lane-hunt | --no-lane-hunt] [--lane-probes 4] [--lane-rounds 3] [--lane-target-rtt <MS>] [--lane-cooldown 60] [--rotate-interval 0] [--rotate-bytes <MB>] [--keepalive 5] [--workers 1|auto] [--max-sessions 4096] [--mtu 1488] [--udp-batch 0] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak reverse --entry --listen-host 0.0.0.0 --listen-port 19643 --expose-host 127.0.0.1 --expose-port <PORT> (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--stun-scope <TAG>] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version 1.3|1.2|auto] [--max-sessions 4096] [--mtu 1488] [--udp-batch 0] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak reverse --agent --server-host <IPv4|IPv6> --server-port 19643 --backend-host 127.0.0.1 --backend-port <PORT> (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--stun-scope <TAG>] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version 1.3|1.2|auto] [--lane-hunt] [--lane-probes 4] [--lane-rounds 3] [--lane-target-rtt <MS>] [--lane-cooldown 60] [--rotate-interval 0] [--rotate-bytes <MB>] [--keepalive 5] [--max-sessions 4096] [--mtu 1488] [--udp-batch 0] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak bypass --listen-host 127.0.0.1 --listen-port 19543 --server-host <IPv4|IPv6> --server-port 19643 (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--stun-scope <TAG>] [--lane-probes 4] [--lane-rounds 3] [--lane-target-rtt <MS>] [--lane-cooldown 60] [--no-lane-hunt] [--rotate-interval 0] [--workers 1|auto] [--max-sessions 4096] [--mtu 1488] [--udp-batch 0] [--keepalive 5] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5]\n  \
         webrtc-cloak bypass --responder --listen-host 127.0.0.1 --listen-port 19643 (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--stun-scope <TAG>] [--workers 1|auto] [--mtu 1488] [--udp-batch 0] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5]\n  \
         webrtc-cloak proxy --client [--reverse --listen-host 0.0.0.0 --listen-port 19643 | --server-host <IPv4|IPv6> --server-port 19643] [--socks-listen 127.0.0.1:19548 | --no-socks] [--tcp-forward LOCAL=TARGET]... [--up 100Mbps] [--down 300Mbps] [--proxy-mtu <BYTES>] [--hot-config <PATH>] (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--stun-scope <TAG>] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version 1.3|1.2|auto] [--lane-hunt] [--lane-probes 4] [--lane-rounds 3] [--lane-target-rtt <MS>] [--lane-cooldown 60] [--rotate-interval 0] [--rotate-bytes <MB>] [--keepalive 5] [--mtu 1488] [--udp-batch 0] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak proxy --server [--reverse --server-host <IPv4|IPv6> --server-port 19643 | --listen-host 0.0.0.0 --listen-port 19643] [--max-up 500Mbps] [--max-down 500Mbps] [--proxy-mtu <BYTES>] [--acl-allow CIDR[:PORT]]... [--acl-deny CIDR[:PORT]]... [--allow-private] [--outbound-ipv4-only] (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--stun-scope <TAG>] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version 1.3|1.2|auto] [--lane-hunt] [--rotate-interval 0] [--rotate-bytes <MB>] [--keepalive 5] [--mtu 1488] [--udp-batch 0] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak bench [count] [payload_bytes] [all|aes-gcm|chacha20|blake2b]\n  \
         webrtc-cloak selftest --server-host <IP|HOST> [--server-port 19643] (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--stun-scope <TAG>] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version 1.3|1.2|auto] [--mtu 1488] [--count 20] [--no-probe] [--no-color] [--json]\n  \
         webrtc-cloak selftest [--local] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version 1.3|1.2|auto] [--mtu 1488] [--no-color] [--json]"
    );
    process::exit(2);
}

fn resolve_optional_psk(
    psk_arg: Option<String>,
    psk_file: Option<String>,
    env_var: &str,
) -> Option<Vec<u8>> {
    if let Some(path) = psk_file {
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.as_bytes().to_vec());
                }
            }
            Err(e) => {
                eprintln!("Failed to read psk-file {}: {}", path, e);
                process::exit(2);
            }
        }
    }
    if let Some(k) = psk_arg.filter(|s| !s.is_empty()) {
        return Some(k.into_bytes());
    }
    if let Ok(env_k) = env::var(env_var) {
        let trimmed = env_k.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.as_bytes().to_vec());
        }
    }
    None
}

fn resolve_psk(psk_arg: Option<String>, psk_file: Option<String>) -> Vec<u8> {
    resolve_optional_psk(psk_arg, psk_file, "WEBRTC_CLOAK_PSK").unwrap_or_else(|| usage())
}

fn check_no_extra(args: Arguments) {
    let rest = args.finish();
    if !rest.is_empty() {
        eprintln!("Unknown argument(s): {:?}", rest);
        usage();
    }
}

fn finish_common_tunnel(args: Arguments) -> Result<CommonTunnelArgs, pico_args::Error> {
    finish_common_tunnel_ex(args, true)
}

fn finish_common_tunnel_ex(
    mut args: Arguments,
    require_psk: bool,
) -> Result<CommonTunnelArgs, pico_args::Error> {
    let psk_arg: Option<String> = args.opt_value_from_str("--psk")?;
    let psk_file: Option<String> = args.opt_value_from_str("--psk-file")?;
    let stun_scope: Option<String> = args.opt_value_from_str("--stun-scope")?;
    let cipher_pref = args
        .opt_value_from_fn("--cipher", parse_cipher_pref)?
        .unwrap_or(CipherPref::Auto);
    let dtls_min_version = args
        .opt_value_from_fn("--dtls-min-version", parse_dtls_min_version)?
        .unwrap_or(DtlsMinVersion::V13Only);
    let workers = args
        .opt_value_from_fn("--workers", parse_workers)?
        .unwrap_or(DEFAULT_WORKERS);
    let max_sessions = args
        .opt_value_from_str::<_, usize>("--max-sessions")?
        .unwrap_or(DEFAULT_MAX_SESSIONS)
        .max(1);
    let wan_mtu = args.opt_value_from_str("--mtu")?.unwrap_or(DEFAULT_WAN_MTU);
    let udp_batch = normalize_udp_batch(
        args.opt_value_from_str("--udp-batch")?
            .unwrap_or(DEFAULT_UDP_BATCH),
    );
    let dtls_enabled = !args.contains("--no-dtls-decoy");
    let idle_timeout_secs = args
        .opt_value_from_str("--idle-timeout")?
        .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS);
    let stats_interval_secs = args
        .opt_value_from_str("--stats-interval")?
        .unwrap_or(DEFAULT_STATS_INTERVAL_SECS);
    let telemetry = TelemetryConfig {
        status_file: args.opt_value_from_str("--status-file")?,
        status_http: args.opt_value_from_fn("--status-http", parse_status_http)?,
        status_interval_secs: args.opt_value_from_str("--status-interval")?.unwrap_or(0),
    };
    check_no_extra(args);
    let psk = if require_psk {
        resolve_psk(psk_arg, psk_file)
    } else {
        resolve_optional_psk(psk_arg, psk_file, "WEBRTC_CLOAK_PSK").unwrap_or_default()
    };
    Ok(CommonTunnelArgs {
        psk,
        stun_scope,
        cipher_pref,
        dtls_min_version,
        workers,
        max_sessions,
        wan_mtu,
        udp_batch,
        dtls_enabled,
        idle_timeout_secs,
        stats_interval_secs,
        telemetry,
    })
}

fn run() -> Result<(), pico_args::Error> {
    let mut args = Arguments::from_env();
    let Some(sub) = args.subcommand()? else {
        usage();
    };
    if args.contains(["-h", "--help"]) {
        usage();
    }

    match sub.as_str() {
        "cpu" => {
            check_no_extra(args);
            print_cpu_info();
        }
        "selftest" => {
            let mut opts = SelftestOptions::default();
            if let Some(scope) = args.opt_value_from_str::<_, String>("--stun-scope")? {
                set_global_stun_scope(scope);
            }
            let server_host: Option<String> = args.opt_value_from_str("--server-host")?;
            let server_port: u16 = args
                .opt_value_from_str("--server-port")?
                .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
            let psk: Option<String> = args.opt_value_from_str("--psk")?;
            let psk_file: Option<String> = args.opt_value_from_str("--psk-file")?;
            if let Some(c) = args.opt_value_from_str::<_, usize>("--count")? {
                opts.probe_count = c.clamp(SELFTEST_PROBE_COUNT_MIN, SELFTEST_PROBE_COUNT_MAX);
            }
            if args.contains("--no-probe") {
                opts.active_probes = false;
            }
            let force_local = args.contains("--local");
            if let Some(c) = args.opt_value_from_fn("--cipher", parse_cipher_pref)? {
                opts.cipher_pref = c;
            }
            if let Some(v) = args.opt_value_from_fn("--dtls-min-version", parse_dtls_min_version)? {
                opts.dtls_min_version = v;
            }
            if let Some(m) = args.opt_value_from_str("--mtu")? {
                opts.wan_mtu = m;
            }
            if args.contains("--no-color") {
                opts.color = false;
            }
            if args.contains("--json") {
                opts.json = true;
            }
            check_no_extra(args);

            if !force_local {
                if let Some(host) = server_host.filter(|s| !s.is_empty()) {
                    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
                    let target_str = if trimmed.contains(':') {
                        format!("[{}]:{}", trimmed, server_port)
                    } else {
                        format!("{}:{}", trimmed, server_port)
                    };
                    let resolved = if let Ok(ip) = trimmed.parse::<IpAddr>() {
                        SocketAddr::new(ip, server_port)
                    } else {
                        match target_str.to_socket_addrs() {
                            Ok(mut it) => match it.next() {
                                Some(a) => a,
                                None => {
                                    eprintln!("Failed to resolve address for {}", target_str);
                                    process::exit(2);
                                }
                            },
                            Err(e) => {
                                eprintln!("Failed to resolve {}: {}", target_str, e);
                                process::exit(2);
                            }
                        }
                    };
                    opts.server_addr = Some(resolved);
                    opts.server_label = Some(target_str);
                    opts.psk = Some(resolve_psk(psk, psk_file));
                }
            }
            if !run_selftest(opts) {
                process::exit(1);
            }
        }
        "sink" => {
            let listen: String = args
                .opt_free_from_str()?
                .unwrap_or_else(|| DEFAULT_SINK_LISTEN.into());
            let workers = args
                .opt_free_from_fn(parse_workers)?
                .unwrap_or(DEFAULT_WORKERS);
            check_no_extra(args);
            run_sink(&listen, workers);
        }
        "loadgen" => {
            let target: String = args
                .opt_free_from_str()?
                .unwrap_or_else(|| DEFAULT_LOADGEN_TARGET.into());
            let packets: u64 = args
                .opt_free_from_str()?
                .unwrap_or(DEFAULT_BENCH_COUNT as u64);
            let size: usize = args
                .opt_free_from_str()?
                .unwrap_or(DEFAULT_BENCH_PAYLOAD_BYTES);
            let rate_mbps: f64 = args.opt_free_from_str()?.unwrap_or(0.0);
            let rtt_iters: usize = args
                .opt_free_from_str()?
                .unwrap_or(DEFAULT_LOADGEN_RTT_ITERS);
            let streams: usize = args.opt_free_from_str()?.unwrap_or(DEFAULT_LOADGEN_STREAMS);
            check_no_extra(args);
            run_loadgen(&target, packets, size, rate_mbps, rtt_iters, streams);
        }
        "bench" => {
            let count: usize = args.opt_free_from_str()?.unwrap_or(DEFAULT_BENCH_COUNT);
            let sz: usize = args
                .opt_free_from_str()?
                .unwrap_or(DEFAULT_BENCH_PAYLOAD_BYTES);
            let mode: String = args.opt_free_from_str()?.unwrap_or_else(|| "all".into());
            check_no_extra(args);
            print_cpu_info();
            if mode == "all" {
                run_bench(count, sz, CipherSuite::Aes128Gcm);
                run_bench(count, sz, CipherSuite::ChaCha20Poly1305);
                run_bench(count, sz, CipherSuite::Blake2b);
            } else {
                match parse_cipher_pref(&mode).unwrap_or_else(|e| {
                    eprintln!("{}", e);
                    process::exit(2);
                }) {
                    CipherPref::Fixed(s) => run_bench(count, sz, s),
                    CipherPref::Auto => run_bench(count, sz, detect_cpu_accel().recommended),
                }
            }
        }
        "client" => {
            let listen_host: String = args
                .opt_value_from_str("--listen-host")?
                .unwrap_or_else(|| DEFAULT_CLIENT_LISTEN_HOST.into());
            let listen_port: u16 = args
                .opt_value_from_str("--listen-port")?
                .unwrap_or(DEFAULT_CLIENT_LISTEN_PORT);
            let server_host: String = args.value_from_str("--server-host")?;
            let server_port: u16 = args
                .opt_value_from_str("--server-port")?
                .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
            let rotate_interval_secs: u64 =
                args.opt_value_from_str("--rotate-interval")?.unwrap_or(0);
            let rotate_bytes_mb: Option<u64> = args.opt_value_from_str("--rotate-bytes")?;
            let retry_ms: u64 = args
                .opt_value_from_str("--retry-ms")?
                .unwrap_or(DEFAULT_CLIENT_RETRY_MS);
            let max_retries: u32 = args
                .opt_value_from_str("--max-retries")?
                .unwrap_or(DEFAULT_CLIENT_MAX_RETRIES);
            let keepalive_secs: u64 = args
                .opt_value_from_str("--keepalive")?
                .unwrap_or(DEFAULT_CLIENT_KEEPALIVE_SECS);
            let lane_hunt_flag = args.contains("--lane-hunt");
            let lane_probes_opt: Option<usize> = args.opt_value_from_str("--lane-probes")?;
            let lane_rounds_opt: Option<usize> = args.opt_value_from_str("--lane-rounds")?;
            let lane_target_rtt_opt: Option<u64> = args.opt_value_from_str("--lane-target-rtt")?;
            let lane_cooldown_opt: Option<u64> = args.opt_value_from_str("--lane-cooldown")?;
            let lane_enabled = lane_hunt_flag
                || lane_probes_opt.is_some_and(|p| p > 1)
                || lane_target_rtt_opt.is_some_and(|t| t > 0);
            let lane_hunt = LaneHuntConfig {
                enabled: lane_enabled,
                probes: lane_probes_opt.unwrap_or(DEFAULT_LANE_PROBES),
                max_rounds: lane_rounds_opt.unwrap_or(DEFAULT_LANE_ROUNDS),
                target_rtt_ms: lane_target_rtt_opt.unwrap_or(0),
                degrade_cooldown_secs: lane_cooldown_opt
                    .unwrap_or(DEFAULT_LANE_DEGRADE_COOLDOWN_SECS),
            }
            .normalized();
            if server_host.is_empty() {
                usage();
            }
            let common = finish_common_tunnel(args)?;

            let rotate_max_bytes = match rotate_bytes_mb {
                Some(mb) => mb.saturating_mul(MIB),
                None if rotate_interval_secs > 0 => DEFAULT_ROTATE_BYTE_BUDGET_MIB * MIB,
                None => 0,
            };
            let listen_addr = parse_socket_addr(&listen_host, listen_port, "listen");
            let server_addr = parse_socket_addr(&server_host, server_port, "server");
            if let Err(e) = run_client(ClientConfig {
                listen_addr,
                server_addr,
                psk: common.psk,
                stun_scope: common.stun_scope,
                cipher_pref: common.cipher_pref,
                dtls_decoy: common.dtls_enabled,
                dtls_min_version: common.dtls_min_version,
                rotate_interval_secs,
                rotate_max_bytes,
                rotate_cooldown_secs: DEFAULT_ROTATE_COOLDOWN_SECS,
                workers: common.workers,
                max_sessions: common.max_sessions,
                wan_mtu: common.wan_mtu,
                udp_batch: common.udp_batch,
                retry_ms,
                max_retries,
                keepalive_secs,
                idle_timeout_secs: common.idle_timeout_secs,
                stats_interval_secs: common.stats_interval_secs,
                lane_hunt,
                telemetry: common.telemetry,
                quiet: false,
                stop: Some(install_shutdown_handler()),
            }) {
                eprintln!("client error: {}", e);
                process::exit(1);
            }
        }
        "server" => {
            let listen_host: String = args
                .opt_value_from_str("--listen-host")?
                .unwrap_or_else(|| DEFAULT_SERVER_LISTEN_HOST.into());
            let listen_port: u16 = args
                .opt_value_from_str("--listen-port")?
                .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
            let backend_host: String = args
                .opt_value_from_str("--backend-host")?
                .unwrap_or_else(|| DEFAULT_BACKEND_HOST.into());
            let backend_port: u16 = args.value_from_str("--backend-port")?;
            let wire_audit_file: Option<String> = args.opt_value_from_str("--wire-audit-file")?;
            if backend_port == 0 {
                usage();
            }
            let common = finish_common_tunnel(args)?;

            let listen_addr = parse_socket_addr(&listen_host, listen_port, "listen");
            let backend_addr = parse_socket_addr(&backend_host, backend_port, "backend");
            if let Err(e) = run_server(ServerConfig {
                listen_addr,
                backend_addr,
                psk: common.psk,
                stun_scope: common.stun_scope,
                cipher_pref: common.cipher_pref,
                dtls_required: common.dtls_enabled,
                dtls_min_version: common.dtls_min_version,
                workers: common.workers,
                max_sessions: common.max_sessions,
                wan_mtu: common.wan_mtu,
                udp_batch: common.udp_batch,
                idle_timeout_secs: common.idle_timeout_secs,
                stats_interval_secs: common.stats_interval_secs,
                wire_audit_file,
                telemetry: common.telemetry,
                quiet: false,
                stop: Some(install_shutdown_handler()),
            }) {
                eprintln!("server error: {}", e);
                process::exit(1);
            }
        }
        "relay" => {
            let listen_host: String = args
                .opt_value_from_str("--listen-host")?
                .unwrap_or_else(|| DEFAULT_SERVER_LISTEN_HOST.into());
            let listen_port: u16 = args
                .opt_value_from_str("--listen-port")?
                .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
            let upstream_mode: String = args
                .opt_value_from_str("--upstream-mode")?
                .unwrap_or_else(|| "bypass".into());
            let upstream_host_opt: Option<String> = args.opt_value_from_str("--upstream-host")?;
            let upstream_port: u16 = args
                .opt_value_from_str("--upstream-port")?
                .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
            let reverse_listen_host: String = args
                .opt_value_from_str("--reverse-listen-host")?
                .unwrap_or_else(|| DEFAULT_SERVER_LISTEN_HOST.into());
            let reverse_listen_port_opt: Option<u16> =
                args.opt_value_from_str("--reverse-listen-port")?;
            let upstream_psk_arg: Option<String> = args.opt_value_from_str("--upstream-psk")?;
            let upstream_psk_file: Option<String> =
                args.opt_value_from_str("--upstream-psk-file")?;
            let upstream_stun_scope: Option<String> =
                args.opt_value_from_str("--upstream-stun-scope")?;
            let upstream_cipher_opt: Option<CipherPref> =
                args.opt_value_from_fn("--upstream-cipher", parse_cipher_pref)?;
            let upstream_dtls_min_opt: Option<DtlsMinVersion> =
                args.opt_value_from_fn("--upstream-dtls-min-version", parse_dtls_min_version)?;
            let upstream_no_dtls_decoy = args.contains("--upstream-no-dtls-decoy");
            let wire_audit_file: Option<String> = args.opt_value_from_str("--wire-audit-file")?;
            let rotate_interval_secs: u64 =
                args.opt_value_from_str("--rotate-interval")?.unwrap_or(0);
            let rotate_bytes_mb: Option<u64> = args.opt_value_from_str("--rotate-bytes")?;
            let retry_ms: u64 = args
                .opt_value_from_str("--retry-ms")?
                .unwrap_or(DEFAULT_CLIENT_RETRY_MS);
            let max_retries_opt: Option<u32> = args.opt_value_from_str("--max-retries")?;
            let keepalive_secs: u64 = args
                .opt_value_from_str("--keepalive")?
                .unwrap_or(DEFAULT_CLIENT_KEEPALIVE_SECS);
            let lane_hunt_flag = args.contains("--lane-hunt");
            let no_lane_hunt = args.contains("--no-lane-hunt");
            let lane_probes_opt: Option<usize> = args.opt_value_from_str("--lane-probes")?;
            let lane_rounds_opt: Option<usize> = args.opt_value_from_str("--lane-rounds")?;
            let lane_target_rtt_opt: Option<u64> = args.opt_value_from_str("--lane-target-rtt")?;
            let lane_cooldown_opt: Option<u64> = args.opt_value_from_str("--lane-cooldown")?;
            let hot_config_path: Option<String> = args.opt_value_from_str("--hot-config")?;
            let passthrough_fallback = args.contains("--passthrough-fallback");
            let is_passthrough = upstream_mode == "passthrough";
            let common = finish_common_tunnel_ex(args, !is_passthrough)?;
            let upstream_psk = resolve_optional_psk(
                upstream_psk_arg,
                upstream_psk_file,
                "WEBRTC_CLOAK_UPSTREAM_PSK",
            )
            .unwrap_or_else(|| common.psk.clone());
            let listen_addr = parse_socket_addr(&listen_host, listen_port, "listen");
            let upstream_addr = if upstream_mode == "reverse" {
                let rev_port = reverse_listen_port_opt.unwrap_or_else(|| {
                    eprintln!("relay --upstream-mode reverse requires --reverse-listen-port");
                    usage();
                });
                if rev_port == 0 {
                    usage();
                }
                parse_socket_addr(&reverse_listen_host, rev_port, "reverse-listen")
            } else {
                let Some(upstream_host) = upstream_host_opt.filter(|s| !s.is_empty()) else {
                    eprintln!(
                        "relay --upstream-mode {} requires --upstream-host",
                        upstream_mode
                    );
                    usage();
                };
                parse_socket_addr(&upstream_host, upstream_port, "upstream")
            };
            let stop = Some(install_shutdown_handler());
            if hot_config_path.is_some() {
                install_reload_handler();
            }

            let ingress = ServerConfig {
                listen_addr,
                backend_addr: upstream_addr,
                psk: common.psk,
                stun_scope: common.stun_scope,
                cipher_pref: common.cipher_pref,
                dtls_required: common.dtls_enabled,
                dtls_min_version: common.dtls_min_version,
                workers: common.workers,
                max_sessions: common.max_sessions,
                wan_mtu: common.wan_mtu,
                udp_batch: common.udp_batch,
                idle_timeout_secs: common.idle_timeout_secs,
                stats_interval_secs: common.stats_interval_secs,
                wire_audit_file,
                telemetry: common.telemetry.clone(),
                quiet: false,
                stop: stop.clone(),
            };

            let upstream = match upstream_mode.as_str() {
                "passthrough" => RelayUpstreamConfig::Passthrough(PassthroughConfig {
                    target_addr: upstream_addr,
                    max_sessions: common.max_sessions,
                    wan_mtu: common.wan_mtu,
                    udp_batch: common.udp_batch,
                    idle_timeout_secs: common.idle_timeout_secs,
                }),
                "bypass" => {
                    let lane_hunt = LaneHuntConfig {
                        enabled: !no_lane_hunt,
                        probes: lane_probes_opt.unwrap_or(DEFAULT_LANE_PROBES),
                        max_rounds: lane_rounds_opt.unwrap_or(DEFAULT_LANE_ROUNDS),
                        target_rtt_ms: lane_target_rtt_opt.unwrap_or(0),
                        degrade_cooldown_secs: lane_cooldown_opt
                            .unwrap_or(DEFAULT_LANE_DEGRADE_COOLDOWN_SECS),
                    }
                    .normalized();
                    RelayUpstreamConfig::Bypass(BypassConfig {
                        listen_addr,
                        server_addr: upstream_addr,
                        psk: upstream_psk,
                        stun_scope: upstream_stun_scope,
                        rotate_interval_secs,
                        workers: common.workers,
                        max_sessions: common.max_sessions,
                        wan_mtu: common.wan_mtu,
                        udp_batch: common.udp_batch,
                        retry_ms,
                        max_retries: max_retries_opt.unwrap_or(2),
                        keepalive_secs,
                        idle_timeout_secs: common.idle_timeout_secs,
                        stats_interval_secs: common.stats_interval_secs,
                        lane_hunt,
                        telemetry: common.telemetry,
                        quiet: false,
                        stop,
                    })
                }
                "cloak" => {
                    let lane_enabled = !no_lane_hunt
                        && (lane_hunt_flag
                            || lane_probes_opt.is_some_and(|p| p > 1)
                            || lane_target_rtt_opt.is_some_and(|t| t > 0));
                    let lane_hunt = LaneHuntConfig {
                        enabled: lane_enabled,
                        probes: lane_probes_opt.unwrap_or(DEFAULT_LANE_PROBES),
                        max_rounds: lane_rounds_opt.unwrap_or(DEFAULT_LANE_ROUNDS),
                        target_rtt_ms: lane_target_rtt_opt.unwrap_or(0),
                        degrade_cooldown_secs: lane_cooldown_opt
                            .unwrap_or(DEFAULT_LANE_DEGRADE_COOLDOWN_SECS),
                    }
                    .normalized();
                    let rotate_max_bytes = match rotate_bytes_mb {
                        Some(mb) => mb.saturating_mul(MIB),
                        None if rotate_interval_secs > 0 => DEFAULT_ROTATE_BYTE_BUDGET_MIB * MIB,
                        None => 0,
                    };
                    RelayUpstreamConfig::Cloak(ClientConfig {
                        listen_addr,
                        server_addr: upstream_addr,
                        psk: upstream_psk,
                        stun_scope: upstream_stun_scope,
                        cipher_pref: upstream_cipher_opt.unwrap_or(common.cipher_pref),
                        dtls_decoy: common.dtls_enabled && !upstream_no_dtls_decoy,
                        dtls_min_version: upstream_dtls_min_opt.unwrap_or(common.dtls_min_version),
                        rotate_interval_secs,
                        rotate_max_bytes,
                        rotate_cooldown_secs: DEFAULT_ROTATE_COOLDOWN_SECS,
                        workers: common.workers,
                        max_sessions: common.max_sessions,
                        wan_mtu: common.wan_mtu,
                        udp_batch: common.udp_batch,
                        retry_ms,
                        max_retries: max_retries_opt.unwrap_or(DEFAULT_CLIENT_MAX_RETRIES),
                        keepalive_secs,
                        idle_timeout_secs: common.idle_timeout_secs,
                        stats_interval_secs: common.stats_interval_secs,
                        lane_hunt,
                        telemetry: common.telemetry,
                        quiet: false,
                        stop,
                    })
                }
                "reverse" => RelayUpstreamConfig::Reverse(ServerConfig {
                    listen_addr: upstream_addr,
                    backend_addr: listen_addr,
                    psk: upstream_psk,
                    stun_scope: upstream_stun_scope,
                    cipher_pref: upstream_cipher_opt.unwrap_or(common.cipher_pref),
                    dtls_required: common.dtls_enabled && !upstream_no_dtls_decoy,
                    dtls_min_version: upstream_dtls_min_opt.unwrap_or(common.dtls_min_version),
                    workers: 1,
                    max_sessions: common.max_sessions,
                    wan_mtu: common.wan_mtu,
                    udp_batch: common.udp_batch,
                    idle_timeout_secs: common.idle_timeout_secs,
                    stats_interval_secs: common.stats_interval_secs,
                    wire_audit_file: None,
                    telemetry: common.telemetry,
                    quiet: false,
                    stop,
                }),
                other => {
                    eprintln!(
                        "Unknown --upstream-mode: {} (expected passthrough, bypass, cloak, or reverse)",
                        other
                    );
                    usage();
                }
            };

            if let Err(e) = run_relay(RelayConfig {
                ingress,
                upstream,
                hot_config_path,
                reload_trigger: None,
                passthrough_fallback,
            }) {
                eprintln!("relay error: {}", e);
                process::exit(1);
            }
        }
        "reverse" => {
            let is_entry = args.contains("--entry");
            let is_agent = args.contains("--agent");
            if is_entry == is_agent {
                eprintln!("reverse requires exactly one of --entry or --agent");
                usage();
            }
            if is_entry {
                let listen_host: String = args
                    .opt_value_from_str("--listen-host")?
                    .unwrap_or_else(|| DEFAULT_SERVER_LISTEN_HOST.into());
                let listen_port: u16 = args
                    .opt_value_from_str("--listen-port")?
                    .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
                let expose_host: String = args
                    .opt_value_from_str("--expose-host")?
                    .unwrap_or_else(|| DEFAULT_CLIENT_LISTEN_HOST.into());
                let expose_port: u16 = args.value_from_str("--expose-port")?;
                let wire_audit_file: Option<String> =
                    args.opt_value_from_str("--wire-audit-file")?;
                if expose_port == 0 {
                    usage();
                }
                let common = finish_common_tunnel(args)?;
                let listen_addr = parse_socket_addr(&listen_host, listen_port, "listen");
                let expose_addr = parse_socket_addr(&expose_host, expose_port, "expose");
                if let Err(e) = run_reverse_entry(ReverseEntryConfig {
                    server: ServerConfig {
                        listen_addr,
                        backend_addr: expose_addr,
                        psk: common.psk,
                        stun_scope: common.stun_scope,
                        cipher_pref: common.cipher_pref,
                        dtls_required: common.dtls_enabled,
                        dtls_min_version: common.dtls_min_version,
                        workers: common.workers,
                        max_sessions: common.max_sessions,
                        wan_mtu: common.wan_mtu,
                        udp_batch: common.udp_batch,
                        idle_timeout_secs: common.idle_timeout_secs,
                        stats_interval_secs: common.stats_interval_secs,
                        wire_audit_file,
                        telemetry: common.telemetry,
                        quiet: false,
                        stop: Some(install_shutdown_handler()),
                    },
                    expose_addr,
                }) {
                    eprintln!("reverse entry error: {}", e);
                    process::exit(1);
                }
            } else {
                let server_host: String = args.value_from_str("--server-host")?;
                let server_port: u16 = args
                    .opt_value_from_str("--server-port")?
                    .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
                let backend_host: String = args
                    .opt_value_from_str("--backend-host")?
                    .unwrap_or_else(|| DEFAULT_BACKEND_HOST.into());
                let backend_port: u16 = args.value_from_str("--backend-port")?;
                let rotate_interval_secs: u64 =
                    args.opt_value_from_str("--rotate-interval")?.unwrap_or(0);
                let rotate_bytes_mb: Option<u64> = args.opt_value_from_str("--rotate-bytes")?;
                let retry_ms: u64 = args
                    .opt_value_from_str("--retry-ms")?
                    .unwrap_or(DEFAULT_CLIENT_RETRY_MS);
                let max_retries: u32 = args
                    .opt_value_from_str("--max-retries")?
                    .unwrap_or(DEFAULT_CLIENT_MAX_RETRIES);
                let keepalive_secs: u64 = args
                    .opt_value_from_str("--keepalive")?
                    .unwrap_or(DEFAULT_CLIENT_KEEPALIVE_SECS);
                let lane_hunt_flag = args.contains("--lane-hunt");
                let lane_probes_opt: Option<usize> = args.opt_value_from_str("--lane-probes")?;
                let lane_rounds_opt: Option<usize> = args.opt_value_from_str("--lane-rounds")?;
                let lane_target_rtt_opt: Option<u64> =
                    args.opt_value_from_str("--lane-target-rtt")?;
                let lane_cooldown_opt: Option<u64> = args.opt_value_from_str("--lane-cooldown")?;
                let lane_enabled = lane_hunt_flag
                    || lane_probes_opt.is_some_and(|p| p > 1)
                    || lane_target_rtt_opt.is_some_and(|t| t > 0);
                let lane_hunt = LaneHuntConfig {
                    enabled: lane_enabled,
                    probes: lane_probes_opt.unwrap_or(DEFAULT_LANE_PROBES),
                    max_rounds: lane_rounds_opt.unwrap_or(DEFAULT_LANE_ROUNDS),
                    target_rtt_ms: lane_target_rtt_opt.unwrap_or(0),
                    degrade_cooldown_secs: lane_cooldown_opt
                        .unwrap_or(DEFAULT_LANE_DEGRADE_COOLDOWN_SECS),
                }
                .normalized();
                if server_host.is_empty() || backend_port == 0 {
                    usage();
                }
                let common = finish_common_tunnel(args)?;
                let rotate_max_bytes = match rotate_bytes_mb {
                    Some(mb) => mb.saturating_mul(MIB),
                    None if rotate_interval_secs > 0 => DEFAULT_ROTATE_BYTE_BUDGET_MIB * MIB,
                    None => 0,
                };
                let server_addr = parse_socket_addr(&server_host, server_port, "server");
                let backend_addr = parse_socket_addr(&backend_host, backend_port, "backend");
                if let Err(e) = run_reverse_agent(ReverseAgentConfig {
                    client: ClientConfig {
                        listen_addr: backend_addr,
                        server_addr,
                        psk: common.psk,
                        stun_scope: common.stun_scope,
                        cipher_pref: common.cipher_pref,
                        dtls_decoy: common.dtls_enabled,
                        dtls_min_version: common.dtls_min_version,
                        rotate_interval_secs,
                        rotate_max_bytes,
                        rotate_cooldown_secs: DEFAULT_ROTATE_COOLDOWN_SECS,
                        workers: common.workers,
                        max_sessions: common.max_sessions,
                        wan_mtu: common.wan_mtu,
                        udp_batch: common.udp_batch,
                        retry_ms,
                        max_retries,
                        keepalive_secs,
                        idle_timeout_secs: common.idle_timeout_secs,
                        stats_interval_secs: common.stats_interval_secs,
                        lane_hunt,
                        telemetry: common.telemetry,
                        quiet: false,
                        stop: Some(install_shutdown_handler()),
                    },
                    backend_addr,
                }) {
                    eprintln!("reverse agent error: {}", e);
                    process::exit(1);
                }
            }
        }
        "bypass" => {
            let is_responder = args.contains("--responder");
            if is_responder {
                let listen_host: String = args
                    .opt_value_from_str("--listen-host")?
                    .unwrap_or_else(|| DEFAULT_CLIENT_LISTEN_HOST.into());
                let listen_port: u16 = args
                    .opt_value_from_str("--listen-port")?
                    .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
                let common = finish_common_tunnel(args)?;
                let listen_addr = parse_socket_addr(&listen_host, listen_port, "listen");
                if let Err(e) = run_bypass_responder(BypassResponderConfig {
                    listen_addr,
                    psk: common.psk,
                    stun_scope: common.stun_scope,
                    workers: common.workers,
                    wan_mtu: common.wan_mtu,
                    udp_batch: common.udp_batch,
                    stats_interval_secs: common.stats_interval_secs,
                    telemetry: common.telemetry,
                    quiet: false,
                    stop: Some(install_shutdown_handler()),
                }) {
                    eprintln!("bypass responder error: {}", e);
                    process::exit(1);
                }
            } else {
                let listen_host: String = args
                    .opt_value_from_str("--listen-host")?
                    .unwrap_or_else(|| DEFAULT_CLIENT_LISTEN_HOST.into());
                let listen_port: u16 = args
                    .opt_value_from_str("--listen-port")?
                    .unwrap_or(DEFAULT_CLIENT_LISTEN_PORT);
                let server_host: String = args.value_from_str("--server-host")?;
                let server_port: u16 = args
                    .opt_value_from_str("--server-port")?
                    .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
                let rotate_interval_secs: u64 =
                    args.opt_value_from_str("--rotate-interval")?.unwrap_or(0);
                let retry_ms: u64 = args
                    .opt_value_from_str("--retry-ms")?
                    .unwrap_or(DEFAULT_CLIENT_RETRY_MS);
                let max_retries: u32 = args.opt_value_from_str("--max-retries")?.unwrap_or(2);
                let keepalive_secs: u64 = args
                    .opt_value_from_str("--keepalive")?
                    .unwrap_or(DEFAULT_CLIENT_KEEPALIVE_SECS);
                let _ = args.contains("--lane-hunt");
                let no_lane_hunt = args.contains("--no-lane-hunt");
                let lane_probes_opt: Option<usize> = args.opt_value_from_str("--lane-probes")?;
                let lane_rounds_opt: Option<usize> = args.opt_value_from_str("--lane-rounds")?;
                let lane_target_rtt_opt: Option<u64> =
                    args.opt_value_from_str("--lane-target-rtt")?;
                let lane_cooldown_opt: Option<u64> = args.opt_value_from_str("--lane-cooldown")?;
                let lane_hunt = LaneHuntConfig {
                    enabled: !no_lane_hunt,
                    probes: lane_probes_opt.unwrap_or(DEFAULT_LANE_PROBES),
                    max_rounds: lane_rounds_opt.unwrap_or(DEFAULT_LANE_ROUNDS),
                    target_rtt_ms: lane_target_rtt_opt.unwrap_or(0),
                    degrade_cooldown_secs: lane_cooldown_opt
                        .unwrap_or(DEFAULT_LANE_DEGRADE_COOLDOWN_SECS),
                }
                .normalized();
                if server_host.is_empty() {
                    usage();
                }
                let common = finish_common_tunnel(args)?;
                let listen_addr = parse_socket_addr(&listen_host, listen_port, "listen");
                let server_addr = parse_socket_addr(&server_host, server_port, "server");
                if let Err(e) = run_bypass(BypassConfig {
                    listen_addr,
                    server_addr,
                    psk: common.psk,
                    stun_scope: common.stun_scope,
                    rotate_interval_secs,
                    workers: common.workers,
                    max_sessions: common.max_sessions,
                    wan_mtu: common.wan_mtu,
                    udp_batch: common.udp_batch,
                    retry_ms,
                    max_retries,
                    keepalive_secs,
                    idle_timeout_secs: common.idle_timeout_secs,
                    stats_interval_secs: common.stats_interval_secs,
                    lane_hunt,
                    telemetry: common.telemetry,
                    quiet: false,
                    stop: Some(install_shutdown_handler()),
                }) {
                    eprintln!("bypass error: {}", e);
                    process::exit(1);
                }
            }
        }
        #[cfg(feature = "embedded-proxy")]
        "proxy" => {
            let is_client = args.contains("--client");
            let is_server = args.contains("--server");
            let is_reverse = args.contains("--reverse");
            if is_client == is_server {
                eprintln!("proxy requires exactly one of --client or --server");
                usage();
            }
            if is_server && !is_reverse {
                let listen_host: String = args
                    .opt_value_from_str("--listen-host")?
                    .unwrap_or_else(|| DEFAULT_SERVER_LISTEN_HOST.into());
                let listen_port: u16 = args
                    .opt_value_from_str("--listen-port")?
                    .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
                let max_up_bps = args
                    .opt_value_from_fn("--max-up", parse_bandwidth_bps)?
                    .unwrap_or(DEFAULT_PROXY_MAX_BPS);
                let max_down_bps = args
                    .opt_value_from_fn("--max-down", parse_bandwidth_bps)?
                    .unwrap_or(DEFAULT_PROXY_MAX_BPS);
                let proxy_mtu: Option<u16> = args.opt_value_from_str("--proxy-mtu")?;
                let acl_allow: Vec<AclRule> = args.values_from_fn("--acl-allow", AclRule::parse)?;
                let acl_deny: Vec<AclRule> = args.values_from_fn("--acl-deny", AclRule::parse)?;
                let allow_private = args.contains("--allow-private");
                let outbound_ipv4_only = args.contains("--outbound-ipv4-only");
                let wire_audit_file: Option<String> =
                    args.opt_value_from_str("--wire-audit-file")?;
                let common = finish_common_tunnel(args)?;
                let listen_addr = parse_socket_addr(&listen_host, listen_port, "listen");
                if let Err(e) = run_proxy_server(ProxyServerConfig {
                    server: ServerConfig {
                        listen_addr,
                        backend_addr: listen_addr,
                        psk: common.psk,
                        stun_scope: common.stun_scope,
                        cipher_pref: common.cipher_pref,
                        dtls_required: common.dtls_enabled,
                        dtls_min_version: common.dtls_min_version,
                        workers: common.workers,
                        max_sessions: common.max_sessions,
                        wan_mtu: common.wan_mtu,
                        udp_batch: common.udp_batch,
                        idle_timeout_secs: common.idle_timeout_secs,
                        stats_interval_secs: common.stats_interval_secs,
                        wire_audit_file,
                        telemetry: common.telemetry,
                        quiet: false,
                        stop: Some(install_shutdown_handler()),
                    },
                    max_up_bps,
                    max_down_bps,
                    acl: AclConfig {
                        allow: acl_allow,
                        deny: acl_deny,
                        reject_private: !allow_private,
                        outbound_ipv4_only,
                    },
                    proxy_mtu,
                }) {
                    eprintln!("proxy server error: {}", e);
                    process::exit(1);
                }
            } else if is_server && is_reverse {
                let server_host: String = args.value_from_str("--server-host")?;
                let server_port: u16 = args
                    .opt_value_from_str("--server-port")?
                    .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
                let max_up_bps = args
                    .opt_value_from_fn("--max-up", parse_bandwidth_bps)?
                    .unwrap_or(DEFAULT_PROXY_MAX_BPS);
                let max_down_bps = args
                    .opt_value_from_fn("--max-down", parse_bandwidth_bps)?
                    .unwrap_or(DEFAULT_PROXY_MAX_BPS);
                let proxy_mtu: Option<u16> = args.opt_value_from_str("--proxy-mtu")?;
                let acl_allow: Vec<AclRule> = args.values_from_fn("--acl-allow", AclRule::parse)?;
                let acl_deny: Vec<AclRule> = args.values_from_fn("--acl-deny", AclRule::parse)?;
                let allow_private = args.contains("--allow-private");
                let outbound_ipv4_only = args.contains("--outbound-ipv4-only");
                let rotate_interval_secs: u64 =
                    args.opt_value_from_str("--rotate-interval")?.unwrap_or(0);
                let rotate_bytes_mb: Option<u64> = args.opt_value_from_str("--rotate-bytes")?;
                let retry_ms: u64 = args
                    .opt_value_from_str("--retry-ms")?
                    .unwrap_or(DEFAULT_CLIENT_RETRY_MS);
                let max_retries: u32 = args
                    .opt_value_from_str("--max-retries")?
                    .unwrap_or(DEFAULT_CLIENT_MAX_RETRIES);
                let keepalive_secs: u64 = args
                    .opt_value_from_str("--keepalive")?
                    .unwrap_or(DEFAULT_CLIENT_KEEPALIVE_SECS);
                let lane_hunt_flag = args.contains("--lane-hunt");
                let lane_probes_opt: Option<usize> = args.opt_value_from_str("--lane-probes")?;
                let lane_rounds_opt: Option<usize> = args.opt_value_from_str("--lane-rounds")?;
                let lane_target_rtt_opt: Option<u64> =
                    args.opt_value_from_str("--lane-target-rtt")?;
                let lane_cooldown_opt: Option<u64> = args.opt_value_from_str("--lane-cooldown")?;
                let lane_enabled = lane_hunt_flag
                    || lane_probes_opt.is_some_and(|p| p > 1)
                    || lane_target_rtt_opt.is_some_and(|t| t > 0);
                let lane_hunt = LaneHuntConfig {
                    enabled: lane_enabled,
                    probes: lane_probes_opt.unwrap_or(DEFAULT_LANE_PROBES),
                    max_rounds: lane_rounds_opt.unwrap_or(DEFAULT_LANE_ROUNDS),
                    target_rtt_ms: lane_target_rtt_opt.unwrap_or(0),
                    degrade_cooldown_secs: lane_cooldown_opt
                        .unwrap_or(DEFAULT_LANE_DEGRADE_COOLDOWN_SECS),
                }
                .normalized();
                if server_host.is_empty() {
                    eprintln!("proxy --server --reverse requires --server-host");
                    usage();
                }
                let common = finish_common_tunnel(args)?;
                let rotate_max_bytes = match rotate_bytes_mb {
                    Some(mb) => mb.saturating_mul(MIB),
                    None if rotate_interval_secs > 0 => DEFAULT_ROTATE_BYTE_BUDGET_MIB * MIB,
                    None => 0,
                };
                let server_addr = parse_socket_addr(&server_host, server_port, "server");
                if let Err(e) = run_proxy_server_reverse(ReverseProxyServerConfig {
                    client: ClientConfig {
                        listen_addr: server_addr,
                        server_addr,
                        psk: common.psk,
                        stun_scope: common.stun_scope,
                        cipher_pref: common.cipher_pref,
                        dtls_decoy: common.dtls_enabled,
                        dtls_min_version: common.dtls_min_version,
                        rotate_interval_secs,
                        rotate_max_bytes,
                        rotate_cooldown_secs: DEFAULT_ROTATE_COOLDOWN_SECS,
                        workers: common.workers,
                        max_sessions: common.max_sessions,
                        wan_mtu: common.wan_mtu,
                        udp_batch: common.udp_batch,
                        retry_ms,
                        max_retries,
                        keepalive_secs,
                        idle_timeout_secs: common.idle_timeout_secs,
                        stats_interval_secs: common.stats_interval_secs,
                        lane_hunt,
                        telemetry: common.telemetry,
                        quiet: false,
                        stop: Some(install_shutdown_handler()),
                    },
                    max_up_bps,
                    max_down_bps,
                    acl: AclConfig {
                        allow: acl_allow,
                        deny: acl_deny,
                        reject_private: !allow_private,
                        outbound_ipv4_only,
                    },
                    proxy_mtu,
                }) {
                    eprintln!("proxy reverse server error: {}", e);
                    process::exit(1);
                }
            } else if is_reverse {
                let listen_host: String = args
                    .opt_value_from_str("--listen-host")?
                    .unwrap_or_else(|| DEFAULT_SERVER_LISTEN_HOST.into());
                let listen_port: u16 = args
                    .opt_value_from_str("--listen-port")?
                    .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
                let no_socks = args.contains("--no-socks");
                let socks_listen_opt: Option<SocketAddr> =
                    args.opt_value_from_str("--socks-listen")?;
                let tcp_forwards: Vec<TcpForwardRule> =
                    args.values_from_fn("--tcp-forward", parse_tcp_forward_rule)?;
                let up_bps = args
                    .opt_value_from_fn("--up", parse_bandwidth_bps)?
                    .unwrap_or(DEFAULT_PROXY_UP_BPS);
                let down_bps = args
                    .opt_value_from_fn("--down", parse_bandwidth_bps)?
                    .unwrap_or(DEFAULT_PROXY_DOWN_BPS);
                let proxy_mtu: Option<u16> = args.opt_value_from_str("--proxy-mtu")?;
                let wire_audit_file: Option<String> =
                    args.opt_value_from_str("--wire-audit-file")?;
                let socks_listen = if no_socks {
                    None
                } else {
                    Some(socks_listen_opt.unwrap_or_else(|| {
                        parse_socket_addr(
                            DEFAULT_CLIENT_LISTEN_HOST,
                            DEFAULT_PROXY_SOCKS_PORT,
                            "socks-listen",
                        )
                    }))
                };
                if socks_listen.is_none() && tcp_forwards.is_empty() {
                    eprintln!("proxy --client --reverse requires at least --socks-listen or --tcp-forward");
                    usage();
                }
                let common = finish_common_tunnel(args)?;
                let listen_addr = parse_socket_addr(&listen_host, listen_port, "listen");
                if let Err(e) = run_proxy_client_reverse(ReverseProxyClientConfig {
                    server: ServerConfig {
                        listen_addr,
                        backend_addr: listen_addr,
                        psk: common.psk,
                        stun_scope: common.stun_scope,
                        cipher_pref: common.cipher_pref,
                        dtls_required: common.dtls_enabled,
                        dtls_min_version: common.dtls_min_version,
                        workers: common.workers,
                        max_sessions: common.max_sessions,
                        wan_mtu: common.wan_mtu,
                        udp_batch: common.udp_batch,
                        idle_timeout_secs: common.idle_timeout_secs,
                        stats_interval_secs: common.stats_interval_secs,
                        wire_audit_file,
                        telemetry: common.telemetry,
                        quiet: false,
                        stop: Some(install_shutdown_handler()),
                    },
                    socks_listen,
                    tcp_forwards,
                    up_bps,
                    down_bps,
                    proxy_mtu,
                }) {
                    eprintln!("proxy reverse client error: {}", e);
                    process::exit(1);
                }
            } else {
                let server_host: String = args.value_from_str("--server-host")?;
                let server_port: u16 = args
                    .opt_value_from_str("--server-port")?
                    .unwrap_or(DEFAULT_SERVER_LISTEN_PORT);
                let no_socks = args.contains("--no-socks");
                let socks_listen_opt: Option<SocketAddr> =
                    args.opt_value_from_str("--socks-listen")?;
                let tcp_forwards: Vec<TcpForwardRule> =
                    args.values_from_fn("--tcp-forward", parse_tcp_forward_rule)?;
                let up_bps = args
                    .opt_value_from_fn("--up", parse_bandwidth_bps)?
                    .unwrap_or(DEFAULT_PROXY_UP_BPS);
                let down_bps = args
                    .opt_value_from_fn("--down", parse_bandwidth_bps)?
                    .unwrap_or(DEFAULT_PROXY_DOWN_BPS);
                let proxy_mtu: Option<u16> = args.opt_value_from_str("--proxy-mtu")?;
                let rotate_interval_secs: u64 =
                    args.opt_value_from_str("--rotate-interval")?.unwrap_or(0);
                let rotate_bytes_mb: Option<u64> = args.opt_value_from_str("--rotate-bytes")?;
                let retry_ms: u64 = args
                    .opt_value_from_str("--retry-ms")?
                    .unwrap_or(DEFAULT_CLIENT_RETRY_MS);
                let max_retries: u32 = args
                    .opt_value_from_str("--max-retries")?
                    .unwrap_or(DEFAULT_CLIENT_MAX_RETRIES);
                let keepalive_secs: u64 = args
                    .opt_value_from_str("--keepalive")?
                    .unwrap_or(DEFAULT_CLIENT_KEEPALIVE_SECS);
                let lane_hunt_flag = args.contains("--lane-hunt");
                let lane_probes_opt: Option<usize> = args.opt_value_from_str("--lane-probes")?;
                let lane_rounds_opt: Option<usize> = args.opt_value_from_str("--lane-rounds")?;
                let lane_target_rtt_opt: Option<u64> =
                    args.opt_value_from_str("--lane-target-rtt")?;
                let lane_cooldown_opt: Option<u64> = args.opt_value_from_str("--lane-cooldown")?;
                let hot_config_path: Option<String> = args.opt_value_from_str("--hot-config")?;
                let hot_switch_timeout_secs: u64 = args
                    .opt_value_from_str("--hot-switch-timeout")?
                    .unwrap_or(0);
                let lane_enabled = lane_hunt_flag
                    || lane_probes_opt.is_some_and(|p| p > 1)
                    || lane_target_rtt_opt.is_some_and(|t| t > 0);
                let lane_hunt = LaneHuntConfig {
                    enabled: lane_enabled,
                    probes: lane_probes_opt.unwrap_or(DEFAULT_LANE_PROBES),
                    max_rounds: lane_rounds_opt.unwrap_or(DEFAULT_LANE_ROUNDS),
                    target_rtt_ms: lane_target_rtt_opt.unwrap_or(0),
                    degrade_cooldown_secs: lane_cooldown_opt
                        .unwrap_or(DEFAULT_LANE_DEGRADE_COOLDOWN_SECS),
                }
                .normalized();
                let socks_listen = if no_socks {
                    None
                } else {
                    Some(socks_listen_opt.unwrap_or_else(|| {
                        parse_socket_addr(
                            DEFAULT_CLIENT_LISTEN_HOST,
                            DEFAULT_PROXY_SOCKS_PORT,
                            "socks-listen",
                        )
                    }))
                };
                if server_host.is_empty() || (socks_listen.is_none() && tcp_forwards.is_empty()) {
                    eprintln!("proxy --client requires --server-host and at least --socks-listen or --tcp-forward");
                    usage();
                }
                let common = finish_common_tunnel(args)?;
                let rotate_max_bytes = match rotate_bytes_mb {
                    Some(mb) => mb.saturating_mul(MIB),
                    None if rotate_interval_secs > 0 => DEFAULT_ROTATE_BYTE_BUDGET_MIB * MIB,
                    None => 0,
                };
                let server_addr = parse_socket_addr(&server_host, server_port, "server");
                if hot_config_path.is_some() {
                    install_reload_handler();
                }
                if let Err(e) = run_proxy_client(ProxyClientConfig {
                    client: ClientConfig {
                        listen_addr: socks_listen.unwrap_or_else(|| tcp_forwards[0].listen),
                        server_addr,
                        psk: common.psk,
                        stun_scope: common.stun_scope,
                        cipher_pref: common.cipher_pref,
                        dtls_decoy: common.dtls_enabled,
                        dtls_min_version: common.dtls_min_version,
                        rotate_interval_secs,
                        rotate_max_bytes,
                        rotate_cooldown_secs: DEFAULT_ROTATE_COOLDOWN_SECS,
                        workers: common.workers,
                        max_sessions: common.max_sessions,
                        wan_mtu: common.wan_mtu,
                        udp_batch: common.udp_batch,
                        retry_ms,
                        max_retries,
                        keepalive_secs,
                        idle_timeout_secs: common.idle_timeout_secs,
                        stats_interval_secs: common.stats_interval_secs,
                        lane_hunt,
                        telemetry: common.telemetry,
                        quiet: false,
                        stop: Some(install_shutdown_handler()),
                    },
                    socks_listen,
                    tcp_forwards,
                    up_bps,
                    down_bps,
                    proxy_mtu,
                    hot_config_path,
                    reload_trigger: None,
                    hot_switch_timeout_secs,
                }) {
                    eprintln!("proxy client error: {}", e);
                    process::exit(1);
                }
            }
        }
        #[cfg(not(feature = "embedded-proxy"))]
        "proxy" => {
            eprintln!("This binary was built without the 'embedded-proxy' feature.");
            process::exit(2);
        }
        _ => usage(),
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Argument error: {}", e);
        usage();
    }
}
