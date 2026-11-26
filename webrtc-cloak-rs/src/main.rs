//! CLI 参数解析与子命令分发入口。

mod bench_tools;
mod client;
mod constants;
mod protocol;
mod selftest;
mod server;
mod telemetry;

use crate::bench_tools::{print_cpu_info, run_bench, run_loadgen, run_sink};
use crate::client::{run_client, ClientConfig};
use crate::constants::{DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_ROTATE_COOLDOWN_SECS, DEFAULT_WAN_MTU};
use crate::protocol::{
    detect_cpu_accel, install_shutdown_handler, CipherPref, CipherSuite, DtlsMinVersion,
};
use crate::selftest::{run_selftest, SelftestOptions};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use pico_args::Arguments;
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process;

/// 1 MiB 字节数，用于将 `--rotate-bytes` 参数换算为字节。
const MIB: u64 = 1024 * 1024;
/// 客户端本地默认监听地址。
const DEFAULT_CLIENT_LISTEN_HOST: &str = "127.0.0.1";
/// 客户端本地默认监听端口。
const DEFAULT_CLIENT_LISTEN_PORT: u16 = 19543;
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
    cipher_pref: CipherPref,
    dtls_min_version: DtlsMinVersion,
    workers: usize,
    max_sessions: usize,
    wan_mtu: usize,
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
    format!("{}:{}", host, port).parse().unwrap_or_else(|e| {
        eprintln!("Invalid {} address {}:{}: {}", label, host, port, e);
        process::exit(2);
    })
}

fn usage() -> ! {
    eprintln!(
        "Usage:\n  \
         webrtc-cloak cpu\n  \
         webrtc-cloak client --listen-host 127.0.0.1 --listen-port 19543 --server-host <IP> --server-port 19643 (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version auto|1.2|1.3] [--rotate-interval 0] [--rotate-bytes <MB>] [--workers 1|auto] [--max-sessions 4096] [--mtu 1488] [--keepalive 5] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak server --listen-host 0.0.0.0 --listen-port 19643 --backend-host 127.0.0.1 --backend-port <PORT> (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version auto|1.2|1.3] [--workers 1|auto] [--max-sessions 4096] [--mtu 1488] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak bench [count] [payload_bytes] [all|aes-gcm|chacha20|blake2b]\n  \
         webrtc-cloak selftest --server-host <IP|HOST> [--server-port 19643] (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version auto|1.2|1.3] [--mtu 1488] [--count 20] [--no-probe] [--no-color] [--json]\n  \
         webrtc-cloak selftest [--local] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version auto|1.2|1.3] [--mtu 1488] [--no-color] [--json]"
    );
    process::exit(2);
}

fn resolve_psk(psk_arg: Option<String>, psk_file: Option<String>) -> Vec<u8> {
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
    if let Some(k) = psk_arg.filter(|s| !s.is_empty()) {
        return k.into_bytes();
    }
    if let Ok(env_k) = env::var("WEBRTC_CLOAK_PSK") {
        let trimmed = env_k.trim();
        if !trimmed.is_empty() {
            return trimmed.as_bytes().to_vec();
        }
    }
    usage();
}

fn check_no_extra(args: Arguments) {
    let rest = args.finish();
    if !rest.is_empty() {
        eprintln!("Unknown argument(s): {:?}", rest);
        usage();
    }
}

fn finish_common_tunnel(mut args: Arguments) -> Result<CommonTunnelArgs, pico_args::Error> {
    let psk_arg: Option<String> = args.opt_value_from_str("--psk")?;
    let psk_file: Option<String> = args.opt_value_from_str("--psk-file")?;
    let cipher_pref = args
        .opt_value_from_fn("--cipher", parse_cipher_pref)?
        .unwrap_or(CipherPref::Auto);
    let dtls_min_version = args
        .opt_value_from_fn("--dtls-min-version", parse_dtls_min_version)?
        .unwrap_or(DtlsMinVersion::Auto);
    let workers = args
        .opt_value_from_fn("--workers", parse_workers)?
        .unwrap_or(DEFAULT_WORKERS);
    let max_sessions = args
        .opt_value_from_str::<_, usize>("--max-sessions")?
        .unwrap_or(DEFAULT_MAX_SESSIONS)
        .max(1);
    let wan_mtu = args.opt_value_from_str("--mtu")?.unwrap_or(DEFAULT_WAN_MTU);
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
    Ok(CommonTunnelArgs {
        psk: resolve_psk(psk_arg, psk_file),
        cipher_pref,
        dtls_min_version,
        workers,
        max_sessions,
        wan_mtu,
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
                    let target_str = format!("{}:{}", host, server_port);
                    let resolved = match target_str.to_socket_addrs() {
                        Ok(mut it) => match it.find(|a| a.is_ipv4()) {
                            Some(a) => a,
                            None => {
                                eprintln!("Failed to resolve IPv4 address for {}", target_str);
                                process::exit(2);
                            }
                        },
                        Err(e) => {
                            eprintln!("Failed to resolve {}: {}", target_str, e);
                            process::exit(2);
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
                cipher_pref: common.cipher_pref,
                dtls_decoy: common.dtls_enabled,
                dtls_min_version: common.dtls_min_version,
                rotate_interval_secs,
                rotate_max_bytes,
                rotate_cooldown_secs: DEFAULT_ROTATE_COOLDOWN_SECS,
                workers: common.workers,
                max_sessions: common.max_sessions,
                wan_mtu: common.wan_mtu,
                retry_ms,
                max_retries,
                keepalive_secs,
                idle_timeout_secs: common.idle_timeout_secs,
                stats_interval_secs: common.stats_interval_secs,
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
                cipher_pref: common.cipher_pref,
                dtls_required: common.dtls_enabled,
                dtls_min_version: common.dtls_min_version,
                workers: common.workers,
                max_sessions: common.max_sessions,
                wan_mtu: common.wan_mtu,
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
