//! CLI 参数解析与子命令分发入口。

mod bench_tools;
mod client;
mod protocol;
mod selftest;
mod server;
mod telemetry;

use crate::bench_tools::{print_cpu_info, run_bench, run_loadgen, run_sink};
use crate::client::{run_client, ClientConfig};
use crate::protocol::{
    detect_cpu_accel, trigger_shutdown_wakers, CipherPref, CipherSuite, DtlsMinVersion,
    DEFAULT_WAN_MTU,
};
use crate::selftest::{run_selftest, SelftestOptions};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn install_shutdown_handler() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        flag.store(true, Ordering::SeqCst);
        trigger_shutdown_wakers();
    });
    stop
}

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

fn parse_dtls_min_version(s: &str) -> DtlsMinVersion {
    match s {
        "auto" | "1.2" => DtlsMinVersion::Auto,
        "1.3" => DtlsMinVersion::V13Only,
        other => {
            eprintln!(
                "Unknown --dtls-min-version: {} (expected auto, 1.2, or 1.3)",
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
         webrtc-cloak client --listen-host 127.0.0.1 --listen-port 19543 --server-host <IP> --server-port 19643 (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version auto|1.2|1.3] [--rotate-interval 0] [--rotate-bytes <MB>] [--workers 1|auto] [--max-sessions 4096] [--mtu 1488] [--keepalive 5] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak server --listen-host 0.0.0.0 --listen-port 19643 --backend-host 127.0.0.1 --backend-port <PORT> (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version auto|1.2|1.3] [--workers 1|auto] [--max-sessions 4096] [--mtu 1488] [--idle-timeout 120] [--status-file <PATH>] [--status-http 127.0.0.1:PORT] [--status-interval 5] [--no-dtls-decoy]\n  \
         webrtc-cloak bench [count] [payload_bytes] [all|aes-gcm|chacha20|blake2b]\n  \
         webrtc-cloak selftest --server-host <IP|HOST> [--server-port 19643] (--psk <KEY> | --psk-file <PATH> | env WEBRTC_CLOAK_PSK) [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version auto|1.2|1.3] [--mtu 1488] [--count 20] [--no-probe] [--no-color] [--json]\n  \
         webrtc-cloak selftest [--local] [--cipher auto|aes-gcm|chacha20|blake2b] [--dtls-min-version auto|1.2|1.3] [--mtu 1488] [--no-color] [--json]"
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "cpu" => {
            print_cpu_info();
        }
        "selftest" => {
            let mut opts = SelftestOptions::default();
            let mut server_host = String::new();
            let mut server_port: u16 = 19643;
            let mut psk = String::new();
            let mut psk_file: Option<String> = None;
            let mut force_local = false;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--server-host" => {
                        i += 1;
                        if i >= args.len() { usage(); }
                        server_host = args[i].clone();
                    }
                    "--server-port" => {
                        i += 1;
                        if i >= args.len() { usage(); }
                        server_port = args[i].parse().unwrap_or(19643);
                    }
                    "--psk" => {
                        i += 1;
                        if i >= args.len() { usage(); }
                        psk = args[i].clone();
                    }
                    "--psk-file" => {
                        i += 1;
                        if i >= args.len() { usage(); }
                        psk_file = Some(args[i].clone());
                    }
                    "--count" => {
                        i += 1;
                        if i >= args.len() { usage(); }
                        opts.probe_count = args[i].parse::<usize>().unwrap_or(20).clamp(5, 200);
                    }
                    "--no-probe" => {
                        opts.active_probes = false;
                    }
                    "--local" => {
                        force_local = true;
                    }
                    "--cipher" => {
                        i += 1;
                        if i >= args.len() { usage(); }
                        opts.cipher_pref = parse_cipher_pref(&args[i]);
                    }
                    "--dtls-min-version" => {
                        i += 1;
                        if i >= args.len() { usage(); }
                        opts.dtls_min_version = parse_dtls_min_version(&args[i]);
                    }
                    "--mtu" => {
                        i += 1;
                        if i >= args.len() { usage(); }
                        opts.wan_mtu = args[i].parse::<usize>().unwrap_or(DEFAULT_WAN_MTU);
                    }
                    "--no-color" => {
                        opts.color = false;
                    }
                    "--json" => {
                        opts.json = true;
                    }
                    other => {
                        eprintln!("Unknown selftest flag: {}", other);
                        usage();
                    }
                }
                i += 1;
            }
            if !force_local && !server_host.is_empty() {
                let target_str = format!("{}:{}", server_host, server_port);
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
            if !run_selftest(opts) {
                process::exit(1);
            }
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
            let mut dtls_min_version = DtlsMinVersion::Auto;
            let mut rotate_interval_secs: u64 = 0;
            let mut rotate_bytes_mb: Option<u64> = None;
            let mut workers: usize = 1;
            let mut max_sessions: usize = 4096;
            let mut wan_mtu: usize = DEFAULT_WAN_MTU;
            let mut retry_ms: u64 = 300;
            let mut max_retries: u32 = 8;
            let mut keepalive_secs: u64 = 5; // RFC 7675 §5.1 Consent Freshness (5s ± 20%)
            let mut idle_timeout_secs: u64 = 120;
            let mut stats_interval_secs: u64 = 10;
            let mut telemetry = TelemetryConfig::default();

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
                    "--dtls-min-version" => { i += 1; dtls_min_version = parse_dtls_min_version(&args[i]); }
                    "--rotate-interval" => { i += 1; rotate_interval_secs = args[i].parse().unwrap(); }
                    "--rotate-bytes" => { i += 1; rotate_bytes_mb = Some(args[i].parse().unwrap()); }
                    "--workers" => { i += 1; workers = parse_workers(&args[i]); }
                    "--max-sessions" => { i += 1; max_sessions = args[i].parse::<usize>().unwrap().max(1); }
                    "--mtu" => { i += 1; wan_mtu = args[i].parse::<usize>().unwrap(); }
                    "--no-dtls-decoy" => { dtls_decoy = false; }
                    "--retry-ms" => { i += 1; retry_ms = args[i].parse().unwrap(); }
                    "--max-retries" => { i += 1; max_retries = args[i].parse().unwrap(); }
                    "--keepalive" => { i += 1; keepalive_secs = args[i].parse().unwrap(); }
                    "--idle-timeout" => { i += 1; idle_timeout_secs = args[i].parse().unwrap(); }
                    "--stats-interval" => { i += 1; stats_interval_secs = args[i].parse().unwrap(); }
                    "--status-file" => { i += 1; telemetry.status_file = Some(args[i].clone()); }
                    "--status-http" => {
                        i += 1;
                        telemetry.status_http = Some(args[i].parse().unwrap_or_else(|_| {
                            eprintln!("Invalid --status-http address: {} (expected IP:PORT, e.g. 127.0.0.1:19544)", args[i]);
                            process::exit(2);
                        }));
                    }
                    "--status-interval" => { i += 1; telemetry.status_interval_secs = args[i].parse().unwrap(); }
                    other => { eprintln!("Unknown flag: {}", other); usage(); }
                }
                i += 1;
            }
            if server_host.is_empty() {
                usage();
            }
            let rotate_max_bytes = match rotate_bytes_mb {
                Some(mb) => mb.saturating_mul(1024 * 1024),
                None if rotate_interval_secs > 0 => 1200u64 * 1024 * 1024, // 600..2220 MiB random budget
                None => 0,
            };
            let psk_bytes = resolve_psk(psk, psk_file);
            let listen_addr: SocketAddr = format!("{}:{}", listen_host, listen_port).parse().unwrap();
            let server_addr: SocketAddr = format!("{}:{}", server_host, server_port).parse().unwrap();
            let stop = install_shutdown_handler();
            if let Err(e) = run_client(ClientConfig {
                listen_addr,
                server_addr,
                psk: psk_bytes,
                cipher_pref,
                dtls_decoy,
                dtls_min_version,
                rotate_interval_secs,
                rotate_max_bytes,
                rotate_cooldown_secs: 60,
                workers,
                max_sessions,
                wan_mtu,
                retry_ms,
                max_retries,
                keepalive_secs,
                idle_timeout_secs,
                stats_interval_secs,
                telemetry,
                quiet: false,
                stop: Some(stop),
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
            let mut dtls_min_version = DtlsMinVersion::Auto;
            let mut workers: usize = 1;
            let mut max_sessions: usize = 4096;
            let mut wan_mtu: usize = DEFAULT_WAN_MTU;
            let mut idle_timeout_secs: u64 = 120;
            let mut stats_interval_secs: u64 = 10;
            let mut wire_audit_file: Option<String> = None;
            let mut telemetry = TelemetryConfig::default();

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
                    "--dtls-min-version" => { i += 1; dtls_min_version = parse_dtls_min_version(&args[i]); }
                    "--workers" => { i += 1; workers = parse_workers(&args[i]); }
                    "--max-sessions" => { i += 1; max_sessions = args[i].parse::<usize>().unwrap().max(1); }
                    "--mtu" => { i += 1; wan_mtu = args[i].parse::<usize>().unwrap(); }
                    "--no-dtls-decoy" => { dtls_required = false; }
                    "--idle-timeout" => { i += 1; idle_timeout_secs = args[i].parse().unwrap(); }
                    "--stats-interval" => { i += 1; stats_interval_secs = args[i].parse().unwrap(); }
                    "--wire-audit-file" => { i += 1; wire_audit_file = Some(args[i].clone()); }
                    "--status-file" => { i += 1; telemetry.status_file = Some(args[i].clone()); }
                    "--status-http" => {
                        i += 1;
                        telemetry.status_http = Some(args[i].parse().unwrap_or_else(|_| {
                            eprintln!("Invalid --status-http address: {} (expected IP:PORT, e.g. 127.0.0.1:19644)", args[i]);
                            process::exit(2);
                        }));
                    }
                    "--status-interval" => { i += 1; telemetry.status_interval_secs = args[i].parse().unwrap(); }
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
            let stop = install_shutdown_handler();
            if let Err(e) = run_server(ServerConfig {
                listen_addr,
                backend_addr,
                psk: psk_bytes,
                cipher_pref,
                dtls_required,
                dtls_min_version,
                workers,
                max_sessions,
                wan_mtu,
                idle_timeout_secs,
                stats_interval_secs,
                wire_audit_file,
                telemetry,
                quiet: false,
                stop: Some(stop),
            }) {
                eprintln!("server error: {}", e);
                process::exit(1);
            }
        }
        _ => usage(),
    }
}
