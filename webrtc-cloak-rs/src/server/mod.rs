//! 服务端配置、会话状态定义、路由清理与多线程启动入口。

mod handlers;
mod registry;
mod worker;
mod worker_cmds;
mod worker_io;

use self::registry::SharedV4Registry;
pub(crate) use self::registry::{SeenTxidCache, TxidCheck};
use self::worker::run_server_worker;
use crate::constants::{
    outer_udp_hdr_len, unspecified_addr_for, SOCK_BUF_4MIB, TRICKLE_RATE_15S_BYTES,
};
use crate::protocol::{
    build_dimpl_config_pool_for, detect_cpu_accel, rand_duration_range_ms, CipherPref, CipherSuite,
    DtlsMinVersion, RollingByteWindow, SrtpCloakCipher,
};
use crate::telemetry::{TelemetryConfig, TelemetryHub};
use crate::udp_batch::format_udp_batch_mode;
use dimpl::Dtls;
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Interest, Poll, Token};
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

thread_local! {
    pub(super) static SERVER_QUIET: Cell<bool> = const { Cell::new(false) };
}

/// 未验证的 1-RTT ICE 迁移路径挑战条目存活时间（秒）。
pub(super) const MIGRATION_CHALLENGE_TTL: Duration = Duration::from_secs(5);
/// 1-RTT 迁移完成后继续容忍旧路径 ECMP 乱序尾包的只收引流窗口（秒）。
pub(super) const OLD_PEER_DRAIN_TTL: Duration = Duration::from_secs(5);
/// 单会话每秒最多发出的 `0xFFFD` 路径挑战次数，防止同 PSK 反射放大洪水。
pub(super) const MAX_CHALLENGES_PER_SEC: u8 = 4;
/// MBB 重叠引流期间允许链式转发上行数据包的最大跳数。
pub(super) const MAX_FORWARD_HOPS: u8 = 4;
/// 服务端进入 Ready 后首条 SRTCP 心跳的最小延迟（毫秒）。
pub(super) const SERVER_SRTCP_INIT_MIN_MS: u64 = 300;
/// 服务端进入 Ready 后首条 SRTCP 心跳的最大延迟（毫秒）。
pub(super) const SERVER_SRTCP_INIT_MAX_MS: u64 = 750;
/// 服务端活跃媒体传输期 SRTCP 最小发送间隔（毫秒）。
pub(super) const SERVER_SRTCP_ACTIVE_MIN_MS: u64 = 950;
/// 服务端活跃媒体传输期 SRTCP 最大发送间隔（毫秒）。
pub(super) const SERVER_SRTCP_ACTIVE_MAX_MS: u64 = 1950;
/// `--wire-audit-file` 单次运行最多落盘的外层抓包记录条数。
const WIRE_AUDIT_MAX_PACKETS: usize = 128;

pub(super) struct WireAudit {
    fp: Option<File>,
    count: usize,
}

impl WireAudit {
    pub(super) fn new(path: Option<&String>) -> std::io::Result<Self> {
        let fp = path.map(File::create).transpose()?;
        Ok(Self { fp, count: 0 })
    }

    #[inline]
    pub(super) fn record(&mut self, d_code: u8, payload: &[u8]) {
        if let Some(ref mut f) = self.fp {
            if self.count < WIRE_AUDIT_MAX_PACKETS {
                let _ = f.write_all(&[d_code]);
                let _ = f.write_all(&(payload.len() as u32).to_be_bytes());
                let _ = f.write_all(payload);
                let _ = f.flush();
                self.count += 1;
            }
        }
    }
}

#[inline]
pub(super) fn alloc_token(next_id: &mut usize) -> Token {
    let tok = Token(*next_id);
    *next_id = next_id.wrapping_add(1);
    if *next_id == 0 || *next_id == usize::MAX {
        *next_id = 1;
    }
    tok
}

#[derive(Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub backend_addr: SocketAddr,
    pub psk: Vec<u8>,
    pub cipher_pref: CipherPref,
    pub dtls_required: bool,
    pub dtls_min_version: DtlsMinVersion,
    pub workers: usize,
    pub max_sessions: usize,
    pub wan_mtu: usize,
    pub udp_batch: usize,
    pub idle_timeout_secs: u64,
    pub stats_interval_secs: u64,
    pub wire_audit_file: Option<String>,
    pub telemetry: TelemetryConfig,
    pub quiet: bool,
    pub stop: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ServerState {
    DtlsHandshake,
    Ready,
    /// Closing(deadline, allow_downlink_flush):
    /// When entered due to peer BYE/close_notify, `allow_downlink_flush = true` still delivers
    /// slow in-flight backend replies during the brief 250ms Closing window to the peer's
    /// receive-only drain socket instead of silently dropping them.
    Closing(Instant, bool),
}

pub(super) enum BackendPipe {
    /// Lazily unbound until first Data packet arrives OR atomic `0xFFFC` handover installs old socket.
    Unbound,
    /// Exclusively owned backend UDP socket registered in this worker's `mio::Poll`.
    Owned(MioUdpSocket),
    /// Handed over to a newer MBB session on the SAME worker (chained <=4-hop drain forwarding).
    ForwardLocal {
        target_tok: Token,
        target_ufrag: String,
    },
    /// Handed over to a newer MBB session on ANOTHER worker (chained <=4-hop drain forwarding).
    ForwardRemote {
        target_worker: usize,
        target_ufrag: String,
    },
}

#[derive(Clone, Copy)]
pub(super) struct PendingPathMigration {
    pub(super) cand_addr: SocketAddr,
    pub(super) cand_worker: usize,
    pub(super) nonce: [u8; 8],
    pub(super) epoch: u64,
    pub(super) expires_at: Instant,
}

pub(super) struct ServerSession {
    pub(super) peer_addr: SocketAddr,
    pub(super) old_peer_addr: Option<(SocketAddr, Instant)>,
    pub(super) username: String,
    pub(super) tie_breaker: [u8; 8],
    pub(super) backend: BackendPipe,
    pub(super) backend_lport: u16,
    /// P1-1: Single-use MBB handover lock (idempotent for same `new_ufrag`, blocks double-handover).
    pub(super) handed_over_to: Option<String>,
    pub(super) state: ServerState,
    pub(super) ready_at: Option<Instant>,
    pub(super) stun_key: [u8; 32],
    pub(super) session_key: Option<[u8; 32]>,
    pub(super) mi_key_mig: Option<[u8; 32]>,
    pub(super) path_epoch: u64,
    /// P0-2: Fixed-size <=4-slot candidate table isolating legitimate retries from spoofed racers.
    pub(super) pending_migrations: Vec<PendingPathMigration>,
    /// P0-4: Per-session 0xFFFD challenge rate limiter (`<= MAX_CHALLENGES_PER_SEC` per 1s).
    pub(super) mig_challenge_win: Instant,
    pub(super) mig_challenge_cnt: u8,
    pub(super) ssrc_c2s: u32,
    pub(super) ssrc_s2c: u32,
    pub(super) dtls: Option<Box<Dtls>>,
    pub(super) dtls_resets: u8,
    pub(super) dtls_next_timeout: Option<Instant>,
    pub(super) dtls_suite_id: Option<u16>,
    pub(super) dtls_km: Option<Vec<u8>>,
    pub(super) negotiated_cipher: Option<CipherSuite>,
    pub(super) cipher: Option<SrtpCloakCipher>,
    /// V3-M-03: buffers early 0-RTT SRTP packets arriving before Flight 5 finishes!
    pub(super) early_srtp: VecDeque<Vec<u8>>,
    pub(super) last_data_active: Instant,
    pub(super) last_peer_rx: Instant,
    pub(super) last_active_burst: Instant,
    pub(super) next_srtcp_at: Instant,
    pub(super) rate_15s: RollingByteWindow,
    pub(super) rx_pkts: u64,
    pub(super) rx_pkts_at_last_rtcp: u64,
    pub(super) rx_bytes: u64,
    pub(super) tx_pkts: u64,
    pub(super) tx_pkts_at_last_rtcp: u64,
    pub(super) tx_bytes: u64,
    pub(super) keepalives: u64,
    pub(super) srtcp_tx: u64,
    pub(super) srtcp_rx: u64,
    pub(super) auth_drops: u64,
}

#[inline]
pub(super) fn record_server_media_bytes(sess: &mut ServerSession, now: Instant, bytes: u64) {
    sess.rate_15s.record(now, bytes);
    if sess.rate_15s.bytes_in_window(now) >= TRICKLE_RATE_15S_BYTES {
        sess.last_active_burst = now;
        if sess.next_srtcp_at > now + Duration::from_millis(SERVER_SRTCP_ACTIVE_MAX_MS) {
            sess.next_srtcp_at = now
                + rand_duration_range_ms(SERVER_SRTCP_ACTIVE_MIN_MS, SERVER_SRTCP_ACTIVE_MAX_MS);
        }
    }
}

pub(super) fn make_udp_socket(
    bind_addr: SocketAddr,
    connect_to: Option<SocketAddr>,
    reuse_port: bool,
    buf_bytes: usize,
) -> std::io::Result<MioUdpSocket> {
    let sock = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    let _ = sock.set_reuse_address(true);
    #[cfg(unix)]
    if reuse_port {
        sock.set_reuse_port(true)?;
    }
    #[cfg(not(unix))]
    let _ = reuse_port;
    let _ = sock.set_recv_buffer_size(buf_bytes);
    let _ = sock.set_send_buffer_size(buf_bytes);
    sock.set_nonblocking(true)?;
    sock.bind(&bind_addr.into())?;
    if let Some(target) = connect_to {
        sock.connect(&target.into())?;
    }
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(MioUdpSocket::from_std(std_sock))
}

pub(super) fn log(worker_id: usize, msg: &str) {
    if !SERVER_QUIET.with(|q| q.get()) {
        println!("[server-rs#{}] {}", worker_id, msg);
    }
}

pub(super) fn ensure_owned_backend(
    worker_id: usize,
    tok: Token,
    sess: &mut ServerSession,
    backend_addr: SocketAddr,
    poll: &Poll,
) -> bool {
    if matches!(sess.backend, BackendPipe::Unbound) {
        let bind_any = unspecified_addr_for(backend_addr);
        let mut bs = match make_udp_socket(bind_any, Some(backend_addr), false, SOCK_BUF_4MIB) {
            Ok(s) => s,
            Err(e) => {
                log(worker_id, &format!("backend socket error: {}", e));
                return false;
            }
        };
        let blport = bs.local_addr().map(|a| a.port()).unwrap_or(0);
        if poll
            .registry()
            .register(&mut bs, tok, Interest::READABLE)
            .is_err()
        {
            return false;
        }
        sess.backend = BackendPipe::Owned(bs);
        sess.backend_lport = blport;
    }
    true
}

pub(super) fn deregister_backend(poll: &Poll, backend: &mut BackendPipe) {
    if let BackendPipe::Owned(ref mut sock) = backend {
        let _ = poll.registry().deregister(sock);
    }
}

/// P1-3: Unified route & registry cleanup whenever a session is removed/evicted/rekeyed.
#[allow(clippy::too_many_arguments)]
fn cleanup_session_routes(
    worker_id: usize,
    tok: Token,
    sess: &mut ServerSession,
    poll: &Poll,
    token_by_peer: &mut HashMap<SocketAddr, Token>,
    token_by_ufrag: &mut HashMap<String, Token>,
    local_mig_pending: &mut HashMap<SocketAddr, (Token, Instant)>,
    registry: &SharedV4Registry,
) {
    deregister_backend(poll, &mut sess.backend);
    if token_by_peer.get(&sess.peer_addr) == Some(&tok) {
        token_by_peer.remove(&sess.peer_addr);
    }
    if let Some((old_p, _)) = sess.old_peer_addr.take() {
        if token_by_peer.get(&old_p) == Some(&tok) {
            token_by_peer.remove(&old_p);
        }
    }
    for mig in sess.pending_migrations.drain(..) {
        if local_mig_pending.get(&mig.cand_addr).map(|&(t, _)| t) == Some(tok) {
            local_mig_pending.remove(&mig.cand_addr);
        }
    }
    if token_by_ufrag.get(&sess.username) == Some(&tok) {
        token_by_ufrag.remove(&sess.username);
    }
    registry.unregister_session(&sess.username, worker_id, sess.mi_key_mig);
}

pub fn run_server(cfg: ServerConfig) -> std::io::Result<()> {
    let workers = cfg.workers.max(1);
    let cpu = detect_cpu_accel();
    let dtls_pool = build_dimpl_config_pool_for(
        cfg.cipher_pref,
        &cpu,
        false,
        cfg.wan_mtu,
        outer_udp_hdr_len(cfg.listen_addr),
    );
    let seen_txids = Arc::new(Mutex::new(SeenTxidCache::new()));
    let registry = Arc::new(SharedV4Registry::new(workers));
    let telemetry = TelemetryHub::start(
        "server",
        &cfg.telemetry,
        workers,
        cfg.wan_mtu,
        cfg.quiet,
        cfg.stop.clone(),
    );
    if !cfg.quiet {
        println!(
            "[server-rs] V4.0 CPU arch={} hw_accel=[{}] recommended={} workers={} dtls=dimpl-{}(mutual-cert,cookie,pfs) silent_drop=true udp_batch={}",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            workers,
            cfg.dtls_min_version.as_str(),
            format_udp_batch_mode(cfg.udp_batch),
        );
    }
    #[cfg(not(target_os = "linux"))]
    if workers > 1 {
        eprintln!("[server-rs] WARN: SO_REUSEPORT UDP hash load-balancing is Linux-specific.");
    }

    if workers == 1 {
        let res = run_server_worker(
            0,
            cfg,
            false,
            dtls_pool,
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
        c.wire_audit_file = None;
        let dp = dtls_pool.clone();
        let cache = Arc::clone(&seen_txids);
        let reg = Arc::clone(&registry);
        let tel = telemetry.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = run_server_worker(wid, c, true, dp, cache, reg, tel) {
                eprintln!("[server-rs#{}] error: {}", wid, e);
            }
        }));
    }
    let res = run_server_worker(
        0,
        cfg,
        true,
        dtls_pool,
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
