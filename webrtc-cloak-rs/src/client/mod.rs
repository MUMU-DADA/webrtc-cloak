//! 客户端配置、会话状态定义、定时器辅助与多线程启动入口。

mod dtls;
mod worker;
mod worker_io;
mod worker_timers;

#[cfg(test)]
mod tests;

use self::dtls::graceful_teardown_client;
use self::worker::run_client_worker;
use crate::constants::{
    CLOSING_DRAIN_MS, POST_BYE_CLOSING_DRAIN_MS, TRICKLE_RATE_15S_BYTES, TRICKLE_WINDOW_15S_SECS,
};
use crate::protocol::{
    build_dimpl_config_pool, detect_cpu_accel, jitter_duration_ms, lognormal_duration_ms,
    rand_byte_budget, rand_duration_range_ms, CipherPref, CipherSuite, DtlsMinVersion,
    RollingByteWindow, SessionIceParams, SrtpCloakCipher,
};
use crate::telemetry::{TelemetryConfig, TelemetryHub};
use dimpl::Dtls;
use mio::net::UdpSocket as MioUdpSocket;
use mio::Token;
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

thread_local! {
    pub(super) static CLIENT_QUIET: Cell<bool> = const { Cell::new(false) };
}

/// 客户端单会话上游 UDP 套接字收发内核缓冲大小（2 MiB）。
pub(super) const SOCK_BUF_2MIB: usize = 2 * 1024 * 1024;
/// 单个工作线程允许保留的静默引流套接字数量上限，防止持续黑洞泄露文件描述符。
pub(super) const MAX_DRAINING_SESSIONS: usize = 16;
/// 判定会话近期活跃并允许触发自动轮换/迁移/快连的时间窗口（秒）。
pub(super) const ACTIVE_ROTATE_WINDOW_SECS: u64 = 30;
/// 近期发生过轮换/迁移的阻尼判定窗口（秒），用于放宽保活重试防止高丢包抖动。
pub(super) const RECENT_ROTATION_DAMP_SECS: u64 = 60;
/// MBB 定时轮换挂起判定滑动窗口时长（5 分钟）。
pub(super) const TRICKLE_WINDOW_5MIN_SECS: u64 = 300;
/// RFC 7675 STUN 同意检查常规最大重传次数（1 次首包 + 2 次同 txid 重传 = 3 次，约 4.7s）。
pub(super) const KA_MAX_RETRIES: u8 = 2;
/// 近期刚轮换后的阻尼 STUN 同意检查最大重传次数（共 5 次，防止高随机丢包反复切端口）。
pub(super) const KA_MAX_RETRIES_DAMPED: u8 = 4;
/// MBB `0xFFFC` 交接请求最小重传间隔下限（毫秒）。
pub(super) const CLIENT_HANDOVER_MIN_RETRY_MS: u64 = 380;
/// `0xFFFD` 路径挑战响应补发间隔（毫秒）。
pub(super) const CLIENT_MIG_ECHO_INTERVAL_MS: u64 = 250;
/// 客户端进入 Ready 后首条 SRTCP 心跳的最小延迟（毫秒）。
pub(super) const CLIENT_SRTCP_INIT_MIN_MS: u64 = 250;
/// 客户端进入 Ready 后首条 SRTCP 心跳的最大延迟（毫秒）。
pub(super) const CLIENT_SRTCP_INIT_MAX_MS: u64 = 600;
/// 客户端活跃媒体传输期 SRTCP 最小发送间隔（毫秒）。
pub(super) const CLIENT_SRTCP_ACTIVE_MIN_MS: u64 = 900;
/// 客户端活跃媒体传输期 SRTCP 最大发送间隔（毫秒）。
pub(super) const CLIENT_SRTCP_ACTIVE_MAX_MS: u64 = 1900;
/// 细流挂起场景下强制兜底 MBB 硬轮换的最短时长下限（5 小时，秒）。
const CLIENT_MBB_HARD_ROTATE_MIN_SECS: u64 = 5 * 3600;
/// 兜底硬轮换随机区间的最小跨度保底值（30 分钟，秒）。
const CLIENT_MBB_HARD_ROTATE_MIN_GAP_SECS: u64 = 1800;

#[derive(Clone)]
pub struct ClientConfig {
    pub listen_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub psk: Vec<u8>,
    pub cipher_pref: CipherPref,
    pub dtls_decoy: bool,
    pub dtls_min_version: DtlsMinVersion,
    /// Optional proactive Make-Before-Break 5-tuple rotation median interval in seconds (`0` = disabled).
    pub rotate_interval_secs: u64,
    /// Optional proactive Make-Before-Break base byte-volume budget (`0` = disabled; jittered `[0.50x, 1.85x]`).
    pub rotate_max_bytes: u64,
    /// Minimum Ready session age before byte-volume MBB rotation can trigger (prevents handshake storms).
    pub rotate_cooldown_secs: u64,
    pub workers: usize,
    pub max_sessions: usize,
    pub wan_mtu: usize,
    pub retry_ms: u64,
    pub max_retries: u32,
    pub keepalive_secs: u64,
    pub idle_timeout_secs: u64,
    pub stats_interval_secs: u64,
    pub telemetry: TelemetryConfig,
    pub quiet: bool,
    pub stop: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum HandshakeState {
    StunWait,
    DtlsHandshake,
    /// V4: Standby MBB session completed DTLS 1.3 and sent encrypted `0xFFFC` Handover Request,
    /// waiting <=1 RTT for server Ack while the old primary remains 100% live (0ms stall!).
    HandoverWait,
    /// V4: Active session switched to a fresh local UDP socket after uplink blackhole and sent
    /// 1-RTT RFC 8445 ICE migration STUN (`mi_key_mig` + `USE-CANDIDATE`), awaiting `0xFFFD` challenge.
    Migrating,
    Ready,
    /// MBB post-promotion receive-only overlap: new 5-tuple already carries all new uplink while
    /// the old 5-tuple stays Ready on the server for a random 2–10s window so slow backend replies
    /// and ECMP-reordered packets arrive with zero loss and `<1ms` new-Ready->old-BYE correlation
    /// is broken. At the deadline, send encrypted BYE + close_notify and transition to `Closing`.
    DrainingBeforeBye(Instant),
    Closing(Instant),
}

pub(super) struct OldPathDrain {
    pub(super) sock: MioUdpSocket,
    pub(super) owner_tok: Token,
    pub(super) deadline: Instant,
}

pub(super) struct PendingReconnect {
    pub(super) at: Instant,
    pub(super) pending: VecDeque<Vec<u8>>,
    pub(super) pending_bytes: usize,
}

pub(super) struct ClientSession {
    pub(super) client_addr: SocketAddr,
    pub(super) upstream: MioUdpSocket,
    pub(super) local_port: u16,
    pub(super) ice: SessionIceParams,
    pub(super) stun_txid: [u8; 12],
    pub(super) cached_initial_stun: Vec<u8>,
    pub(super) state: HandshakeState,
    pub(super) created_at: Instant,
    pub(super) ready_at: Option<Instant>,
    pub(super) last_data_active: Instant,
    pub(super) last_active_burst: Instant,
    pub(super) next_retry_at: Instant,
    pub(super) next_keepalive_at: Instant,
    pub(super) next_srtcp_at: Instant,
    pub(super) dtls_next_timeout: Option<Instant>,
    pub(super) is_standby: bool,
    pub(super) standby_for_primary: Option<Token>,
    pub(super) standby_spawned: bool,
    pub(super) rotate_at: Option<Instant>,
    pub(super) hard_rotate_at: Option<Instant>,
    pub(super) rotate_byte_budget: Option<u64>,
    pub(super) rate_15s: RollingByteWindow,
    pub(super) rate_5min: RollingByteWindow,
    pub(super) retries: u32,
    /// In-flight RFC 7675 STUN consent check transaction (RFC 5389 §7.2.1 same-txid retransmission).
    pub(super) ka_txid: Option<[u8; 12]>,
    pub(super) ka_pkt: Vec<u8>,
    pub(super) ka_retries: u8,
    pub(super) ka_max_retries: u8,
    pub(super) ka_rto_at: Option<Instant>,
    pub(super) ka_sent_at: Option<Instant>,
    /// V4 1-RTT ICE path migration state & loss-resilient 0xFFFD response echo
    pub(super) mig_txid: Option<[u8; 12]>,
    pub(super) mig_retries: u8,
    pub(super) mig_retry_at: Option<Instant>,
    pub(super) mig_echo_payload: Option<Vec<u8>>,
    pub(super) mig_echo_next_at: Option<Instant>,
    pub(super) mig_echo_left: u8,
    /// V4 scheduled MBB encrypted 0xFFFC handover state
    pub(super) handover_payload: Option<Vec<u8>>,
    pub(super) handover_retries: u8,
    pub(super) handover_retry_at: Option<Instant>,
    pub(super) stun_key: Option<[u8; 32]>,
    pub(super) session_key: Option<[u8; 32]>,
    pub(super) mi_key_mig: Option<[u8; 32]>,
    pub(super) ssrc_c2s: u32,
    pub(super) ssrc_s2c: u32,
    pub(super) dtls: Option<Dtls>,
    pub(super) dtls_resets: u8,
    pub(super) pending_sh_suite: Option<u16>,
    pub(super) dtls_suite_id: Option<u16>,
    pub(super) dtls_km: Option<Vec<u8>>,
    pub(super) active_cipher: Option<CipherSuite>,
    pub(super) cipher: Option<SrtpCloakCipher>,
    pub(super) pending: VecDeque<Vec<u8>>,
    pub(super) pending_bytes: usize,
    pub(super) tx_pkts: u64,
    pub(super) tx_pkts_at_last_rtcp: u64,
    pub(super) tx_bytes: u64,
    pub(super) rx_pkts: u64,
    pub(super) rx_pkts_at_last_rtcp: u64,
    pub(super) rx_bytes: u64,
    pub(super) keepalives_ok: u64,
    pub(super) srtcp_tx: u64,
    pub(super) srtcp_rx: u64,
    pub(super) auth_drops: u64,
}

pub(super) fn schedule_mbb_timers(sess: &mut ClientSession, cfg: &ClientConfig, now: Instant) {
    if sess.is_standby {
        sess.rotate_at = None;
        sess.hard_rotate_at = None;
        sess.rotate_byte_budget = None;
        return;
    }
    if cfg.rotate_interval_secs > 0 {
        sess.rotate_at = Some(now + lognormal_duration_ms(cfg.rotate_interval_secs * 1000));
        sess.hard_rotate_at = if cfg.rotate_interval_secs >= 60 {
            let min_h = cfg
                .rotate_interval_secs
                .saturating_mul(4)
                .max(CLIENT_MBB_HARD_ROTATE_MIN_SECS);
            let max_h = (min_h.saturating_mul(8) / 5)
                .max(min_h + CLIENT_MBB_HARD_ROTATE_MIN_GAP_SECS);
            Some(now + rand_duration_range_ms(min_h * 1000, max_h * 1000))
        } else {
            Some(now + Duration::from_secs(cfg.rotate_interval_secs.saturating_mul(6)))
        };
    } else {
        sess.rotate_at = None;
        sess.hard_rotate_at = None;
    }
    sess.rotate_byte_budget = if cfg.rotate_max_bytes > 0 {
        Some(rand_byte_budget(cfg.rotate_max_bytes))
    } else {
        None
    };
}

#[inline]
pub(super) fn is_client_in_trickle(sess: &mut ClientSession, now: Instant) -> bool {
    let age_ge_15s = sess.ready_at.map_or(false, |r| {
        now.duration_since(r) >= Duration::from_secs(TRICKLE_WINDOW_15S_SECS)
    });
    age_ge_15s && sess.rate_15s.bytes_in_window(now) < TRICKLE_RATE_15S_BYTES
}

#[inline]
pub(super) fn record_client_media_bytes(
    sess: &mut ClientSession,
    cfg: &ClientConfig,
    ka_base_ms: u64,
    now: Instant,
    bytes: u64,
) {
    sess.rate_15s.record(now, bytes);
    sess.rate_5min.record(now, bytes);
    if sess.rate_15s.bytes_in_window(now) >= TRICKLE_RATE_15S_BYTES {
        sess.last_active_burst = now;
        if cfg.keepalive_secs > 0 {
            let max_active_ka = Duration::from_millis(ka_base_ms + ka_base_ms / 5);
            if sess.next_keepalive_at > now + max_active_ka {
                sess.next_keepalive_at = now + jitter_duration_ms(ka_base_ms);
            }
        }
        if sess.next_srtcp_at > now + Duration::from_millis(CLIENT_SRTCP_ACTIVE_MAX_MS) {
            sess.next_srtcp_at =
                now + rand_duration_range_ms(CLIENT_SRTCP_ACTIVE_MIN_MS, CLIENT_SRTCP_ACTIVE_MAX_MS);
        }
    }
}

pub(super) fn cancel_standby_for_client(
    client_addr: SocketAddr,
    standby_by_client: &mut HashMap<SocketAddr, Token>,
    sessions_by_token: &mut HashMap<Token, ClientSession>,
    dtls_buf: &mut Vec<u8>,
    now: Instant,
) {
    if let Some(st_tok) = standby_by_client.remove(&client_addr) {
        let owner_prim = sessions_by_token
            .get(&st_tok)
            .and_then(|s| s.standby_for_primary);
        if let Some(st_sess) = sessions_by_token.get_mut(&st_tok) {
            if matches!(
                st_sess.state,
                HandshakeState::Ready
                    | HandshakeState::HandoverWait
                    | HandshakeState::DrainingBeforeBye(_)
            ) {
                graceful_teardown_client(st_sess, dtls_buf);
                st_sess.state =
                    HandshakeState::Closing(now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS));
            } else if !matches!(st_sess.state, HandshakeState::Closing(_)) {
                st_sess.state =
                    HandshakeState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
            }
        }
        // P1-2 fix: Always clear `standby_spawned` on the surviving primary so MBB never locks up!
        if let Some(pt) = owner_prim {
            if let Some(prim) = sessions_by_token.get_mut(&pt) {
                prim.standby_spawned = false;
            }
        }
    }
}

pub(super) fn make_udp_socket(
    bind_addr: SocketAddr,
    connect_to: Option<SocketAddr>,
    reuse_port: bool,
    buf_bytes: usize,
) -> std::io::Result<MioUdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
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
    if !CLIENT_QUIET.with(|q| q.get()) {
        println!("[client-rs#{}] {}", worker_id, msg);
    }
}

pub fn run_client(cfg: ClientConfig) -> std::io::Result<()> {
    let workers = cfg.workers.max(1);
    let cpu = detect_cpu_accel();
    let dtls_pool = build_dimpl_config_pool(cfg.cipher_pref, &cpu, true, cfg.wan_mtu);
    let telemetry = TelemetryHub::start(
        "client",
        &cfg.telemetry,
        workers,
        cfg.wan_mtu,
        cfg.quiet,
        cfg.stop.clone(),
    );
    if !cfg.quiet {
        println!(
            "[client-rs] V4.0 CPU arch={} hw_accel=[{}] recommended={} workers={} dtls=dimpl-{}(mutual-cert,pfs)",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            workers,
            cfg.dtls_min_version.as_str()
        );
    }
    #[cfg(not(target_os = "linux"))]
    if workers > 1 {
        eprintln!("[client-rs] WARN: SO_REUSEPORT UDP hash load-balancing is Linux-specific.");
    }

    if workers == 1 {
        let res = run_client_worker(0, cfg, false, dtls_pool, telemetry.clone());
        if let Some(ref th) = telemetry {
            th.shutdown();
        }
        return res;
    }

    let mut handles = Vec::with_capacity(workers - 1);
    for wid in 1..workers {
        let c = cfg.clone();
        let dp = dtls_pool.clone();
        let tel = telemetry.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = run_client_worker(wid, c, true, dp, tel) {
                eprintln!("[client-rs#{}] error: {}", wid, e);
            }
        }));
    }
    let res = run_client_worker(0, cfg, true, dtls_pool, telemetry.clone());
    for h in handles {
        let _ = h.join();
    }
    if let Some(ref th) = telemetry {
        th.shutdown();
    }
    res
}
