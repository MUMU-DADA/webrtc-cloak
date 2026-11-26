//! 非阻塞多候选 ECMP 信道抽卡探测、启动预热与持续 RTT 优选守护引擎。

use super::dtls::{build_session_after_stun, graceful_teardown_client, spawn_client_session};
use super::worker::ClientWorker;
use super::{
    alloc_token, cancel_standby_for_client, log, make_udp_socket, record_client_media_bytes,
    schedule_mbb_timers, HandshakeState, OldPathDrain, CLIENT_MIG_ECHO_INTERVAL_MS, KA_MAX_RETRIES,
    KA_MAX_RETRIES_DAMPED, MAX_DRAINING_SESSIONS, SOCK_BUF_2MIB,
};
use crate::constants::{
    outer_udp_hdr_len, unspecified_addr_for, BLACKHOLE_DRAIN_SECS, CLOSING_DRAIN_MS,
    CTRL_FRAME_BUF_LEN, PATH_CHALLENGE_OP_REQ, PATH_CHALLENGE_OP_RESP, PATH_CHALLENGE_PAYLOAD_LEN,
    POST_BYE_CLOSING_DRAIN_MS, SRTP_PATH_CHALLENGE_MAGIC, STUN_BINDING_SUCCESS,
    WORKER_MIN_FAST_WAIT_MS,
};
use crate::protocol::{
    build_ice_stun_request, build_ice_stun_request_with_key, demux_rfc7983, jitter_duration_ms,
    make_fresh_stun_txid, parse_stun_with_key, PacketKind, SessionIceParams, SrtpFrame,
};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Interest, Token};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 每轮抽卡探测的默认并行候选端口数。
pub const DEFAULT_LANE_PROBES: usize = 4;
/// 每轮抽卡允许的候选端口数下限。
pub const MIN_LANE_PROBES: usize = 2;
/// 每轮抽卡允许的候选端口数上限。
pub const MAX_LANE_PROBES: usize = 8;
/// 未抽中达标信道时的默认最大重试轮次。
pub const DEFAULT_LANE_ROUNDS: usize = 3;
/// 最大重试轮次上限。
pub const MAX_LANE_ROUNDS: usize = 6;
/// 活跃信道退化触发后台 MBB 重新抽卡的默认冷却时间（秒）。
pub const DEFAULT_LANE_DEGRADE_COOLDOWN_SECS: u64 = 60;
/// 冷却时间允许下限（秒）。
pub const MIN_LANE_DEGRADE_COOLDOWN_SECS: u64 = 5;
/// 冷却时间允许上限（秒）。
pub const MAX_LANE_DEGRADE_COOLDOWN_SECS: u64 = 3600;

/// 服务端单会话每秒允许的 1-RTT 路径挑战配额上限（与 `server::MAX_CHALLENGES_PER_SEC` 对齐）。
const MIGRATE_1RTT_MAX_PROBES: usize = 4;
/// 同轮候选之间的自然发包错峰间隔（毫秒，模拟 ICE trickle 节奏避免瞬时微突发）。
const LANE_PROBE_STAGGER_MS: u64 = 15;
/// 连续多少次 STUN 保活 RTT 超标后判定活跃信道退化并触发后台 MBB 抽卡。
pub(super) const LANE_DEGRADE_CONSECUTIVE: u8 = 3;
/// 活跃信道 RTT EWMA 新样本权重。
pub(super) const LANE_RTT_EWMA_ALPHA: f64 = 0.35;
/// 退化重抽未能命中目标阈值时，仍值得切换的最小绝对收益（毫秒）。
const LANE_IMPROVE_MIN_DELTA_MS: f64 = 25.0;
/// 退化重抽未能命中目标阈值时，仍值得切换的最大 RTT 比例（需至少快 20%）。
const LANE_IMPROVE_MIN_RATIO: f64 = 0.80;
/// 自动阈值模式下，后续抽卡判定优秀信道的基线倍率与最小增量（毫秒）。
const LANE_AUTO_TARGET_MULT: f64 = 1.65;
const LANE_AUTO_TARGET_ADD_MS: f64 = 40.0;
/// 自动阈值模式下，活跃信道退化守护的基线倍率与最小增量（毫秒）。
const LANE_AUTO_DEGRADE_MULT: f64 = 1.80;
const LANE_AUTO_DEGRADE_ADD_MS: f64 = 50.0;
/// 单轮探测等待超时下限与上限（毫秒）。
const LANE_ROUND_TIMEOUT_MIN_MS: u64 = 450;
const LANE_ROUND_TIMEOUT_MAX_MS: u64 = 1200;
/// 预热抽卡失败后的初始重试间隔（毫秒）与空闲重热延迟（毫秒）。
const PREWARM_FAIL_RETRY_MS: u64 = 3_000;
const PREWARM_IDLE_REARM_MS: u64 = 1_500;
/// 1-RTT 迁移成功后 `0xFFFD` 响应的补发次数（与 `worker_io::CLIENT_MIG_ECHO_COUNT` 对齐）。
const MIG_ECHO_COUNT: u8 = 3;

/// ECMP 信道抽卡探测与活跃信道优选守护配置。
#[derive(Clone, Copy, Debug)]
pub struct LaneHuntConfig {
    /// 是否启用抽卡探测与持续信道优选（默认 `false`，保持既有行为零变化）。
    pub enabled: bool,
    /// 每轮并行探测的候选源端口数（默认 4，范围 2..=8）。
    pub probes: usize,
    /// 未命中目标延迟时的最大抽卡轮数（默认 3，范围 1..=6）。
    pub max_rounds: usize,
    /// 显式优秀信道 RTT 上限（毫秒，`0` 表示基于观测最佳 RTT 自动适应）。
    pub target_rtt_ms: u64,
    /// 活跃信道退化触发后台 MBB 重新抽卡的最小冷却期（秒，默认 60s）。
    pub degrade_cooldown_secs: u64,
}

impl Default for LaneHuntConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            probes: DEFAULT_LANE_PROBES,
            max_rounds: DEFAULT_LANE_ROUNDS,
            target_rtt_ms: 0,
            degrade_cooldown_secs: DEFAULT_LANE_DEGRADE_COOLDOWN_SECS,
        }
    }
}

impl LaneHuntConfig {
    #[inline]
    pub fn normalized(mut self) -> Self {
        self.probes = self.probes.clamp(MIN_LANE_PROBES, MAX_LANE_PROBES);
        self.max_rounds = self.max_rounds.clamp(1, MAX_LANE_ROUNDS);
        self.degrade_cooldown_secs = self.degrade_cooldown_secs.clamp(
            MIN_LANE_DEGRADE_COOLDOWN_SECS,
            MAX_LANE_DEGRADE_COOLDOWN_SECS,
        );
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum HuntPurpose {
    /// 启动预热或空闲重热：抽中优秀信道并完成握手后暂存，供下个本地客户端 0ms 秒连。
    PreWarm,
    /// 为具体本地客户端建立全新主会话（抽卡期间透明缓存其首包）。
    NewPrimary {
        client_addr: SocketAddr,
        ka_max_retries: u8,
    },
    /// 后台 MBB 备选抽卡：为存活主会话抽中更优/优秀信道后再握手并 0ms 交接。
    MbbStandby {
        primary_tok: Token,
        client_addr: SocketAddr,
        /// `Some(cur_ewma_ms)` 表示退化触发的重抽，若未抽到明显更优信道则放弃切换保稳定；
        /// `None` 表示定时/字节预算触发的计划轮换，始终择优切换。
        degrade_baseline_ms: Option<u64>,
    },
    /// 黑洞 1-RTT ICE 路径迁移多候选竞速：最多 4 路并发挑战，仅对最快信道回复 `0xFFFD RESP`。
    Migrate1Rtt {
        session_tok: Token,
        client_addr: SocketAddr,
        recently_rotated: bool,
    },
}

impl HuntPurpose {
    fn label(self) -> &'static str {
        match self {
            HuntPurpose::PreWarm => "prewarm",
            HuntPurpose::NewPrimary { .. } => "new-primary",
            HuntPurpose::MbbStandby {
                degrade_baseline_ms: Some(_),
                ..
            } => "mbb-degrade",
            HuntPurpose::MbbStandby {
                degrade_baseline_ms: None,
                ..
            } => "mbb-rotate",
            HuntPurpose::Migrate1Rtt { .. } => "migrate-1rtt",
        }
    }

    pub(super) fn client_addr(self) -> Option<SocketAddr> {
        match self {
            HuntPurpose::PreWarm => None,
            HuntPurpose::NewPrimary { client_addr, .. }
            | HuntPurpose::MbbStandby { client_addr, .. }
            | HuntPurpose::Migrate1Rtt { client_addr, .. } => Some(client_addr),
        }
    }
}

pub(super) struct HuntCandidate {
    pub(super) tok: Token,
    pub(super) sock: MioUdpSocket,
    pub(super) local_port: u16,
    pub(super) ice: SessionIceParams,
    pub(super) txid: [u8; 12],
    pub(super) stun_pkt: Vec<u8>,
    pub(super) send_at: Instant,
    pub(super) sent_at: Option<Instant>,
    pub(super) rtt_ms: Option<f64>,
    pub(super) mapped_addr: Option<SocketAddr>,
    pub(super) mig_challenge: Option<[u8; PATH_CHALLENGE_PAYLOAD_LEN]>,
}

impl HuntCandidate {
    #[inline]
    fn is_ready(&self, is_migrate: bool) -> bool {
        if is_migrate {
            self.rtt_ms.is_some() && self.mig_challenge.is_some()
        } else {
            self.rtt_ms.is_some()
        }
    }
}

pub(super) struct LaneHunt {
    pub(super) id: usize,
    pub(super) purpose: HuntPurpose,
    pub(super) round: usize,
    pub(super) max_rounds: usize,
    pub(super) total_probed: usize,
    pub(super) round_deadline: Instant,
    pub(super) candidates: Vec<HuntCandidate>,
    pub(super) best_fallback: Option<HuntCandidate>,
    pub(super) pending: VecDeque<Vec<u8>>,
    pub(super) pending_bytes: usize,
}

impl ClientWorker {
    /// 计算当前抽卡目标 RTT 上限（毫秒）：优先使用显式 `--lane-target-rtt`，否则基于历史最佳 RTT 自适应。
    pub(super) fn effective_hunt_target_rtt(&self) -> Option<f64> {
        if self.cfg.lane_hunt.target_rtt_ms > 0 {
            Some(self.cfg.lane_hunt.target_rtt_ms as f64)
        } else {
            self.best_observed_rtt_ms
                .map(|b| (b * LANE_AUTO_TARGET_MULT).max(b + LANE_AUTO_TARGET_ADD_MS))
        }
    }

    /// 计算活跃信道退化触发阈值（毫秒）。
    pub(super) fn effective_degrade_ceiling_rtt(&self) -> Option<f64> {
        if self.cfg.lane_hunt.target_rtt_ms > 0 {
            Some(self.cfg.lane_hunt.target_rtt_ms as f64)
        } else {
            self.best_observed_rtt_ms
                .map(|b| (b * LANE_AUTO_DEGRADE_MULT).max(b + LANE_AUTO_DEGRADE_ADD_MS))
        }
    }

    /// 保守更新观测到的优秀信道基线 RTT（偏向最小值，防止劣质信道拉高基线）。
    pub(super) fn observe_good_rtt(&mut self, rtt_ms: f64) {
        if !rtt_ms.is_finite() || rtt_ms <= 0.0 || rtt_ms > 30_000.0 {
            return;
        }
        self.best_observed_rtt_ms = Some(match self.best_observed_rtt_ms {
            Some(prev) if rtt_ms < prev => prev * 0.3 + rtt_ms * 0.7,
            Some(prev) => prev.min(rtt_ms * 0.05 + prev * 0.95),
            None => rtt_ms,
        });
    }

    /// 计算预热会话为保活服务端 `idle_timeout` 而发送微小 `0xFFFE` 探测包的间隔。
    pub(super) fn prewarm_keepwarm_interval(&self) -> Duration {
        let secs = if self.cfg.idle_timeout_secs == 0 {
            60
        } else {
            ((self.cfg.idle_timeout_secs * 2) / 3).clamp(15, 90)
        };
        Duration::from_secs(secs)
    }

    /// 是否存在正在为 `client_addr` 执行的 `NewPrimary` 抽卡任务（用于在抽卡期间缓存应用包）。
    pub(super) fn find_new_primary_hunt_id(&self, client_addr: SocketAddr) -> Option<usize> {
        self.lane_hunts.iter().find_map(|(&id, h)| match h.purpose {
            HuntPurpose::NewPrimary {
                client_addr: ca, ..
            } if ca == client_addr => Some(id),
            _ => None,
        })
    }

    /// 是否存在正在进行的 `PreWarm` 抽卡任务。
    pub(super) fn find_prewarm_hunt_id(&self) -> Option<usize> {
        self.lane_hunts.iter().find_map(|(&id, h)| {
            if h.purpose == HuntPurpose::PreWarm {
                Some(id)
            } else {
                None
            }
        })
    }

    /// 取消与 `client_addr` 相关的所有进行中抽卡任务并释放全部候选套接字。
    pub(super) fn cancel_hunts_for_client(&mut self, client_addr: SocketAddr) {
        let ids: Vec<usize> = self
            .lane_hunts
            .iter()
            .filter(|(_, h)| h.purpose.client_addr() == Some(client_addr))
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.abort_hunt(id);
        }
    }

    fn abort_hunt(&mut self, hunt_id: usize) {
        if let Some(mut hunt) = self.lane_hunts.remove(&hunt_id) {
            for mut c in hunt.candidates.drain(..) {
                self.hunt_tok_to_id.remove(&c.tok);
                let _ = self.poll.registry().deregister(&mut c.sock);
            }
            if let Some(mut fb) = hunt.best_fallback.take() {
                self.hunt_tok_to_id.remove(&fb.tok);
                let _ = self.poll.registry().deregister(&mut fb.sock);
            }
            if let HuntPurpose::MbbStandby { primary_tok, .. } = hunt.purpose {
                if let Some(prim) = self.sessions_by_token.get_mut(&primary_tok) {
                    prim.standby_spawned = false;
                }
            }
        }
    }

    /// 启动一次新的多候选 ECMP 抽卡任务。返回是否成功启动。
    pub(super) fn start_lane_hunt(
        &mut self,
        purpose: HuntPurpose,
        now: Instant,
        carried_pending: VecDeque<Vec<u8>>,
        carried_bytes: usize,
    ) -> bool {
        let cfg = self.cfg.lane_hunt.normalized();
        if !cfg.enabled {
            return false;
        }
        // 避免同用途重复拉起
        match purpose {
            HuntPurpose::PreWarm => {
                if self.prewarm_tok.is_some() || self.find_prewarm_hunt_id().is_some() {
                    return false;
                }
            }
            HuntPurpose::NewPrimary { client_addr, .. } => {
                if self.find_new_primary_hunt_id(client_addr).is_some() {
                    return false;
                }
            }
            HuntPurpose::MbbStandby {
                client_addr,
                primary_tok,
                ..
            } => {
                if self.standby_by_client.contains_key(&client_addr)
                    || self.lane_hunts.values().any(|h| {
                        matches!(
                            h.purpose,
                            HuntPurpose::MbbStandby {
                                client_addr: ca, ..
                            } if ca == client_addr
                        )
                    })
                {
                    return false;
                }
                if let Some(prim) = self.sessions_by_token.get_mut(&primary_tok) {
                    prim.standby_spawned = true;
                }
            }
            HuntPurpose::Migrate1Rtt { session_tok, .. } => {
                let valid = self
                    .sessions_by_token
                    .get(&session_tok)
                    .is_some_and(|s| s.mi_key_mig.is_some() && s.cipher.is_some());
                if !valid {
                    return false;
                }
            }
        }

        let id = self.next_hunt_id;
        self.next_hunt_id = self.next_hunt_id.wrapping_add(1).max(1);
        let max_rounds = match purpose {
            HuntPurpose::Migrate1Rtt { .. } => 1,
            _ => cfg.max_rounds,
        };
        let mut hunt = LaneHunt {
            id,
            purpose,
            round: 0,
            max_rounds,
            total_probed: 0,
            round_deadline: now,
            candidates: Vec::new(),
            best_fallback: None,
            pending: carried_pending,
            pending_bytes: carried_bytes,
        };
        if !self.spawn_hunt_round(&mut hunt, now) {
            if let HuntPurpose::MbbStandby { primary_tok, .. } = purpose {
                if let Some(prim) = self.sessions_by_token.get_mut(&primary_tok) {
                    prim.standby_spawned = false;
                }
            }
            return false;
        }
        log(
            self.worker_id,
            &format!(
                "LANE HUNT start [{}] round 1/{} probes={} target={}",
                purpose.label(),
                hunt.max_rounds,
                hunt.candidates.len(),
                self.effective_hunt_target_rtt()
                    .map(|t| format!("<={:.0}ms", t))
                    .unwrap_or_else(|| "auto".into())
            ),
        );
        self.lane_hunts.insert(id, hunt);
        true
    }

    fn round_timeout_dur(&self, probe_count: usize) -> Duration {
        let base_ms = if self.cfg.lane_hunt.target_rtt_ms > 0 {
            (self.cfg.lane_hunt.target_rtt_ms.saturating_mul(2) + 200)
                .clamp(LANE_ROUND_TIMEOUT_MIN_MS, LANE_ROUND_TIMEOUT_MAX_MS)
        } else if let Some(b) = self.best_observed_rtt_ms {
            ((b * 3.0) as u64 + 180).clamp(LANE_ROUND_TIMEOUT_MIN_MS, LANE_ROUND_TIMEOUT_MAX_MS)
        } else {
            650
        };
        let stagger_ms = (probe_count.saturating_sub(1) as u64) * LANE_PROBE_STAGGER_MS;
        Duration::from_millis(base_ms + stagger_ms)
    }

    fn spawn_hunt_round(&mut self, hunt: &mut LaneHunt, now: Instant) -> bool {
        let cfg = self.cfg.lane_hunt.normalized();
        let is_migrate = matches!(hunt.purpose, HuntPurpose::Migrate1Rtt { .. });
        let count = if is_migrate {
            cfg.probes.min(MIGRATE_1RTT_MAX_PROBES)
        } else {
            cfg.probes
        };
        let mig_params = match hunt.purpose {
            HuntPurpose::Migrate1Rtt { session_tok, .. } => self
                .sessions_by_token
                .get(&session_tok)
                .and_then(|s| s.mi_key_mig.map(|mk| (s.ice.clone(), mk))),
            _ => None,
        };
        if is_migrate && mig_params.is_none() {
            return false;
        }

        let bind_any = unspecified_addr_for(self.cfg.server_addr);
        let mut spawned = Vec::with_capacity(count);
        for i in 0..count {
            let mut sock =
                match make_udp_socket(bind_any, Some(self.cfg.server_addr), false, SOCK_BUF_2MIB) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
            let local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
            let tok = alloc_token(&mut self.next_token_id);
            if self
                .poll
                .registry()
                .register(&mut sock, tok, Interest::READABLE)
                .is_err()
            {
                continue;
            }
            let (ice, txid, stun_pkt) = if let Some((ref sess_ice, mk)) = mig_params {
                let (pkt, txid) =
                    build_ice_stun_request_with_key(&self.cfg.psk, &mk, sess_ice, None, true);
                (sess_ice.clone(), txid, pkt)
            } else {
                let ice = SessionIceParams::generate();
                let txid = make_fresh_stun_txid(&self.cfg.psk);
                let (pkt, _) = build_ice_stun_request(&self.cfg.psk, &ice, Some(txid), true);
                (ice, txid, pkt)
            };
            let send_at = now + Duration::from_millis((i as u64) * LANE_PROBE_STAGGER_MS);
            let sent_at = if i == 0 {
                let _ = sock.send(&stun_pkt);
                Some(now)
            } else {
                None
            };
            self.hunt_tok_to_id.insert(tok, hunt.id);
            spawned.push(HuntCandidate {
                tok,
                sock,
                local_port,
                ice,
                txid,
                stun_pkt,
                send_at,
                sent_at,
                rtt_ms: None,
                mapped_addr: None,
                mig_challenge: None,
            });
        }

        if spawned.is_empty() {
            return false;
        }
        hunt.round += 1;
        hunt.total_probed += spawned.len();
        hunt.round_deadline = now + self.round_timeout_dur(spawned.len());
        hunt.candidates = spawned;
        true
    }

    /// 驱动全部抽卡任务的错峰发送、早停决策、重抽轮次与预热定时重arm。
    pub(super) fn process_hunt_timers(
        &mut self,
        now: Instant,
        wait: &mut Duration,
        standby_ready: &mut Vec<(Token, SocketAddr)>,
    ) {
        // 1) 空闲预热重arm（启动失败重试 / 全会话关闭后重热）
        if self.cfg.lane_hunt.enabled
            && self.prewarm_tok.is_none()
            && self.token_by_client.is_empty()
            && self.pending_reconnects.is_empty()
            && self.lane_hunts.is_empty()
        {
            if let Some(at) = self.next_prewarm_at {
                if now >= at {
                    self.next_prewarm_at = None;
                    if !self.start_lane_hunt(HuntPurpose::PreWarm, now, VecDeque::new(), 0) {
                        self.next_prewarm_at =
                            Some(now + Duration::from_millis(PREWARM_FAIL_RETRY_MS));
                    }
                } else {
                    let rem = at.saturating_duration_since(now);
                    if rem < *wait {
                        *wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                    }
                }
            } else {
                self.next_prewarm_at = Some(now + Duration::from_millis(PREWARM_IDLE_REARM_MS));
                let rem = Duration::from_millis(PREWARM_IDLE_REARM_MS);
                if rem < *wait {
                    *wait = rem;
                }
            }
        }

        if self.lane_hunts.is_empty() {
            return;
        }

        let eff_target = self.effective_hunt_target_rtt();
        let mut finished_rounds: Vec<usize> = Vec::new();
        let hunt_ids: Vec<usize> = self.lane_hunts.keys().copied().collect();

        for id in hunt_ids {
            let Some(hunt) = self.lane_hunts.get_mut(&id) else {
                continue;
            };
            let is_migrate = matches!(hunt.purpose, HuntPurpose::Migrate1Rtt { .. });

            // 错峰发送尚未发出的候选 STUN
            let mut all_sent = true;
            let mut last_sent: Option<Instant> = None;
            for c in hunt.candidates.iter_mut() {
                if c.sent_at.is_none() {
                    if now >= c.send_at {
                        let _ = c.sock.send(&c.stun_pkt);
                        c.sent_at = Some(now);
                    } else {
                        all_sent = false;
                        let rem = c.send_at.saturating_duration_since(now);
                        if rem < *wait {
                            *wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                        }
                    }
                }
                if let Some(st) = c.sent_at {
                    last_sent = Some(match last_sent {
                        Some(prev) => prev.max(st),
                        None => st,
                    });
                }
            }

            let all_ready = !hunt.candidates.is_empty()
                && hunt.candidates.iter().all(|c| c.is_ready(is_migrate));
            let best_in_round = hunt
                .candidates
                .iter()
                .filter(|c| c.is_ready(is_migrate))
                .filter_map(|c| c.rtt_ms)
                .reduce(f64::min);

            // 计算早停截止时刻：已有高速候选回复后仅短暂等待其余高速兄弟比较，绝不傻等 230ms 绕路慢包
            let early_settle_at = if all_sent {
                if let (Some(best_rtt), Some(ls)) = (best_in_round, last_sent) {
                    if let Some(t) = eff_target {
                        if best_rtt <= t {
                            let grace_ms = ((best_rtt as u64) + 45).min((t as u64) + 25).max(35);
                            Some(ls + Duration::from_millis(grace_ms))
                        } else {
                            None
                        }
                    } else {
                        let grace_ms = ((best_rtt * 2.0) as u64).clamp(80, 240);
                        Some(ls + Duration::from_millis(grace_ms))
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let effective_deadline = match early_settle_at {
                Some(es) => es.min(hunt.round_deadline),
                None => hunt.round_deadline,
            };

            if all_ready || now >= effective_deadline {
                finished_rounds.push(id);
            } else {
                let rem = effective_deadline.saturating_duration_since(now);
                if rem < *wait {
                    *wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                }
            }
        }

        for id in finished_rounds {
            self.finish_hunt_round(id, now, standby_ready);
        }
    }

    /// 处理抽卡候选套接字的可读事件（STUN Binding Success / Migrate1Rtt `0xFFFD` 挑战）。
    pub(super) fn handle_hunt_readable(
        &mut self,
        tok: Token,
        now: Instant,
        standby_ready: &mut Vec<(Token, SocketAddr)>,
    ) {
        let Some(&hunt_id) = self.hunt_tok_to_id.get(&tok) else {
            return;
        };
        let Some(purpose) = self.lane_hunts.get(&hunt_id).map(|h| h.purpose) else {
            return;
        };
        let mig_sess_tok = match purpose {
            HuntPurpose::Migrate1Rtt { session_tok, .. } => Some(session_tok),
            _ => None,
        };
        let mi_key_opt =
            mig_sess_tok.and_then(|st| self.sessions_by_token.get(&st).and_then(|s| s.mi_key_mig));

        let mut round_all_ready = false;
        if let Some(hunt) = self.lane_hunts.get_mut(&hunt_id) {
            let is_migrate = mig_sess_tok.is_some();
            // 定位当前 token 对应的候选（正常在本轮 `candidates` 中；若属于 `best_fallback` 仅排空缓冲）
            let cand_idx = hunt.candidates.iter().position(|c| c.tok == tok);
            if let Some(idx) = cand_idx {
                loop {
                    let n = match hunt.candidates[idx].sock.recv(&mut self.rbuf) {
                        Ok(n) => n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    };
                    let pkt = &self.rbuf[..n];
                    let cand = &mut hunt.candidates[idx];
                    let Some(sent_at) = cand.sent_at else {
                        continue;
                    };
                    match demux_rfc7983(pkt) {
                        PacketKind::Stun => {
                            let key = if is_migrate {
                                match mi_key_opt {
                                    Some(ref k) => k,
                                    None => continue,
                                }
                            } else {
                                &self.stun_mi_key
                            };
                            if let Some(parsed) = parse_stun_with_key(pkt, &self.cfg.psk, key) {
                                if parsed.authenticated
                                    && parsed.msg_type == STUN_BINDING_SUCCESS
                                    && parsed.txid == cand.txid
                                {
                                    if cand.rtt_ms.is_none() {
                                        cand.rtt_ms = Some(
                                            now.saturating_duration_since(sent_at).as_secs_f64()
                                                * 1000.0,
                                        );
                                    }
                                    cand.mapped_addr = parsed.xor_mapped;
                                }
                            }
                        }
                        PacketKind::Srtp if is_migrate => {
                            if let Some(st) = mig_sess_tok {
                                if let Some(sess) = self.sessions_by_token.get_mut(&st) {
                                    if let Some(ref mut cipher) = sess.cipher {
                                        if let Some(SrtpFrame::PathChallenge(pn)) =
                                            cipher.unwrap_into_ex(pkt, &mut self.wbuf)
                                        {
                                            if pn == PATH_CHALLENGE_PAYLOAD_LEN
                                                && self.wbuf[0] == PATH_CHALLENGE_OP_REQ
                                            {
                                                let mut ch = [0u8; PATH_CHALLENGE_PAYLOAD_LEN];
                                                ch.copy_from_slice(
                                                    &self.wbuf[..PATH_CHALLENGE_PAYLOAD_LEN],
                                                );
                                                cand.mig_challenge = Some(ch);
                                                if cand.rtt_ms.is_none() {
                                                    cand.rtt_ms = Some(
                                                        now.saturating_duration_since(sent_at)
                                                            .as_secs_f64()
                                                            * 1000.0,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                round_all_ready = !hunt.candidates.is_empty()
                    && hunt.candidates.iter().all(|c| c.is_ready(is_migrate));
            } else if let Some(ref mut fb) = hunt.best_fallback {
                if fb.tok == tok {
                    while fb.sock.recv(&mut self.rbuf).is_ok() {}
                }
            }
        }

        if round_all_ready {
            self.finish_hunt_round(hunt_id, now, standby_ready);
        }
    }

    fn finish_hunt_round(
        &mut self,
        hunt_id: usize,
        now: Instant,
        standby_ready: &mut Vec<(Token, SocketAddr)>,
    ) {
        let Some(mut hunt) = self.lane_hunts.remove(&hunt_id) else {
            return;
        };
        let is_migrate = matches!(hunt.purpose, HuntPurpose::Migrate1Rtt { .. });

        // 从本轮候选中选出最低 RTT 的就绪者，其余立即 deregister + drop（零 FD 泄漏）
        let mut round_rtts: Vec<String> = Vec::with_capacity(hunt.candidates.len());
        let mut best_round: Option<HuntCandidate> = None;
        for mut c in hunt.candidates.drain(..) {
            if c.is_ready(is_migrate) {
                let rtt = c.rtt_ms.unwrap_or(f64::INFINITY);
                round_rtts.push(format!("{}:{:.1}ms", c.local_port, rtt));
                let replace = best_round
                    .as_ref()
                    .and_then(|b| b.rtt_ms)
                    .map(|br| rtt < br)
                    .unwrap_or(true);
                if replace {
                    if let Some(mut prev) = best_round.replace(c) {
                        self.hunt_tok_to_id.remove(&prev.tok);
                        let _ = self.poll.registry().deregister(&mut prev.sock);
                    }
                } else {
                    self.hunt_tok_to_id.remove(&c.tok);
                    let _ = self.poll.registry().deregister(&mut c.sock);
                }
            } else {
                round_rtts.push(format!("{}:timeout", c.local_port));
                self.hunt_tok_to_id.remove(&c.tok);
                let _ = self.poll.registry().deregister(&mut c.sock);
            }
        }

        // 与跨轮次保底最优候选合并
        if let Some(br) = best_round {
            let br_rtt = br.rtt_ms.unwrap_or(f64::INFINITY);
            let replace_fb = hunt
                .best_fallback
                .as_ref()
                .and_then(|f| f.rtt_ms)
                .map(|fr| br_rtt < fr)
                .unwrap_or(true);
            if replace_fb {
                if let Some(mut old_fb) = hunt.best_fallback.replace(br) {
                    self.hunt_tok_to_id.remove(&old_fb.tok);
                    let _ = self.poll.registry().deregister(&mut old_fb.sock);
                }
            } else {
                let mut drop_c = br;
                self.hunt_tok_to_id.remove(&drop_c.tok);
                let _ = self.poll.registry().deregister(&mut drop_c.sock);
            }
        }

        let eff_target = self.effective_hunt_target_rtt();
        let best_rtt = hunt.best_fallback.as_ref().and_then(|c| c.rtt_ms);
        let target_met = match (best_rtt, eff_target) {
            (Some(r), Some(t)) => r <= t,
            (Some(_), None) => true,
            (None, _) => false,
        };

        // 未达标且还有剩余轮次 -> 继续下一轮抽卡（保留最佳候选做保底）
        if !target_met && hunt.round < hunt.max_rounds {
            log(
                self.worker_id,
                &format!(
                    "LANE HUNT [{}] round {}/{} [{}] best={} > target={} -> retrying next round",
                    hunt.purpose.label(),
                    hunt.round,
                    hunt.max_rounds,
                    round_rtts.join(" "),
                    best_rtt
                        .map(|r| format!("{:.1}ms", r))
                        .unwrap_or_else(|| "none".into()),
                    eff_target
                        .map(|t| format!("<={:.0}ms", t))
                        .unwrap_or_else(|| "auto".into())
                ),
            );
            if self.spawn_hunt_round(&mut hunt, now) {
                self.lane_hunts.insert(hunt_id, hunt);
                return;
            }
        }

        // 抽卡结束：提取优胜候选并按用途提交
        let Some(mut winner) = hunt.best_fallback.take() else {
            log(
                self.worker_id,
                &format!(
                    "LANE HUNT [{}] FAILED: 0 replies across {} probe(s) ({} rounds)",
                    hunt.purpose.label(),
                    hunt.total_probed,
                    hunt.round
                ),
            );
            self.handle_hunt_empty(hunt, now);
            return;
        };
        self.hunt_tok_to_id.remove(&winner.tok);
        let winner_rtt = winner.rtt_ms.unwrap_or(0.0);

        match hunt.purpose {
            HuntPurpose::PreWarm => {
                self.observe_good_rtt(winner_rtt);
                let target_desc = eff_target
                    .map(|t| format!("<={:.0}ms", t))
                    .unwrap_or_else(|| "auto".into());
                log(
                    self.worker_id,
                    &format!(
                        "LANE HUNT OK [prewarm] winner up_sport={} rtt={:.1}ms (round {}/{}, probed={}, target={}, sample=[{}])",
                        winner.local_port,
                        winner_rtt,
                        hunt.round,
                        hunt.max_rounds,
                        hunt.total_probed,
                        target_desc,
                        round_rtts.join(" ")
                    ),
                );
                if let Some(ref th) = self.telemetry {
                    th.record_lane_hunt(
                        false,
                        format!(
                            "prewarm up_sport={} rtt={:.1}ms probed={}",
                            winner.local_port, winner_rtt, hunt.total_probed
                        ),
                    );
                }
                let dummy_client = unspecified_addr_for(self.cfg.listen_addr);
                let keepwarm_dur = self.prewarm_keepwarm_interval();
                if let Some(tok) = self.promote_stun_winner(
                    winner,
                    dummy_client,
                    KA_MAX_RETRIES,
                    None,
                    true,
                    Some(now + keepwarm_dur),
                    VecDeque::new(),
                    0,
                    now,
                    standby_ready,
                ) {
                    self.prewarm_tok = Some(tok);
                } else {
                    self.next_prewarm_at = Some(now + Duration::from_millis(PREWARM_FAIL_RETRY_MS));
                }
            }
            HuntPurpose::NewPrimary {
                client_addr,
                ka_max_retries,
            } => {
                self.observe_good_rtt(winner_rtt);
                log(
                    self.worker_id,
                    &format!(
                        "LANE HUNT OK [new-primary] client={} winner up_sport={} rtt={:.1}ms (round {}/{}, probed={}, sample=[{}])",
                        client_addr,
                        winner.local_port,
                        winner_rtt,
                        hunt.round,
                        hunt.max_rounds,
                        hunt.total_probed,
                        round_rtts.join(" ")
                    ),
                );
                if let Some(ref th) = self.telemetry {
                    th.record_lane_hunt(
                        false,
                        format!(
                            "new-primary up_sport={} rtt={:.1}ms probed={}",
                            winner.local_port, winner_rtt, hunt.total_probed
                        ),
                    );
                }
                if let Some(tok) = self.promote_stun_winner(
                    winner,
                    client_addr,
                    ka_max_retries,
                    None,
                    false,
                    None,
                    hunt.pending,
                    hunt.pending_bytes,
                    now,
                    standby_ready,
                ) {
                    self.token_by_client.insert(client_addr, tok);
                }
            }
            HuntPurpose::MbbStandby {
                primary_tok,
                client_addr,
                degrade_baseline_ms,
            } => {
                // 校验归属主会话依然存活
                let prim_alive = self.token_by_client.get(&client_addr) == Some(&primary_tok)
                    && self
                        .sessions_by_token
                        .get(&primary_tok)
                        .is_some_and(|s| s.state == HandshakeState::Ready);
                if !prim_alive {
                    let _ = self.poll.registry().deregister(&mut winner.sock);
                    return;
                }

                // 若是退化触发的后台重抽：只有在命中优秀目标或明显优于当前信道时才切换，避免全局波动抖动
                if let Some(cur_ms_u64) = degrade_baseline_ms {
                    let cur_ms = cur_ms_u64 as f64;
                    let clearly_better = target_met
                        || (winner_rtt + LANE_IMPROVE_MIN_DELTA_MS < cur_ms
                            && winner_rtt <= cur_ms * LANE_IMPROVE_MIN_RATIO);
                    if !clearly_better {
                        let _ = self.poll.registry().deregister(&mut winner.sock);
                        if let Some(prim) = self.sessions_by_token.get_mut(&primary_tok) {
                            prim.standby_spawned = false;
                            prim.next_lane_hunt_at = now
                                + Duration::from_secs(
                                    self.cfg.lane_hunt.normalized().degrade_cooldown_secs,
                                );
                        }
                        log(
                            self.worker_id,
                            &format!(
                                "LANE HUNT [mbb-degrade] no better lane (best={:.1}ms vs cur={:.0}ms, probed={}) -> keeping active primary",
                                winner_rtt, cur_ms, hunt.total_probed
                            ),
                        );
                        if let Some(ref th) = self.telemetry {
                            th.record_lane_hunt(
                                false,
                                format!("keep-active best={:.1}ms cur={:.0}ms", winner_rtt, cur_ms),
                            );
                        }
                        return;
                    }
                }

                self.observe_good_rtt(winner_rtt);
                log(
                    self.worker_id,
                    &format!(
                        "LANE HUNT OK [{}] client={} winner up_sport={} rtt={:.1}ms (round {}/{}, probed={}, sample=[{}]) -> MBB 0ms handover",
                        hunt.purpose.label(),
                        client_addr,
                        winner.local_port,
                        winner_rtt,
                        hunt.round,
                        hunt.max_rounds,
                        hunt.total_probed,
                        round_rtts.join(" ")
                    ),
                );
                if let Some(ref th) = self.telemetry {
                    th.record_lane_hunt(
                        true,
                        format!(
                            "{} up_sport={} rtt={:.1}ms probed={}",
                            hunt.purpose.label(),
                            winner.local_port,
                            winner_rtt,
                            hunt.total_probed
                        ),
                    );
                }
                if let Some(tok) = self.promote_stun_winner(
                    winner,
                    client_addr,
                    KA_MAX_RETRIES,
                    Some(primary_tok),
                    false,
                    None,
                    VecDeque::new(),
                    0,
                    now,
                    standby_ready,
                ) {
                    self.standby_by_client.insert(client_addr, tok);
                } else if let Some(prim) = self.sessions_by_token.get_mut(&primary_tok) {
                    prim.standby_spawned = false;
                }
            }
            HuntPurpose::Migrate1Rtt {
                session_tok,
                client_addr,
                recently_rotated,
            } => {
                self.commit_migrate_1rtt_winner(
                    session_tok,
                    client_addr,
                    recently_rotated,
                    winner,
                    hunt.total_probed,
                    &round_rtts,
                    now,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn promote_stun_winner(
        &mut self,
        winner: HuntCandidate,
        client_addr: SocketAddr,
        ka_max_retries: u8,
        standby_for_primary: Option<Token>,
        is_prewarm: bool,
        next_keepwarm_at: Option<Instant>,
        pending: VecDeque<Vec<u8>>,
        pending_bytes: usize,
        now: Instant,
        standby_ready: &mut Vec<(Token, SocketAddr)>,
    ) -> Option<Token> {
        let tok = winner.tok;
        let rtt_ms = winner.rtt_ms.unwrap_or(0.0);
        if let Some(ref th) = self.telemetry {
            th.record_stun_ok(rtt_ms, 0, winner.mapped_addr);
        }
        let mut sess = build_session_after_stun(
            self.worker_id,
            client_addr,
            winner.sock,
            winner.local_port,
            winner.ice,
            winner.txid,
            rtt_ms,
            winner.mapped_addr,
            &self.cfg,
            &mut self.cert_cache,
            &self.dtls_pool,
            &self.cpu,
            now,
            self.retry_dur,
            self.ka_base_ms,
            ka_max_retries,
            standby_for_primary,
            is_prewarm,
            next_keepwarm_at,
            pending,
            pending_bytes,
            &mut self.dtls_buf,
            &mut self.wbuf,
        );
        if sess.state == HandshakeState::Ready && sess.is_standby {
            standby_ready.push((tok, client_addr));
        }
        if sess.state == HandshakeState::Ready && !sess.is_prewarm {
            schedule_mbb_timers(&mut sess, &self.cfg, now);
        }
        self.sessions_by_token.insert(tok, sess);
        Some(tok)
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_migrate_1rtt_winner(
        &mut self,
        session_tok: Token,
        client_addr: SocketAddr,
        recently_rotated: bool,
        mut winner: HuntCandidate,
        total_probed: usize,
        round_rtts: &[String],
        now: Instant,
    ) {
        let Some(challenge) = winner.mig_challenge else {
            let _ = self.poll.registry().deregister(&mut winner.sock);
            return;
        };
        let winner_rtt = winner.rtt_ms.unwrap_or(0.0);
        let _ = self.poll.registry().deregister(&mut winner.sock);

        let old_up_opt: Option<MioUdpSocket>;
        let mut flushed = 0usize;
        let mut flushed_bytes = 0u64;
        let old_port: u16;

        if let Some(sess) = self.sessions_by_token.get_mut(&session_tok) {
            let mut old_up = std::mem::replace(&mut sess.upstream, winner.sock);
            let _ = self.poll.registry().deregister(&mut old_up);
            if self
                .poll
                .registry()
                .register(&mut sess.upstream, session_tok, Interest::READABLE)
                .is_err()
            {
                sess.upstream = old_up;
                let _ = self.poll.registry().register(
                    &mut sess.upstream,
                    session_tok,
                    Interest::READABLE,
                );
                return;
            }
            old_port = sess.local_port;
            old_up_opt = Some(old_up);
            sess.local_port = winner.local_port;
            sess.ka_max_retries = if recently_rotated {
                KA_MAX_RETRIES_DAMPED
            } else {
                KA_MAX_RETRIES
            };
            sess.lane_rtt_ewma_ms = Some(winner_rtt);
            sess.lane_degrade_streak = 0;
            sess.next_lane_hunt_at =
                now + Duration::from_secs(self.cfg.lane_hunt.normalized().degrade_cooldown_secs);

            let mut resp_payload = [0u8; PATH_CHALLENGE_PAYLOAD_LEN];
            resp_payload[0] = PATH_CHALLENGE_OP_RESP;
            resp_payload[1..PATH_CHALLENGE_PAYLOAD_LEN]
                .copy_from_slice(&challenge[1..PATH_CHALLENGE_PAYLOAD_LEN]);
            sess.pending_bytes = 0;
            if let Some(ref mut cipher) = sess.cipher {
                let mut cbuf = [0u8; CTRL_FRAME_BUF_LEN];
                if let Some(wn) =
                    cipher.wrap_control_into(SRTP_PATH_CHALLENGE_MAGIC, &resp_payload, &mut cbuf)
                {
                    if sess.upstream.send(&cbuf[..wn]).is_ok() {
                        sess.tx_pkts += 1;
                    }
                }
                while let Some(raw) = sess.pending.pop_front() {
                    if let Some(wn) = cipher.wrap_into(&raw, &mut self.wbuf) {
                        if sess.upstream.send(&self.wbuf[..wn]).is_ok() {
                            sess.tx_pkts += 1;
                            sess.tx_bytes += raw.len() as u64;
                            flushed_bytes = flushed_bytes.saturating_add(raw.len() as u64);
                            flushed += 1;
                        }
                    }
                }
            }
            sess.state = HandshakeState::Ready;
            sess.mig_txid = None;
            sess.mig_retry_at = None;
            sess.mig_echo_payload = Some(resp_payload.to_vec());
            sess.mig_echo_next_at = Some(now + Duration::from_millis(CLIENT_MIG_ECHO_INTERVAL_MS));
            sess.mig_echo_left = MIG_ECHO_COUNT;
            sess.next_keepalive_at = now + jitter_duration_ms(self.ka_base_ms);
            if flushed_bytes > 0 {
                record_client_media_bytes(sess, &self.cfg, self.ka_base_ms, now, flushed_bytes);
            }
        } else {
            return;
        }

        // 将旧黑洞套接字转入 50s 只收引流池（零 ICMP Port Unreachable）
        if let Some(mut old_up) = old_up_opt {
            if self.old_path_drains.len() >= MAX_DRAINING_SESSIONS {
                if let Some((&oldest_t, _)) =
                    self.old_path_drains.iter().min_by_key(|(_, d)| d.deadline)
                {
                    if let Some(mut evicted) = self.old_path_drains.remove(&oldest_t) {
                        let _ = self.poll.registry().deregister(&mut evicted.sock);
                    }
                }
            }
            let drain_tok = alloc_token(&mut self.next_token_id);
            if self
                .poll
                .registry()
                .register(&mut old_up, drain_tok, Interest::READABLE)
                .is_ok()
            {
                self.old_path_drains.insert(
                    drain_tok,
                    OldPathDrain {
                        sock: old_up,
                        owner_tok: session_tok,
                        deadline: now + Duration::from_secs(BLACKHOLE_DRAIN_SECS),
                    },
                );
            }
        }

        self.observe_good_rtt(winner_rtt);
        log(
            self.worker_id,
            &format!(
                "LANE HUNT OK [migrate-1rtt] client={} old_sport={} -> winner up_sport={} rtt={:.1}ms (probed={}, sample=[{}]) flushed={}",
                client_addr,
                old_port,
                winner.local_port,
                winner_rtt,
                total_probed,
                round_rtts.join(" "),
                flushed
            ),
        );
        if let Some(ref th) = self.telemetry {
            th.record_stun_ok(winner_rtt, 0, winner.mapped_addr);
            th.record_migration_1rtt(format!(
                "up_sport={} rtt={:.1}ms flushed={}",
                winner.local_port, winner_rtt, flushed
            ));
            th.record_lane_hunt(
                true,
                format!(
                    "migrate-1rtt {}->{} rtt={:.1}ms",
                    old_port, winner.local_port, winner_rtt
                ),
            );
        }
    }

    fn handle_hunt_empty(&mut self, hunt: LaneHunt, now: Instant) {
        match hunt.purpose {
            HuntPurpose::PreWarm => {
                self.next_prewarm_at = Some(now + Duration::from_millis(PREWARM_FAIL_RETRY_MS));
            }
            HuntPurpose::NewPrimary {
                client_addr,
                ka_max_retries,
            } => {
                // 回退至常规单路会话建立，避免极端丢包下丢失首包队列
                if !self.token_by_client.contains_key(&client_addr) {
                    if let Some(tok) = spawn_client_session(
                        self.worker_id,
                        client_addr,
                        &self.cfg,
                        &mut self.poll,
                        &mut self.sessions_by_token,
                        &mut self.token_by_client,
                        &mut self.standby_by_client,
                        &mut self.next_token_id,
                        &mut self.dtls_buf,
                        now,
                        self.retry_dur,
                        self.ka_base_ms,
                        self.idle_dur,
                        ka_max_retries,
                        None,
                    ) {
                        if let Some(s) = self.sessions_by_token.get_mut(&tok) {
                            s.pending = hunt.pending;
                            s.pending_bytes = hunt.pending_bytes;
                        }
                    }
                }
            }
            HuntPurpose::MbbStandby { primary_tok, .. } => {
                if let Some(prim) = self.sessions_by_token.get_mut(&primary_tok) {
                    prim.standby_spawned = false;
                    prim.next_lane_hunt_at = now
                        + Duration::from_secs(
                            self.cfg.lane_hunt.normalized().degrade_cooldown_secs,
                        );
                }
            }
            HuntPurpose::Migrate1Rtt {
                session_tok,
                client_addr,
                recently_rotated,
            } => {
                // 服务端可能已重启丢失会话状态 -> 优雅关闭旧会话并回退新建带抽卡主会话
                let (carried_pending, carried_bytes) = self
                    .sessions_by_token
                    .get_mut(&session_tok)
                    .map(|s| {
                        s.mig_txid = None;
                        s.mig_retry_at = None;
                        s.state =
                            HandshakeState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
                        let p = std::mem::take(&mut s.pending);
                        let b = s.pending_bytes;
                        s.pending_bytes = 0;
                        (p, b)
                    })
                    .unwrap_or_else(|| (VecDeque::new(), 0));
                if self.token_by_client.get(&client_addr) == Some(&session_tok) {
                    self.token_by_client.remove(&client_addr);
                }
                cancel_standby_for_client(
                    client_addr,
                    &mut self.standby_by_client,
                    &mut self.sessions_by_token,
                    &mut self.dtls_buf,
                    now,
                );
                let ka_retries = if recently_rotated {
                    KA_MAX_RETRIES_DAMPED
                } else {
                    KA_MAX_RETRIES
                };
                let _ = self.start_lane_hunt(
                    HuntPurpose::NewPrimary {
                        client_addr,
                        ka_max_retries: ka_retries,
                    },
                    now,
                    carried_pending,
                    carried_bytes,
                );
            }
        }
    }

    /// 当本地客户端到达首包时，尝试 0ms 领用已预热（Ready 或 DtlsHandshake）的优秀信道会话。
    pub(super) fn try_adopt_prewarm(
        &mut self,
        client_addr: SocketAddr,
        now: Instant,
    ) -> Option<Token> {
        let tok = self.prewarm_tok?;
        let adoptable = self.sessions_by_token.get(&tok).is_some_and(|s| {
            s.is_prewarm
                && matches!(
                    s.state,
                    HandshakeState::Ready | HandshakeState::DtlsHandshake
                )
        });
        if !adoptable {
            self.prewarm_tok = None;
            return None;
        }
        self.prewarm_tok = None;
        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            sess.is_prewarm = false;
            sess.client_addr = client_addr;
            sess.next_keepwarm_at = None;
            sess.last_data_active = now;
            sess.last_active_burst = now;
            if sess.state == HandshakeState::Ready {
                schedule_mbb_timers(sess, &self.cfg, now);
            }
            log(
                self.worker_id,
                &format!(
                    "adopted pre-warmed session client={} -> up_sport={} state={} (0ms lane ready!)",
                    client_addr,
                    sess.local_port,
                    if sess.state == HandshakeState::Ready {
                        "READY"
                    } else {
                        "DTLS"
                    }
                ),
            );
        }
        self.token_by_client.insert(client_addr, tok);
        Some(tok)
    }

    /// 每次 STUN 保活应答后评估当前活跃/预热信道质量，持续退化时触发后台 0ms MBB 重抽。
    pub(super) fn evaluate_lane_quality_on_ka(&mut self, tok: Token, ka_rtt_ms: f64, now: Instant) {
        if !self.cfg.lane_hunt.enabled || !ka_rtt_ms.is_finite() || ka_rtt_ms <= 0.0 {
            return;
        }
        let ceiling = self.effective_degrade_ceiling_rtt();
        enum Action {
            None,
            ReplacePrewarm,
            StartMbbDegrade {
                client_addr: SocketAddr,
                ewma_ms: f64,
            },
        }
        let mut action = Action::None;
        let mut observed_good = false;
        let cooldown = Duration::from_secs(self.cfg.lane_hunt.normalized().degrade_cooldown_secs);

        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            if sess.is_standby || sess.state != HandshakeState::Ready {
                return;
            }
            let ewma = match sess.lane_rtt_ewma_ms {
                Some(prev) => prev * (1.0 - LANE_RTT_EWMA_ALPHA) + ka_rtt_ms * LANE_RTT_EWMA_ALPHA,
                None => ka_rtt_ms,
            };
            sess.lane_rtt_ewma_ms = Some(ewma);

            if let Some(ceil) = ceiling {
                if ka_rtt_ms > ceil {
                    sess.lane_degrade_streak = sess.lane_degrade_streak.saturating_add(1);
                    if sess.lane_degrade_streak >= LANE_DEGRADE_CONSECUTIVE
                        && !sess.standby_spawned
                        && now >= sess.next_lane_hunt_at
                    {
                        sess.lane_degrade_streak = 0;
                        sess.next_lane_hunt_at = now + cooldown;
                        if sess.is_prewarm {
                            log(
                                self.worker_id,
                                &format!(
                                    "LANE GUARD: pre-warmed up_sport={} degraded (rtt={:.1}ms, ewma={:.1}ms > {:.0}ms x{}) -> re-hunting",
                                    sess.local_port, ka_rtt_ms, ewma, ceil, LANE_DEGRADE_CONSECUTIVE
                                ),
                            );
                            graceful_teardown_client(sess, &mut self.dtls_buf);
                            sess.state = HandshakeState::Closing(
                                now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS),
                            );
                            action = Action::ReplacePrewarm;
                        } else {
                            log(
                                self.worker_id,
                                &format!(
                                    "LANE GUARD: active up_sport={} degraded (rtt={:.1}ms, ewma={:.1}ms > {:.0}ms x{}) -> background MBB lane hunt",
                                    sess.local_port, ka_rtt_ms, ewma, ceil, LANE_DEGRADE_CONSECUTIVE
                                ),
                            );
                            action = Action::StartMbbDegrade {
                                client_addr: sess.client_addr,
                                ewma_ms: ewma,
                            };
                        }
                    }
                } else {
                    sess.lane_degrade_streak = 0;
                    observed_good = true;
                }
            } else {
                observed_good = true;
            }
        }

        if observed_good {
            self.observe_good_rtt(ka_rtt_ms);
        }

        match action {
            Action::None => {}
            Action::ReplacePrewarm => {
                if self.prewarm_tok == Some(tok) {
                    self.prewarm_tok = None;
                }
                let _ = self.start_lane_hunt(HuntPurpose::PreWarm, now, VecDeque::new(), 0);
            }
            Action::StartMbbDegrade {
                client_addr,
                ewma_ms,
            } => {
                let _ = self.start_lane_hunt(
                    HuntPurpose::MbbStandby {
                        primary_tok: tok,
                        client_addr,
                        degrade_baseline_ms: Some(ewma_ms.round() as u64),
                    },
                    now,
                    VecDeque::new(),
                    0,
                );
            }
        }
    }
}

/// 供 `build_session_after_stun` 使用的 DTLS/SRTP 外层包头长度辅助。
#[inline]
pub(super) fn client_outer_hdr_len(server_addr: SocketAddr) -> usize {
    outer_udp_hdr_len(server_addr)
}
