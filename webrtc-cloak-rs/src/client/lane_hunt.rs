//! 非阻塞多候选 ECMP 信道抽卡探测、启动预热与持续 RTT 优选守护引擎。

use super::dtls::{build_session_after_stun, graceful_teardown_client, spawn_client_session};
use super::worker::ClientWorker;
use super::{
    alloc_token, cancel_standby_for_client, log, make_udp_socket, record_client_media_bytes,
    schedule_mbb_timers, HandshakeState, OldPathDrain, CLIENT_MIG_ECHO_INTERVAL_MS, KA_MAX_RETRIES,
    KA_MAX_RETRIES_DAMPED, MAX_DRAINING_SESSIONS,
};
use crate::constants::{
    outer_udp_hdr_len, unspecified_addr_for, BLACKHOLE_DRAIN_SECS, CLOSING_DRAIN_MS,
    CTRL_FRAME_BUF_LEN, PATH_CHALLENGE_OP_REQ, PATH_CHALLENGE_OP_RESP, PATH_CHALLENGE_PAYLOAD_LEN,
    POST_BYE_CLOSING_DRAIN_MS, SOCK_BUF_8MIB, SRTP_PATH_CHALLENGE_MAGIC, STUN_BINDING_SUCCESS,
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
/// 自动阈值冷启动校准默认最少采样轮次（跨越至少 2 轮取全局最低 RTT，彻底避免硬编码 ms 阈值与单轮抽黑）。
const LANE_COLD_CALIBRATION_ROUNDS: usize = 2;
/// 冷启动自动校准期望的最小独立端口探测总数（`probes` 较小时自动补足到最多 3 轮）。
const LANE_COLD_MIN_PROBES: usize = 6;
/// 成熟已确认活跃信道连续多少次综合评分退化后触发后台 MBB 重抽。
const LANE_DEGRADE_CONSECUTIVE: u8 = 3;
/// 新切换/刚采用信道的试用确认期（Canary）连续多少次退化即快速淘汰重抽。
const LANE_TRIAL_DEGRADE_CONSECUTIVE: u8 = 2;
/// 试用确认期快速淘汰的缩短冷却上限（秒），连续失败过多时自动退回完整冷却防止风暴。
const LANE_TRIAL_FAIL_COOLDOWN_SECS: u64 = 15;
/// 允许启用缩短试用冷却的最大连续试用失败次数。
const LANE_MAX_FAST_TRIAL_RETRIES: u8 = 2;
/// 新信道连续多少个健康评估窗（高评分且低丢包）后晋升为「已强化确认」信道。
const LANE_CONFIRM_GOOD_WINDOWS: u16 = 2;
/// 持续处于亚健康区间（未触发退化但明显弱于历史最优）多少个评估窗后尝试一次低优先级后台寻优。
const LANE_SUBOPT_MIN_WINDOWS: u16 = 6;
/// 低优先级后台寻优的冷却倍率（避免平稳期频繁抽卡）。
const LANE_SUBOPT_COOLDOWN_MULT: u64 = 3;
/// 活跃信道 RTT EWMA 新样本权重。
const LANE_RTT_EWMA_ALPHA: f64 = 0.35;
/// 数据面下行丢包率评估所需的最小已稳定预期包数（低流量时跨保活周期累加直至达标）。
const LANE_DATA_LOSS_MIN_PKTS: u64 = 24;
/// 数据面下行丢包率 EWMA 新样本权重（偏敏捷，及时捕捉突发限速/拥塞丢包）。
const LANE_DATA_LOSS_EWMA_ALPHA: f64 = 0.60;
/// 静默无下行数据面窗口内，历史数据面丢包率的平滑衰减系数。
const LANE_DATA_LOSS_IDLE_DECAY: f64 = 0.75;
/// 触发「丢包主导退化」归类的有效丢包率阈值（8%）。
const LANE_DATA_LOSS_DEGRADE_RATE: f64 = 0.08;
/// 单会话 STUN 保活丢包滑动窗口容量（条，配合单丢包免疫防止偶发 1 包丢失误切）。
const LANE_STUN_WINDOW_CAP: usize = 16;
/// 跨地域无量纲综合评分的 RTT 归一化下限（毫秒，防止本机/局域网 1->5ms 调度抖动误判）。
const LANE_SCORE_RTT_FLOOR_MS: f64 = 30.0;
/// 综合评分中有效丢包率的惩罚权重（8% 丢包 -> 代价 +0.84 -> 评分 54.3 < 55，与 8% 退化线精确对齐）。
const LANE_SCORE_LOSS_WEIGHT: f64 = 10.5;
/// 综合评分中归一化抖动的惩罚权重与上限。
const LANE_SCORE_JITTER_WEIGHT: f64 = 0.45;
const LANE_SCORE_JITTER_CAP: f64 = 1.5;
/// 综合评分低于该值判定信道退化（0..=100，满分 100）。
pub(super) const LANE_DEGRADE_SCORE_THRESHOLD: f64 = 55.0;
/// 综合评分达到该值且低丢包才可累计试用确认并强化最优基线。
const LANE_CONFIRM_SCORE_THRESHOLD: f64 = 70.0;
/// 退化重抽未能命中目标阈值时，仍值得切换的最小绝对收益（毫秒）。
const LANE_IMPROVE_MIN_DELTA_MS: f64 = 25.0;
/// 低优先级后台寻优要求候选比当前信道至少快多少毫秒。
const LANE_OPT_MIN_DELTA_MS: f64 = 15.0;
/// 退化/寻优重抽仍值得切换的最大 RTT 比例（需至少快 20%）。
const LANE_IMPROVE_MIN_RATIO: f64 = 0.80;
/// 自动阈值模式下，后续抽卡判定优秀信道的基线倍率与最小增量（毫秒）。
/// 严格低于 `score < 55` 对应的无丢包退化上界（`b + 0.818 * max(b, 30)`），形成无陷阱带迟滞区间。
const LANE_AUTO_TARGET_MULT: f64 = 1.40;
const LANE_AUTO_TARGET_ADD_MS: f64 = 20.0;
/// 冷启动自动校准单轮探测等待超时（毫秒，覆盖跨洋高延迟链路）。
const LANE_COLD_ROUND_TIMEOUT_MS: u64 = 750;
/// 冷启动自动校准早停附加余量与上下限（毫秒，确保同轮更快兄弟必能到达，同时不傻等绕路慢道）。
const LANE_EARLY_SETTLE_AUTO_MARGIN_MS: f64 = 45.0;
const LANE_EARLY_SETTLE_AUTO_MIN_MS: u64 = 80;
const LANE_EARLY_SETTLE_AUTO_MAX_MS: u64 = 550;
/// 单轮探测等待超时下限与上限（毫秒）。
const LANE_ROUND_TIMEOUT_MIN_MS: u64 = 450;
const LANE_ROUND_TIMEOUT_MAX_MS: u64 = 1200;
/// 预热抽卡失败后的初始重试间隔（毫秒）与空闲重热延迟（毫秒）。
const PREWARM_FAIL_RETRY_MS: u64 = 3_000;
const PREWARM_IDLE_REARM_MS: u64 = 1_500;
/// 1-RTT 迁移成功后 `0xFFFD` 响应的补发次数（与 `worker_io::CLIENT_MIG_ECHO_COUNT` 对齐）。
const MIG_ECHO_COUNT: u8 = 3;

/// 跨地域无量纲综合信道评分（`0.0..=100.0`，越高越好）。
/// 融合相对延迟倍率、真实数据面/STUN 有效丢包率与归一化抖动，在 5ms 局域网到 250ms 跨洲链路上通用一致。
pub(super) fn compute_lane_score(
    rtt_ewma_ms: f64,
    ref_rtt_ms: f64,
    loss_eff: f64,
    jitter_ms: f64,
) -> f64 {
    if !rtt_ewma_ms.is_finite() || !ref_rtt_ms.is_finite() {
        return 100.0;
    }
    let scale = ref_rtt_ms.max(LANE_SCORE_RTT_FLOOR_MS);
    let rtt_term = 1.0 + (rtt_ewma_ms - ref_rtt_ms).max(0.0) / scale;
    let loss_term = loss_eff.clamp(0.0, 1.0) * LANE_SCORE_LOSS_WEIGHT;
    let jitter_term =
        (jitter_ms.max(0.0) / scale).min(LANE_SCORE_JITTER_CAP) * LANE_SCORE_JITTER_WEIGHT;
    let cost = (rtt_term + loss_term + jitter_term).max(1.0);
    (100.0 / cost).clamp(0.0, 100.0)
}

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
pub(super) enum MbbHuntReason {
    /// 定时或字节预算触发的计划 5-tuple 轮换：始终切换到本轮抽卡最优候选。
    ScheduledRotate,
    /// 活跃信道延迟/抖动退化：仅当候选达标或明显优于当前信道时才切换，避免全局拥塞抖动。
    DegradeRtt { cur_ewma_ms: u64 },
    /// 活跃信道数据面或 STUN 丢包退化：接受任何达标或不显著慢于当前信道的健康候选以逃离限速/高丢包通道。
    DegradeLoss { cur_ewma_ms: u64, loss_pct_x10: u16 },
    /// 长期处于亚健康区间后的低优先级后台寻优：仅在抽到严格更优信道时切换，零打扰强化最优信道。
    Optimize {
        cur_ewma_ms: u64,
        cur_loss_pct_x10: u16,
    },
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
        reason: MbbHuntReason,
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
                reason: MbbHuntReason::ScheduledRotate,
                ..
            } => "mbb-rotate",
            HuntPurpose::MbbStandby {
                reason: MbbHuntReason::DegradeRtt { .. },
                ..
            } => "mbb-degrade-rtt",
            HuntPurpose::MbbStandby {
                reason: MbbHuntReason::DegradeLoss { .. },
                ..
            } => "mbb-degrade-loss",
            HuntPurpose::MbbStandby {
                reason: MbbHuntReason::Optimize { .. },
                ..
            } => "mbb-optimize",
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
    pub(super) cold_calibration: bool,
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

    /// 计算新信道试用确认期（Canary）允许的最短重抽冷却：正常时缩短至 15s 快速逃离劣化新通道；
    /// 若连续试用失败过多（表明网络或本地链路整体拥塞/丢包），按 2^k 指数退避（上限 `MAX_LANE_DEGRADE_COOLDOWN_SECS`）防止切换风暴。
    pub(super) fn trial_cooldown_dur(&self) -> Duration {
        let base_secs = self.cfg.lane_hunt.normalized().degrade_cooldown_secs;
        if self.consecutive_trial_failures < LANE_MAX_FAST_TRIAL_RETRIES {
            Duration::from_secs(base_secs.min(LANE_TRIAL_FAIL_COOLDOWN_SECS))
        } else {
            let exp = (self.consecutive_trial_failures - LANE_MAX_FAST_TRIAL_RETRIES).min(3);
            let backed_off = base_secs
                .saturating_mul(1u64 << exp)
                .min(MAX_LANE_DEGRADE_COOLDOWN_SECS);
            Duration::from_secs(backed_off)
        }
    }

    /// 强化更新观测到的最优信道基线 RTT（使用保守平滑步长仅向更优方向收紧，防止单次毛刺棘轮下漂）。
    pub(super) fn observe_good_rtt(&mut self, rtt_ms: f64) {
        if !rtt_ms.is_finite() || rtt_ms <= 0.0 || rtt_ms > 30_000.0 {
            return;
        }
        self.best_observed_rtt_ms = Some(match self.best_observed_rtt_ms {
            Some(prev) if rtt_ms < prev => prev * 0.50 + rtt_ms * 0.50,
            Some(prev) => prev,
            None => rtt_ms,
        });
    }

    /// 当一整次多轮抽卡穷尽全部轮次后仍无法达到历史基线（例如从 Wi-Fi 切到 5G 或网络全局抬升），
    /// 温和向上松弛基线 RTT，使自适应评分逐步收敛到新的真实地板而不永久误报。
    fn relax_baseline_rtt(&mut self, observed_best_ms: f64) {
        if !observed_best_ms.is_finite() || observed_best_ms <= 0.0 || observed_best_ms > 30_000.0 {
            return;
        }
        if let Some(prev) = self.best_observed_rtt_ms {
            if observed_best_ms > prev {
                self.best_observed_rtt_ms = Some(prev * 0.85 + observed_best_ms * 0.15);
            }
        }
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
        let cold_calibration = cfg.target_rtt_ms == 0
            && self.best_observed_rtt_ms.is_none()
            && !matches!(purpose, HuntPurpose::Migrate1Rtt { .. });
        let mut hunt = LaneHunt {
            id,
            purpose,
            cold_calibration,
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
                if hunt.cold_calibration {
                    "auto-calibrate(min-rtt)".into()
                } else {
                    self.effective_hunt_target_rtt()
                        .map(|t| format!("<={:.0}ms", t))
                        .unwrap_or_else(|| "auto".into())
                }
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
            LANE_COLD_ROUND_TIMEOUT_MS
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
                match make_udp_socket(bind_any, Some(self.cfg.server_addr), false, SOCK_BUF_8MIB) {
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
                        // 通用自适应早停：等待至少 `best_rtt + 45ms`（钳位 80..=550ms），保证跨洲高延迟
                        // 链路下任何可能更快（< best_rtt）的兄弟探针都能完整到达，同时不傻等绕路慢包。
                        let grace_ms = ((best_rtt + LANE_EARLY_SETTLE_AUTO_MARGIN_MS) as u64)
                            .clamp(LANE_EARLY_SETTLE_AUTO_MIN_MS, LANE_EARLY_SETTLE_AUTO_MAX_MS);
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
        let target_met = if hunt.cold_calibration {
            // PreWarm 在后台异步执行，probes 较小时可补足至最多 3 轮凑够 >=6 端口；
            // NewPrimary 有首包在等待，最多 2 轮即可避免跨洲链路首连延迟过长。
            let desired_rounds = if hunt.purpose == HuntPurpose::PreWarm
                && hunt.total_probed < LANE_COLD_MIN_PROBES
            {
                hunt.max_rounds.min(3)
            } else {
                hunt.max_rounds.min(LANE_COLD_CALIBRATION_ROUNDS)
            };
            best_rtt.is_some() && hunt.round >= desired_rounds
        } else {
            match (best_rtt, eff_target) {
                (Some(r), Some(t)) => r <= t,
                (Some(_), None) => true,
                (None, _) => false,
            }
        };

        // 未达标（或处于冷启动多轮最低延迟校准期）且还有剩余轮次 -> 继续下一轮抽卡（保留最佳候选做保底）
        if !target_met && hunt.round < hunt.max_rounds {
            if hunt.cold_calibration {
                log(
                    self.worker_id,
                    &format!(
                        "LANE HUNT [{}] calibration round {}/{} [{}] best={} -> sampling next round for global minimum",
                        hunt.purpose.label(),
                        hunt.round,
                        hunt.max_rounds,
                        round_rtts.join(" "),
                        best_rtt
                            .map(|r| format!("{:.1}ms", r))
                            .unwrap_or_else(|| "none".into()),
                    ),
                );
            } else {
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
            }
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
                reason,
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

                // 按触发原因决策是否切换：计划轮换始终择优切换；延迟退化必须真正优于当前信道（杜绝
                // 基线抬升期因 target_met 短路导致的同类延迟反复切换死循环）；丢包退化接受健康低延迟候选。
                let (accept_switch, cur_desc) = match reason {
                    MbbHuntReason::ScheduledRotate => (true, String::new()),
                    MbbHuntReason::DegradeRtt { cur_ewma_ms } => {
                        let cur_ms = cur_ewma_ms as f64;
                        let clear_gain = winner_rtt + LANE_IMPROVE_MIN_DELTA_MS < cur_ms
                            && winner_rtt <= cur_ms * LANE_IMPROVE_MIN_RATIO;
                        let target_gain = target_met
                            && winner_rtt + LANE_OPT_MIN_DELTA_MS < cur_ms
                            && winner_rtt <= cur_ms * 0.85;
                        (clear_gain || target_gain, format!("cur={:.0}ms", cur_ms))
                    }
                    MbbHuntReason::DegradeLoss {
                        cur_ewma_ms,
                        loss_pct_x10,
                    } => {
                        let cur_ms = cur_ewma_ms as f64;
                        let max_ok = (cur_ms * 1.50 + 35.0).max(eff_target.unwrap_or(0.0));
                        let ok = target_met || winner_rtt <= max_ok;
                        (
                            ok,
                            format!(
                                "cur={:.0}ms/loss={:.1}%",
                                cur_ms,
                                (loss_pct_x10 as f64) / 10.0
                            ),
                        )
                    }
                    MbbHuntReason::Optimize {
                        cur_ewma_ms,
                        cur_loss_pct_x10,
                    } => {
                        let cur_ms = cur_ewma_ms as f64;
                        // 阈值与确认期的 3.0% 丢包界限严格对齐，避免 3.0%~3.9% 区间反复白抽卡
                        let ok = if cur_loss_pct_x10 >= 30 {
                            winner_rtt <= cur_ms * 1.15 + 15.0
                        } else {
                            winner_rtt + LANE_OPT_MIN_DELTA_MS < cur_ms
                                && winner_rtt <= cur_ms * LANE_IMPROVE_MIN_RATIO
                        };
                        (
                            ok,
                            format!(
                                "cur={:.0}ms/loss={:.1}%",
                                cur_ms,
                                (cur_loss_pct_x10 as f64) / 10.0
                            ),
                        )
                    }
                };

                if !accept_switch {
                    let _ = self.poll.registry().deregister(&mut winner.sock);
                    // 退化重抽找不到明显更优信道时，说明网络真实地板可能已上移，温和松弛历史基线
                    if matches!(reason, MbbHuntReason::DegradeRtt { .. })
                        || (!target_met && hunt.round >= hunt.max_rounds)
                    {
                        self.relax_baseline_rtt(winner_rtt);
                    }
                    let full_cd =
                        Duration::from_secs(self.cfg.lane_hunt.normalized().degrade_cooldown_secs);
                    let next_cd = if matches!(reason, MbbHuntReason::Optimize { .. }) {
                        full_cd.saturating_mul(LANE_SUBOPT_COOLDOWN_MULT as u32)
                    } else {
                        self.trial_cooldown_dur().max(full_cd)
                    };
                    if let Some(prim) = self.sessions_by_token.get_mut(&primary_tok) {
                        prim.standby_spawned = false;
                        prim.next_lane_hunt_at = now + next_cd;
                    }
                    log(
                        self.worker_id,
                        &format!(
                            "LANE HUNT [{}] no better lane (best={:.1}ms vs {}, probed={}) -> keeping active primary",
                            hunt.purpose.label(),
                            winner_rtt,
                            cur_desc,
                            hunt.total_probed
                        ),
                    );
                    if let Some(ref th) = self.telemetry {
                        th.record_lane_hunt(
                            false,
                            format!("keep-active best={:.1}ms {}", winner_rtt, cur_desc),
                        );
                    }
                    return;
                }

                if !target_met && hunt.round >= hunt.max_rounds {
                    self.relax_baseline_rtt(winner_rtt);
                } else {
                    self.observe_good_rtt(winner_rtt);
                }
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
        let initial_lane_cooldown = self.trial_cooldown_dur();
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
            initial_lane_cooldown,
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

        let trial_cooldown = self.trial_cooldown_dur();
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
            // 重置新迁移信道的丢包纪元、抖动与试用期状态，彻底隔离旧黑洞断层与旧路径尾包
            if let Some(ref mut cipher) = sess.cipher {
                cipher.reset_rx_loss_epoch();
            }
            sess.lane_prev_settled_exp = 0;
            sess.lane_prev_settled_rx = 0;
            sess.lane_last_ka_settled_exp = 0;
            sess.lane_rtt_ewma_ms = Some(winner_rtt);
            sess.lane_rtt_last_ms = Some(winner_rtt);
            sess.lane_jitter_ms = 0.0;
            sess.lane_data_loss_rate = 0.0;
            sess.lane_stun_outcomes.clear();
            sess.lane_score = None;
            sess.lane_confirmed = false;
            sess.lane_good_windows = 0;
            sess.lane_subopt_windows = 0;
            sess.lane_degrade_streak = 0;
            sess.next_lane_hunt_at = now + trial_cooldown;

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
        let trial_cooldown = self.trial_cooldown_dur();
        self.prewarm_tok = None;
        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            sess.is_prewarm = false;
            sess.client_addr = client_addr;
            sess.next_keepwarm_at = None;
            sess.last_data_active = now;
            sess.last_active_burst = now;
            // 领用后开启真实负载试用确认窗，避免空载 STUN 表现掩盖满载丢包/限速
            if let Some(ref cipher) = sess.cipher {
                let (se, sr) = cipher.rx_settled_stats();
                sess.lane_prev_settled_exp = se;
                sess.lane_prev_settled_rx = sr;
                sess.lane_last_ka_settled_exp = se;
            }
            sess.lane_data_loss_rate = 0.0;
            sess.lane_confirmed = false;
            sess.lane_good_windows = 0;
            sess.lane_subopt_windows = 0;
            sess.lane_degrade_streak = 0;
            sess.next_lane_hunt_at = now + trial_cooldown;
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

    /// 每次 STUN 保活应答后综合评估活跃/预热信道的多维质量（延迟、真实数据面丢包、STUN 丢包与抖动），
    /// 负责试用期确认、最优基线持续强化、退化 0ms MBB 逃逸以及亚健康后台寻优。
    pub(super) fn evaluate_lane_quality_on_ka(
        &mut self,
        tok: Token,
        ka_rtt_ms: f64,
        ka_retries: u8,
        now: Instant,
    ) {
        if !ka_rtt_ms.is_finite() || ka_rtt_ms <= 0.0 {
            return;
        }
        enum Action {
            None,
            ReplacePrewarm,
            StartMbb {
                client_addr: SocketAddr,
                reason: MbbHuntReason,
            },
        }
        let mut action = Action::None;
        let mut observed_good_ewma: Option<f64> = None;
        let mut trial_confirmed_now = false;
        let mut trial_failed_now = false;
        let lane_enabled = self.cfg.lane_hunt.enabled;
        let explicit_target_ms = self.cfg.lane_hunt.target_rtt_ms;
        let best_rtt_snap = self.best_observed_rtt_ms;
        let full_cooldown =
            Duration::from_secs(self.cfg.lane_hunt.normalized().degrade_cooldown_secs);
        let backed_off_cooldown = self.trial_cooldown_dur().max(full_cooldown);

        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            if sess.is_standby || sess.state != HandshakeState::Ready {
                return;
            }

            // 1) 更新真实数据面下行丢包率（基于 SRTP 双 SSRC 已稳定序号窗口，0 额外线开销且免疫 ECMP 乱序）
            if let Some(ref cipher) = sess.cipher {
                let (settled_exp, settled_rx) = cipher.rx_settled_stats();
                let new_since_last_ka = settled_exp.saturating_sub(sess.lane_last_ka_settled_exp);
                sess.lane_last_ka_settled_exp = settled_exp;
                let d_exp = settled_exp.saturating_sub(sess.lane_prev_settled_exp);
                let d_rx = settled_rx.saturating_sub(sess.lane_prev_settled_rx);
                if d_exp >= LANE_DATA_LOSS_MIN_PKTS {
                    let raw_loss =
                        (d_exp.saturating_sub(d_rx) as f64 / d_exp as f64).clamp(0.0, 1.0);
                    sess.lane_data_loss_rate = if sess.lane_data_loss_rate == 0.0 {
                        raw_loss
                    } else {
                        sess.lane_data_loss_rate * (1.0 - LANE_DATA_LOSS_EWMA_ALPHA)
                            + raw_loss * LANE_DATA_LOSS_EWMA_ALPHA
                    };
                    sess.lane_prev_settled_exp = settled_exp;
                    sess.lane_prev_settled_rx = settled_rx;
                } else if new_since_last_ka == 0 && sess.lane_data_loss_rate > 0.0 {
                    // 相邻两次保活间无新增已稳定包（含低速流转静默的 1..=23 残留情况）-> 平滑衰减防历史高丢包永久锁死
                    sess.lane_data_loss_rate *= LANE_DATA_LOSS_IDLE_DECAY;
                    if sess.lane_data_loss_rate < 0.001 {
                        sess.lane_data_loss_rate = 0.0;
                        sess.lane_prev_settled_exp = settled_exp;
                        sess.lane_prev_settled_rx = settled_rx;
                    }
                }
            }

            if !lane_enabled {
                return;
            }

            // 2) 更新单会话 STUN 抖动、RTT EWMA 与 STUN 上行同意丢包窗口
            if let Some(prev_rtt) = sess.lane_rtt_last_ms {
                let d = (ka_rtt_ms - prev_rtt).abs();
                sess.lane_jitter_ms += (d - sess.lane_jitter_ms) / 4.0;
            }
            sess.lane_rtt_last_ms = Some(ka_rtt_ms);
            let ewma = match sess.lane_rtt_ewma_ms {
                Some(prev) => prev * (1.0 - LANE_RTT_EWMA_ALPHA) + ka_rtt_ms * LANE_RTT_EWMA_ALPHA,
                None => ka_rtt_ms,
            };
            sess.lane_rtt_ewma_ms = Some(ewma);

            for _ in 0..ka_retries {
                if sess.lane_stun_outcomes.len() >= LANE_STUN_WINDOW_CAP {
                    sess.lane_stun_outcomes.pop_front();
                }
                sess.lane_stun_outcomes.push_back(false);
            }
            if sess.lane_stun_outcomes.len() >= LANE_STUN_WINDOW_CAP {
                sess.lane_stun_outcomes.pop_front();
            }
            sess.lane_stun_outcomes.push_back(true);
            // 免疫单次偶发 STUN 丢包（仅在窗口内累计 >=2 次重传丢失时才按满窗容量折算上行丢包率）
            let stun_lost = sess.lane_stun_outcomes.iter().filter(|&&ok| !ok).count();
            let stun_loss_rate = if stun_lost <= 1 {
                0.0
            } else {
                (stun_lost as f64) / (LANE_STUN_WINDOW_CAP as f64)
            };

            // 3) 计算跨地域无量纲综合信道评分（0..=100）
            let ref_rtt = if explicit_target_ms > 0 {
                let t = explicit_target_ms as f64;
                best_rtt_snap.unwrap_or(t).max(t * 0.55)
            } else {
                best_rtt_snap.unwrap_or(ewma)
            };
            let loss_eff = sess.lane_data_loss_rate.max(stun_loss_rate).clamp(0.0, 1.0);
            let score = compute_lane_score(ewma, ref_rtt, loss_eff, sess.lane_jitter_ms);
            sess.lane_score = Some(score);

            let explicit_rtt_breach =
                explicit_target_ms > 0 && ka_rtt_ms > (explicit_target_ms as f64);
            let is_degraded = explicit_rtt_breach || score < LANE_DEGRADE_SCORE_THRESHOLD;
            let needed_streak = if !sess.lane_confirmed && !sess.is_prewarm {
                LANE_TRIAL_DEGRADE_CONSECUTIVE
            } else {
                LANE_DEGRADE_CONSECUTIVE
            };

            if is_degraded {
                sess.lane_good_windows = 0;
                sess.lane_subopt_windows = 0;
                sess.lane_degrade_streak = sess.lane_degrade_streak.saturating_add(1);
                if sess.lane_degrade_streak >= needed_streak
                    && !sess.standby_spawned
                    && now >= sess.next_lane_hunt_at
                {
                    sess.lane_degrade_streak = 0;
                    sess.next_lane_hunt_at = now + backed_off_cooldown;
                    if !sess.lane_confirmed && !sess.is_prewarm {
                        trial_failed_now = true;
                    }
                    let reason = if loss_eff >= LANE_DATA_LOSS_DEGRADE_RATE {
                        MbbHuntReason::DegradeLoss {
                            cur_ewma_ms: ewma.round() as u64,
                            loss_pct_x10: (loss_eff * 1000.0).round().min(1000.0) as u16,
                        }
                    } else {
                        MbbHuntReason::DegradeRtt {
                            cur_ewma_ms: ewma.round() as u64,
                        }
                    };
                    if sess.is_prewarm {
                        log(
                            self.worker_id,
                            &format!(
                                "LANE GUARD: pre-warmed up_sport={} degraded (score={:.1}, rtt={:.1}ms, ewma={:.1}ms, loss={:.1}%, jit={:.1}ms x{}) -> re-hunting",
                                sess.local_port,
                                score,
                                ka_rtt_ms,
                                ewma,
                                loss_eff * 100.0,
                                sess.lane_jitter_ms,
                                needed_streak
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
                                "LANE GUARD: active up_sport={} {} (score={:.1}, rtt={:.1}ms, ewma={:.1}ms, data_loss={:.1}%, stun_loss={:.1}%, jit={:.1}ms x{}) -> background MBB lane hunt",
                                sess.local_port,
                                if !sess.lane_confirmed { "failed canary" } else { "degraded" },
                                score,
                                ka_rtt_ms,
                                ewma,
                                sess.lane_data_loss_rate * 100.0,
                                stun_loss_rate * 100.0,
                                sess.lane_jitter_ms,
                                needed_streak
                            ),
                        );
                        action = Action::StartMbb {
                            client_addr: sess.client_addr,
                            reason,
                        };
                    }
                }
            } else {
                sess.lane_degrade_streak = 0;
                if score >= LANE_CONFIRM_SCORE_THRESHOLD && loss_eff < 0.03 {
                    sess.lane_subopt_windows = 0;
                    sess.lane_good_windows = sess.lane_good_windows.saturating_add(1);
                    if !sess.lane_confirmed
                        && !sess.is_prewarm
                        && sess.lane_good_windows >= LANE_CONFIRM_GOOD_WINDOWS
                    {
                        sess.lane_confirmed = true;
                        trial_confirmed_now = true;
                        log(
                            self.worker_id,
                            &format!(
                                "LANE CONFIRMED: up_sport={} passed canary (score={:.1}, ewma={:.1}ms, data_loss={:.1}%, jit={:.1}ms)",
                                sess.local_port,
                                score,
                                ewma,
                                sess.lane_data_loss_rate * 100.0,
                                sess.lane_jitter_ms
                            ),
                        );
                    }
                    if sess.lane_confirmed || sess.is_prewarm {
                        // 使用平滑后的 EWMA 强化历史最优基线，防止单次偶发毛刺棘轮下漂
                        observed_good_ewma = Some(ewma);
                    }
                } else {
                    sess.lane_good_windows = 0;
                    if !sess.is_prewarm && !sess.standby_spawned {
                        sess.lane_subopt_windows = sess.lane_subopt_windows.saturating_add(1);
                        if sess.lane_subopt_windows >= LANE_SUBOPT_MIN_WINDOWS
                            && now >= sess.next_lane_hunt_at
                        {
                            sess.lane_subopt_windows = 0;
                            sess.next_lane_hunt_at = now
                                + full_cooldown.saturating_mul(LANE_SUBOPT_COOLDOWN_MULT as u32);
                            log(
                                self.worker_id,
                                &format!(
                                    "LANE OPTIMIZE: up_sport={} sustained sub-optimal (score={:.1}, ewma={:.1}ms, loss={:.1}%) -> quiet background MBB hunt",
                                    sess.local_port,
                                    score,
                                    ewma,
                                    loss_eff * 100.0
                                ),
                            );
                            action = Action::StartMbb {
                                client_addr: sess.client_addr,
                                reason: MbbHuntReason::Optimize {
                                    cur_ewma_ms: ewma.round() as u64,
                                    cur_loss_pct_x10: (loss_eff * 1000.0).round().min(1000.0)
                                        as u16,
                                },
                            };
                        }
                    }
                }
            }
        }

        if trial_confirmed_now {
            self.consecutive_trial_failures = 0;
        } else if trial_failed_now {
            self.consecutive_trial_failures = self.consecutive_trial_failures.saturating_add(1);
        }
        if let Some(good_ewma) = observed_good_ewma {
            self.observe_good_rtt(good_ewma);
        }

        match action {
            Action::None => {}
            Action::ReplacePrewarm => {
                if self.prewarm_tok == Some(tok) {
                    self.prewarm_tok = None;
                }
                let _ = self.start_lane_hunt(HuntPurpose::PreWarm, now, VecDeque::new(), 0);
            }
            Action::StartMbb {
                client_addr,
                reason,
            } => {
                let _ = self.start_lane_hunt(
                    HuntPurpose::MbbStandby {
                        primary_tok: tok,
                        client_addr,
                        reason,
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
