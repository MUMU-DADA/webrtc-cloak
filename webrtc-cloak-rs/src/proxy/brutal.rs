//! Hysteria 2 风格 Brutal 丢包补偿恒速拥塞控制器（实现 `quinn_proto::congestion::Controller`）。
//!
//! 核心机制：
//! - 维护最近 5 秒每秒 1 槽的 ACK / Lost 统计滑动窗口；
//! - `ack_rate = clamp(acked / (acked + lost), MIN_ACK_RATE, 1.0)`（默认下限 `0.70`，补偿倍速上限 `1.43x`）；
//! - `effective_bytes_per_sec = target_bytes_per_sec / ack_rate`；
//! - 遇丢包绝不减半拥塞窗口（抗家宽国际出口 1%–10% 随机丢包），窗口随真实 RTT 与动态协商速率即时更新；
//! - 支持连接建立后经 Control Stream 动态下发/限幅目标带宽（通过 `Arc<BrutalRateHandle>` 跨 32/64 位无锁/安全更新）。

use quinn_proto::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use std::any::Any;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 跨 32/64 位架构的动态 Brutal 速率句柄：64 位平台走无锁 `AtomicU64`，32 位 `armv5te` 等无 64 位原子目标安全回退 `Mutex<u64>`。
pub struct BrutalRateHandle {
    #[cfg(target_has_atomic = "64")]
    inner: AtomicU64,
    #[cfg(not(target_has_atomic = "64"))]
    inner: Mutex<u64>,
}

impl BrutalRateHandle {
    pub fn new(bytes_per_sec: u64) -> Self {
        Self {
            #[cfg(target_has_atomic = "64")]
            inner: AtomicU64::new(bytes_per_sec),
            #[cfg(not(target_has_atomic = "64"))]
            inner: Mutex::new(bytes_per_sec),
        }
    }

    #[inline]
    pub fn load(&self) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            self.inner.load(Ordering::Relaxed)
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            self.inner
                .lock()
                .map(|g| *g)
                .unwrap_or(MIN_BRUTAL_BYTES_PER_SEC)
        }
    }

    #[inline]
    pub fn store(&self, bytes_per_sec: u64) {
        #[cfg(target_has_atomic = "64")]
        {
            self.inner.store(bytes_per_sec, Ordering::Relaxed);
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            if let Ok(mut g) = self.inner.lock() {
                *g = bytes_per_sec;
            }
        }
    }
}

/// 最小发包速率下限（64 KiB/s = 512 kbps），防止零值除零或死锁。
pub const MIN_BRUTAL_BYTES_PER_SEC: u64 = 64 * 1024;
/// 滑动丢包统计窗口槽位数（秒）。
const PKT_INFO_SLOTS: usize = 5;
/// 启用丢包率补偿的最小样本包数阈值（避免冷启动偶发丢包误放大）。
const MIN_SAMPLE_COUNT: u64 = 20;
/// 最低 ACK 比率下限（0.70 => 最多补偿 30% 丢包，约 1.43x 发包速率，防黑洞放大风暴）。
const DEFAULT_MIN_ACK_RATE: f64 = 0.70;
/// 拥塞窗口相对有效 BDP 的弹性系数（quinn-proto 内置 Pacer 已固定按 1.25× cwnd/rtt 放行，
/// 取 1.00 可精确得到 1.25× 目标速率的线速上限，覆盖 SRTP/QUIC 封装与抖动裕量且避免 1.50× 过冲打爆出口 fq 队列）。
const CWND_BDP_GAIN: f64 = 1.00;
/// 单连接最大拥塞窗口硬上限（32 MiB）。
const MAX_CWND_BYTES: u64 = 32 * 1024 * 1024;
/// 冷启动首包未测出 RTT 前的默认估计 RTT（毫秒）。
const DEFAULT_INITIAL_RTT_MS: u64 = 80;

#[derive(Clone, Copy, Default)]
struct PktSlot {
    sec: u64,
    acked: u64,
    lost: u64,
}

/// 可动态调速的 Brutal 拥塞控制工厂。
///
/// 每次 `quinn-proto` 创建新连接调用 `build()` 时，会生成一个独立的 `Arc<BrutalRateHandle>` 目标速率句柄
/// 并暂存至 `last_rate_handle`，调用方在 `endpoint.connect()` / `endpoint.accept()` 后立即取走，
/// 即可在 Control Stream 完成带宽协商后精准更新该连接的真实 Brutal 发送速率。
pub struct BrutalConfig {
    default_bytes_per_sec: u64,
    min_ack_rate: f64,
    last_rate_handle: Mutex<Option<Arc<BrutalRateHandle>>>,
}

impl BrutalConfig {
    pub fn new(default_bytes_per_sec: u64) -> Self {
        Self {
            default_bytes_per_sec: default_bytes_per_sec.max(MIN_BRUTAL_BYTES_PER_SEC),
            min_ack_rate: DEFAULT_MIN_ACK_RATE,
            last_rate_handle: Mutex::new(None),
        }
    }

    #[allow(dead_code)]
    pub fn with_min_ack_rate(mut self, min_ack_rate: f64) -> Self {
        self.min_ack_rate = min_ack_rate.clamp(0.50, 1.0);
        self
    }

    /// 取走最近一次新建连接绑定的动态速率句柄（字节/秒）。
    pub fn take_last_rate_handle(&self) -> Arc<BrutalRateHandle> {
        if let Ok(mut guard) = self.last_rate_handle.lock() {
            if let Some(h) = guard.take() {
                return h;
            }
        }
        Arc::new(BrutalRateHandle::new(self.default_bytes_per_sec))
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let rate_handle = Arc::new(BrutalRateHandle::new(self.default_bytes_per_sec));
        if let Ok(mut guard) = self.last_rate_handle.lock() {
            *guard = Some(Arc::clone(&rate_handle));
        }
        Box::new(BrutalController::new(
            rate_handle,
            self.min_ack_rate,
            now,
            current_mtu,
        ))
    }
}

#[derive(Clone)]
pub struct BrutalController {
    target_bytes_per_sec: Arc<BrutalRateHandle>,
    min_ack_rate: f64,
    epoch: Instant,
    current_mtu: u16,
    last_rtt: Duration,
    slots: [PktSlot; PKT_INFO_SLOTS],
    cached_ack_rate: f64,
}

impl BrutalController {
    pub fn new(
        target_bytes_per_sec: Arc<BrutalRateHandle>,
        min_ack_rate: f64,
        now: Instant,
        current_mtu: u16,
    ) -> Self {
        Self {
            target_bytes_per_sec,
            min_ack_rate: min_ack_rate.clamp(0.50, 1.0),
            epoch: now,
            current_mtu: current_mtu.max(1200),
            last_rtt: Duration::from_millis(DEFAULT_INITIAL_RTT_MS),
            slots: [PktSlot::default(); PKT_INFO_SLOTS],
            cached_ack_rate: 1.0,
        }
    }

    #[inline]
    fn slot_sec(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs() + 1
    }

    fn record_outcome(&mut self, now: Instant, acked_pkts: u64, lost_pkts: u64) {
        let sec = self.slot_sec(now);
        let idx = (sec as usize) % PKT_INFO_SLOTS;
        if self.slots[idx].sec != sec {
            self.slots[idx] = PktSlot {
                sec,
                acked: acked_pkts,
                lost: lost_pkts,
            };
        } else {
            self.slots[idx].acked = self.slots[idx].acked.saturating_add(acked_pkts);
            self.slots[idx].lost = self.slots[idx].lost.saturating_add(lost_pkts);
        }
        self.refresh_ack_rate(sec);
    }

    fn refresh_ack_rate(&mut self, cur_sec: u64) {
        let min_valid_sec = cur_sec.saturating_sub((PKT_INFO_SLOTS as u64) - 1);
        let mut total_acked = 0u64;
        let mut total_lost = 0u64;
        for s in &self.slots {
            if s.sec >= min_valid_sec && s.sec <= cur_sec {
                total_acked = total_acked.saturating_add(s.acked);
                total_lost = total_lost.saturating_add(s.lost);
            }
        }
        let total = total_acked.saturating_add(total_lost);
        if total < MIN_SAMPLE_COUNT {
            self.cached_ack_rate = 1.0;
        } else {
            let raw = total_acked as f64 / total as f64;
            self.cached_ack_rate = raw.clamp(self.min_ack_rate, 1.0);
        }
    }

    #[inline]
    fn effective_bytes_per_sec(&self) -> f64 {
        let target = self
            .target_bytes_per_sec
            .load()
            .max(MIN_BRUTAL_BYTES_PER_SEC);
        (target as f64) / self.cached_ack_rate.clamp(self.min_ack_rate, 1.0)
    }

    #[cfg(test)]
    pub fn record_test_ack(&mut self, now: Instant, bytes: u64, rtt: Duration) {
        if !rtt.is_zero() {
            self.last_rtt = rtt;
        }
        let mtu = u64::from(self.current_mtu).max(1);
        let pkts = bytes.div_ceil(mtu).max(1);
        self.record_outcome(now, pkts, 0);
    }

    #[inline]
    fn compute_cwnd(&self) -> u64 {
        let min_cwnd = u64::from(self.current_mtu) * 10;
        let rtt_secs = self.last_rtt.as_secs_f64().clamp(0.005, 2.0);
        let bdp_bytes = self.effective_bytes_per_sec() * rtt_secs * CWND_BDP_GAIN;
        let raw = if bdp_bytes.is_finite() && bdp_bytes > 0.0 {
            bdp_bytes.round() as u64
        } else {
            min_cwnd
        };
        raw.clamp(min_cwnd, MAX_CWND_BYTES)
    }
}

impl Controller for BrutalController {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, _last_packet_number: u64) {}

    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        let r = rtt.get();
        if !r.is_zero() {
            self.last_rtt = r;
        }
        let mtu = u64::from(self.current_mtu).max(1);
        let pkts = bytes.div_ceil(mtu).max(1);
        self.record_outcome(now, pkts, 0);
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if lost_bytes == 0 {
            return;
        }
        let mtu = u64::from(self.current_mtu).max(1);
        let lost_pkts = lost_bytes.div_ceil(mtu).max(1);
        self.record_outcome(now, 0, lost_pkts);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu.max(1200);
    }

    fn window(&self) -> u64 {
        self.compute_cwnd()
    }

    fn metrics(&self) -> ControllerMetrics {
        let cwnd = self.compute_cwnd();
        let pacing_bps = (self.effective_bytes_per_sec() * 8.0) as u64;
        let mut m = ControllerMetrics::default();
        m.congestion_window = cwnd;
        m.pacing_rate = Some(pacing_bps);
        m
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.compute_cwnd()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
