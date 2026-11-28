//! 单进程融合中继 `mio` 工作线程：支持零解密透传（`passthrough`）、融合 `cloak`/`bypass`/`reverse`
//! 及 `SIGHUP` 不断网过渡期 `AB` 双模热切换。

use super::{
    log, PassthroughConfig, PassthroughTable, RelayConfig, RelayUpstreamConfig, RELAY_QUIET,
};
use crate::bypass::{BypassConfig, BypassWorker};
use crate::client::{
    ClientConfig, ClientWorker, LaneHuntConfig, DEFAULT_LANE_DEGRADE_COOLDOWN_SECS,
    DEFAULT_LANE_PROBES, DEFAULT_LANE_ROUNDS,
};
use crate::constants::{
    outer_udp_hdr_len, SharedPoll, DEFAULT_ROTATE_COOLDOWN_SECS, LISTEN_TOKEN, MIO_EVENTS_CAP,
    REVERSE_LISTEN_TOKEN, SOCK_BUF_8MIB, TELEMETRY_DEFAULT_INTERVAL_SECS, WAKE_TOKEN,
    WORKER_QUIET_STOP_POLL_MS,
};
#[cfg(unix)]
use crate::constants::{RELOAD_PIPE_TOKEN, SHUTDOWN_PIPE_TOKEN};
use crate::hot_reload::{load_relay_hot_config, read_psk_file, resolve_host_port};
#[cfg(unix)]
use crate::protocol::drain_reload_pipe;
use crate::protocol::{
    build_dimpl_config_pool_for, detect_cpu_accel, is_shutdown_requested, register_reload_poll,
    register_shutdown_poll, take_reload_requested, DtlsConfigPool,
};
use crate::server::{
    make_udp_socket, RelayPassthroughPolicy, SeenTxidCache, ServerConfig, ServerHook, ServerWorker,
    SharedV4Registry,
};
use crate::telemetry::{TelemetryHub, WorkerSnapshot};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 中继出站侧工作状态机（单线程零锁与入站 `ServerWorker` 零拷贝直连）。
pub(crate) enum RelayEgress {
    Bypass(BypassWorker),
    Cloak(ClientWorker),
    Reverse(Box<ServerWorker>),
}

impl RelayEgress {
    #[inline]
    pub(crate) fn send_uplink_single(
        &mut self,
        flow_addr: SocketAddr,
        payload: &[u8],
        now: Instant,
    ) -> bool {
        match self {
            RelayEgress::Bypass(b) => b.send_uplink_single(flow_addr, payload, now),
            RelayEgress::Cloak(c) => c.send_uplink_single(flow_addr, payload, now),
            RelayEgress::Reverse(rev) => rev
                .active_ready_relay_flow()
                .is_some_and(|dst| rev.deliver_downlink_single(dst, payload, now)),
        }
    }

    pub(crate) fn close_flow(&mut self, flow_addr: SocketAddr, now: Instant) {
        match self {
            RelayEgress::Bypass(b) => b.close_flow(flow_addr),
            RelayEgress::Cloak(c) => c.close_flow(flow_addr, now),
            RelayEgress::Reverse(_) => {}
        }
    }

    pub(crate) fn graceful_shutdown_all(&mut self) {
        match self {
            RelayEgress::Bypass(b) => b.shutdown_all(),
            RelayEgress::Cloak(c) => c.graceful_shutdown_all(),
            RelayEgress::Reverse(rev) => rev.graceful_shutdown_all(),
        }
    }

    pub(crate) fn build_worker_snapshot(&self) -> WorkerSnapshot {
        match self {
            RelayEgress::Bypass(b) => b.build_worker_snapshot(),
            RelayEgress::Cloak(c) => c.build_worker_snapshot(),
            RelayEgress::Reverse(rev) => rev.build_worker_snapshot(),
        }
    }
}

/// 合并入站（Leg 1）与出站（Leg 2）快照，为单进程中继输出统一遥测视图。
#[inline]
fn merge_relay_snapshot(in_snap: WorkerSnapshot, out_snap: WorkerSnapshot) -> WorkerSnapshot {
    let dtls_version = if !in_snap.dtls_version.is_empty() && in_snap.dtls_version != "none" {
        in_snap.dtls_version
    } else {
        out_snap.dtls_version
    };
    let cipher = if !in_snap.cipher.is_empty() && in_snap.cipher != "none" {
        in_snap.cipher
    } else {
        out_snap.cipher
    };
    WorkerSnapshot {
        active_sessions: in_snap.active_sessions,
        handshaking_sessions: in_snap.handshaking_sessions + out_snap.handshaking_sessions,
        migrating_sessions: out_snap.migrating_sessions,
        tx_bytes_total: in_snap.tx_bytes_total,
        rx_bytes_total: in_snap.rx_bytes_total,
        tx_pkts_total: in_snap.tx_pkts_total,
        rx_pkts_total: in_snap.rx_pkts_total,
        auth_drops_total: in_snap
            .auth_drops_total
            .saturating_add(out_snap.auth_drops_total),
        unauth_drops_total: in_snap
            .unauth_drops_total
            .saturating_add(out_snap.unauth_drops_total),
        active_up_sport: out_snap.active_up_sport,
        active_backend_sport: 0,
        data_loss_pct: out_snap.data_loss_pct,
        lane_score: out_snap.lane_score,
        lane_best_rtt_ms: out_snap.lane_best_rtt_ms,
        lane_confirmed: out_snap.lane_confirmed,
        dtls_version,
        cipher,
        dual_ssrc: in_snap.dual_ssrc || out_snap.dual_ssrc,
    }
}

#[inline]
fn merge_with_passthrough(base: WorkerSnapshot, pt_snap: WorkerSnapshot) -> WorkerSnapshot {
    let dtls_version = if base.active_sessions > 0 {
        base.dtls_version
    } else if pt_snap.active_sessions > 0 {
        pt_snap.dtls_version
    } else {
        base.dtls_version
    };
    let cipher = if base.active_sessions > 0 {
        base.cipher
    } else if pt_snap.active_sessions > 0 {
        pt_snap.cipher
    } else {
        base.cipher
    };
    WorkerSnapshot {
        active_sessions: base.active_sessions + pt_snap.active_sessions,
        handshaking_sessions: base.handshaking_sessions,
        migrating_sessions: base.migrating_sessions,
        tx_bytes_total: base.tx_bytes_total.saturating_add(pt_snap.tx_bytes_total),
        rx_bytes_total: base.rx_bytes_total.saturating_add(pt_snap.rx_bytes_total),
        tx_pkts_total: base.tx_pkts_total.saturating_add(pt_snap.tx_pkts_total),
        rx_pkts_total: base.rx_pkts_total.saturating_add(pt_snap.rx_pkts_total),
        auth_drops_total: base.auth_drops_total,
        unauth_drops_total: base.unauth_drops_total,
        active_up_sport: if pt_snap.active_up_sport != 0 && base.active_sessions == 0 {
            pt_snap.active_up_sport
        } else if base.active_up_sport != 0 {
            base.active_up_sport
        } else {
            pt_snap.active_up_sport
        },
        active_backend_sport: 0,
        data_loss_pct: base.data_loss_pct,
        lane_score: base.lane_score,
        lane_best_rtt_ms: base.lane_best_rtt_ms,
        lane_confirmed: base.lane_confirmed,
        dtls_version,
        cipher,
        dual_ssrc: base.dual_ssrc,
    }
}

/// 运行时中继形态：支持在纯零解密透传与完整加解密中继之间不关主端口热切换。
#[allow(clippy::large_enum_variant)]
enum RelayRuntime {
    PurePassthrough {
        listen_sock: MioUdpSocket,
        pt: PassthroughTable,
    },
    Managed {
        ingress: ServerWorker,
        egress: RelayEgress,
        pt: Option<PassthroughTable>,
        pt_policy: RelayPassthroughPolicy,
        mode_tag: &'static str,
    },
}

impl RelayRuntime {
    fn mode_label(&self) -> &'static str {
        match self {
            RelayRuntime::PurePassthrough { .. } => "passthrough",
            RelayRuntime::Managed {
                pt_policy: RelayPassthroughPolicy::PreferPassthrough,
                ..
            } => "draining->passthrough",
            RelayRuntime::Managed {
                pt_policy: RelayPassthroughPolicy::DrainExistingOnly,
                mode_tag,
                ..
            } => mode_tag,
            RelayRuntime::Managed {
                pt_policy: RelayPassthroughPolicy::FallbackOnUnauth,
                ..
            } => "cloak+passthrough",
            RelayRuntime::Managed { mode_tag, .. } => mode_tag,
        }
    }

    fn build_snapshot(&self) -> WorkerSnapshot {
        match self {
            RelayRuntime::PurePassthrough { pt, .. } => pt.build_worker_snapshot(),
            RelayRuntime::Managed {
                ingress,
                egress,
                pt,
                ..
            } => {
                let base = merge_relay_snapshot(
                    ingress.build_worker_snapshot(),
                    egress.build_worker_snapshot(),
                );
                if let Some(table) = pt {
                    merge_with_passthrough(base, table.build_worker_snapshot())
                } else {
                    base
                }
            }
        }
    }

    fn shutdown_all(&mut self) {
        match self {
            RelayRuntime::PurePassthrough { pt, .. } => {
                pt.shutdown_all();
            }
            RelayRuntime::Managed {
                ingress,
                egress,
                pt,
                ..
            } => {
                ingress.graceful_shutdown_all();
                egress.graceful_shutdown_all();
                if let Some(table) = pt {
                    table.shutdown_all();
                }
            }
        }
    }
}

/// 热重载期间保留的默认模板（用于填充热配置文件中省略的可选字段）。
struct RelayHotDefaults {
    ingress_template: ServerConfig,
    upstream_addr: SocketAddr,
    upstream_psk: Vec<u8>,
    upstream_stun_scope: Option<String>,
    lane_hunt: LaneHuntConfig,
    rotate_interval_secs: u64,
    rotate_max_bytes: u64,
    retry_ms: u64,
    max_retries: u32,
    keepalive_secs: u64,
    reuse_port: bool,
    seen_txids: Arc<Mutex<SeenTxidCache>>,
    registry: Arc<SharedV4Registry>,
    telemetry: Option<Arc<TelemetryHub>>,
    shared_poll: SharedPoll,
}

impl RelayHotDefaults {
    fn make_passthrough_cfg(&self, target: SocketAddr) -> PassthroughConfig {
        PassthroughConfig {
            target_addr: target,
            max_sessions: self.ingress_template.max_sessions,
            wan_mtu: self.ingress_template.wan_mtu,
            udp_batch: self.ingress_template.udp_batch,
            idle_timeout_secs: self.ingress_template.idle_timeout_secs,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_egress(
        &self,
        worker_id: usize,
        mode: &str,
        target: SocketAddr,
        upstream_psk: Vec<u8>,
        upstream_stun_scope: Option<String>,
        lane_hunt: LaneHuntConfig,
        rotate_interval_secs: u64,
    ) -> Result<(RelayEgress, &'static str), String> {
        let cpu = detect_cpu_accel();
        match mode {
            "cloak" => {
                let ccfg = ClientConfig {
                    listen_addr: self.ingress_template.listen_addr,
                    server_addr: target,
                    psk: upstream_psk,
                    stun_scope: upstream_stun_scope,
                    cipher_pref: self.ingress_template.cipher_pref,
                    dtls_decoy: self.ingress_template.dtls_required,
                    dtls_min_version: self.ingress_template.dtls_min_version,
                    rotate_interval_secs,
                    rotate_max_bytes: self.rotate_max_bytes,
                    rotate_cooldown_secs: DEFAULT_ROTATE_COOLDOWN_SECS,
                    workers: self.ingress_template.workers,
                    max_sessions: self.ingress_template.max_sessions,
                    wan_mtu: self.ingress_template.wan_mtu,
                    udp_batch: self.ingress_template.udp_batch,
                    retry_ms: self.retry_ms,
                    max_retries: self.max_retries,
                    keepalive_secs: self.keepalive_secs,
                    idle_timeout_secs: self.ingress_template.idle_timeout_secs,
                    stats_interval_secs: self.ingress_template.stats_interval_secs,
                    lane_hunt,
                    telemetry: self.ingress_template.telemetry.clone(),
                    quiet: self.ingress_template.quiet,
                    stop: self.ingress_template.stop.clone(),
                };
                let dp = build_dimpl_config_pool_for(
                    ccfg.cipher_pref,
                    &cpu,
                    true,
                    ccfg.wan_mtu,
                    outer_udp_hdr_len(ccfg.server_addr),
                );
                Ok((
                    RelayEgress::Cloak(ClientWorker::new_for_relay(
                        worker_id,
                        ccfg,
                        dp,
                        self.shared_poll.clone(),
                        self.telemetry.clone(),
                    )),
                    "cloak",
                ))
            }
            "bypass" => {
                let bcfg = BypassConfig {
                    listen_addr: self.ingress_template.listen_addr,
                    server_addr: target,
                    psk: upstream_psk,
                    stun_scope: upstream_stun_scope,
                    rotate_interval_secs,
                    workers: self.ingress_template.workers,
                    max_sessions: self.ingress_template.max_sessions,
                    wan_mtu: self.ingress_template.wan_mtu,
                    udp_batch: self.ingress_template.udp_batch,
                    retry_ms: self.retry_ms,
                    max_retries: self.max_retries.min(4),
                    keepalive_secs: self.keepalive_secs,
                    idle_timeout_secs: self.ingress_template.idle_timeout_secs,
                    stats_interval_secs: self.ingress_template.stats_interval_secs,
                    lane_hunt,
                    telemetry: self.ingress_template.telemetry.clone(),
                    quiet: self.ingress_template.quiet,
                    stop: self.ingress_template.stop.clone(),
                };
                Ok((
                    RelayEgress::Bypass(BypassWorker::new_for_relay(
                        worker_id,
                        bcfg,
                        self.shared_poll.clone(),
                        self.telemetry.clone(),
                    )),
                    "bypass",
                ))
            }
            other => Err(format!("unsupported managed hot-switch mode '{}'", other)),
        }
    }
}

fn apply_relay_hot_reload(
    worker_id: usize,
    path: &str,
    runtime: &mut Option<RelayRuntime>,
    defaults: &mut RelayHotDefaults,
) {
    let hot = match load_relay_hot_config(path) {
        Ok(c) => c,
        Err(e) => {
            log(
                worker_id,
                &format!("HOT-SWITCH ignored (invalid config): {}", e),
            );
            return;
        }
    };

    let current_mode = match runtime.as_ref() {
        Some(RelayRuntime::PurePassthrough { .. }) => "passthrough",
        Some(RelayRuntime::Managed {
            pt_policy: RelayPassthroughPolicy::PreferPassthrough,
            ..
        }) => "passthrough",
        Some(RelayRuntime::Managed { mode_tag, .. }) => mode_tag,
        None => return,
    };
    let target_mode = hot
        .upstream_mode
        .as_deref()
        .unwrap_or(current_mode)
        .to_string();

    let target_addr = match (&hot.upstream_host, hot.upstream_port) {
        (Some(h), Some(p)) => match resolve_host_port(h, p) {
            Ok(a) => a,
            Err(e) => {
                log(worker_id, &format!("HOT-SWITCH ignored: {}", e));
                return;
            }
        },
        (Some(h), None) => match resolve_host_port(h, defaults.upstream_addr.port()) {
            Ok(a) => a,
            Err(e) => {
                log(worker_id, &format!("HOT-SWITCH ignored: {}", e));
                return;
            }
        },
        (None, Some(p)) => SocketAddr::new(defaults.upstream_addr.ip(), p),
        (None, None) => defaults.upstream_addr,
    };

    // 1) 目标模式 = passthrough（零解密透传）
    if target_mode == "passthrough" {
        defaults.upstream_addr = target_addr;
        match runtime.as_mut() {
            Some(RelayRuntime::PurePassthrough { pt, .. }) => {
                if pt.target_addr() != target_addr {
                    let old = pt.target_addr();
                    pt.set_target_addr(target_addr);
                    log(
                        worker_id,
                        &format!(
                            "HOT-SWITCH passthrough target updated {} -> {} (existing flows draining cleanly)",
                            old, target_addr
                        ),
                    );
                } else {
                    log(worker_id, "HOT-SWITCH passthrough unchanged (no-op)");
                }
            }
            Some(RelayRuntime::Managed {
                ingress,
                pt,
                pt_policy,
                ..
            }) => {
                if let Some(table) = pt.as_mut() {
                    table.set_target_addr(target_addr);
                } else {
                    *pt = Some(PassthroughTable::new(
                        worker_id,
                        defaults.make_passthrough_cfg(target_addr),
                        defaults.shared_poll.clone(),
                    ));
                }
                *pt_policy = RelayPassthroughPolicy::PreferPassthrough;
                log(
                    worker_id,
                    &format!(
                        "HOT-SWITCH -> passthrough (target={}, AB dual-mode draining existing sessions={})",
                        target_addr,
                        ingress.build_worker_snapshot().active_sessions
                    ),
                );
            }
            None => {}
        }
        return;
    }

    // 2) 目标模式 = cloak / bypass
    if target_mode != "cloak" && target_mode != "bypass" {
        log(
            worker_id,
            &format!("HOT-SWITCH ignored: unsupported mode '{}'", target_mode),
        );
        return;
    }

    let ingress_psk = if let Some(ref p) = hot.psk_file {
        match read_psk_file(p) {
            Ok(k) => k,
            Err(e) => {
                log(worker_id, &format!("HOT-SWITCH ignored: {}", e));
                return;
            }
        }
    } else if let Some(ref k) = hot.psk {
        k.as_bytes().to_vec()
    } else if !defaults.ingress_template.psk.is_empty() {
        defaults.ingress_template.psk.clone()
    } else {
        log(
            worker_id,
            "HOT-SWITCH ignored: switching into cloak/bypass requires psk_file or psk",
        );
        return;
    };

    let upstream_psk = if let Some(ref p) = hot.upstream_psk_file {
        match read_psk_file(p) {
            Ok(k) => k,
            Err(e) => {
                log(worker_id, &format!("HOT-SWITCH ignored: {}", e));
                return;
            }
        }
    } else if let Some(ref k) = hot.upstream_psk {
        k.as_bytes().to_vec()
    } else if !defaults.upstream_psk.is_empty() {
        defaults.upstream_psk.clone()
    } else {
        ingress_psk.clone()
    };

    let mut lane_hunt = defaults.lane_hunt;
    if let Some(en) = hot.lane_hunt {
        lane_hunt.enabled = en;
    }
    if let Some(p) = hot.lane_probes {
        lane_hunt.probes = p;
    }
    if let Some(r) = hot.lane_rounds {
        lane_hunt.max_rounds = r;
    }
    lane_hunt = lane_hunt.normalized();

    let rotate_interval = hot
        .rotate_interval_secs
        .unwrap_or(defaults.rotate_interval_secs);
    let upstream_stun_scope = hot
        .upstream_stun_scope
        .clone()
        .or_else(|| defaults.upstream_stun_scope.clone());

    defaults.ingress_template.psk = ingress_psk;
    if let Some(scope) = hot.stun_scope.clone() {
        defaults.ingress_template.stun_scope = if scope.is_empty() { None } else { Some(scope) };
    }
    defaults.upstream_addr = target_addr;
    defaults.upstream_psk = upstream_psk.clone();
    defaults.upstream_stun_scope = upstream_stun_scope.clone();
    defaults.lane_hunt = lane_hunt;
    defaults.rotate_interval_secs = rotate_interval;

    let current = runtime.take();
    match current {
        Some(RelayRuntime::PurePassthrough {
            listen_sock,
            mut pt,
        }) => {
            let cpu = detect_cpu_accel();
            let in_dp = build_dimpl_config_pool_for(
                defaults.ingress_template.cipher_pref,
                &cpu,
                false,
                defaults.ingress_template.wan_mtu,
                outer_udp_hdr_len(defaults.ingress_template.listen_addr),
            );
            let mut ingress_cfg = defaults.ingress_template.clone();
            ingress_cfg.backend_addr = target_addr;
            match (
                ServerWorker::new_for_relay_with_socket(
                    worker_id,
                    ingress_cfg,
                    defaults.reuse_port,
                    listen_sock,
                    in_dp,
                    Arc::clone(&defaults.seen_txids),
                    Arc::clone(&defaults.registry),
                    defaults.shared_poll.clone(),
                    defaults.telemetry.clone(),
                ),
                defaults.build_egress(
                    worker_id,
                    &target_mode,
                    target_addr,
                    upstream_psk,
                    upstream_stun_scope,
                    lane_hunt,
                    rotate_interval,
                ),
            ) {
                (Ok(ingress), Ok((egress, mode_tag))) => {
                    let policy = if hot.passthrough_fallback == Some(true) {
                        pt.set_target_addr(target_addr);
                        RelayPassthroughPolicy::FallbackOnUnauth
                    } else {
                        pt.set_draining(true);
                        RelayPassthroughPolicy::DrainExistingOnly
                    };
                    let draining_pt = pt.active_sessions();
                    let keep_pt =
                        draining_pt > 0 || policy == RelayPassthroughPolicy::FallbackOnUnauth;
                    *runtime = Some(RelayRuntime::Managed {
                        ingress,
                        egress,
                        pt: keep_pt.then_some(pt),
                        pt_policy: if keep_pt {
                            policy
                        } else {
                            RelayPassthroughPolicy::Disabled
                        },
                        mode_tag,
                    });
                    log(
                        worker_id,
                        &format!(
                            "HOT-SWITCH passthrough -> {} (target={}, draining_passthrough_flows={})",
                            mode_tag, target_addr, draining_pt
                        ),
                    );
                }
                (Err(e), _) => {
                    log(
                        worker_id,
                        &format!("HOT-SWITCH failed constructing ingress: {}", e),
                    );
                }
                (Ok(ingress), Err(e)) => {
                    let listen_sock = ingress.into_listen_sock();
                    *runtime = Some(RelayRuntime::PurePassthrough { listen_sock, pt });
                    log(worker_id, &format!("HOT-SWITCH failed: {}", e));
                }
            }
        }
        Some(RelayRuntime::Managed {
            ingress,
            mut egress,
            mut pt,
            mut pt_policy,
            mut mode_tag,
        }) => {
            if let Some(fb) = hot.passthrough_fallback {
                if fb {
                    if let Some(table) = pt.as_mut() {
                        table.set_target_addr(target_addr);
                    } else {
                        pt = Some(PassthroughTable::new(
                            worker_id,
                            defaults.make_passthrough_cfg(target_addr),
                            defaults.shared_poll.clone(),
                        ));
                    }
                    pt_policy = RelayPassthroughPolicy::FallbackOnUnauth;
                } else if let Some(table) = pt.as_mut() {
                    table.set_draining(true);
                    pt_policy = if table.active_sessions() > 0 {
                        RelayPassthroughPolicy::DrainExistingOnly
                    } else {
                        pt = None;
                        RelayPassthroughPolicy::Disabled
                    };
                } else {
                    pt_policy = RelayPassthroughPolicy::Disabled;
                }
            } else if pt_policy == RelayPassthroughPolicy::PreferPassthrough {
                if let Some(table) = pt.as_mut() {
                    table.set_draining(true);
                    pt_policy = if table.active_sessions() > 0 {
                        RelayPassthroughPolicy::DrainExistingOnly
                    } else {
                        pt = None;
                        RelayPassthroughPolicy::Disabled
                    };
                } else {
                    pt_policy = RelayPassthroughPolicy::Disabled;
                }
            }

            let need_new_egress = hot.upstream_mode.is_some()
                || hot.upstream_host.is_some()
                || hot.upstream_port.is_some()
                || hot.upstream_psk_file.is_some()
                || hot.upstream_psk.is_some()
                || hot.lane_hunt.is_some();

            if need_new_egress {
                match defaults.build_egress(
                    worker_id,
                    &target_mode,
                    target_addr,
                    upstream_psk,
                    upstream_stun_scope,
                    lane_hunt,
                    rotate_interval,
                ) {
                    Ok((new_egress, new_tag)) => {
                        egress.graceful_shutdown_all();
                        egress = new_egress;
                        mode_tag = new_tag;
                        log(
                            worker_id,
                            &format!(
                                "HOT-SWITCH managed egress updated -> {} (target={}, fallback={})",
                                mode_tag,
                                target_addr,
                                pt_policy == RelayPassthroughPolicy::FallbackOnUnauth
                            ),
                        );
                    }
                    Err(e) => {
                        log(
                            worker_id,
                            &format!("HOT-SWITCH egress rebuild failed: {}", e),
                        );
                    }
                }
            } else {
                log(
                    worker_id,
                    &format!(
                        "HOT-SWITCH managed policy updated (mode={}, fallback={})",
                        mode_tag,
                        pt_policy == RelayPassthroughPolicy::FallbackOnUnauth
                    ),
                );
            }

            *runtime = Some(RelayRuntime::Managed {
                ingress,
                egress,
                pt,
                pt_policy,
                mode_tag,
            });
        }
        None => {}
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_relay_worker(
    worker_id: usize,
    cfg: RelayConfig,
    reuse_port: bool,
    ingress_dtls_pool: Option<DtlsConfigPool>,
    egress_dtls_pool: Option<DtlsConfigPool>,
    seen_txids: Arc<Mutex<SeenTxidCache>>,
    registry: Arc<SharedV4Registry>,
    telemetry: Option<Arc<TelemetryHub>>,
) -> std::io::Result<()> {
    let quiet = cfg.ingress.quiet;
    let stop = cfg.ingress.stop.clone();
    let hot_config_path = cfg.hot_config_path.clone();
    let reload_trigger = cfg.reload_trigger.clone();
    let initial_fallback = cfg.passthrough_fallback;
    let workers = cfg.ingress.workers.max(1);
    let stats_dur = Duration::from_secs(cfg.ingress.stats_interval_secs);
    let stats_enabled = cfg.ingress.stats_interval_secs > 0;
    let listen_addr = cfg.ingress.listen_addr;
    let upstream_addr = match &cfg.upstream {
        RelayUpstreamConfig::Passthrough(p) => p.target_addr,
        RelayUpstreamConfig::Bypass(b) => b.server_addr,
        RelayUpstreamConfig::Cloak(c) => c.server_addr,
        RelayUpstreamConfig::Reverse(r) => r.listen_addr,
    };

    RELAY_QUIET.with(|q| q.set(quiet));
    let mut poll = Poll::new()?;
    if workers > 1 {
        if let Ok(waker) = Waker::new(poll.registry(), WAKE_TOKEN) {
            registry.set_waker(worker_id, Arc::new(waker));
        }
    }
    register_shutdown_poll(&poll, quiet, stop.is_some());
    register_reload_poll(&poll, quiet, hot_config_path.is_some());

    let shared_poll = SharedPoll::new(poll.registry().try_clone()?);

    let (
        upstream_psk,
        upstream_stun_scope,
        lane_hunt,
        rotate_interval_secs,
        rotate_max_bytes,
        retry_ms,
        max_retries,
        keepalive_secs,
    ) = match &cfg.upstream {
        RelayUpstreamConfig::Passthrough(_) => (
            cfg.ingress.psk.clone(),
            None,
            LaneHuntConfig {
                enabled: false,
                probes: DEFAULT_LANE_PROBES,
                max_rounds: DEFAULT_LANE_ROUNDS,
                target_rtt_ms: 0,
                degrade_cooldown_secs: DEFAULT_LANE_DEGRADE_COOLDOWN_SECS,
            }
            .normalized(),
            0,
            0,
            300,
            8,
            5,
        ),
        RelayUpstreamConfig::Bypass(b) => (
            b.psk.clone(),
            b.stun_scope.clone(),
            b.lane_hunt,
            b.rotate_interval_secs,
            0,
            b.retry_ms,
            b.max_retries,
            b.keepalive_secs,
        ),
        RelayUpstreamConfig::Cloak(c) => (
            c.psk.clone(),
            c.stun_scope.clone(),
            c.lane_hunt,
            c.rotate_interval_secs,
            c.rotate_max_bytes,
            c.retry_ms,
            c.max_retries,
            c.keepalive_secs,
        ),
        RelayUpstreamConfig::Reverse(r) => (
            r.psk.clone(),
            r.stun_scope.clone(),
            LaneHuntConfig {
                enabled: false,
                probes: DEFAULT_LANE_PROBES,
                max_rounds: DEFAULT_LANE_ROUNDS,
                target_rtt_ms: 0,
                degrade_cooldown_secs: DEFAULT_LANE_DEGRADE_COOLDOWN_SECS,
            }
            .normalized(),
            0,
            0,
            300,
            8,
            5,
        ),
    };

    let mut defaults = RelayHotDefaults {
        ingress_template: cfg.ingress.clone(),
        upstream_addr,
        upstream_psk,
        upstream_stun_scope,
        lane_hunt,
        rotate_interval_secs,
        rotate_max_bytes,
        retry_ms,
        max_retries,
        keepalive_secs,
        reuse_port,
        seen_txids: Arc::clone(&seen_txids),
        registry: Arc::clone(&registry),
        telemetry: telemetry.clone(),
        shared_poll: shared_poll.clone(),
    };

    let mut runtime: Option<RelayRuntime> = match cfg.upstream {
        RelayUpstreamConfig::Passthrough(pcfg) => {
            let mut listen_sock = make_udp_socket(listen_addr, None, reuse_port, SOCK_BUF_8MIB)?;
            poll.registry()
                .register(&mut listen_sock, LISTEN_TOKEN, Interest::READABLE)?;
            let pt = PassthroughTable::new(worker_id, pcfg, shared_poll.clone());
            Some(RelayRuntime::PurePassthrough { listen_sock, pt })
        }
        other => {
            let in_dp = ingress_dtls_pool
                .expect("ingress DTLS pool must exist for non-passthrough relay mode");
            let ingress = ServerWorker::new_for_relay(
                worker_id,
                cfg.ingress,
                reuse_port,
                in_dp,
                seen_txids,
                registry,
                shared_poll.clone(),
                telemetry.clone(),
            )?;
            let (egress, mode_tag) = match other {
                RelayUpstreamConfig::Bypass(bcfg) => (
                    RelayEgress::Bypass(BypassWorker::new_for_relay(
                        worker_id,
                        bcfg,
                        shared_poll.clone(),
                        telemetry.clone(),
                    )),
                    "bypass",
                ),
                RelayUpstreamConfig::Cloak(ccfg) => {
                    let dp =
                        egress_dtls_pool.expect("egress DTLS pool must exist for relay cloak mode");
                    (
                        RelayEgress::Cloak(ClientWorker::new_for_relay(
                            worker_id,
                            ccfg,
                            dp,
                            shared_poll.clone(),
                            telemetry.clone(),
                        )),
                        "cloak",
                    )
                }
                RelayUpstreamConfig::Reverse(rcfg) => {
                    let dp = egress_dtls_pool
                        .expect("egress DTLS pool must exist for relay reverse mode");
                    let rev_seen = Arc::new(Mutex::new(SeenTxidCache::new()));
                    let rev_reg = Arc::new(SharedV4Registry::new(1));
                    (
                        RelayEgress::Reverse(Box::new(ServerWorker::new_for_relay_with_token(
                            worker_id,
                            rcfg,
                            false,
                            REVERSE_LISTEN_TOKEN,
                            dp,
                            rev_seen,
                            rev_reg,
                            shared_poll.clone(),
                            None,
                        )?)),
                        "reverse",
                    )
                }
                RelayUpstreamConfig::Passthrough(_) => unreachable!(),
            };
            let (pt, pt_policy) = if initial_fallback {
                (
                    Some(PassthroughTable::new(
                        worker_id,
                        defaults.make_passthrough_cfg(upstream_addr),
                        shared_poll.clone(),
                    )),
                    RelayPassthroughPolicy::FallbackOnUnauth,
                )
            } else {
                (None, RelayPassthroughPolicy::Disabled)
            };
            Some(RelayRuntime::Managed {
                ingress,
                egress,
                pt,
                pt_policy,
                mode_tag,
            })
        }
    };

    log(
        worker_id,
        &format!(
            "listening on {} -> {} (mode={}, reuse_port={}, zero_loopback=true)",
            listen_addr,
            upstream_addr,
            runtime.as_ref().map(|r| r.mode_label()).unwrap_or("none"),
            reuse_port
        ),
    );

    let telemetry_dur = telemetry
        .as_ref()
        .map(|th| th.interval())
        .unwrap_or(Duration::from_secs(TELEMETRY_DEFAULT_INTERVAL_SECS));
    let mut last_telemetry = Instant::now();
    let mut last_stats = last_telemetry;
    let mut events = Events::with_capacity(MIO_EVENTS_CAP);

    loop {
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        if let Some(ref hot_path) = hot_config_path {
            if take_reload_requested(reload_trigger.as_ref(), quiet) {
                apply_relay_hot_reload(worker_id, hot_path, &mut runtime, &mut defaults);
            }
        }

        let now = Instant::now();

        // 若处于 `cloak/bypass -> passthrough` 排空期且旧会话全部归零，自动升级为纯零解密透传（零额外内存/状态开销）
        let promote_to_pure_pt = matches!(
            runtime.as_ref(),
            Some(RelayRuntime::Managed {
                ingress,
                pt: Some(_),
                pt_policy: RelayPassthroughPolicy::PreferPassthrough,
                ..
            }) if !ingress.has_live_sessions()
        );
        if promote_to_pure_pt {
            if let Some(RelayRuntime::Managed {
                ingress,
                mut egress,
                pt: Some(pt),
                ..
            }) = runtime.take()
            {
                egress.graceful_shutdown_all();
                let listen_sock = ingress.into_listen_sock();
                log(
                    worker_id,
                    &format!(
                        "HOT-SWITCH drain complete -> pure zero-crypto passthrough (target={}, active_pt={})",
                        pt.target_addr(),
                        pt.active_sessions()
                    ),
                );
                runtime = Some(RelayRuntime::PurePassthrough { listen_sock, pt });
            }
        }

        let (wait_core, mut standby_promoted, mut standby_ready) = match runtime.as_mut() {
            Some(RelayRuntime::PurePassthrough { pt, .. }) => {
                (pt.gc_idle(now), Vec::new(), Vec::new())
            }
            Some(RelayRuntime::Managed {
                ingress,
                egress,
                pt,
                pt_policy,
                ..
            }) => {
                ingress.drain_worker_cmds_with(now, Some(ServerHook::Relay(egress)));
                let w_in = ingress.process_timers_with(now, Some(ServerHook::Relay(egress)));
                for flow_addr in ingress.drain_closed_relay_flows() {
                    egress.close_flow(flow_addr, now);
                }

                let (w_out, sp, sr) = match egress {
                    RelayEgress::Bypass(ref mut b) => {
                        b.drive_timers_relay(now);
                        (b.next_poll_timeout_relay(now), Vec::new(), Vec::new())
                    }
                    RelayEgress::Cloak(ref mut c) => c.process_timers_relay(now),
                    RelayEgress::Reverse(ref mut rev) => {
                        rev.drain_worker_cmds_with(
                            now,
                            Some(ServerHook::RelayReversePeer(ingress)),
                        );
                        let w = rev
                            .process_timers_with(now, Some(ServerHook::RelayReversePeer(ingress)));
                        let _ = rev.drain_closed_relay_flows();
                        (w, Vec::new(), Vec::new())
                    }
                };

                let mut w = w_in.min(w_out);
                if let Some(table) = pt.as_mut() {
                    w = w.min(table.gc_idle(now));
                    if *pt_policy == RelayPassthroughPolicy::DrainExistingOnly
                        && table.active_sessions() == 0
                    {
                        *pt = None;
                        *pt_policy = RelayPassthroughPolicy::Disabled;
                        log(
                            worker_id,
                            "HOT-SWITCH draining passthrough table reached 0 flows; detached cleanly",
                        );
                    }
                }
                (w, sp, sr)
            }
            None => break,
        };

        let mut wait = wait_core;
        if telemetry.is_some() && wait > telemetry_dur {
            wait = telemetry_dur;
        }
        let quiet_cap = Duration::from_millis(WORKER_QUIET_STOP_POLL_MS);
        if (stop.is_some() || reload_trigger.is_some()) && quiet && wait > quiet_cap {
            wait = quiet_cap;
        }

        if let Err(e) = poll.poll(&mut events, Some(wait)) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        let now = Instant::now();
        let mut graceful_reconnects: Vec<(Token, SocketAddr)> = Vec::new();
        #[cfg(unix)]
        let mut saw_reload_pipe = false;

        for ev in events.iter() {
            let tok = ev.token();
            #[cfg(unix)]
            if tok == SHUTDOWN_PIPE_TOKEN {
                continue;
            }
            #[cfg(unix)]
            if tok == RELOAD_PIPE_TOKEN {
                drain_reload_pipe();
                saw_reload_pipe = true;
                continue;
            }
            if tok == WAKE_TOKEN {
                continue;
            }

            match runtime.as_mut() {
                Some(RelayRuntime::PurePassthrough { listen_sock, pt }) => {
                    if tok == LISTEN_TOKEN {
                        pt.handle_listen_readable(listen_sock, now);
                    } else if pt.owns_token(tok) {
                        pt.handle_upstream_readable(tok, listen_sock, now);
                    }
                }
                Some(RelayRuntime::Managed {
                    ingress,
                    egress,
                    pt,
                    pt_policy,
                    ..
                }) => {
                    if tok == LISTEN_TOKEN {
                        ingress.handle_listen_readable_relay(
                            now,
                            Some(ServerHook::Relay(egress)),
                            pt.as_mut(),
                            *pt_policy,
                        );
                    } else if tok == REVERSE_LISTEN_TOKEN {
                        if let RelayEgress::Reverse(ref mut rev) = egress {
                            rev.handle_listen_readable_with(
                                now,
                                Some(ServerHook::RelayReversePeer(ingress)),
                            );
                        }
                    } else if pt.as_ref().is_some_and(|t| t.owns_token(tok)) {
                        if let Some(table) = pt.as_mut() {
                            table.handle_upstream_readable(tok, &ingress.listen_sock, now);
                        }
                    } else {
                        match egress {
                            RelayEgress::Bypass(ref mut b) => {
                                b.handle_event_relay(tok, ingress, now);
                            }
                            RelayEgress::Cloak(ref mut c) => {
                                c.handle_event_relay(
                                    tok,
                                    ingress,
                                    now,
                                    &mut standby_ready,
                                    &mut standby_promoted,
                                    &mut graceful_reconnects,
                                );
                            }
                            RelayEgress::Reverse(_) => {}
                        }
                    }
                }
                None => {}
            }
        }

        if let Some(RelayRuntime::Managed {
            ingress, egress, ..
        }) = runtime.as_mut()
        {
            for flow_addr in ingress.drain_closed_relay_flows() {
                egress.close_flow(flow_addr, now);
            }
            match egress {
                RelayEgress::Bypass(ref mut b) => {
                    b.drive_timers_relay(Instant::now());
                }
                RelayEgress::Cloak(ref mut c) => {
                    c.process_post_events_relay(
                        now,
                        standby_ready,
                        standby_promoted,
                        graceful_reconnects,
                    );
                }
                RelayEgress::Reverse(ref mut rev) => {
                    let _ = rev.drain_closed_relay_flows();
                }
            }
        }

        #[cfg(unix)]
        if saw_reload_pipe {
            if let Some(ref hot_path) = hot_config_path {
                let _ = take_reload_requested(reload_trigger.as_ref(), quiet);
                apply_relay_hot_reload(worker_id, hot_path, &mut runtime, &mut defaults);
            }
        }

        let post_now = Instant::now();
        if let Some(ref th) = telemetry {
            if post_now.duration_since(last_telemetry) >= telemetry_dur {
                last_telemetry = post_now;
                if let Some(ref rt) = runtime {
                    th.update_worker(worker_id, rt.build_snapshot());
                }
            }
        }
        if stats_enabled && post_now.duration_since(last_stats) >= stats_dur {
            last_stats = post_now;
            if let Some(ref rt) = runtime {
                let merged = rt.build_snapshot();
                if merged.active_sessions > 0 || merged.handshaking_sessions > 0 {
                    log(
                        worker_id,
                        &format!(
                            "stats mode={} sessions={} up_sport={} rx={}pkts/{:.1}KB tx={}pkts/{:.1}KB best_rtt={:?}ms drops={} unauth={}",
                            rt.mode_label(),
                            merged.active_sessions,
                            merged.active_up_sport,
                            merged.rx_pkts_total,
                            merged.rx_bytes_total as f64 / 1024.0,
                            merged.tx_pkts_total,
                            merged.tx_bytes_total as f64 / 1024.0,
                            merged.lane_best_rtt_ms.map(|v| (v * 10.0).round() / 10.0),
                            merged.auth_drops_total,
                            merged.unauth_drops_total,
                        ),
                    );
                }
            }
        }
    }

    if let Some(ref mut rt) = runtime {
        rt.shutdown_all();
        if let Some(ref th) = telemetry {
            th.update_worker(worker_id, rt.build_snapshot());
        }
    }
    Ok(())
}
