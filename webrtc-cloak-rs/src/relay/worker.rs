//! 单进程融合中继 `mio` 工作线程：入站 `ServerWorker` 与出站 `RelayEgress` 共享同一 `Poll` 循环。

use super::{log, RelayConfig, RelayUpstreamConfig, RELAY_QUIET};
use crate::bypass::BypassWorker;
use crate::client::ClientWorker;
#[cfg(unix)]
use crate::constants::SHUTDOWN_PIPE_TOKEN;
use crate::constants::{
    SharedPoll, LISTEN_TOKEN, MIO_EVENTS_CAP, REVERSE_LISTEN_TOKEN,
    TELEMETRY_DEFAULT_INTERVAL_SECS, WAKE_TOKEN, WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{is_shutdown_requested, register_shutdown_poll, DtlsConfigPool};
use crate::server::{SeenTxidCache, ServerHook, ServerWorker, SharedV4Registry};
use crate::telemetry::{TelemetryHub, WorkerSnapshot};
use mio::{Events, Poll, Token, Waker};
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

#[allow(clippy::too_many_arguments)]
pub(super) fn run_relay_worker(
    worker_id: usize,
    cfg: RelayConfig,
    reuse_port: bool,
    ingress_dtls_pool: DtlsConfigPool,
    egress_dtls_pool: Option<DtlsConfigPool>,
    seen_txids: Arc<Mutex<SeenTxidCache>>,
    registry: Arc<SharedV4Registry>,
    telemetry: Option<Arc<TelemetryHub>>,
) -> std::io::Result<()> {
    let quiet = cfg.ingress.quiet;
    let stop = cfg.ingress.stop.clone();
    let workers = cfg.ingress.workers.max(1);
    let stats_dur = Duration::from_secs(cfg.ingress.stats_interval_secs);
    let stats_enabled = cfg.ingress.stats_interval_secs > 0;
    let listen_addr = cfg.ingress.listen_addr;
    let upstream_addr = match &cfg.upstream {
        RelayUpstreamConfig::Bypass(b) => b.server_addr,
        RelayUpstreamConfig::Cloak(c) => c.server_addr,
        RelayUpstreamConfig::Reverse(r) => r.listen_addr,
    };
    let mode_tag = match &cfg.upstream {
        RelayUpstreamConfig::Bypass(_) => "bypass",
        RelayUpstreamConfig::Cloak(_) => "cloak",
        RelayUpstreamConfig::Reverse(_) => "reverse",
    };

    RELAY_QUIET.with(|q| q.set(quiet));
    let mut poll = Poll::new()?;
    if workers > 1 {
        if let Ok(waker) = Waker::new(poll.registry(), WAKE_TOKEN) {
            registry.set_waker(worker_id, Arc::new(waker));
        }
    }
    register_shutdown_poll(&poll, quiet, stop.is_some());

    let ingress_poll = SharedPoll::new(poll.registry().try_clone()?);
    let egress_poll = ingress_poll.clone();

    let mut ingress = ServerWorker::new_for_relay(
        worker_id,
        cfg.ingress,
        reuse_port,
        ingress_dtls_pool,
        seen_txids,
        registry,
        ingress_poll,
        telemetry.clone(),
    )?;

    let mut egress = match cfg.upstream {
        RelayUpstreamConfig::Bypass(bcfg) => RelayEgress::Bypass(BypassWorker::new_for_relay(
            worker_id,
            bcfg,
            egress_poll,
            telemetry.clone(),
        )),
        RelayUpstreamConfig::Cloak(ccfg) => {
            let dp = egress_dtls_pool.expect("egress DTLS pool must exist for relay cloak mode");
            RelayEgress::Cloak(ClientWorker::new_for_relay(
                worker_id,
                ccfg,
                dp,
                egress_poll,
                telemetry.clone(),
            ))
        }
        RelayUpstreamConfig::Reverse(rcfg) => {
            let dp = egress_dtls_pool.expect("egress DTLS pool must exist for relay reverse mode");
            let rev_seen = Arc::new(Mutex::new(SeenTxidCache::new()));
            let rev_reg = Arc::new(SharedV4Registry::new(1));
            RelayEgress::Reverse(Box::new(ServerWorker::new_for_relay_with_token(
                worker_id,
                rcfg,
                false,
                REVERSE_LISTEN_TOKEN,
                dp,
                rev_seen,
                rev_reg,
                egress_poll,
                None,
            )?))
        }
    };

    log(
        worker_id,
        &format!(
            "listening on {} -> {} (mode={}, reuse_port={}, zero_loopback=true)",
            listen_addr, upstream_addr, mode_tag, reuse_port
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

        let now = Instant::now();
        ingress.drain_worker_cmds_with(now, Some(ServerHook::Relay(&mut egress)));
        let w_in = ingress.process_timers_with(now, Some(ServerHook::Relay(&mut egress)));
        for flow_addr in ingress.drain_closed_relay_flows() {
            egress.close_flow(flow_addr, now);
        }

        let (w_out, mut standby_promoted, mut standby_ready) = match egress {
            RelayEgress::Bypass(ref mut b) => {
                b.drive_timers_relay(now);
                (b.next_poll_timeout_relay(now), Vec::new(), Vec::new())
            }
            RelayEgress::Cloak(ref mut c) => c.process_timers_relay(now),
            RelayEgress::Reverse(ref mut rev) => {
                rev.drain_worker_cmds_with(now, Some(ServerHook::RelayReversePeer(&mut ingress)));
                let w =
                    rev.process_timers_with(now, Some(ServerHook::RelayReversePeer(&mut ingress)));
                let _ = rev.drain_closed_relay_flows();
                (w, Vec::new(), Vec::new())
            }
        };

        let mut wait = w_in.min(w_out);
        if telemetry.is_some() && wait > telemetry_dur {
            wait = telemetry_dur;
        }
        let quiet_cap = Duration::from_millis(WORKER_QUIET_STOP_POLL_MS);
        if stop.is_some() && quiet && wait > quiet_cap {
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
        for ev in events.iter() {
            let tok = ev.token();
            #[cfg(unix)]
            if tok == SHUTDOWN_PIPE_TOKEN {
                continue;
            }
            if tok == WAKE_TOKEN {
                continue;
            }
            if tok == LISTEN_TOKEN {
                ingress.handle_listen_readable_with(now, Some(ServerHook::Relay(&mut egress)));
            } else if tok == REVERSE_LISTEN_TOKEN {
                if let RelayEgress::Reverse(ref mut rev) = egress {
                    rev.handle_listen_readable_with(
                        now,
                        Some(ServerHook::RelayReversePeer(&mut ingress)),
                    );
                }
            } else {
                match egress {
                    RelayEgress::Bypass(ref mut b) => {
                        b.handle_event_relay(tok, &mut ingress, now);
                    }
                    RelayEgress::Cloak(ref mut c) => {
                        c.handle_event_relay(
                            tok,
                            &mut ingress,
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

        let post_now = Instant::now();
        if let Some(ref th) = telemetry {
            if post_now.duration_since(last_telemetry) >= telemetry_dur {
                last_telemetry = post_now;
                let merged = merge_relay_snapshot(
                    ingress.build_worker_snapshot(),
                    egress.build_worker_snapshot(),
                );
                th.update_worker(worker_id, merged);
            }
        }
        if stats_enabled && post_now.duration_since(last_stats) >= stats_dur {
            last_stats = post_now;
            let merged = merge_relay_snapshot(
                ingress.build_worker_snapshot(),
                egress.build_worker_snapshot(),
            );
            if merged.active_sessions > 0 || merged.handshaking_sessions > 0 {
                log(
                    worker_id,
                    &format!(
                        "stats mode={} sessions={} up_sport={} rx={}pkts/{:.1}KB tx={}pkts/{:.1}KB best_rtt={:?}ms drops={} unauth={}",
                        mode_tag,
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

    ingress.graceful_shutdown_all();
    egress.graceful_shutdown_all();
    if let Some(ref th) = telemetry {
        let merged = merge_relay_snapshot(
            ingress.build_worker_snapshot(),
            egress.build_worker_snapshot(),
        );
        th.update_worker(worker_id, merged);
    }
    Ok(())
}
