//! 客户端超时驱动、黑洞 1-RTT 迁移、MBB 备选拉起与会话清理。

use super::dtls::{
    drain_client_dtls, schedule_async_teardown_client, send_client_dtls_close_notify,
    spawn_client_session,
};
use super::lane_hunt::{HuntPurpose, MbbHuntReason};
use super::worker::ClientWorker;
use super::{
    alloc_token, cancel_standby_for_client, is_client_in_trickle, log, make_udp_socket,
    HandshakeState, OldPathDrain, ACTIVE_ROTATE_WINDOW_SECS, CLIENT_HANDOVER_MIN_RETRY_MS,
    CLIENT_MIG_ECHO_INTERVAL_MS, CLIENT_SRTCP_ACTIVE_MAX_MS, CLIENT_SRTCP_ACTIVE_MIN_MS,
    KA_MAX_RETRIES, KA_MAX_RETRIES_DAMPED, MAX_DRAINING_SESSIONS, RECENT_ROTATION_DAMP_SECS,
    TRICKLE_WINDOW_5MIN_SECS,
};
use crate::constants::{
    unspecified_addr_for, BLACKHOLE_DRAIN_SECS, CLOSING_DRAIN_MS, DTLS_IDLE_TIMEOUT_THRESHOLD_SECS,
    POST_BYE_CLOSING_DRAIN_MS, SOCK_BUF_8MIB, SRTCP_ACTIVE_MEDIA_WINDOW_SECS, SRTCP_IDLE_MAX_MS,
    SRTCP_IDLE_MIN_MS, SRTCP_LONG_TRICKLE_MAX_MS, SRTCP_LONG_TRICKLE_MIN_MS, SRTCP_TRICKLE_MAX_MS,
    SRTCP_TRICKLE_MIN_MS, SRTP_HANDOVER_MAGIC, SRTP_PATH_CHALLENGE_MAGIC, WORKER_ACTIVE_POLL_SECS,
    WORKER_IDLE_POLL_SECS, WORKER_MIN_FAST_WAIT_MS, WORKER_MIN_NORMAL_WAIT_MS,
};
use crate::protocol::{build_ice_stun_request_with_key, rand_duration_range_ms};
use mio::{Interest, Token};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 客户端轮换历史记录表最大容量，超过后清理过期条目。
const MAX_ROTATION_HISTORY_ENTRIES: usize = 1024;
/// 5 分钟滑动窗口内低于该字节数（64 KiB，约 218 B/s）时暂停定时 MBB 轮换。
const TRICKLE_MBB_5MIN_BYTES: u64 = 64 * 1024;
/// STUN 保活首次 RTO 最小等待时间（毫秒）。
const KA_RTO_INITIAL_MIN_MS: u64 = 950;
/// STUN 保活首次 RTO 最大等待时间（毫秒）。
const KA_RTO_INITIAL_MAX_MS: u64 = 1250;
/// STUN 保活第 1 次重传后 RTO 最小等待时间（毫秒）。
const KA_RTO_RETRY1_MIN_MS: u64 = 1400;
/// STUN 保活第 1 次重传后 RTO 最大等待时间（毫秒）。
const KA_RTO_RETRY1_MAX_MS: u64 = 1800;
/// STUN 保活后续重传 RTO 最小等待时间（毫秒）。
const KA_RTO_RETRY2_MIN_MS: u64 = 1800;
/// STUN 保活后续重传 RTO 最大等待时间（毫秒）。
const KA_RTO_RETRY2_MAX_MS: u64 = 2200;
/// 判定静默下行死锁所需的最小已发送数据包数。
const CLIENT_DL_DEADLOCK_MIN_TX_PKTS: u64 = 3;
/// 发送数据后零下行认证包触发自动轮换的死锁保护时长（秒）。
const CLIENT_DL_DEADLOCK_SECS: u64 = 15;
/// MBB `0xFFFC` 交接请求最大重传次数（覆盖跨洋 DTLS 1.3 Flight 5 丢失恢复时间）。
const CLIENT_HANDOVER_MAX_RETRIES: u8 = 4;
/// 1-RTT ICE 迁移 STUN 请求最大重传次数，超限后回退为完整新建会话。
const CLIENT_MIGRATION_MAX_RETRIES: u8 = 2;
/// 细流状态下挂起 MBB 轮换后的最小复检间隔（毫秒）。
const CLIENT_MBB_TRICKLE_RECHECK_MIN_MS: u64 = 60_000;
/// 细流状态下挂起 MBB 轮换后的最大复检间隔（毫秒）。
const CLIENT_MBB_TRICKLE_RECHECK_MAX_MS: u64 = 180_000;
/// MBB 备选会话握手失败后的最小重试退避间隔（毫秒）。
const CLIENT_MBB_FAIL_BACKOFF_MIN_MS: u64 = 45_000;
/// MBB 备选会话握手失败后的最大重试退避间隔（毫秒）。
const CLIENT_MBB_FAIL_BACKOFF_MAX_MS: u64 = 90_000;
/// 客户端进入长细流期（与服务端 `SERVER_LONG_TRICKLE_SECS` 对齐）后同步切换至极低频（25..45s）对称 RTCP RR。
const CLIENT_LONG_TRICKLE_SECS: u64 = 60;
/// MBB 定时轮换检查的最小 poll 步进下限（毫秒）。
const WORKER_MIN_ROTATE_WAIT_MS: u64 = 20;

/// 定时器单轮处理结果：`(下次 poll 等待时长, 待提交的 MBB 晋升列表, 待发起 0xFFFC 交接的备选就绪列表)`。
pub(super) type TimerOutcome = (Duration, Vec<(Token, SocketAddr)>, Vec<(Token, SocketAddr)>);

impl ClientWorker {
    pub(super) fn process_timers(&mut self, now: Instant) -> TimerOutcome {
        let mut wait = if self.sessions_by_token.is_empty()
            && self.pending_reconnects.is_empty()
            && self.lane_hunts.is_empty()
        {
            Duration::from_secs(WORKER_IDLE_POLL_SECS)
        } else {
            Duration::from_secs(WORKER_ACTIVE_POLL_SECS)
        };
        let mut to_close: Vec<(Token, &'static str)> = Vec::new();
        let mut to_rotate: Vec<(Token, SocketAddr, bool)> = Vec::new();
        let mut to_migrate: Vec<Token> = Vec::new();
        let mut to_spawn_standby: Vec<(Token, SocketAddr)> = Vec::new();
        let mut standby_promoted_timers: Vec<(Token, SocketAddr)> = Vec::new();
        let mut standby_ready_timers: Vec<(Token, SocketAddr)> = Vec::new();

        // 若预热槽会话已进入 Closing（如服务端优雅关闭/黑洞），立刻解绑以便立即重热
        if let Some(pwt) = self.prewarm_tok {
            let dead = self
                .sessions_by_token
                .get(&pwt)
                .map(|s| matches!(s.state, HandshakeState::Closing(_)))
                .unwrap_or(true);
            if dead {
                self.prewarm_tok = None;
                self.next_prewarm_at = Some(now + Duration::from_millis(500));
            }
        }

        self.process_hunt_timers(now, &mut wait, &mut standby_ready_timers);

        // Expire old migrated receive-only drain sockets
        if !self.old_path_drains.is_empty() {
            let expired_drains: Vec<Token> = self
                .old_path_drains
                .iter()
                .filter(|(_, d)| now >= d.deadline)
                .map(|(&t, _)| t)
                .collect();
            for dt in expired_drains {
                if let Some(mut d) = self.old_path_drains.remove(&dt) {
                    let _ = self.poll.registry().deregister(&mut d.sock);
                }
            }
        }

        // Fire jittered post-server-BYE reconnects once their 80..350ms backoff expires
        let mut due_reconnects: Vec<SocketAddr> = Vec::new();
        for (&caddr, pr) in self.pending_reconnects.iter() {
            if now >= pr.at {
                due_reconnects.push(caddr);
            } else {
                let rem = pr.at.saturating_duration_since(now);
                if rem < wait {
                    wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                }
            }
        }
        for caddr in due_reconnects {
            if let Some(pr) = self.pending_reconnects.remove(&caddr) {
                if !self.token_by_client.contains_key(&caddr) {
                    if let Some(adopted) = self.try_adopt_prewarm(caddr, now) {
                        if let Some(new_sess) = self.sessions_by_token.get_mut(&adopted) {
                            if new_sess.state == HandshakeState::Ready {
                                if let Some(ref mut cipher) = new_sess.cipher {
                                    for raw in pr.pending {
                                        if let Some(wn) = cipher.wrap_into(&raw, &mut self.wbuf) {
                                            if new_sess.upstream.send(&self.wbuf[..wn]).is_ok() {
                                                new_sess.tx_pkts += 1;
                                                new_sess.tx_bytes += raw.len() as u64;
                                            }
                                        }
                                    }
                                }
                            } else {
                                new_sess.pending = pr.pending;
                                new_sess.pending_bytes = pr.pending_bytes;
                            }
                        }
                        continue;
                    }
                    if self.cfg.lane_hunt.enabled
                        && self.start_lane_hunt(
                            HuntPurpose::NewPrimary {
                                client_addr: caddr,
                                ka_max_retries: KA_MAX_RETRIES,
                            },
                            now,
                            pr.pending.clone(),
                            pr.pending_bytes,
                        )
                    {
                        continue;
                    }
                    if let Some(new_tok) = spawn_client_session(
                        self.worker_id,
                        caddr,
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
                        KA_MAX_RETRIES,
                        None,
                    ) {
                        if let Some(new_sess) = self.sessions_by_token.get_mut(&new_tok) {
                            new_sess.pending = pr.pending;
                            new_sess.pending_bytes = pr.pending_bytes;
                        }
                    }
                }
            }
        }

        for (&tok, sess) in self.sessions_by_token.iter_mut() {
            match sess.state {
                HandshakeState::StunWait => {
                    if now >= sess.next_retry_at {
                        if sess.retries >= self.cfg.max_retries {
                            to_close.push((tok, "stun_handshake_timeout"));
                            continue;
                        }
                        sess.retries += 1;
                        sess.next_retry_at = now + self.retry_dur;
                        let _ = sess.upstream.send(&sess.cached_initial_stun);
                    } else {
                        let rem = sess.next_retry_at.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                        }
                    }
                }
                HandshakeState::DtlsHandshake => {
                    if let Some(t) = sess.dtls_next_timeout {
                        if now >= t {
                            let err = if let Some(ref mut dtls) = sess.dtls {
                                dtls.handle_timeout(now).is_err()
                            } else {
                                true
                            };
                            if err {
                                to_close.push((tok, "dtls_handshake_timeout"));
                                continue;
                            }
                            if drain_client_dtls(
                                self.worker_id,
                                sess,
                                &mut self.dtls_buf,
                                &mut self.wbuf,
                                &self.cfg,
                                &self.cpu,
                                now,
                                None,
                            ) {
                                sess.state = HandshakeState::Closing(
                                    now + Duration::from_millis(CLOSING_DRAIN_MS),
                                );
                            }
                        } else {
                            let rem = t.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                            }
                        }
                    }
                }
                HandshakeState::HandoverWait => {
                    // Drive DTLS 1.3 Flight 5 retransmit timer if still armed while awaiting 0xFFFC Ack
                    if let Some(t) = sess.dtls_next_timeout {
                        let rem = t.saturating_duration_since(now);
                        if rem > Duration::from_secs(DTLS_IDLE_TIMEOUT_THRESHOLD_SECS) {
                            sess.dtls_next_timeout = None;
                        } else if now >= t {
                            let err = if let Some(ref mut dtls) = sess.dtls {
                                dtls.handle_timeout(now).is_err()
                            } else {
                                true
                            };
                            if err {
                                // P1-5 fix: clear expired DTLS timer on Err
                                sess.dtls_next_timeout = None;
                            } else if drain_client_dtls(
                                self.worker_id,
                                sess,
                                &mut self.dtls_buf,
                                &mut self.wbuf,
                                &self.cfg,
                                &self.cpu,
                                now,
                                None,
                            ) {
                                sess.state = HandshakeState::Closing(
                                    now + Duration::from_millis(CLOSING_DRAIN_MS),
                                );
                                continue;
                            }
                        } else if rem < wait {
                            wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                        }
                    }
                    if let Some(rt) = sess.handover_retry_at {
                        if now >= rt {
                            // P0-5 fix: 4 retries x ~380ms (~1.5s) covers >=2 full DTLS 1.3 Flight 5 RTOs
                            // on 180ms trans-Pacific WAN while old primary keeps running with 0ms stall!
                            if sess.handover_retries < CLIENT_HANDOVER_MAX_RETRIES {
                                sess.handover_retries += 1;
                                if let (Some(ref payload), Some(ref mut cipher)) =
                                    (&sess.handover_payload, &mut sess.cipher)
                                {
                                    if let Some(wn) = cipher.wrap_control_into(
                                        SRTP_HANDOVER_MAGIC,
                                        payload,
                                        &mut self.wbuf,
                                    ) {
                                        if sess.upstream.send(&self.wbuf[..wn]).is_ok() {
                                            sess.tx_pkts += 1;
                                        }
                                    }
                                }
                                sess.handover_retry_at = Some(
                                    now + self
                                        .retry_dur
                                        .max(Duration::from_millis(CLIENT_HANDOVER_MIN_RETRY_MS)),
                                );
                            } else {
                                // P0-5 fix: Only fall back to legacy v0.3.8 promotion if peer proved live
                                // (authenticated SRTCP/SRTP or DTLS 1.3 Flight 5 ACK received); otherwise
                                // abort the unconfirmed standby and keep the healthy primary untouched!
                                let server_confirmed_alive = sess.rx_pkts > 0
                                    || sess.srtcp_rx > 0
                                    || sess.dtls_next_timeout.is_none();
                                sess.handover_payload = None;
                                sess.handover_retry_at = None;
                                if server_confirmed_alive {
                                    sess.state = HandshakeState::Ready;
                                    standby_promoted_timers.push((tok, sess.client_addr));
                                } else {
                                    log(
                                    self.worker_id,
                                    &format!(
                                        "MBB standby handover unconfirmed (0 server rx) up_sport={} -> aborting standby",
                                        sess.local_port
                                    ),
                                );
                                    if let Some(delay) = schedule_async_teardown_client(sess, now) {
                                        if delay < wait {
                                            wait = delay.max(Duration::from_millis(
                                                WORKER_MIN_FAST_WAIT_MS,
                                            ));
                                        }
                                    }
                                    sess.state = HandshakeState::Closing(
                                        now + Duration::from_millis(CLOSING_DRAIN_MS),
                                    );
                                }
                            }
                        } else {
                            let rem = rt.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                            }
                        }
                    }
                }
                HandshakeState::Migrating => {
                    if let Some(rt) = sess.mig_retry_at {
                        if now >= rt {
                            if sess.mig_retries < CLIENT_MIGRATION_MAX_RETRIES {
                                sess.mig_retries += 1;
                                if let Some(mk) = sess.mi_key_mig {
                                    // Fresh txid on each retry prevents an on-path spoofed-IP racer from stalling us!
                                    let (pkt, txid) = build_ice_stun_request_with_key(
                                        &self.stun_auth_psk,
                                        &mk,
                                        &sess.ice,
                                        None,
                                        true,
                                    );
                                    let _ = sess.upstream.send(&pkt);
                                    sess.mig_txid = Some(txid);
                                }
                                sess.mig_retry_at = Some(now + self.retry_dur);
                            } else {
                                // Server lost session state or is legacy v0.3.8 -> fall back to fresh STUN+DTLS!
                                log(
                                self.worker_id,
                                &format!(
                                    "ICE 1-RTT migration unanswered up_sport={} -> falling back to fresh STUN+DTLS",
                                    sess.local_port
                                ),
                            );
                                sess.mig_txid = None;
                                sess.mig_retry_at = None;
                                sess.state = HandshakeState::Closing(
                                    now + Duration::from_millis(CLOSING_DRAIN_MS),
                                );
                                to_rotate.push((tok, sess.client_addr, true));
                                continue;
                            }
                        } else {
                            let rem = rt.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                            }
                        }
                    }
                }
                HandshakeState::Ready => {
                    // V4: Re-send encrypted 0xFFFD path challenge response if lossy link dropped first copy
                    if sess.mig_echo_left > 0 {
                        if let Some(next_at) = sess.mig_echo_next_at {
                            if now >= next_at {
                                if let (Some(ref payload), Some(ref mut cipher)) =
                                    (&sess.mig_echo_payload, &mut sess.cipher)
                                {
                                    if let Some(wn) = cipher.wrap_control_into(
                                        SRTP_PATH_CHALLENGE_MAGIC,
                                        payload,
                                        &mut self.wbuf,
                                    ) {
                                        if sess.upstream.send(&self.wbuf[..wn]).is_ok() {
                                            sess.tx_pkts += 1;
                                        }
                                    }
                                }
                                sess.mig_echo_left -= 1;
                                if sess.mig_echo_left == 0 {
                                    sess.mig_echo_payload = None;
                                    sess.mig_echo_next_at = None;
                                } else {
                                    sess.mig_echo_next_at = Some(
                                        now + Duration::from_millis(CLIENT_MIG_ECHO_INTERVAL_MS),
                                    );
                                }
                            } else {
                                let rem = next_at.saturating_duration_since(now);
                                if rem < wait {
                                    wait =
                                        rem.max(Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS));
                                }
                            }
                        }
                    }
                    // H-01 fix: DTLS 1.3 Client emits Output::Connected upon sending Flight 5 (Cert+CV+Fin)
                    // while keeping its Flight 5 retransmission timer armed until server ACK arrives.
                    // Drive near-term (<60s) dtls_next_timeout in Ready state so a single lost Flight 5
                    // recovers within ~350ms instead of stalling 25s!
                    if let Some(t) = sess.dtls_next_timeout {
                        let rem = t.saturating_duration_since(now);
                        if rem > Duration::from_secs(DTLS_IDLE_TIMEOUT_THRESHOLD_SECS) {
                            // dimpl entered 10-year IDLE_INTERVAL after receiving server ACK
                            sess.dtls_next_timeout = None;
                        } else if now >= t {
                            let err = if let Some(ref mut dtls) = sess.dtls {
                                dtls.handle_timeout(now).is_err()
                            } else {
                                true
                            };
                            if err {
                                if sess.rx_pkts > 0 || sess.srtcp_rx > 0 {
                                    // Server is already Ready (only server's DTLS 1.3 ACK packet was lost)
                                    sess.dtls_next_timeout = None;
                                } else {
                                    log(
                                    self.worker_id,
                                    &format!(
                                        "DTLS 1.3 Flight 5 unacknowledged (0 rx) up_sport={} -> rotating",
                                        sess.local_port
                                    ),
                                );
                                    sess.dtls_next_timeout = None;
                                    sess.state = HandshakeState::Closing(
                                        now + Duration::from_millis(CLOSING_DRAIN_MS),
                                    );
                                    to_rotate.push((tok, sess.client_addr, true));
                                    continue;
                                }
                            } else if drain_client_dtls(
                                self.worker_id,
                                sess,
                                &mut self.dtls_buf,
                                &mut self.wbuf,
                                &self.cfg,
                                &self.cpu,
                                now,
                                None,
                            ) {
                                sess.state = HandshakeState::Closing(
                                    now + Duration::from_millis(CLOSING_DRAIN_MS),
                                );
                                continue;
                            }
                        } else if rem < wait {
                            wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                        }
                    }

                    // Sequence/Nonce exhaustion or silent data-plane deadlock guard (e.g. --keepalive 0
                    // or post-crash/blackhole session where prior packets arrived before peer died).
                    let seq_exhausted = sess
                        .cipher
                        .as_ref()
                        .map(|c| c.is_seq_exhausted())
                        .unwrap_or(false);
                    let deadlock_secs =
                        if self.cfg.keepalive_secs == 0 && is_client_in_trickle(sess, now) {
                            55
                        } else {
                            CLIENT_DL_DEADLOCK_SECS
                        };
                    let dl_deadlock = sess.tx_pkts_since_dl_rx >= CLIENT_DL_DEADLOCK_MIN_TX_PKTS
                        && now.duration_since(sess.last_auth_dl_rx)
                            > Duration::from_secs(deadlock_secs)
                        && sess
                            .ready_at
                            .map(|r| {
                                now.duration_since(r) > Duration::from_secs(CLIENT_DL_DEADLOCK_SECS)
                            })
                            .unwrap_or(false);
                    if seq_exhausted || dl_deadlock {
                        log(
                            self.worker_id,
                            &format!(
                                "{} up_sport={} -> rotating to fresh session",
                                if seq_exhausted {
                                    "SRTP/SRTCP seq ceiling reached"
                                } else {
                                    "Zero authenticated downlink SRTP/SRTCP after 15s"
                                },
                                sess.local_port
                            ),
                        );
                        if let Some(delay) = schedule_async_teardown_client(sess, now) {
                            if delay < wait {
                                wait = delay.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                            }
                        }
                        sess.state =
                            HandshakeState::Closing(now + Duration::from_millis(CLOSING_DRAIN_MS));
                        to_rotate.push((tok, sess.client_addr, true));
                        continue;
                    }

                    // Proactive Make-Before-Break scheduled 5-tuple rotation:
                    //   1) Random single-session byte-volume budget (e.g. 600MB..2.2GB) with cooldown lock
                    //   2) Log-normal wide-distribution duration, suspended during background trickle (<64KB/5m)
                    //      until real traffic resumes or hard fallback cap (5-8h) is reached.
                    if !sess.is_standby && !sess.standby_spawned {
                        let byte_trigger = sess.rotate_byte_budget.is_some_and(|budget| {
                            sess.tx_bytes.saturating_add(sess.rx_bytes) >= budget
                                && sess.ready_at.is_some_and(|r| {
                                    now.duration_since(r)
                                        >= Duration::from_secs(self.cfg.rotate_cooldown_secs)
                                })
                        });
                        if byte_trigger {
                            to_spawn_standby.push((tok, sess.client_addr));
                        } else if let Some(rot_at) = sess.rotate_at {
                            if now >= rot_at {
                                let obs_secs = sess
                                    .ready_at
                                    .map_or(1, |r| now.duration_since(r).as_secs().max(1))
                                    .min(TRICKLE_WINDOW_5MIN_SECS);
                                let threshold_bytes =
                                    (TRICKLE_MBB_5MIN_BYTES * obs_secs) / TRICKLE_WINDOW_5MIN_SECS;
                                let recent_bytes = sess.rate_5min.bytes_in_window(now);
                                let active_traffic = now.duration_since(sess.last_data_active)
                                    <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS)
                                    && recent_bytes >= threshold_bytes;
                                let hard_cap_hit = sess.hard_rotate_at.is_some_and(|h| now >= h)
                                    && now.duration_since(sess.last_data_active) <= self.idle_dur;
                                if active_traffic || hard_cap_hit {
                                    to_spawn_standby.push((tok, sess.client_addr));
                                } else {
                                    // Background trickle keepalives only -> suspend MBB churn and re-check later!
                                    let recheck = if self.cfg.rotate_interval_secs >= 60 {
                                        rand_duration_range_ms(
                                            CLIENT_MBB_TRICKLE_RECHECK_MIN_MS,
                                            CLIENT_MBB_TRICKLE_RECHECK_MAX_MS,
                                        )
                                    } else {
                                        Duration::from_secs(self.cfg.rotate_interval_secs.max(1))
                                    };
                                    sess.rotate_at = Some(now + recheck);
                                }
                            } else {
                                let rem = rot_at.saturating_duration_since(now);
                                if rem < wait {
                                    wait =
                                        rem.max(Duration::from_millis(WORKER_MIN_ROTATE_WAIT_MS));
                                }
                            }
                        }
                    }

                    if !sess.is_prewarm
                        && !self.persistent_tunnel
                        && now.duration_since(sess.last_data_active) > self.idle_dur
                    {
                        if let Some(delay) = schedule_async_teardown_client(sess, now) {
                            if delay < wait {
                                wait = delay.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                            }
                        }
                        sess.state = HandshakeState::Closing(
                            now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS),
                        );
                        continue;
                    }
                    if self.reverse_agent
                        && !sess.is_standby
                        && !sess.is_prewarm
                        && !sess.rev_registered
                    {
                        if let Some(t) = sess.next_rev_hello_at {
                            if now < t {
                                let rem = t.saturating_duration_since(now);
                                if rem < wait {
                                    wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                                }
                            } else {
                                wait = wait.min(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                            }
                        } else {
                            wait = wait.min(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                        }
                    }
                    // RFC 7675 §5.1 + RFC 5389 §7.2.1 bidirectional STUN consent check:
                    // ONLY an authenticated STUN Binding Success Response proves uplink connectivity
                    // (unsolicited server SRTCP or QUIC PTO SRTP MUST NOT mask an asymmetric uplink blackhole!).
                    if self.cfg.keepalive_secs > 0 {
                        if sess.ka_txid.is_some() {
                            if let Some(rto_at) = sess.ka_rto_at {
                                if now >= rto_at {
                                    if sess.ka_retries < sess.ka_max_retries {
                                        sess.ka_retries += 1;
                                        // v0.7.1: sign Ready-state STUN keepalives with per-session
                                        // DTLS-PFS `mi_key_mig` (NOT static `stun_mi_key`) and mint
                                        // a fresh txid on retry so a SIGKILL-restarted server drops
                                        // stale keepalives silently instead of looping forever.
                                        let ka_key =
                                            sess.mi_key_mig.as_ref().unwrap_or(&self.stun_mi_key);
                                        let (pkt, txid) = build_ice_stun_request_with_key(
                                            &self.stun_auth_psk,
                                            ka_key,
                                            &sess.ice,
                                            None,
                                            false,
                                        );
                                        let _ = sess.upstream.send(&pkt);
                                        sess.ka_txid = Some(txid);
                                        sess.ka_pkt = pkt;
                                        sess.ka_sent_at = Some(now);
                                        let next_rto = if sess.ka_retries == 1 {
                                            rand_duration_range_ms(
                                                KA_RTO_RETRY1_MIN_MS,
                                                KA_RTO_RETRY1_MAX_MS,
                                            )
                                        } else {
                                            rand_duration_range_ms(
                                                KA_RTO_RETRY2_MIN_MS,
                                                KA_RTO_RETRY2_MAX_MS,
                                            )
                                        };
                                        sess.ka_rto_at = Some(now + next_rto);
                                    } else {
                                        if let Some(ref th) = self.telemetry {
                                            th.record_blackhole(
                                                sess.ka_max_retries + 1,
                                                format!("up_sport={}", sess.local_port),
                                            );
                                        }
                                        if sess.is_prewarm {
                                            log(
                                                self.worker_id,
                                                &format!(
                                                    "RFC 7675 consent lost on pre-warmed up_sport={} -> draining & re-hunting",
                                                    sess.local_port
                                                ),
                                            );
                                            if let Some(delay) =
                                                schedule_async_teardown_client(sess, now)
                                            {
                                                if delay < wait {
                                                    wait = delay.max(Duration::from_millis(
                                                        WORKER_MIN_FAST_WAIT_MS,
                                                    ));
                                                }
                                            }
                                            sess.ka_txid = None;
                                            sess.ka_pkt.clear();
                                            sess.ka_retries = 0;
                                            sess.ka_rto_at = None;
                                            sess.state = HandshakeState::Closing(
                                                now + Duration::from_secs(BLACKHOLE_DRAIN_SECS),
                                            );
                                            continue;
                                        }
                                        let active_recently = self.reverse_agent
                                            || self.persistent_tunnel
                                            || now.duration_since(sess.last_data_active)
                                                <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS);
                                        if active_recently
                                            && !sess.is_standby
                                            && sess.mi_key_mig.is_some()
                                            && sess.cipher.is_some()
                                        {
                                            // V4: Attempt 1-RTT RFC 8445 ICE path migration on fresh 5-tuple
                                            // (preserves DTLS PFS key, SRTP seq, and server backend_lport!)
                                            log(
                                            self.worker_id,
                                            &format!(
                                                "RFC 7675 consent lost ({}/{} STUN unanswered) client={} up_sport={} -> 1-RTT ICE path migration (draining old {}s)",
                                                sess.ka_max_retries + 1,
                                                sess.ka_max_retries + 1,
                                                sess.client_addr,
                                                sess.local_port,
                                                BLACKHOLE_DRAIN_SECS,
                                            ),
                                        );
                                            sess.ka_txid = None;
                                            sess.ka_pkt.clear();
                                            sess.ka_retries = 0;
                                            sess.ka_rto_at = None;
                                            to_migrate.push(tok);
                                            continue;
                                        }
                                        log(
                                        self.worker_id,
                                        &format!(
                                            "RFC 7675 consent lost ({}/{} STUN unanswered) client={} up_sport={} -> draining {}s{}",
                                            sess.ka_max_retries + 1,
                                            sess.ka_max_retries + 1,
                                            sess.client_addr,
                                            sess.local_port,
                                            BLACKHOLE_DRAIN_SECS,
                                            if active_recently {
                                                " + rotating to fresh 5-tuple"
                                            } else {
                                                " (idle)"
                                            }
                                        ),
                                    );
                                        if let Some(delay) =
                                            schedule_async_teardown_client(sess, now)
                                        {
                                            if delay < wait {
                                                wait = delay.max(Duration::from_millis(
                                                    WORKER_MIN_FAST_WAIT_MS,
                                                ));
                                            }
                                        }
                                        sess.ka_txid = None;
                                        sess.ka_pkt.clear();
                                        sess.ka_retries = 0;
                                        sess.ka_rto_at = None;
                                        sess.state = HandshakeState::Closing(
                                            now + Duration::from_secs(BLACKHOLE_DRAIN_SECS),
                                        );
                                        to_rotate.push((tok, sess.client_addr, active_recently));
                                        continue;
                                    }
                                } else {
                                    let rem = rto_at.saturating_duration_since(now);
                                    if rem < wait {
                                        wait = rem
                                            .max(Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS));
                                    }
                                }
                            }
                        } else if now >= sess.next_keepalive_at {
                            let ka_key = sess.mi_key_mig.as_ref().unwrap_or(&self.stun_mi_key);
                            let (pkt, txid) = build_ice_stun_request_with_key(
                                &self.stun_auth_psk,
                                ka_key,
                                &sess.ice,
                                None,
                                false,
                            );
                            let _ = sess.upstream.send(&pkt);
                            sess.ka_txid = Some(txid);
                            sess.ka_pkt = pkt;
                            sess.ka_retries = 0;
                            sess.ka_sent_at = Some(now);
                            sess.ka_rto_at = Some(
                                now + rand_duration_range_ms(
                                    KA_RTO_INITIAL_MIN_MS,
                                    KA_RTO_INITIAL_MAX_MS,
                                ),
                            );
                        } else {
                            let rem = sess.next_keepalive_at.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS));
                            }
                        }
                    }
                    if now >= sess.next_srtcp_at {
                        let in_trickle = is_client_in_trickle(sess, now);
                        let long_trickle = in_trickle
                            && now.duration_since(sess.last_active_burst)
                                >= Duration::from_secs(CLIENT_LONG_TRICKLE_SECS);
                        let is_active_media = !in_trickle
                            && now.duration_since(sess.last_data_active)
                                <= Duration::from_secs(SRTCP_ACTIVE_MEDIA_WINDOW_SECS);
                        let sent_media = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
                        let has_rx = sess.rx_pkts > sess.rx_pkts_at_last_rtcp;
                        sess.tx_pkts_at_last_rtcp = sess.tx_pkts;
                        sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
                        if let Some(ref mut cipher) = sess.cipher {
                            let pkt = cipher.build_srtcp(has_rx, sent_media, false);
                            if sess.upstream.send(&pkt).is_ok() {
                                sess.srtcp_tx += 1;
                            }
                        }
                        sess.next_srtcp_at = now
                            + if long_trickle {
                                rand_duration_range_ms(
                                    SRTCP_LONG_TRICKLE_MIN_MS,
                                    SRTCP_LONG_TRICKLE_MAX_MS,
                                )
                            } else if is_active_media {
                                rand_duration_range_ms(
                                    CLIENT_SRTCP_ACTIVE_MIN_MS,
                                    CLIENT_SRTCP_ACTIVE_MAX_MS,
                                )
                            } else if !in_trickle {
                                rand_duration_range_ms(SRTCP_IDLE_MIN_MS, SRTCP_IDLE_MAX_MS)
                            } else {
                                rand_duration_range_ms(SRTCP_TRICKLE_MIN_MS, SRTCP_TRICKLE_MAX_MS)
                            };
                    } else {
                        let rem = sess.next_srtcp_at.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS));
                        }
                    }
                }
                HandshakeState::DrainingBeforeBye(bye_at) => {
                    if now >= bye_at {
                        if let Some(delay) = schedule_async_teardown_client(sess, now) {
                            if delay < wait {
                                wait = delay.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                            }
                        }
                        sess.state = HandshakeState::Closing(
                            now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS),
                        );
                    } else {
                        let rem = bye_at.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS));
                        }
                    }
                }
                HandshakeState::Closing(deadline) => {
                    if let Some(cn_at) = sess.pending_close_notify_at {
                        if now >= cn_at {
                            sess.pending_close_notify_at = None;
                            send_client_dtls_close_notify(sess, &mut self.dtls_buf);
                        } else {
                            let rem = cn_at.saturating_duration_since(now);
                            if rem < wait {
                                wait = rem.max(Duration::from_millis(WORKER_MIN_FAST_WAIT_MS));
                            }
                        }
                    }
                    if now >= deadline {
                        if sess.pending_close_notify_at.take().is_some() {
                            send_client_dtls_close_notify(sess, &mut self.dtls_buf);
                        }
                        to_close.push((tok, "graceful_close"));
                    } else {
                        let rem = deadline.saturating_duration_since(now);
                        if rem < wait {
                            wait = rem.max(Duration::from_millis(WORKER_MIN_NORMAL_WAIT_MS));
                        }
                    }
                }
            }
        }

        // Execute V4 1-RTT ICE path migrations (blackhole recovery without DTLS re-handshake or backend port change)
        for tok in to_migrate {
            let client_addr_opt = self.sessions_by_token.get(&tok).map(|s| s.client_addr);
            let Some(client_addr) = client_addr_opt else {
                continue;
            };
            self.cancel_hunts_for_client(client_addr);
            cancel_standby_for_client(
                client_addr,
                &mut self.standby_by_client,
                &mut self.sessions_by_token,
                &mut self.dtls_buf,
                now,
            );
            let recently_rotated = self
                .last_rotation_by_client
                .get(&client_addr)
                .map(|&t| now.duration_since(t) < Duration::from_secs(RECENT_ROTATION_DAMP_SECS))
                .unwrap_or(false);
            self.last_rotation_by_client.insert(client_addr, now);
            if self.cfg.lane_hunt.enabled {
                if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                    sess.state = HandshakeState::Migrating;
                    sess.mig_txid = None;
                    sess.mig_retries = 0;
                    sess.mig_retry_at = None;
                }
                if self.start_lane_hunt(
                    HuntPurpose::Migrate1Rtt {
                        session_tok: tok,
                        client_addr,
                        recently_rotated,
                    },
                    now,
                    VecDeque::new(),
                    0,
                ) {
                    continue;
                }
            }
            let bind_any = unspecified_addr_for(self.cfg.server_addr);
            let new_up =
                match make_udp_socket(bind_any, Some(self.cfg.server_addr), false, SOCK_BUF_8MIB) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
            let new_port = new_up.local_addr().map(|a| a.port()).unwrap_or(0);
            if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                let mut old_up = std::mem::replace(&mut sess.upstream, new_up);
                let _ = self.poll.registry().deregister(&mut old_up);
                if self
                    .poll
                    .registry()
                    .register(&mut sess.upstream, tok, Interest::READABLE)
                    .is_err()
                {
                    // Restore old socket on unexpected registration failure
                    sess.upstream = old_up;
                    let _ =
                        self.poll
                            .registry()
                            .register(&mut sess.upstream, tok, Interest::READABLE);
                    continue;
                }
                // Move old blackholed socket into bounded silent receive-only drain pool (50s, zero ICMP bounce!)
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
                            owner_tok: tok,
                            deadline: now + Duration::from_secs(BLACKHOLE_DRAIN_SECS),
                        },
                    );
                }

                let old_port = sess.local_port;
                sess.local_port = new_port;
                sess.ka_max_retries = if recently_rotated {
                    KA_MAX_RETRIES_DAMPED
                } else {
                    KA_MAX_RETRIES
                };
                if let Some(mk) = sess.mi_key_mig {
                    let (pkt, txid) = build_ice_stun_request_with_key(
                        &self.stun_auth_psk,
                        &mk,
                        &sess.ice,
                        None,
                        true,
                    );
                    let _ = sess.upstream.send(&pkt);
                    sess.state = HandshakeState::Migrating;
                    sess.mig_txid = Some(txid);
                    sess.mig_retries = 0;
                    sess.mig_retry_at = Some(now + self.retry_dur);
                    log(
                    self.worker_id,
                    &format!(
                        "ICE 1-RTT migration started client={} old_sport={} -> new_sport={} ufrag={}",
                        client_addr, old_port, new_port, sess.ice.username()
                    ),
                );
                }
            }
        }

        for (prim_tok, client_addr) in to_spawn_standby {
            if !self.standby_by_client.contains_key(&client_addr) {
                if self.cfg.lane_hunt.enabled {
                    let _ = self.start_lane_hunt(
                        HuntPurpose::MbbStandby {
                            primary_tok: prim_tok,
                            client_addr,
                            reason: MbbHuntReason::ScheduledRotate,
                        },
                        now,
                        VecDeque::new(),
                        0,
                    );
                    continue;
                }
                // P1-2 fix: Only set `standby_spawned = true` when spawn actually succeeds!
                if spawn_client_session(
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
                    KA_MAX_RETRIES,
                    Some(prim_tok),
                )
                .is_some()
                {
                    if let Some(prim) = self.sessions_by_token.get_mut(&prim_tok) {
                        prim.standby_spawned = true;
                    }
                }
            }
        }

        for (old_tok, client_addr, active_recently) in to_rotate {
            if self.token_by_client.get(&client_addr) == Some(&old_tok) {
                self.token_by_client.remove(&client_addr);
            }
            self.pending_reconnects.remove(&client_addr);
            self.cancel_hunts_for_client(client_addr);
            cancel_standby_for_client(
                client_addr,
                &mut self.standby_by_client,
                &mut self.sessions_by_token,
                &mut self.dtls_buf,
                now,
            );
            let recently_rotated = self
                .last_rotation_by_client
                .get(&client_addr)
                .map(|&t| now.duration_since(t) < Duration::from_secs(RECENT_ROTATION_DAMP_SECS))
                .unwrap_or(false);
            self.last_rotation_by_client.insert(client_addr, now);
            if self.last_rotation_by_client.len() > MAX_ROTATION_HISTORY_ENTRIES {
                self.last_rotation_by_client.retain(|_, &mut t| {
                    now.duration_since(t) < Duration::from_secs(RECENT_ROTATION_DAMP_SECS)
                });
            }
            let next_ka_retries = if recently_rotated {
                KA_MAX_RETRIES_DAMPED
            } else {
                KA_MAX_RETRIES
            };
            if active_recently {
                // P0-5 fix: Carry over any buffered app packets (`old_sess.pending`) into the replacement session!
                let (carried_pending, carried_bytes) = self
                    .sessions_by_token
                    .get_mut(&old_tok)
                    .map(|s| {
                        let p = std::mem::take(&mut s.pending);
                        let b = s.pending_bytes;
                        s.pending_bytes = 0;
                        (p, b)
                    })
                    .unwrap_or_else(|| (VecDeque::new(), 0));
                if let Some(adopted) = self.try_adopt_prewarm(client_addr, now) {
                    if !carried_pending.is_empty() {
                        if let Some(ns) = self.sessions_by_token.get_mut(&adopted) {
                            if ns.state == HandshakeState::Ready {
                                if let Some(ref mut cipher) = ns.cipher {
                                    for raw in carried_pending {
                                        if let Some(wn) = cipher.wrap_into(&raw, &mut self.wbuf) {
                                            if ns.upstream.send(&self.wbuf[..wn]).is_ok() {
                                                ns.tx_pkts += 1;
                                                ns.tx_bytes += raw.len() as u64;
                                            }
                                        }
                                    }
                                }
                            } else {
                                ns.pending = carried_pending;
                                ns.pending_bytes = carried_bytes;
                            }
                        }
                    }
                    continue;
                }
                if self.cfg.lane_hunt.enabled
                    && self.start_lane_hunt(
                        HuntPurpose::NewPrimary {
                            client_addr,
                            ka_max_retries: next_ka_retries,
                        },
                        now,
                        carried_pending.clone(),
                        carried_bytes,
                    )
                {
                    continue;
                }
                if let Some(new_tok) = spawn_client_session(
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
                    next_ka_retries,
                    None,
                ) {
                    if !carried_pending.is_empty() {
                        if let Some(ns) = self.sessions_by_token.get_mut(&new_tok) {
                            ns.pending = carried_pending;
                            ns.pending_bytes = carried_bytes;
                        }
                    }
                }
            }
        }

        for (tok, reason) in to_close {
            if let Some(mut sess) = self.sessions_by_token.remove(&tok) {
                self.closed_tx_bytes = self.closed_tx_bytes.saturating_add(sess.tx_bytes);
                self.closed_rx_bytes = self.closed_rx_bytes.saturating_add(sess.rx_bytes);
                self.closed_tx_pkts = self.closed_tx_pkts.saturating_add(sess.tx_pkts);
                self.closed_rx_pkts = self.closed_rx_pkts.saturating_add(sess.rx_pkts);
                self.closed_auth_drops = self.closed_auth_drops.saturating_add(sess.auth_drops);
                let _ = self.poll.registry().deregister(&mut sess.upstream);
                // P2-1: Shrink any remaining self.old_path_drains owned by a normally closed session to free 2MB socket FDs promptly
                let drain_cap = now + Duration::from_millis(CLOSING_DRAIN_MS);
                for d in self.old_path_drains.values_mut() {
                    if d.owner_tok == tok && d.deadline > drain_cap {
                        d.deadline = drain_cap;
                    }
                }
                if self.prewarm_tok == Some(tok) {
                    self.prewarm_tok = None;
                    if self.cfg.lane_hunt.enabled {
                        self.next_prewarm_at = Some(now + Duration::from_millis(500));
                    }
                }
                if self.token_by_client.get(&sess.client_addr) == Some(&tok) {
                    self.token_by_client.remove(&sess.client_addr);
                    self.cancel_hunts_for_client(sess.client_addr);
                    // Primary closed -> cancel any orphan standby belonging to it!
                    cancel_standby_for_client(
                        sess.client_addr,
                        &mut self.standby_by_client,
                        &mut self.sessions_by_token,
                        &mut self.dtls_buf,
                        now,
                    );
                }
                if self.standby_by_client.get(&sess.client_addr) == Some(&tok) {
                    self.standby_by_client.remove(&sess.client_addr);
                    // Standby MBB handshake failed -> postpone retry ONLY on its exact owning primary!
                    if let Some(owner_tok) = sess.standby_for_primary {
                        if self.token_by_client.get(&sess.client_addr) == Some(&owner_tok) {
                            if let Some(prim) = self.sessions_by_token.get_mut(&owner_tok) {
                                prim.standby_spawned = false;
                                if self.cfg.rotate_interval_secs > 0 {
                                    prim.rotate_at = Some(
                                        now + rand_duration_range_ms(
                                            CLIENT_MBB_FAIL_BACKOFF_MIN_MS,
                                            CLIENT_MBB_FAIL_BACKOFF_MAX_MS,
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
                log(
                self.worker_id,
                &format!(
                    "close session client={} up_sport={} reason={} tx={}pkts/{}B rx={}pkts/{}B ka={} rtcp={}/{} drops={}",
                    sess.client_addr, sess.local_port, reason, sess.tx_pkts, sess.tx_bytes,
                    sess.rx_pkts, sess.rx_bytes, sess.keepalives_ok, sess.srtcp_tx, sess.srtcp_rx, sess.auth_drops
                ),
            );
            }
        }
        (wait, standby_promoted_timers, standby_ready_timers)
    }
}
