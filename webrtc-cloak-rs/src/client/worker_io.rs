//! 客户端本地应用收发、旧路径静默引流、远端解封装与 MBB 切换提交。

use super::dtls::{drain_client_dtls, graceful_teardown_client, spawn_client_session};
use super::lane_hunt::{client_outer_hdr_len, HuntPurpose};
use super::worker::ClientWorker;
use super::{
    cancel_standby_for_client, is_client_in_trickle, log, record_client_media_bytes,
    schedule_mbb_timers, HandshakeState, PendingReconnect, ACTIVE_ROTATE_WINDOW_SECS,
    CLIENT_HANDOVER_MIN_RETRY_MS, CLIENT_MIG_ECHO_INTERVAL_MS, CLIENT_SRTCP_INIT_MAX_MS,
    CLIENT_SRTCP_INIT_MIN_MS, KA_MAX_RETRIES, KA_MAX_RETRIES_DAMPED, RECENT_ROTATION_DAMP_SECS,
    TRICKLE_WINDOW_5MIN_SECS,
};
use crate::constants::{
    CLOSING_DRAIN_MS, CTRL_FRAME_BUF_LEN, DTLS_READY_ALERT_ONLY_GRACE_SECS, HANDOVER_OP_ACK,
    HANDOVER_OP_REQ, HANDOVER_PROOF_LEN, MAX_DTLS_RESETS, MAX_INNER_UDP_LEN,
    PATH_CHALLENGE_OP_CONFIRM, PATH_CHALLENGE_OP_REQ, PATH_CHALLENGE_OP_RESP,
    PATH_CHALLENGE_PAYLOAD_LEN, PATH_CONFIRM_PAYLOAD_LEN, POST_BYE_CLOSING_DRAIN_MS,
    SRTP_HANDOVER_MAGIC, SRTP_PATH_CHALLENGE_MAGIC, STUN_BINDING_SUCCESS, TRICKLE_WINDOW_15S_SECS,
};
use crate::protocol::{
    combine_session_key, compute_handover_proof, demux_rfc7983, derive_ice_migration_key,
    derive_stun_material, extract_dtls_server_hello_suite, jitter_duration_ms, new_dtls_instance,
    parse_stun_with_key, rand_duration_range_ms, resolve_srtp_suite, validate_dtls_datagram,
    PacketKind, RollingByteWindow, SrtpCloakCipher, SrtpFrame,
};
use mio::Token;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 细流模式下 STUN 保活退避最小间隔（毫秒，低于典型 CGNAT 超时与 45s 服务端同意超时）。
const TRICKLE_KA_MIN_MS: u64 = 10_000;
/// 细流模式下 STUN 保活退避最大间隔（毫秒）。
const TRICKLE_KA_MAX_MS: u64 = 14_000;
/// 启用细流 STUN 保活退避的 `--keepalive` 下界（秒，含）。
const TRICKLE_KA_ENABLE_MIN_SECS: u64 = 3;
/// 启用细流 STUN 保活退避的 `--keepalive` 上界（秒，不含）。
const TRICKLE_KA_ENABLE_MAX_SECS: u64 = 10;
/// 握手或重连缓冲队列允许暂存的最大应用数据包个数。
const MAX_PENDING_PKTS: usize = 256;
/// 握手或重连缓冲队列允许暂存的最大总字节数（256 KiB）。
const MAX_PENDING_BYTES: usize = 256 * 1024;
/// 收到 `0xFFFD` 路径挑战后重复回显确认的最大补发次数，防止弱网丢失响应。
const CLIENT_MIG_ECHO_COUNT: u8 = 3;
/// MBB 切换完成后旧会话延迟发送 BYE 的最小重叠引流时长（毫秒，打破切换时间关联指纹）。
const CLIENT_MBB_DELAYED_BYE_MIN_MS: u64 = 2_000;
/// MBB 切换完成后旧会话延迟发送 BYE 的最大重叠引流时长（毫秒）。
const CLIENT_MBB_DELAYED_BYE_MAX_MS: u64 = 10_000;
/// 收到服务端优雅关闭 BYE 后客户端快连的最小抖动退避（毫秒，避开 systemd 重启窗口）。
const CLIENT_GRACEFUL_RECONNECT_MIN_MS: u64 = 80;
/// 收到服务端优雅关闭 BYE 后客户端快连的最大抖动退避（毫秒）。
const CLIENT_GRACEFUL_RECONNECT_MAX_MS: u64 = 350;

impl ClientWorker {
    pub(super) fn handle_listen_readable(&mut self, now: Instant) {
        loop {
            let (n, client_addr) = match self.listen_sock.recv_from(&mut self.rbuf) {
                Ok(v) => v,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if n > MAX_INNER_UDP_LEN {
                continue;
            }

            // If this client is inside the 80..350ms post-server-BYE reconnect jitter window,
            // buffer arriving app packets so we never bypass the backoff and trigger ICMP bounce!
            if let Some(pr) = self.pending_reconnects.get_mut(&client_addr) {
                if n <= self.max_inner_pending
                    && pr.pending.len() < MAX_PENDING_PKTS
                    && pr.pending_bytes.saturating_add(n) <= MAX_PENDING_BYTES
                {
                    pr.pending.push_back(self.rbuf[..n].to_vec());
                    pr.pending_bytes += n;
                }
                continue;
            }

            // If existing session is in Closing/DrainingBeforeBye, detach it from self.token_by_client while
            // letting its socket finish silent receive-only drain (zero ICMP Port Unreachable).
            if let Some(&existing_tok) = self.token_by_client.get(&client_addr) {
                if matches!(
                    self.sessions_by_token.get(&existing_tok).map(|s| s.state),
                    Some(HandshakeState::Closing(_) | HandshakeState::DrainingBeforeBye(_))
                ) {
                    self.token_by_client.remove(&client_addr);
                }
            }

            let tok = if let Some(&existing) = self.token_by_client.get(&client_addr) {
                existing
            } else if let Some(hid) = self.find_new_primary_hunt_id(client_addr) {
                if let Some(hunt) = self.lane_hunts.get_mut(&hid) {
                    if n <= self.max_inner_pending
                        && hunt.pending.len() < MAX_PENDING_PKTS
                        && hunt.pending_bytes.saturating_add(n) <= MAX_PENDING_BYTES
                    {
                        hunt.pending.push_back(self.rbuf[..n].to_vec());
                        hunt.pending_bytes += n;
                    }
                }
                continue;
            } else if let Some(adopted) = self.try_adopt_prewarm(client_addr, now) {
                adopted
            } else {
                let recently_rotated = self
                    .last_rotation_by_client
                    .get(&client_addr)
                    .map(|&t| {
                        now.duration_since(t) < Duration::from_secs(RECENT_ROTATION_DAMP_SECS)
                    })
                    .unwrap_or(false);
                let ka_retries = if recently_rotated {
                    KA_MAX_RETRIES_DAMPED
                } else {
                    KA_MAX_RETRIES
                };
                if self.cfg.lane_hunt.enabled {
                    // 若启动预热抽卡正在进行中，直接将其就地升级为当前客户端的主抽卡并缓存首包（零浪费套接字）
                    if let Some(pw_id) = self.find_prewarm_hunt_id() {
                        if let Some(hunt) = self.lane_hunts.get_mut(&pw_id) {
                            hunt.purpose = HuntPurpose::NewPrimary {
                                client_addr,
                                ka_max_retries: ka_retries,
                            };
                            if n <= self.max_inner_pending
                                && hunt.pending.len() < MAX_PENDING_PKTS
                                && hunt.pending_bytes.saturating_add(n) <= MAX_PENDING_BYTES
                            {
                                hunt.pending.push_back(self.rbuf[..n].to_vec());
                                hunt.pending_bytes += n;
                            }
                            continue;
                        }
                    }
                    let mut init_pending = VecDeque::with_capacity(16);
                    let mut init_bytes = 0usize;
                    if n <= self.max_inner_pending {
                        init_pending.push_back(self.rbuf[..n].to_vec());
                        init_bytes = n;
                    }
                    if self.start_lane_hunt(
                        HuntPurpose::NewPrimary {
                            client_addr,
                            ka_max_retries: ka_retries,
                        },
                        now,
                        init_pending,
                        init_bytes,
                    ) {
                        continue;
                    }
                }
                match spawn_client_session(
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
                    ka_retries,
                    None,
                ) {
                    Some(t) => t,
                    None => continue,
                }
            };

            if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                sess.last_data_active = now;
                if sess.state != HandshakeState::Ready {
                    if n <= self.max_inner_pending
                        && sess.pending.len() < MAX_PENDING_PKTS
                        && sess.pending_bytes.saturating_add(n) <= MAX_PENDING_BYTES
                    {
                        sess.pending.push_back(self.rbuf[..n].to_vec());
                        sess.pending_bytes += n;
                    }
                } else {
                    let mut sent_ok = false;
                    if let Some(ref mut cipher) = sess.cipher {
                        if let Some(wn) = cipher.wrap_into(&self.rbuf[..n], &mut self.wbuf) {
                            if sess.upstream.send(&self.wbuf[..wn]).is_ok() {
                                sess.tx_pkts += 1;
                                sess.tx_bytes += n as u64;
                                sent_ok = true;
                            }
                        }
                    }
                    if sent_ok {
                        record_client_media_bytes(sess, &self.cfg, self.ka_base_ms, now, n as u64);
                    }
                }
            }
        }
    }

    pub(super) fn handle_old_path_drain(
        &mut self,
        tok: Token,
        now: Instant,
        graceful_reconnects: &mut Vec<(Token, SocketAddr)>,
    ) {
        if let Some(drain) = self.old_path_drains.get_mut(&tok) {
            // V4 silent receive-only drain for old socket after 1-RTT ICE migration:
            // still delivers trailing authenticated downlink SRTP with zero WAN TX (zero ICMP bounce!).
            let owner_tok = drain.owner_tok;
            loop {
                let n = match drain.sock.recv(&mut self.rbuf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                let pkt = &self.rbuf[..n];
                match demux_rfc7983(pkt) {
                    PacketKind::Srtp => {
                        if let Some(owner) = self.sessions_by_token.get_mut(&owner_tok) {
                            if let Some(ref mut cipher) = owner.cipher {
                                if let Some(pn) = cipher.unwrap_into(pkt, &mut self.wbuf) {
                                    if self
                                        .listen_sock
                                        .send_to(&self.wbuf[..pn], owner.client_addr)
                                        .is_ok()
                                    {
                                        owner.rx_pkts += 1;
                                        owner.rx_bytes += pn as u64;
                                    }
                                }
                            }
                        }
                    }
                    // P1-5 fix: Detect server SIGTERM graceful BYE arriving on old draining socket during migration!
                    PacketKind::Srtcp => {
                        if let Some(owner) = self.sessions_by_token.get_mut(&owner_tok) {
                            if matches!(
                                owner.state,
                                HandshakeState::Migrating | HandshakeState::Ready
                            ) {
                                if let Some(ref mut cipher) = owner.cipher {
                                    if let Some(true) = cipher.verify_srtcp(pkt) {
                                        owner.srtcp_rx += 1;
                                        let active_recently = now
                                            .duration_since(owner.last_data_active)
                                            <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS);
                                        owner.state = HandshakeState::Closing(
                                            now + Duration::from_millis(CLOSING_DRAIN_MS),
                                        );
                                        if !owner.is_standby && active_recently {
                                            graceful_reconnects
                                                .push((owner_tok, owner.client_addr));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    pub(super) fn handle_upstream_readable(
        &mut self,
        tok: Token,
        now: Instant,
        standby_ready: &mut Vec<(Token, SocketAddr)>,
        standby_promoted: &mut Vec<(Token, SocketAddr)>,
        graceful_reconnects: &mut Vec<(Token, SocketAddr)>,
    ) {
        let mut ka_sample: Option<(f64, u8)> = None;
        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            loop {
                let n = match sess.upstream.recv(&mut self.rbuf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                let pkt = &self.rbuf[..n];
                if matches!(
                    sess.state,
                    HandshakeState::Closing(_) | HandshakeState::DrainingBeforeBye(_)
                ) {
                    // Make-Before-Break silent receive-only drain: deliver authenticated in-flight
                    // downlink SRTP to local app while transmitting ZERO WAN packets until delayed BYE.
                    match demux_rfc7983(pkt) {
                        PacketKind::Srtp => {
                            if let Some(ref mut cipher) = sess.cipher {
                                if let Some(pn) = cipher.unwrap_into(pkt, &mut self.wbuf) {
                                    if self
                                        .listen_sock
                                        .send_to(&self.wbuf[..pn], sess.client_addr)
                                        .is_ok()
                                    {
                                        sess.rx_pkts += 1;
                                        sess.rx_bytes += pn as u64;
                                    }
                                }
                            }
                        }
                        PacketKind::Srtcp
                            if matches!(sess.state, HandshakeState::DrainingBeforeBye(_)) =>
                        {
                            if let Some(ref mut cipher) = sess.cipher {
                                if let Some(has_bye) = cipher.verify_srtcp(pkt) {
                                    sess.srtcp_rx += 1;
                                    if has_bye {
                                        sess.state = HandshakeState::Closing(
                                            now + Duration::from_millis(CLOSING_DRAIN_MS),
                                        );
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                match demux_rfc7983(pkt) {
                    PacketKind::Stun => {
                        if sess.state == HandshakeState::Migrating {
                            // V4 1-RTT ICE migration STUN Success signed with per-session mi_key_mig
                            if let Some(mk) = sess.mi_key_mig {
                                if let Some(parsed) = parse_stun_with_key(pkt, &self.cfg.psk, &mk) {
                                    if parsed.authenticated
                                        && parsed.msg_type == STUN_BINDING_SUCCESS
                                        && sess.mig_txid == Some(parsed.txid)
                                    {
                                        // Valid STUN reply; paired 0xFFFD challenge arrives in same flight
                                        continue;
                                    }
                                }
                            }
                            sess.auth_drops += 1;
                            continue;
                        }
                        if let Some(parsed) =
                            parse_stun_with_key(pkt, &self.cfg.psk, &self.stun_mi_key)
                        {
                            if parsed.authenticated && parsed.msg_type == STUN_BINDING_SUCCESS {
                                if sess.state == HandshakeState::StunWait
                                    && parsed.txid == sess.stun_txid
                                {
                                    let rtt_ms = sess.created_at.elapsed().as_secs_f64() * 1000.0;
                                    if let Some(ref th) = self.telemetry {
                                        th.record_stun_ok(
                                            rtt_ms,
                                            sess.retries.min(255) as u8,
                                            parsed.xor_mapped,
                                        );
                                    }
                                    let uname = sess.ice.username();
                                    let (stun_key, s_c2s, s_s2c) = derive_stun_material(
                                        &self.cfg.psk,
                                        &sess.stun_txid,
                                        &uname,
                                    );
                                    sess.stun_key = Some(stun_key);
                                    sess.ssrc_c2s = s_c2s;
                                    sess.ssrc_s2c = s_s2c;
                                    let mapped_s = parsed
                                        .xor_mapped
                                        .map(|a| a.to_string())
                                        .unwrap_or_else(|| "unknown".into());
                                    log(
                                    self.worker_id,
                                    &format!(
                                        "ICE STUN OK up_sport={} rtt={:.2}ms mapped={} ssrc_tx=0x{:08x} ssrc_rx=0x{:08x}",
                                        sess.local_port, rtt_ms, mapped_s, s_c2s, s_s2c
                                    ),
                                );
                                    sess.cached_initial_stun = Vec::new();
                                    if self.cfg.dtls_decoy {
                                        let cert = self.cert_cache.get(now);
                                        let mut dtls = Box::new(new_dtls_instance(
                                            self.cfg.dtls_min_version,
                                            self.dtls_pool.pick(),
                                            cert,
                                            now,
                                        ));
                                        dtls.set_active(true);
                                        let _ = dtls.handle_timeout(now);
                                        sess.dtls = Some(dtls);
                                        sess.state = HandshakeState::DtlsHandshake;
                                        let _ = drain_client_dtls(
                                            self.worker_id,
                                            sess,
                                            &mut self.dtls_buf,
                                            &mut self.wbuf,
                                            &self.cfg,
                                            &self.cpu,
                                            now,
                                            None,
                                        );
                                    } else {
                                        let chosen = resolve_srtp_suite(
                                            self.cfg.cipher_pref,
                                            None,
                                            &self.cpu,
                                            true,
                                        );
                                        let final_key = combine_session_key(&stun_key, None);
                                        sess.session_key = Some(final_key);
                                        sess.mi_key_mig =
                                            Some(derive_ice_migration_key(&final_key));
                                        sess.active_cipher = Some(chosen);
                                        let mut c = SrtpCloakCipher::new(
                                            &final_key, s_c2s, s_s2c, true, chosen,
                                        );
                                        c.set_wan_mtu_for(
                                            self.cfg.wan_mtu,
                                            client_outer_hdr_len(self.cfg.server_addr),
                                        );
                                        sess.cipher = Some(c);
                                        sess.state = HandshakeState::Ready;
                                        sess.ready_at = Some(now);
                                        sess.last_data_active = now;
                                        sess.last_active_burst = now;
                                        sess.rate_15s = RollingByteWindow::new(
                                            now,
                                            Duration::from_secs(TRICKLE_WINDOW_15S_SECS),
                                        );
                                        sess.rate_5min = RollingByteWindow::new(
                                            now,
                                            Duration::from_secs(TRICKLE_WINDOW_5MIN_SECS),
                                        );
                                        sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
                                        sess.ka_txid = None;
                                        sess.ka_pkt.clear();
                                        sess.ka_retries = 0;
                                        sess.ka_rto_at = None;
                                        sess.next_keepalive_at =
                                            now + jitter_duration_ms(self.ka_base_ms);
                                        sess.next_srtcp_at = now
                                            + rand_duration_range_ms(
                                                CLIENT_SRTCP_INIT_MIN_MS,
                                                CLIENT_SRTCP_INIT_MAX_MS,
                                            );
                                        schedule_mbb_timers(sess, &self.cfg, now);
                                        if sess.is_standby {
                                            standby_ready.push((tok, sess.client_addr));
                                        }
                                        let mut flushed = 0usize;
                                        let mut flushed_bytes = 0u64;
                                        sess.pending_bytes = 0;
                                        if let Some(ref mut cipher) = sess.cipher {
                                            while let Some(raw) = sess.pending.pop_front() {
                                                if let Some(wn) =
                                                    cipher.wrap_into(&raw, &mut self.wbuf)
                                                {
                                                    if sess.upstream.send(&self.wbuf[..wn]).is_ok()
                                                    {
                                                        sess.tx_pkts += 1;
                                                        sess.tx_bytes += raw.len() as u64;
                                                        flushed_bytes = flushed_bytes
                                                            .saturating_add(raw.len() as u64);
                                                        flushed += 1;
                                                    }
                                                }
                                            }
                                        }
                                        if flushed_bytes > 0 {
                                            record_client_media_bytes(
                                                sess,
                                                &self.cfg,
                                                self.ka_base_ms,
                                                now,
                                                flushed_bytes,
                                            );
                                        }
                                        log(
                                        self.worker_id,
                                        &format!(
                                            "session READY (no-dtls) up_sport={} cipher={} flushed={}",
                                            sess.local_port,
                                            chosen.name(),
                                            flushed
                                        ),
                                    );
                                    }
                                } else if sess.state == HandshakeState::Ready
                                    && sess.ka_txid == Some(parsed.txid)
                                {
                                    let ka_rtt = sess
                                        .ka_sent_at
                                        .map(|t| {
                                            now.saturating_duration_since(t).as_secs_f64() * 1000.0
                                        })
                                        .unwrap_or(0.0);
                                    let ka_retries_before_ok = sess.ka_retries;
                                    if ka_rtt > 0.0 {
                                        ka_sample = Some((ka_rtt, ka_retries_before_ok));
                                    }
                                    if let Some(ref th) = self.telemetry {
                                        th.record_stun_ok(
                                            ka_rtt,
                                            ka_retries_before_ok,
                                            parsed.xor_mapped,
                                        );
                                    }
                                    sess.keepalives_ok += 1;
                                    sess.ka_txid = None;
                                    sess.ka_pkt.clear();
                                    sess.ka_retries = 0;
                                    sess.ka_sent_at = None;
                                    sess.ka_rto_at = None;
                                    let in_trickle = is_client_in_trickle(sess, now);
                                    sess.next_keepalive_at = now
                                        + if in_trickle
                                            && self.cfg.keepalive_secs >= TRICKLE_KA_ENABLE_MIN_SECS
                                            && self.cfg.keepalive_secs < TRICKLE_KA_ENABLE_MAX_SECS
                                        {
                                            // Conservative trickle STUN backoff (10-14s, safely below 20-30s CGNAT & 45s server consent)
                                            rand_duration_range_ms(
                                                TRICKLE_KA_MIN_MS,
                                                TRICKLE_KA_MAX_MS,
                                            )
                                        } else {
                                            jitter_duration_ms(self.ka_base_ms)
                                        };
                                }
                            } else {
                                sess.auth_drops += 1;
                            }
                        } else {
                            sess.auth_drops += 1;
                        }
                    }
                    PacketKind::Dtls => {
                        // V3.2: strict DTLS pre-validation + Ready gating + Fail-Fast reset in DtlsHandshake
                        let ready_only_alert = matches!(
                            sess.state,
                            HandshakeState::Ready
                                | HandshakeState::HandoverWait
                                | HandshakeState::Migrating
                        ) && sess
                            .ready_at
                            .map(|r| {
                                now.duration_since(r)
                                    > Duration::from_secs(DTLS_READY_ALERT_ONLY_GRACE_SECS)
                            })
                            .unwrap_or(false);
                        if !validate_dtls_datagram(pkt, ready_only_alert) {
                            sess.auth_drops += 1;
                            continue;
                        }
                        let candidate_sh = if sess.state == HandshakeState::DtlsHandshake {
                            extract_dtls_server_hello_suite(pkt)
                        } else {
                            None
                        };
                        let mut dtls_err = false;
                        if let Some(ref mut dtls) = sess.dtls {
                            if sess.dtls_next_timeout.map(|t| now >= t).unwrap_or(false) {
                                let _ = dtls.handle_timeout(now);
                            }
                            if dtls.handle_packet(pkt).is_err() {
                                dtls_err = true;
                            }
                        } else {
                            sess.auth_drops += 1;
                            continue;
                        }
                        if dtls_err {
                            sess.auth_drops += 1;
                            if matches!(
                                sess.state,
                                HandshakeState::Ready
                                    | HandshakeState::HandoverWait
                                    | HandshakeState::Migrating
                            ) {
                                // Keep established SRTP tunnel alive; drop corrupted DTLS handle only
                                sess.dtls = None;
                                sess.dtls_next_timeout = None;
                            } else if sess.state == HandshakeState::DtlsHandshake {
                                // P0-4: dimpl Err during handshake means transcript/state is fatally poisoned.
                                // Fail-fast reset (up to MAX_DTLS_RESETS) instead of stalling 12s!
                                if sess.dtls_resets < MAX_DTLS_RESETS {
                                    sess.dtls_resets += 1;
                                    sess.pending_sh_suite = None;
                                    sess.dtls_suite_id = None;
                                    sess.dtls_km = None;
                                    let cert = self.cert_cache.get(now);
                                    let mut fresh = Box::new(new_dtls_instance(
                                        self.cfg.dtls_min_version,
                                        self.dtls_pool.pick(),
                                        cert,
                                        now,
                                    ));
                                    fresh.set_active(true);
                                    let _ = fresh.handle_timeout(now);
                                    sess.dtls = Some(fresh);
                                    let _ = drain_client_dtls(
                                        self.worker_id,
                                        sess,
                                        &mut self.dtls_buf,
                                        &mut self.wbuf,
                                        &self.cfg,
                                        &self.cpu,
                                        now,
                                        None,
                                    );
                                } else {
                                    sess.state = HandshakeState::Closing(
                                        now + Duration::from_millis(CLOSING_DRAIN_MS),
                                    );
                                }
                            }
                            continue;
                        }
                        let was_ready = sess.state == HandshakeState::Ready;
                        if drain_client_dtls(
                            self.worker_id,
                            sess,
                            &mut self.dtls_buf,
                            &mut self.wbuf,
                            &self.cfg,
                            &self.cpu,
                            now,
                            candidate_sh,
                        ) {
                            let active_recently = now.duration_since(sess.last_data_active)
                                <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS);
                            sess.state = HandshakeState::Closing(
                                now + Duration::from_millis(CLOSING_DRAIN_MS),
                            );
                            if was_ready && !sess.is_standby && !sess.is_prewarm && active_recently
                            {
                                graceful_reconnects.push((tok, sess.client_addr));
                            }
                        } else if !was_ready
                            && sess.state == HandshakeState::Ready
                            && sess.is_standby
                        {
                            standby_ready.push((tok, sess.client_addr));
                        }
                    }
                    PacketKind::Srtcp => {
                        // P1-5 fix: Also accept authenticated SRTCP (esp. server SIGTERM BYE) during HandoverWait/Migrating!
                        if matches!(
                            sess.state,
                            HandshakeState::Ready
                                | HandshakeState::HandoverWait
                                | HandshakeState::Migrating
                        ) {
                            if let Some(ref mut cipher) = sess.cipher {
                                if let Some(has_bye) = cipher.verify_srtcp(pkt) {
                                    sess.srtcp_rx += 1;
                                    if has_bye {
                                        let active_recently = now
                                            .duration_since(sess.last_data_active)
                                            <= Duration::from_secs(ACTIVE_ROTATE_WINDOW_SECS);
                                        sess.state = HandshakeState::Closing(
                                            now + Duration::from_millis(CLOSING_DRAIN_MS),
                                        );
                                        if !sess.is_standby && !sess.is_prewarm && active_recently {
                                            graceful_reconnects.push((tok, sess.client_addr));
                                        }
                                    }
                                } else {
                                    sess.auth_drops += 1;
                                }
                            }
                        } else {
                            sess.auth_drops += 1;
                        }
                    }
                    PacketKind::Srtp => {
                        if matches!(
                            sess.state,
                            HandshakeState::Ready
                                | HandshakeState::HandoverWait
                                | HandshakeState::Migrating
                        ) {
                            let mut rx_ok_bytes = 0u64;
                            let frame = sess
                                .cipher
                                .as_mut()
                                .and_then(|c| c.unwrap_into_ex(pkt, &mut self.wbuf));
                            match frame {
                                Some(SrtpFrame::Data(pn)) => {
                                    sess.last_data_active = now;
                                    if sess.state == HandshakeState::Ready && sess.mig_echo_left > 0
                                    {
                                        sess.mig_echo_left = 0;
                                        sess.mig_echo_payload = None;
                                        sess.mig_echo_next_at = None;
                                    }
                                    if self
                                        .listen_sock
                                        .send_to(&self.wbuf[..pn], sess.client_addr)
                                        .is_ok()
                                    {
                                        sess.rx_pkts += 1;
                                        sess.rx_bytes += pn as u64;
                                        rx_ok_bytes = pn as u64;
                                    }
                                }
                                Some(SrtpFrame::PathChallenge(pn)) => {
                                    sess.rx_pkts += 1;
                                    if pn == PATH_CHALLENGE_PAYLOAD_LEN
                                        && self.wbuf[0] == PATH_CHALLENGE_OP_REQ
                                    {
                                        // P0-2 fix: Accept 0xFFFD(0x01) both in `Migrating` AND while
                                        // in `Ready` with unconfirmed `mig_echo_left > 0` (epoch >= current)!
                                        let cur_epoch = sess
                                            .mig_echo_payload
                                            .as_deref()
                                            .filter(|p| p.len() == PATH_CHALLENGE_PAYLOAD_LEN)
                                            .map(|p| {
                                                u64::from_be_bytes(p[9..17].try_into().unwrap())
                                            })
                                            .unwrap_or(0);
                                        let got_epoch = u64::from_be_bytes(
                                            self.wbuf[9..17].try_into().unwrap(),
                                        );
                                        let accept_challenge = sess.state
                                            == HandshakeState::Migrating
                                            || (sess.state == HandshakeState::Ready
                                                && sess.mig_echo_left > 0
                                                && got_epoch >= cur_epoch);
                                        if accept_challenge {
                                            let mut resp_payload =
                                                [0u8; PATH_CHALLENGE_PAYLOAD_LEN];
                                            resp_payload[0] = PATH_CHALLENGE_OP_RESP;
                                            resp_payload[1..PATH_CHALLENGE_PAYLOAD_LEN]
                                                .copy_from_slice(
                                                    &self.wbuf[1..PATH_CHALLENGE_PAYLOAD_LEN],
                                                );
                                            let was_migrating =
                                                sess.state == HandshakeState::Migrating;
                                            let mut flushed = 0usize;
                                            let mut flushed_bytes = 0u64;
                                            if was_migrating {
                                                sess.pending_bytes = 0;
                                            }
                                            if let Some(ref mut cipher) = sess.cipher {
                                                let mut cbuf = [0u8; CTRL_FRAME_BUF_LEN];
                                                if let Some(wn) = cipher.wrap_control_into(
                                                    SRTP_PATH_CHALLENGE_MAGIC,
                                                    &resp_payload,
                                                    &mut cbuf,
                                                ) {
                                                    if sess.upstream.send(&cbuf[..wn]).is_ok() {
                                                        sess.tx_pkts += 1;
                                                    }
                                                }
                                                if was_migrating {
                                                    while let Some(raw) = sess.pending.pop_front() {
                                                        if let Some(wn) =
                                                            cipher.wrap_into(&raw, &mut self.wbuf)
                                                        {
                                                            if sess
                                                                .upstream
                                                                .send(&self.wbuf[..wn])
                                                                .is_ok()
                                                            {
                                                                sess.tx_pkts += 1;
                                                                sess.tx_bytes += raw.len() as u64;
                                                                flushed_bytes = flushed_bytes
                                                                    .saturating_add(
                                                                        raw.len() as u64
                                                                    );
                                                                flushed += 1;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            sess.state = HandshakeState::Ready;
                                            sess.mig_txid = None;
                                            sess.mig_retry_at = None;
                                            sess.mig_echo_payload = Some(resp_payload.to_vec());
                                            sess.mig_echo_next_at = Some(
                                                now + Duration::from_millis(
                                                    CLIENT_MIG_ECHO_INTERVAL_MS,
                                                ),
                                            );
                                            sess.mig_echo_left = CLIENT_MIG_ECHO_COUNT;
                                            if was_migrating {
                                                // 重置新路径的丢包纪元、RTT/抖动与试用期基线，隔离旧黑洞路径的历史断层与残留延迟
                                                if let Some(ref mut cipher) = sess.cipher {
                                                    cipher.reset_rx_loss_epoch();
                                                }
                                                sess.lane_prev_settled_exp = 0;
                                                sess.lane_prev_settled_rx = 0;
                                                sess.lane_last_ka_settled_exp = 0;
                                                sess.lane_rtt_ewma_ms = None;
                                                sess.lane_rtt_last_ms = None;
                                                sess.lane_data_loss_rate = 0.0;
                                                sess.lane_stun_outcomes.clear();
                                                sess.lane_jitter_ms = 0.0;
                                                sess.lane_score = None;
                                                sess.lane_confirmed = false;
                                                sess.lane_good_windows = 0;
                                                sess.lane_subopt_windows = 0;
                                                sess.lane_degrade_streak = 0;
                                                sess.next_keepalive_at =
                                                    now + jitter_duration_ms(self.ka_base_ms);
                                                if flushed_bytes > 0 {
                                                    record_client_media_bytes(
                                                        sess,
                                                        &self.cfg,
                                                        self.ka_base_ms,
                                                        now,
                                                        flushed_bytes,
                                                    );
                                                }
                                                log(
                                                self.worker_id,
                                                &format!(
                                                    "ICE 1-RTT MIGRATION OK -> READY up_sport={} flushed={}",
                                                    sess.local_port, flushed
                                                ),
                                            );
                                                if let Some(ref th) = self.telemetry {
                                                    th.record_migration_1rtt(format!(
                                                        "up_sport={} flushed={}",
                                                        sess.local_port, flushed
                                                    ));
                                                }
                                            }
                                        }
                                    } else if pn >= PATH_CONFIRM_PAYLOAD_LEN
                                        && self.wbuf[0] == PATH_CHALLENGE_OP_CONFIRM
                                    {
                                        // P2-1: Verify confirm nonce matches active in-flight echo
                                        let nonce_ok = sess
                                            .mig_echo_payload
                                            .as_deref()
                                            .filter(|p| p.len() >= PATH_CONFIRM_PAYLOAD_LEN)
                                            .map(|p| p[1..9] == self.wbuf[1..9])
                                            .unwrap_or(true);
                                        if nonce_ok {
                                            sess.mig_echo_left = 0;
                                            sess.mig_echo_payload = None;
                                            sess.mig_echo_next_at = None;
                                        }
                                    }
                                }
                                Some(SrtpFrame::Handover(pn)) => {
                                    sess.rx_pkts += 1;
                                    if sess.state == HandshakeState::HandoverWait
                                        && pn >= 2
                                        && self.wbuf[0] == HANDOVER_OP_ACK
                                    {
                                        sess.handover_payload = None;
                                        sess.handover_retry_at = None;
                                        sess.state = HandshakeState::Ready;
                                        standby_promoted.push((tok, sess.client_addr));
                                    }
                                }
                                Some(SrtpFrame::Probe(_)) => {
                                    sess.rx_pkts += 1;
                                    sess.last_data_active = now;
                                }
                                None => {
                                    sess.auth_drops += 1;
                                }
                            }
                            if rx_ok_bytes > 0 {
                                record_client_media_bytes(
                                    sess,
                                    &self.cfg,
                                    self.ka_base_ms,
                                    now,
                                    rx_ok_bytes,
                                );
                            }
                        } else {
                            sess.auth_drops += 1;
                        }
                    }
                    PacketKind::Unknown => {
                        sess.auth_drops += 1;
                    }
                }
            }
        }
        if let Some((ka_rtt, ka_retries)) = ka_sample {
            self.evaluate_lane_quality_on_ka(tok, ka_rtt, ka_retries, now);
        }
    }

    pub(super) fn process_post_events(
        &mut self,
        now: Instant,
        standby_ready: Vec<(Token, SocketAddr)>,
        mut standby_promoted: Vec<(Token, SocketAddr)>,
        graceful_reconnects: Vec<(Token, SocketAddr)>,
    ) {
        // V4: When a standby MBB session completes DTLS 1.3 (or STUN), send encrypted 0xFFFC
        // backend_sock atomic handover request while keeping old primary 100% live (0ms stall!).
        for (new_tok, client_addr) in standby_ready {
            let is_current_standby = self.standby_by_client.get(&client_addr) == Some(&new_tok);
            let expected_prim = self
                .sessions_by_token
                .get(&new_tok)
                .and_then(|s| s.standby_for_primary);
            let owner_info = if is_current_standby
                && expected_prim.is_some()
                && self.token_by_client.get(&client_addr).copied() == expected_prim
            {
                expected_prim.and_then(|pt| {
                    self.sessions_by_token.get(&pt).and_then(|p| {
                        if p.state == HandshakeState::Ready {
                            p.session_key.map(|k| (p.ice.username(), k))
                        } else {
                            None
                        }
                    })
                })
            } else {
                None
            };

            let Some((old_ufrag, old_key)) = owner_info else {
                if is_current_standby {
                    self.standby_by_client.remove(&client_addr);
                }
                if let Some(orphan) = self.sessions_by_token.get_mut(&new_tok) {
                    graceful_teardown_client(orphan, &mut self.dtls_buf);
                    orphan.state = HandshakeState::Closing(
                        now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS),
                    );
                }
                continue;
            };

            if let Some(new_sess) = self.sessions_by_token.get_mut(&new_tok) {
                if let Some(new_key) = new_sess.session_key {
                    let proof = compute_handover_proof(&old_key, &new_key);
                    let ub = old_ufrag.as_bytes();
                    let mut payload = Vec::with_capacity(2 + ub.len() + HANDOVER_PROOF_LEN);
                    payload.push(HANDOVER_OP_REQ);
                    payload.push(ub.len() as u8);
                    payload.extend_from_slice(ub);
                    payload.extend_from_slice(&proof);
                    if let Some(ref mut cipher) = new_sess.cipher {
                        if let Some(wn) =
                            cipher.wrap_control_into(SRTP_HANDOVER_MAGIC, &payload, &mut self.wbuf)
                        {
                            if new_sess.upstream.send(&self.wbuf[..wn]).is_ok() {
                                new_sess.tx_pkts += 1;
                            }
                        }
                    }
                    new_sess.state = HandshakeState::HandoverWait;
                    new_sess.handover_payload = Some(payload);
                    new_sess.handover_retries = 0;
                    new_sess.handover_retry_at = Some(
                        now + self
                            .retry_dur
                            .max(Duration::from_millis(CLIENT_HANDOVER_MIN_RETRY_MS)),
                    );
                } else {
                    standby_promoted.push((new_tok, client_addr));
                }
            }
        }

        // Atomic 0ms Make-Before-Break standby promotion with ownership verification & delayed BYE (2-10s)
        for (new_tok, client_addr) in standby_promoted {
            let is_current_standby = self.standby_by_client.get(&client_addr) == Some(&new_tok);
            if is_current_standby {
                self.standby_by_client.remove(&client_addr);
            }
            let expected_prim = self
                .sessions_by_token
                .get(&new_tok)
                .and_then(|s| s.standby_for_primary);
            let owner_is_live_primary = is_current_standby
                && expected_prim.is_some()
                && self.token_by_client.get(&client_addr).copied() == expected_prim
                && expected_prim
                    .and_then(|pt| self.sessions_by_token.get(&pt))
                    .map(|p| p.state == HandshakeState::Ready)
                    .unwrap_or(false);

            if !owner_is_live_primary {
                // Orphaned standby (owning primary already rotated, restarted, or closed) -> tear down cleanly!
                if let Some(orphan) = self.sessions_by_token.get_mut(&new_tok) {
                    graceful_teardown_client(orphan, &mut self.dtls_buf);
                    orphan.state = HandshakeState::Closing(
                        now + Duration::from_millis(POST_BYE_CLOSING_DRAIN_MS),
                    );
                }
                continue;
            }

            let trial_cooldown = self.trial_cooldown_dur();
            let new_port = match self.sessions_by_token.get_mut(&new_tok) {
                Some(new_sess) if new_sess.state == HandshakeState::Ready => {
                    new_sess.is_standby = false;
                    new_sess.standby_for_primary = None;
                    new_sess.standby_spawned = false;
                    new_sess.lane_confirmed = false;
                    new_sess.lane_good_windows = 0;
                    new_sess.lane_subopt_windows = 0;
                    new_sess.lane_degrade_streak = 0;
                    new_sess.next_lane_hunt_at = now + trial_cooldown;
                    schedule_mbb_timers(new_sess, &self.cfg, now);
                    new_sess.local_port
                }
                _ => continue,
            };
            if let Some(old_tok) = self.token_by_client.insert(client_addr, new_tok) {
                if old_tok != new_tok {
                    if let Some(old_sess) = self.sessions_by_token.get_mut(&old_tok) {
                        if old_sess.state == HandshakeState::Ready {
                            let bye_delay = rand_duration_range_ms(
                                CLIENT_MBB_DELAYED_BYE_MIN_MS,
                                CLIENT_MBB_DELAYED_BYE_MAX_MS,
                            );
                            log(
                            self.worker_id,
                            &format!(
                                "MBB 0ms rotation complete client={} old_sport={} -> new_sport={} (delayed BYE in {:.1}s)",
                                client_addr,
                                old_sess.local_port,
                                new_port,
                                bye_delay.as_secs_f64()
                            ),
                        );
                            if let Some(ref th) = self.telemetry {
                                th.record_mbb_rotation(format!(
                                    "{}->{}",
                                    old_sess.local_port, new_port
                                ));
                            }
                            old_sess.ka_txid = None;
                            old_sess.ka_pkt.clear();
                            old_sess.ka_retries = 0;
                            old_sess.ka_rto_at = None;
                            old_sess.state = HandshakeState::DrainingBeforeBye(now + bye_delay);
                        }
                    }
                }
            }
        }

        // Jittered sub-second reconnect when server sends graceful BYE/close_notify (e.g. SIGTERM restart).
        // Waits 80..350ms before transmitting fresh STUN to clear systemd restart bind gap (zero ICMP bounce!).
        for (old_tok, client_addr) in graceful_reconnects {
            if self.token_by_client.get(&client_addr) == Some(&old_tok) {
                self.token_by_client.remove(&client_addr);
                self.cancel_hunts_for_client(client_addr);
                cancel_standby_for_client(
                    client_addr,
                    &mut self.standby_by_client,
                    &mut self.sessions_by_token,
                    &mut self.dtls_buf,
                    now,
                );
                let jitter = rand_duration_range_ms(
                    CLIENT_GRACEFUL_RECONNECT_MIN_MS,
                    CLIENT_GRACEFUL_RECONNECT_MAX_MS,
                );
                log(
                self.worker_id,
                &format!(
                    "peer sent graceful BYE/close_notify on active client={} -> fast-reconnecting in {}ms",
                    client_addr,
                    jitter.as_millis()
                ),
            );
                if let Some(ref th) = self.telemetry {
                    th.record_graceful_reconnect(format!("jitter_ms={}", jitter.as_millis()));
                }
                self.pending_reconnects
                    .entry(client_addr)
                    .or_insert_with(|| PendingReconnect {
                        at: now + jitter,
                        pending: VecDeque::with_capacity(32),
                        pending_bytes: 0,
                    });
            }
        }
    }
}
