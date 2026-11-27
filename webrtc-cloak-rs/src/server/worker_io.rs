//! 服务端公网入口包分发与后端回包加密转发。

use super::handlers::{
    arm_or_reuse_migration_challenge, drain_server_dtls, graceful_teardown_server,
    handle_ready_srtp_frame, process_ready_srtp, send_encrypted_path_challenge,
};
use super::registry::{TxidCheck, WorkerCmd};
use super::worker::ServerWorker;
use super::{
    alloc_token, cleanup_session_routes, log, record_server_media_bytes, BackendPipe,
    ServerSession, ServerState, MIGRATION_CHALLENGE_TTL, SERVER_SRTCP_INIT_MAX_MS,
    SERVER_SRTCP_INIT_MIN_MS,
};
use crate::constants::{
    outer_udp_hdr_len, CLOSING_DRAIN_MS, DTLS_READY_ALERT_ONLY_GRACE_SECS, MAX_DTLS_RESETS,
    MAX_INNER_UDP_LEN, SRTP_DATA_MIN_WIRE_LEN, STUN_BINDING_REQUEST, TRICKLE_WINDOW_15S_SECS,
};
use crate::protocol::{
    build_stun_success_response, build_stun_success_response_with_key, combine_session_key,
    demux_rfc7983, derive_ice_migration_key, derive_stun_material, new_dtls_instance,
    parse_stun_with_key, peek_stun_request_username, rand_duration_range_ms, resolve_srtp_suite,
    validate_dtls_datagram, PacketKind, RollingByteWindow, SrtpCloakCipher, SrtpFrame,
};
use crate::udp_batch::UdpSendBatch;
use mio::Token;
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 服务端在 DTLS Flight 5 完成前每会话最多缓存的 0-RTT 早到 SRTP 包数。
const EARLY_SRTP_CAP: usize = 32;
/// 服务端未验证迁移候选映射表硬容量上限，防止 OOM。
const MAX_MIG_PENDING_MAP: usize = 4096;

#[inline]
fn flush_server_uplink_batch(
    pending_tok: &mut Option<Token>,
    tx_batch: &mut UdpSendBatch,
    sessions_by_token: &mut HashMap<Token, ServerSession>,
    now: Instant,
) {
    if let Some(tok) = pending_tok.take() {
        if tx_batch.is_empty() {
            return;
        }
        if let Some(sess) = sessions_by_token.get_mut(&tok) {
            let (sent_pkts, sent_bytes) = match sess.backend {
                BackendPipe::Owned(ref sock) => tx_batch.flush_connected(sock),
                _ => {
                    // 清空残留槽位，防止影响后续会话
                    let _ = tx_batch.is_empty();
                    (0, 0)
                }
            };
            if sent_pkts > 0 {
                sess.rx_pkts += sent_pkts as u64;
                sess.rx_bytes += sent_bytes;
                record_server_media_bytes(sess, now, sent_bytes);
            }
        }
    }
}

impl ServerWorker {
    pub(super) fn handle_listen_readable(&mut self, now: Instant) {
        if self.rx_batch.is_some() {
            self.handle_listen_readable_batched(now);
            return;
        }
        loop {
            let (n, peer_addr) = match self.listen_sock.recv_from(&mut self.rbuf) {
                Ok(v) => v,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            self.dispatch_listen_packet(n, peer_addr, now);
        }
    }

    fn handle_listen_readable_batched(&mut self, now: Instant) {
        let Some(mut rx_batch) = self.rx_batch.take() else {
            return;
        };
        let Some(mut tx_batch) = self.tx_batch.take() else {
            self.rx_batch = Some(rx_batch);
            return;
        };

        loop {
            let count = match rx_batch.recv_from(&self.listen_sock) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            let mut pending_tok: Option<Token> = None;

            for i in 0..count {
                let pkt = rx_batch.packet(i);
                let Some(peer_addr) = rx_batch.peer(i) else {
                    continue;
                };
                if pkt.is_empty() {
                    continue;
                }

                // 快路径：已就绪且持有 Owned 后端套接字的 SRTP 数据包，零拷贝解密入批并合并 sendmmsg
                if demux_rfc7983(pkt) == PacketKind::Srtp {
                    if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
                        let fast_ready = self.sessions_by_token.get(&tok).is_some_and(|s| {
                            s.state == ServerState::Ready
                                && matches!(s.backend, BackendPipe::Owned(_))
                        });
                        if fast_ready {
                            if pending_tok != Some(tok) || tx_batch.is_full() {
                                flush_server_uplink_batch(
                                    &mut pending_tok,
                                    &mut tx_batch,
                                    &mut self.sessions_by_token,
                                    now,
                                );
                                pending_tok = Some(tok);
                            }
                            self.audit.record(0, pkt);
                            let frame = {
                                let sess = self.sessions_by_token.get_mut(&tok).unwrap();
                                let slot = tx_batch.next_slot_mut().unwrap();
                                sess.cipher
                                    .as_mut()
                                    .and_then(|c| c.unwrap_into_ex(pkt, slot))
                            };
                            match frame {
                                Some(SrtpFrame::Data(pn)) => {
                                    tx_batch.commit_slot(pn, pn as u64, None);
                                    if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                                        sess.last_data_active = now;
                                        sess.last_peer_rx = now;
                                    }
                                }
                                Some(ctrl_frame) => {
                                    let pn = match ctrl_frame {
                                        SrtpFrame::Data(n)
                                        | SrtpFrame::Probe(n)
                                        | SrtpFrame::PathChallenge(n)
                                        | SrtpFrame::Handover(n) => n,
                                    };
                                    let copy_len = pn.min(self.wbuf.len());
                                    self.wbuf[..copy_len].copy_from_slice(
                                        tx_batch.uncommitted_slot_prefix(copy_len),
                                    );
                                    flush_server_uplink_batch(
                                        &mut pending_tok,
                                        &mut tx_batch,
                                        &mut self.sessions_by_token,
                                        now,
                                    );
                                    handle_ready_srtp_frame(
                                        self.worker_id,
                                        tok,
                                        peer_addr,
                                        ctrl_frame,
                                        &mut self.sessions_by_token,
                                        &mut self.token_by_peer,
                                        &mut self.token_by_ufrag,
                                        &mut self.local_mig_pending,
                                        &self.poll,
                                        &self.listen_sock,
                                        &self.cfg,
                                        &self.registry,
                                        self.telemetry.as_ref(),
                                        &mut self.wbuf,
                                        now,
                                        &mut self.audit,
                                    );
                                }
                                None => {
                                    if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                                        sess.auth_drops += 1;
                                    }
                                }
                            }
                            continue;
                        }
                    }
                }

                // 慢路径（STUN / DTLS / SRTCP / 首包建后端 / 迁移 / 交接）：先按序刷新数据批再复用既有状态机
                flush_server_uplink_batch(
                    &mut pending_tok,
                    &mut tx_batch,
                    &mut self.sessions_by_token,
                    now,
                );
                let len = pkt.len().min(self.rbuf.len());
                self.rbuf[..len].copy_from_slice(&pkt[..len]);
                self.dispatch_listen_packet(len, peer_addr, now);
            }

            flush_server_uplink_batch(
                &mut pending_tok,
                &mut tx_batch,
                &mut self.sessions_by_token,
                now,
            );
        }

        self.rx_batch = Some(rx_batch);
        self.tx_batch = Some(tx_batch);
    }

    fn dispatch_listen_packet(&mut self, n: usize, peer_addr: SocketAddr, now: Instant) {
        let pkt = &self.rbuf[..n];
        self.audit.record(0, pkt);

        match demux_rfc7983(pkt) {
            PacketKind::Stun => {
                // V4 + P0-1 fix: `already_same_peer` strictly checks `s.peer_addr == peer_addr`
                // (NOT old_peer_addr or unverified candidate!) so retries & Addr1->Addr2->Addr1
                // switchbacks always enter the V4 migration path cleanly!
                let mig_meta = peek_stun_request_username(pkt).and_then(|u| {
                    let already_same_peer = self
                        .token_by_peer
                        .get(&peer_addr)
                        .and_then(|t| self.sessions_by_token.get(t))
                        .map(|s| {
                            s.peer_addr == peer_addr
                                && s.username == u
                                && !matches!(s.state, ServerState::Closing(_, _))
                        })
                        .unwrap_or(false);
                    if already_same_peer {
                        None
                    } else {
                        self.registry.lookup_ufrag(u)
                    }
                });

                if let Some(meta) = mig_meta {
                    if let Some(parsed) = parse_stun_with_key(pkt, &self.cfg.psk, &meta.mi_key_mig)
                    {
                        if parsed.msg_type == STUN_BINDING_REQUEST
                            && parsed.authenticated
                            && parsed.use_candidate
                            && parsed.tie_breaker == Some(meta.tie_breaker)
                        {
                            let uname = parsed.username.unwrap_or_default();
                            let txid_status = {
                                let mut cache = self.seen_txids.lock().unwrap();
                                cache.check(parsed.txid, peer_addr, now, true)
                            };
                            match txid_status {
                                TxidCheck::Rejected => {
                                    self.unauth_drops += 1;
                                    return;
                                }
                                TxidCheck::Retransmit(buf, len) => {
                                    let reply = &buf[..len as usize];
                                    if meta.worker_id == self.worker_id {
                                        if let Some(&tok) = self.token_by_ufrag.get(&uname) {
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                if let Some((nonce, epoch)) =
                                                    arm_or_reuse_migration_challenge(
                                                        sess,
                                                        peer_addr,
                                                        self.worker_id,
                                                        now,
                                                    )
                                                {
                                                    self.audit.record(1, reply);
                                                    let _ =
                                                        self.listen_sock.send_to(reply, peer_addr);
                                                    send_encrypted_path_challenge(
                                                        sess,
                                                        peer_addr,
                                                        nonce,
                                                        epoch,
                                                        &self.listen_sock,
                                                        &mut self.audit,
                                                    );
                                                }
                                            }
                                        }
                                    } else {
                                        // P2-2: Symmetric cross-worker retransmit re-triggers idempotent challenge
                                        self.registry.send_cmd(
                                            meta.worker_id,
                                            WorkerCmd::CrossWorkerChallengeRequest {
                                                ufrag: uname,
                                                cand_addr: peer_addr,
                                                cand_worker: self.worker_id,
                                                stun_resp: reply.to_vec(),
                                            },
                                        );
                                    }
                                    return;
                                }
                                TxidCheck::Fresh => {}
                            }

                            let resp = build_stun_success_response_with_key(
                                &parsed.txid,
                                peer_addr,
                                &meta.mi_key_mig,
                            );
                            {
                                let mut cache = self.seen_txids.lock().unwrap();
                                cache.record(parsed.txid, peer_addr, now, &resp);
                            }

                            if meta.worker_id == self.worker_id {
                                // P0-1 & P0-2 & P0-4: Same-worker migration uses bounded `self.local_mig_pending`
                                // (NEVER touches `self.token_by_peer` before 0xFFFD proof!) + idempotent nonce + rate limit!
                                if self.local_mig_pending.len() >= MAX_MIG_PENDING_MAP {
                                    self.local_mig_pending.retain(|_, (_, e)| now <= *e);
                                    if self.local_mig_pending.len() >= MAX_MIG_PENDING_MAP {
                                        self.unauth_drops += 1;
                                        return;
                                    }
                                }
                                if let Some(&tok) = self.token_by_ufrag.get(&uname) {
                                    if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                                        if sess.state == ServerState::Ready {
                                            if let Some((nonce, epoch)) =
                                                arm_or_reuse_migration_challenge(
                                                    sess,
                                                    peer_addr,
                                                    self.worker_id,
                                                    now,
                                                )
                                            {
                                                self.local_mig_pending.insert(
                                                    peer_addr,
                                                    (tok, now + MIGRATION_CHALLENGE_TTL),
                                                );
                                                self.audit.record(1, &resp);
                                                let _ = self.listen_sock.send_to(&resp, peer_addr);
                                                send_encrypted_path_challenge(
                                                    sess,
                                                    peer_addr,
                                                    nonce,
                                                    epoch,
                                                    &self.listen_sock,
                                                    &mut self.audit,
                                                );
                                            }
                                            return;
                                        }
                                    }
                                }
                            } else {
                                // P0-4: Bounded `self.cross_worker_pending`
                                if self.cross_worker_pending.len() >= MAX_MIG_PENDING_MAP {
                                    self.cross_worker_pending.retain(|_, (_, _, e)| now <= *e);
                                    if self.cross_worker_pending.len() >= MAX_MIG_PENDING_MAP {
                                        self.unauth_drops += 1;
                                        return;
                                    }
                                }
                                self.cross_worker_pending.insert(
                                    peer_addr,
                                    (uname.clone(), meta.worker_id, now + MIGRATION_CHALLENGE_TTL),
                                );
                                self.registry.send_cmd(
                                    meta.worker_id,
                                    WorkerCmd::CrossWorkerChallengeRequest {
                                        ufrag: uname,
                                        cand_addr: peer_addr,
                                        cand_worker: self.worker_id,
                                        stun_resp: resp,
                                    },
                                );
                                return;
                            }
                        }
                    }
                    // Existing active ufrag from another peer MUST pass mi_key_mig; reject global PSK hijack!
                    self.unauth_drops += 1;
                    return;
                }

                let parsed = match parse_stun_with_key(pkt, &self.cfg.psk, &self.stun_mi_key) {
                    Some(p) if p.msg_type == STUN_BINDING_REQUEST && p.authenticated => p,
                    _ => {
                        self.unauth_drops += 1;
                        return;
                    }
                };

                let uname = parsed.username.unwrap_or_default();
                let same_active = self
                    .token_by_peer
                    .get(&peer_addr)
                    .and_then(|tok| self.sessions_by_token.get(tok))
                    .map(|s| {
                        s.peer_addr == peer_addr
                            && s.username == uname
                            && !matches!(s.state, ServerState::Closing(_, _))
                    })
                    .unwrap_or(false);

                let txid_status = {
                    let mut cache = self.seen_txids.lock().unwrap();
                    cache.check(parsed.txid, peer_addr, now, same_active)
                };

                match txid_status {
                    TxidCheck::Rejected => {
                        self.unauth_drops += 1;
                        return;
                    }
                    TxidCheck::Retransmit(buf, len) => {
                        let reply = &buf[..len as usize];
                        self.audit.record(1, reply);
                        let _ = self.listen_sock.send_to(reply, peer_addr);
                        if same_active {
                            if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
                                if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                                    sess.last_peer_rx = now;
                                }
                            }
                        }
                        return;
                    }
                    TxidCheck::Fresh => {}
                }

                if same_active {
                    if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
                        let resp =
                            build_stun_success_response(&parsed.txid, peer_addr, &self.cfg.psk);
                        {
                            let mut cache = self.seen_txids.lock().unwrap();
                            cache.record(parsed.txid, peer_addr, now, &resp);
                        }
                        self.audit.record(1, &resp);
                        let _ = self.listen_sock.send_to(&resp, peer_addr);
                        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                            sess.keepalives += 1;
                            sess.last_peer_rx = now;
                        }
                        return;
                    }
                }

                // NEW-M-01: Reject orphan STUN keepalives (without USE-CANDIDATE)
                if !parsed.use_candidate {
                    self.unauth_drops += 1;
                    return;
                }

                // P0-3: Reject duplicate ufrag hijacking an active/handshaking session on another peer!
                let same_peer_rekey_same_ufrag = self
                    .token_by_peer
                    .get(&peer_addr)
                    .and_then(|t| self.sessions_by_token.get(t))
                    .map(|s| s.peer_addr == peer_addr && s.username == uname)
                    .unwrap_or(false);
                if !same_peer_rekey_same_ufrag
                    && (self.token_by_ufrag.contains_key(&uname)
                        || self.registry.lookup_ufrag(&uname).is_some())
                {
                    self.unauth_drops += 1;
                    return;
                }

                // P0-1 fix: Re-key ONLY if `old.peer_addr == peer_addr`!
                // If `peer_addr` was only a draining `old_peer_addr`, detach that drain key cleanly
                // WITHOUT destroying the live migrated session!
                if let Some(&old_tok) = self.token_by_peer.get(&peer_addr) {
                    let is_exact_primary_peer = self
                        .sessions_by_token
                        .get(&old_tok)
                        .map(|s| s.peer_addr == peer_addr)
                        .unwrap_or(false);
                    if is_exact_primary_peer {
                        if let Some(mut old) = self.sessions_by_token.remove(&old_tok) {
                            self.closed_tx_bytes =
                                self.closed_tx_bytes.saturating_add(old.tx_bytes);
                            self.closed_rx_bytes =
                                self.closed_rx_bytes.saturating_add(old.rx_bytes);
                            self.closed_tx_pkts = self.closed_tx_pkts.saturating_add(old.tx_pkts);
                            self.closed_rx_pkts = self.closed_rx_pkts.saturating_add(old.rx_pkts);
                            self.closed_auth_drops =
                                self.closed_auth_drops.saturating_add(old.auth_drops);
                            cleanup_session_routes(
                                self.worker_id,
                                old_tok,
                                &mut old,
                                &self.poll,
                                &mut self.token_by_peer,
                                &mut self.token_by_ufrag,
                                &mut self.local_mig_pending,
                                &self.registry,
                            );
                            log(
                                self.worker_id,
                                &format!(
                                    "REKEY peer={} old_ufrag={} -> new_ufrag={}",
                                    peer_addr, old.username, uname
                                ),
                            );
                        }
                    } else {
                        self.token_by_peer.remove(&peer_addr);
                        if let Some(old) = self.sessions_by_token.get_mut(&old_tok) {
                            if old.old_peer_addr.map(|(p, _)| p) == Some(peer_addr) {
                                old.old_peer_addr = None;
                            }
                        }
                    }
                }

                if self.sessions_by_token.len() >= self.cfg.max_sessions {
                    let expired: Vec<Token> = self
                        .sessions_by_token
                        .iter()
                        .filter(|(_, s)| {
                            matches!(s.state, ServerState::Closing(_, _))
                                || now.duration_since(s.last_data_active) > self.idle_dur
                        })
                        .map(|(&t, _)| t)
                        .collect();
                    for t in expired {
                        if let Some(mut s) = self.sessions_by_token.remove(&t) {
                            self.closed_tx_bytes = self.closed_tx_bytes.saturating_add(s.tx_bytes);
                            self.closed_rx_bytes = self.closed_rx_bytes.saturating_add(s.rx_bytes);
                            self.closed_tx_pkts = self.closed_tx_pkts.saturating_add(s.tx_pkts);
                            self.closed_rx_pkts = self.closed_rx_pkts.saturating_add(s.rx_pkts);
                            self.closed_auth_drops =
                                self.closed_auth_drops.saturating_add(s.auth_drops);
                            graceful_teardown_server(
                                &mut s,
                                &self.listen_sock,
                                &mut self.dtls_buf,
                                &mut self.audit,
                            );
                            cleanup_session_routes(
                                self.worker_id,
                                t,
                                &mut s,
                                &self.poll,
                                &mut self.token_by_peer,
                                &mut self.token_by_ufrag,
                                &mut self.local_mig_pending,
                                &self.registry,
                            );
                        }
                    }
                    if self.sessions_by_token.len() >= self.cfg.max_sessions {
                        log(
                            self.worker_id,
                            &format!(
                                "max_sessions={} reached, rejecting {}",
                                self.cfg.max_sessions, peer_addr
                            ),
                        );
                        return;
                    }
                }

                let (stun_key, s_c2s, s_s2c) =
                    derive_stun_material(&self.cfg.psk, &parsed.txid, &uname);
                let tok = alloc_token(&mut self.next_token_id);
                let tie_breaker = parsed.tie_breaker.unwrap_or([0u8; 8]);

                let (state, dtls_opt, cipher_opt, chosen_opt, ready_at, skey_opt, mkey_opt) =
                    if self.cfg.dtls_required {
                        let cert = self.cert_cache.get(now);
                        let mut dtls = Box::new(new_dtls_instance(
                            self.cfg.dtls_min_version,
                            self.dtls_pool.pick(),
                            cert,
                            now,
                        ));
                        let _ = dtls.handle_timeout(now);
                        (
                            ServerState::DtlsHandshake,
                            Some(dtls),
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                    } else {
                        let chosen =
                            resolve_srtp_suite(self.cfg.cipher_pref, None, &self.cpu, true);
                        let final_key = combine_session_key(&stun_key, None);
                        let mk = derive_ice_migration_key(&final_key);
                        let mut c = SrtpCloakCipher::new(&final_key, s_s2c, s_c2s, false, chosen);
                        c.set_wan_mtu_for(
                            self.cfg.wan_mtu,
                            outer_udp_hdr_len(self.cfg.listen_addr),
                        );
                        self.registry
                            .register_session(&uname, self.worker_id, mk, tie_breaker);
                        (
                            ServerState::Ready,
                            None,
                            Some(c),
                            Some(chosen),
                            Some(now),
                            Some(final_key),
                            Some(mk),
                        )
                    };

                let resp = build_stun_success_response(&parsed.txid, peer_addr, &self.cfg.psk);
                {
                    let mut cache = self.seen_txids.lock().unwrap();
                    cache.record(parsed.txid, peer_addr, now, &resp);
                }

                log(
                        self.worker_id,
                        &format!(
                            "AUTH STUN OK new session peer={} ufrag={} ssrc_rx=0x{:08x} ssrc_tx=0x{:08x}",
                            peer_addr, uname, s_c2s, s_s2c
                        ),
                    );

                let sess = ServerSession {
                    peer_addr,
                    old_peer_addr: None,
                    username: uname.clone(),
                    tie_breaker,
                    backend: BackendPipe::Unbound,
                    backend_lport: 0,
                    handed_over_to: None,
                    state,
                    ready_at,
                    stun_key,
                    session_key: skey_opt,
                    mi_key_mig: mkey_opt,
                    path_epoch: 0,
                    pending_migrations: Vec::new(),
                    mig_challenge_win: now,
                    mig_challenge_cnt: 0,
                    ssrc_c2s: s_c2s,
                    ssrc_s2c: s_s2c,
                    dtls: dtls_opt,
                    dtls_resets: 0,
                    dtls_next_timeout: None,
                    dtls_suite_id: None,
                    dtls_km: None,
                    negotiated_cipher: chosen_opt,
                    cipher: cipher_opt,
                    early_srtp: VecDeque::new(),
                    last_data_active: now,
                    last_peer_rx: now,
                    last_active_burst: now,
                    next_srtcp_at: now
                        + rand_duration_range_ms(
                            SERVER_SRTCP_INIT_MIN_MS,
                            SERVER_SRTCP_INIT_MAX_MS,
                        ),
                    rate_15s: RollingByteWindow::new(
                        now,
                        Duration::from_secs(TRICKLE_WINDOW_15S_SECS),
                    ),
                    rx_pkts: 0,
                    rx_pkts_at_last_rtcp: 0,
                    rx_bytes: 0,
                    tx_pkts: 0,
                    tx_pkts_at_last_rtcp: 0,
                    tx_bytes: 0,
                    keepalives: 0,
                    srtcp_tx: 0,
                    srtcp_rx: 0,
                    auth_drops: 0,
                };
                self.token_by_peer.insert(peer_addr, tok);
                self.token_by_ufrag.insert(uname, tok);
                self.sessions_by_token.insert(tok, sess);

                self.audit.record(1, &resp);
                let _ = self.listen_sock.send_to(&resp, peer_addr);
            }
            PacketKind::Dtls => {
                if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
                    let mut became_ready = false;
                    if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                        // P0-1: Ignore DTLS from draining old_peer_addr so reused NAT ports cannot kill `sess.dtls`!
                        if sess.peer_addr != peer_addr
                            || matches!(sess.state, ServerState::Closing(_, _))
                        {
                            return;
                        }
                        let ready_only_alert = sess.state == ServerState::Ready
                            && (sess.rx_pkts > 0
                                || sess
                                    .ready_at
                                    .map(|r| {
                                        now.duration_since(r)
                                            > Duration::from_secs(DTLS_READY_ALERT_ONLY_GRACE_SECS)
                                    })
                                    .unwrap_or(false));
                        if !validate_dtls_datagram(pkt, ready_only_alert) {
                            sess.auth_drops += 1;
                            return;
                        }
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
                            return;
                        }
                        if dtls_err {
                            sess.auth_drops += 1;
                            if sess.state == ServerState::Ready {
                                sess.dtls = None;
                                sess.dtls_next_timeout = None;
                            } else if sess.state == ServerState::DtlsHandshake
                                && sess.dtls_resets < MAX_DTLS_RESETS
                                && sess.dtls_suite_id.is_none()
                            {
                                sess.dtls_resets += 1;
                                sess.dtls_km = None;
                                let cert = self.cert_cache.get(now);
                                let mut fresh = Box::new(new_dtls_instance(
                                    self.cfg.dtls_min_version,
                                    self.dtls_pool.pick(),
                                    cert,
                                    now,
                                ));
                                let _ = fresh.handle_timeout(now);
                                sess.dtls = Some(fresh);
                                sess.dtls_next_timeout = None;
                            }
                            return;
                        }
                        if sess.state == ServerState::DtlsHandshake {
                            sess.last_peer_rx = now;
                        }
                        let (peer_closed, br) = drain_server_dtls(
                            self.worker_id,
                            sess,
                            &self.listen_sock,
                            &mut self.dtls_buf,
                            &self.cfg,
                            &self.cpu,
                            &self.registry,
                            now,
                            &mut self.audit,
                        );
                        became_ready = br;
                        if peer_closed {
                            sess.state = ServerState::Closing(
                                now + Duration::from_millis(CLOSING_DRAIN_MS),
                                true,
                            );
                        }
                    }
                    if became_ready {
                        let early_pkts: Vec<Vec<u8>> = self
                            .sessions_by_token
                            .get_mut(&tok)
                            .map(|s| {
                                let pkts: Vec<Vec<u8>> = s.early_srtp.drain(..).collect();
                                s.early_srtp.shrink_to_fit();
                                pkts
                            })
                            .unwrap_or_default();
                        for raw in early_pkts {
                            process_ready_srtp(
                                self.worker_id,
                                tok,
                                peer_addr,
                                &raw,
                                &mut self.sessions_by_token,
                                &mut self.token_by_peer,
                                &mut self.token_by_ufrag,
                                &mut self.local_mig_pending,
                                &self.poll,
                                &self.listen_sock,
                                &self.cfg,
                                &self.registry,
                                self.telemetry.as_ref(),
                                &mut self.wbuf,
                                now,
                                &mut self.audit,
                            );
                        }
                    }
                } else {
                    self.unauth_drops += 1;
                }
            }
            PacketKind::Srtcp => {
                if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
                    if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                        if sess.state == ServerState::Ready {
                            if let Some(ref mut cipher) = sess.cipher {
                                if let Some(has_bye) = cipher.verify_srtcp(pkt) {
                                    sess.srtcp_rx += 1;
                                    sess.last_peer_rx = now;
                                    if has_bye {
                                        sess.state = ServerState::Closing(
                                            now + Duration::from_millis(CLOSING_DRAIN_MS),
                                            true,
                                        );
                                    }
                                } else {
                                    sess.auth_drops += 1;
                                }
                            }
                        } else if !matches!(sess.state, ServerState::Closing(_, _)) {
                            sess.auth_drops += 1;
                        }
                    }
                } else {
                    self.unauth_drops += 1;
                }
            }
            PacketKind::Srtp => {
                // 1) Fast path: verified active or draining `self.token_by_peer`
                if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
                    let state = self.sessions_by_token.get(&tok).map(|s| s.state);
                    match state {
                        Some(ServerState::Ready) => {
                            process_ready_srtp(
                                self.worker_id,
                                tok,
                                peer_addr,
                                pkt,
                                &mut self.sessions_by_token,
                                &mut self.token_by_peer,
                                &mut self.token_by_ufrag,
                                &mut self.local_mig_pending,
                                &self.poll,
                                &self.listen_sock,
                                &self.cfg,
                                &self.registry,
                                self.telemetry.as_ref(),
                                &mut self.wbuf,
                                now,
                                &mut self.audit,
                            );
                        }
                        Some(ServerState::DtlsHandshake) => {
                            if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                                if sess.early_srtp.len() < EARLY_SRTP_CAP
                                    && pkt.len() >= SRTP_DATA_MIN_WIRE_LEN
                                    && pkt.len() <= self.max_early_srtp_len
                                {
                                    sess.early_srtp.push_back(pkt.to_vec());
                                }
                            }
                        }
                        _ => {}
                    }
                } else if let Some((tok, exp)) = self.local_mig_pending.get(&peer_addr).copied() {
                    // 2) P0-1: Unverified same-worker 1-RTT migration candidate (SRTP-only fallback!)
                    if now <= exp {
                        process_ready_srtp(
                            self.worker_id,
                            tok,
                            peer_addr,
                            pkt,
                            &mut self.sessions_by_token,
                            &mut self.token_by_peer,
                            &mut self.token_by_ufrag,
                            &mut self.local_mig_pending,
                            &self.poll,
                            &self.listen_sock,
                            &self.cfg,
                            &self.registry,
                            self.telemetry.as_ref(),
                            &mut self.wbuf,
                            now,
                            &mut self.audit,
                        );
                    } else {
                        self.local_mig_pending.remove(&peer_addr);
                        self.unauth_drops += 1;
                    }
                } else if let Some((ufrag, owner_wid, exp)) =
                    self.cross_worker_pending.get(&peer_addr).cloned()
                {
                    // 3) Unverified cross-worker 1-RTT migration candidate
                    if now <= exp {
                        self.registry.send_cmd(
                            owner_wid,
                            WorkerCmd::CrossWorkerChallengeVerify {
                                ufrag,
                                cand_addr: peer_addr,
                                cand_worker: self.worker_id,
                                pkt: pkt.to_vec(),
                            },
                        );
                    } else {
                        self.cross_worker_pending.remove(&peer_addr);
                        self.unauth_drops += 1;
                    }
                } else {
                    self.unauth_drops += 1;
                }
            }
            PacketKind::Unknown => {
                self.unauth_drops += 1;
            }
        }
    }

    pub(super) fn handle_backend_readable(&mut self, tok: Token, now: Instant) {
        if self.rx_batch.is_some() {
            self.handle_backend_readable_batched(tok, now);
            return;
        }
        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            loop {
                let n = match sess.backend {
                    BackendPipe::Owned(ref sock) => match sock.recv(&mut self.rbuf) {
                        Ok(n) => n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    },
                    _ => break,
                };
                let can_tx_downlink = matches!(
                    sess.state,
                    ServerState::Ready | ServerState::Closing(_, true)
                );
                if !can_tx_downlink || n > MAX_INNER_UDP_LEN {
                    continue;
                }
                let mut sent_bytes = 0u64;
                if let Some(ref mut cipher) = sess.cipher {
                    if sess.state == ServerState::Ready {
                        sess.last_data_active = now;
                    }
                    if let Some(wn) = cipher.wrap_into(&self.rbuf[..n], &mut self.wbuf) {
                        self.audit.record(1, &self.wbuf[..wn]);
                        if self
                            .listen_sock
                            .send_to(&self.wbuf[..wn], sess.peer_addr)
                            .is_ok()
                        {
                            sess.tx_pkts += 1;
                            sess.tx_bytes += n as u64;
                            sent_bytes = n as u64;
                        }
                    }
                }
                if sent_bytes > 0 && sess.state == ServerState::Ready {
                    record_server_media_bytes(sess, now, sent_bytes);
                }
            }
        }
    }

    fn handle_backend_readable_batched(&mut self, tok: Token, now: Instant) {
        let Some(mut rx_batch) = self.rx_batch.take() else {
            return;
        };
        let Some(mut tx_batch) = self.tx_batch.take() else {
            self.rx_batch = Some(rx_batch);
            return;
        };

        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            loop {
                let count = match sess.backend {
                    BackendPipe::Owned(ref sock) => match rx_batch.recv_connected(sock) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    },
                    _ => break,
                };
                let can_tx_downlink = matches!(
                    sess.state,
                    ServerState::Ready | ServerState::Closing(_, true)
                );
                if !can_tx_downlink {
                    continue;
                }
                let peer_addr = sess.peer_addr;
                let is_ready = sess.state == ServerState::Ready;
                for i in 0..count {
                    let pkt = rx_batch.packet(i);
                    if pkt.is_empty() || pkt.len() > MAX_INNER_UDP_LEN {
                        continue;
                    }
                    if tx_batch.is_full() {
                        let (sp, sb) = tx_batch.flush_to(&self.listen_sock);
                        if sp > 0 {
                            sess.tx_pkts += sp as u64;
                            sess.tx_bytes += sb;
                            if is_ready {
                                record_server_media_bytes(sess, now, sb);
                            }
                        }
                    }
                    if let Some(ref mut cipher) = sess.cipher {
                        if is_ready {
                            sess.last_data_active = now;
                        }
                        if let Some(slot) = tx_batch.next_slot_mut() {
                            if let Some(wn) = cipher.wrap_into(pkt, slot) {
                                self.audit.record(1, &slot[..wn]);
                                tx_batch.commit_slot(wn, pkt.len() as u64, Some(peer_addr));
                            }
                        }
                    }
                }
                if !tx_batch.is_empty() {
                    let (sp, sb) = tx_batch.flush_to(&self.listen_sock);
                    if sp > 0 {
                        sess.tx_pkts += sp as u64;
                        sess.tx_bytes += sb;
                        if is_ready {
                            record_server_media_bytes(sess, now, sb);
                        }
                    }
                }
            }
        }

        self.rx_batch = Some(rx_batch);
        self.tx_batch = Some(tx_batch);
    }
}
