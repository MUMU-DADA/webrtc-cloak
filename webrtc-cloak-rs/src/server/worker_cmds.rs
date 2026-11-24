//! 服务端跨 worker 迁移挑战、会话搬移与后端套接字交接指令处理。

use super::handlers::{
    arm_or_reuse_migration_challenge, deliver_uplink_payload, process_ready_srtp,
    send_encrypted_handover_ack, send_encrypted_path_challenge, send_encrypted_path_confirm,
};
use super::registry::WorkerCmd;
use super::worker::ServerWorker;
use super::{
    alloc_token, deregister_backend, log, record_server_media_bytes, BackendPipe, ServerState,
    MAX_FORWARD_HOPS, OLD_PEER_DRAIN_TTL,
};
use crate::protocol::{compute_handover_proof, SrtpFrame};
use mio::net::UdpSocket as MioUdpSocket;
use mio::Interest;
use std::time::Instant;
use subtle::ConstantTimeEq;

impl ServerWorker {
    pub(super) fn drain_worker_cmds(&mut self, now: Instant) {
    // Drain cross-worker V4 control commands (0 lock on SRTP hot path!)
    self.cmd_buf.clear();
    self.registry.drain_cmds(self.worker_id, &mut self.cmd_buf);
    for cmd in self.cmd_buf.drain(..) {
        match cmd {
            WorkerCmd::CrossWorkerChallengeRequest {
                ufrag,
                cand_addr,
                cand_worker,
                stun_resp,
            } => {
                if let Some(&tok) = self.token_by_ufrag.get(&ufrag) {
                    if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                        if sess.state == ServerState::Ready {
                            if let Some((nonce, epoch)) = arm_or_reuse_migration_challenge(
                                sess,
                                cand_addr,
                                cand_worker,
                                now,
                            ) {
                                self.audit.record(1, &stun_resp);
                                let _ = self.listen_sock.send_to(&stun_resp, cand_addr);
                                send_encrypted_path_challenge(
                                    sess,
                                    cand_addr,
                                    nonce,
                                    epoch,
                                    &self.listen_sock,
                                    &mut self.audit,
                                );
                            }
                        }
                    }
                }
            }
            WorkerCmd::CrossWorkerChallengeVerify {
                ufrag,
                cand_addr,
                cand_worker,
                pkt,
            } => {
                let Some(&tok) = self.token_by_ufrag.get(&ufrag) else {
                    // Session may have just migrated to `cand_worker` (<20us race): bounce packet there!
                    if let Some(meta) = self.registry.lookup_ufrag(&ufrag) {
                        if meta.worker_id == cand_worker {
                            self.registry.send_cmd(
                                cand_worker,
                                WorkerCmd::ReprocessSrtp {
                                    peer_addr: cand_addr,
                                    pkt,
                                },
                            );
                        }
                    }
                    continue;
                };
                let mut should_move = false;
                let mut early_data_len: Option<usize> = None;
                if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                    if sess.state == ServerState::Ready {
                        let has_slot = sess.pending_migrations.iter().any(|m| {
                            m.cand_addr == cand_addr
                                && m.cand_worker == cand_worker
                                && now <= m.expires_at
                        });
                        if has_slot {
                            match sess
                                .cipher
                                .as_mut()
                                .and_then(|c| c.unwrap_into_ex(&pkt, &mut self.wbuf))
                            {
                                Some(SrtpFrame::PathChallenge(pn))
                                    if pn == 17 && self.wbuf[0] == 0x02 =>
                                {
                                    sess.rx_pkts += 1;
                                    let got_nonce: [u8; 8] = self.wbuf[1..9].try_into().unwrap();
                                    let got_epoch =
                                        u64::from_be_bytes(self.wbuf[9..17].try_into().unwrap());
                                    let matched = sess
                                        .pending_migrations
                                        .iter()
                                        .find(|m| {
                                            m.cand_addr == cand_addr
                                                && m.cand_worker == cand_worker
                                                && now <= m.expires_at
                                                && got_epoch == m.epoch
                                                && bool::from(got_nonce.ct_eq(&m.nonce))
                                        })
                                        .copied();
                                    if let Some(mig) = matched {
                                        // P1-3: Clean any prior old_peer_addr before overwriting!
                                        if let Some((prev_old, _)) = sess.old_peer_addr.take() {
                                            if prev_old != sess.peer_addr
                                                && self.token_by_peer.get(&prev_old) == Some(&tok)
                                            {
                                                self.token_by_peer.remove(&prev_old);
                                            }
                                        }
                                        let old_peer = sess.peer_addr;
                                        sess.path_epoch = mig.epoch;
                                        sess.old_peer_addr =
                                            Some((old_peer, now + OLD_PEER_DRAIN_TTL));
                                        sess.peer_addr = cand_addr;
                                        for m in sess.pending_migrations.drain(..) {
                                            if self.local_mig_pending
                                                .get(&m.cand_addr)
                                                .map(|&(t, _)| t)
                                                == Some(tok)
                                            {
                                                self.local_mig_pending.remove(&m.cand_addr);
                                            }
                                        }
                                        sess.last_peer_rx = now;
                                        send_encrypted_path_confirm(
                                            sess,
                                            cand_addr,
                                            got_nonce,
                                            &self.listen_sock,
                                            &mut self.audit,
                                        );
                                        should_move = true;
                                    }
                                }
                                Some(SrtpFrame::Data(pn)) => {
                                    sess.last_data_active = now;
                                    sess.last_peer_rx = now;
                                    early_data_len = Some(pn);
                                }
                                _ => {
                                    sess.auth_drops += 1;
                                }
                            }
                        }
                    }
                }
                if let Some(pn) = early_data_len {
                    let ok = deliver_uplink_payload(
                        self.worker_id,
                        tok,
                        &self.wbuf[..pn],
                        MAX_FORWARD_HOPS,
                        &mut self.sessions_by_token,
                        &self.poll,
                        self.cfg.backend_addr,
                        &self.registry,
                    );
                    if ok {
                        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                            sess.rx_pkts += 1;
                            sess.rx_bytes += pn as u64;
                            record_server_media_bytes(sess, now, pn as u64);
                        }
                    }
                }
                if should_move {
                    if let Some(mut sess) = self.sessions_by_token.remove(&tok) {
                        deregister_backend(&self.poll, &mut sess.backend);
                        self.token_by_ufrag.remove(&sess.username);
                        if let Some((old_p, _)) = sess.old_peer_addr.take() {
                            if self.token_by_peer.get(&old_p) == Some(&tok) {
                                self.token_by_peer.remove(&old_p);
                            }
                        }
                        if self.token_by_peer.get(&sess.peer_addr) == Some(&tok) {
                            self.token_by_peer.remove(&sess.peer_addr);
                        }
                        if let Some(mk) = sess.mi_key_mig {
                            self.registry.register_session(
                                &sess.username,
                                cand_worker,
                                mk,
                                sess.tie_breaker,
                            );
                        }
                        log(
                            self.worker_id,
                            &format!(
                                "ICE 1-RTT MIGRATION (cross-worker {}->{}) ufrag={} -> {} epoch={} backend_sport={}",
                                self.worker_id, cand_worker, sess.username, sess.peer_addr, sess.path_epoch, sess.backend_lport
                            ),
                        );
                        if let Some(ref th) = self.telemetry {
                            th.record_migration_1rtt(format!(
                                "ufrag={} cross_worker={}->{} backend_sport={}",
                                sess.username, self.worker_id, cand_worker, sess.backend_lport
                            ));
                        }
                        self.registry.send_cmd(
                            cand_worker,
                            WorkerCmd::MigrateInstall {
                                sess: Box::new(sess),
                            },
                        );
                    }
                }
            }
            WorkerCmd::MigrateInstall { mut sess } => {
                let new_tok = alloc_token(&mut self.next_token_id);
                if let BackendPipe::Owned(ref mut sock) = sess.backend {
                    let _ = self.poll.registry().register(sock, new_tok, Interest::READABLE);
                }
                self.cross_worker_pending.remove(&sess.peer_addr);
                // P1-3: Only register verified `sess.peer_addr` (do not insert foreign old_p!)
                sess.old_peer_addr = None;
                self.token_by_peer.insert(sess.peer_addr, new_tok);
                self.token_by_ufrag.insert(sess.username.clone(), new_tok);
                self.sessions_by_token.insert(new_tok, *sess);
            }
            WorkerCmd::HandoverExtract {
                old_ufrag,
                new_ufrag,
                new_session_key,
                proof,
                target_worker,
            } => {
                let mut ok = false;
                let mut extracted: Option<(MioUdpSocket, u16)> = None;
                if let Some(&old_tok) = self.token_by_ufrag.get(&old_ufrag) {
                    if let Some(old_s) = self.sessions_by_token.get_mut(&old_tok) {
                        if let Some(old_key) = old_s.session_key {
                            let expected = compute_handover_proof(&old_key, &new_session_key);
                            if bool::from(proof.ct_eq(&expected)) {
                                if old_s.handed_over_to.as_deref() == Some(new_ufrag.as_str()) {
                                    ok = true;
                                } else if old_s.handed_over_to.is_none() {
                                    ok = true;
                                    old_s.handed_over_to = Some(new_ufrag.clone());
                                    let lport = old_s.backend_lport;
                                    let prev = std::mem::replace(
                                        &mut old_s.backend,
                                        BackendPipe::ForwardRemote {
                                            target_worker,
                                            target_ufrag: new_ufrag.clone(),
                                        },
                                    );
                                    match prev {
                                        BackendPipe::Owned(mut sock) => {
                                            let _ = self.poll.registry().deregister(&mut sock);
                                            extracted = Some((sock, lport));
                                        }
                                        // P1-1: Even if Unbound, old_s stays ForwardRemote!
                                        BackendPipe::Unbound => {}
                                        other => {
                                            old_s.backend = other;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some((sock, lport)) = extracted {
                    self.registry.send_cmd(
                        target_worker,
                        WorkerCmd::HandoverInstall {
                            new_ufrag,
                            backend_sock: sock,
                            backend_lport: lport,
                        },
                    );
                } else {
                    self.registry.send_cmd(
                        target_worker,
                        WorkerCmd::HandoverAckOnly { new_ufrag, ok },
                    );
                }
            }
            WorkerCmd::HandoverInstall {
                new_ufrag,
                mut backend_sock,
                backend_lport,
            } => {
                if let Some(&new_tok) = self.token_by_ufrag.get(&new_ufrag) {
                    if let Some(new_s) = self.sessions_by_token.get_mut(&new_tok) {
                        if new_s.state == ServerState::Ready {
                            deregister_backend(&self.poll, &mut new_s.backend);
                            if self.poll
                                .registry()
                                .register(&mut backend_sock, new_tok, Interest::READABLE)
                                .is_ok()
                            {
                                new_s.backend = BackendPipe::Owned(backend_sock);
                                new_s.backend_lport = backend_lport;
                                log(
                                    self.worker_id,
                                    &format!(
                                        "MBB HANDOVER (cross-worker) -> {} backend_sport={} (0 port change!)",
                                        new_ufrag, backend_lport
                                    ),
                                );
                                if let Some(ref th) = self.telemetry {
                                    th.record_mbb_rotation(format!(
                                        "cross_worker->{} backend_sport={}",
                                        new_ufrag, backend_lport
                                    ));
                                }
                                send_encrypted_handover_ack(
                                    new_s,
                                    true,
                                    &self.listen_sock,
                                    &mut self.audit,
                                );
                            }
                        }
                    }
                }
            }
            WorkerCmd::HandoverAckOnly { new_ufrag, ok } => {
                if let Some(&new_tok) = self.token_by_ufrag.get(&new_ufrag) {
                    if let Some(new_s) = self.sessions_by_token.get_mut(&new_tok) {
                        send_encrypted_handover_ack(new_s, ok, &self.listen_sock, &mut self.audit);
                    }
                }
            }
            WorkerCmd::DrainUplinkForward {
                target_ufrag,
                payload,
                hops_left,
            } => {
                if let Some(&t_tok) = self.token_by_ufrag.get(&target_ufrag) {
                    let _ = deliver_uplink_payload(
                        self.worker_id,
                        t_tok,
                        &payload,
                        hops_left,
                        &mut self.sessions_by_token,
                        &self.poll,
                        self.cfg.backend_addr,
                        &self.registry,
                    );
                } else if hops_left > 0 {
                    if let Some(meta) = self.registry.lookup_ufrag(&target_ufrag) {
                        if meta.worker_id != self.worker_id {
                            self.registry.send_cmd(
                                meta.worker_id,
                                WorkerCmd::DrainUplinkForward {
                                    target_ufrag,
                                    payload,
                                    hops_left: hops_left - 1,
                                },
                            );
                        }
                    }
                }
            }
            WorkerCmd::ReprocessSrtp { peer_addr, pkt } => {
                if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
                    process_ready_srtp(
                        self.worker_id,
                        tok,
                        peer_addr,
                        &pkt,
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
        }
    }
    }
}
