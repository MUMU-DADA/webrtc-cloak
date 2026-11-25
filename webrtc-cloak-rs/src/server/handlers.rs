//! 服务端 DTLS 握手推进、优雅关闭、SRTP 解密与 V4 迁移/交接处理。

use super::registry::{SharedV4Registry, WorkerCmd};
use super::{
    deregister_backend, ensure_owned_backend, log, record_server_media_bytes, BackendPipe,
    PendingPathMigration, ServerConfig, ServerSession, ServerState, WireAudit,
    MAX_CHALLENGES_PER_SEC, MAX_FORWARD_HOPS, MIGRATION_CHALLENGE_TTL, OLD_PEER_DRAIN_TTL,
    SERVER_SRTCP_INIT_MAX_MS, SERVER_SRTCP_INIT_MIN_MS,
};
use crate::constants::{
    CTRL_FRAME_BUF_LEN, HANDOVER_MIN_REQ_LEN, HANDOVER_OP_ACK, HANDOVER_OP_REQ, HANDOVER_PROOF_LEN,
    PATH_CHALLENGE_OP_CONFIRM, PATH_CHALLENGE_OP_REQ, PATH_CHALLENGE_OP_RESP,
    PATH_CHALLENGE_PAYLOAD_LEN, PATH_CONFIRM_PAYLOAD_LEN, PROBE_IO_BUF_LEN, SRTP_HANDOVER_MAGIC,
    SRTP_PATH_CHALLENGE_MAGIC, STUN_MAX_USERNAME_LEN, TRICKLE_WINDOW_15S_SECS,
};
use crate::protocol::{
    combine_session_key, compute_handover_proof, derive_ice_migration_key,
    extract_dtls_server_hello_suite, fill_random, rand_duration_range_ms, resolve_srtp_suite,
    RollingByteWindow, SrtpCloakCipher, SrtpFrame,
};
use crate::telemetry::TelemetryHub;
use dimpl::{Output as DtlsOutput, ProtocolVersion};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Interest, Poll, Token};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// 单会话最多同时保留的未验证迁移候选地址槽位数，隔离伪造源地址竞争攻击。
const MAX_PENDING_MIGRATIONS_PER_SESSION: usize = 4;

/// P0-2 & P0-4: Rate-limited, idempotent 4-slot candidate challenge allocator.
/// Reuses exact `(nonce, epoch)` if `cand_addr` already has an unexpired slot so reordered STUN
/// retries NEVER invalidate an in-flight challenge!
pub(super) fn arm_or_reuse_migration_challenge(
    sess: &mut ServerSession,
    cand_addr: SocketAddr,
    cand_worker: usize,
    now: Instant,
) -> Option<([u8; 8], u64)> {
    if now.duration_since(sess.mig_challenge_win) >= Duration::from_secs(1) {
        sess.mig_challenge_win = now;
        sess.mig_challenge_cnt = 0;
    }
    if sess.mig_challenge_cnt >= MAX_CHALLENGES_PER_SEC {
        return None;
    }
    sess.mig_challenge_cnt = sess.mig_challenge_cnt.saturating_add(1);

    sess.pending_migrations.retain(|m| now <= m.expires_at);
    if let Some(existing) = sess
        .pending_migrations
        .iter_mut()
        .find(|m| m.cand_addr == cand_addr)
    {
        existing.cand_worker = cand_worker;
        existing.expires_at = now + MIGRATION_CHALLENGE_TTL;
        return Some((existing.nonce, existing.epoch));
    }

    if sess.pending_migrations.len() >= MAX_PENDING_MIGRATIONS_PER_SESSION {
        sess.pending_migrations.remove(0);
    }
    let mut nonce = [0u8; 8];
    fill_random(&mut nonce);
    let epoch = sess.path_epoch.saturating_add(1);
    sess.pending_migrations.push(PendingPathMigration {
        cand_addr,
        cand_worker,
        nonce,
        epoch,
        expires_at: now + MIGRATION_CHALLENGE_TTL,
    });
    Some((nonce, epoch))
}

/// P0-4 + P1-4: Unpadded 57B SRTP 0xFFFD challenge (`64B STUN + 57B SRTP = 121B <= 1.32x`)
/// + increments `sess.tx_pkts` for strict RTCP causality!
pub(super) fn send_encrypted_path_challenge(
    sess: &mut ServerSession,
    target_addr: SocketAddr,
    nonce: [u8; 8],
    epoch: u64,
    listen_sock: &MioUdpSocket,
    audit: &mut WireAudit,
) {
    let mut payload = [0u8; PATH_CHALLENGE_PAYLOAD_LEN];
    payload[0] = PATH_CHALLENGE_OP_REQ; // Server -> Client challenge
    payload[1..9].copy_from_slice(&nonce);
    payload[9..17].copy_from_slice(&epoch.to_be_bytes());
    let mut pbuf = [0u8; CTRL_FRAME_BUF_LEN];
    if let Some(ref mut cipher) = sess.cipher {
        if let Some(wn) =
            cipher.wrap_control_unpadded_into(SRTP_PATH_CHALLENGE_MAGIC, &payload, &mut pbuf)
        {
            audit.record(1, &pbuf[..wn]);
            if listen_sock.send_to(&pbuf[..wn], target_addr).is_ok() {
                sess.tx_pkts += 1;
            }
        }
    }
}

pub(super) fn send_encrypted_path_confirm(
    sess: &mut ServerSession,
    target_addr: SocketAddr,
    nonce: [u8; 8],
    listen_sock: &MioUdpSocket,
    audit: &mut WireAudit,
) {
    let mut payload = [0u8; PATH_CONFIRM_PAYLOAD_LEN];
    payload[0] = PATH_CHALLENGE_OP_CONFIRM; // Server -> Client confirm
    payload[1..9].copy_from_slice(&nonce);
    let mut pbuf = [0u8; CTRL_FRAME_BUF_LEN];
    if let Some(ref mut cipher) = sess.cipher {
        if let Some(wn) = cipher.wrap_control_into(SRTP_PATH_CHALLENGE_MAGIC, &payload, &mut pbuf) {
            audit.record(1, &pbuf[..wn]);
            if listen_sock.send_to(&pbuf[..wn], target_addr).is_ok() {
                sess.tx_pkts += 1;
            }
        }
    }
}

pub(super) fn send_encrypted_handover_ack(
    sess: &mut ServerSession,
    ok: bool,
    listen_sock: &MioUdpSocket,
    audit: &mut WireAudit,
) {
    let payload = [HANDOVER_OP_ACK, if ok { 0x01 } else { 0x00 }];
    let mut pbuf = [0u8; CTRL_FRAME_BUF_LEN];
    if let Some(ref mut cipher) = sess.cipher {
        if let Some(wn) = cipher.wrap_control_into(SRTP_HANDOVER_MAGIC, &payload, &mut pbuf) {
            audit.record(1, &pbuf[..wn]);
            if listen_sock.send_to(&pbuf[..wn], sess.peer_addr).is_ok() {
                sess.tx_pkts += 1;
            }
        }
    }
}

/// P1-1: Deliver decrypted uplink UDP payload following up to `hops_left` chained MBB handovers
/// (`ForwardLocal` -> `ForwardLocal` -> `Owned`/`Unbound` or `ForwardRemote` across workers!).
#[allow(clippy::too_many_arguments)]
pub(super) fn deliver_uplink_payload(
    worker_id: usize,
    start_tok: Token,
    payload: &[u8],
    hops_left: u8,
    sessions_by_token: &mut HashMap<Token, ServerSession>,
    poll: &Poll,
    backend_addr: SocketAddr,
    registry: &SharedV4Registry,
) -> bool {
    let mut cur_tok = start_tok;
    let mut remaining = hops_left;
    loop {
        if let Some(sess) = sessions_by_token.get_mut(&cur_tok) {
            if matches!(sess.backend, BackendPipe::Unbound) {
                let _ = ensure_owned_backend(worker_id, cur_tok, sess, backend_addr, poll);
            }
            match sess.backend {
                BackendPipe::Owned(ref sock) => return sock.send(payload).is_ok(),
                BackendPipe::ForwardLocal {
                    target_tok,
                    ref target_ufrag,
                } => {
                    if remaining == 0 {
                        return false;
                    }
                    remaining -= 1;
                    let tu = target_ufrag.clone();
                    if sessions_by_token.contains_key(&target_tok) {
                        cur_tok = target_tok;
                        continue;
                    }
                    // Target session may have migrated to another worker after handover!
                    if let Some(meta) = registry.lookup_ufrag(&tu) {
                        if meta.worker_id != worker_id {
                            registry.send_cmd(
                                meta.worker_id,
                                WorkerCmd::DrainUplinkForward {
                                    target_ufrag: tu,
                                    payload: payload.to_vec(),
                                    hops_left: remaining,
                                },
                            );
                            return true;
                        }
                    }
                    return false;
                }
                BackendPipe::ForwardRemote {
                    target_worker,
                    ref target_ufrag,
                } => {
                    if remaining == 0 {
                        return false;
                    }
                    let tu = target_ufrag.clone();
                    let dest_worker = registry
                        .lookup_ufrag(&tu)
                        .map(|m| m.worker_id)
                        .unwrap_or(target_worker);
                    registry.send_cmd(
                        dest_worker,
                        WorkerCmd::DrainUplinkForward {
                            target_ufrag: tu,
                            payload: payload.to_vec(),
                            hops_left: remaining - 1,
                        },
                    );
                    return true;
                }
                BackendPipe::Unbound => return false,
            }
        } else {
            return false;
        }
    }
}

/// Returns `(peer_closed, became_ready)`.
#[allow(clippy::too_many_arguments)]
pub(super) fn drain_server_dtls(
    worker_id: usize,
    sess: &mut ServerSession,
    listen_sock: &MioUdpSocket,
    dtls_buf: &mut Vec<u8>,
    cfg: &ServerConfig,
    cpu: &crate::protocol::CpuAccelInfo,
    registry: &SharedV4Registry,
    now: Instant,
    audit: &mut WireAudit,
) -> (bool, bool) {
    let mut connected_now = false;
    let mut peer_closed = false;
    let mut became_ready = false;

    if let Some(ref mut dtls) = sess.dtls {
        loop {
            match dtls.poll_output(dtls_buf) {
                DtlsOutput::Packet(p) => {
                    if let Some(cs) = extract_dtls_server_hello_suite(p) {
                        sess.dtls_suite_id = Some(cs);
                    }
                    audit.record(1, p);
                    let _ = listen_sock.send_to(p, sess.peer_addr);
                }
                DtlsOutput::BufferTooSmall { needed } => {
                    dtls_buf.resize(needed, 0);
                }
                DtlsOutput::Timeout(t) => {
                    sess.dtls_next_timeout = Some(t);
                    break;
                }
                DtlsOutput::KeyingMaterial(km, _profile) => {
                    sess.dtls_km = Some(km.to_vec());
                }
                DtlsOutput::Connected => {
                    connected_now = true;
                }
                DtlsOutput::CloseNotify => {
                    peer_closed = true;
                }
                _ => {}
            }
        }
    }

    if connected_now && sess.state == ServerState::DtlsHandshake {
        let Some(km) = sess.dtls_km.as_deref().filter(|k| !k.is_empty()) else {
            log(
                worker_id,
                &format!(
                    "DTLS Connected without SRTP KeyingMaterial peer={} (Fail-Closed!)",
                    sess.peer_addr
                ),
            );
            return (true, false);
        };
        let is_dtls13 =
            sess.dtls.as_ref().and_then(|d| d.protocol_version()) == Some(ProtocolVersion::DTLS1_3);
        let chosen = resolve_srtp_suite(cfg.cipher_pref, sess.dtls_suite_id, cpu, false);
        let final_key = combine_session_key(&sess.stun_key, Some(km));
        let mi_key_mig = derive_ice_migration_key(&final_key);
        sess.session_key = Some(final_key);
        sess.mi_key_mig = Some(mi_key_mig);
        sess.negotiated_cipher = Some(chosen);
        let mut c = SrtpCloakCipher::new(&final_key, sess.ssrc_s2c, sess.ssrc_c2s, false, chosen);
        c.set_wan_mtu(cfg.wan_mtu);
        c.set_dual_ssrc(is_dtls13);
        sess.cipher = Some(c);
        sess.state = ServerState::Ready;
        sess.ready_at = Some(now);
        sess.last_data_active = now;
        sess.last_peer_rx = now;
        sess.last_active_burst = now;
        sess.rate_15s = RollingByteWindow::new(now, Duration::from_secs(TRICKLE_WINDOW_15S_SECS));
        sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
        sess.next_srtcp_at =
            now + rand_duration_range_ms(SERVER_SRTCP_INIT_MIN_MS, SERVER_SRTCP_INIT_MAX_MS);
        registry.register_session(&sess.username, worker_id, mi_key_mig, sess.tie_breaker);
        became_ready = true;
        log(
            worker_id,
            &format!(
                "DTLS {} (dimpl mutual-cert PFS) OK -> READY peer={} cipher={} dual_ssrc={} backend_sport={} early_srtp={}",
                if is_dtls13 { "1.3" } else { "1.2" },
                sess.peer_addr,
                chosen.name(),
                is_dtls13,
                sess.backend_lport,
                sess.early_srtp.len()
            ),
        );
    }

    (peer_closed, became_ready)
}

pub(super) fn graceful_teardown_server(
    sess: &mut ServerSession,
    listen_sock: &MioUdpSocket,
    dtls_buf: &mut Vec<u8>,
    audit: &mut WireAudit,
) {
    if sess.state == ServerState::Ready {
        let has_rx = sess.rx_pkts > sess.rx_pkts_at_last_rtcp;
        let is_sender = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
        if let Some(ref mut cipher) = sess.cipher {
            let bye = cipher.build_srtcp(has_rx, is_sender, true);
            audit.record(1, &bye);
            let _ = listen_sock.send_to(&bye, sess.peer_addr);
        }
        if let Some(ref mut dtls) = sess.dtls {
            if dtls.close().is_ok() {
                loop {
                    match dtls.poll_output(dtls_buf) {
                        DtlsOutput::Packet(p) => {
                            audit.record(1, p);
                            let _ = listen_sock.send_to(p, sess.peer_addr);
                        }
                        DtlsOutput::BufferTooSmall { needed } => dtls_buf.resize(needed, 0),
                        DtlsOutput::Timeout(_) => break,
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Process a decrypted Ready-state SRTP packet (normal Data, `0xFFFE` Probe, `0xFFFD` PathChallenge
/// response, or `0xFFFC` MBB backend_sock handover) with full multi-worker & chained handover support.
#[allow(clippy::too_many_arguments)]
pub(super) fn process_ready_srtp(
    worker_id: usize,
    tok: Token,
    from_peer: SocketAddr,
    pkt: &[u8],
    sessions_by_token: &mut HashMap<Token, ServerSession>,
    token_by_peer: &mut HashMap<SocketAddr, Token>,
    token_by_ufrag: &mut HashMap<String, Token>,
    local_mig_pending: &mut HashMap<SocketAddr, (Token, Instant)>,
    poll: &Poll,
    listen_sock: &MioUdpSocket,
    cfg: &ServerConfig,
    registry: &SharedV4Registry,
    telemetry: Option<&Arc<TelemetryHub>>,
    wbuf: &mut [u8],
    now: Instant,
    audit: &mut WireAudit,
) {
    let frame = {
        let Some(sess) = sessions_by_token.get_mut(&tok) else {
            return;
        };
        if sess.state != ServerState::Ready {
            return;
        }
        match sess
            .cipher
            .as_mut()
            .and_then(|c| c.unwrap_into_ex(pkt, wbuf))
        {
            Some(f) => f,
            None => {
                sess.auth_drops += 1;
                return;
            }
        }
    };

    match frame {
        SrtpFrame::Data(pn) => {
            let delivered = deliver_uplink_payload(
                worker_id,
                tok,
                &wbuf[..pn],
                MAX_FORWARD_HOPS,
                sessions_by_token,
                poll,
                cfg.backend_addr,
                registry,
            );
            if let Some(sess) = sessions_by_token.get_mut(&tok) {
                sess.last_data_active = now;
                sess.last_peer_rx = now;
                if delivered {
                    sess.rx_pkts += 1;
                    sess.rx_bytes += pn as u64;
                    record_server_media_bytes(sess, now, pn as u64);
                }
            }
        }
        SrtpFrame::Probe(pn) => {
            if let Some(sess) = sessions_by_token.get_mut(&tok) {
                sess.last_data_active = now;
                sess.last_peer_rx = now;
                let target = if sess
                    .pending_migrations
                    .iter()
                    .any(|m| m.cand_addr == from_peer && now <= m.expires_at)
                {
                    from_peer
                } else {
                    sess.peer_addr
                };
                let mut pbuf = [0u8; PROBE_IO_BUF_LEN];
                if let Some(ref mut cipher) = sess.cipher {
                    if let Some(wn) = cipher.wrap_probe_into(&wbuf[..pn], &mut pbuf) {
                        audit.record(1, &pbuf[..wn]);
                        if listen_sock.send_to(&pbuf[..wn], target).is_ok() {
                            sess.rx_pkts += 1;
                            sess.tx_pkts += 1;
                        }
                    }
                }
                record_server_media_bytes(sess, now, (pn as u64) * 2);
            }
        }
        SrtpFrame::PathChallenge(pn) => {
            // V4 1-RTT ICE path reachability response: [0x02 || nonce(8B) || epoch_be(8B)]
            if pn == PATH_CHALLENGE_PAYLOAD_LEN && wbuf[0] == PATH_CHALLENGE_OP_RESP {
                let got_nonce: [u8; 8] = wbuf[1..9].try_into().unwrap();
                let got_epoch = u64::from_be_bytes(wbuf[9..17].try_into().unwrap());
                if let Some(sess) = sessions_by_token.get_mut(&tok) {
                    sess.rx_pkts += 1;
                    sess.last_peer_rx = now;
                    let matched_mig = sess
                        .pending_migrations
                        .iter()
                        .find(|m| {
                            m.cand_addr == from_peer
                                && now <= m.expires_at
                                && got_epoch == m.epoch
                                && bool::from(got_nonce.ct_eq(&m.nonce))
                        })
                        .copied();
                    if let Some(mig) = matched_mig {
                        let old_peer = sess.peer_addr;
                        // Clean previous old_peer_addr & all local_mig_pending entries for this session
                        if let Some((prev_old, _)) = sess.old_peer_addr.take() {
                            if prev_old != old_peer
                                && prev_old != from_peer
                                && token_by_peer.get(&prev_old) == Some(&tok)
                            {
                                token_by_peer.remove(&prev_old);
                            }
                        }
                        for m in sess.pending_migrations.drain(..) {
                            if local_mig_pending.get(&m.cand_addr).map(|&(t, _)| t) == Some(tok) {
                                local_mig_pending.remove(&m.cand_addr);
                            }
                        }
                        sess.path_epoch = mig.epoch;
                        sess.peer_addr = from_peer;
                        if old_peer != from_peer {
                            sess.old_peer_addr = Some((old_peer, now + OLD_PEER_DRAIN_TTL));
                        }
                        // P0-1: ONLY insert `from_peer` into `token_by_peer` AFTER 0xFFFD verification!
                        token_by_peer.insert(from_peer, tok);
                        send_encrypted_path_confirm(sess, from_peer, got_nonce, listen_sock, audit);
                        log(
                            worker_id,
                            &format!(
                                "ICE 1-RTT MIGRATION verified ufrag={} {} -> {} epoch={} backend_sport={} (preserved!)",
                                sess.username, old_peer, from_peer, sess.path_epoch, sess.backend_lport
                            ),
                        );
                        if let Some(th) = telemetry {
                            th.record_migration_1rtt(format!(
                                "ufrag={} backend_sport={}",
                                sess.username, sess.backend_lport
                            ));
                        }
                        return;
                    }
                    // Duplicate response after migration already completed -> idempotently re-confirm
                    if from_peer == sess.peer_addr && got_epoch == sess.path_epoch {
                        send_encrypted_path_confirm(sess, from_peer, got_nonce, listen_sock, audit);
                    }
                }
            }
        }
        SrtpFrame::Handover(pn) => {
            // V4 MBB encrypted backend_sock handover: [0x01 || old_ufrag_len(1B) || old_ufrag || proof(32B)]
            if pn < HANDOVER_MIN_REQ_LEN || wbuf[0] != HANDOVER_OP_REQ {
                return;
            }
            let ulen = wbuf[1] as usize;
            if ulen == 0 || ulen > STUN_MAX_USERNAME_LEN || pn != 2 + ulen + HANDOVER_PROOF_LEN {
                return;
            }
            let Ok(old_ufrag) = std::str::from_utf8(&wbuf[2..2 + ulen]) else {
                return;
            };
            let old_ufrag = old_ufrag.to_string();
            let proof: [u8; HANDOVER_PROOF_LEN] = wbuf[2 + ulen..2 + ulen + HANDOVER_PROOF_LEN]
                .try_into()
                .unwrap();

            let Some((new_ufrag, new_key)) = sessions_by_token.get_mut(&tok).and_then(|s| {
                s.rx_pkts += 1;
                s.last_peer_rx = now;
                s.session_key.map(|k| (s.username.clone(), k))
            }) else {
                return;
            };
            if old_ufrag == new_ufrag {
                return;
            }

            // 1) Check if old session lives on THIS worker (fast atomic local handover!)
            if let Some(&old_tok) = token_by_ufrag.get(&old_ufrag) {
                if old_tok != tok {
                    enum LocalHandoverAction {
                        Reject,
                        IdempotentOk,
                        Transfer(Option<(MioUdpSocket, u16)>),
                    }
                    let action = if let Some(old_s) = sessions_by_token.get_mut(&old_tok) {
                        let verified = old_s
                            .session_key
                            .map(|old_key| {
                                let expected = compute_handover_proof(&old_key, &new_key);
                                bool::from(proof.ct_eq(&expected))
                            })
                            .unwrap_or(false);
                        if !verified {
                            LocalHandoverAction::Reject
                        } else if old_s.handed_over_to.as_deref() == Some(new_ufrag.as_str()) {
                            // P1-1: Idempotent retry of same handover!
                            LocalHandoverAction::IdempotentOk
                        } else if old_s.handed_over_to.is_some() {
                            // P1-1: Already handed over to another session -> block double-handover!
                            LocalHandoverAction::Reject
                        } else {
                            old_s.handed_over_to = Some(new_ufrag.clone());
                            let old_lport = old_s.backend_lport;
                            let prev_pipe = std::mem::replace(
                                &mut old_s.backend,
                                BackendPipe::ForwardLocal {
                                    target_tok: tok,
                                    target_ufrag: new_ufrag.clone(),
                                },
                            );
                            match prev_pipe {
                                BackendPipe::Owned(mut sock) => {
                                    let _ = poll.registry().deregister(&mut sock);
                                    LocalHandoverAction::Transfer(Some((sock, old_lport)))
                                }
                                // P1-1: Even if Unbound, old_s stays ForwardLocal so no dual-socket split-brain!
                                BackendPipe::Unbound => LocalHandoverAction::Transfer(None),
                                other => {
                                    old_s.backend = other;
                                    LocalHandoverAction::Transfer(None)
                                }
                            }
                        }
                    } else {
                        LocalHandoverAction::Reject
                    };

                    if let Some(new_s) = sessions_by_token.get_mut(&tok) {
                        match action {
                            LocalHandoverAction::Reject => {
                                new_s.auth_drops += 1;
                                send_encrypted_handover_ack(new_s, false, listen_sock, audit);
                            }
                            LocalHandoverAction::IdempotentOk => {
                                send_encrypted_handover_ack(new_s, true, listen_sock, audit);
                            }
                            LocalHandoverAction::Transfer(sock_opt) => {
                                if let Some((mut sock, lport)) = sock_opt {
                                    deregister_backend(poll, &mut new_s.backend);
                                    if poll
                                        .registry()
                                        .register(&mut sock, tok, Interest::READABLE)
                                        .is_ok()
                                    {
                                        new_s.backend = BackendPipe::Owned(sock);
                                        new_s.backend_lport = lport;
                                        log(
                                            worker_id,
                                            &format!(
                                                "MBB HANDOVER (local) {} -> {} backend_sport={} (0 port change!)",
                                                old_ufrag, new_ufrag, lport
                                            ),
                                        );
                                        if let Some(th) = telemetry {
                                            th.record_mbb_rotation(format!(
                                                "{}->{} backend_sport={}",
                                                old_ufrag, new_ufrag, lport
                                            ));
                                        }
                                    }
                                }
                                send_encrypted_handover_ack(new_s, true, listen_sock, audit);
                            }
                        }
                    }
                    return;
                }
            }

            // 2) Check if old session lives on ANOTHER worker (Linux SO_REUSEPORT multi-worker!)
            if let Some(meta) = registry.lookup_ufrag(&old_ufrag) {
                if meta.worker_id != worker_id {
                    registry.send_cmd(
                        meta.worker_id,
                        WorkerCmd::HandoverExtract {
                            old_ufrag,
                            new_ufrag,
                            new_session_key: new_key,
                            proof,
                            target_worker: worker_id,
                        },
                    );
                    return;
                }
            }

            // Not found anywhere -> send negative ack cleanly so client does not stall
            if let Some(s) = sessions_by_token.get_mut(&tok) {
                send_encrypted_handover_ack(s, false, listen_sock, audit);
            }
        }
    }
}
