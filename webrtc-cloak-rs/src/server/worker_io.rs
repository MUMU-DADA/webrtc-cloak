//! 服务端公网入口包分发与后端回包加密转发。

use super::handlers::{
    arm_or_reuse_migration_challenge, drain_server_dtls, graceful_teardown_server,
    handle_ready_srtp_frame, process_ready_srtp, send_encrypted_path_challenge,
};
use super::registry::{TxidCheck, WorkerCmd};
use super::worker::ServerWorker;
use super::{
    alloc_token, cleanup_session_routes, log, record_server_media_bytes, BackendPipe, ServerHook,
    ServerSession, ServerState, MIGRATION_CHALLENGE_TTL, SERVER_SRTCP_INIT_MAX_MS,
    SERVER_SRTCP_INIT_MIN_MS,
};
use crate::constants::{
    outer_udp_hdr_len, CLOSING_DRAIN_MS, DTLS_READY_ALERT_ONLY_GRACE_SECS, MAX_DTLS_RESETS,
    MAX_INNER_UDP_LEN, SRTP_DATA_MIN_WIRE_LEN, STUN_BINDING_REQUEST, TRICKLE_WINDOW_15S_SECS,
};
use crate::protocol::{
    build_stun_success_response_with_key, combine_session_key, demux_rfc7983,
    derive_ice_migration_key, derive_stun_material, new_dtls_instance, parse_stun_with_key,
    peek_stun_request_username, rand_duration_range_ms, resolve_srtp_suite, validate_dtls_datagram,
    PacketKind, RollingByteWindow, SrtpCloakCipher, SrtpFrame,
};
use crate::relay::{PassthroughTable, RelayEgress};
use crate::udp_batch::UdpSendBatch;
use mio::Token;
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 中继热切换过渡期与双模共存时的透传分流策略。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayPassthroughPolicy {
    /// 纯 `cloak` / `bypass` 模式（严格静默丢弃一切未认证报文）。
    Disabled,
    /// `passthrough -> cloak/bypass` 切换排空期：仅既有透传五元组继续走透传，新连接一律进入 `ServerWorker`。
    DrainExistingOnly,
    /// `cloak/bypass -> passthrough` 切换排空期：既有 `ServerWorker` 会话继续排空，新连接一律零解密透传。
    PreferPassthrough,
    /// 双模并存：既有透传走透传，新连接先试本地 PSK，认证失败的 STUN（如端到端直连出口 PSK）自动落入透传。
    FallbackOnUnauth,
}

/// 服务端在 DTLS Flight 5 完成前每会话最多缓存的 0-RTT 早到 SRTP 包数。
const EARLY_SRTP_CAP: usize = 32;
/// 服务端未验证迁移候选映射表硬容量上限，防止 OOM。
const MAX_MIG_PENDING_MAP: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingUplink {
    BackendOwned(Token),
    RelayBypass {
        ingress_tok: Token,
        up_tok: Token,
    },
    RelayCloak {
        ingress_tok: Token,
        up_tok: Token,
    },
    RelayReverse {
        ingress_tok: Token,
        peer_flow: SocketAddr,
    },
    ReverseEntry(Token),
    #[cfg(feature = "embedded-proxy")]
    ProxyServer {
        flow_addr: SocketAddr,
    },
    #[cfg(feature = "embedded-proxy")]
    ProxyClient,
}

#[inline]
fn flush_server_uplink_batch(
    pending: &mut Option<PendingUplink>,
    tx_batch: &mut UdpSendBatch,
    sessions_by_token: &mut HashMap<Token, ServerSession>,
    hook: &mut Option<ServerHook<'_>>,
    now: Instant,
) {
    if let Some(target) = pending.take() {
        if tx_batch.is_empty() {
            return;
        }
        match target {
            PendingUplink::BackendOwned(tok) => {
                if let Some(sess) = sessions_by_token.get_mut(&tok) {
                    let (sent_pkts, sent_bytes) = match sess.backend {
                        BackendPipe::Owned(ref sock) => tx_batch.flush_connected(sock),
                        _ => {
                            tx_batch.clear();
                            (0, 0)
                        }
                    };
                    if sent_pkts > 0 {
                        sess.rx_pkts += sent_pkts as u64;
                        sess.rx_bytes += sent_bytes;
                        record_server_media_bytes(sess, now, sent_bytes);
                    }
                } else {
                    tx_batch.clear();
                }
            }
            PendingUplink::RelayBypass {
                ingress_tok,
                up_tok,
            } => {
                let (sent_pkts, sent_bytes) =
                    if let Some(ServerHook::Relay(RelayEgress::Bypass(b))) = hook.as_mut() {
                        b.flush_batched_uplink(up_tok, tx_batch, now)
                    } else {
                        tx_batch.clear();
                        (0, 0)
                    };
                if sent_pkts > 0 {
                    if let Some(sess) = sessions_by_token.get_mut(&ingress_tok) {
                        sess.rx_pkts += sent_pkts as u64;
                        sess.rx_bytes += sent_bytes;
                        record_server_media_bytes(sess, now, sent_bytes);
                    }
                }
            }
            PendingUplink::RelayCloak {
                ingress_tok,
                up_tok,
            } => {
                let (sent_pkts, sent_bytes) =
                    if let Some(ServerHook::Relay(RelayEgress::Cloak(c))) = hook.as_mut() {
                        c.flush_batched_uplink(up_tok, tx_batch, now)
                    } else {
                        tx_batch.clear();
                        (0, 0)
                    };
                if sent_pkts > 0 {
                    if let Some(sess) = sessions_by_token.get_mut(&ingress_tok) {
                        sess.rx_pkts += sent_pkts as u64;
                        sess.rx_bytes += sent_bytes;
                        record_server_media_bytes(sess, now, sent_bytes);
                    }
                }
            }
            PendingUplink::RelayReverse {
                ingress_tok,
                peer_flow,
            } => {
                let (sent_pkts, sent_bytes) = match hook.as_mut() {
                    Some(ServerHook::Relay(RelayEgress::Reverse(peer))) => {
                        let (sp, sb) = tx_batch.flush_to(&peer.listen_sock);
                        if sp > 0 {
                            peer.record_downlink_sent(peer_flow, sp, sb, now);
                        }
                        (sp, sb)
                    }
                    Some(ServerHook::RelayReversePeer(peer)) => {
                        let (sp, sb) = tx_batch.flush_to(&peer.listen_sock);
                        if sp > 0 {
                            peer.record_downlink_sent(peer_flow, sp, sb, now);
                        }
                        (sp, sb)
                    }
                    _ => {
                        tx_batch.clear();
                        (0, 0)
                    }
                };
                if sent_pkts > 0 {
                    if let Some(sess) = sessions_by_token.get_mut(&ingress_tok) {
                        sess.rx_pkts += sent_pkts as u64;
                        sess.rx_bytes += sent_bytes;
                        record_server_media_bytes(sess, now, sent_bytes);
                    }
                }
            }
            PendingUplink::ReverseEntry(tok) => {
                let (sent_pkts, sent_bytes) =
                    if let Some(ServerHook::ReverseEntry(hub)) = hook.as_mut() {
                        tx_batch.flush_to(hub.expose_sock())
                    } else {
                        tx_batch.clear();
                        (0, 0)
                    };
                if sent_pkts > 0 {
                    if let Some(sess) = sessions_by_token.get_mut(&tok) {
                        sess.rx_pkts += sent_pkts as u64;
                        sess.rx_bytes += sent_bytes;
                        record_server_media_bytes(sess, now, sent_bytes);
                    }
                }
            }
            #[cfg(feature = "embedded-proxy")]
            PendingUplink::ProxyServer { .. } | PendingUplink::ProxyClient => {
                tx_batch.clear();
            }
        }
    }
}

impl ServerWorker {
    #[inline]
    fn is_tracked_peer(&self, peer_addr: SocketAddr, pkt: &[u8]) -> bool {
        if self.token_by_peer.contains_key(&peer_addr)
            || self.local_mig_pending.contains_key(&peer_addr)
            || self.cross_worker_pending.contains_key(&peer_addr)
        {
            return true;
        }
        if demux_rfc7983(pkt) == PacketKind::Stun {
            if let Some(u) = peek_stun_request_username(pkt) {
                if self.token_by_ufrag.contains_key(u) || self.registry.lookup_ufrag(u).is_some() {
                    return true;
                }
            }
        }
        false
    }

    #[inline]
    fn should_route_passthrough(
        &self,
        peer_addr: SocketAddr,
        pkt: &[u8],
        pt: Option<&PassthroughTable>,
        policy: RelayPassthroughPolicy,
    ) -> bool {
        let Some(table) = pt else {
            return false;
        };
        match policy {
            RelayPassthroughPolicy::Disabled => false,
            RelayPassthroughPolicy::DrainExistingOnly => table.has_peer(peer_addr),
            RelayPassthroughPolicy::PreferPassthrough => !self.is_tracked_peer(peer_addr, pkt),
            RelayPassthroughPolicy::FallbackOnUnauth => {
                if table.has_peer(peer_addr) {
                    return true;
                }
                if self.is_tracked_peer(peer_addr, pkt) {
                    return false;
                }
                if demux_rfc7983(pkt) == PacketKind::Stun {
                    let auth_ok = parse_stun_with_key(pkt, &self.stun_auth_psk, &self.stun_mi_key)
                        .is_some_and(|p| p.msg_type == STUN_BINDING_REQUEST && p.authenticated);
                    !auth_ok
                } else {
                    true
                }
            }
        }
    }

    pub(crate) fn handle_listen_readable_with(
        &mut self,
        now: Instant,
        hook: Option<ServerHook<'_>>,
    ) {
        self.handle_listen_readable_relay(now, hook, None, RelayPassthroughPolicy::Disabled);
    }

    pub(crate) fn handle_listen_readable_relay(
        &mut self,
        now: Instant,
        mut hook: Option<ServerHook<'_>>,
        mut pt: Option<&mut PassthroughTable>,
        pt_policy: RelayPassthroughPolicy,
    ) {
        if self.rx_batch.is_some() {
            self.handle_listen_readable_batched_with(now, hook, pt, pt_policy);
            return;
        }
        loop {
            let (n, peer_addr) = match self.listen_sock.recv_from(&mut self.rbuf) {
                Ok(v) => v,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if n == 0 {
                continue;
            }
            if pt_policy != RelayPassthroughPolicy::Disabled
                && self.should_route_passthrough(
                    peer_addr,
                    &self.rbuf[..n],
                    pt.as_deref(),
                    pt_policy,
                )
            {
                if let Some(table) = pt.as_deref_mut() {
                    table.forward_uplink(peer_addr, &self.rbuf[..n], now);
                }
                continue;
            }
            self.dispatch_listen_packet_with(n, peer_addr, now, &mut hook);
        }
    }

    fn handle_listen_readable_batched_with(
        &mut self,
        now: Instant,
        mut hook: Option<ServerHook<'_>>,
        mut pt: Option<&mut PassthroughTable>,
        pt_policy: RelayPassthroughPolicy,
    ) {
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
            let mut pending_uplink: Option<PendingUplink> = None;

            for i in 0..count {
                let pkt = rx_batch.packet(i);
                let Some(peer_addr) = rx_batch.peer(i) else {
                    continue;
                };
                if pkt.is_empty() {
                    continue;
                }
                if pt_policy != RelayPassthroughPolicy::Disabled
                    && self.should_route_passthrough(peer_addr, pkt, pt.as_deref(), pt_policy)
                {
                    if let Some(table) = pt.as_deref_mut() {
                        table.forward_uplink(peer_addr, pkt, now);
                    }
                    continue;
                }

                // 快路径：已就绪 SRTP 数据包直通 Owned 后端、零回环 RelayEgress 或 ReverseEntry
                if demux_rfc7983(pkt) == PacketKind::Srtp {
                    if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
                        let fast_target = self.sessions_by_token.get(&tok).and_then(|s| {
                            if s.state != ServerState::Ready {
                                return None;
                            }
                            match s.backend {
                                BackendPipe::Owned(_) => Some(PendingUplink::BackendOwned(tok)),
                                BackendPipe::RelayFlow(flow_addr) => match hook.as_mut() {
                                    Some(ServerHook::Relay(RelayEgress::Bypass(b))) => b
                                        .ready_upstream_tok(flow_addr)
                                        .map(|up_tok| PendingUplink::RelayBypass {
                                            ingress_tok: tok,
                                            up_tok,
                                        }),
                                    Some(ServerHook::Relay(RelayEgress::Cloak(c))) => c
                                        .ready_upstream_tok(flow_addr)
                                        .map(|up_tok| PendingUplink::RelayCloak {
                                            ingress_tok: tok,
                                            up_tok,
                                        }),
                                    Some(ServerHook::Relay(RelayEgress::Reverse(peer))) => peer
                                        .active_ready_relay_flow()
                                        .map(|peer_flow| PendingUplink::RelayReverse {
                                            ingress_tok: tok,
                                            peer_flow,
                                        }),
                                    Some(ServerHook::RelayReversePeer(peer)) => peer
                                        .active_ready_relay_flow()
                                        .map(|peer_flow| PendingUplink::RelayReverse {
                                            ingress_tok: tok,
                                            peer_flow,
                                        }),
                                    #[cfg(feature = "embedded-proxy")]
                                    Some(ServerHook::Proxy(_)) => {
                                        Some(PendingUplink::ProxyServer { flow_addr })
                                    }
                                    #[cfg(feature = "embedded-proxy")]
                                    Some(ServerHook::ProxyClient(_)) => {
                                        Some(PendingUplink::ProxyClient)
                                    }
                                    _ => None,
                                },
                                BackendPipe::ReverseAgent
                                    if matches!(hook, Some(ServerHook::ReverseEntry(_))) =>
                                {
                                    Some(PendingUplink::ReverseEntry(tok))
                                }
                                _ => None,
                            }
                        });
                        if let Some(target) = fast_target {
                            if pending_uplink != Some(target) || tx_batch.is_full() {
                                flush_server_uplink_batch(
                                    &mut pending_uplink,
                                    &mut tx_batch,
                                    &mut self.sessions_by_token,
                                    &mut hook,
                                    now,
                                );
                                pending_uplink = Some(target);
                            }
                            self.audit.record(0, pkt);
                            match target {
                                PendingUplink::BackendOwned(_)
                                | PendingUplink::RelayBypass { .. } => {
                                    let frame = {
                                        let sess = self.sessions_by_token.get_mut(&tok).unwrap();
                                        let slot = tx_batch.next_slot_mut().unwrap();
                                        sess.cipher
                                            .as_mut()
                                            .and_then(|c| c.unwrap_into_ex(pkt, slot))
                                    };
                                    match frame {
                                        Some(SrtpFrame::Data(pn)) => {
                                            if pn > 0 {
                                                tx_batch.commit_slot(pn, pn as u64, None);
                                            }
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.last_data_active = now;
                                                sess.last_peer_rx = now;
                                            }
                                        }
                                        Some(ctrl_frame) => {
                                            let pn = ctrl_frame.payload_len();
                                            let copy_len = pn.min(self.wbuf.len());
                                            self.wbuf[..copy_len].copy_from_slice(
                                                tx_batch.uncommitted_slot_prefix(copy_len),
                                            );
                                            flush_server_uplink_batch(
                                                &mut pending_uplink,
                                                &mut tx_batch,
                                                &mut self.sessions_by_token,
                                                &mut hook,
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
                                                &mut self.relay,
                                                &mut hook,
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
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.auth_drops += 1;
                                            }
                                        }
                                    }
                                }
                                PendingUplink::ReverseEntry(_) => {
                                    let frame = {
                                        let sess = self.sessions_by_token.get_mut(&tok).unwrap();
                                        let slot = tx_batch.next_slot_mut().unwrap();
                                        sess.cipher
                                            .as_mut()
                                            .and_then(|c| c.unwrap_into_ex(pkt, slot))
                                    };
                                    match frame {
                                        Some(SrtpFrame::ReverseData { flow_id, len }) => {
                                            if len > 0 {
                                                if let Some(ServerHook::ReverseEntry(hub)) =
                                                    hook.as_mut()
                                                {
                                                    if let Some(dst) =
                                                        hub.peer_for_flow(flow_id, now)
                                                    {
                                                        tx_batch.commit_slot(
                                                            len,
                                                            len as u64,
                                                            Some(dst),
                                                        );
                                                    }
                                                }
                                            }
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.last_data_active = now;
                                                sess.last_peer_rx = now;
                                            }
                                        }
                                        Some(ctrl_frame) => {
                                            let pn = ctrl_frame.payload_len();
                                            let copy_len = pn.min(self.wbuf.len());
                                            self.wbuf[..copy_len].copy_from_slice(
                                                tx_batch.uncommitted_slot_prefix(copy_len),
                                            );
                                            flush_server_uplink_batch(
                                                &mut pending_uplink,
                                                &mut tx_batch,
                                                &mut self.sessions_by_token,
                                                &mut hook,
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
                                                &mut self.relay,
                                                &mut hook,
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
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.auth_drops += 1;
                                            }
                                        }
                                    }
                                }
                                PendingUplink::RelayCloak { up_tok, .. } => {
                                    let frame = {
                                        let sess = self.sessions_by_token.get_mut(&tok).unwrap();
                                        sess.cipher
                                            .as_mut()
                                            .and_then(|c| c.unwrap_into_ex(pkt, &mut self.wbuf))
                                    };
                                    match frame {
                                        Some(SrtpFrame::Data(pn)) => {
                                            if pn > 0 && pn <= MAX_INNER_UDP_LEN {
                                                if let Some(ServerHook::Relay(
                                                    RelayEgress::Cloak(c),
                                                )) = hook.as_mut()
                                                {
                                                    if let Some(slot) = tx_batch.next_slot_mut() {
                                                        if let Some(wn) = c.wrap_uplink_into_slot(
                                                            up_tok,
                                                            &self.wbuf[..pn],
                                                            slot,
                                                            now,
                                                        ) {
                                                            tx_batch
                                                                .commit_slot(wn, pn as u64, None);
                                                        }
                                                    }
                                                }
                                            }
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.last_data_active = now;
                                                sess.last_peer_rx = now;
                                            }
                                        }
                                        Some(ctrl_frame) => {
                                            flush_server_uplink_batch(
                                                &mut pending_uplink,
                                                &mut tx_batch,
                                                &mut self.sessions_by_token,
                                                &mut hook,
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
                                                &mut self.relay,
                                                &mut hook,
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
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.auth_drops += 1;
                                            }
                                        }
                                    }
                                }
                                PendingUplink::RelayReverse { peer_flow, .. } => {
                                    let frame = {
                                        let sess = self.sessions_by_token.get_mut(&tok).unwrap();
                                        sess.cipher
                                            .as_mut()
                                            .and_then(|c| c.unwrap_into_ex(pkt, &mut self.wbuf))
                                    };
                                    match frame {
                                        Some(SrtpFrame::Data(pn)) => {
                                            if pn > 0 && pn <= MAX_INNER_UDP_LEN {
                                                let enc = match hook.as_mut() {
                                                    Some(ServerHook::Relay(
                                                        RelayEgress::Reverse(peer),
                                                    )) => {
                                                        tx_batch.next_slot_mut().and_then(|slot| {
                                                            peer.encrypt_downlink_into_slot(
                                                                peer_flow,
                                                                &self.wbuf[..pn],
                                                                slot,
                                                                now,
                                                            )
                                                        })
                                                    }
                                                    Some(ServerHook::RelayReversePeer(peer)) => {
                                                        tx_batch.next_slot_mut().and_then(|slot| {
                                                            peer.encrypt_downlink_into_slot(
                                                                peer_flow,
                                                                &self.wbuf[..pn],
                                                                slot,
                                                                now,
                                                            )
                                                        })
                                                    }
                                                    _ => None,
                                                };
                                                if let Some((wn, dst_addr)) = enc {
                                                    tx_batch.commit_slot(
                                                        wn,
                                                        pn as u64,
                                                        Some(dst_addr),
                                                    );
                                                }
                                            }
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.last_data_active = now;
                                                sess.last_peer_rx = now;
                                            }
                                        }
                                        Some(ctrl_frame) => {
                                            flush_server_uplink_batch(
                                                &mut pending_uplink,
                                                &mut tx_batch,
                                                &mut self.sessions_by_token,
                                                &mut hook,
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
                                                &mut self.relay,
                                                &mut hook,
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
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.auth_drops += 1;
                                            }
                                        }
                                    }
                                }
                                #[cfg(feature = "embedded-proxy")]
                                PendingUplink::ProxyServer { flow_addr } => {
                                    let frame = {
                                        let sess = self.sessions_by_token.get_mut(&tok).unwrap();
                                        sess.cipher
                                            .as_mut()
                                            .and_then(|c| c.unwrap_into_ex(pkt, &mut self.wbuf))
                                    };
                                    match frame {
                                        Some(SrtpFrame::Data(pn)) => {
                                            if pn > 0 && pn <= MAX_INNER_UDP_LEN {
                                                if let Some(ServerHook::Proxy(engine)) =
                                                    hook.as_mut()
                                                {
                                                    engine.on_tunnel_datagram(
                                                        flow_addr,
                                                        &self.wbuf[..pn],
                                                    );
                                                }
                                            }
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.last_data_active = now;
                                                sess.last_peer_rx = now;
                                                sess.rx_pkts += 1;
                                                sess.rx_bytes += pn as u64;
                                                record_server_media_bytes(sess, now, pn as u64);
                                            }
                                        }
                                        Some(ctrl_frame) => {
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
                                                &mut self.relay,
                                                &mut hook,
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
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.auth_drops += 1;
                                            }
                                        }
                                    }
                                }
                                #[cfg(feature = "embedded-proxy")]
                                PendingUplink::ProxyClient => {
                                    let frame = {
                                        let sess = self.sessions_by_token.get_mut(&tok).unwrap();
                                        sess.cipher
                                            .as_mut()
                                            .and_then(|c| c.unwrap_into_ex(pkt, &mut self.wbuf))
                                    };
                                    match frame {
                                        Some(SrtpFrame::Data(pn)) => {
                                            if pn > 0 && pn <= MAX_INNER_UDP_LEN {
                                                if let Some(ServerHook::ProxyClient(engine)) =
                                                    hook.as_mut()
                                                {
                                                    engine.on_tunnel_datagram(&self.wbuf[..pn]);
                                                }
                                            }
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.last_data_active = now;
                                                sess.last_peer_rx = now;
                                                sess.rx_pkts += 1;
                                                sess.rx_bytes += pn as u64;
                                                record_server_media_bytes(sess, now, pn as u64);
                                            }
                                        }
                                        Some(ctrl_frame) => {
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
                                                &mut self.relay,
                                                &mut hook,
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
                                            if let Some(sess) = self.sessions_by_token.get_mut(&tok)
                                            {
                                                sess.auth_drops += 1;
                                            }
                                        }
                                    }
                                }
                            }
                            continue;
                        }
                    }
                }

                // 慢路径（STUN / DTLS / SRTCP / 首包建后端 / 迁移 / 交接）：先按序刷新数据批再复用既有状态机
                flush_server_uplink_batch(
                    &mut pending_uplink,
                    &mut tx_batch,
                    &mut self.sessions_by_token,
                    &mut hook,
                    now,
                );
                let len = pkt.len().min(self.rbuf.len());
                self.rbuf[..len].copy_from_slice(&pkt[..len]);
                self.dispatch_listen_packet_with(len, peer_addr, now, &mut hook);
            }

            flush_server_uplink_batch(
                &mut pending_uplink,
                &mut tx_batch,
                &mut self.sessions_by_token,
                &mut hook,
                now,
            );
        }

        self.rx_batch = Some(rx_batch);
        self.tx_batch = Some(tx_batch);
    }

    fn dispatch_listen_packet_with(
        &mut self,
        n: usize,
        peer_addr: SocketAddr,
        now: Instant,
        hook: &mut Option<ServerHook<'_>>,
    ) {
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
                    if let Some(parsed) =
                        parse_stun_with_key(pkt, &self.stun_auth_psk, &meta.mi_key_mig)
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

                // v0.7.1: Authenticate Ready-state RFC 7675 consent keepalives (`USE-CANDIDATE=false`)
                // strictly with the session's ephemeral DTLS-PFS `mi_key_mig` (NOT static `stun_mi_key`).
                // Eliminates both:
                //   (a) SIGKILL/crash restart zombie loop (restarted server lacks `mi_key_mig` -> 0B drop)
                //   (b) >90s post-close keepalive replay oracle (destroyed session key -> 0B drop forever).
                let ready_ka_ctx = peek_stun_request_username(pkt).and_then(|u| {
                    let &tok = self.token_by_peer.get(&peer_addr)?;
                    let sess = self.sessions_by_token.get(&tok)?;
                    if sess.peer_addr == peer_addr
                        && sess.username == u
                        && sess.state == ServerState::Ready
                    {
                        sess.mi_key_mig.map(|mk| (tok, mk))
                    } else {
                        None
                    }
                });
                if let Some((tok, mk)) = ready_ka_ctx {
                    if let Some(parsed) = parse_stun_with_key(pkt, &self.stun_auth_psk, &mk) {
                        if parsed.msg_type == STUN_BINDING_REQUEST
                            && parsed.authenticated
                            && !parsed.use_candidate
                        {
                            let txid_status = {
                                let mut cache = self.seen_txids.lock().unwrap();
                                cache.check(parsed.txid, peer_addr, now, false)
                            };
                            if !matches!(txid_status, TxidCheck::Fresh) {
                                self.unauth_drops += 1;
                                return;
                            }
                            let resp =
                                build_stun_success_response_with_key(&parsed.txid, peer_addr, &mk);
                            {
                                let mut cache = self.seen_txids.lock().unwrap();
                                cache.record_single_use(parsed.txid, peer_addr, now);
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
                }

                let parsed = match parse_stun_with_key(pkt, &self.stun_auth_psk, &self.stun_mi_key)
                {
                    Some(p) if p.msg_type == STUN_BINDING_REQUEST && p.authenticated => p,
                    _ => {
                        self.unauth_drops += 1;
                        return;
                    }
                };

                let uname = parsed.username.unwrap_or_default();
                let (same_active, same_ready, allow_retransmit) = self
                    .token_by_peer
                    .get(&peer_addr)
                    .and_then(|tok| self.sessions_by_token.get(tok))
                    .map(|s| {
                        let active = s.peer_addr == peer_addr
                            && s.username == uname
                            && !matches!(s.state, ServerState::Closing(_, _));
                        let ready = active && s.state == ServerState::Ready;
                        let retx =
                            active && !s.dtls_started && s.state == ServerState::DtlsHandshake;
                        (active, ready, retx)
                    })
                    .unwrap_or((false, false, false));

                let txid_status = {
                    let mut cache = self.seen_txids.lock().unwrap();
                    cache.check(parsed.txid, peer_addr, now, allow_retransmit)
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
                    // Ready sessions MUST use per-session DTLS-PFS `mi_key_mig` for keepalives;
                    // reject static-PSK keepalives on an already-Ready session.
                    if same_ready {
                        self.unauth_drops += 1;
                        return;
                    }
                    if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
                        let resp = build_stun_success_response_with_key(
                            &parsed.txid,
                            peer_addr,
                            &self.stun_mi_key,
                        );
                        {
                            let mut cache = self.seen_txids.lock().unwrap();
                            cache.record_single_use(parsed.txid, peer_addr, now);
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

                // v0.7 RFC 8445 regular ICE connectivity check (`USE-CANDIDATE = false`):
                // Reply 64B ONLY for ICE-CONTROLLING unlocked same-IP hunt probes without creating
                // a ServerSession. Unnominated entries remain tombstoned for 20s (> STUN freshness);
                // once nominated (`USE-CANDIDATE = true`), `ufrag` is locked for 90s.
                if !parsed.use_candidate {
                    if parsed.tie_breaker.is_none()
                        || !self.registry.allow_hunt_probe(&uname, peer_addr, now)
                    {
                        self.unauth_drops += 1;
                        return;
                    }
                    let resp = build_stun_success_response_with_key(
                        &parsed.txid,
                        peer_addr,
                        &self.stun_mi_key,
                    );
                    {
                        let mut cache = self.seen_txids.lock().unwrap();
                        cache.record_single_use(parsed.txid, peer_addr, now);
                    }
                    self.audit.record(1, &resp);
                    let _ = self.listen_sock.send_to(&resp, peer_addr);
                    return;
                }

                // P0-3 + v0.7 nomination lock: reject duplicate ufrag hijacking or cross-IP replay,
                // and immediately burn all unused sibling `--lane-hunt` probes for this `ufrag`.
                let same_peer_rekey_same_ufrag = self
                    .token_by_peer
                    .get(&peer_addr)
                    .and_then(|t| self.sessions_by_token.get(t))
                    .map(|s| s.peer_addr == peer_addr && s.username == uname)
                    .unwrap_or(false);
                if !same_peer_rekey_same_ufrag
                    && (self.token_by_ufrag.contains_key(&uname)
                        || self.registry.lookup_ufrag(&uname).is_some()
                        || !self.registry.lock_hunt_ufrag(&uname, peer_addr, now))
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
                                &mut self.relay,
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
                                &mut self.relay,
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
                    derive_stun_material(&self.stun_auth_psk, &parsed.txid, &uname);
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

                let resp = build_stun_success_response_with_key(
                    &parsed.txid,
                    peer_addr,
                    &self.stun_mi_key,
                );
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
                    is_reverse_agent: false,
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
                    initial_stun_txid: parsed.txid,
                    dtls_started: false,
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
                    pending_close_notify_at: None,
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
                        if !sess.dtls_started {
                            sess.dtls_started = true;
                            self.seen_txids
                                .lock()
                                .unwrap()
                                .invalidate(sess.initial_stun_txid);
                        }
                        // P2-1 + R2-P1-3 fix: Only a brand-new ClientWorker fail-fast reset has
                        // `epoch == 0 && record_seq == 0 (pkt[5..11] == [0; 6]) && msg_seq == 0`.
                        // Normal ClientHello RTO retransmissions carry `record_seq >= 1` and MUST
                        // reach `sess.dtls` so `dimpl` resends Flight-4 under the existing keys!
                        let is_fresh_epoch0_ch = sess.state == ServerState::DtlsHandshake
                            && sess.dtls_suite_id.is_some()
                            && pkt.len() >= 25
                            && pkt[0] == 22
                            && pkt[3] == 0
                            && pkt[4] == 0
                            && pkt[5..11] == [0; 6]
                            && pkt[13] == 1
                            && pkt[17] == 0
                            && pkt[18] == 0;
                        if is_fresh_epoch0_ch && sess.dtls_resets < MAX_DTLS_RESETS {
                            sess.dtls_resets += 1;
                            sess.dtls_suite_id = None;
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
                            }
                            // R3-P2-1: Per RFC 9147 §4.5.2, never wipe an in-progress server
                            // `DtlsHandshake` on a bad/spoofed packet; only a verified fresh
                            // `epoch=0, record_seq=0` ClientHello triggers `is_fresh_epoch0_ch`.
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
                                &mut self.relay,
                                hook,
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
                                &mut self.relay,
                                hook,
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
                            &mut self.relay,
                            hook,
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
