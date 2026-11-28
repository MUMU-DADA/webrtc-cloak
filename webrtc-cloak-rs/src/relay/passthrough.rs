//! 零解密 L4 UDP 透传中继表（`webrtc-cloak relay --upstream-mode passthrough`）。
//!
//! 特性：
//! - 零加解密、零 PSK 依赖：中继节点不做任何 DTLS/SRTP 加解密或包头改写，客户端与出口端到端直连；
//! - 原生双栈协议转换：支持入站 IPv6（例如家宽公网 IPv6）零开销透传至出站 IPv4 出口（及反向）；
//! - 每客户端源端口独立固定出站 UDP 套接字：完整保留客户端 `--lane-hunt` 多路探测与 0ms MBB 轮换语意；
//! - 支持 Linux `recvmmsg`/`sendmmsg` 批量收发与过渡期 `AB` 排空模式（热切换零丢包）。

use super::log;
use crate::constants::{
    unspecified_addr_for, worker_udp_recv_buf_len, SharedPoll, PASSTHROUGH_TOK_BASE, SOCK_BUF_4MIB,
};
use crate::server::make_udp_socket;
use crate::telemetry::WorkerSnapshot;
use crate::udp_batch::{is_udp_batch_active, UdpRecvBatch, UdpSendBatch};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Interest, Token};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 零解密透传中继配置（`webrtc-cloak relay --upstream-mode passthrough`）。
#[derive(Clone)]
pub struct PassthroughConfig {
    pub target_addr: SocketAddr,
    pub max_sessions: usize,
    pub wan_mtu: usize,
    pub udp_batch: usize,
    pub idle_timeout_secs: u64,
}

struct PassthroughSession {
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
    upstream: MioUdpSocket,
    up_lport: u16,
    last_active: Instant,
    tx_pkts: u64,
    tx_bytes: u64,
    rx_pkts: u64,
    rx_bytes: u64,
}

/// 单线程零锁 L4 UDP 透传表（可独立运行，也可在热切换过渡期与 `ServerWorker` 共存于同一 `mio::Poll`）。
pub(crate) struct PassthroughTable {
    worker_id: usize,
    target_addr: SocketAddr,
    poll: SharedPoll,
    max_sessions: usize,
    idle_dur: Duration,
    /// `true` 表示当前处于切出排空态：已存在的客户端流继续双工转发直到自然空闲，新流不再进入本表。
    draining: bool,
    sessions_by_token: HashMap<Token, PassthroughSession>,
    token_by_peer: HashMap<SocketAddr, Token>,
    next_tok_off: usize,
    rbuf: Vec<u8>,
    rx_batch: Option<UdpRecvBatch>,
    tx_batch: Option<UdpSendBatch>,
    last_active_up_sport: u16,
    closed_tx_pkts: u64,
    closed_tx_bytes: u64,
    closed_rx_pkts: u64,
    closed_rx_bytes: u64,
}

impl PassthroughTable {
    pub(crate) fn new(worker_id: usize, cfg: PassthroughConfig, poll: SharedPoll) -> Self {
        let buf_len = worker_udp_recv_buf_len(cfg.wan_mtu);
        let batch_enabled = is_udp_batch_active(cfg.udp_batch);
        let rx_batch = batch_enabled.then(|| UdpRecvBatch::new(cfg.udp_batch, buf_len));
        let tx_batch = batch_enabled.then(|| UdpSendBatch::new(cfg.udp_batch, buf_len));
        Self {
            worker_id,
            target_addr: cfg.target_addr,
            poll,
            max_sessions: cfg.max_sessions.max(1),
            idle_dur: Duration::from_secs(cfg.idle_timeout_secs.max(15)),
            draining: false,
            sessions_by_token: HashMap::with_capacity(64),
            token_by_peer: HashMap::with_capacity(64),
            next_tok_off: 0,
            rbuf: vec![0u8; buf_len],
            rx_batch,
            tx_batch,
            last_active_up_sport: 0,
            closed_tx_pkts: 0,
            closed_tx_bytes: 0,
            closed_rx_pkts: 0,
            closed_rx_bytes: 0,
        }
    }

    #[inline]
    pub(crate) fn target_addr(&self) -> SocketAddr {
        self.target_addr
    }

    /// 热更新后续新客户端流的目标出口地址；已有活跃流继续沿原出站五元组无感排空。
    pub(crate) fn set_target_addr(&mut self, new_target: SocketAddr) {
        self.target_addr = new_target;
        self.draining = false;
    }

    pub(crate) fn set_draining(&mut self, draining: bool) {
        self.draining = draining;
    }

    #[inline]
    pub(crate) fn active_sessions(&self) -> usize {
        self.sessions_by_token.len()
    }

    #[inline]
    pub(crate) fn has_peer(&self, peer_addr: SocketAddr) -> bool {
        self.token_by_peer.contains_key(&peer_addr)
    }

    #[inline]
    pub(crate) fn owns_token(&self, tok: Token) -> bool {
        tok.0 >= PASSTHROUGH_TOK_BASE && tok.0 < usize::MAX - 16
    }

    fn alloc_token(&mut self) -> Token {
        let span = (usize::MAX - 16)
            .saturating_sub(PASSTHROUGH_TOK_BASE)
            .max(1);
        loop {
            let off = self.next_tok_off;
            self.next_tok_off = (self.next_tok_off + 1) % span;
            let tok = Token(PASSTHROUGH_TOK_BASE + off);
            if !self.sessions_by_token.contains_key(&tok) {
                return tok;
            }
        }
    }

    fn evict_if_full(&mut self, now: Instant) {
        if self.sessions_by_token.len() < self.max_sessions {
            return;
        }
        // 1) 先清理所有已超时的空闲会话
        let expired: Vec<Token> = self
            .sessions_by_token
            .iter()
            .filter(|(_, s)| now.saturating_duration_since(s.last_active) >= self.idle_dur)
            .map(|(&t, _)| t)
            .collect();
        for tok in expired {
            self.remove_session(tok);
        }
        if self.sessions_by_token.len() < self.max_sessions {
            return;
        }
        // 2) 若仍满载，淘汰最久未活跃的一条会话（LRU 防 OOM）
        if let Some((&oldest_tok, _)) = self
            .sessions_by_token
            .iter()
            .min_by_key(|(_, s)| s.last_active)
        {
            self.remove_session(oldest_tok);
        }
    }

    fn remove_session(&mut self, tok: Token) {
        if let Some(mut s) = self.sessions_by_token.remove(&tok) {
            self.token_by_peer.remove(&s.peer_addr);
            let _ = self.poll.registry().deregister(&mut s.upstream);
            self.closed_tx_pkts = self.closed_tx_pkts.saturating_add(s.tx_pkts);
            self.closed_tx_bytes = self.closed_tx_bytes.saturating_add(s.tx_bytes);
            self.closed_rx_pkts = self.closed_rx_pkts.saturating_add(s.rx_pkts);
            self.closed_rx_bytes = self.closed_rx_bytes.saturating_add(s.rx_bytes);
        }
    }

    fn get_or_create_session(&mut self, peer_addr: SocketAddr, now: Instant) -> Option<Token> {
        if let Some(&tok) = self.token_by_peer.get(&peer_addr) {
            return Some(tok);
        }
        if self.draining {
            return None;
        }
        self.evict_if_full(now);
        let bind_addr = unspecified_addr_for(self.target_addr);
        let mut sock =
            match make_udp_socket(bind_addr, Some(self.target_addr), false, SOCK_BUF_4MIB) {
                Ok(s) => s,
                Err(e) => {
                    log(
                        self.worker_id,
                        &format!(
                            "passthrough socket create failed peer={} -> {}: {}",
                            peer_addr, self.target_addr, e
                        ),
                    );
                    return None;
                }
            };
        let up_lport = sock.local_addr().map(|a| a.port()).unwrap_or(0);
        let tok = self.alloc_token();
        if let Err(e) = self
            .poll
            .registry()
            .register(&mut sock, tok, Interest::READABLE)
        {
            log(
                self.worker_id,
                &format!("passthrough poll register failed: {}", e),
            );
            return None;
        }
        self.sessions_by_token.insert(
            tok,
            PassthroughSession {
                peer_addr,
                target_addr: self.target_addr,
                upstream: sock,
                up_lport,
                last_active: now,
                tx_pkts: 0,
                tx_bytes: 0,
                rx_pkts: 0,
                rx_bytes: 0,
            },
        );
        self.token_by_peer.insert(peer_addr, tok);
        self.last_active_up_sport = up_lport;
        log(
            self.worker_id,
            &format!(
                "PASSTHROUGH flow open peer={} -> up_sport={} -> {} (active={})",
                peer_addr,
                up_lport,
                self.target_addr,
                self.sessions_by_token.len()
            ),
        );
        Some(tok)
    }

    /// 零解密转发单个上行报文至该客户端绑定的专属出站 UDP 套接字。
    #[inline]
    pub(crate) fn forward_uplink(&mut self, peer_addr: SocketAddr, pkt: &[u8], now: Instant) {
        if pkt.is_empty() {
            return;
        }
        let Some(tok) = self.get_or_create_session(peer_addr, now) else {
            return;
        };
        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            sess.last_active = now;
            if sess.upstream.send(pkt).is_ok() {
                sess.rx_pkts = sess.rx_pkts.saturating_add(1);
                sess.rx_bytes = sess.rx_bytes.saturating_add(pkt.len() as u64);
                self.last_active_up_sport = sess.up_lport;
            }
        }
    }

    /// 纯透传模式下直接从主监听套接字读取并批量转发至出站上游（支持 `recvmmsg` + `sendmmsg`）。
    pub(crate) fn handle_listen_readable(&mut self, listen_sock: &MioUdpSocket, now: Instant) {
        if self.rx_batch.is_some() && self.tx_batch.is_some() {
            self.handle_listen_readable_batched(listen_sock, now);
            return;
        }
        loop {
            let (n, peer_addr) = match listen_sock.recv_from(&mut self.rbuf) {
                Ok(v) => v,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if n == 0 {
                continue;
            }
            let Some(tok) = self.get_or_create_session(peer_addr, now) else {
                continue;
            };
            if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                sess.last_active = now;
                if sess.upstream.send(&self.rbuf[..n]).is_ok() {
                    sess.rx_pkts = sess.rx_pkts.saturating_add(1);
                    sess.rx_bytes = sess.rx_bytes.saturating_add(n as u64);
                    self.last_active_up_sport = sess.up_lport;
                }
            }
        }
    }

    fn handle_listen_readable_batched(&mut self, listen_sock: &MioUdpSocket, now: Instant) {
        let Some(mut rx_batch) = self.rx_batch.take() else {
            return;
        };
        let Some(mut tx_batch) = self.tx_batch.take() else {
            self.rx_batch = Some(rx_batch);
            return;
        };

        let flush_pending = |pending_tok: &mut Option<Token>,
                             tx_batch: &mut UdpSendBatch,
                             sessions: &mut HashMap<Token, PassthroughSession>,
                             last_sport: &mut u16| {
            if let Some(tok) = pending_tok.take() {
                if tx_batch.is_empty() {
                    return;
                }
                if let Some(sess) = sessions.get_mut(&tok) {
                    let (sp, sb) = tx_batch.flush_connected(&sess.upstream);
                    if sp > 0 {
                        sess.rx_pkts = sess.rx_pkts.saturating_add(sp as u64);
                        sess.rx_bytes = sess.rx_bytes.saturating_add(sb);
                        *last_sport = sess.up_lport;
                    }
                } else {
                    tx_batch.clear();
                }
            }
        };

        loop {
            let count = match rx_batch.recv_from(listen_sock) {
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
                let Some(tok) = self.get_or_create_session(peer_addr, now) else {
                    continue;
                };
                if pending_tok != Some(tok) || tx_batch.is_full() {
                    flush_pending(
                        &mut pending_tok,
                        &mut tx_batch,
                        &mut self.sessions_by_token,
                        &mut self.last_active_up_sport,
                    );
                    pending_tok = Some(tok);
                }
                if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
                    sess.last_active = now;
                }
                if let Some(slot) = tx_batch.next_slot_mut() {
                    if pkt.len() <= slot.len() {
                        slot[..pkt.len()].copy_from_slice(pkt);
                        tx_batch.commit_slot(pkt.len(), pkt.len() as u64, None);
                    }
                }
            }
            flush_pending(
                &mut pending_tok,
                &mut tx_batch,
                &mut self.sessions_by_token,
                &mut self.last_active_up_sport,
            );
        }

        self.rx_batch = Some(rx_batch);
        self.tx_batch = Some(tx_batch);
    }

    /// 零解密转发来自上游出口的下行回包至原客户端（支持 `recvmmsg` + `sendmmsg` 批量回发）。
    pub(crate) fn handle_upstream_readable(
        &mut self,
        tok: Token,
        listen_sock: &MioUdpSocket,
        now: Instant,
    ) {
        if self.rx_batch.is_some() && self.tx_batch.is_some() {
            self.handle_upstream_readable_batched(tok, listen_sock, now);
            return;
        }
        let Some(sess) = self.sessions_by_token.get_mut(&tok) else {
            return;
        };
        let peer_addr = sess.peer_addr;
        loop {
            let n = match sess.upstream.recv(&mut self.rbuf) {
                Ok(0) => continue,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            sess.last_active = now;
            if listen_sock.send_to(&self.rbuf[..n], peer_addr).is_ok() {
                sess.tx_pkts = sess.tx_pkts.saturating_add(1);
                sess.tx_bytes = sess.tx_bytes.saturating_add(n as u64);
            }
        }
    }

    fn handle_upstream_readable_batched(
        &mut self,
        tok: Token,
        listen_sock: &MioUdpSocket,
        now: Instant,
    ) {
        let Some(mut rx_batch) = self.rx_batch.take() else {
            return;
        };
        let Some(mut tx_batch) = self.tx_batch.take() else {
            self.rx_batch = Some(rx_batch);
            return;
        };

        if let Some(sess) = self.sessions_by_token.get_mut(&tok) {
            let peer_addr = sess.peer_addr;
            loop {
                let count = match rx_batch.recv_connected(&sess.upstream) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                sess.last_active = now;
                for i in 0..count {
                    let pkt = rx_batch.packet(i);
                    if pkt.is_empty() {
                        continue;
                    }
                    if tx_batch.is_full() {
                        let (sp, sb) = tx_batch.flush_to(listen_sock);
                        if sp > 0 {
                            sess.tx_pkts = sess.tx_pkts.saturating_add(sp as u64);
                            sess.tx_bytes = sess.tx_bytes.saturating_add(sb);
                        }
                    }
                    if let Some(slot) = tx_batch.next_slot_mut() {
                        if pkt.len() <= slot.len() {
                            slot[..pkt.len()].copy_from_slice(pkt);
                            tx_batch.commit_slot(pkt.len(), pkt.len() as u64, Some(peer_addr));
                        }
                    }
                }
                if !tx_batch.is_empty() {
                    let (sp, sb) = tx_batch.flush_to(listen_sock);
                    if sp > 0 {
                        sess.tx_pkts = sess.tx_pkts.saturating_add(sp as u64);
                        sess.tx_bytes = sess.tx_bytes.saturating_add(sb);
                    }
                }
            }
        }

        self.rx_batch = Some(rx_batch);
        self.tx_batch = Some(tx_batch);
    }

    /// 清理空闲超时的透传会话，返回建议的下一次事件循环定时等待时长。
    pub(crate) fn gc_idle(&mut self, now: Instant) -> Duration {
        let expired: Vec<Token> = self
            .sessions_by_token
            .iter()
            .filter(|(_, s)| now.saturating_duration_since(s.last_active) >= self.idle_dur)
            .map(|(&t, _)| t)
            .collect();
        for tok in expired {
            if let Some(s) = self.sessions_by_token.get(&tok) {
                log(
                    self.worker_id,
                    &format!(
                        "PASSTHROUGH flow idle timeout peer={} -> {} (rx={}pkts tx={}pkts)",
                        s.peer_addr, s.target_addr, s.rx_pkts, s.tx_pkts
                    ),
                );
            }
            self.remove_session(tok);
        }
        if self.sessions_by_token.is_empty() {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(2)
        }
    }

    pub(crate) fn shutdown_all(&mut self) {
        let toks: Vec<Token> = self.sessions_by_token.keys().copied().collect();
        for tok in toks {
            self.remove_session(tok);
        }
    }

    pub(crate) fn build_worker_snapshot(&self) -> WorkerSnapshot {
        let mut tx_bytes = self.closed_tx_bytes;
        let mut rx_bytes = self.closed_rx_bytes;
        let mut tx_pkts = self.closed_tx_pkts;
        let mut rx_pkts = self.closed_rx_pkts;
        for s in self.sessions_by_token.values() {
            tx_bytes = tx_bytes.saturating_add(s.tx_bytes);
            rx_bytes = rx_bytes.saturating_add(s.rx_bytes);
            tx_pkts = tx_pkts.saturating_add(s.tx_pkts);
            rx_pkts = rx_pkts.saturating_add(s.rx_pkts);
        }
        WorkerSnapshot {
            active_sessions: self.sessions_by_token.len(),
            handshaking_sessions: 0,
            migrating_sessions: 0,
            tx_bytes_total: tx_bytes,
            rx_bytes_total: rx_bytes,
            tx_pkts_total: tx_pkts,
            rx_pkts_total: rx_pkts,
            auth_drops_total: 0,
            unauth_drops_total: 0,
            active_up_sport: self.last_active_up_sport,
            active_backend_sport: 0,
            data_loss_pct: 0.0,
            lane_score: None,
            lane_best_rtt_ms: None,
            lane_confirmed: false,
            dtls_version: "passthrough",
            cipher: "e2e",
            dual_ssrc: false,
        }
    }
}
