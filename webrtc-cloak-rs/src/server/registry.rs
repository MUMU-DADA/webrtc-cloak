//! 服务端 STUN 防重放缓存与跨 worker 会话迁移注册表。

use super::ServerSession;
use mio::net::UdpSocket as MioUdpSocket;
use mio::Waker;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 服务端缓存的单条 STUN 应答报文最大字节数（标准 IPv4 Binding Success 固定 64B）。
const STUN_CACHED_REPLY_MAX_LEN: usize = 64;
/// 跨 worker 共享 STUN 事务 ID 防重放缓存条目存活时间（秒）。
const SEEN_TXID_TTL: Duration = Duration::from_secs(90);
/// 合法同端同 txid UDP 丢包重传的缓存应答有效窗口（秒）。
const SEEN_TXID_RETRANSMIT_WINDOW: Duration = Duration::from_secs(8);
/// 单条 STUN txid 在重传窗口内允许返回缓存应答的最大次数。
const MAX_STUN_RETRANSMITS: u8 = 6;
/// 共享 STUN 事务 ID 防重放缓存最大条目数。
const SEEN_TXID_CAP: usize = 65_536;
/// 单个 worker 跨线程非所有权移交控制指令队列上限，防内存耗尽。
const MAX_WORKER_CMD_QUEUE: usize = 4096;

pub(super) enum TxidCheck {
    Fresh,
    /// Genuine same-peer short-window UDP retry (bounded <= 6x): resend exact cached 64B reply!
    Retransmit([u8; STUN_CACHED_REPLY_MAX_LEN], u8),
    /// Cross-IP replay, post-close replay, or exceeded retries -> Silent Drop!
    Rejected,
}

struct TxidEntry {
    peer: SocketAddr,
    seen_at: Instant,
    cached_reply: [u8; STUN_CACHED_REPLY_MAX_LEN],
    cached_len: u8,
    retransmits: u8,
}

/// Shared O(1) bounded FIFO anti-replay cache across all SO_REUSEPORT workers.
pub(super) struct SeenTxidCache {
    map: HashMap<[u8; 12], TxidEntry>,
    order: VecDeque<([u8; 12], Instant)>,
}

impl SeenTxidCache {
    pub(super) fn new() -> Self {
        Self {
            map: HashMap::with_capacity(16),
            order: VecDeque::with_capacity(16),
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        while let Some(&(txid, ts)) = self.order.front() {
            if now.duration_since(ts) > SEEN_TXID_TTL {
                self.order.pop_front();
                if let Some(entry) = self.map.get(&txid) {
                    if entry.seen_at == ts {
                        self.map.remove(&txid);
                    }
                }
            } else {
                break;
            }
        }
    }

    pub(super) fn check(
        &mut self,
        txid: [u8; 12],
        peer: SocketAddr,
        now: Instant,
        same_session_active: bool,
    ) -> TxidCheck {
        self.evict_expired(now);
        if let Some(entry) = self.map.get_mut(&txid) {
            if entry.peer == peer
                && same_session_active
                && now.duration_since(entry.seen_at) <= SEEN_TXID_RETRANSMIT_WINDOW
                && entry.retransmits < MAX_STUN_RETRANSMITS
            {
                entry.retransmits += 1;
                return TxidCheck::Retransmit(entry.cached_reply, entry.cached_len);
            }
            return TxidCheck::Rejected;
        }
        TxidCheck::Fresh
    }

    pub(super) fn record(&mut self, txid: [u8; 12], peer: SocketAddr, now: Instant, resp: &[u8]) {
        self.evict_expired(now);
        while self.map.len() >= SEEN_TXID_CAP {
            if let Some((old_txid, old_ts)) = self.order.pop_front() {
                if let Some(e) = self.map.get(&old_txid) {
                    if e.seen_at == old_ts {
                        self.map.remove(&old_txid);
                    }
                }
            } else {
                break;
            }
        }
        let mut buf = [0u8; STUN_CACHED_REPLY_MAX_LEN];
        let clen = resp.len().min(STUN_CACHED_REPLY_MAX_LEN);
        buf[..clen].copy_from_slice(&resp[..clen]);
        self.map.insert(
            txid,
            TxidEntry {
                peer,
                seen_at: now,
                cached_reply: buf,
                cached_len: clen as u8,
                retransmits: 0,
            },
        );
        self.order.push_back((txid, now));
    }
}

#[derive(Clone, Copy)]
pub(super) struct ActiveSessionMeta {
    pub(super) worker_id: usize,
    pub(super) mi_key_mig: [u8; 32],
    pub(super) tie_breaker: [u8; 8],
}

pub(super) enum WorkerCmd {
    /// Worker receiving migration STUN asks owner worker to arm/reuse `0xFFFD` challenge WITHOUT
    /// moving the session yet (prevents spoofed-IP DoS against live owner!).
    CrossWorkerChallengeRequest {
        ufrag: String,
        cand_addr: SocketAddr,
        cand_worker: usize,
        stun_resp: Vec<u8>,
    },
    /// Worker receiving `0xFFFD` response (or early SRTP) from `cand_addr` forwards it to owner for
    /// AEAD verification; ONLY upon cryptographic proof does owner deregister & transfer `ServerSession`!
    CrossWorkerChallengeVerify {
        ufrag: String,
        cand_addr: SocketAddr,
        cand_worker: usize,
        pkt: Vec<u8>,
    },
    /// Owner worker delivers verified migrated `ServerSession` (with intact `backend_sock`!) to new worker.
    MigrateInstall { sess: Box<ServerSession> },
    /// MBB scheduled DTLS 1.3 rekey: new worker asks old owner worker to verify handover proof and
    /// atomically transfer `backend_sock` ownership to `new_ufrag`.
    HandoverExtract {
        old_ufrag: String,
        new_ufrag: String,
        new_session_key: [u8; 32],
        proof: [u8; 32],
        target_worker: usize,
    },
    /// Old owner worker delivers extracted `backend_sock` to new MBB session on `target_worker`.
    HandoverInstall {
        new_ufrag: String,
        backend_sock: MioUdpSocket,
        backend_lport: u16,
    },
    /// Handover finished without a socket to transfer (unbound old session) or failed verification.
    HandoverAckOnly { new_ufrag: String, ok: bool },
    /// Rare draining-window ECMP-reordered uplink packet forwarded from old session (`ForwardRemote`)
    /// with bounded hop count (`hops_left`) to survive chained MBB handovers / cross-worker migrations.
    DrainUplinkForward {
        target_ufrag: String,
        payload: Vec<u8>,
        hops_left: u8,
    },
    /// Bounce an in-flight SRTP packet that raced ahead of `MigrateInstall` back to the new owner worker.
    ReprocessSrtp { peer_addr: SocketAddr, pkt: Vec<u8> },
}

struct WorkerInbox {
    queue: Mutex<VecDeque<WorkerCmd>>,
    waker: Mutex<Option<Arc<Waker>>>,
}

pub(super) struct SharedV4Registry {
    ufrag_index: Mutex<HashMap<String, ActiveSessionMeta>>,
    inboxes: Vec<WorkerInbox>,
}

impl SharedV4Registry {
    pub(super) fn new(workers: usize) -> Self {
        let mut inboxes = Vec::with_capacity(workers);
        for _ in 0..workers {
            inboxes.push(WorkerInbox {
                queue: Mutex::new(VecDeque::new()),
                waker: Mutex::new(None),
            });
        }
        Self {
            ufrag_index: Mutex::new(HashMap::with_capacity(16)),
            inboxes,
        }
    }

    pub(super) fn set_waker(&self, worker_id: usize, waker: Arc<Waker>) {
        if let Some(inbox) = self.inboxes.get(worker_id) {
            if let Ok(mut g) = inbox.waker.lock() {
                *g = Some(waker);
            }
        }
    }

    pub(super) fn register_session(
        &self,
        ufrag: &str,
        worker_id: usize,
        mi_key_mig: [u8; 32],
        tie_breaker: [u8; 8],
    ) {
        if let Ok(mut idx) = self.ufrag_index.lock() {
            idx.insert(
                ufrag.to_string(),
                ActiveSessionMeta {
                    worker_id,
                    mi_key_mig,
                    tie_breaker,
                },
            );
        }
    }

    /// P0-3 fix: NEVER wildcard-delete when `mi_key_mig` is `None` (unready sessions never registered!).
    pub(super) fn unregister_session(
        &self,
        ufrag: &str,
        worker_id: usize,
        mi_key_mig: Option<[u8; 32]>,
    ) {
        let Some(mk) = mi_key_mig else {
            return;
        };
        if let Ok(mut idx) = self.ufrag_index.lock() {
            let matches = idx
                .get(ufrag)
                .is_some_and(|m| m.worker_id == worker_id && m.mi_key_mig == mk);
            if matches {
                idx.remove(ufrag);
            }
        }
    }

    pub(super) fn lookup_ufrag(&self, ufrag: &str) -> Option<ActiveSessionMeta> {
        self.ufrag_index
            .lock()
            .ok()
            .and_then(|idx| idx.get(ufrag).copied())
    }

    /// P0-4 fix: Bounded inbox capacity prevents memory exhaustion under same-PSK flooding.
    /// Ownership-bearing commands (`MigrateInstall` / `HandoverInstall`) bypass the cap so live
    /// `MioUdpSocket` handles are never dropped in transit.
    pub(super) fn send_cmd(&self, target_worker: usize, cmd: WorkerCmd) {
        let is_ownership_transfer = matches!(
            cmd,
            WorkerCmd::MigrateInstall { .. } | WorkerCmd::HandoverInstall { .. }
        );
        if let Some(inbox) = self.inboxes.get(target_worker) {
            if let Ok(mut q) = inbox.queue.lock() {
                if !is_ownership_transfer && q.len() >= MAX_WORKER_CMD_QUEUE {
                    return;
                }
                q.push_back(cmd);
            }
            if let Ok(w) = inbox.waker.lock() {
                if let Some(ref waker) = *w {
                    let _ = waker.wake();
                }
            }
        }
    }

    pub(super) fn drain_cmds(&self, worker_id: usize, out: &mut Vec<WorkerCmd>) {
        if let Some(inbox) = self.inboxes.get(worker_id) {
            if let Ok(mut q) = inbox.queue.lock() {
                while let Some(cmd) = q.pop_front() {
                    out.push(cmd);
                }
            }
        }
    }
}
