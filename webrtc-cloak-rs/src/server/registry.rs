//! 服务端 STUN 防重放缓存与跨 worker 会话迁移注册表。

use super::ServerSession;
use mio::net::UdpSocket as MioUdpSocket;
use mio::Waker;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 服务端缓存的单条 STUN 应答报文最大字节数（IPv4 固定 64B / IPv6 固定 76B）。
const STUN_CACHED_REPLY_MAX_LEN: usize = 80;
/// 跨 worker 共享 STUN 事务 ID 防重放缓存条目存活时间（秒）。
const SEEN_TXID_TTL: Duration = Duration::from_secs(90);
/// 合法同端同 txid UDP 丢包重传的缓存应答有效窗口（2.5 秒，仅用于 DTLS 前初始握手抗单包丢失）。
const SEEN_TXID_RETRANSMIT_WINDOW: Duration = Duration::from_millis(2500);
/// 单条 STUN txid 在重传窗口内允许返回缓存应答的最大次数（收紧至 2 次）。
const MAX_STUN_RETRANSMITS: u8 = 2;
/// 共享 STUN 事务 ID 防重放缓存最大条目数。
const SEEN_TXID_CAP: usize = 65_536;
/// v0.7 抽卡共享 ufrag 未锁定前允许同源 IP 并发探针的活跃测速窗口（秒）。
const HUNT_UFRAG_ACTIVE_TTL: Duration = Duration::from_secs(4);
/// v0.7 抽卡共享 ufrag 未锁定条目墓碑留存时长（20 秒 > ±10s STUN 新鲜度窗口，彻底封堵过期后跨 IP/同 IP 重放）。
const HUNT_UFRAG_TOMBSTONE_TTL: Duration = Duration::from_secs(20);
/// v0.7 抽卡共享 ufrag 提名锁定或会话销毁后的反重放墓碑时长（90 秒）。
const HUNT_UFRAG_LOCKED_TTL: Duration = Duration::from_secs(90);
/// 单次抽卡共享 ufrag 未锁定前允许的最大探针数（覆盖 4 轮 × 4 探针）。
const HUNT_UFRAG_MAX_PROBES: u8 = 16;
/// 共享抽卡 ufrag 表容量上限。
const HUNT_UFRAG_CAP: usize = 16_384;
/// 单个 worker 跨线程非所有权移交控制指令队列上限，防内存耗尽。
const MAX_WORKER_CMD_QUEUE: usize = 4096;

pub(crate) enum TxidCheck {
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
pub(crate) struct SeenTxidCache {
    map: HashMap<[u8; 12], TxidEntry>,
    order: VecDeque<([u8; 12], Instant)>,
}

impl SeenTxidCache {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn check(
        &mut self,
        txid: [u8; 12],
        peer: SocketAddr,
        now: Instant,
        allow_retransmit: bool,
    ) -> TxidCheck {
        self.check_with_limit(txid, peer, now, allow_retransmit, MAX_STUN_RETRANSMITS)
    }

    pub(crate) fn check_with_limit(
        &mut self,
        txid: [u8; 12],
        peer: SocketAddr,
        now: Instant,
        allow_retransmit: bool,
        max_retransmits: u8,
    ) -> TxidCheck {
        self.evict_expired(now);
        if let Some(entry) = self.map.get_mut(&txid) {
            if allow_retransmit
                && max_retransmits > 0
                && entry.peer == peer
                && now.duration_since(entry.seen_at) <= SEEN_TXID_RETRANSMIT_WINDOW
                && entry.retransmits < max_retransmits
            {
                entry.retransmits += 1;
                return TxidCheck::Retransmit(entry.cached_reply, entry.cached_len);
            }
            return TxidCheck::Rejected;
        }
        TxidCheck::Fresh
    }

    /// Permanently burn a recorded `txid` (e.g. once DTLS begins or for single-use hunt probes)
    /// so subsequent replays from even the exact same 5-tuple return `TxidCheck::Rejected`.
    pub(crate) fn invalidate(&mut self, txid: [u8; 12]) {
        if let Some(entry) = self.map.get_mut(&txid) {
            entry.retransmits = u8::MAX;
        }
    }

    pub(crate) fn record_single_use(&mut self, txid: [u8; 12], peer: SocketAddr, now: Instant) {
        self.record(txid, peer, now, &[]);
        self.invalidate(txid);
    }

    pub(crate) fn record(&mut self, txid: [u8; 12], peer: SocketAddr, now: Instant, resp: &[u8]) {
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

#[derive(Clone, Copy)]
struct HuntUfragEntry {
    src_ip: IpAddr,
    first_seen: Instant,
    locked_peer: Option<SocketAddr>,
    locked_at: Option<Instant>,
    probes_seen: u8,
    tombstoned: bool,
}

struct HuntUfragTable {
    map: HashMap<String, HuntUfragEntry>,
    order: VecDeque<(String, Instant)>,
}

impl HuntUfragTable {
    fn new() -> Self {
        Self {
            map: HashMap::with_capacity(16),
            order: VecDeque::with_capacity(16),
        }
    }

    fn is_expired(e: &HuntUfragEntry, now: Instant) -> bool {
        if let Some(la) = e.locked_at {
            now.duration_since(la) > HUNT_UFRAG_LOCKED_TTL
        } else {
            now.duration_since(e.first_seen) > HUNT_UFRAG_TOMBSTONE_TTL
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        while let Some((ufrag, ts)) = self.order.front() {
            let expired = self
                .map
                .get(ufrag)
                .map(|e| e.first_seen == *ts && Self::is_expired(e, now))
                .unwrap_or(true);
            if expired {
                let (u, t) = self.order.pop_front().unwrap();
                if let Some(e) = self.map.get(&u) {
                    if e.first_seen == t && Self::is_expired(e, now) {
                        self.map.remove(&u);
                    }
                }
            } else {
                break;
            }
        }
    }

    fn ensure_cap(&mut self) {
        while self.map.len() >= HUNT_UFRAG_CAP {
            if let Some((old_u, old_ts)) = self.order.pop_front() {
                if self.map.get(&old_u).is_some_and(|e| e.first_seen == old_ts) {
                    self.map.remove(&old_u);
                }
            } else {
                break;
            }
        }
    }
}

pub(crate) struct SharedV4Registry {
    ufrag_index: Mutex<HashMap<String, ActiveSessionMeta>>,
    hunt_ufrags: Mutex<HuntUfragTable>,
    inboxes: Vec<WorkerInbox>,
}

impl SharedV4Registry {
    pub(crate) fn new(workers: usize) -> Self {
        let mut inboxes = Vec::with_capacity(workers);
        for _ in 0..workers {
            inboxes.push(WorkerInbox {
                queue: Mutex::new(VecDeque::new()),
                waker: Mutex::new(None),
            });
        }
        Self {
            ufrag_index: Mutex::new(HashMap::with_capacity(16)),
            hunt_ufrags: Mutex::new(HuntUfragTable::new()),
            inboxes,
        }
    }

    /// v0.7 RFC 8445 connectivity check gate (`USE-CANDIDATE = false`):
    /// Permits parallel same-`ufrag` probes ONLY from the same source IP within `4s` and BEFORE
    /// nomination locks that `ufrag`. Unnominated entries remain tombstoned for `20s` (> ±10s STUN
    /// freshness window) so expired entries can NEVER be deleted-and-reinserted by a delayed replay.
    pub(super) fn allow_hunt_probe(&self, ufrag: &str, peer: SocketAddr, now: Instant) -> bool {
        if self.lookup_ufrag(ufrag).is_some() {
            return false;
        }
        let Ok(mut tbl) = self.hunt_ufrags.lock() else {
            return false;
        };
        tbl.evict_expired(now);
        if let Some(entry) = tbl.map.get_mut(ufrag) {
            if HuntUfragTable::is_expired(entry, now) {
                tbl.map.remove(ufrag);
            } else {
                if entry.tombstoned
                    || entry.locked_peer.is_some()
                    || entry.src_ip != peer.ip()
                    || now.duration_since(entry.first_seen) > HUNT_UFRAG_ACTIVE_TTL
                    || entry.probes_seen >= HUNT_UFRAG_MAX_PROBES
                {
                    return false;
                }
                entry.probes_seen = entry.probes_seen.saturating_add(1);
                return true;
            }
        }
        tbl.ensure_cap();
        tbl.map.insert(
            ufrag.to_string(),
            HuntUfragEntry {
                src_ip: peer.ip(),
                first_seen: now,
                locked_peer: None,
                locked_at: None,
                probes_seen: 1,
                tombstoned: false,
            },
        );
        tbl.order.push_back((ufrag.to_string(), now));
        true
    }

    /// v0.7 RFC 8445 nomination lock (`USE-CANDIDATE = true`):
    /// Locks `ufrag` exclusively to `peer` for 90s, instantly invalidating every unused sibling
    /// probe from the same `--lane-hunt` batch across all workers and source IPs/ports.
    pub(super) fn lock_hunt_ufrag(&self, ufrag: &str, peer: SocketAddr, now: Instant) -> bool {
        let Ok(mut tbl) = self.hunt_ufrags.lock() else {
            return false;
        };
        tbl.evict_expired(now);
        if let Some(entry) = tbl.map.get_mut(ufrag) {
            if !HuntUfragTable::is_expired(entry, now) {
                if entry.tombstoned {
                    return false;
                }
                if let Some(lp) = entry.locked_peer {
                    if lp != peer {
                        return false;
                    }
                    entry.locked_at = Some(now);
                    return true;
                }
                if entry.src_ip != peer.ip() {
                    return false;
                }
                entry.locked_peer = Some(peer);
                entry.locked_at = Some(now);
                entry.probes_seen = u8::MAX;
                return true;
            }
            tbl.map.remove(ufrag);
        }
        tbl.ensure_cap();
        tbl.map.insert(
            ufrag.to_string(),
            HuntUfragEntry {
                src_ip: peer.ip(),
                first_seen: now,
                locked_peer: Some(peer),
                locked_at: Some(now),
                probes_seen: u8::MAX,
                tombstoned: false,
            },
        );
        tbl.order.push_back((ufrag.to_string(), now));
        true
    }

    /// Tombstone a closed/rotated session `ufrag` for 90s so withheld probes or keepalives can
    /// never reopen or probe the server even after a session outlived its initial nomination lock.
    pub(super) fn tombstone_ufrag(&self, ufrag: &str, now: Instant) {
        let Ok(mut tbl) = self.hunt_ufrags.lock() else {
            return;
        };
        tbl.evict_expired(now);
        tbl.ensure_cap();
        tbl.map.insert(
            ufrag.to_string(),
            HuntUfragEntry {
                src_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                first_seen: now,
                locked_peer: None,
                locked_at: Some(now),
                probes_seen: u8::MAX,
                tombstoned: true,
            },
        );
        tbl.order.push_back((ufrag.to_string(), now));
    }

    pub(crate) fn set_waker(&self, worker_id: usize, waker: Arc<Waker>) {
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
    /// Also re-tombstones `ufrag` for 90s on removal so >90s-old closed sessions cannot be probed.
    pub(super) fn unregister_session(
        &self,
        ufrag: &str,
        worker_id: usize,
        mi_key_mig: Option<[u8; 32]>,
    ) {
        let Some(mk) = mi_key_mig else {
            return;
        };
        let mut removed = false;
        if let Ok(mut idx) = self.ufrag_index.lock() {
            let matches = idx
                .get(ufrag)
                .is_some_and(|m| m.worker_id == worker_id && m.mi_key_mig == mk);
            if matches {
                idx.remove(ufrag);
                removed = true;
            }
        }
        if removed {
            self.tombstone_ufrag(ufrag, Instant::now());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn r2_hunt_ufrag_tombstone_and_post_close_lock() {
        let reg = SharedV4Registry::new(1);
        let p_a1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 40001);
        let p_a2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 40002);
        let p_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50001);
        let t0 = Instant::now();

        // 1. Same-IP probes within active window (4s) allowed; cross-IP rejected.
        assert!(reg.allow_hunt_probe("abcd:efgh", p_a1, t0));
        assert!(reg.allow_hunt_probe("abcd:efgh", p_a2, t0 + Duration::from_secs(1)));
        assert!(!reg.allow_hunt_probe("abcd:efgh", p_b, t0 + Duration::from_secs(1)));

        // 2. After active window (4s) but within tombstone window (20s > STUN ±10s):
        //    BOTH same-IP and cross-IP MUST be rejected (no delete-and-reinsert at 6.6s!).
        let t_66 = t0 + Duration::from_millis(6600);
        assert!(!reg.allow_hunt_probe("abcd:efgh", p_a2, t_66));
        assert!(!reg.allow_hunt_probe("abcd:efgh", p_b, t_66));
        assert!(!reg.allow_hunt_probe("abcd:efgh", p_b, t0 + Duration::from_secs(15)));

        // 3. Post-close tombstone: unregister_session re-tombstones the ufrag for 90s even if
        //    its initial nomination lock expired hours earlier.
        let mk = [0x5Au8; 32];
        reg.register_session("live:sess", 0, mk, [1u8; 8]);
        assert!(!reg.allow_hunt_probe("live:sess", p_a1, t0));
        reg.unregister_session("live:sess", 0, Some(mk));
        let now = Instant::now();
        assert!(
            !reg.allow_hunt_probe("live:sess", p_a1, now + Duration::from_secs(1)),
            "unregistered ufrag MUST stay tombstoned against same-IP probes"
        );
        assert!(
            !reg.allow_hunt_probe("live:sess", p_b, now + Duration::from_secs(10)),
            "unregistered ufrag MUST stay tombstoned against cross-IP probes"
        );
        assert!(
            !reg.lock_hunt_ufrag("live:sess", p_a1, now + Duration::from_secs(10)),
            "unregistered tombstoned ufrag MUST NOT be re-locked"
        );
    }
}
