//! 客户端与服务端端到端集成测试公共辅助模块。

mod lane_hunt;
mod lifecycle;
mod mbb;
mod v4_audit;
mod v4_migration;
mod v4_resilience;

use std::collections::HashSet;
use std::net::UdpSocket;
use std::sync::{Mutex, OnceLock};

pub(super) fn reserve_free_port() -> u16 {
    static USED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let used = USED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = used.lock().unwrap();
    let mut held = Vec::new();
    loop {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let p = s.local_addr().unwrap().port();
        if guard.insert(p) {
            return p;
        }
        held.push(s);
    }
}
