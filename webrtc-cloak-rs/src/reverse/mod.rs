//! 原生反向隧道模式（`webrtc-cloak reverse --entry | --agent`）。
//!
//! 适用于出口节点位于 NAT / CGNAT / 无公网入站端口环境的场景（类似反向 WireGuard，但完整伪装为
//! RFC 7983 WebRTC ICE STUN + DTLS 1.3 PFS + 双 SSRC Chrome SRTP）：
//! - **Entry 端（`--entry`，公网入口节点）**：监听公网 WebRTC 隧道端口（0 字节静默丢弃未认证探测）
//!   并暴露本地/公网 UDP 业务端口（`--expose-host:--expose-port`），按来源地址分配 `flow_id: u32`
//!   通过加密带内 `0xFFFB` 帧多路复用到已注册的反向 Agent 隧道中。
//! - **Agent 端（`--agent`，NAT/内网出口节点）**：零入站端口，启动后立即主动外拨 Entry 并常驻保活
//!   （支持 `--lane-hunt` ECMP 选路、`0xFFFC` 零中断 MBB 轮换、`0xFFFD` 1-RTT 断网/换 IP 迁移与
//!   断线自动重连），按 `flow_id` 为每个远端会话维护独立固定源端口的本地后端 UDP 套接字转发至
//!   `--backend-host:--backend-port`（原生兼容单对端反向 WireGuard 与多并发客户端 Hysteria 2 / QUIC）。

mod agent;
mod entry;
#[cfg(test)]
mod tests;

pub(crate) use self::agent::ReverseAgentMux;
pub use self::agent::{run_reverse_agent, ReverseAgentConfig};
pub(crate) use self::entry::ReverseEntryHub;
pub use self::entry::{run_reverse_entry, ReverseEntryConfig};

use mio::net::UdpSocket as MioUdpSocket;
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::Cell;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

thread_local! {
    pub(super) static REV_QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Reverse Agent 在内部 `ClientWorker` 中使用的固定逻辑隧道标识（仅做内存键，不经过操作系统）。
#[inline]
pub(crate) const fn rev_tunnel_key() -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
        1,
        0,
        0,
    ))
}

pub(super) fn log(role_tag: &str, msg: &str) {
    if !REV_QUIET.with(|q| q.get()) {
        println!("[{}] {}", role_tag, msg);
    }
}

pub(super) fn make_udp_socket(
    bind_addr: SocketAddr,
    connect_to: Option<SocketAddr>,
    buf_bytes: usize,
) -> std::io::Result<MioUdpSocket> {
    let sock = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    let _ = sock.set_reuse_address(true);
    let _ = sock.set_recv_buffer_size(buf_bytes);
    let _ = sock.set_send_buffer_size(buf_bytes);
    sock.set_nonblocking(true)?;
    sock.bind(&bind_addr.into())?;
    if let Some(target) = connect_to {
        sock.connect(&target.into())?;
    }
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(MioUdpSocket::from_std(std_sock))
}
