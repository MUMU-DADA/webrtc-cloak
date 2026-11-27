//! 内嵌类 Hysteria 2 代理模式（`webrtc-cloak proxy --client | --server`）。
//!
//! 架构分层：
//! - **外层传输（零改动复用）**：WebRTC-Cloak 完整 ICE STUN + DTLS 1.3 PFS + Dual-SSRC SRTP +
//!   0ms MBB + 1-RTT 黑洞迁移 + Lane Hunt（中继节点 `relay --upstream-mode cloak` 透明无感）。
//! - **内层传输（进程内 Sans-IO 零回环）**：嵌入式 `quinn-proto`（自定义 No-op 加密后端，零 `rustls`、
//!   零二次 AEAD、零 16B Tag 开销）+ Hysteria 2 风格 Brutal 丢包补偿恒速拥塞控制 +
//!   RFC 9221 不可靠 QUIC Datagram 透明 UDP 转发。
//! - **业务入口/出口**：客户端直接提供本地 SOCKS5（TCP + UDP Associate）与可重复的 L4 TCP 端口转发
//!   （如 `127.0.0.1:19443 → 198.51.100.10:443`）；服务端直接以非阻塞 `mio` 出站 TCP/UDP 配合独立异步 DNS 池
//!   与 CIDR ACL，彻底消除外部 `hysteria-server` 与 `lo` 回环内核开销。
//! - **完全可选**：不影响现有 `client` / `server` / `relay` / `reverse` / `bypass` 外挂 Hy2/WG 透传场景。

pub mod brutal;
mod client;
pub mod proto;
pub mod quic_crypto;
mod server;
#[cfg(test)]
mod tests;

pub(crate) use self::client::ProxyClientEngine;
pub use self::client::{
    run_proxy_client, run_proxy_client_reverse, ProxyClientConfig, ReverseProxyClientConfig,
};
pub use self::proto::{
    parse_bandwidth_bps, parse_tcp_forward_rule, AclConfig, AclRule, TcpForwardRule,
};
pub(crate) use self::server::ProxyServerEngine;
pub use self::server::{
    run_proxy_server, run_proxy_server_reverse, ProxyServerConfig, ReverseProxyServerConfig,
};

use mio::net::UdpSocket as MioUdpSocket;
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::Cell;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

thread_local! {
    pub(super) static PROXY_QUIET: Cell<bool> = const { Cell::new(false) };
}

/// 代理客户端在内部 `ClientWorker` 中使用的固定逻辑隧道键（纯内存键，不经过操作系统）。
#[inline]
pub(crate) const fn proxy_tunnel_key() -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        1,
        0,
        0,
    ))
}

/// 内嵌 `quinn-proto` 客户端侧使用的固定逻辑远端地址（纯状态机标识，不经过操作系统）。
#[inline]
pub(super) const fn proxy_quic_peer_addr() -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3),
        443,
        0,
        0,
    ))
}

pub(super) fn log(role_tag: &str, msg: &str) {
    if !PROXY_QUIET.with(|q| q.get()) {
        println!("[{}] {}", role_tag, msg);
    }
}

pub(super) fn make_udp_socket(
    bind_addr: SocketAddr,
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
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(MioUdpSocket::from_std(std_sock))
}
