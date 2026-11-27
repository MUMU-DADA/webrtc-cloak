//! 可选的 Linux UDP 批量收发引擎（`recvmmsg` / `sendmmsg`，通过 `--udp-batch <N>` 按需开启）。
//!
//! - 默认关闭（`udp_batch == 0`）：零额外缓冲分配，保持单包 `recv_from`/`send_to` 路径不变。
//! - 开启后（Linux，`2..=64`）：单次系统调用收发多包，大幅削减虚拟化 KVM/老架构 CPU 的
//!   KPTI/MDS 系统调用切换与 VM-exit 开销；非 Linux 平台自动平滑回退为单包收发。

use mio::net::UdpSocket as MioUdpSocket;
use std::io;
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// 预分配的批量 UDP 接收缓冲池（热路径零堆分配）。
pub struct UdpRecvBatch {
    bufs: Vec<u8>,
    slot_len: usize,
    #[cfg(target_os = "linux")]
    cap: usize,
    lens: Vec<usize>,
    peers: Vec<Option<SocketAddr>>,
    #[cfg(target_os = "linux")]
    addrs: Vec<libc::sockaddr_storage>,
    #[cfg(target_os = "linux")]
    iovs: Vec<libc::iovec>,
    #[cfg(target_os = "linux")]
    hdrs: Vec<libc::mmsghdr>,
}

impl UdpRecvBatch {
    pub fn new(cap: usize, slot_len: usize) -> Self {
        let cap = cap.max(1);
        let slot_len = slot_len.max(1);
        Self {
            bufs: vec![0u8; cap * slot_len],
            slot_len,
            #[cfg(target_os = "linux")]
            cap,
            lens: vec![0usize; cap],
            peers: vec![None; cap],
            #[cfg(target_os = "linux")]
            addrs: vec![unsafe { std::mem::zeroed() }; cap],
            #[cfg(target_os = "linux")]
            iovs: vec![unsafe { std::mem::zeroed() }; cap],
            #[cfg(target_os = "linux")]
            hdrs: vec![unsafe { std::mem::zeroed() }; cap],
        }
    }

    #[inline]
    pub fn packet(&self, idx: usize) -> &[u8] {
        let len = self.lens[idx];
        let start = idx * self.slot_len;
        &self.bufs[start..start + len]
    }

    #[inline]
    pub fn peer(&self, idx: usize) -> Option<SocketAddr> {
        self.peers[idx]
    }

    /// 从已 `connect()` 的 UDP 套接字批量收包（无需内核复制对端地址）。
    #[cfg(target_os = "linux")]
    pub fn recv_connected(&mut self, sock: &MioUdpSocket) -> io::Result<usize> {
        let fd = sock.as_raw_fd();
        for i in 0..self.cap {
            let base = unsafe { self.bufs.as_mut_ptr().add(i * self.slot_len) };
            self.iovs[i].iov_base = base as *mut libc::c_void;
            self.iovs[i].iov_len = self.slot_len;
            let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
            m.msg_hdr.msg_iov = &mut self.iovs[i] as *mut libc::iovec;
            m.msg_hdr.msg_iovlen = 1 as _;
            self.hdrs[i] = m;
        }
        loop {
            let ret = unsafe {
                libc::recvmmsg(
                    fd,
                    self.hdrs.as_mut_ptr(),
                    self.cap as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                    std::ptr::null_mut(),
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            let count = (ret as usize).min(self.cap);
            for i in 0..count {
                let flags = self.hdrs[i].msg_hdr.msg_flags;
                let n = self.hdrs[i].msg_len as usize;
                if (flags & libc::MSG_TRUNC) != 0 || n == 0 || n > self.slot_len {
                    self.lens[i] = 0;
                } else {
                    self.lens[i] = n;
                }
                self.peers[i] = None;
            }
            return Ok(count);
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn recv_connected(&mut self, sock: &MioUdpSocket) -> io::Result<usize> {
        let n = sock.recv(&mut self.bufs[..self.slot_len])?;
        self.lens[0] = n;
        self.peers[0] = None;
        Ok(1)
    }

    /// 从未连接的监听 UDP 套接字批量收包并解析每包来源地址（IPv4/IPv6）。
    #[cfg(target_os = "linux")]
    pub fn recv_from(&mut self, sock: &MioUdpSocket) -> io::Result<usize> {
        let fd = sock.as_raw_fd();
        let addr_cap = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        for i in 0..self.cap {
            let base = unsafe { self.bufs.as_mut_ptr().add(i * self.slot_len) };
            self.iovs[i].iov_base = base as *mut libc::c_void;
            self.iovs[i].iov_len = self.slot_len;
            let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
            m.msg_hdr.msg_name = (&mut self.addrs[i] as *mut libc::sockaddr_storage).cast();
            m.msg_hdr.msg_namelen = addr_cap;
            m.msg_hdr.msg_iov = &mut self.iovs[i] as *mut libc::iovec;
            m.msg_hdr.msg_iovlen = 1 as _;
            self.hdrs[i] = m;
        }
        loop {
            let ret = unsafe {
                libc::recvmmsg(
                    fd,
                    self.hdrs.as_mut_ptr(),
                    self.cap as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                    std::ptr::null_mut(),
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            let count = (ret as usize).min(self.cap);
            for i in 0..count {
                let flags = self.hdrs[i].msg_hdr.msg_flags;
                let n = self.hdrs[i].msg_len as usize;
                let addr = sockaddr_to_socket_addr(&self.addrs[i], self.hdrs[i].msg_hdr.msg_namelen);
                if (flags & libc::MSG_TRUNC) != 0 || n == 0 || n > self.slot_len || addr.is_none() {
                    self.lens[i] = 0;
                    self.peers[i] = None;
                } else {
                    self.lens[i] = n;
                    self.peers[i] = addr;
                }
            }
            return Ok(count);
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn recv_from(&mut self, sock: &MioUdpSocket) -> io::Result<usize> {
        let (n, peer) = sock.recv_from(&mut self.bufs[..self.slot_len])?;
        self.lens[0] = n;
        self.peers[0] = Some(peer);
        Ok(1)
    }
}

/// 预分配的批量 UDP 发送缓冲池（允许加解密直接原地写入待发送槽位，零拷贝）。
pub struct UdpSendBatch {
    bufs: Vec<u8>,
    slot_len: usize,
    cap: usize,
    count: usize,
    lens: Vec<usize>,
    app_bytes: Vec<u64>,
    dests: Vec<Option<SocketAddr>>,
    #[cfg(target_os = "linux")]
    addrs: Vec<libc::sockaddr_storage>,
    #[cfg(target_os = "linux")]
    addr_lens: Vec<libc::socklen_t>,
    #[cfg(target_os = "linux")]
    iovs: Vec<libc::iovec>,
    #[cfg(target_os = "linux")]
    hdrs: Vec<libc::mmsghdr>,
}

impl UdpSendBatch {
    pub fn new(cap: usize, slot_len: usize) -> Self {
        let cap = cap.max(1);
        let slot_len = slot_len.max(1);
        Self {
            bufs: vec![0u8; cap * slot_len],
            slot_len,
            cap,
            count: 0,
            lens: vec![0usize; cap],
            app_bytes: vec![0u64; cap],
            dests: vec![None; cap],
            #[cfg(target_os = "linux")]
            addrs: vec![unsafe { std::mem::zeroed() }; cap],
            #[cfg(target_os = "linux")]
            addr_lens: vec![0; cap],
            #[cfg(target_os = "linux")]
            iovs: vec![unsafe { std::mem::zeroed() }; cap],
            #[cfg(target_os = "linux")]
            hdrs: vec![unsafe { std::mem::zeroed() }; cap],
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= self.cap
    }

    /// 获取下一个可写槽位切片；若未调用 `commit_slot`，该槽位可被下次直接复用。
    #[inline]
    pub fn next_slot_mut(&mut self) -> Option<&mut [u8]> {
        if self.count >= self.cap {
            return None;
        }
        let start = self.count * self.slot_len;
        Some(&mut self.bufs[start..start + self.slot_len])
    }

    /// 读取当前未提交槽位的前 `len` 字节（用于将控制帧从临时槽位拷出）。
    #[inline]
    pub fn uncommitted_slot_prefix(&self, len: usize) -> &[u8] {
        let start = self.count * self.slot_len;
        &self.bufs[start..start + len.min(self.slot_len)]
    }

    /// 提交当前槽位（由调用方确保 `wire_len <= slot_len`）。
    #[inline]
    pub fn commit_slot(&mut self, wire_len: usize, app_len: u64, dest: Option<SocketAddr>) {
        debug_assert!(self.count < self.cap && wire_len <= self.slot_len);
        let idx = self.count;
        self.lens[idx] = wire_len;
        self.app_bytes[idx] = app_len;
        self.dests[idx] = dest;
        #[cfg(target_os = "linux")]
        if let Some(addr) = dest {
            self.addr_lens[idx] = socket_addr_to_sockaddr(addr, &mut self.addrs[idx]);
        } else {
            self.addr_lens[idx] = 0;
        }
        self.count += 1;
    }

    /// 向已 `connect()` 的 UDP 套接字批量刷新发送队列，返回 `(实际发送包数, 对应应用字节数)`。
    pub fn flush_connected(&mut self, sock: &MioUdpSocket) -> (usize, u64) {
        let n = self.count;
        if n == 0 {
            return (0, 0);
        }
        self.count = 0;
        if n == 1 {
            let ok = sock.send(&self.bufs[..self.lens[0]]).is_ok();
            return if ok { (1, self.app_bytes[0]) } else { (0, 0) };
        }
        #[cfg(target_os = "linux")]
        {
            let fd = sock.as_raw_fd();
            for i in 0..n {
                let base = unsafe { self.bufs.as_mut_ptr().add(i * self.slot_len) };
                self.iovs[i].iov_base = base as *mut libc::c_void;
                self.iovs[i].iov_len = self.lens[i];
                let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
                m.msg_hdr.msg_iov = &mut self.iovs[i] as *mut libc::iovec;
                m.msg_hdr.msg_iovlen = 1 as _;
                self.hdrs[i] = m;
            }
            let sent = sendmmsg_all(fd, &mut self.hdrs[..n]);
            let mut bytes = 0u64;
            for i in 0..sent {
                bytes = bytes.saturating_add(self.app_bytes[i]);
            }
            (sent, bytes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut sent = 0usize;
            let mut bytes = 0u64;
            for i in 0..n {
                let start = i * self.slot_len;
                if sock.send(&self.bufs[start..start + self.lens[i]]).is_ok() {
                    sent += 1;
                    bytes = bytes.saturating_add(self.app_bytes[i]);
                }
            }
            (sent, bytes)
        }
    }

    /// 向未连接的监听 UDP 套接字按每包目标地址批量刷新发送队列，返回 `(实际发送包数, 对应应用字节数)`。
    pub fn flush_to(&mut self, sock: &MioUdpSocket) -> (usize, u64) {
        let n = self.count;
        if n == 0 {
            return (0, 0);
        }
        self.count = 0;
        if n == 1 {
            let ok = self.dests[0]
                .map(|d| sock.send_to(&self.bufs[..self.lens[0]], d).is_ok())
                .unwrap_or(false);
            return if ok { (1, self.app_bytes[0]) } else { (0, 0) };
        }
        #[cfg(target_os = "linux")]
        {
            let fd = sock.as_raw_fd();
            for i in 0..n {
                let base = unsafe { self.bufs.as_mut_ptr().add(i * self.slot_len) };
                self.iovs[i].iov_base = base as *mut libc::c_void;
                self.iovs[i].iov_len = self.lens[i];
                let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
                m.msg_hdr.msg_name = (&mut self.addrs[i] as *mut libc::sockaddr_storage).cast();
                m.msg_hdr.msg_namelen = self.addr_lens[i];
                m.msg_hdr.msg_iov = &mut self.iovs[i] as *mut libc::iovec;
                m.msg_hdr.msg_iovlen = 1 as _;
                self.hdrs[i] = m;
            }
            let sent = sendmmsg_all(fd, &mut self.hdrs[..n]);
            let mut bytes = 0u64;
            for i in 0..sent {
                bytes = bytes.saturating_add(self.app_bytes[i]);
            }
            (sent, bytes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut sent = 0usize;
            let mut bytes = 0u64;
            for i in 0..n {
                let start = i * self.slot_len;
                if let Some(d) = self.dests[i] {
                    if sock.send_to(&self.bufs[start..start + self.lens[i]], d).is_ok() {
                        sent += 1;
                        bytes = bytes.saturating_add(self.app_bytes[i]);
                    }
                }
            }
            (sent, bytes)
        }
    }
}

#[cfg(target_os = "linux")]
fn sendmmsg_all(fd: libc::c_int, hdrs: &mut [libc::mmsghdr]) -> usize {
    let total = hdrs.len();
    loop {
        let ret = unsafe {
            libc::sendmmsg(
                fd,
                hdrs.as_mut_ptr(),
                total as libc::c_uint,
                libc::MSG_DONTWAIT as _,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return 0;
        }
        return (ret as usize).min(total);
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    let family = storage.ss_family as libc::c_int;
    if family == libc::AF_INET {
        if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
            return None;
        }
        let sin = unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
        let port = u16::from_be(sin.sin_port);
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if family == libc::AF_INET6 {
        if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
            return None;
        }
        let sin6 =
            unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
        let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        let port = u16::from_be(sin6.sin6_port);
        Some(SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            sin6.sin6_flowinfo,
            sin6.sin6_scope_id,
        )))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn socket_addr_to_sockaddr(
    addr: SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    *storage = unsafe { std::mem::zeroed() };
    match addr.ip() {
        IpAddr::V4(v4) => {
            let sin = unsafe { &mut *(storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = addr.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.octets()),
            };
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        IpAddr::V6(v6) => {
            let SocketAddr::V6(sa6) = addr else {
                unreachable!()
            };
            let sin6 =
                unsafe { &mut *(storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = sa6.port().to_be();
            sin6.sin6_flowinfo = sa6.flowinfo();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.octets(),
            };
            sin6.sin6_scope_id = sa6.scope_id();
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// 格式化启动日志中的 `--udp-batch` 状态描述。
pub fn format_udp_batch_mode(udp_batch: usize) -> String {
    if udp_batch <= 1 {
        "off".to_string()
    } else if cfg!(target_os = "linux") {
        format!("on(size={})", udp_batch)
    } else {
        format!("off(requested={},linux-only)", udp_batch)
    }
}

/// 判断当前平台与配置是否启用批量收发路径（非 Linux 生产构建自动关闭；测试模式允许演练批处理状态机）。
#[inline]
pub const fn is_udp_batch_active(udp_batch: usize) -> bool {
    (cfg!(target_os = "linux") || cfg!(test)) && udp_batch > 1
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[cfg(target_os = "linux")]
    #[test]
    fn sockaddr_roundtrip_ipv4_and_ipv6() {
        let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)), 19643);
        let l4 = socket_addr_to_sockaddr(v4, &mut st);
        assert_eq!(sockaddr_to_socket_addr(&st, l4), Some(v4));

        let v6 = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::42".parse::<Ipv6Addr>().unwrap(),
            19643,
            0x12345,
            3,
        ));
        let l6 = socket_addr_to_sockaddr(v6, &mut st);
        assert_eq!(sockaddr_to_socket_addr(&st, l6), Some(v6));
    }

    #[test]
    fn batch_send_and_recv_loopback_ipv4() {
        let rx_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_std.set_nonblocking(true).unwrap();
        let rx_addr = rx_std.local_addr().unwrap();
        let rx_sock = MioUdpSocket::from_std(rx_std);

        let tx_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        tx_std.set_nonblocking(true).unwrap();
        let tx_addr = tx_std.local_addr().unwrap();
        let tx_sock = MioUdpSocket::from_std(tx_std);

        let mut tx = UdpSendBatch::new(16, 2048);
        for i in 0..8usize {
            let msg = format!("batch-pkt-{:02}", i);
            let slot = tx.next_slot_mut().unwrap();
            slot[..msg.len()].copy_from_slice(msg.as_bytes());
            tx.commit_slot(msg.len(), msg.len() as u64, Some(rx_addr));
        }
        let (sent, bytes) = tx.flush_to(&tx_sock);
        assert_eq!(sent, 8);
        assert_eq!(bytes, 8 * 12);
        assert!(tx.is_empty());

        let mut rx = UdpRecvBatch::new(16, 2048);
        let mut got = Vec::new();
        for _ in 0..20 {
            match rx.recv_from(&rx_sock) {
                Ok(n) => {
                    for i in 0..n {
                        assert_eq!(rx.peer(i), Some(tx_addr));
                        got.push(String::from_utf8(rx.packet(i).to_vec()).unwrap());
                    }
                    if got.len() >= 8 {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(e) => panic!("recv_from failed: {}", e),
            }
        }
        assert_eq!(got.len(), 8);
        for (i, item) in got.iter().enumerate() {
            assert_eq!(item, &format!("batch-pkt-{:02}", i));
        }
    }
}
