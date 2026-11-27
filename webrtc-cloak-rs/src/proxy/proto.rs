//! 内嵌类 Hy2 代理协议线格式、带宽解析、UDP 分片重组与 CIDR ACL 规则引擎。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Control Stream 握手魔数（"WC" + v1）。
pub const CTRL_HELLO_MAGIC: [u8; 3] = [0x57, 0x43, 0x01];
/// Control Stream 握手固定长度（3B 魔数 + 8B up_bps + 8B down_bps = 19B）。
pub const CTRL_HELLO_LEN: usize = 19;

/// TCP 代理双向流请求命令码。
pub const STREAM_CMD_TCP: u8 = 0x01;

/// 服务端对 TCP 流请求的响应状态码。
pub const STREAM_STATUS_OK: u8 = 0x00;
pub const STREAM_STATUS_ACL_DENIED: u8 = 0x01;
pub const STREAM_STATUS_CONNECT_FAILED: u8 = 0x02;

/// RFC 1928 地址类型常量（复用于内层流头、UDP 报头与本地 SOCKS5）。
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// 内层地址最大域名长度（字节）。
pub const MAX_DOMAIN_LEN: usize = 255;

/// UDP 分片重组缓存上限（防止畸形分片耗尽内存）。
const MAX_FRAG_ENTRIES: usize = 64;
/// UDP 分片重组超时（秒）。
const FRAG_TTL: Duration = Duration::from_secs(2);

// ============================================================================
// 目标地址编码 / 解码（与 RFC 1928 SOCKS5 线格式一致）
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetAddr {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Self::V6(*v6.ip(), v6.port()),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::V4(ip, port) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::V6(ip, port) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Domain(host, port) => {
                let bytes = host.as_bytes();
                let n = bytes.len().min(MAX_DOMAIN_LEN);
                out.push(ATYP_DOMAIN);
                out.push(n as u8);
                out.extend_from_slice(&bytes[..n]);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// 尝试从 `buf` 头部解析地址：
    /// - `Ok(Some((addr, consumed)))`: 解析成功；
    /// - `Ok(None)`: 字节尚不完整，等待更多数据；
    /// - `Err(())`: 非法地址类型或无效 UTF-8。
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>, ()> {
        if buf.is_empty() {
            return Ok(None);
        }
        match buf[0] {
            ATYP_IPV4 => {
                if buf.len() < 7 {
                    return Ok(None);
                }
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok(Some((Self::V4(ip, port), 7)))
            }
            ATYP_IPV6 => {
                if buf.len() < 19 {
                    return Ok(None);
                }
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(oct);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok(Some((Self::V6(ip, port), 19)))
            }
            ATYP_DOMAIN => {
                if buf.len() < 2 {
                    return Ok(None);
                }
                let dlen = buf[1] as usize;
                if dlen == 0 {
                    return Err(());
                }
                let total = 2 + dlen + 2;
                if buf.len() < total {
                    return Ok(None);
                }
                let host = std::str::from_utf8(&buf[2..2 + dlen])
                    .map_err(|_| ())?
                    .to_string();
                let port = u16::from_be_bytes([buf[2 + dlen], buf[2 + dlen + 1]]);
                Ok(Some((Self::Domain(host, port), total)))
            }
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(ip, p) => write!(f, "{}:{}", ip, p),
            Self::V6(ip, p) => write!(f, "[{}]:{}", ip, p),
            Self::Domain(h, p) => write!(f, "{}:{}", h, p),
        }
    }
}

// ============================================================================
// Control Stream 带宽协商帧（19B）
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtrlHello {
    pub up_bps: u64,
    pub down_bps: u64,
}

impl CtrlHello {
    pub fn encode(&self) -> [u8; CTRL_HELLO_LEN] {
        let mut out = [0u8; CTRL_HELLO_LEN];
        out[0..3].copy_from_slice(&CTRL_HELLO_MAGIC);
        out[3..11].copy_from_slice(&self.up_bps.to_be_bytes());
        out[11..19].copy_from_slice(&self.down_bps.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < CTRL_HELLO_LEN || buf[0..3] != CTRL_HELLO_MAGIC {
            return None;
        }
        let up_bps = u64::from_be_bytes(buf[3..11].try_into().ok()?);
        let down_bps = u64::from_be_bytes(buf[11..19].try_into().ok()?);
        Some(Self { up_bps, down_bps })
    }
}

// ============================================================================
// RFC 9221 QUIC Datagram UDP 透传帧（支持超长包 2 片自动分片/重组）
// ============================================================================

/// 帧格式：`[session_id: u32 BE, frag_id: u16 BE, frag_idx: u8, frag_cnt: u8, addr..., payload...]`
pub const UDP_FRAME_FIXED_HDR: usize = 8;

pub fn encode_udp_datagrams(
    session_id: u32,
    frag_id: u16,
    addr: &TargetAddr,
    payload: &[u8],
    max_dgram_len: usize,
) -> Vec<Vec<u8>> {
    let mut addr_buf = Vec::with_capacity(32);
    addr.encode(&mut addr_buf);
    let hdr_len = UDP_FRAME_FIXED_HDR + addr_buf.len();
    if max_dgram_len <= hdr_len + 16 {
        return Vec::new();
    }
    let max_chunk = max_dgram_len - hdr_len;
    if payload.len() <= max_chunk {
        let mut pkt = Vec::with_capacity(hdr_len + payload.len());
        pkt.extend_from_slice(&session_id.to_be_bytes());
        pkt.extend_from_slice(&frag_id.to_be_bytes());
        pkt.push(0);
        pkt.push(1);
        pkt.extend_from_slice(&addr_buf);
        pkt.extend_from_slice(payload);
        return vec![pkt];
    }
    // 最多分 2 片（覆盖 <= 2500B 超长 DNSSEC / QUIC 报文，避免放大）
    if payload.len() > max_chunk * 2 {
        return Vec::new();
    }
    let mid = payload.len() / 2;
    let mut out = Vec::with_capacity(2);
    for (idx, chunk) in [&payload[..mid], &payload[mid..]].iter().enumerate() {
        let mut pkt = Vec::with_capacity(hdr_len + chunk.len());
        pkt.extend_from_slice(&session_id.to_be_bytes());
        pkt.extend_from_slice(&frag_id.to_be_bytes());
        pkt.push(idx as u8);
        pkt.push(2);
        pkt.extend_from_slice(&addr_buf);
        pkt.extend_from_slice(chunk);
        out.push(pkt);
    }
    out
}

pub struct DecodedUdpFrame<'a> {
    pub session_id: u32,
    pub frag_id: u16,
    pub frag_idx: u8,
    pub frag_cnt: u8,
    pub addr: TargetAddr,
    pub payload: &'a [u8],
}

pub fn decode_udp_datagram(buf: &[u8]) -> Option<DecodedUdpFrame<'_>> {
    if buf.len() <= UDP_FRAME_FIXED_HDR {
        return None;
    }
    let session_id = u32::from_be_bytes(buf[0..4].try_into().ok()?);
    let frag_id = u16::from_be_bytes(buf[4..6].try_into().ok()?);
    let frag_idx = buf[6];
    let frag_cnt = buf[7];
    if frag_cnt == 0 || frag_cnt > 2 || frag_idx >= frag_cnt {
        return None;
    }
    let (addr, alen) = TargetAddr::decode(&buf[UDP_FRAME_FIXED_HDR..]).ok()??;
    let payload = &buf[UDP_FRAME_FIXED_HDR + alen..];
    Some(DecodedUdpFrame {
        session_id,
        frag_id,
        frag_idx,
        frag_cnt,
        addr,
        payload,
    })
}

struct PendingFrag {
    created_at: Instant,
    addr: TargetAddr,
    first_idx: u8,
    part: Vec<u8>,
}

/// 轻量 2 片 UDP 重组器（有容量硬上限与 2 秒 TTL）。
#[derive(Default)]
pub struct UdpFragReassembler {
    pending: HashMap<(u32, u16), PendingFrag>,
}

impl UdpFragReassembler {
    pub fn push(
        &mut self,
        frame: DecodedUdpFrame<'_>,
        now: Instant,
    ) -> Option<(u32, TargetAddr, Vec<u8>)> {
        if frame.frag_cnt == 1 {
            return Some((frame.session_id, frame.addr, frame.payload.to_vec()));
        }
        let key = (frame.session_id, frame.frag_id);
        if let Some(prev) = self.pending.remove(&key) {
            if now.saturating_duration_since(prev.created_at) <= FRAG_TTL
                && prev.first_idx != frame.frag_idx
            {
                let mut combined = Vec::with_capacity(prev.part.len() + frame.payload.len());
                if prev.first_idx == 0 {
                    combined.extend_from_slice(&prev.part);
                    combined.extend_from_slice(frame.payload);
                } else {
                    combined.extend_from_slice(frame.payload);
                    combined.extend_from_slice(&prev.part);
                }
                return Some((frame.session_id, prev.addr, combined));
            }
        }
        if self.pending.len() >= MAX_FRAG_ENTRIES {
            self.gc(now);
            if self.pending.len() >= MAX_FRAG_ENTRIES {
                if let Some(&oldest) = self
                    .pending
                    .iter()
                    .min_by_key(|(_, v)| v.created_at)
                    .map(|(k, _)| k)
                {
                    self.pending.remove(&oldest);
                }
            }
        }
        self.pending.insert(
            key,
            PendingFrag {
                created_at: now,
                addr: frame.addr,
                first_idx: frame.frag_idx,
                part: frame.payload.to_vec(),
            },
        );
        None
    }

    pub fn gc(&mut self, now: Instant) {
        self.pending
            .retain(|_, v| now.saturating_duration_since(v.created_at) <= FRAG_TTL);
    }
}

// ============================================================================
// 带宽字符串解析 & L4 TCP 转发规则解析
// ============================================================================

/// 解析人性化带宽字符串为 bit/s（支持 `100m`、`420 Mbps`、`500mbps`、`1g`、`50000k`、`100000000`）。
pub fn parse_bandwidth_bps(input: &str) -> Result<u64, String> {
    let cleaned: String = input
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if cleaned.is_empty() {
        return Err("empty bandwidth value".to_string());
    }
    let (num_str, mult): (&str, u64) = if let Some(s) = cleaned.strip_suffix("gbps") {
        (s, 1_000_000_000)
    } else if let Some(s) = cleaned.strip_suffix("mbps") {
        (s, 1_000_000)
    } else if let Some(s) = cleaned.strip_suffix("kbps") {
        (s, 1_000)
    } else if let Some(s) = cleaned.strip_suffix("bps") {
        (s, 1)
    } else if let Some(s) = cleaned.strip_suffix('g') {
        (s, 1_000_000_000)
    } else if let Some(s) = cleaned.strip_suffix('m') {
        (s, 1_000_000)
    } else if let Some(s) = cleaned.strip_suffix('k') {
        (s, 1_000)
    } else {
        (cleaned.as_str(), 1)
    };
    let val: f64 = num_str
        .parse()
        .map_err(|_| format!("invalid bandwidth: '{}'", input))?;
    if !val.is_finite() || val <= 0.0 {
        return Err(format!("bandwidth must be positive: '{}'", input));
    }
    let bps = (val * mult as f64).round() as u64;
    Ok(bps.max(512_000))
}

/// 客户端固定 L4 TCP 端口转发规则（`LOCAL_IP:PORT=REMOTE_HOST:PORT`，如 `127.0.0.1:19443=198.51.100.10:443`）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpForwardRule {
    pub listen: SocketAddr,
    pub target: TargetAddr,
}

pub fn parse_tcp_forward_rule(spec: &str) -> Result<TcpForwardRule, String> {
    let (lhs, rhs) = spec
        .split_once('=')
        .ok_or_else(|| format!("invalid --tcp-forward '{}': expected LISTEN=TARGET", spec))?;
    let listen: SocketAddr = lhs
        .trim()
        .parse()
        .map_err(|_| format!("invalid --tcp-forward listen addr '{}'", lhs.trim()))?;
    let target = parse_target_addr_str(rhs.trim())?;
    Ok(TcpForwardRule { listen, target })
}

pub fn parse_target_addr_str(s: &str) -> Result<TargetAddr, String> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(TargetAddr::from_socket_addr(sa));
    }
    let (host, port_s) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid target address '{}': expected HOST:PORT", s))?;
    let port: u16 = port_s
        .parse()
        .map_err(|_| format!("invalid port in '{}'", s))?;
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || host.len() > MAX_DOMAIN_LEN {
        return Err(format!("invalid host in '{}'", s));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(TargetAddr::from_socket_addr(SocketAddr::new(ip, port)))
    } else {
        Ok(TargetAddr::Domain(host.to_string(), port))
    }
}

// ============================================================================
// 服务端出站 CIDR ACL 规则引擎（先匹配 allow，再匹配 deny / reject_private）
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpNet {
    V4(u32, u32),
    V6(u128, u128),
}

impl IpNet {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim().trim_start_matches('[').trim_end_matches(']');
        if let Some((ip_s, prefix_s)) = s.split_once('/') {
            let ip: IpAddr = ip_s
                .parse()
                .map_err(|_| format!("invalid CIDR IP '{}'", s))?;
            let prefix: u32 = prefix_s
                .parse()
                .map_err(|_| format!("invalid CIDR prefix '{}'", s))?;
            match ip {
                IpAddr::V4(v4) if prefix <= 32 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    };
                    Ok(Self::V4(u32::from(v4) & mask, mask))
                }
                IpAddr::V6(v6) if prefix <= 128 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    };
                    Ok(Self::V6(u128::from(v6) & mask, mask))
                }
                _ => Err(format!("CIDR prefix out of range '{}'", s)),
            }
        } else {
            let ip: IpAddr = s.parse().map_err(|_| format!("invalid IP '{}'", s))?;
            match ip {
                IpAddr::V4(v4) => Ok(Self::V4(u32::from(v4), u32::MAX)),
                IpAddr::V6(v6) => Ok(Self::V6(u128::from(v6), u128::MAX)),
            }
        }
    }

    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (Self::V4(net, mask), IpAddr::V4(v4)) => (u32::from(v4) & mask) == net,
            (Self::V6(net, mask), IpAddr::V6(v6)) => (u128::from(v6) & mask) == net,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AclRule {
    pub net: IpNet,
    pub port: Option<u16>,
}

impl AclRule {
    /// 支持格式：`10.0.0.10/32:8443`、`10.0.0.10:8443`、`198.51.100.0/24`、`[::1]/128:8443`、`::1/128`
    pub fn parse(spec: &str) -> Result<Self, String> {
        let s = spec.trim();
        // 处理带括号 IPv6 + 可选端口，如 `[::1]:443` 或 `[fc00::/7]:443`
        if let Some(rest) = s.strip_prefix('[') {
            let (inside, tail) = rest
                .split_once(']')
                .ok_or_else(|| format!("unclosed '[' in ACL rule '{}'", s))?;
            let net = IpNet::parse(inside)?;
            let port = if tail.is_empty() {
                None
            } else if let Some(p_s) = tail.strip_prefix(':') {
                Some(
                    p_s.parse::<u16>()
                        .map_err(|_| format!("invalid port in ACL rule '{}'", s))?,
                )
            } else {
                return Err(format!("invalid ACL rule '{}'", s));
            };
            return Ok(Self { net, port });
        }
        // 纯 IPv6 CIDR/地址（含至少两个 ':'）不带端口
        if s.matches(':').count() >= 2 {
            return Ok(Self {
                net: IpNet::parse(s)?,
                port: None,
            });
        }
        // IPv4 或 IPv4 CIDR + 可选 `:port`
        if let Some((lhs, port_s)) = s.rsplit_once(':') {
            let net = IpNet::parse(lhs)?;
            let port: u16 = port_s
                .parse()
                .map_err(|_| format!("invalid port in ACL rule '{}'", s))?;
            Ok(Self {
                net,
                port: Some(port),
            })
        } else {
            Ok(Self {
                net: IpNet::parse(s)?,
                port: None,
            })
        }
    }

    #[inline]
    pub fn matches(&self, addr: SocketAddr) -> bool {
        self.net.contains(addr.ip()) && self.port.is_none_or(|p| p == addr.port())
    }
}

#[derive(Clone, Debug)]
pub struct AclConfig {
    pub allow: Vec<AclRule>,
    pub deny: Vec<AclRule>,
    pub reject_private: bool,
    pub outbound_ipv4_only: bool,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
            reject_private: true,
            outbound_ipv4_only: false,
        }
    }
}

impl AclConfig {
    #[inline]
    pub fn is_allowed(&self, addr: SocketAddr) -> bool {
        if self.allow.iter().any(|r| r.matches(addr)) {
            return true;
        }
        if self.deny.iter().any(|r| r.matches(addr)) {
            return false;
        }
        if self.reject_private && is_private_or_special_ip(addr.ip()) {
            return false;
        }
        true
    }
}

#[inline]
pub fn is_private_or_special_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
                || (o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_or_special_ip(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xFE00) == 0xFC00 // fc00::/7 ULA
                || (seg[0] & 0xFFC0) == 0xFE80 // fe80::/10 link-local
        }
    }
}
