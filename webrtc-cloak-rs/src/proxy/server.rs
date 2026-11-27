//! 内嵌类 Hy2 代理服务端（`webrtc-cloak proxy --server`）。
//!
//! 在单一 `mio::Poll` 事件循环中融合：
//! - 外层 `ServerWorker`（公网 DTLS 1.3 + Dual-SSRC SRTP 终止 + `0xFFFC` MBB 零感知接管 + `0xFFFD` 1-RTT 迁移）；
//! - 内层多客户端 `quinn-proto::Endpoint`（No-op 零加密 + 动态协商 Brutal 恒速拥塞控制 + RFC 9221 Datagram）；
//! - 独立 2 线程异步 DNS 解析池（`mio::Waker` 毫秒级唤醒，解析后强制复检 CIDR ACL 防 DNS Rebinding）；
//! - 非阻塞 `mio::net::TcpStream` / `UdpSocket` 直接出站（彻底消除 `hysteria-server` 与 `lo` 回环内核开销）。

use super::brutal::{BrutalConfig, BrutalRateHandle, MIN_BRUTAL_BYTES_PER_SEC};
use super::proto::{
    decode_udp_datagram, encode_udp_datagrams, AclConfig, CtrlHello, TargetAddr,
    UdpFragReassembler, CTRL_HELLO_LEN, CTRL_HELLO_MAGIC, STREAM_CMD_TCP, STREAM_STATUS_ACL_DENIED,
    STREAM_STATUS_CONNECT_FAILED, STREAM_STATUS_OK,
};
use super::quic_crypto::{
    build_endpoint_config, build_quic_server_config, build_transport_config,
    compute_inner_quic_mtu, DEFAULT_QUIC_IDLE_TIMEOUT_SECS,
};
use super::{log, make_udp_socket, proxy_tunnel_key, PROXY_QUIET};
use crate::client::{ClientConfig, ClientWorker};
#[cfg(unix)]
use crate::constants::SHUTDOWN_PIPE_TOKEN;
use crate::constants::{
    outer_udp_hdr_len, worker_udp_write_buf_len, SharedPoll, LISTEN_TOKEN, MIO_EVENTS_CAP,
    SOCK_BUF_4MIB, TELEMETRY_DEFAULT_INTERVAL_SECS, WAKE_TOKEN, WORKER_QUIET_STOP_POLL_MS,
};
use crate::protocol::{
    build_dimpl_config_pool_for, detect_cpu_accel, is_shutdown_requested, rand_u32,
    register_shutdown_poll,
};
use crate::server::{SeenTxidCache, ServerConfig, ServerHook, ServerWorker, SharedV4Registry};
use crate::telemetry::TelemetryHub;
use crate::udp_batch::{format_udp_batch_mode, is_udp_batch_active, UdpSendBatch};
use bytes::{Bytes, BytesMut};
use mio::event::Event as MioEvent;
use mio::net::{TcpStream, UdpSocket as MioUdpSocket};
use mio::{Events, Interest, Poll, Token, Waker};
use quinn_proto::{
    Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, Event as QuicEvent, ReadError,
    StreamEvent, StreamId, VarInt, WriteError,
};
use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// 服务端代理出站套接字在 `mio::Poll` 中的保留令牌基址（与 `LISTEN_TOKEN` / `WAKE_TOKEN` 严格隔离）。
const PROXY_SERVER_TOK_BASE: usize = 1usize << (usize::BITS - 2);
/// 异步 DNS 线程池唤醒主循环的保留令牌。
const PROXY_DNS_WAKE_TOKEN: Token = Token(usize::MAX - 3);
/// 单次事件循环每条流最多搬运字节数。
const STREAM_IO_BUDGET: usize = 64 * 1024;
/// 单次 QUIC 刷包上限（按连接）。
const MAX_QUIC_TRANSMITS_PER_CONN: usize = 64;
/// 远端 TCP 出站连接建立超时（秒）。
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 出站 UDP 会话空闲回收时间（秒）。
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// 异步 DNS 正向结果内存缓存时长（秒）。
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
/// DNS 缓存容量上限。
const DNS_CACHE_CAP: usize = 512;
/// 异步 DNS 解析工作线程数。
const DNS_WORKERS: usize = 2;
/// 单服务端允许的最大并发出站 TCP/UDP 套接字总数上限。
const MAX_OUTBOUND_SOCKS: usize = 4096;

/// 内嵌类 Hy2 代理服务端配置（`webrtc-cloak proxy --server`）。
#[derive(Clone)]
pub struct ProxyServerConfig {
    pub server: ServerConfig,
    /// 允许客户端协商的最大上行带宽上限（bit/s）。
    pub max_up_bps: u64,
    /// 服务端发往客户端的最大下行 Brutal 带宽上限（bit/s）。
    pub max_down_bps: u64,
    /// 出站 CIDR ACL 与仅 IPv4 限制。
    pub acl: AclConfig,
    /// 可选内层 QUIC MTU 覆盖（字节，`None` 默认收敛至 1200B 对齐 WebRTC/Hy2 伪装包长）。
    pub proxy_mtu: Option<u16>,
}

/// 反向内嵌类 Hy2 代理出口端配置（`webrtc-cloak proxy --server --reverse`）。
///
/// 零公网入站端口：由位于 NAT / CGNAT 后的出口机主动外拨 `proxy --client --reverse` 或
/// `relay --upstream-mode reverse`，原生享有 `--lane-hunt`、0ms MBB、1-RTT 迁移与断线重连。
#[derive(Clone)]
pub struct ReverseProxyServerConfig {
    pub client: ClientConfig,
    pub max_up_bps: u64,
    pub max_down_bps: u64,
    pub acl: AclConfig,
    /// 可选内层 QUIC MTU 覆盖（字节，`None` 默认收敛至 1200B 对齐 WebRTC/Hy2 伪装包长）。
    pub proxy_mtu: Option<u16>,
}

enum ServerOuter<'a> {
    Forward(&'a mut ServerWorker),
    Reverse {
        worker: &'a mut ClientWorker,
        tunnel_key: SocketAddr,
    },
}

impl ServerOuter<'_> {
    #[inline]
    fn deliver_single(&mut self, flow_addr: SocketAddr, pkt: &[u8], now: Instant) {
        match self {
            ServerOuter::Forward(ingress) => {
                ingress.deliver_downlink_single(flow_addr, pkt, now);
            }
            ServerOuter::Reverse { worker, tunnel_key } => {
                worker.send_uplink_single(*tunnel_key, pkt, now);
            }
        }
    }
}

struct DnsJob {
    req_id: u64,
    host: String,
    port: u16,
    ipv4_only: bool,
}

struct DnsResult {
    req_id: u64,
    host: String,
    port: u16,
    addr: Option<SocketAddr>,
}

enum DnsWaiter {
    Tcp {
        conn_handle: ConnectionHandle,
        stream_id: StreamId,
        early_data: Vec<u8>,
        quic_eof: bool,
    },
    Udp {
        conn_handle: ConnectionHandle,
        session_id: u32,
        payload: Vec<u8>,
    },
}

struct DnsResolverPool {
    job_tx: Option<mpsc::Sender<DnsJob>>,
    res_rx: mpsc::Receiver<DnsResult>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl DnsResolverPool {
    fn start(waker: Arc<Waker>) -> Self {
        let (job_tx, job_rx) = mpsc::channel::<DnsJob>();
        let (res_tx, res_rx) = mpsc::channel::<DnsResult>();
        let shared_rx = Arc::new(Mutex::new(job_rx));
        let mut handles = Vec::with_capacity(DNS_WORKERS);

        for _ in 0..DNS_WORKERS {
            let rx = Arc::clone(&shared_rx);
            let tx = res_tx.clone();
            let wk = Arc::clone(&waker);
            handles.push(thread::spawn(move || loop {
                let job = {
                    let Ok(guard) = rx.lock() else { break };
                    match guard.recv() {
                        Ok(j) => j,
                        Err(_) => break,
                    }
                };
                let resolved = resolve_host_sync(&job.host, job.port, job.ipv4_only);
                if tx
                    .send(DnsResult {
                        req_id: job.req_id,
                        host: job.host,
                        port: job.port,
                        addr: resolved,
                    })
                    .is_err()
                {
                    break;
                }
                let _ = wk.wake();
            }));
        }

        Self {
            job_tx: Some(job_tx),
            res_rx,
            handles,
        }
    }

    fn submit(&self, job: DnsJob) -> bool {
        self.job_tx.as_ref().is_some_and(|tx| tx.send(job).is_ok())
    }

    fn shutdown(&mut self) {
        self.job_tx.take();
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

fn resolve_host_sync(host: &str, port: u16, ipv4_only: bool) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ipv4_only && !ip.is_ipv4() {
            return None;
        }
        return Some(SocketAddr::new(ip, port));
    }
    let addrs = (host, port).to_socket_addrs().ok()?;
    let mut fallback_v6: Option<SocketAddr> = None;
    for a in addrs {
        if a.is_ipv4() {
            return Some(a);
        }
        if !ipv4_only && fallback_v6.is_none() {
            fallback_v6 = Some(a);
        }
    }
    fallback_v6
}

struct ServerQuicConn {
    handle: ConnectionHandle,
    flow_addr: SocketAddr,
    conn: Connection,
    rate_handle: Arc<BrutalRateHandle>,
    /// True once the previous video-frame-shaped TCP->QUIC write burst has drained its tail packet.
    burst_drained: bool,
    /// Estimated stream payload bytes still pending transmission in the current shaped burst.
    burst_bytes_rem: usize,
    /// Safety deadline base so a CWND-stalled burst never blocks TCP reads past 120ms.
    burst_started_at: Instant,
    /// 正在解析首部（尚未区分 Control 还是 TCP 流、或正等待异步 DNS）的流缓冲。
    header_streams: HashMap<StreamId, HeaderStreamBuf>,
    udp_reassembler: UdpFragReassembler,
    next_frag_id: u16,
}

struct HeaderStreamBuf {
    rx: Vec<u8>,
    quic_eof: bool,
    is_ctrl: Option<bool>,
}

enum OutboundTcpState {
    Connecting {
        created_at: Instant,
        pending_to_tcp: Vec<u8>,
        quic_eof: bool,
    },
    Relaying {
        pending_to_quic: Vec<u8>,
        q_pos: usize,
        pending_to_tcp: Vec<u8>,
        t_pos: usize,
        tcp_eof: bool,
        quic_eof: bool,
    },
}

struct ServerTcpOutbound {
    conn_handle: ConnectionHandle,
    stream_id: StreamId,
    stream: TcpStream,
    interest: Interest,
    state: OutboundTcpState,
}

struct ServerUdpOutbound {
    conn_handle: ConnectionHandle,
    session_id: u32,
    is_ipv6: bool,
    sock: MioUdpSocket,
    last_active: Instant,
}

pub(crate) struct ProxyServerEngine {
    poll: SharedPoll,
    endpoint: Endpoint,
    brutal_cfg: Arc<BrutalConfig>,
    acl: AclConfig,
    max_up_bps: u64,
    max_down_bps: u64,
    inner_mtu: u16,
    conns: HashMap<ConnectionHandle, ServerQuicConn>,
    next_dyn_tok: usize,
    tcp_outbounds: HashMap<Token, ServerTcpOutbound>,
    tok_by_stream: HashMap<(ConnectionHandle, StreamId), Token>,
    udp_outbounds: HashMap<Token, ServerUdpOutbound>,
    tok_by_udp_sess: HashMap<(ConnectionHandle, u32, bool), Token>,
    dns_pool: DnsResolverPool,
    next_dns_req_id: u64,
    dns_waiters: HashMap<u64, DnsWaiter>,
    dns_cache: HashMap<(String, u16), (SocketAddr, Instant)>,
    rx_queue: VecDeque<(SocketAddr, Vec<u8>)>,
    deferred_tcp_reads: VecDeque<Token>,
    deferred_quic_reads: VecDeque<(ConnectionHandle, StreamId)>,
    more_tx_pending: bool,
    tx_scratch: Vec<u8>,
    tx_batch: Option<UdpSendBatch>,
    io_buf: Vec<u8>,
    udp_buf: Vec<u8>,
    total_streams_accepted: u64,
    total_acl_denied: u64,
    total_udp_tx: u64,
    total_udp_rx: u64,
}

impl ProxyServerEngine {
    fn new(
        poll: SharedPoll,
        dns_waker: Arc<Waker>,
        cfg: &ProxyServerConfig,
    ) -> std::io::Result<Self> {
        Self::new_common(
            poll,
            dns_waker,
            cfg.server.listen_addr,
            cfg.server.wan_mtu,
            cfg.proxy_mtu,
            cfg.server.udp_batch,
            cfg.max_up_bps,
            cfg.max_down_bps,
            cfg.acl.clone(),
        )
    }

    fn new_reverse(
        poll: SharedPoll,
        dns_waker: Arc<Waker>,
        cfg: &ReverseProxyServerConfig,
    ) -> std::io::Result<Self> {
        Self::new_common(
            poll,
            dns_waker,
            cfg.client.server_addr,
            cfg.client.wan_mtu,
            cfg.proxy_mtu,
            cfg.client.udp_batch,
            cfg.max_up_bps,
            cfg.max_down_bps,
            cfg.acl.clone(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_common(
        poll: SharedPoll,
        dns_waker: Arc<Waker>,
        outer_addr: SocketAddr,
        wan_mtu: usize,
        proxy_mtu: Option<u16>,
        udp_batch: usize,
        max_up_bps: u64,
        max_down_bps: u64,
        acl: AclConfig,
    ) -> std::io::Result<Self> {
        let outer_hdr = outer_udp_hdr_len(outer_addr);
        let inner_mtu = compute_inner_quic_mtu(wan_mtu, outer_hdr, proxy_mtu);
        let ep_cfg = build_endpoint_config(inner_mtu);
        let brutal_cfg = Arc::new(BrutalConfig::new(max_down_bps / 8));
        let transport = build_transport_config(
            inner_mtu,
            Arc::clone(&brutal_cfg),
            DEFAULT_QUIC_IDLE_TIMEOUT_SECS,
            None,
        );
        let server_cfg = build_quic_server_config(transport);
        let endpoint = Endpoint::new(Arc::new(ep_cfg), Some(server_cfg), true, None);

        let wbuf_len = worker_udp_write_buf_len(wan_mtu);
        let tx_batch =
            is_udp_batch_active(udp_batch).then(|| UdpSendBatch::new(udp_batch, wbuf_len));

        Ok(Self {
            poll,
            endpoint,
            brutal_cfg,
            acl,
            max_up_bps,
            max_down_bps,
            inner_mtu,
            conns: HashMap::with_capacity(8),
            next_dyn_tok: 0,
            tcp_outbounds: HashMap::with_capacity(64),
            tok_by_stream: HashMap::with_capacity(64),
            udp_outbounds: HashMap::with_capacity(32),
            tok_by_udp_sess: HashMap::with_capacity(32),
            dns_pool: DnsResolverPool::start(dns_waker),
            next_dns_req_id: 1,
            dns_waiters: HashMap::with_capacity(32),
            dns_cache: HashMap::with_capacity(64),
            rx_queue: VecDeque::with_capacity(64),
            deferred_tcp_reads: VecDeque::with_capacity(32),
            deferred_quic_reads: VecDeque::with_capacity(32),
            more_tx_pending: false,
            tx_scratch: Vec::with_capacity(2048),
            tx_batch,
            io_buf: vec![0u8; 32 * 1024],
            udp_buf: vec![0u8; 65_536],
            total_streams_accepted: 0,
            total_acl_denied: 0,
            total_udp_tx: 0,
            total_udp_rx: 0,
        })
    }

    fn alloc_dyn_token(&mut self) -> Token {
        let span = (usize::MAX - 8)
            .saturating_sub(PROXY_SERVER_TOK_BASE)
            .max(1);
        loop {
            let off = self.next_dyn_tok;
            self.next_dyn_tok = (self.next_dyn_tok + 1) % span;
            let tok = Token(PROXY_SERVER_TOK_BASE + off);
            if !self.tcp_outbounds.contains_key(&tok) && !self.udp_outbounds.contains_key(&tok) {
                return tok;
            }
        }
    }

    /// 外层 `ServerWorker` 解密上行 SRTP 数据包后零回环直递本方法。
    #[inline]
    pub(crate) fn on_tunnel_datagram(&mut self, flow_addr: SocketAddr, payload: &[u8]) {
        if !payload.is_empty() {
            self.rx_queue.push_back((flow_addr, payload.to_vec()));
        }
    }

    fn on_outer_flow_closed(&mut self, flow_addr: SocketAddr) {
        let dead_handles: Vec<ConnectionHandle> = self
            .conns
            .iter()
            .filter(|(_, c)| c.flow_addr == flow_addr)
            .map(|(&h, _)| h)
            .collect();
        for ch in dead_handles {
            self.remove_quic_conn(ch, "outer_flow_closed");
        }
    }

    fn remove_quic_conn(&mut self, ch: ConnectionHandle, reason: &str) {
        if self.conns.remove(&ch).is_some() {
            log(
                "proxy-server",
                &format!("inner QUIC conn closed ({})", reason),
            );
        }
        let dead_tcp: Vec<Token> = self
            .tcp_outbounds
            .iter()
            .filter(|(_, t)| t.conn_handle == ch)
            .map(|(&tok, _)| tok)
            .collect();
        for tok in dead_tcp {
            self.close_tcp_outbound(tok, false);
        }
        let dead_udp: Vec<Token> = self
            .udp_outbounds
            .iter()
            .filter(|(_, u)| u.conn_handle == ch)
            .map(|(&tok, _)| tok)
            .collect();
        for tok in dead_udp {
            self.close_udp_outbound(tok);
        }
    }

    fn update_tcp_interest(&mut self, tok: Token, want: Interest) {
        if let Some(t) = self.tcp_outbounds.get_mut(&tok) {
            if t.interest != want {
                t.interest = want;
                let _ = self.poll.registry().reregister(&mut t.stream, tok, want);
            }
        }
    }

    fn close_tcp_outbound(&mut self, tok: Token, notify_quic: bool) {
        let Some(mut out) = self.tcp_outbounds.remove(&tok) else {
            return;
        };
        let _ = self.poll.registry().deregister(&mut out.stream);
        self.tok_by_stream.remove(&(out.conn_handle, out.stream_id));
        if notify_quic {
            if let Some(q) = self.conns.get_mut(&out.conn_handle) {
                let _ = q.conn.send_stream(out.stream_id).reset(VarInt::from_u32(0));
                let _ = q.conn.recv_stream(out.stream_id).stop(VarInt::from_u32(0));
            }
        }
    }

    fn close_udp_outbound(&mut self, tok: Token) {
        if let Some(mut u) = self.udp_outbounds.remove(&tok) {
            let _ = self.poll.registry().deregister(&mut u.sock);
            self.tok_by_udp_sess
                .remove(&(u.conn_handle, u.session_id, u.is_ipv6));
        }
    }

    fn send_stream_status_and_close(
        &mut self,
        ch: ConnectionHandle,
        stream_id: StreamId,
        status: u8,
    ) {
        if let Some(q) = self.conns.get_mut(&ch) {
            let _ = q.conn.send_stream(stream_id).write(&[status]);
            let _ = q.conn.send_stream(stream_id).finish();
            let _ = q.conn.recv_stream(stream_id).stop(VarInt::from_u32(0));
        }
    }

    fn initiate_tcp_connect(
        &mut self,
        ch: ConnectionHandle,
        stream_id: StreamId,
        addr: SocketAddr,
        early_data: Vec<u8>,
        quic_eof: bool,
        now: Instant,
    ) {
        if self.acl.outbound_ipv4_only && !addr.is_ipv4() {
            self.total_acl_denied += 1;
            self.send_stream_status_and_close(ch, stream_id, STREAM_STATUS_ACL_DENIED);
            return;
        }
        if !self.acl.is_allowed(addr) {
            self.total_acl_denied += 1;
            self.send_stream_status_and_close(ch, stream_id, STREAM_STATUS_ACL_DENIED);
            return;
        }
        if self.tcp_outbounds.len() + self.udp_outbounds.len() >= MAX_OUTBOUND_SOCKS {
            self.send_stream_status_and_close(ch, stream_id, STREAM_STATUS_CONNECT_FAILED);
            return;
        }
        let mut stream = match TcpStream::connect(addr) {
            Ok(s) => s,
            Err(_) => {
                self.send_stream_status_and_close(ch, stream_id, STREAM_STATUS_CONNECT_FAILED);
                return;
            }
        };
        let tok = self.alloc_dyn_token();
        let interest = Interest::READABLE | Interest::WRITABLE;
        if self
            .poll
            .registry()
            .register(&mut stream, tok, interest)
            .is_err()
        {
            self.send_stream_status_and_close(ch, stream_id, STREAM_STATUS_CONNECT_FAILED);
            return;
        }
        self.total_streams_accepted += 1;
        self.tok_by_stream.insert((ch, stream_id), tok);
        self.tcp_outbounds.insert(
            tok,
            ServerTcpOutbound {
                conn_handle: ch,
                stream_id,
                stream,
                interest,
                state: OutboundTcpState::Connecting {
                    created_at: now,
                    pending_to_tcp: early_data,
                    quic_eof,
                },
            },
        );
    }

    fn handle_stream_header_readable(&mut self, ch: ConnectionHandle, sid: StreamId, now: Instant) {
        enum Parsed {
            WaitMore,
            Drop,
            CtrlHello(CtrlHello),
            TcpTarget {
                target: TargetAddr,
                early_data: Vec<u8>,
                quic_eof: bool,
            },
        }
        let mut parsed = Parsed::WaitMore;

        if let Some(q) = self.conns.get_mut(&ch) {
            let entry = q
                .header_streams
                .entry(sid)
                .or_insert_with(|| HeaderStreamBuf {
                    rx: Vec::with_capacity(64),
                    quic_eof: false,
                    is_ctrl: None,
                });
            if let Ok(mut chunks) = q.conn.recv_stream(sid).read(true) {
                loop {
                    match chunks.next(1024) {
                        Ok(Some(chunk)) => {
                            entry.rx.extend_from_slice(&chunk.bytes);
                            if entry.rx.len() > 4096 {
                                break;
                            }
                        }
                        Ok(None) => {
                            entry.quic_eof = true;
                            break;
                        }
                        Err(ReadError::Blocked) => break,
                        Err(ReadError::Reset(_)) => {
                            parsed = Parsed::Drop;
                            break;
                        }
                    }
                }
                let _ = chunks.finalize();
            }

            if !matches!(parsed, Parsed::Drop) && !entry.rx.is_empty() {
                let first = entry.rx[0];
                if first == CTRL_HELLO_MAGIC[0] {
                    entry.is_ctrl = Some(true);
                    if entry.rx.len() >= CTRL_HELLO_LEN {
                        if let Some(h) = CtrlHello::decode(&entry.rx) {
                            parsed = Parsed::CtrlHello(h);
                        } else {
                            parsed = Parsed::Drop;
                        }
                    }
                } else if first == STREAM_CMD_TCP {
                    entry.is_ctrl = Some(false);
                    match TargetAddr::decode(&entry.rx[1..]) {
                        Ok(Some((target, alen))) => {
                            let early_data = entry.rx[1 + alen..].to_vec();
                            let quic_eof = entry.quic_eof;
                            parsed = Parsed::TcpTarget {
                                target,
                                early_data,
                                quic_eof,
                            };
                        }
                        Ok(None) => {
                            if entry.quic_eof || entry.rx.len() > 512 {
                                parsed = Parsed::Drop;
                            }
                        }
                        Err(()) => parsed = Parsed::Drop,
                    }
                } else {
                    parsed = Parsed::Drop;
                }
            } else if entry.quic_eof {
                parsed = Parsed::Drop;
            }
        }

        match parsed {
            Parsed::WaitMore => {}
            Parsed::Drop => {
                if let Some(q) = self.conns.get_mut(&ch) {
                    q.header_streams.remove(&sid);
                    let _ = q.conn.send_stream(sid).reset(VarInt::from_u32(1));
                    let _ = q.conn.recv_stream(sid).stop(VarInt::from_u32(1));
                }
            }
            Parsed::CtrlHello(req) => {
                if let Some(q) = self.conns.get_mut(&ch) {
                    q.header_streams.remove(&sid);
                    let granted_up = req.up_bps.min(self.max_up_bps).max(512_000);
                    let granted_down = req.down_bps.min(self.max_down_bps).max(512_000);
                    let down_bytes = (granted_down / 8).max(MIN_BRUTAL_BYTES_PER_SEC);
                    q.rate_handle.store(down_bytes);
                    let reply = CtrlHello {
                        up_bps: granted_up,
                        down_bps: granted_down,
                    }
                    .encode();
                    let _ = q.conn.send_stream(sid).write(&reply);
                    let _ = q.conn.send_stream(sid).finish();
                    log(
                        "proxy-server",
                        &format!(
                            "QUIC+Brutal negotiated flow={} up={:.1}Mbps down={:.1}Mbps inner_mtu={}",
                            q.flow_addr,
                            granted_up as f64 / 1e6,
                            granted_down as f64 / 1e6,
                            self.inner_mtu
                        ),
                    );
                }
            }
            Parsed::TcpTarget {
                target,
                early_data,
                quic_eof,
            } => {
                if let Some(q) = self.conns.get_mut(&ch) {
                    q.header_streams.remove(&sid);
                }
                match target {
                    TargetAddr::V4(ip, port) => {
                        self.initiate_tcp_connect(
                            ch,
                            sid,
                            SocketAddr::new(IpAddr::V4(ip), port),
                            early_data,
                            quic_eof,
                            now,
                        );
                    }
                    TargetAddr::V6(ip, port) => {
                        self.initiate_tcp_connect(
                            ch,
                            sid,
                            SocketAddr::new(IpAddr::V6(ip), port),
                            early_data,
                            quic_eof,
                            now,
                        );
                    }
                    TargetAddr::Domain(host, port) => {
                        if let Some(cached) = self.lookup_dns_cache(&host, port, now) {
                            self.initiate_tcp_connect(ch, sid, cached, early_data, quic_eof, now);
                        } else {
                            let req_id = self.next_dns_req_id;
                            self.next_dns_req_id = self.next_dns_req_id.wrapping_add(1).max(1);
                            let job = DnsJob {
                                req_id,
                                host,
                                port,
                                ipv4_only: self.acl.outbound_ipv4_only,
                            };
                            if self.dns_pool.submit(job) {
                                self.dns_waiters.insert(
                                    req_id,
                                    DnsWaiter::Tcp {
                                        conn_handle: ch,
                                        stream_id: sid,
                                        early_data,
                                        quic_eof,
                                    },
                                );
                            } else {
                                self.send_stream_status_and_close(
                                    ch,
                                    sid,
                                    STREAM_STATUS_CONNECT_FAILED,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn lookup_dns_cache(&mut self, host: &str, port: u16, now: Instant) -> Option<SocketAddr> {
        let key = (host.to_string(), port);
        if let Some(&(addr, ts)) = self.dns_cache.get(&key) {
            if now.saturating_duration_since(ts) <= DNS_CACHE_TTL {
                return Some(addr);
            }
            self.dns_cache.remove(&key);
        }
        None
    }

    fn store_dns_cache(&mut self, host: String, port: u16, addr: SocketAddr, now: Instant) {
        if self.dns_cache.len() >= DNS_CACHE_CAP {
            self.dns_cache
                .retain(|_, (_, ts)| now.saturating_duration_since(*ts) <= DNS_CACHE_TTL);
            if self.dns_cache.len() >= DNS_CACHE_CAP {
                self.dns_cache.clear();
            }
        }
        self.dns_cache.insert((host, port), (addr, now));
    }

    fn drain_dns_results(&mut self, now: Instant) {
        let mut results = Vec::new();
        while let Ok(res) = self.dns_pool.res_rx.try_recv() {
            results.push(res);
        }
        for res in results {
            if let Some(addr) = res.addr {
                self.store_dns_cache(res.host, res.port, addr, now);
            }
            let Some(waiter) = self.dns_waiters.remove(&res.req_id) else {
                continue;
            };
            match waiter {
                DnsWaiter::Tcp {
                    conn_handle,
                    stream_id,
                    early_data,
                    quic_eof,
                } => {
                    if !self.conns.contains_key(&conn_handle) {
                        continue;
                    }
                    if let Some(addr) = res.addr {
                        self.initiate_tcp_connect(
                            conn_handle,
                            stream_id,
                            addr,
                            early_data,
                            quic_eof,
                            now,
                        );
                    } else {
                        self.send_stream_status_and_close(
                            conn_handle,
                            stream_id,
                            STREAM_STATUS_CONNECT_FAILED,
                        );
                    }
                }
                DnsWaiter::Udp {
                    conn_handle,
                    session_id,
                    payload,
                } => {
                    if let Some(addr) = res.addr {
                        if self.conns.contains_key(&conn_handle) {
                            self.send_outbound_udp(conn_handle, session_id, addr, &payload, now);
                        }
                    }
                }
            }
        }
    }

    fn handle_outbound_event(&mut self, ev: &MioEvent, now: Instant) {
        let tok = ev.token();
        if self.udp_outbounds.contains_key(&tok) {
            self.handle_outbound_udp_readable(tok, now);
            return;
        }
        if !self.tcp_outbounds.contains_key(&tok) {
            return;
        }

        // 若正处于 Connecting 状态，先完成异步 connect 检查
        if matches!(
            self.tcp_outbounds.get(&tok).map(|t| &t.state),
            Some(OutboundTcpState::Connecting { .. })
        ) {
            let (ch, sid, connected_ok) = {
                let out = self.tcp_outbounds.get(&tok).unwrap();
                let ok = !ev.is_error()
                    && out.stream.take_error().ok().flatten().is_none()
                    && out.stream.peer_addr().is_ok();
                (out.conn_handle, out.stream_id, ok)
            };
            if !connected_ok {
                self.close_tcp_outbound(tok, false);
                self.send_stream_status_and_close(ch, sid, STREAM_STATUS_CONNECT_FAILED);
                return;
            }
            let mut need_writable = false;
            if let Some(out) = self.tcp_outbounds.get_mut(&tok) {
                let _ = out.stream.set_nodelay(true);
                if let OutboundTcpState::Connecting {
                    pending_to_tcp,
                    quic_eof,
                    ..
                } = &mut out.state
                {
                    let p_tcp = std::mem::take(pending_to_tcp);
                    let qeof = *quic_eof;
                    need_writable = !p_tcp.is_empty();
                    let mut status_pending = Vec::new();
                    if let Some(q) = self.conns.get_mut(&ch) {
                        match q.conn.send_stream(sid).write(&[STREAM_STATUS_OK]) {
                            Ok(1) => {}
                            Ok(_) | Err(WriteError::Blocked) => {
                                status_pending.push(STREAM_STATUS_OK);
                            }
                            Err(_) => {
                                self.close_tcp_outbound(tok, true);
                                return;
                            }
                        }
                    }
                    out.state = OutboundTcpState::Relaying {
                        pending_to_quic: status_pending,
                        q_pos: 0,
                        pending_to_tcp: p_tcp,
                        t_pos: 0,
                        tcp_eof: false,
                        quic_eof: qeof,
                    };
                }
            }
            let want = if need_writable {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            self.update_tcp_interest(tok, want);
            if need_writable {
                self.handle_outbound_tcp_writable(tok);
            } else {
                // 可能对端发了 early EOF 或有更多 QUIC 数据待读
                self.pump_quic_to_outbound_tcp(ch, sid);
            }
            if ev.is_readable() && self.tcp_outbounds.contains_key(&tok) {
                self.handle_outbound_tcp_readable(tok);
            }
            return;
        }

        if ev.is_error() {
            self.close_tcp_outbound(tok, true);
            return;
        }
        if ev.is_writable() {
            self.handle_outbound_tcp_writable(tok);
        }
        if ev.is_readable() && self.tcp_outbounds.contains_key(&tok) {
            self.handle_outbound_tcp_readable(tok);
        }
    }

    fn handle_outbound_tcp_writable(&mut self, tok: Token) {
        let mut close_now = false;
        let mut drop_writable = false;
        let mut pump_next: Option<(ConnectionHandle, StreamId)> = None;

        if let Some(out) = self.tcp_outbounds.get_mut(&tok) {
            if let OutboundTcpState::Relaying {
                pending_to_quic,
                pending_to_tcp,
                t_pos,
                tcp_eof,
                quic_eof,
                ..
            } = &mut out.state
            {
                while *t_pos < pending_to_tcp.len() {
                    match out.stream.write(&pending_to_tcp[*t_pos..]) {
                        Ok(0) => {
                            close_now = true;
                            break;
                        }
                        Ok(n) => *t_pos += n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => {
                            close_now = true;
                            break;
                        }
                    }
                }
                if !close_now && *t_pos >= pending_to_tcp.len() {
                    pending_to_tcp.clear();
                    *t_pos = 0;
                    drop_writable = true;
                    if *quic_eof {
                        let _ = out.stream.shutdown(Shutdown::Write);
                        if *tcp_eof && pending_to_quic.is_empty() {
                            close_now = true;
                        }
                    } else {
                        pump_next = Some((out.conn_handle, out.stream_id));
                    }
                }
            }
        }

        if close_now {
            self.close_tcp_outbound(tok, false);
            return;
        }
        if drop_writable {
            self.update_tcp_interest(tok, Interest::READABLE);
        }
        if let Some((ch, sid)) = pump_next {
            self.pump_quic_to_outbound_tcp(ch, sid);
        }
    }

    fn handle_outbound_tcp_readable(&mut self, tok: Token) {
        let mut close_now = false;
        let mut reset_quic = false;

        if let Some(out) = self.tcp_outbounds.get_mut(&tok) {
            let ch = out.conn_handle;
            let sid = out.stream_id;
            if let OutboundTcpState::Relaying {
                pending_to_quic,
                q_pos,
                pending_to_tcp,
                tcp_eof,
                quic_eof,
                ..
            } = &mut out.state
            {
                if !pending_to_quic.is_empty() || *tcp_eof {
                    return;
                }
                let Some(q) = self.conns.get_mut(&ch) else {
                    self.close_tcp_outbound(tok, false);
                    return;
                };
                if !q.burst_drained {
                    if !self.deferred_tcp_reads.contains(&tok) {
                        self.deferred_tcp_reads.push_back(tok);
                    }
                    return;
                }
                // v0.7.1: Shape bulk TCP->QUIC bursts into WebRTC video-frame boundaries:
                // 5..=10 full-MTU packets + 1 genuine 500..=979B frame-tail packet (~9..17% tails).
                // `burst_drained` + `burst_bytes_rem` defers refilling until the tail packet
                // actually leaves `poll_transmit`, eliminating 99% full-MTU rectangular boxes.
                let mss = (self.inner_mtu as usize).saturating_sub(42).max(512);
                let full_pkts = 5 + ((rand_u32() as usize) % 6);
                let tail_bytes = 500 + ((rand_u32() as usize) % 480);
                let mut budget = (full_pkts * mss + tail_bytes).min(STREAM_IO_BUDGET);
                let mut total_written = 0usize;
                let mut hit_would_block = false;
                while budget > 0 {
                    let cap = self.io_buf.len().min(budget);
                    match out.stream.read(&mut self.io_buf[..cap]) {
                        Ok(0) => {
                            *tcp_eof = true;
                            hit_would_block = true;
                            let _ = q.conn.send_stream(sid).finish();
                            if *quic_eof && pending_to_tcp.is_empty() {
                                close_now = true;
                            }
                            break;
                        }
                        Ok(n) => {
                            budget = budget.saturating_sub(n);
                            let mut written = 0usize;
                            let mut write_blocked = false;
                            while written < n {
                                match q.conn.send_stream(sid).write(&self.io_buf[written..n]) {
                                    Ok(0) | Err(WriteError::Blocked) => {
                                        write_blocked = true;
                                        break;
                                    }
                                    Ok(w) => {
                                        written += w;
                                        total_written = total_written.saturating_add(w);
                                    }
                                    Err(_) => {
                                        close_now = true;
                                        write_blocked = true;
                                        break;
                                    }
                                }
                            }
                            if close_now {
                                hit_would_block = true;
                                break;
                            }
                            if write_blocked {
                                // 注意：必须一直循环 write 直到 quinn-proto 返回 Err(WriteError::Blocked)，
                                // 否则流不会被加入 connection_blocked，后续不会再收到 StreamEvent::Writable。
                                pending_to_quic.extend_from_slice(&self.io_buf[written..n]);
                                *q_pos = 0;
                                hit_would_block = true;
                                break;
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            hit_would_block = true;
                            break;
                        }
                        Err(_) => {
                            close_now = true;
                            reset_quic = true;
                            hit_would_block = true;
                            break;
                        }
                    }
                }
                if !hit_would_block && total_written >= mss {
                    q.burst_drained = false;
                    q.burst_bytes_rem = q.burst_bytes_rem.saturating_add(total_written);
                    q.burst_started_at = Instant::now();
                }
                if !hit_would_block && !self.deferred_tcp_reads.contains(&tok) {
                    self.deferred_tcp_reads.push_back(tok);
                }
            }
        }

        if close_now {
            self.close_tcp_outbound(tok, reset_quic);
        }
    }

    fn flush_quic_write_for_stream(&mut self, ch: ConnectionHandle, sid: StreamId) {
        let Some(&tok) = self.tok_by_stream.get(&(ch, sid)) else {
            return;
        };
        let mut close_now = false;
        let mut pump_read = false;
        if let (Some(out), Some(q)) = (self.tcp_outbounds.get_mut(&tok), self.conns.get_mut(&ch)) {
            if let OutboundTcpState::Relaying {
                pending_to_quic,
                q_pos,
                pending_to_tcp,
                tcp_eof,
                quic_eof,
                ..
            } = &mut out.state
            {
                while *q_pos < pending_to_quic.len() {
                    match q.conn.send_stream(sid).write(&pending_to_quic[*q_pos..]) {
                        Ok(n) => *q_pos += n,
                        Err(WriteError::Blocked) => break,
                        Err(_) => {
                            close_now = true;
                            break;
                        }
                    }
                }
                if !close_now && *q_pos >= pending_to_quic.len() {
                    pending_to_quic.clear();
                    *q_pos = 0;
                    if *tcp_eof {
                        let _ = q.conn.send_stream(sid).finish();
                        if *quic_eof && pending_to_tcp.is_empty() {
                            close_now = true;
                        }
                    } else {
                        pump_read = true;
                    }
                }
            }
        }
        if close_now {
            self.close_tcp_outbound(tok, false);
        } else if pump_read {
            // 排入延迟读队列，让同批次其他流先公平刷出 pending_to_quic 后再轮询续读
            self.deferred_tcp_reads.push_back(tok);
        }
    }

    fn pump_quic_to_outbound_tcp(&mut self, ch: ConnectionHandle, sid: StreamId) {
        let Some(&tok) = self.tok_by_stream.get(&(ch, sid)) else {
            return;
        };
        let mut close_now = false;
        let mut need_writable = false;
        let mut hit_quic_blocked = true;

        if let (Some(out), Some(q)) = (self.tcp_outbounds.get_mut(&tok), self.conns.get_mut(&ch)) {
            match &mut out.state {
                OutboundTcpState::Connecting {
                    pending_to_tcp,
                    quic_eof,
                    ..
                } => {
                    // 连接建立期间最多预缓存 64 KiB 首包数据
                    if pending_to_tcp.len() < 64 * 1024 && !*quic_eof {
                        if let Ok(mut chunks) = q.conn.recv_stream(sid).read(true) {
                            while pending_to_tcp.len() < 64 * 1024 {
                                match chunks.next(16 * 1024) {
                                    Ok(Some(chunk)) => {
                                        pending_to_tcp.extend_from_slice(&chunk.bytes)
                                    }
                                    Ok(None) => {
                                        *quic_eof = true;
                                        break;
                                    }
                                    Err(ReadError::Blocked) => break,
                                    Err(ReadError::Reset(_)) => {
                                        close_now = true;
                                        break;
                                    }
                                }
                            }
                            let _ = chunks.finalize();
                        }
                    }
                }
                OutboundTcpState::Relaying {
                    pending_to_quic,
                    pending_to_tcp,
                    t_pos,
                    tcp_eof,
                    quic_eof,
                    ..
                } => {
                    if !pending_to_tcp.is_empty() || *quic_eof {
                        return;
                    }
                    let mut budget = STREAM_IO_BUDGET;
                    hit_quic_blocked = false;
                    if let Ok(mut chunks) = q.conn.recv_stream(sid).read(true) {
                        while budget > 0 {
                            match chunks.next(budget.min(32 * 1024)) {
                                Ok(Some(chunk)) => {
                                    let data = &chunk.bytes;
                                    budget = budget.saturating_sub(data.len());
                                    let mut written = 0usize;
                                    while written < data.len() {
                                        match out.stream.write(&data[written..]) {
                                            Ok(0) => {
                                                close_now = true;
                                                hit_quic_blocked = true;
                                                break;
                                            }
                                            Ok(n) => written += n,
                                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                            Err(_) => {
                                                close_now = true;
                                                hit_quic_blocked = true;
                                                break;
                                            }
                                        }
                                    }
                                    if close_now {
                                        break;
                                    }
                                    if written < data.len() {
                                        pending_to_tcp.extend_from_slice(&data[written..]);
                                        *t_pos = 0;
                                        need_writable = true;
                                        hit_quic_blocked = true;
                                        break;
                                    }
                                }
                                Ok(None) => {
                                    *quic_eof = true;
                                    hit_quic_blocked = true;
                                    if pending_to_tcp.is_empty() {
                                        let _ = out.stream.shutdown(Shutdown::Write);
                                        if *tcp_eof && pending_to_quic.is_empty() {
                                            close_now = true;
                                        }
                                    }
                                    break;
                                }
                                Err(ReadError::Blocked) => {
                                    hit_quic_blocked = true;
                                    break;
                                }
                                Err(ReadError::Reset(_)) => {
                                    close_now = true;
                                    hit_quic_blocked = true;
                                    break;
                                }
                            }
                        }
                        let _ = chunks.finalize();
                    } else {
                        hit_quic_blocked = true;
                    }
                }
            }
        }

        if close_now {
            self.close_tcp_outbound(tok, false);
        } else {
            if need_writable {
                self.update_tcp_interest(tok, Interest::READABLE | Interest::WRITABLE);
            }
            if !hit_quic_blocked {
                self.deferred_quic_reads.push_back((ch, sid));
            }
        }
    }

    fn send_outbound_udp(
        &mut self,
        ch: ConnectionHandle,
        session_id: u32,
        dst: SocketAddr,
        payload: &[u8],
        now: Instant,
    ) {
        if self.acl.outbound_ipv4_only && !dst.is_ipv4() {
            self.total_acl_denied += 1;
            return;
        }
        if !self.acl.is_allowed(dst) {
            self.total_acl_denied += 1;
            return;
        }
        let is_ipv6 = dst.is_ipv6();
        let key = (ch, session_id, is_ipv6);
        if let Some(&tok) = self.tok_by_udp_sess.get(&key) {
            if let Some(u) = self.udp_outbounds.get_mut(&tok) {
                u.last_active = now;
                if u.sock.send_to(payload, dst).is_ok() {
                    self.total_udp_tx += 1;
                }
            }
            return;
        }
        if self.tcp_outbounds.len() + self.udp_outbounds.len() >= MAX_OUTBOUND_SOCKS {
            return;
        }
        let bind_addr = if is_ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let mut sock = match make_udp_socket(bind_addr, SOCK_BUF_4MIB) {
            Ok(s) => s,
            Err(_) => return,
        };
        let tok = self.alloc_dyn_token();
        if self
            .poll
            .registry()
            .register(&mut sock, tok, Interest::READABLE)
            .is_err()
        {
            return;
        }
        if sock.send_to(payload, dst).is_ok() {
            self.total_udp_tx += 1;
        }
        self.tok_by_udp_sess.insert(key, tok);
        self.udp_outbounds.insert(
            tok,
            ServerUdpOutbound {
                conn_handle: ch,
                session_id,
                is_ipv6,
                sock,
                last_active: now,
            },
        );
    }

    fn drain_incoming_datagrams(&mut self, ch: ConnectionHandle, now: Instant) {
        let mut items: Vec<(u32, TargetAddr, Vec<u8>)> = Vec::new();
        if let Some(q) = self.conns.get_mut(&ch) {
            while let Some(raw) = q.conn.datagrams().recv() {
                if let Some(frame) = decode_udp_datagram(&raw) {
                    if let Some(complete) = q.udp_reassembler.push(frame, now) {
                        items.push(complete);
                    }
                }
            }
        }
        for (sid, dst, payload) in items {
            match dst {
                TargetAddr::V4(ip, port) => {
                    self.send_outbound_udp(
                        ch,
                        sid,
                        SocketAddr::new(IpAddr::V4(ip), port),
                        &payload,
                        now,
                    );
                }
                TargetAddr::V6(ip, port) => {
                    self.send_outbound_udp(
                        ch,
                        sid,
                        SocketAddr::new(IpAddr::V6(ip), port),
                        &payload,
                        now,
                    );
                }
                TargetAddr::Domain(host, port) => {
                    if let Some(cached) = self.lookup_dns_cache(&host, port, now) {
                        self.send_outbound_udp(ch, sid, cached, &payload, now);
                    } else {
                        let req_id = self.next_dns_req_id;
                        self.next_dns_req_id = self.next_dns_req_id.wrapping_add(1).max(1);
                        let job = DnsJob {
                            req_id,
                            host,
                            port,
                            ipv4_only: self.acl.outbound_ipv4_only,
                        };
                        if self.dns_pool.submit(job) {
                            self.dns_waiters.insert(
                                req_id,
                                DnsWaiter::Udp {
                                    conn_handle: ch,
                                    session_id: sid,
                                    payload,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    fn handle_outbound_udp_readable(&mut self, tok: Token, now: Instant) {
        let mut pkts: Vec<(ConnectionHandle, u32, SocketAddr, Vec<u8>)> = Vec::new();
        if let Some(u) = self.udp_outbounds.get_mut(&tok) {
            u.last_active = now;
            loop {
                let (n, src) = match u.sock.recv_from(&mut self.udp_buf) {
                    Ok(v) => v,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                pkts.push((u.conn_handle, u.session_id, src, self.udp_buf[..n].to_vec()));
            }
        }
        for (ch, sid, src, payload) in pkts {
            if let Some(q) = self.conns.get_mut(&ch) {
                let max_dgram = q
                    .conn
                    .datagrams()
                    .max_size()
                    .unwrap_or(self.inner_mtu.saturating_sub(48) as usize);
                let fid = q.next_frag_id;
                q.next_frag_id = q.next_frag_id.wrapping_add(1);
                let encoded = encode_udp_datagrams(
                    sid,
                    fid,
                    &TargetAddr::from_socket_addr(src),
                    &payload,
                    max_dgram,
                );
                for frame in encoded {
                    if q.conn.datagrams().send(Bytes::from(frame), false).is_ok() {
                        self.total_udp_rx += 1;
                    }
                }
            }
        }
    }

    fn drive(&mut self, outer: &mut ServerOuter<'_>, now: Instant) -> Duration {
        // 1) 处理已完成的异步 DNS 解析
        self.drain_dns_results(now);

        // 2) 喂入来自外层 WebRTC-Cloak 的上行 QUIC 报文
        while let Some((flow_addr, raw)) = self.rx_queue.pop_front() {
            let mut resp_buf = Vec::new();
            let ev = self.endpoint.handle(
                now,
                flow_addr,
                None,
                None,
                BytesMut::from(&raw[..]),
                &mut resp_buf,
            );
            match ev {
                Some(DatagramEvent::NewConnection(incoming)) => {
                    resp_buf.clear();
                    match self.endpoint.accept(incoming, now, &mut resp_buf, None) {
                        Ok((handle, conn)) => {
                            // R3-P2-2: In reverse proxy mode, a single entry peer owns `flow_addr`;
                            // if the entry restarted via SIGKILL and opened a fresh inner QUIC
                            // connection, immediately reap any orphaned ServerQuicConn & backend FDs
                            // (lossless outer MBB never fires `NewConnection`).
                            if matches!(outer, ServerOuter::Reverse { .. }) {
                                let stale: Vec<ConnectionHandle> = self
                                    .conns
                                    .iter()
                                    .filter(|(&ch, q)| ch != handle && q.flow_addr == flow_addr)
                                    .map(|(&ch, _)| ch)
                                    .collect();
                                for old_ch in stale {
                                    self.remove_quic_conn(
                                        old_ch,
                                        "replaced by new reverse connection",
                                    );
                                }
                            }
                            let rate_handle = self.brutal_cfg.take_last_rate_handle();
                            self.conns.insert(
                                handle,
                                ServerQuicConn {
                                    handle,
                                    flow_addr,
                                    conn,
                                    rate_handle,
                                    burst_drained: true,
                                    burst_bytes_rem: 0,
                                    burst_started_at: now,
                                    header_streams: HashMap::with_capacity(16),
                                    udp_reassembler: UdpFragReassembler::default(),
                                    next_frag_id: 1,
                                },
                            );
                        }
                        Err(e) => {
                            if !resp_buf.is_empty() {
                                outer.deliver_single(flow_addr, &resp_buf, now);
                            }
                            log(
                                "proxy-server",
                                &format!("QUIC accept rejected flow={}: {:?}", flow_addr, e.cause),
                            );
                        }
                    }
                }
                Some(DatagramEvent::ConnectionEvent(ch, cev)) => {
                    if let Some(q) = self.conns.get_mut(&ch) {
                        q.flow_addr = flow_addr;
                        q.conn.handle_event(cev);
                    }
                }
                Some(DatagramEvent::Response(_)) if !resp_buf.is_empty() => {
                    outer.deliver_single(flow_addr, &resp_buf, now);
                }
                _ => {}
            }
        }

        // 3) 推进所有 QUIC 连接的定时器、Endpoint 事件与应用事件
        let handles: Vec<ConnectionHandle> = self.conns.keys().copied().collect();
        let mut dead_conns: Vec<(ConnectionHandle, String)> = Vec::new();

        for ch in handles {
            let mut quic_events = Vec::new();
            if let Some(q) = self.conns.get_mut(&ch) {
                if let Some(t) = q.conn.poll_timeout() {
                    if now >= t {
                        q.conn.handle_timeout(now);
                    }
                }
                while let Some(ev) = q.conn.poll_endpoint_events() {
                    if let Some(cev) = self.endpoint.handle_event(q.handle, ev) {
                        q.conn.handle_event(cev);
                    }
                }
                while let Some(ev) = q.conn.poll() {
                    quic_events.push(ev);
                }
            }

            for ev in quic_events {
                match ev {
                    QuicEvent::ConnectionLost { reason } => {
                        dead_conns.push((ch, format!("{:?}", reason)));
                    }
                    QuicEvent::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                        let mut opened = Vec::new();
                        if let Some(q) = self.conns.get_mut(&ch) {
                            while let Some(sid) = q.conn.streams().accept(Dir::Bi) {
                                opened.push(sid);
                            }
                        }
                        for sid in opened {
                            self.handle_stream_header_readable(ch, sid, now);
                        }
                    }
                    QuicEvent::Stream(StreamEvent::Readable { id }) => {
                        if self.tok_by_stream.contains_key(&(ch, id)) {
                            self.pump_quic_to_outbound_tcp(ch, id);
                        } else {
                            self.handle_stream_header_readable(ch, id, now);
                        }
                    }
                    QuicEvent::Stream(StreamEvent::Writable { id }) => {
                        self.flush_quic_write_for_stream(ch, id);
                    }
                    QuicEvent::Stream(StreamEvent::Stopped { id, .. }) => {
                        if let Some(&tok) = self.tok_by_stream.get(&(ch, id)) {
                            let mut close_now = false;
                            if let Some(out) = self.tcp_outbounds.get_mut(&tok) {
                                if let OutboundTcpState::Relaying {
                                    pending_to_quic,
                                    q_pos,
                                    pending_to_tcp,
                                    tcp_eof,
                                    quic_eof,
                                    ..
                                } = &mut out.state
                                {
                                    pending_to_quic.clear();
                                    *q_pos = 0;
                                    *tcp_eof = true;
                                    if *quic_eof && pending_to_tcp.is_empty() {
                                        close_now = true;
                                    }
                                }
                            }
                            if close_now {
                                self.close_tcp_outbound(tok, false);
                            }
                        }
                    }
                    QuicEvent::DatagramReceived => {
                        self.drain_incoming_datagrams(ch, now);
                    }
                    _ => {}
                }
            }
        }

        for (ch, reason) in dead_conns {
            self.remove_quic_conn(ch, &reason);
        }

        // 3.5) 执行一轮延迟的边缘触发读写续传（!ready 流原序保前防饥饿，确保高吞吐下载不饿死并发交互流）
        let n_tcp = self.deferred_tcp_reads.len();
        let mut skipped_tcp = VecDeque::new();
        for _ in 0..n_tcp {
            if let Some(tok) = self.deferred_tcp_reads.pop_front() {
                if let Some(ch) = self.tcp_outbounds.get(&tok).map(|o| o.conn_handle) {
                    let ready = self.conns.get(&ch).is_none_or(|q| q.burst_drained);
                    if ready {
                        self.handle_outbound_tcp_readable(tok);
                    } else {
                        skipped_tcp.push_back(tok);
                    }
                }
            }
        }
        while let Some(tok) = skipped_tcp.pop_back() {
            self.deferred_tcp_reads.push_front(tok);
        }
        let n_quic = self.deferred_quic_reads.len();
        for _ in 0..n_quic {
            if let Some((ch, sid)) = self.deferred_quic_reads.pop_front() {
                if self.tok_by_stream.contains_key(&(ch, sid)) {
                    self.pump_quic_to_outbound_tcp(ch, sid);
                }
            }
        }

        // 4) 批量刷出所有 QUIC 下行报文（有 sendmmsg 批处理时合并单次系统调用直发公网！）
        self.flush_all_transmits(outer, now);

        // 5) 计算精确的下一次唤醒时间（支持 2ms Brutal Pacer 定时唤醒）
        let has_ready_tcp_read = self.deferred_tcp_reads.iter().any(|tok| {
            self.tcp_outbounds
                .get(tok)
                .and_then(|o| self.conns.get(&o.conn_handle))
                .is_none_or(|q| q.burst_drained)
        });
        if self.more_tx_pending || has_ready_tcp_read || !self.deferred_quic_reads.is_empty() {
            return Duration::ZERO;
        }
        let mut wait = Duration::from_secs(1);
        for q in self.conns.values_mut() {
            if let Some(t) = q.conn.poll_timeout() {
                wait = wait.min(t.saturating_duration_since(now));
            }
            if !q.burst_drained && !self.deferred_tcp_reads.is_empty() {
                let fuse = q.burst_started_at + Duration::from_millis(120);
                wait = wait.min(fuse.saturating_duration_since(now));
            }
        }
        wait
    }

    fn flush_all_transmits(&mut self, outer: &mut ServerOuter<'_>, now: Instant) {
        self.more_tx_pending = false;
        let full_pkt_thresh = (self.inner_mtu as usize).saturating_sub(64);
        let handles: Vec<ConnectionHandle> = self.conns.keys().copied().collect();
        match outer {
            ServerOuter::Forward(ingress) => {
                if let Some(mut tx_batch) = self.tx_batch.take() {
                    for ch in handles {
                        let Some(q) = self.conns.get_mut(&ch) else {
                            continue;
                        };
                        let flow_addr = q.flow_addr;
                        let mut count = 0usize;
                        let mut saw_tail = false;
                        let mut sent_pkts_for_flow = 0usize;
                        let mut sent_bytes_for_flow = 0u64;

                        while count < MAX_QUIC_TRANSMITS_PER_CONN {
                            self.tx_scratch.clear();
                            let Some(t) = q.conn.poll_transmit(now, 1, &mut self.tx_scratch) else {
                                break;
                            };
                            if t.size == 0 {
                                break;
                            }
                            if t.size > 20 {
                                q.burst_bytes_rem =
                                    q.burst_bytes_rem.saturating_sub(t.size.saturating_sub(12));
                            }
                            if t.size > 20 && t.size < full_pkt_thresh {
                                saw_tail = true;
                            }
                            let pkt = &self.tx_scratch[..t.size];
                            if tx_batch.is_full() {
                                let (sp, sb) = tx_batch.flush_to(&ingress.listen_sock);
                                sent_pkts_for_flow += sp;
                                sent_bytes_for_flow += sb;
                            }
                            if let Some(slot) = tx_batch.next_slot_mut() {
                                if let Some((wn, peer_addr)) =
                                    ingress.encrypt_downlink_into_slot(flow_addr, pkt, slot, now)
                                {
                                    tx_batch.commit_slot(wn, pkt.len() as u64, Some(peer_addr));
                                }
                            }
                            count += 1;
                        }
                        if count >= MAX_QUIC_TRANSMITS_PER_CONN {
                            self.more_tx_pending = true;
                        } else if !q.burst_drained
                            && (saw_tail
                                || q.burst_bytes_rem == 0
                                || now.saturating_duration_since(q.burst_started_at)
                                    >= Duration::from_millis(120))
                        {
                            q.burst_drained = true;
                            q.burst_bytes_rem = 0;
                        }
                        if !tx_batch.is_empty() {
                            let (sp, sb) = tx_batch.flush_to(&ingress.listen_sock);
                            sent_pkts_for_flow += sp;
                            sent_bytes_for_flow += sb;
                        }
                        if sent_pkts_for_flow > 0 {
                            ingress.record_downlink_sent(
                                flow_addr,
                                sent_pkts_for_flow,
                                sent_bytes_for_flow,
                                now,
                            );
                        }
                    }
                    self.tx_batch = Some(tx_batch);
                } else {
                    for ch in handles {
                        let Some(q) = self.conns.get_mut(&ch) else {
                            continue;
                        };
                        let flow_addr = q.flow_addr;
                        let mut count = 0usize;
                        let mut saw_tail = false;
                        while count < MAX_QUIC_TRANSMITS_PER_CONN {
                            self.tx_scratch.clear();
                            let Some(t) = q.conn.poll_transmit(now, 1, &mut self.tx_scratch) else {
                                break;
                            };
                            if t.size == 0 {
                                break;
                            }
                            if t.size > 20 {
                                q.burst_bytes_rem =
                                    q.burst_bytes_rem.saturating_sub(t.size.saturating_sub(12));
                            }
                            if t.size > 20 && t.size < full_pkt_thresh {
                                saw_tail = true;
                            }
                            ingress.deliver_downlink_single(
                                flow_addr,
                                &self.tx_scratch[..t.size],
                                now,
                            );
                            count += 1;
                        }
                        if count >= MAX_QUIC_TRANSMITS_PER_CONN {
                            self.more_tx_pending = true;
                        } else if !q.burst_drained
                            && (saw_tail
                                || q.burst_bytes_rem == 0
                                || now.saturating_duration_since(q.burst_started_at)
                                    >= Duration::from_millis(120))
                        {
                            q.burst_drained = true;
                            q.burst_bytes_rem = 0;
                        }
                    }
                }
            }
            ServerOuter::Reverse { worker, tunnel_key } => {
                let ready_tok = worker.ready_upstream_tok(*tunnel_key);
                if let (Some(up_tok), Some(mut tx_batch)) = (ready_tok, self.tx_batch.take()) {
                    for ch in handles {
                        let Some(q) = self.conns.get_mut(&ch) else {
                            continue;
                        };
                        let mut count = 0usize;
                        let mut saw_tail = false;
                        while count < MAX_QUIC_TRANSMITS_PER_CONN {
                            self.tx_scratch.clear();
                            let Some(t) = q.conn.poll_transmit(now, 1, &mut self.tx_scratch) else {
                                break;
                            };
                            if t.size == 0 {
                                break;
                            }
                            if t.size > 20 {
                                q.burst_bytes_rem =
                                    q.burst_bytes_rem.saturating_sub(t.size.saturating_sub(12));
                            }
                            if t.size > 20 && t.size < full_pkt_thresh {
                                saw_tail = true;
                            }
                            let pkt = &self.tx_scratch[..t.size];
                            if tx_batch.is_full() {
                                let _ = worker.flush_batched_uplink(up_tok, &mut tx_batch, now);
                            }
                            if let Some(slot) = tx_batch.next_slot_mut() {
                                if let Some(wn) =
                                    worker.wrap_uplink_into_slot(up_tok, pkt, slot, now)
                                {
                                    tx_batch.commit_slot(wn, pkt.len() as u64, None);
                                }
                            }
                            count += 1;
                        }
                        if count >= MAX_QUIC_TRANSMITS_PER_CONN {
                            self.more_tx_pending = true;
                        } else if !q.burst_drained
                            && (saw_tail
                                || q.burst_bytes_rem == 0
                                || now.saturating_duration_since(q.burst_started_at)
                                    >= Duration::from_millis(120))
                        {
                            q.burst_drained = true;
                            q.burst_bytes_rem = 0;
                        }
                    }
                    if !tx_batch.is_empty() {
                        let _ = worker.flush_batched_uplink(up_tok, &mut tx_batch, now);
                    }
                    self.tx_batch = Some(tx_batch);
                } else {
                    for ch in handles {
                        let Some(q) = self.conns.get_mut(&ch) else {
                            continue;
                        };
                        let mut count = 0usize;
                        let mut saw_tail = false;
                        while count < MAX_QUIC_TRANSMITS_PER_CONN {
                            self.tx_scratch.clear();
                            let Some(t) = q.conn.poll_transmit(now, 1, &mut self.tx_scratch) else {
                                break;
                            };
                            if t.size == 0 {
                                break;
                            }
                            if t.size > 20 {
                                q.burst_bytes_rem =
                                    q.burst_bytes_rem.saturating_sub(t.size.saturating_sub(12));
                            }
                            if t.size > 20 && t.size < full_pkt_thresh {
                                saw_tail = true;
                            }
                            worker.send_uplink_single(*tunnel_key, &self.tx_scratch[..t.size], now);
                            count += 1;
                        }
                        if count >= MAX_QUIC_TRANSMITS_PER_CONN {
                            self.more_tx_pending = true;
                        } else if !q.burst_drained
                            && (saw_tail
                                || q.burst_bytes_rem == 0
                                || now.saturating_duration_since(q.burst_started_at)
                                    >= Duration::from_millis(120))
                        {
                            q.burst_drained = true;
                            q.burst_bytes_rem = 0;
                        }
                    }
                }
            }
        }
    }

    fn gc_timers(&mut self, now: Instant) {
        // 清理建连超时的出站 TCP
        let mut timed_out_tcp = Vec::new();
        for (&tok, out) in &self.tcp_outbounds {
            if let OutboundTcpState::Connecting { created_at, .. } = out.state {
                if now.saturating_duration_since(created_at) > TCP_CONNECT_TIMEOUT {
                    timed_out_tcp.push((tok, out.conn_handle, out.stream_id));
                }
            }
        }
        for (tok, ch, sid) in timed_out_tcp {
            self.close_tcp_outbound(tok, false);
            self.send_stream_status_and_close(ch, sid, STREAM_STATUS_CONNECT_FAILED);
        }

        // 清理空闲出站 UDP
        let expired_udp: Vec<Token> = self
            .udp_outbounds
            .iter()
            .filter(|(_, u)| {
                now.saturating_duration_since(u.last_active) > UDP_SESSION_IDLE_TIMEOUT
            })
            .map(|(&tok, _)| tok)
            .collect();
        for tok in expired_udp {
            self.close_udp_outbound(tok);
        }

        for q in self.conns.values_mut() {
            q.udp_reassembler.gc(now);
        }
    }

    fn shutdown_all(&mut self) {
        let tcp_toks: Vec<Token> = self.tcp_outbounds.keys().copied().collect();
        for tok in tcp_toks {
            self.close_tcp_outbound(tok, false);
        }
        let udp_toks: Vec<Token> = self.udp_outbounds.keys().copied().collect();
        for tok in udp_toks {
            self.close_udp_outbound(tok);
        }
        self.conns.clear();
        self.dns_pool.shutdown();
    }
}

/// 启动内嵌类 Hy2 代理服务端（`webrtc-cloak proxy --server`）。
pub fn run_proxy_server(mut cfg: ProxyServerConfig) -> std::io::Result<()> {
    let quiet = cfg.server.quiet;
    let stop = cfg.server.stop.clone();
    PROXY_QUIET.with(|q| q.set(quiet));
    if cfg.server.workers > 1 && !quiet {
        eprintln!("[proxy-server] WARN: embedded proxy server runs in single-thread zero-loopback mode; clamping --workers to 1.");
    }
    cfg.server.workers = 1;

    let cpu = detect_cpu_accel();
    let dtls_pool = build_dimpl_config_pool_for(
        cfg.server.cipher_pref,
        &cpu,
        false,
        cfg.server.wan_mtu,
        outer_udp_hdr_len(cfg.server.listen_addr),
    );
    let telemetry = TelemetryHub::start(
        "proxy-server",
        &cfg.server.telemetry,
        1,
        cfg.server.wan_mtu,
        quiet,
        stop.clone(),
    );

    let mut poll = Poll::new()?;
    register_shutdown_poll(&poll, quiet, stop.is_some());
    let dns_waker = Arc::new(Waker::new(poll.registry(), PROXY_DNS_WAKE_TOKEN)?);
    let shared_poll = SharedPoll::new(poll.registry().try_clone()?);

    let mut engine = ProxyServerEngine::new(shared_poll.clone(), dns_waker, &cfg)?;

    if !quiet {
        println!(
            "[proxy-server] CPU arch={} hw_accel=[{}] recommended={} listen={} max_brutal={:.0}/{:.0}Mbps inner_mtu={} acl_allow={} acl_deny={} reject_private={} ipv4_only={} dtls=dimpl-{} udp_batch={}",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            cfg.server.listen_addr,
            cfg.max_up_bps as f64 / 1e6,
            cfg.max_down_bps as f64 / 1e6,
            engine.inner_mtu,
            cfg.acl.allow.len(),
            cfg.acl.deny.len(),
            cfg.acl.reject_private,
            cfg.acl.outbound_ipv4_only,
            cfg.server.dtls_min_version.as_str(),
            format_udp_batch_mode(cfg.server.udp_batch),
        );
    }

    let stats_dur = Duration::from_secs(cfg.server.stats_interval_secs);
    let stats_enabled = cfg.server.stats_interval_secs > 0;
    let seen_txids = Arc::new(Mutex::new(SeenTxidCache::new()));
    let registry = Arc::new(SharedV4Registry::new(1));

    let mut ingress = ServerWorker::new_for_relay(
        0,
        cfg.server,
        false,
        dtls_pool,
        seen_txids,
        registry,
        shared_poll,
        telemetry.clone(),
    )?;
    ingress.set_persistent_tunnel(true);

    let telemetry_dur = telemetry
        .as_ref()
        .map(|th| th.interval())
        .unwrap_or(Duration::from_secs(TELEMETRY_DEFAULT_INTERVAL_SECS));
    let mut last_telemetry = Instant::now();
    let mut last_stats = last_telemetry;
    let mut last_gc = last_telemetry;
    let mut events = Events::with_capacity(MIO_EVENTS_CAP);

    loop {
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        let now = Instant::now();
        ingress.drain_worker_cmds_with(now, Some(ServerHook::Proxy(&mut engine)));
        let w_in = ingress.process_timers_with(now, Some(ServerHook::Proxy(&mut engine)));
        for flow_addr in ingress.drain_closed_relay_flows() {
            engine.on_outer_flow_closed(flow_addr);
        }

        if now.duration_since(last_gc) >= Duration::from_secs(2) {
            last_gc = now;
            engine.gc_timers(now);
        }

        let w_proxy = engine.drive(&mut ServerOuter::Forward(&mut ingress), now);

        let mut wait = w_in.min(w_proxy);
        if telemetry.is_some() && wait > telemetry_dur {
            wait = telemetry_dur;
        }
        let quiet_cap = Duration::from_millis(WORKER_QUIET_STOP_POLL_MS);
        if stop.is_some() && quiet && wait > quiet_cap {
            wait = quiet_cap;
        }

        if let Err(e) = poll.poll(&mut events, Some(wait)) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            engine.shutdown_all();
            if let Some(ref th) = telemetry {
                th.shutdown();
            }
            return Err(e);
        }
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        let now = Instant::now();
        for ev in events.iter() {
            let tok = ev.token();
            #[cfg(unix)]
            if tok == SHUTDOWN_PIPE_TOKEN {
                continue;
            }
            if tok == WAKE_TOKEN {
                continue;
            }
            if tok == PROXY_DNS_WAKE_TOKEN {
                engine.drain_dns_results(now);
                continue;
            }
            if tok == LISTEN_TOKEN {
                ingress.handle_listen_readable_with(now, Some(ServerHook::Proxy(&mut engine)));
            } else if tok.0 >= PROXY_SERVER_TOK_BASE {
                engine.handle_outbound_event(ev, now);
            }
        }

        for flow_addr in ingress.drain_closed_relay_flows() {
            engine.on_outer_flow_closed(flow_addr);
        }
        let _ = engine.drive(&mut ServerOuter::Forward(&mut ingress), Instant::now());

        let post_now = Instant::now();
        if let Some(ref th) = telemetry {
            if post_now.duration_since(last_telemetry) >= telemetry_dur {
                last_telemetry = post_now;
                th.update_worker(0, ingress.build_worker_snapshot());
            }
        }
        if stats_enabled && post_now.duration_since(last_stats) >= stats_dur {
            last_stats = post_now;
            let snap = ingress.build_worker_snapshot();
            log(
                "proxy-server",
                &format!(
                    "stats outer_sessions={} quic_conns={} tcp_active={} udp_active={} streams_total={} acl_denied={} udp_tx={} udp_rx={} tx={:.1}KB rx={:.1}KB unauth={}",
                    snap.active_sessions,
                    engine.conns.len(),
                    engine.tcp_outbounds.len(),
                    engine.udp_outbounds.len(),
                    engine.total_streams_accepted,
                    engine.total_acl_denied,
                    engine.total_udp_tx,
                    engine.total_udp_rx,
                    snap.tx_bytes_total as f64 / 1024.0,
                    snap.rx_bytes_total as f64 / 1024.0,
                    snap.unauth_drops_total,
                ),
            );
        }
    }

    engine.shutdown_all();
    ingress.graceful_shutdown_all();
    if let Some(ref th) = telemetry {
        th.shutdown();
    }
    Ok(())
}

/// 启动反向内嵌类 Hy2 代理出口端（`webrtc-cloak proxy --server --reverse`）。
///
/// 零公网入站端口：适用于位于 NAT / CGNAT 后的家宽或内网出口机，主动外拨 `proxy --client --reverse`
/// 或 `relay --upstream-mode reverse`，支持 `--lane-hunt`、0ms MBB、1-RTT 迁移与断线自动重连。
pub fn run_proxy_server_reverse(mut cfg: ReverseProxyServerConfig) -> std::io::Result<()> {
    let quiet = cfg.client.quiet;
    let stop = cfg.client.stop.clone();
    PROXY_QUIET.with(|q| q.set(quiet));
    if cfg.client.workers > 1 && !quiet {
        eprintln!("[proxy-rev-server] WARN: reverse proxy server runs in single-thread zero-loopback mode; clamping --workers to 1.");
    }
    cfg.client.workers = 1;

    let cpu = detect_cpu_accel();
    let dtls_pool = build_dimpl_config_pool_for(
        cfg.client.cipher_pref,
        &cpu,
        true,
        cfg.client.wan_mtu,
        outer_udp_hdr_len(cfg.client.server_addr),
    );
    let telemetry = TelemetryHub::start(
        "proxy-rev-server",
        &cfg.client.telemetry,
        1,
        cfg.client.wan_mtu,
        quiet,
        stop.clone(),
    );

    let mut poll = Poll::new()?;
    register_shutdown_poll(&poll, quiet, stop.is_some());
    let dns_waker = Arc::new(Waker::new(poll.registry(), PROXY_DNS_WAKE_TOKEN)?);
    let shared_poll = SharedPoll::new(poll.registry().try_clone()?);

    let mut engine = ProxyServerEngine::new_reverse(shared_poll.clone(), dns_waker, &cfg)?;
    let tunnel_key = proxy_tunnel_key();

    if !quiet {
        println!(
            "[proxy-rev-server] CPU arch={} hw_accel=[{}] recommended={} target={} max_brutal={:.0}/{:.0}Mbps inner_mtu={} acl_allow={} acl_deny={} reject_private={} ipv4_only={} dtls=dimpl-{} udp_batch={}",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            cfg.client.server_addr,
            cfg.max_up_bps as f64 / 1e6,
            cfg.max_down_bps as f64 / 1e6,
            engine.inner_mtu,
            cfg.acl.allow.len(),
            cfg.acl.deny.len(),
            cfg.acl.reject_private,
            cfg.acl.outbound_ipv4_only,
            cfg.client.dtls_min_version.as_str(),
            format_udp_batch_mode(cfg.client.udp_batch),
        );
    }

    let stats_dur = Duration::from_secs(cfg.client.stats_interval_secs);
    let stats_enabled = cfg.client.stats_interval_secs > 0;
    let mut client = ClientWorker::new_for_proxy_client(
        0,
        cfg.client,
        dtls_pool,
        shared_poll,
        telemetry.clone(),
        tunnel_key,
    );

    let telemetry_dur = telemetry
        .as_ref()
        .map(|th| th.interval())
        .unwrap_or(Duration::from_secs(TELEMETRY_DEFAULT_INTERVAL_SECS));
    let mut last_telemetry = Instant::now();
    let mut last_stats = last_telemetry;
    let mut last_gc = last_telemetry;
    let mut events = Events::with_capacity(MIO_EVENTS_CAP);

    loop {
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        let now = Instant::now();
        client.ensure_persistent_tunnel(tunnel_key, now);
        let (w_outer, mut standby_promoted, mut standby_ready) = client.process_timers_relay(now);

        if now.duration_since(last_gc) >= Duration::from_secs(2) {
            last_gc = now;
            engine.gc_timers(now);
        }

        let w_proxy = engine.drive(
            &mut ServerOuter::Reverse {
                worker: &mut client,
                tunnel_key,
            },
            now,
        );

        let mut wait = w_outer.min(w_proxy);
        if telemetry.is_some() && wait > telemetry_dur {
            wait = telemetry_dur;
        }
        let quiet_cap = Duration::from_millis(WORKER_QUIET_STOP_POLL_MS);
        if stop.is_some() && quiet && wait > quiet_cap {
            wait = quiet_cap;
        }

        if let Err(e) = poll.poll(&mut events, Some(wait)) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            engine.shutdown_all();
            if let Some(ref th) = telemetry {
                th.shutdown();
            }
            return Err(e);
        }
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        let now = Instant::now();
        let mut graceful_reconnects: Vec<(Token, SocketAddr)> = Vec::new();
        for ev in events.iter() {
            let tok = ev.token();
            #[cfg(unix)]
            if tok == SHUTDOWN_PIPE_TOKEN {
                continue;
            }
            if tok == WAKE_TOKEN {
                continue;
            }
            if tok == PROXY_DNS_WAKE_TOKEN {
                engine.drain_dns_results(now);
                continue;
            }
            if tok.0 >= PROXY_SERVER_TOK_BASE && tok.0 < usize::MAX - 4 {
                engine.handle_outbound_event(ev, now);
            } else {
                client.handle_event_proxy_server(
                    tok,
                    &mut engine,
                    now,
                    &mut standby_ready,
                    &mut standby_promoted,
                    &mut graceful_reconnects,
                );
            }
        }

        client.process_post_events_relay(now, standby_ready, standby_promoted, graceful_reconnects);
        client.ensure_persistent_tunnel(tunnel_key, Instant::now());
        let _ = engine.drive(
            &mut ServerOuter::Reverse {
                worker: &mut client,
                tunnel_key,
            },
            Instant::now(),
        );

        let post_now = Instant::now();
        if let Some(ref th) = telemetry {
            if post_now.duration_since(last_telemetry) >= telemetry_dur {
                last_telemetry = post_now;
                th.update_worker(0, client.build_worker_snapshot());
            }
        }
        if stats_enabled && post_now.duration_since(last_stats) >= stats_dur {
            last_stats = post_now;
            let snap = client.build_worker_snapshot();
            log(
                "proxy-rev-server",
                &format!(
                    "stats outer_sport={} quic_conns={} tcp_active={} udp_active={} streams_total={} acl_denied={} udp_tx={} udp_rx={} tx={:.1}KB rx={:.1}KB loss={:.1}%",
                    snap.active_up_sport,
                    engine.conns.len(),
                    engine.tcp_outbounds.len(),
                    engine.udp_outbounds.len(),
                    engine.total_streams_accepted,
                    engine.total_acl_denied,
                    engine.total_udp_tx,
                    engine.total_udp_rx,
                    snap.tx_bytes_total as f64 / 1024.0,
                    snap.rx_bytes_total as f64 / 1024.0,
                    snap.data_loss_pct,
                ),
            );
        }
    }

    engine.shutdown_all();
    client.graceful_shutdown_all();
    if let Some(ref th) = telemetry {
        th.shutdown();
    }
    Ok(())
}
