//! 内嵌类 Hy2 代理客户端（`webrtc-cloak proxy --client`）。
//!
//! 在单一 `mio::Poll` 事件循环中融合：
//! - 外层 `ClientWorker`（DTLS 1.3 + Dual-SSRC SRTP + Lane Hunt + 0ms MBB + 1-RTT 迁移）；
//! - 内层 `quinn-proto` Sans-IO 状态机（No-op 加密 + Brutal 拥塞控制 + RFC 9221 Datagram）；
//! - 本地 SOCKS5 代理（TCP CONNECT + UDP ASSOCIATE，零侵入对接 Mihomo/OpenClash）；
//! - 可重复的本地 L4 TCP 端口转发（`--tcp-forward 127.0.0.1:19443=198.51.100.10:443`）。

use super::brutal::{BrutalConfig, BrutalRateHandle};
use super::proto::{
    decode_udp_datagram, encode_udp_datagrams, CtrlHello, TargetAddr, TcpForwardRule,
    UdpFragReassembler, CTRL_HELLO_LEN, STREAM_CMD_TCP, STREAM_STATUS_ACL_DENIED, STREAM_STATUS_OK,
};
use super::quic_crypto::{
    build_endpoint_config, build_quic_client_config, build_transport_config,
    compute_inner_quic_mtu, DEFAULT_QUIC_IDLE_TIMEOUT_SECS,
};
use super::{log, make_udp_socket, proxy_quic_peer_addr, proxy_tunnel_key, PROXY_QUIET};
use crate::client::{ClientConfig, ClientWorker, REV_BACKEND_TOK_BASE};
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
use mio::net::{TcpListener, TcpStream, UdpSocket as MioUdpSocket};
use mio::{Events, Interest, Poll, Token};
use quinn_proto::{
    Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, Event as QuicEvent, ReadError,
    StreamEvent, StreamId, VarInt, WriteError,
};
use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 客户端本地 SOCKS5 / L4 转发 / 套接字在 `mio::Poll` 中的令牌基址（与 `ClientWorker` 严格隔离）。
const PROXY_CLIENT_TOK_BASE: usize = REV_BACKEND_TOK_BASE;
const SOCKS_ACCEPT_TOK: Token = Token(PROXY_CLIENT_TOK_BASE);
const FWD_ACCEPT_BASE: usize = PROXY_CLIENT_TOK_BASE + 1;
const DYN_TOK_BASE: usize = PROXY_CLIENT_TOK_BASE + 256;

/// 单次事件循环每条流最多搬运字节数，防止单条高速流饿死其他并发流或 ACK。
const STREAM_IO_BUDGET: usize = 64 * 1024;
/// 单次 QUIC 刷包最大报文数上限。
const MAX_QUIC_TRANSMITS_PER_PASS: usize = 64;
/// 建连等待队列最长容忍时长（秒）。
const PENDING_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
/// 内层 QUIC 断线后重拨退避（毫秒）。
const QUIC_RECONNECT_BACKOFF: Duration = Duration::from_millis(300);

/// 内嵌类 Hy2 代理客户端配置（`webrtc-cloak proxy --client`）。
#[derive(Clone)]
pub struct ProxyClientConfig {
    pub client: ClientConfig,
    /// 可选本地 SOCKS5 监听地址（TCP + UDP Associate），`None` 表示关闭 SOCKS5。
    pub socks_listen: Option<SocketAddr>,
    /// 可选固定 L4 TCP 端口转发列表（例如 `127.0.0.1:19443=198.51.100.10:443`）。
    pub tcp_forwards: Vec<TcpForwardRule>,
    /// 期望上行带宽（bit/s），协商后写入客户端 Brutal 控制器。
    pub up_bps: u64,
    /// 期望下行带宽（bit/s），通过 Control Stream 通知服务端 Brutal 控制器。
    pub down_bps: u64,
    /// 可选内层 QUIC MTU 覆盖（字节，`None` 默认收敛至 1200B 对齐 WebRTC/Hy2 伪装包长）。
    pub proxy_mtu: Option<u16>,
}

/// 反向内嵌类 Hy2 代理入口客户端配置（`webrtc-cloak proxy --client --reverse`）。
///
/// 被动监听公网 UDP 端口等待 NAT 后方的 `proxy --server --reverse` 主动反连，
/// 在本机提供 SOCKS5 与 `--tcp-forward` 入口，零回环直驱内层 No-op QUIC + Brutal。
#[derive(Clone)]
pub struct ReverseProxyClientConfig {
    pub server: ServerConfig,
    pub socks_listen: Option<SocketAddr>,
    pub tcp_forwards: Vec<TcpForwardRule>,
    pub up_bps: u64,
    pub down_bps: u64,
    /// 可选内层 QUIC MTU 覆盖（字节，`None` 默认收敛至 1200B 对齐 WebRTC/Hy2 伪装包长）。
    pub proxy_mtu: Option<u16>,
}

enum ClientOuter<'a> {
    Forward {
        worker: &'a mut ClientWorker,
        tunnel_key: SocketAddr,
    },
    Reverse {
        worker: &'a mut ServerWorker,
        flow_addr: Option<SocketAddr>,
    },
}

impl ClientOuter<'_> {
    #[inline]
    fn is_ready(&self) -> bool {
        match self {
            ClientOuter::Forward { worker, tunnel_key } => {
                worker.ready_upstream_tok(*tunnel_key).is_some()
            }
            ClientOuter::Reverse { flow_addr, .. } => flow_addr.is_some(),
        }
    }

    #[inline]
    fn send_single(&mut self, pkt: &[u8], now: Instant) {
        match self {
            ClientOuter::Forward { worker, tunnel_key } => {
                worker.send_uplink_single(*tunnel_key, pkt, now);
            }
            ClientOuter::Reverse { worker, flow_addr } => {
                if let Some(fa) = *flow_addr {
                    worker.deliver_downlink_single(fa, pkt, now);
                }
            }
        }
    }
}

enum ClientTcpState {
    SocksGreeting {
        rx: Vec<u8>,
        tx: Vec<u8>,
        tx_pos: usize,
    },
    SocksRequest {
        rx: Vec<u8>,
    },
    /// 等待内层 QUIC 连接就绪后再打开对应 Stream。
    WaitQuicReady {
        target: TargetAddr,
        is_socks5: bool,
        created_at: Instant,
    },
    /// 已发送 `[STREAM_CMD_TCP, target]`，等待服务端返回 1 字节状态码。
    WaitServerReply {
        stream_id: StreamId,
        is_socks5: bool,
        pending_to_quic: Vec<u8>,
        q_pos: usize,
        tcp_eof: bool,
    },
    /// 全双工字节透传中。
    Relaying {
        stream_id: StreamId,
        pending_to_quic: Vec<u8>,
        q_pos: usize,
        pending_to_tcp: Vec<u8>,
        t_pos: usize,
        tcp_eof: bool,
        quic_eof: bool,
    },
    /// SOCKS5 错误应答刷完即关。
    FlushAndClose {
        tx: Vec<u8>,
        tx_pos: usize,
    },
    /// SOCKS5 UDP ASSOCIATE 控制连接（按 RFC 1928 §7 保活，TCP 断开即销毁对应 UDP 套接字）。
    SocksUdpCtrl {
        session_id: u32,
        tx: Vec<u8>,
        tx_pos: usize,
    },
}

struct ClientTcpConn {
    stream: TcpStream,
    interest: Interest,
    state: ClientTcpState,
}

struct ClientUdpSession {
    udp_tok: Token,
    sock: MioUdpSocket,
    client_peer: Option<SocketAddr>,
}

struct InnerQuicConn {
    handle: ConnectionHandle,
    conn: Connection,
    rate_handle: Arc<BrutalRateHandle>,
    established: bool,
    ctrl_stream: Option<StreamId>,
    ctrl_rx: Vec<u8>,
    ctrl_negotiated: bool,
    /// True once the previous video-frame-shaped TCP->QUIC uplink burst has drained its tail packet.
    burst_drained: bool,
    burst_bytes_rem: usize,
    burst_started_at: Instant,
}

pub(crate) struct ProxyClientEngine {
    poll: SharedPoll,
    endpoint: Endpoint,
    brutal_cfg: Arc<BrutalConfig>,
    quic_client_cfg: quinn_proto::ClientConfig,
    up_bps: u64,
    down_bps: u64,
    inner_mtu: u16,
    socks_listener: Option<TcpListener>,
    fwd_listeners: Vec<(Token, TcpListener, TargetAddr)>,
    next_dyn_tok: usize,
    tcp_conns: HashMap<Token, ClientTcpConn>,
    tok_by_stream: HashMap<StreamId, Token>,
    pending_open_toks: VecDeque<Token>,
    next_udp_session_id: u32,
    udp_sessions: HashMap<u32, ClientUdpSession>,
    udp_sess_by_tok: HashMap<Token, u32>,
    udp_reassembler: UdpFragReassembler,
    next_frag_id: u16,
    quic: Option<InnerQuicConn>,
    last_quic_attempt: Option<Instant>,
    rx_queue: VecDeque<Vec<u8>>,
    deferred_tcp_reads: VecDeque<Token>,
    deferred_quic_reads: VecDeque<StreamId>,
    more_tx_pending: bool,
    tx_scratch: Vec<u8>,
    tx_batch: Option<UdpSendBatch>,
    io_buf: Vec<u8>,
    udp_buf: Vec<u8>,
    total_streams_opened: u64,
    total_udp_tx: u64,
    total_udp_rx: u64,
}

impl ProxyClientEngine {
    fn new(poll: SharedPoll, cfg: &ProxyClientConfig) -> std::io::Result<Self> {
        Self::new_common(
            poll,
            cfg.client.server_addr,
            cfg.client.wan_mtu,
            cfg.proxy_mtu,
            cfg.client.udp_batch,
            cfg.socks_listen,
            &cfg.tcp_forwards,
            cfg.up_bps,
            cfg.down_bps,
        )
    }

    fn new_reverse(poll: SharedPoll, cfg: &ReverseProxyClientConfig) -> std::io::Result<Self> {
        Self::new_common(
            poll,
            cfg.server.listen_addr,
            cfg.server.wan_mtu,
            cfg.proxy_mtu,
            cfg.server.udp_batch,
            cfg.socks_listen,
            &cfg.tcp_forwards,
            cfg.up_bps,
            cfg.down_bps,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_common(
        poll: SharedPoll,
        outer_addr: SocketAddr,
        wan_mtu: usize,
        proxy_mtu: Option<u16>,
        udp_batch: usize,
        socks_listen: Option<SocketAddr>,
        tcp_forwards: &[TcpForwardRule],
        up_bps: u64,
        down_bps: u64,
    ) -> std::io::Result<Self> {
        let outer_hdr = outer_udp_hdr_len(outer_addr);
        let inner_mtu = compute_inner_quic_mtu(wan_mtu, outer_hdr, proxy_mtu);
        let ep_cfg = build_endpoint_config(inner_mtu);
        let endpoint = Endpoint::new(Arc::new(ep_cfg), None, true, None);
        let brutal_cfg = Arc::new(BrutalConfig::new(up_bps / 8));
        let transport = build_transport_config(
            inner_mtu,
            Arc::clone(&brutal_cfg),
            DEFAULT_QUIC_IDLE_TIMEOUT_SECS,
            None,
        );
        let quic_client_cfg = build_quic_client_config(transport);

        let socks_listener = if let Some(addr) = socks_listen {
            let mut l = TcpListener::bind(addr)?;
            poll.registry()
                .register(&mut l, SOCKS_ACCEPT_TOK, Interest::READABLE)?;
            Some(l)
        } else {
            None
        };

        let mut fwd_listeners = Vec::with_capacity(tcp_forwards.len());
        for (idx, rule) in tcp_forwards.iter().enumerate() {
            if idx >= 250 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "too many --tcp-forward rules (max 250)",
                ));
            }
            let tok = Token(FWD_ACCEPT_BASE + idx);
            let mut l = TcpListener::bind(rule.listen)?;
            poll.registry().register(&mut l, tok, Interest::READABLE)?;
            fwd_listeners.push((tok, l, rule.target.clone()));
        }

        let wbuf_len = worker_udp_write_buf_len(wan_mtu);
        let tx_batch =
            is_udp_batch_active(udp_batch).then(|| UdpSendBatch::new(udp_batch, wbuf_len));

        Ok(Self {
            poll,
            endpoint,
            brutal_cfg,
            quic_client_cfg,
            up_bps,
            down_bps,
            inner_mtu,
            socks_listener,
            fwd_listeners,
            next_dyn_tok: 0,
            tcp_conns: HashMap::with_capacity(64),
            tok_by_stream: HashMap::with_capacity(64),
            pending_open_toks: VecDeque::with_capacity(16),
            next_udp_session_id: 1,
            udp_sessions: HashMap::with_capacity(16),
            udp_sess_by_tok: HashMap::with_capacity(16),
            udp_reassembler: UdpFragReassembler::default(),
            next_frag_id: 1,
            quic: None,
            last_quic_attempt: None,
            rx_queue: VecDeque::with_capacity(64),
            deferred_tcp_reads: VecDeque::with_capacity(32),
            deferred_quic_reads: VecDeque::with_capacity(32),
            more_tx_pending: false,
            tx_scratch: Vec::with_capacity(2048),
            tx_batch,
            io_buf: vec![0u8; 32 * 1024],
            udp_buf: vec![0u8; 65_536],
            total_streams_opened: 0,
            total_udp_tx: 0,
            total_udp_rx: 0,
        })
    }

    fn alloc_dyn_token(&mut self) -> Token {
        let span = (usize::MAX - 8).saturating_sub(DYN_TOK_BASE).max(1);
        loop {
            let off = self.next_dyn_tok;
            self.next_dyn_tok = (self.next_dyn_tok + 1) % span;
            let tok = Token(DYN_TOK_BASE + off);
            if !self.tcp_conns.contains_key(&tok) && !self.udp_sess_by_tok.contains_key(&tok) {
                return tok;
            }
        }
    }

    /// 外层 `ClientWorker` 解密下行的 SRTP 数据包后零回环直递本方法。
    #[inline]
    pub(crate) fn on_tunnel_datagram(&mut self, payload: &[u8]) {
        if !payload.is_empty() {
            self.rx_queue.push_back(payload.to_vec());
        }
    }

    fn ensure_quic_conn(&mut self, outer_ready: bool, now: Instant) {
        if self.quic.is_some() || !outer_ready {
            return;
        }
        if let Some(last) = self.last_quic_attempt {
            if now.saturating_duration_since(last) < QUIC_RECONNECT_BACKOFF {
                return;
            }
        }
        self.last_quic_attempt = Some(now);
        match self.endpoint.connect(
            now,
            self.quic_client_cfg.clone(),
            proxy_quic_peer_addr(),
            "cloak-proxy.internal",
        ) {
            Ok((handle, conn)) => {
                let rate_handle = self.brutal_cfg.take_last_rate_handle();
                self.quic = Some(InnerQuicConn {
                    handle,
                    conn,
                    rate_handle,
                    established: false,
                    ctrl_stream: None,
                    ctrl_rx: Vec::with_capacity(CTRL_HELLO_LEN),
                    ctrl_negotiated: false,
                    burst_drained: true,
                    burst_bytes_rem: 0,
                    burst_started_at: now,
                });
            }
            Err(e) => {
                log(
                    "proxy-client",
                    &format!("inner QUIC connect error: {:?}", e),
                );
            }
        }
    }

    fn reset_quic_conn(&mut self, reason: &str) {
        if let Some(old) = self.quic.take() {
            let _ = old;
            log("proxy-client", &format!("inner QUIC closed ({})", reason));
        }
        // 关闭所有绑定在旧 QUIC 连接上的 TCP 流（避免僵尸连接挂起）
        let dead_toks: Vec<Token> = self.tok_by_stream.drain().map(|(_, t)| t).collect();
        for tok in dead_toks {
            self.close_tcp_conn(tok);
        }
    }

    fn update_tcp_interest(&mut self, tok: Token, want: Interest) {
        if let Some(c) = self.tcp_conns.get_mut(&tok) {
            if c.interest != want {
                c.interest = want;
                let _ = self.poll.registry().reregister(&mut c.stream, tok, want);
            }
        }
    }

    fn close_tcp_conn(&mut self, tok: Token) {
        let Some(mut c) = self.tcp_conns.remove(&tok) else {
            return;
        };
        let _ = self.poll.registry().deregister(&mut c.stream);
        match c.state {
            ClientTcpState::WaitServerReply { stream_id, .. }
            | ClientTcpState::Relaying { stream_id, .. } => {
                self.tok_by_stream.remove(&stream_id);
                if let Some(ref mut q) = self.quic {
                    let _ = q.conn.send_stream(stream_id).reset(VarInt::from_u32(0));
                    let _ = q.conn.recv_stream(stream_id).stop(VarInt::from_u32(0));
                }
            }
            ClientTcpState::SocksUdpCtrl { session_id, .. } => {
                if let Some(mut sess) = self.udp_sessions.remove(&session_id) {
                    self.udp_sess_by_tok.remove(&sess.udp_tok);
                    let _ = self.poll.registry().deregister(&mut sess.sock);
                }
            }
            _ => {}
        }
    }

    fn handle_local_event(&mut self, ev: &MioEvent, now: Instant) {
        let tok = ev.token();
        if tok == SOCKS_ACCEPT_TOK {
            self.accept_socks();
            return;
        }
        if tok.0 >= FWD_ACCEPT_BASE && tok.0 < DYN_TOK_BASE {
            let idx = tok.0 - FWD_ACCEPT_BASE;
            self.accept_forward(idx, now);
            return;
        }
        if let Some(&sess_id) = self.udp_sess_by_tok.get(&tok) {
            self.handle_local_udp_readable(sess_id);
            return;
        }
        if self.tcp_conns.contains_key(&tok) {
            if ev.is_error() {
                self.close_tcp_conn(tok);
                return;
            }
            if ev.is_writable() {
                self.handle_tcp_writable(tok);
            }
            if ev.is_readable() && self.tcp_conns.contains_key(&tok) {
                self.handle_tcp_readable(tok, now);
            }
        }
    }

    fn accept_socks(&mut self) {
        let mut accepted = Vec::new();
        if let Some(ref listener) = self.socks_listener {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => accepted.push(stream),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        for mut stream in accepted {
            let _ = stream.set_nodelay(true);
            let tok = self.alloc_dyn_token();
            if self
                .poll
                .registry()
                .register(&mut stream, tok, Interest::READABLE)
                .is_err()
            {
                continue;
            }
            self.tcp_conns.insert(
                tok,
                ClientTcpConn {
                    stream,
                    interest: Interest::READABLE,
                    state: ClientTcpState::SocksGreeting {
                        rx: Vec::with_capacity(32),
                        tx: Vec::new(),
                        tx_pos: 0,
                    },
                },
            );
        }
    }

    fn accept_forward(&mut self, idx: usize, now: Instant) {
        let mut accepted = Vec::new();
        let target = if let Some((_, ref listener, ref tgt)) = self.fwd_listeners.get(idx) {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => accepted.push(stream),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            tgt.clone()
        } else {
            return;
        };
        for mut stream in accepted {
            let _ = stream.set_nodelay(true);
            let tok = self.alloc_dyn_token();
            if self
                .poll
                .registry()
                .register(&mut stream, tok, Interest::READABLE)
                .is_err()
            {
                continue;
            }
            self.tcp_conns.insert(
                tok,
                ClientTcpConn {
                    stream,
                    interest: Interest::READABLE,
                    state: ClientTcpState::WaitQuicReady {
                        target: target.clone(),
                        is_socks5: false,
                        created_at: now,
                    },
                },
            );
            if !self.try_open_stream_for_tok(tok) {
                self.pending_open_toks.push_back(tok);
            }
        }
    }

    fn try_open_stream_for_tok(&mut self, tok: Token) -> bool {
        let ready = self.quic.as_ref().is_some_and(|q| q.established);
        if !ready {
            return false;
        }
        let Some(conn_entry) = self.tcp_conns.get_mut(&tok) else {
            return true;
        };
        let (target, is_socks5) = match &conn_entry.state {
            ClientTcpState::WaitQuicReady {
                target, is_socks5, ..
            } => (target.clone(), *is_socks5),
            _ => return true,
        };
        let Some(ref mut q) = self.quic else {
            return false;
        };
        let Some(stream_id) = q.conn.streams().open(Dir::Bi) else {
            return false;
        };
        let mut hdr = Vec::with_capacity(32);
        hdr.push(STREAM_CMD_TCP);
        target.encode(&mut hdr);
        let mut q_pos = 0usize;
        while q_pos < hdr.len() {
            match q.conn.send_stream(stream_id).write(&hdr[q_pos..]) {
                Ok(0) | Err(WriteError::Blocked) => break,
                Ok(n) => q_pos += n,
                Err(_) => {
                    self.close_tcp_conn(tok);
                    return true;
                }
            }
        }
        let pending_to_quic = if q_pos < hdr.len() {
            hdr[q_pos..].to_vec()
        } else {
            Vec::new()
        };
        self.total_streams_opened += 1;
        self.tok_by_stream.insert(stream_id, tok);
        if let Some(c) = self.tcp_conns.get_mut(&tok) {
            c.state = ClientTcpState::WaitServerReply {
                stream_id,
                is_socks5,
                pending_to_quic,
                q_pos: 0,
                tcp_eof: false,
            };
        }
        true
    }

    fn handle_tcp_writable(&mut self, tok: Token) {
        let mut close_now = false;
        let mut next_interest: Option<Interest> = None;
        let mut drain_quic_stream: Option<StreamId> = None;

        if let Some(c) = self.tcp_conns.get_mut(&tok) {
            match &mut c.state {
                ClientTcpState::SocksGreeting { tx, tx_pos, .. } => {
                    while *tx_pos < tx.len() {
                        match c.stream.write(&tx[*tx_pos..]) {
                            Ok(0) => {
                                close_now = true;
                                break;
                            }
                            Ok(n) => *tx_pos += n,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => {
                                close_now = true;
                                break;
                            }
                        }
                    }
                    if !close_now && *tx_pos >= tx.len() {
                        c.state = ClientTcpState::SocksRequest {
                            rx: Vec::with_capacity(64),
                        };
                        next_interest = Some(Interest::READABLE);
                    }
                }
                ClientTcpState::FlushAndClose { tx, tx_pos } => {
                    while *tx_pos < tx.len() {
                        match c.stream.write(&tx[*tx_pos..]) {
                            Ok(0) => {
                                close_now = true;
                                break;
                            }
                            Ok(n) => *tx_pos += n,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => {
                                close_now = true;
                                break;
                            }
                        }
                    }
                    if *tx_pos >= tx.len() {
                        close_now = true;
                    }
                }
                ClientTcpState::SocksUdpCtrl { tx, tx_pos, .. } => {
                    while *tx_pos < tx.len() {
                        match c.stream.write(&tx[*tx_pos..]) {
                            Ok(0) => {
                                close_now = true;
                                break;
                            }
                            Ok(n) => *tx_pos += n,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => {
                                close_now = true;
                                break;
                            }
                        }
                    }
                    if !close_now && *tx_pos >= tx.len() {
                        tx.clear();
                        *tx_pos = 0;
                        next_interest = Some(Interest::READABLE);
                    }
                }
                ClientTcpState::Relaying {
                    stream_id,
                    pending_to_quic,
                    pending_to_tcp,
                    t_pos,
                    tcp_eof,
                    quic_eof,
                    ..
                } => {
                    while *t_pos < pending_to_tcp.len() {
                        match c.stream.write(&pending_to_tcp[*t_pos..]) {
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
                        if *quic_eof {
                            let _ = c.stream.shutdown(Shutdown::Write);
                            if *tcp_eof && pending_to_quic.is_empty() {
                                close_now = true;
                            }
                        } else {
                            drain_quic_stream = Some(*stream_id);
                        }
                        if !close_now {
                            let want = if !*tcp_eof && pending_to_quic.is_empty() {
                                Interest::READABLE
                            } else {
                                // 没有待写给 TCP 且暂停读 TCP：仅保持可读用于感知对端 FIN/RST
                                Interest::READABLE
                            };
                            next_interest = Some(want);
                        }
                    }
                }
                _ => {
                    next_interest = Some(Interest::READABLE);
                }
            }
        }

        if close_now {
            self.close_tcp_conn(tok);
            return;
        }
        if let Some(want) = next_interest {
            self.update_tcp_interest(tok, want);
        }
        if let Some(sid) = drain_quic_stream {
            self.pump_quic_to_tcp(sid);
        }
    }

    fn handle_tcp_readable(&mut self, tok: Token, now: Instant) {
        enum Action {
            None,
            Close,
            UpdateInterest(Interest),
            TryOpenStream,
            SetupUdpAssociate,
        }
        let mut action = Action::None;

        if let Some(c) = self.tcp_conns.get_mut(&tok) {
            match &mut c.state {
                ClientTcpState::SocksGreeting { rx, tx, tx_pos } => {
                    if !tx.is_empty() {
                        return;
                    }
                    loop {
                        match c.stream.read(&mut self.io_buf[..256]) {
                            Ok(0) => {
                                action = Action::Close;
                                break;
                            }
                            Ok(n) => {
                                rx.extend_from_slice(&self.io_buf[..n]);
                                if rx.len() > 260 {
                                    action = Action::Close;
                                    break;
                                }
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => {
                                action = Action::Close;
                                break;
                            }
                        }
                    }
                    if !matches!(action, Action::Close) && rx.len() >= 2 {
                        if rx[0] != 0x05 {
                            action = Action::Close;
                        } else {
                            let nm = rx[1] as usize;
                            if rx.len() >= 2 + nm {
                                let reply = [0x05u8, 0x00u8];
                                match c.stream.write(&reply) {
                                    Ok(2) => {
                                        let leftover = rx[2 + nm..].to_vec();
                                        c.state = ClientTcpState::SocksRequest { rx: leftover };
                                        if let ClientTcpState::SocksRequest { rx: ref l } = c.state
                                        {
                                            if !l.is_empty() {
                                                // 继续直接解析紧随其后的 SOCKS5 Request
                                            }
                                        }
                                    }
                                    Ok(n) => {
                                        *tx = reply[n..].to_vec();
                                        *tx_pos = 0;
                                        action = Action::UpdateInterest(
                                            Interest::READABLE | Interest::WRITABLE,
                                        );
                                    }
                                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                        *tx = reply.to_vec();
                                        *tx_pos = 0;
                                        action = Action::UpdateInterest(
                                            Interest::READABLE | Interest::WRITABLE,
                                        );
                                    }
                                    Err(_) => action = Action::Close,
                                }
                            }
                        }
                    }
                }
                ClientTcpState::SocksUdpCtrl { .. } => {
                    // 控制连接只要 EOF 或错误就拆除关联的 UDP 会话
                    loop {
                        match c.stream.read(&mut self.io_buf[..256]) {
                            Ok(0) => {
                                action = Action::Close;
                                break;
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => {
                                action = Action::Close;
                                break;
                            }
                        }
                    }
                }
                ClientTcpState::WaitQuicReady { .. } | ClientTcpState::FlushAndClose { .. } => {}
                ClientTcpState::WaitServerReply { .. } => {
                    // 等待服务端 1B 确认期间暂缓读取本地 TCP（由 OS 缓冲提供天然背压）
                }
                ClientTcpState::Relaying {
                    stream_id,
                    pending_to_quic,
                    q_pos,
                    pending_to_tcp,
                    tcp_eof,
                    quic_eof,
                    ..
                } => {
                    let sid = *stream_id;
                    if !pending_to_quic.is_empty() || *tcp_eof {
                        return;
                    }
                    let Some(ref mut q) = self.quic else {
                        self.close_tcp_conn(tok);
                        return;
                    };
                    if !q.burst_drained {
                        if !self.deferred_tcp_reads.contains(&tok) {
                            self.deferred_tcp_reads.push_back(tok);
                        }
                        return;
                    }
                    // v0.7.1: Shape bulk uplink TCP->QUIC bursts identically to downlink video frames:
                    // 5..=10 full-MTU packets + 1 genuine 500..=979B frame-tail packet per burst.
                    let mss = (self.inner_mtu as usize).saturating_sub(42).max(512);
                    let full_pkts = 5 + ((rand_u32() as usize) % 6);
                    let tail_bytes = 500 + ((rand_u32() as usize) % 480);
                    let mut budget = (full_pkts * mss + tail_bytes).min(STREAM_IO_BUDGET);
                    let mut total_written = 0usize;
                    let mut hit_would_block = false;
                    while budget > 0 {
                        let cap = self.io_buf.len().min(budget);
                        match c.stream.read(&mut self.io_buf[..cap]) {
                            Ok(0) => {
                                *tcp_eof = true;
                                hit_would_block = true;
                                let _ = q.conn.send_stream(sid).finish();
                                if *quic_eof && pending_to_tcp.is_empty() {
                                    action = Action::Close;
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
                                            action = Action::Close;
                                            write_blocked = true;
                                            break;
                                        }
                                    }
                                }
                                if matches!(action, Action::Close) {
                                    hit_would_block = true;
                                    break;
                                }
                                if write_blocked {
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
                                action = Action::Close;
                                hit_would_block = true;
                                break;
                            }
                        }
                    }
                    if !hit_would_block && total_written >= mss {
                        q.burst_drained = false;
                        q.burst_bytes_rem = q.burst_bytes_rem.saturating_add(total_written);
                        q.burst_started_at = now;
                    }
                    if !hit_would_block && !self.deferred_tcp_reads.contains(&tok) {
                        self.deferred_tcp_reads.push_back(tok);
                    }
                }
                ClientTcpState::SocksRequest { .. } => {}
            }
        }

        // 单独处理 SocksRequest（兼容 Greeting 同包黏连场景）
        if matches!(action, Action::None)
            && matches!(
                self.tcp_conns.get(&tok).map(|c| &c.state),
                Some(ClientTcpState::SocksRequest { .. })
            )
        {
            if let Some(c) = self.tcp_conns.get_mut(&tok) {
                if let ClientTcpState::SocksRequest { rx } = &mut c.state {
                    loop {
                        match c.stream.read(&mut self.io_buf[..512]) {
                            Ok(0) => {
                                action = Action::Close;
                                break;
                            }
                            Ok(n) => {
                                rx.extend_from_slice(&self.io_buf[..n]);
                                if rx.len() > 512 {
                                    action = Action::Close;
                                    break;
                                }
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => {
                                action = Action::Close;
                                break;
                            }
                        }
                    }
                    if !matches!(action, Action::Close) && rx.len() >= 4 {
                        if rx[0] != 0x05 {
                            action = Action::Close;
                        } else {
                            let cmd = rx[1];
                            match TargetAddr::decode(&rx[3..]) {
                                Ok(Some((target, _consumed))) => match cmd {
                                    0x01 => {
                                        c.state = ClientTcpState::WaitQuicReady {
                                            target,
                                            is_socks5: true,
                                            created_at: now,
                                        };
                                        action = Action::TryOpenStream;
                                    }
                                    0x03 => {
                                        action = Action::SetupUdpAssociate;
                                    }
                                    _ => {
                                        let rep = socks5_reply(0x07, None);
                                        c.state =
                                            ClientTcpState::FlushAndClose { tx: rep, tx_pos: 0 };
                                        action = Action::UpdateInterest(
                                            Interest::READABLE | Interest::WRITABLE,
                                        );
                                    }
                                },
                                Ok(None) => {}
                                Err(()) => action = Action::Close,
                            }
                        }
                    }
                }
            }
        }

        match action {
            Action::None => {}
            Action::Close => self.close_tcp_conn(tok),
            Action::UpdateInterest(want) => {
                self.update_tcp_interest(tok, want);
                if want.is_writable() {
                    self.handle_tcp_writable(tok);
                }
            }
            Action::TryOpenStream => {
                if !self.try_open_stream_for_tok(tok) {
                    self.pending_open_toks.push_back(tok);
                }
            }
            Action::SetupUdpAssociate => {
                self.setup_socks_udp_associate(tok);
            }
        }
    }

    fn setup_socks_udp_associate(&mut self, ctrl_tok: Token) {
        let bind_ip = self
            .tcp_conns
            .get(&ctrl_tok)
            .and_then(|c| c.stream.local_addr().ok())
            .map(|a| a.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut udp_sock = match make_udp_socket(SocketAddr::new(bind_ip, 0), SOCK_BUF_4MIB) {
            Ok(s) => s,
            Err(_) => {
                self.close_tcp_conn(ctrl_tok);
                return;
            }
        };
        let local_udp_addr = match udp_sock.local_addr() {
            Ok(a) => a,
            Err(_) => {
                self.close_tcp_conn(ctrl_tok);
                return;
            }
        };
        let udp_tok = self.alloc_dyn_token();
        if self
            .poll
            .registry()
            .register(&mut udp_sock, udp_tok, Interest::READABLE)
            .is_err()
        {
            self.close_tcp_conn(ctrl_tok);
            return;
        }
        let sid = self.next_udp_session_id;
        self.next_udp_session_id = self.next_udp_session_id.wrapping_add(1).max(1);
        self.udp_sessions.insert(
            sid,
            ClientUdpSession {
                udp_tok,
                sock: udp_sock,
                client_peer: None,
            },
        );
        self.udp_sess_by_tok.insert(udp_tok, sid);

        let reply = socks5_reply(0x00, Some(local_udp_addr));
        if let Some(c) = self.tcp_conns.get_mut(&ctrl_tok) {
            c.state = ClientTcpState::SocksUdpCtrl {
                session_id: sid,
                tx: reply,
                tx_pos: 0,
            };
        }
        self.update_tcp_interest(ctrl_tok, Interest::READABLE | Interest::WRITABLE);
        self.handle_tcp_writable(ctrl_tok);
    }

    fn handle_local_udp_readable(&mut self, session_id: u32) {
        let mut pkts: Vec<(SocketAddr, TargetAddr, Vec<u8>)> = Vec::new();
        if let Some(sess) = self.udp_sessions.get_mut(&session_id) {
            loop {
                let (n, src) = match sess.sock.recv_from(&mut self.udp_buf) {
                    Ok(v) => v,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                if n < 7 || self.udp_buf[0] != 0 || self.udp_buf[1] != 0 || self.udp_buf[2] != 0 {
                    continue;
                }
                sess.client_peer = Some(src);
                if let Ok(Some((dst, alen))) = TargetAddr::decode(&self.udp_buf[3..n]) {
                    pkts.push((src, dst, self.udp_buf[3 + alen..n].to_vec()));
                }
            }
        }
        let Some(ref mut q) = self.quic else {
            return;
        };
        if !q.established {
            return;
        }
        let max_dgram = q
            .conn
            .datagrams()
            .max_size()
            .unwrap_or(self.inner_mtu.saturating_sub(48) as usize);
        for (_src, dst, payload) in pkts {
            let fid = self.next_frag_id;
            self.next_frag_id = self.next_frag_id.wrapping_add(1);
            let encoded = encode_udp_datagrams(session_id, fid, &dst, &payload, max_dgram);
            for frame in encoded {
                if q.conn.datagrams().send(Bytes::from(frame), false).is_ok() {
                    self.total_udp_tx += 1;
                }
            }
        }
    }

    fn flush_quic_write_for_stream(&mut self, stream_id: StreamId) {
        let Some(&tok) = self.tok_by_stream.get(&stream_id) else {
            return;
        };
        let mut close_now = false;
        let mut finish_now = false;
        let mut resume_tcp_read = false;
        if let (Some(c), Some(ref mut q)) = (self.tcp_conns.get_mut(&tok), self.quic.as_mut()) {
            match &mut c.state {
                ClientTcpState::WaitServerReply {
                    pending_to_quic,
                    q_pos,
                    ..
                } => {
                    while *q_pos < pending_to_quic.len() {
                        match q
                            .conn
                            .send_stream(stream_id)
                            .write(&pending_to_quic[*q_pos..])
                        {
                            Ok(n) => *q_pos += n,
                            Err(WriteError::Blocked) => break,
                            Err(_) => {
                                close_now = true;
                                break;
                            }
                        }
                    }
                    if *q_pos >= pending_to_quic.len() {
                        pending_to_quic.clear();
                        *q_pos = 0;
                    }
                }
                ClientTcpState::Relaying {
                    pending_to_quic,
                    q_pos,
                    pending_to_tcp,
                    tcp_eof,
                    quic_eof,
                    ..
                } => {
                    while *q_pos < pending_to_quic.len() {
                        match q
                            .conn
                            .send_stream(stream_id)
                            .write(&pending_to_quic[*q_pos..])
                        {
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
                            finish_now = true;
                            if *quic_eof && pending_to_tcp.is_empty() {
                                close_now = true;
                            }
                        } else {
                            resume_tcp_read = true;
                        }
                    }
                }
                _ => {}
            }
            if finish_now {
                let _ = q.conn.send_stream(stream_id).finish();
            }
        }
        if close_now {
            self.close_tcp_conn(tok);
        } else if resume_tcp_read {
            self.deferred_tcp_reads.push_back(tok);
        }
    }

    fn pump_quic_to_tcp(&mut self, stream_id: StreamId) {
        // 先检查是否是 Control Stream
        if self
            .quic
            .as_ref()
            .is_some_and(|q| q.ctrl_stream == Some(stream_id))
        {
            self.pump_ctrl_stream(stream_id);
            return;
        }
        let Some(&tok) = self.tok_by_stream.get(&stream_id) else {
            return;
        };
        let mut close_now = false;
        let mut need_writable = false;

        // 1) 若在 WaitServerReply，先读出 1B 状态码及任何紧随的业务数据
        if matches!(
            self.tcp_conns.get(&tok).map(|c| &c.state),
            Some(ClientTcpState::WaitServerReply { .. })
        ) {
            let mut got_status: Option<u8> = None;
            let mut extra_data = Vec::new();
            let mut hit_eof = false;
            let mut hit_reset = false;
            if let Some(ref mut q) = self.quic {
                if let Ok(mut chunks) = q.conn.recv_stream(stream_id).read(true) {
                    loop {
                        match chunks.next(32 * 1024) {
                            Ok(Some(chunk)) => {
                                if got_status.is_none() && !chunk.bytes.is_empty() {
                                    got_status = Some(chunk.bytes[0]);
                                    if chunk.bytes.len() > 1 {
                                        extra_data.extend_from_slice(&chunk.bytes[1..]);
                                    }
                                    break;
                                }
                            }
                            Ok(None) => {
                                hit_eof = true;
                                break;
                            }
                            Err(ReadError::Blocked) => break,
                            Err(ReadError::Reset(_)) => {
                                hit_reset = true;
                                break;
                            }
                        }
                    }
                    let _ = chunks.finalize();
                }
            }
            if hit_reset || (got_status.is_none() && hit_eof) {
                self.close_tcp_conn(tok);
                return;
            }
            if let Some(status) = got_status {
                if let Some(c) = self.tcp_conns.get_mut(&tok) {
                    if let ClientTcpState::WaitServerReply {
                        is_socks5,
                        pending_to_quic,
                        q_pos,
                        tcp_eof,
                        ..
                    } = &mut c.state
                    {
                        if status == STREAM_STATUS_OK {
                            let mut out = Vec::new();
                            if *is_socks5 {
                                out.extend_from_slice(&socks5_reply(0x00, None));
                            }
                            out.extend_from_slice(&extra_data);
                            let p_q = std::mem::take(pending_to_quic);
                            let qp = *q_pos;
                            let teof = *tcp_eof;
                            c.state = ClientTcpState::Relaying {
                                stream_id,
                                pending_to_quic: p_q,
                                q_pos: qp,
                                pending_to_tcp: out,
                                t_pos: 0,
                                tcp_eof: teof,
                                quic_eof: hit_eof,
                            };
                            need_writable = true;
                        } else {
                            let rep = if status == STREAM_STATUS_ACL_DENIED {
                                0x02
                            } else {
                                0x05
                            };
                            if *is_socks5 {
                                c.state = ClientTcpState::FlushAndClose {
                                    tx: socks5_reply(rep, None),
                                    tx_pos: 0,
                                };
                                need_writable = true;
                            } else {
                                close_now = true;
                            }
                        }
                    }
                }
            }
            if close_now {
                self.close_tcp_conn(tok);
                return;
            }
            if need_writable {
                // 转入 Relaying 后可能已有提前到达的本地 TCP 数据（如 --tcp-forward），立即排期读取
                if matches!(
                    self.tcp_conns.get(&tok).map(|c| &c.state),
                    Some(ClientTcpState::Relaying { .. })
                ) {
                    self.deferred_tcp_reads.push_back(tok);
                }
                self.update_tcp_interest(tok, Interest::READABLE | Interest::WRITABLE);
                self.handle_tcp_writable(tok);
                if !self.tcp_conns.contains_key(&tok) {
                    return;
                }
            }
        }

        // 2) 处于 Relaying 状态且 pending_to_tcp 为空时直接从 QUIC 搬运到 TCP
        let mut hit_quic_blocked = true;
        if let (Some(c), Some(ref mut q)) = (self.tcp_conns.get_mut(&tok), self.quic.as_mut()) {
            if let ClientTcpState::Relaying {
                pending_to_quic,
                pending_to_tcp,
                t_pos,
                tcp_eof,
                quic_eof,
                ..
            } = &mut c.state
            {
                if !pending_to_tcp.is_empty() || *quic_eof {
                    return;
                }
                let mut budget = STREAM_IO_BUDGET;
                hit_quic_blocked = false;
                if let Ok(mut chunks) = q.conn.recv_stream(stream_id).read(true) {
                    while budget > 0 {
                        match chunks.next(budget.min(32 * 1024)) {
                            Ok(Some(chunk)) => {
                                let data = &chunk.bytes;
                                budget = budget.saturating_sub(data.len());
                                let mut written = 0usize;
                                while written < data.len() {
                                    match c.stream.write(&data[written..]) {
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
                                    let _ = c.stream.shutdown(Shutdown::Write);
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

        if close_now {
            self.close_tcp_conn(tok);
        } else {
            if need_writable {
                self.update_tcp_interest(tok, Interest::READABLE | Interest::WRITABLE);
            }
            if !hit_quic_blocked {
                self.deferred_quic_reads.push_back(stream_id);
            }
        }
    }

    fn pump_ctrl_stream(&mut self, stream_id: StreamId) {
        let Some(ref mut q) = self.quic else {
            return;
        };
        if q.ctrl_negotiated {
            return;
        }
        if let Ok(mut chunks) = q.conn.recv_stream(stream_id).read(true) {
            while let Ok(Some(chunk)) = chunks.next(64) {
                q.ctrl_rx.extend_from_slice(&chunk.bytes);
                if q.ctrl_rx.len() >= CTRL_HELLO_LEN {
                    break;
                }
            }
            let _ = chunks.finalize();
        }
        if let Some(hello) = CtrlHello::decode(&q.ctrl_rx) {
            q.ctrl_negotiated = true;
            let granted_up_bytes = (hello.up_bps / 8).max(super::brutal::MIN_BRUTAL_BYTES_PER_SEC);
            q.rate_handle.store(granted_up_bytes);
            log(
                "proxy-client",
                &format!(
                    "QUIC+Brutal READY (No-op crypto, mtu={}) negotiated up={:.1}Mbps down={:.1}Mbps",
                    self.inner_mtu,
                    hello.up_bps as f64 / 1e6,
                    hello.down_bps as f64 / 1e6
                ),
            );
        }
    }

    fn drain_incoming_datagrams(&mut self, now: Instant) {
        let mut received = Vec::new();
        if let Some(ref mut q) = self.quic {
            while let Some(d) = q.conn.datagrams().recv() {
                received.push(d);
            }
        }
        for raw in received {
            if let Some(frame) = decode_udp_datagram(&raw) {
                if let Some((sid, src_addr, payload)) = self.udp_reassembler.push(frame, now) {
                    if let Some(sess) = self.udp_sessions.get(&sid) {
                        if let Some(peer) = sess.client_peer {
                            let mut pkt = Vec::with_capacity(32 + payload.len());
                            pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
                            src_addr.encode(&mut pkt);
                            pkt.extend_from_slice(&payload);
                            if sess.sock.send_to(&pkt, peer).is_ok() {
                                self.total_udp_rx += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    fn drive(&mut self, outer: &mut ClientOuter<'_>, now: Instant) -> Duration {
        let outer_ready = outer.is_ready();
        self.ensure_quic_conn(outer_ready, now);

        // 1) 喂入来自外层 WebRTC-Cloak 的下行 QUIC 报文
        let peer_addr = proxy_quic_peer_addr();
        while let Some(raw) = self.rx_queue.pop_front() {
            let mut resp_buf = Vec::new();
            let ev = self.endpoint.handle(
                now,
                peer_addr,
                None,
                None,
                BytesMut::from(&raw[..]),
                &mut resp_buf,
            );
            match ev {
                Some(DatagramEvent::ConnectionEvent(ch, cev)) => {
                    if let Some(ref mut q) = self.quic {
                        if q.handle == ch {
                            q.conn.handle_event(cev);
                        }
                    }
                }
                Some(DatagramEvent::Response(_)) if !resp_buf.is_empty() => {
                    outer.send_single(&resp_buf, now);
                }
                _ => {}
            }
        }

        // 2) 推进 QUIC 定时器与 Endpoint 事件
        if let Some(ref mut q) = self.quic {
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
        }

        // 3) 消费 QUIC 应用事件
        let mut quic_events = Vec::new();
        if let Some(ref mut q) = self.quic {
            while let Some(ev) = q.conn.poll() {
                quic_events.push(ev);
            }
        }
        let mut lost_reason: Option<String> = None;
        for ev in quic_events {
            match ev {
                QuicEvent::Connected => {
                    if let Some(ref mut q) = self.quic {
                        q.established = true;
                        if let Some(sid) = q.conn.streams().open(Dir::Bi) {
                            let hello = CtrlHello {
                                up_bps: self.up_bps,
                                down_bps: self.down_bps,
                            }
                            .encode();
                            let _ = q.conn.send_stream(sid).write(&hello);
                            q.ctrl_stream = Some(sid);
                        }
                    }
                    // 立即为排队中的本地连接打开 QUIC 流
                    let pending: Vec<Token> = self.pending_open_toks.drain(..).collect();
                    for tok in pending {
                        if !self.try_open_stream_for_tok(tok) && self.tcp_conns.contains_key(&tok) {
                            self.pending_open_toks.push_back(tok);
                        }
                    }
                }
                QuicEvent::ConnectionLost { reason } => {
                    lost_reason = Some(format!("{:?}", reason));
                }
                QuicEvent::Stream(StreamEvent::Readable { id }) => {
                    self.pump_quic_to_tcp(id);
                }
                QuicEvent::Stream(StreamEvent::Writable { id }) => {
                    self.flush_quic_write_for_stream(id);
                }
                QuicEvent::Stream(StreamEvent::Stopped { id, .. }) => {
                    // 对端停止接收我方上行（STOP_SENDING），仅关闭发送侧，绝不提前丢弃对端待读的响应/下行数据
                    if let Some(&tok) = self.tok_by_stream.get(&id) {
                        let mut close_now = false;
                        if let Some(c) = self.tcp_conns.get_mut(&tok) {
                            match &mut c.state {
                                ClientTcpState::WaitServerReply {
                                    pending_to_quic,
                                    q_pos,
                                    tcp_eof,
                                    ..
                                } => {
                                    pending_to_quic.clear();
                                    *q_pos = 0;
                                    *tcp_eof = true;
                                }
                                ClientTcpState::Relaying {
                                    pending_to_quic,
                                    q_pos,
                                    pending_to_tcp,
                                    tcp_eof,
                                    quic_eof,
                                    ..
                                } => {
                                    pending_to_quic.clear();
                                    *q_pos = 0;
                                    *tcp_eof = true;
                                    if *quic_eof && pending_to_tcp.is_empty() {
                                        close_now = true;
                                    }
                                }
                                _ => {}
                            }
                        }
                        if close_now {
                            self.close_tcp_conn(tok);
                        }
                    }
                }
                QuicEvent::DatagramReceived => {
                    self.drain_incoming_datagrams(now);
                }
                _ => {}
            }
        }
        if let Some(reason) = lost_reason {
            self.reset_quic_conn(&reason);
        }

        // 清理超时的 WaitQuicReady 连接
        let mut timed_out = Vec::new();
        for (&tok, c) in &self.tcp_conns {
            if let ClientTcpState::WaitQuicReady { created_at, .. } = c.state {
                if now.saturating_duration_since(created_at) > PENDING_OPEN_TIMEOUT {
                    timed_out.push(tok);
                }
            }
        }
        for tok in timed_out {
            self.close_tcp_conn(tok);
        }

        // 3.5) 执行一轮延迟的边缘触发读写续传（遇 !burst_drained 立即 break 保留队首公平轮转，杜绝多流饥饿）
        let n_tcp = self.deferred_tcp_reads.len();
        for _ in 0..n_tcp {
            if self.quic.as_ref().is_some_and(|q| !q.burst_drained) {
                break;
            }
            if let Some(tok) = self.deferred_tcp_reads.pop_front() {
                if self.tcp_conns.contains_key(&tok) {
                    self.handle_tcp_readable(tok, now);
                }
            }
        }
        let n_quic = self.deferred_quic_reads.len();
        for _ in 0..n_quic {
            if let Some(sid) = self.deferred_quic_reads.pop_front() {
                if self.tok_by_stream.contains_key(&sid) {
                    self.pump_quic_to_tcp(sid);
                }
            }
        }

        // 4) 批量刷出所有待发 QUIC 报文（有 sendmmsg 批处理时合并一次系统调用直发公网！）
        self.flush_quic_transmits(outer, now);

        // 5) 计算精确的下一次唤醒时间（支持 2ms Brutal Pacer 定时唤醒）
        let has_ready_tcp_read = !self.deferred_tcp_reads.is_empty()
            && self.quic.as_ref().is_none_or(|q| q.burst_drained);
        if self.more_tx_pending || has_ready_tcp_read || !self.deferred_quic_reads.is_empty() {
            return Duration::ZERO;
        }
        let mut wait = Duration::from_secs(1);
        if let Some(ref mut q) = self.quic {
            if let Some(t) = q.conn.poll_timeout() {
                wait = wait.min(t.saturating_duration_since(now));
            }
            if !q.burst_drained && !self.deferred_tcp_reads.is_empty() {
                let fuse = q.burst_started_at + Duration::from_millis(120);
                wait = wait.min(fuse.saturating_duration_since(now));
            }
        } else if outer_ready {
            wait = wait.min(QUIC_RECONNECT_BACKOFF);
        }
        wait
    }

    fn flush_quic_transmits(&mut self, outer: &mut ClientOuter<'_>, now: Instant) {
        self.more_tx_pending = false;
        let full_pkt_thresh = (self.inner_mtu as usize).saturating_sub(64);
        let Some(ref mut q) = self.quic else {
            return;
        };
        let mut count = 0usize;
        let mut saw_tail = false;

        match outer {
            ClientOuter::Forward { worker, tunnel_key } => {
                let ready_tok = worker.ready_upstream_tok(*tunnel_key);
                if let (Some(up_tok), Some(mut tx_batch)) = (ready_tok, self.tx_batch.take()) {
                    while count < MAX_QUIC_TRANSMITS_PER_PASS {
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
                            if let Some(wn) = worker.wrap_uplink_into_slot(up_tok, pkt, slot, now) {
                                tx_batch.commit_slot(wn, pkt.len() as u64, None);
                            }
                        }
                        count += 1;
                    }
                    if !tx_batch.is_empty() {
                        let _ = worker.flush_batched_uplink(up_tok, &mut tx_batch, now);
                    }
                    self.tx_batch = Some(tx_batch);
                } else {
                    while count < MAX_QUIC_TRANSMITS_PER_PASS {
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
                }
            }
            ClientOuter::Reverse { worker, flow_addr } => {
                let Some(fa) = *flow_addr else {
                    return;
                };
                if let Some(mut tx_batch) = self.tx_batch.take() {
                    let mut sent_pkts = 0usize;
                    let mut sent_bytes = 0u64;
                    while count < MAX_QUIC_TRANSMITS_PER_PASS {
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
                            let (sp, sb) = tx_batch.flush_to(&worker.listen_sock);
                            sent_pkts += sp;
                            sent_bytes += sb;
                        }
                        if let Some(slot) = tx_batch.next_slot_mut() {
                            if let Some((wn, peer_addr)) =
                                worker.encrypt_downlink_into_slot(fa, pkt, slot, now)
                            {
                                tx_batch.commit_slot(wn, pkt.len() as u64, Some(peer_addr));
                            }
                        }
                        count += 1;
                    }
                    if !tx_batch.is_empty() {
                        let (sp, sb) = tx_batch.flush_to(&worker.listen_sock);
                        sent_pkts += sp;
                        sent_bytes += sb;
                    }
                    if sent_pkts > 0 {
                        worker.record_downlink_sent(fa, sent_pkts, sent_bytes, now);
                    }
                    self.tx_batch = Some(tx_batch);
                } else {
                    while count < MAX_QUIC_TRANSMITS_PER_PASS {
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
                        worker.deliver_downlink_single(fa, &self.tx_scratch[..t.size], now);
                        count += 1;
                    }
                }
            }
        }
        if count >= MAX_QUIC_TRANSMITS_PER_PASS {
            self.more_tx_pending = true;
        } else if !q.burst_drained
            && (saw_tail
                || q.burst_bytes_rem == 0
                || now.saturating_duration_since(q.burst_started_at) >= Duration::from_millis(120))
        {
            q.burst_drained = true;
            q.burst_bytes_rem = 0;
        }
    }

    fn shutdown_all(&mut self) {
        if let Some(mut l) = self.socks_listener.take() {
            let _ = self.poll.registry().deregister(&mut l);
        }
        for (_, mut l, _) in self.fwd_listeners.drain(..) {
            let _ = self.poll.registry().deregister(&mut l);
        }
        let all_toks: Vec<Token> = self.tcp_conns.keys().copied().collect();
        for tok in all_toks {
            self.close_tcp_conn(tok);
        }
        for (_, mut sess) in self.udp_sessions.drain() {
            let _ = self.poll.registry().deregister(&mut sess.sock);
        }
        self.udp_sess_by_tok.clear();
    }
}

fn socks5_reply(rep: u8, bind: Option<SocketAddr>) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.extend_from_slice(&[0x05, rep, 0x00]);
    match bind {
        Some(SocketAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            out.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0]);
        }
    }
    out
}

/// 启动内嵌类 Hy2 代理客户端（`webrtc-cloak proxy --client`）。
pub fn run_proxy_client(mut cfg: ProxyClientConfig) -> std::io::Result<()> {
    let quiet = cfg.client.quiet;
    let stop = cfg.client.stop.clone();
    PROXY_QUIET.with(|q| q.set(quiet));
    if cfg.client.workers > 1 && !quiet {
        eprintln!("[proxy-client] WARN: embedded proxy client uses a single persistent tunnel; clamping --workers to 1.");
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
        "proxy-client",
        &cfg.client.telemetry,
        1,
        cfg.client.wan_mtu,
        quiet,
        stop.clone(),
    );

    let mut poll = Poll::new()?;
    register_shutdown_poll(&poll, quiet, stop.is_some());
    let shared_poll = SharedPoll::new(poll.registry().try_clone()?);

    let mut engine = ProxyClientEngine::new(shared_poll.clone(), &cfg)?;
    let tunnel_key = proxy_tunnel_key();

    if !quiet {
        let socks_desc = cfg
            .socks_listen
            .map(|a| a.to_string())
            .unwrap_or_else(|| "off".to_string());
        let fwds_desc: Vec<String> = cfg
            .tcp_forwards
            .iter()
            .map(|f| format!("{}->{}", f.listen, f.target))
            .collect();
        println!(
            "[proxy-client] CPU arch={} hw_accel=[{}] recommended={} server={} socks5={} tcp_fwds=[{}] brutal={:.0}/{:.0}Mbps inner_mtu={} dtls=dimpl-{} udp_batch={}",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            cfg.client.server_addr,
            socks_desc,
            fwds_desc.join(","),
            cfg.up_bps as f64 / 1e6,
            cfg.down_bps as f64 / 1e6,
            engine.inner_mtu,
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
    let mut had_ready_outer = false;

    let sync_outer_quic =
        |client: &ClientWorker, engine: &mut ProxyClientEngine, had_ready_outer: &mut bool| {
            let is_ready = client.ready_upstream_tok(tunnel_key).is_some();
            if is_ready {
                *had_ready_outer = true;
            } else if *had_ready_outer {
                *had_ready_outer = false;
                engine.reset_quic_conn("outer tunnel disconnected (non-MBB)");
                engine.last_quic_attempt = None;
            }
        };

    loop {
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        let now = Instant::now();
        client.ensure_persistent_tunnel(tunnel_key, now);
        let (w_outer, mut standby_promoted, mut standby_ready) = client.process_timers_relay(now);
        sync_outer_quic(&client, &mut engine, &mut had_ready_outer);
        let w_inner = engine.drive(
            &mut ClientOuter::Forward {
                worker: &mut client,
                tunnel_key,
            },
            now,
        );

        if now.duration_since(last_gc) >= Duration::from_secs(2) {
            last_gc = now;
            engine.udp_reassembler.gc(now);
        }

        let mut wait = w_outer.min(w_inner);
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
            if tok.0 >= PROXY_CLIENT_TOK_BASE && tok.0 < usize::MAX - 2 {
                engine.handle_local_event(ev, now);
            } else {
                client.handle_event_proxy(
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
        sync_outer_quic(&client, &mut engine, &mut had_ready_outer);
        client.ensure_persistent_tunnel(tunnel_key, Instant::now());
        let _ = engine.drive(
            &mut ClientOuter::Forward {
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
            let q_rtt = engine
                .quic
                .as_ref()
                .map(|q| q.conn.rtt().as_secs_f64() * 1000.0)
                .unwrap_or(0.0);
            log(
                "proxy-client",
                &format!(
                    "stats outer_sport={} quic_rtt={:.1}ms tcp_active={} streams_total={} udp_tx={} udp_rx={} tx={:.1}KB rx={:.1}KB loss={:.1}%",
                    snap.active_up_sport,
                    q_rtt,
                    engine.tcp_conns.len(),
                    engine.total_streams_opened,
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

/// 启动反向内嵌类 Hy2 代理入口客户端（`webrtc-cloak proxy --client --reverse`）。
///
/// 被动监听公网 UDP 端口等待 NAT 后方的 `proxy --server --reverse` 主动反连，
/// 收到 DTLS Ready 会话后自动建立内层 No-op QUIC + Brutal 隧道并对外提供 SOCKS5 / `--tcp-forward`。
pub fn run_proxy_client_reverse(mut cfg: ReverseProxyClientConfig) -> std::io::Result<()> {
    let quiet = cfg.server.quiet;
    let stop = cfg.server.stop.clone();
    PROXY_QUIET.with(|q| q.set(quiet));
    if cfg.server.workers > 1 && !quiet {
        eprintln!("[proxy-rev-client] WARN: reverse proxy client runs in single-thread mode; clamping --workers to 1.");
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
        "proxy-rev-client",
        &cfg.server.telemetry,
        1,
        cfg.server.wan_mtu,
        quiet,
        stop.clone(),
    );

    let mut poll = Poll::new()?;
    register_shutdown_poll(&poll, quiet, stop.is_some());
    let shared_poll = SharedPoll::new(poll.registry().try_clone()?);

    let mut engine = ProxyClientEngine::new_reverse(shared_poll.clone(), &cfg)?;

    if !quiet {
        let socks_desc = cfg
            .socks_listen
            .map(|a| a.to_string())
            .unwrap_or_else(|| "off".to_string());
        let fwds_desc: Vec<String> = cfg
            .tcp_forwards
            .iter()
            .map(|f| format!("{}->{}", f.listen, f.target))
            .collect();
        println!(
            "[proxy-rev-client] CPU arch={} hw_accel=[{}] recommended={} listen={} socks5={} tcp_fwds=[{}] brutal={:.0}/{:.0}Mbps inner_mtu={} dtls=dimpl-{} udp_batch={}",
            cpu.arch,
            cpu.features.join(", "),
            cpu.recommended.name(),
            cfg.server.listen_addr,
            socks_desc,
            fwds_desc.join(","),
            cfg.up_bps as f64 / 1e6,
            cfg.down_bps as f64 / 1e6,
            engine.inner_mtu,
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
    let mut active_flow: Option<SocketAddr> = None;

    let sync_active_flow = |ingress: &mut ServerWorker,
                            engine: &mut ProxyClientEngine,
                            active_flow: &mut Option<SocketAddr>| {
        for closed in ingress.drain_closed_relay_flows() {
            if *active_flow == Some(closed) {
                *active_flow = None;
                engine.reset_quic_conn("reverse exit tunnel closed");
            }
        }
        let cur = ingress.active_ready_relay_flow();
        match cur {
            Some(new_fa) => {
                if *active_flow != Some(new_fa) {
                    if active_flow.is_some() {
                        engine.reset_quic_conn("reverse exit reconnected on new session");
                    }
                    *active_flow = Some(new_fa);
                    engine.last_quic_attempt = None;
                    log(
                        "proxy-rev-client",
                        &format!("reverse exit agent attached flow={}", new_fa),
                    );
                }
            }
            None => {
                if active_flow.is_some() {
                    *active_flow = None;
                    engine.reset_quic_conn("reverse exit tunnel closing");
                }
            }
        }
    };

    loop {
        if is_shutdown_requested(stop.as_ref(), quiet) {
            break;
        }

        let now = Instant::now();
        ingress.drain_worker_cmds_with(now, Some(ServerHook::ProxyClient(&mut engine)));
        let w_outer = ingress.process_timers_with(now, Some(ServerHook::ProxyClient(&mut engine)));
        sync_active_flow(&mut ingress, &mut engine, &mut active_flow);

        let w_inner = engine.drive(
            &mut ClientOuter::Reverse {
                worker: &mut ingress,
                flow_addr: active_flow,
            },
            now,
        );

        if now.duration_since(last_gc) >= Duration::from_secs(2) {
            last_gc = now;
            engine.udp_reassembler.gc(now);
        }

        let mut wait = w_outer.min(w_inner);
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
            if tok == LISTEN_TOKEN {
                ingress
                    .handle_listen_readable_with(now, Some(ServerHook::ProxyClient(&mut engine)));
            } else if tok.0 >= PROXY_CLIENT_TOK_BASE && tok.0 < usize::MAX - 4 {
                engine.handle_local_event(ev, now);
            }
        }

        sync_active_flow(&mut ingress, &mut engine, &mut active_flow);
        let _ = engine.drive(
            &mut ClientOuter::Reverse {
                worker: &mut ingress,
                flow_addr: active_flow,
            },
            Instant::now(),
        );

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
            let q_rtt = engine
                .quic
                .as_ref()
                .map(|q| q.conn.rtt().as_secs_f64() * 1000.0)
                .unwrap_or(0.0);
            log(
                "proxy-rev-client",
                &format!(
                    "stats outer_sessions={} quic_rtt={:.1}ms tcp_active={} streams_total={} udp_tx={} udp_rx={} tx={:.1}KB rx={:.1}KB unauth={}",
                    snap.active_sessions,
                    q_rtt,
                    engine.tcp_conns.len(),
                    engine.total_streams_opened,
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
