//! 本地离线沙箱回显后端、可编程网络劣化代理与托管客户端/服务端。

use super::{reserve_free_port, tune_socket, XorShift64};
use crate::client::{run_client, ClientConfig};
use crate::protocol::{
    demux_rfc7983, parse_stun, CipherPref, DtlsMinVersion, PacketKind, STUN_BINDING_REQUEST,
};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use std::cmp::Ordering as CmpOrdering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Default, Clone)]
pub(super) struct BackendStats {
    pub(super) unique_seqs: u64,
    pub(super) dup_seqs: u64,
    pub(super) sink_pkts: u64,
    pub(super) sink_bytes: u64,
    pub(super) sink_first: Option<Instant>,
    pub(super) sink_last: Option<Instant>,
}

pub(super) struct EchoBackend {
    pub(super) port: u16,
    pub(super) stats: Arc<Mutex<BackendStats>>,
    pub(super) seen_seqs: Arc<Mutex<HashSet<u64>>>,
    pub(super) stop: Arc<AtomicBool>,
    pub(super) handle: Option<JoinHandle<()>>,
}

impl EchoBackend {
    pub(super) fn start() -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind backend");
        tune_socket(&sock);
        let port = sock.local_addr().unwrap().port();
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();

        let stats = Arc::new(Mutex::new(BackendStats::default()));
        let seen_seqs = Arc::new(Mutex::new(HashSet::<u64>::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let st = Arc::clone(&stats);
        let seen = Arc::clone(&seen_seqs);
        let stop_flag = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            while !stop_flag.load(Ordering::Relaxed) {
                match sock.recv_from(&mut buf) {
                    Ok((n, peer)) => {
                        let pkt = &buf[..n];
                        if pkt.starts_with(b"SINK:") {
                            let now = Instant::now();
                            let mut s = st.lock().unwrap();
                            if s.sink_first.is_none() {
                                s.sink_first = Some(now);
                            }
                            s.sink_last = Some(now);
                            s.sink_pkts += 1;
                            s.sink_bytes += n as u64;
                            continue;
                        }
                        if n >= 12 && &pkt[..4] == b"SEQ:" {
                            let seq = u64::from_be_bytes(pkt[4..12].try_into().unwrap());
                            let mut set = seen.lock().unwrap();
                            let mut s = st.lock().unwrap();
                            if set.insert(seq) {
                                s.unique_seqs += 1;
                            } else {
                                s.dup_seqs += 1;
                            }
                        }
                        let _ = sock.send_to(pkt, peer);
                    }
                    Err(_) => {}
                }
            }
        });

        Self {
            port,
            stats,
            seen_seqs,
            stop,
            handle: Some(handle),
        }
    }

    pub(super) fn snapshot(&self) -> BackendStats {
        self.stats.lock().unwrap().clone()
    }

    pub(super) fn reset(&self) {
        *self.stats.lock().unwrap() = BackendStats::default();
        self.seen_seqs.lock().unwrap().clear();
    }
}

impl Drop for EchoBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Programmable Network Impairment Proxy
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub(super) struct NetProfile {
    pub(super) base_delay_ms: u64,
    pub(super) jitter_ms: u64,
    pub(super) loss_c2s_pct: u32,
    pub(super) loss_s2c_pct: u32,
    pub(super) reorder_pct: u32,
    pub(super) duplicate_pct: u32,
    pub(super) seed: u64,
}

#[derive(Default, Clone)]
pub(super) struct WireStats {
    pub(super) c2s_pkts: u64,
    pub(super) s2c_pkts: u64,
    pub(super) stun_pkts: u64,
    pub(super) dtls_pkts: u64,
    pub(super) srtp_pkts: u64,
    pub(super) srtp_bytes: u64,
    pub(super) srtcp_pkts: u64,
    pub(super) max_wire_udp: usize,
    pub(super) dropped_by_proxy: u64,
    pub(super) reordered_pkts: u64,
    pub(super) duplicated_pkts: u64,
    pub(super) same_txid_ka_retransmits: u64,
    pub(super) blackhole_ka_retransmits: u64,
    pub(super) dl_srtcp_during_blackhole: u64,
    pub(super) ports_seen: Vec<u16>,
    pub(super) captured_valid_stun: Option<Vec<u8>>,
}

struct DelayedPkt {
    deliver_at: Instant,
    seq: u64,
    dir_c2s: bool,
    client_port: u16,
    client_addr: SocketAddr,
    data: Vec<u8>,
}

impl Eq for DelayedPkt {}
impl PartialEq for DelayedPkt {
    fn eq(&self, other: &Self) -> bool {
        self.deliver_at == other.deliver_at && self.seq == other.seq
    }
}
impl Ord for DelayedPkt {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        other
            .deliver_at
            .cmp(&self.deliver_at)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for DelayedPkt {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

pub(super) struct ImpairmentProxy {
    pub(super) port: u16,
    pub(super) stats: Arc<Mutex<WireStats>>,
    pub(super) blackhole_port: Arc<AtomicU16>,
    pub(super) first_port: Arc<AtomicU16>,
    pub(super) latest_port: Arc<AtomicU16>,
    pub(super) stop: Arc<AtomicBool>,
    pub(super) handle: Option<JoinHandle<()>>,
}

impl ImpairmentProxy {
    pub(super) fn start(
        server_port: u16,
        psk: Vec<u8>,
        profile: NetProfile,
        mut drop_first_ka: bool,
    ) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind proxy");
        tune_socket(&front);
        let port = front.local_addr().unwrap().port();
        front.set_nonblocking(true).unwrap();

        let stats = Arc::new(Mutex::new(WireStats::default()));
        let blackhole_port = Arc::new(AtomicU16::new(0));
        let first_port = Arc::new(AtomicU16::new(0));
        let latest_port = Arc::new(AtomicU16::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let st = Arc::clone(&stats);
        let bh_p = Arc::clone(&blackhole_port);
        let fp = Arc::clone(&first_port);
        let lp = Arc::clone(&latest_port);
        let stop_flag = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
            let mut upstreams: HashMap<u16, (UdpSocket, SocketAddr)> = HashMap::new();
            let mut heap: BinaryHeap<DelayedPkt> = BinaryHeap::new();
            let mut rng = XorShift64::new(profile.seed);
            let mut seq_gen: u64 = 0;
            let mut dropped_ka_txid: Option<[u8; 12]> = None;
            let mut bh_first_ka_txid: Option<[u8; 12]> = None;
            let mut buf = vec![0u8; 65536];

            while !stop_flag.load(Ordering::Relaxed) {
                let mut did_work = false;
                let now = Instant::now();

                // 1) Client -> Server
                while let Ok((n, cli_addr)) = front.recv_from(&mut buf) {
                    did_work = true;
                    let pkt = &buf[..n];
                    let cport = cli_addr.port();
                    let _ = fp.compare_exchange(0, cport, Ordering::SeqCst, Ordering::SeqCst);
                    lp.store(cport, Ordering::SeqCst);

                    let kind = demux_rfc7983(pkt);
                    let parsed_stun = if kind == PacketKind::Stun {
                        parse_stun(pkt, &psk)
                    } else {
                        None
                    };
                    let is_ka_stun = parsed_stun
                        .as_ref()
                        .map(|p| {
                            p.authenticated
                                && p.msg_type == STUN_BINDING_REQUEST
                                && !p.use_candidate
                        })
                        .unwrap_or(false);

                    {
                        let mut s = st.lock().unwrap();
                        s.c2s_pkts += 1;
                        if n > s.max_wire_udp {
                            s.max_wire_udp = n;
                        }
                        if !s.ports_seen.contains(&cport) {
                            s.ports_seen.push(cport);
                        }
                        match kind {
                            PacketKind::Stun => {
                                s.stun_pkts += 1;
                                if s.captured_valid_stun.is_none() {
                                    if let Some(ref ps) = parsed_stun {
                                        if ps.authenticated && ps.use_candidate {
                                            s.captured_valid_stun = Some(pkt.to_vec());
                                        }
                                    }
                                }
                            }
                            PacketKind::Dtls => s.dtls_pkts += 1,
                            PacketKind::Srtp => {
                                s.srtp_pkts += 1;
                                s.srtp_bytes += n as u64;
                            }
                            PacketKind::Srtcp => s.srtcp_pkts += 1,
                            PacketKind::Unknown => {}
                        }
                    }

                    // Asymmetric uplink blackhole on blackhole_port
                    let bh = bh_p.load(Ordering::SeqCst);
                    if bh != 0 && cport == bh {
                        if is_ka_stun {
                            if let Some(ref p) = parsed_stun {
                                match bh_first_ka_txid {
                                    None => bh_first_ka_txid = Some(p.txid),
                                    Some(prev) if prev == p.txid => {
                                        st.lock().unwrap().blackhole_ka_retransmits += 1;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        st.lock().unwrap().dropped_by_proxy += 1;
                        continue;
                    }

                    // Single STUN keepalive drop test
                    if is_ka_stun {
                        if let Some(ref p) = parsed_stun {
                            if drop_first_ka {
                                drop_first_ka = false;
                                dropped_ka_txid = Some(p.txid);
                                st.lock().unwrap().dropped_by_proxy += 1;
                                continue;
                            }
                            if dropped_ka_txid == Some(p.txid) {
                                st.lock().unwrap().same_txid_ka_retransmits += 1;
                                dropped_ka_txid = None;
                            }
                        }
                    }

                    // Random C2S loss
                    if rng.chance_pct(profile.loss_c2s_pct) {
                        st.lock().unwrap().dropped_by_proxy += 1;
                        continue;
                    }

                    upstreams.entry(cport).or_insert_with(|| {
                        let s = UdpSocket::bind("127.0.0.1:0").expect("proxy upstream");
                        tune_socket(&s);
                        s.set_nonblocking(true).unwrap();
                        s.connect(srv_addr).unwrap();
                        (s, cli_addr)
                    });

                    let mut delay_ms = compute_delay(&profile, &mut rng);
                    if kind == PacketKind::Srtp && rng.chance_pct(profile.reorder_pct) {
                        delay_ms += rng.range_u64(18, 48);
                        st.lock().unwrap().reordered_pkts += 1;
                    }

                    // Duplicate SRTP wire copy for replay-window defense verification
                    if kind == PacketKind::Srtp && rng.chance_pct(profile.duplicate_pct) {
                        let dup_delay = delay_ms + rng.range_u64(8, 24);
                        seq_gen += 1;
                        heap.push(DelayedPkt {
                            deliver_at: now + Duration::from_millis(dup_delay),
                            seq: seq_gen,
                            dir_c2s: true,
                            client_port: cport,
                            client_addr: cli_addr,
                            data: pkt.to_vec(),
                        });
                        st.lock().unwrap().duplicated_pkts += 1;
                    }

                    if delay_ms == 0 {
                        if let Some((usock, _)) = upstreams.get(&cport) {
                            let _ = usock.send(pkt);
                        }
                    } else {
                        seq_gen += 1;
                        heap.push(DelayedPkt {
                            deliver_at: now + Duration::from_millis(delay_ms),
                            seq: seq_gen,
                            dir_c2s: true,
                            client_port: cport,
                            client_addr: cli_addr,
                            data: pkt.to_vec(),
                        });
                    }
                }

                // 2) Server -> Client
                let bh = bh_p.load(Ordering::SeqCst);
                for (&cport, (usock, cli_addr)) in upstreams.iter() {
                    while let Ok(n) = usock.recv(&mut buf) {
                        did_work = true;
                        let pkt = &buf[..n];
                        let kind = demux_rfc7983(pkt);
                        {
                            let mut s = st.lock().unwrap();
                            s.s2c_pkts += 1;
                            if n > s.max_wire_udp {
                                s.max_wire_udp = n;
                            }
                            match kind {
                                PacketKind::Stun => s.stun_pkts += 1,
                                PacketKind::Dtls => s.dtls_pkts += 1,
                                PacketKind::Srtp => {
                                    s.srtp_pkts += 1;
                                    s.srtp_bytes += n as u64;
                                }
                                PacketKind::Srtcp => {
                                    s.srtcp_pkts += 1;
                                    if bh != 0 && cport == bh {
                                        s.dl_srtcp_during_blackhole += 1;
                                    }
                                }
                                PacketKind::Unknown => {}
                            }
                        }

                        if rng.chance_pct(profile.loss_s2c_pct) {
                            st.lock().unwrap().dropped_by_proxy += 1;
                            continue;
                        }

                        let mut delay_ms = compute_delay(&profile, &mut rng);
                        if kind == PacketKind::Srtp && rng.chance_pct(profile.reorder_pct) {
                            delay_ms += rng.range_u64(18, 48);
                            st.lock().unwrap().reordered_pkts += 1;
                        }

                        if kind == PacketKind::Srtp && rng.chance_pct(profile.duplicate_pct) {
                            let dup_delay = delay_ms + rng.range_u64(8, 24);
                            seq_gen += 1;
                            heap.push(DelayedPkt {
                                deliver_at: now + Duration::from_millis(dup_delay),
                                seq: seq_gen,
                                dir_c2s: false,
                                client_port: cport,
                                client_addr: *cli_addr,
                                data: pkt.to_vec(),
                            });
                            st.lock().unwrap().duplicated_pkts += 1;
                        }

                        if delay_ms == 0 {
                            let _ = front.send_to(pkt, *cli_addr);
                        } else {
                            seq_gen += 1;
                            heap.push(DelayedPkt {
                                deliver_at: now + Duration::from_millis(delay_ms),
                                seq: seq_gen,
                                dir_c2s: false,
                                client_port: cport,
                                client_addr: *cli_addr,
                                data: pkt.to_vec(),
                            });
                        }
                    }
                }

                // 3) Drain scheduled packets ready for delivery
                let now2 = Instant::now();
                while let Some(top) = heap.peek() {
                    if top.deliver_at <= now2 {
                        let item = heap.pop().unwrap();
                        did_work = true;
                        if item.dir_c2s {
                            if let Some((usock, _)) = upstreams.get(&item.client_port) {
                                let _ = usock.send(&item.data);
                            }
                        } else {
                            let _ = front.send_to(&item.data, item.client_addr);
                        }
                    } else {
                        break;
                    }
                }

                if !did_work {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });

        Self {
            port,
            stats,
            blackhole_port,
            first_port,
            latest_port,
            stop,
            handle: Some(handle),
        }
    }

    pub(super) fn snapshot(&self) -> WireStats {
        self.stats.lock().unwrap().clone()
    }
}

fn compute_delay(profile: &NetProfile, rng: &mut XorShift64) -> u64 {
    if profile.base_delay_ms == 0 && profile.jitter_ms == 0 {
        return 0;
    }
    if profile.jitter_ms == 0 {
        return profile.base_delay_ms;
    }
    let lo = profile.base_delay_ms.saturating_sub(profile.jitter_ms);
    let hi = profile.base_delay_ms.saturating_add(profile.jitter_ms);
    rng.range_u64(lo, hi)
}

impl Drop for ImpairmentProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Managed Tunnel Harness (Client + Server + Backend + Optional Proxy)
// ---------------------------------------------------------------------------

pub(super) struct ManagedServer {
    pub(super) stop: Arc<AtomicBool>,
    pub(super) handle: Option<JoinHandle<()>>,
}

impl ManagedServer {
    pub(super) fn start(
        port: u16,
        backend_port: u16,
        psk: Vec<u8>,
        cipher_pref: CipherPref,
        wan_mtu: usize,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let _ = run_server(ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
                psk,
                cipher_pref,
                dtls_required: true,
                dtls_min_version: DtlsMinVersion::Auto,
                workers: 1,
                max_sessions: 128,
                wan_mtu,
                idle_timeout_secs: 120,
                stats_interval_secs: 3600,
                wire_audit_file: None,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(stop_c),
            });
        });
        thread::sleep(Duration::from_millis(40));
        Self {
            stop,
            handle: Some(handle),
        }
    }

    pub(super) fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ManagedServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub(super) struct ManagedClient {
    pub(super) port: u16,
    pub(super) stop: Arc<AtomicBool>,
    pub(super) handle: Option<JoinHandle<()>>,
}

impl ManagedClient {
    pub(super) fn start(
        target_port: u16,
        psk: Vec<u8>,
        cipher_pref: CipherPref,
        wan_mtu: usize,
        keepalive_secs: u64,
        retry_ms: u64,
    ) -> Self {
        let port = reserve_free_port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let _ = run_client(ClientConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), target_port),
                psk,
                cipher_pref,
                dtls_decoy: true,
                dtls_min_version: DtlsMinVersion::Auto,
                rotate_interval_secs: 0,
                rotate_max_bytes: 0,
                rotate_cooldown_secs: 60,
                workers: 1,
                max_sessions: 128,
                wan_mtu,
                retry_ms,
                max_retries: 12,
                keepalive_secs,
                idle_timeout_secs: 120,
                stats_interval_secs: 3600,
                telemetry: TelemetryConfig::default(),
                quiet: true,
                stop: Some(stop_c),
            });
        });
        thread::sleep(Duration::from_millis(40));
        Self {
            port,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for ManagedClient {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub(super) fn connect_app(client_port: u16, timeout_ms: u64) -> UdpSocket {
    let app = UdpSocket::bind("127.0.0.1:0").expect("bind app");
    tune_socket(&app);
    app.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .unwrap();
    app.connect(("127.0.0.1", client_port))
        .expect("connect client");
    app
}

pub(super) fn handshake_app(app: &UdpSocket, max_wait: Duration) -> Option<f64> {
    let t0 = Instant::now();
    let ping = b"HANDSHAKE_PROBE_V034";
    let mut rbuf = [0u8; 256];
    let _ = app.set_read_timeout(Some(Duration::from_millis(120)));
    let _ = app.send(ping);
    while t0.elapsed() < max_wait {
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == ping {
                return Some(t0.elapsed().as_secs_f64() * 1000.0);
            }
        } else {
            let _ = app.send(ping);
        }
    }
    None
}
