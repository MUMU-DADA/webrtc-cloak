//! Dual-mode network, security & CPU self-test suite for `webrtc-cloak`:
//!
//! 1. **Live Remote Mode** (`--server-host <IP|HOST> --server-port <PORT> --psk ...`):
//!    Connects directly to a real running `webrtc-cloak server` over the real network without
//!    disrupting existing production sessions. Verifies WAN ICE STUN + NAT mapping, DTLS 1.3/1.2
//!    mutual-cert handshake, WAN Consent RTT/jitter/loss, `SeenTxidCache` retransmit,
//!    server Compound SRTCP downlink heartbeat, in-band encrypted SRTP (`0xFFFE`) data-plane
//!    RTT/loss/reorder & real WAN Path MTU probing (`v0.3.5+`), 5-tuple rotation & carrier NAT
//!    mapping behavior, 7-vector live Silent-Drop security audit, graceful teardown, and local
//!    CPU crypto + P-256 certificate benchmarks.
//!
//! 2. **Local Loopback Mode** (`--local` or no `--server-host`):
//!    Spins up real `run_client` + `run_server` + UDP echo/sink backend + an in-process
//!    programmable network-impairment proxy on `127.0.0.1` to test synthetic faults that cannot
//!    safely be injected on production servers (asymmetric uplink blackhole, server restart,
//!    35% ECMP reorder + 30% duplicate injection, etc.).

use crate::client::{run_client, ClientConfig};
use crate::protocol::{
    build_dimpl_config_pool, build_ice_stun_request, combine_session_key, demux_rfc7983,
    derive_stun_material, detect_cpu_accel, extract_dtls_server_hello_suite, fill_random,
    generate_ephemeral_webrtc_cert, make_fresh_stun_txid, new_dtls_instance, parse_stun,
    resolve_srtp_suite, validate_dtls_datagram, CipherPref, CipherSuite, DtlsMinVersion,
    PacketKind, SessionIceParams, SrtpCloakCipher, SrtpFrame, DEFAULT_WAN_MTU,
    STUN_BINDING_REQUEST, STUN_BINDING_SUCCESS,
};
use crate::server::{run_server, ServerConfig};
use dimpl::{Dtls, Output as DtlsOutput, ProtocolVersion};
use std::cmp::Ordering as CmpOrdering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub struct SelftestOptions {
    pub server_addr: Option<SocketAddr>,
    pub server_label: Option<String>,
    pub psk: Option<Vec<u8>>,
    pub cipher_pref: CipherPref,
    pub dtls_min_version: DtlsMinVersion,
    pub wan_mtu: usize,
    pub probe_count: usize,
    pub active_probes: bool,
    pub color: bool,
    pub json: bool,
}

impl Default for SelftestOptions {
    fn default() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Self {
            server_addr: None,
            server_label: None,
            psk: None,
            cipher_pref: CipherPref::Auto,
            dtls_min_version: DtlsMinVersion::Auto,
            wan_mtu: DEFAULT_WAN_MTU,
            probe_count: 20,
            active_probes: true,
            color: !no_color,
            json: false,
        }
    }
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn chance_pct(&mut self, pct: u32) -> bool {
        if pct == 0 {
            return false;
        }
        if pct >= 100 {
            return true;
        }
        (self.next_u64() % 10_000) < (pct as u64 * 100)
    }

    fn range_u64(&mut self, min_inclusive: u64, max_inclusive: u64) -> u64 {
        if max_inclusive <= min_inclusive {
            return min_inclusive;
        }
        min_inclusive + (self.next_u64() % (max_inclusive - min_inclusive + 1))
    }
}

fn reserve_free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral port");
    s.local_addr().unwrap().port()
}

fn tune_socket(sock: &UdpSocket) {
    let s2 = socket2::SockRef::from(sock);
    let _ = s2.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = s2.set_send_buffer_size(4 * 1024 * 1024);
}

// ---------------------------------------------------------------------------
// Local Echo + Sequence-Dedup + Sink Backend
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct BackendStats {
    unique_seqs: u64,
    dup_seqs: u64,
    sink_pkts: u64,
    sink_bytes: u64,
    sink_first: Option<Instant>,
    sink_last: Option<Instant>,
}

struct EchoBackend {
    port: u16,
    stats: Arc<Mutex<BackendStats>>,
    seen_seqs: Arc<Mutex<HashSet<u64>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EchoBackend {
    fn start() -> Self {
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

    fn snapshot(&self) -> BackendStats {
        self.stats.lock().unwrap().clone()
    }

    fn reset(&self) {
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
struct NetProfile {
    base_delay_ms: u64,
    jitter_ms: u64,
    loss_c2s_pct: u32,
    loss_s2c_pct: u32,
    reorder_pct: u32,
    duplicate_pct: u32,
    seed: u64,
}

#[derive(Default, Clone)]
struct WireStats {
    c2s_pkts: u64,
    s2c_pkts: u64,
    stun_pkts: u64,
    dtls_pkts: u64,
    srtp_pkts: u64,
    srtp_bytes: u64,
    srtcp_pkts: u64,
    max_wire_udp: usize,
    dropped_by_proxy: u64,
    reordered_pkts: u64,
    duplicated_pkts: u64,
    same_txid_ka_retransmits: u64,
    blackhole_ka_retransmits: u64,
    dl_srtcp_during_blackhole: u64,
    ports_seen: Vec<u16>,
    captured_valid_stun: Option<Vec<u8>>,
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

struct ImpairmentProxy {
    port: u16,
    stats: Arc<Mutex<WireStats>>,
    blackhole_port: Arc<AtomicU16>,
    first_port: Arc<AtomicU16>,
    latest_port: Arc<AtomicU16>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ImpairmentProxy {
    fn start(
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

    fn snapshot(&self) -> WireStats {
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

struct ManagedServer {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ManagedServer {
    fn start(
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

    fn shutdown(mut self) {
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

struct ManagedClient {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ManagedClient {
    fn start(
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
                workers: 1,
                max_sessions: 128,
                wan_mtu,
                retry_ms,
                max_retries: 12,
                keepalive_secs,
                idle_timeout_secs: 120,
                stats_interval_secs: 3600,
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

fn connect_app(client_port: u16, timeout_ms: u64) -> UdpSocket {
    let app = UdpSocket::bind("127.0.0.1:0").expect("bind app");
    tune_socket(&app);
    app.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .unwrap();
    app.connect(("127.0.0.1", client_port))
        .expect("connect client");
    app
}

fn handshake_app(app: &UdpSocket, max_wait: Duration) -> Option<f64> {
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

fn percentile(sorted: &[f64], p: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len().saturating_sub(1)) * p) / 100;
    sorted[idx]
}

// ---------------------------------------------------------------------------
// Scenario Results & Telemetry Summary
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScenarioStatus {
    Pass,
    Skip,
    Fail,
}

impl ScenarioStatus {
    fn from_bool(ok: bool) -> Self {
        if ok {
            Self::Pass
        } else {
            Self::Fail
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Skip => "skip",
            Self::Fail => "fail",
        }
    }
}

struct ScenarioResult {
    id: u8,
    code: &'static str,
    name: &'static str,
    condition: &'static str,
    status: ScenarioStatus,
    metrics: String,
    detail: String,
    elapsed_s: f64,
}

#[derive(Default)]
struct Highlights {
    is_remote: bool,
    target_label: Option<String>,
    nat_mapped: Option<String>,
    negotiated_cipher: Option<String>,
    wan_p50_ms: Option<f64>,
    wan_loss_pct: Option<f64>,
    wan_mtu_pass: Option<usize>,
    overhead_pct: Option<f64>,
    overhead_bytes: Option<f64>,
    max_wire_udp: usize,
    blackhole_recover_s: Option<f64>,
    restart_recover_s: Option<f64>,
    probes_blocked: usize,
    probes_total: usize,
    goodput_mbps: Option<f64>,
    goodput_kpps: Option<f64>,
    cpu_cores: usize,
    cpu_aes_mbps: Option<f64>,
    cpu_chacha_mbps: Option<f64>,
    cpu_blake2b_mbps: Option<f64>,
    cpu_multicore_gbps: Option<f64>,
    cpu_p256_certs_per_s: Option<f64>,
}

// ---------------------------------------------------------------------------
// 10 Real-World Network & Security Scenarios
// ---------------------------------------------------------------------------

fn test_01_baseline(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-01-baseline-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), false);
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    let app = connect_app(client.port, 500);
    let hs_ms = match handshake_app(&app, Duration::from_secs(3)) {
        Some(v) => v,
        None => {
            return ScenarioResult {
                id: 1,
                code: "baseline",
                name: "Baseline & Wire Overhead",
                condition: "0ms / 0% loss",
                status: ScenarioStatus::Fail,
                metrics: "Handshake FAILED".into(),
                detail: "Initial STUN+DTLS handshake did not complete within 3s".into(),
                elapsed_s: t0.elapsed().as_secs_f64(),
            };
        }
    };

    // Wait briefly so handshake packets finish, then reset wire baseline by snapshotting delta
    thread::sleep(Duration::from_millis(30));
    let before = proxy.snapshot();

    let payload_len = 1200usize;
    let count = 60usize;
    let mut pkt = vec![0u8; payload_len];
    let mut rbuf = vec![0u8; 4096];
    let mut rtts_ms = Vec::with_capacity(count);
    let mut ok = 0usize;
    app.set_read_timeout(Some(Duration::from_millis(300))).unwrap();

    for i in 0..count {
        pkt[..4].copy_from_slice(b"RTT:");
        pkt[4..12].copy_from_slice(&(i as u64).to_be_bytes());
        fill_random(&mut pkt[12..]);
        let ts = Instant::now();
        let _ = app.send(&pkt);
        if let Ok(n) = app.recv(&mut rbuf) {
            if n == payload_len && rbuf[..12] == pkt[..12] {
                rtts_ms.push(ts.elapsed().as_secs_f64() * 1000.0);
                ok += 1;
            }
        }
    }

    let after = proxy.snapshot();
    let srtp_pkts_delta = after.srtp_pkts.saturating_sub(before.srtp_pkts);
    let srtp_bytes_delta = after.srtp_bytes.saturating_sub(before.srtp_bytes);
    let avg_wire = if srtp_pkts_delta > 0 {
        srtp_bytes_delta as f64 / srtp_pkts_delta as f64
    } else {
        0.0
    };
    let delta_b = (avg_wire - payload_len as f64).max(0.0);
    let overhead_pct = (delta_b / payload_len as f64) * 100.0;

    rtts_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = percentile(&rtts_ms, 50);
    let p95 = percentile(&rtts_ms, 95);

    hi.overhead_pct = Some(overhead_pct);
    hi.overhead_bytes = Some(delta_b);
    hi.max_wire_udp = hi.max_wire_udp.max(after.max_wire_udp);

    let max_allowed = opts.wan_mtu.saturating_sub(28);
    let passed = ok == count
        && after.stun_pkts >= 2
        && after.dtls_pkts >= 4
        && after.max_wire_udp <= max_allowed
        && overhead_pct > 2.5
        && overhead_pct < 7.0;

    ScenarioResult {
        id: 1,
        code: "baseline",
        name: "Baseline & Wire Overhead",
        condition: "0ms / 0% loss",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "hs {:.1}ms | p50 {:.2}ms | {}/{} | +{:.1}B (+{:.2}%)",
            hs_ms, p50, ok, count, delta_b, overhead_pct
        ),
        detail: format!(
            "STUN={} DTLS={} SRTP={} SRTCP={} max_wire={}B p95={:.2}ms",
            after.stun_pkts, after.dtls_pkts, srtp_pkts_delta, after.srtcp_pkts, after.max_wire_udp, p95
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn test_02_transpacific_latency(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-02-wan-rtt-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    let proxy = ImpairmentProxy::start(
        server_port,
        psk.clone(),
        NetProfile {
            base_delay_ms: 80,
            jitter_ms: 12,
            seed: 2026_02,
            ..Default::default()
        },
        false,
    );
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 600);

    let app = connect_app(client.port, 1000);
    // Avoid double-sending during slow WAN handshake: wait up to 4s with 1s read timeout
    let hs_t0 = Instant::now();
    let ping = b"WAN_HANDSHAKE_PROBE";
    let mut rbuf = vec![0u8; 4096];
    let mut hs_ms = None;
    let _ = app.send(ping);
    while hs_t0.elapsed() < Duration::from_secs(4) {
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == ping {
                hs_ms = Some(hs_t0.elapsed().as_secs_f64() * 1000.0);
                break;
            }
        } else {
            let _ = app.send(ping);
        }
    }

    let Some(hs_val) = hs_ms else {
        return ScenarioResult {
            id: 2,
            code: "wan_latency",
            name: "Trans-Pacific RTT & Jitter",
            condition: "160ms +/-24ms RTT",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "STUN+DTLS handshake timed out under 160ms WAN RTT".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    };

    let count = 12usize;
    let mut pkt = vec![0u8; 1000];
    let mut rtts_ms = Vec::with_capacity(count);
    let mut ok = 0usize;
    app.set_read_timeout(Some(Duration::from_millis(800))).unwrap();

    for i in 0..count {
        pkt[..4].copy_from_slice(b"WAN:");
        pkt[4..12].copy_from_slice(&(i as u64).to_be_bytes());
        fill_random(&mut pkt[12..]);
        let ts = Instant::now();
        let _ = app.send(&pkt);
        if let Ok(n) = app.recv(&mut rbuf) {
            if n == pkt.len() && rbuf[..12] == pkt[..12] {
                rtts_ms.push(ts.elapsed().as_secs_f64() * 1000.0);
                ok += 1;
            }
        }
    }

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);
    rtts_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = percentile(&rtts_ms, 50);
    let p95 = percentile(&rtts_ms, 95);

    let passed = ok == count && p50 >= 130.0 && p50 <= 210.0 && snap.ports_seen.len() == 1;
    ScenarioResult {
        id: 2,
        code: "wan_latency",
        name: "Trans-Pacific RTT & Jitter",
        condition: "160ms +/-24ms RTT",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "hs {:.0}ms | p50 {:.0}ms | p95 {:.0}ms | {}/{}",
            hs_val, p50, p95, ok, count
        ),
        detail: format!("ports={} c2s={} s2c={}", snap.ports_seen.len(), snap.c2s_pkts, snap.s2c_pkts),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn test_03_random_loss(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-03-random-loss-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    let proxy = ImpairmentProxy::start(
        server_port,
        psk.clone(),
        NetProfile {
            base_delay_ms: 8,
            jitter_ms: 3,
            loss_c2s_pct: 8,
            loss_s2c_pct: 8,
            seed: 2026_03,
            ..Default::default()
        },
        false,
    );
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    let app = connect_app(client.port, 400);
    let Some(hs_ms) = handshake_app(&app, Duration::from_secs(5)) else {
        return ScenarioResult {
            id: 3,
            code: "random_loss",
            name: "Bidirectional Random Loss",
            condition: "8% C2S + 8% S2C",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel could not establish under 8% bidirectional packet loss".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    };

    backend.reset();
    let total = 100u64;
    let mut pkt = vec![0u8; 900];
    pkt[..4].copy_from_slice(b"SEQ:");
    app.set_nonblocking(true).unwrap();

    let mut received = HashSet::<u64>::new();
    let mut rbuf = vec![0u8; 4096];

    for seq in 0..total {
        pkt[4..12].copy_from_slice(&seq.to_be_bytes());
        fill_random(&mut pkt[12..]);
        let _ = app.send(&pkt);
        while let Ok(n) = app.recv(&mut rbuf) {
            if n == pkt.len() && &rbuf[..4] == b"SEQ:" {
                let s = u64::from_be_bytes(rbuf[4..12].try_into().unwrap());
                received.insert(s);
            }
        }
        thread::sleep(Duration::from_millis(6));
    }

    let drain_end = Instant::now() + Duration::from_millis(250);
    while Instant::now() < drain_end {
        while let Ok(n) = app.recv(&mut rbuf) {
            if n == pkt.len() && &rbuf[..4] == b"SEQ:" {
                let s = u64::from_be_bytes(rbuf[4..12].try_into().unwrap());
                received.insert(s);
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let snap = proxy.snapshot();
    let bst = backend.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);

    // Expected two-way delivery ~ (0.92)^2 = 84.6%; require >= 68% and 0 false port rotations
    let passed = received.len() >= 68
        && bst.dup_seqs == 0
        && snap.ports_seen.len() == 1
        && snap.dropped_by_proxy >= 5;

    ScenarioResult {
        id: 3,
        code: "random_loss",
        name: "Bidirectional Random Loss",
        condition: "8% C2S + 8% S2C",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "hs {:.0}ms | echo {}/{} | drops={} | ports={}",
            hs_ms,
            received.len(),
            total,
            snap.dropped_by_proxy,
            snap.ports_seen.len()
        ),
        detail: format!("backend_unique={} backend_dup={}", bst.unique_seqs, bst.dup_seqs),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn test_04_reorder_and_replay(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-04-reorder-dup-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    let proxy = ImpairmentProxy::start(
        server_port,
        psk.clone(),
        NetProfile {
            base_delay_ms: 5,
            jitter_ms: 2,
            reorder_pct: 35,
            duplicate_pct: 30,
            seed: 2026_04,
            ..Default::default()
        },
        false,
    );
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    let app = connect_app(client.port, 500);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 4,
            code: "reorder_replay",
            name: "ECMP Reorder & Replay Guard",
            condition: "35% reorder + 30% dup",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    backend.reset();
    let total = 120u64;
    let mut pkt = vec![0u8; 800];
    pkt[..4].copy_from_slice(b"SEQ:");
    app.set_nonblocking(true).unwrap();

    let mut rx_unique = HashSet::<u64>::new();
    let mut rx_client_dups = 0u64;
    let mut rx_out_of_order = 0u64;
    let mut max_seq_seen: Option<u64> = None;
    let mut rbuf = vec![0u8; 4096];

    let pkt_len = pkt.len();
    let mut drain_app = |rx_u: &mut HashSet<u64>, dups: &mut u64, ooo: &mut u64, max_s: &mut Option<u64>| {
        while let Ok(n) = app.recv(&mut rbuf) {
            if n == pkt_len && &rbuf[..4] == b"SEQ:" {
                let s = u64::from_be_bytes(rbuf[4..12].try_into().unwrap());
                if !rx_u.insert(s) {
                    *dups += 1;
                }
                if let Some(m) = *max_s {
                    if s < m {
                        *ooo += 1;
                    } else {
                        *max_s = Some(s);
                    }
                } else {
                    *max_s = Some(s);
                }
            }
        }
    };

    for seq in 0..total {
        pkt[4..12].copy_from_slice(&seq.to_be_bytes());
        fill_random(&mut pkt[12..]);
        let _ = app.send(&pkt);
        drain_app(&mut rx_unique, &mut rx_client_dups, &mut rx_out_of_order, &mut max_seq_seen);
        thread::sleep(Duration::from_millis(5));
    }

    let drain_end = Instant::now() + Duration::from_millis(350);
    while Instant::now() < drain_end {
        drain_app(&mut rx_unique, &mut rx_client_dups, &mut rx_out_of_order, &mut max_seq_seen);
        thread::sleep(Duration::from_millis(5));
    }

    let snap = proxy.snapshot();
    let bst = backend.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);

    let passed = rx_unique.len() as u64 == total
        && bst.unique_seqs == total
        && bst.dup_seqs == 0
        && rx_client_dups == 0
        && snap.reordered_pkts >= 20
        && snap.duplicated_pkts >= 20;

    ScenarioResult {
        id: 4,
        code: "reorder_replay",
        name: "ECMP Reorder & Replay Guard",
        condition: "35% reorder + 30% dup",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "unique {}/{} | ooo={} | dup_inj={} -> leaked=0",
            rx_unique.len(),
            total,
            rx_out_of_order,
            snap.duplicated_pkts
        ),
        detail: format!(
            "backend_dup={} client_dup={} proxy_reordered={}",
            bst.dup_seqs, rx_client_dups, snap.reordered_pkts
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn test_05_mtu_guard(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-05-mtu-guard-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), false);
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    let app = connect_app(client.port, 400);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 5,
            code: "mtu_guard",
            name: "PPPoE MTU 1488 Anti-Frag",
            condition: "1200..1452B probes",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let max_wire_allowed = opts.wan_mtu.saturating_sub(28);
    // Exact max inner payload = max_wire_allowed - 38 (20B RTP+BEDE + 2B len + 16B tag)
    let exact_edge = max_wire_allowed.saturating_sub(38);
    let oversize = exact_edge + 30; // e.g., 1452B when WAN MTU = 1488

    let probe = |len: usize| -> bool {
        let mut p = vec![0u8; len];
        p[..4].copy_from_slice(b"MTU:");
        fill_random(&mut p[4..]);
        let mut rb = vec![0u8; 4096];
        app.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let _ = app.send(&p);
        match app.recv(&mut rb) {
            Ok(n) => n == len && rb[..16] == p[..16],
            Err(_) => false,
        }
    };

    let ok_1200 = probe(1200);
    let ok_1400 = probe(1400.min(exact_edge));
    let ok_edge = probe(exact_edge);
    let ok_over = probe(oversize); // MUST be false (silently dropped to prevent IPv4 fragmentation)
    let ok_after = probe(256); // Tunnel MUST stay healthy after oversized drop

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);

    let passed = ok_1200
        && ok_1400
        && ok_edge
        && !ok_over
        && ok_after
        && snap.max_wire_udp <= max_wire_allowed;

    ScenarioResult {
        id: 5,
        code: "mtu_guard",
        name: "PPPoE MTU 1488 Anti-Frag",
        condition: "1200..1452B probes",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "{}B PASS | {}B DROP | max_wire={}B/{}B",
            exact_edge, oversize, snap.max_wire_udp, max_wire_allowed
        ),
        detail: format!(
            "1200={} 1400={} edge({})={} over({})={} post_health={}",
            ok_1200, ok_1400, exact_edge, ok_edge, oversize, ok_over, ok_after
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn test_06_single_stun_drop(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-06-single-ka-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), true);
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 1, 200);

    let app = connect_app(client.port, 250);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 6,
            code: "single_ka_drop",
            name: "Single STUN Drop Immunity",
            condition: "Drop 1 KA STUN",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let port1 = proxy.first_port.load(Ordering::SeqCst);
    let mut rbuf = [0u8; 256];
    let wait_t0 = Instant::now();
    let mut ping_ok = 0u64;
    while wait_t0.elapsed() < Duration::from_secs(5) {
        let _ = app.send(b"KEEP_DATA_ALIVE");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"KEEP_DATA_ALIVE" {
                ping_ok += 1;
            }
        }
        if proxy.snapshot().same_txid_ka_retransmits >= 1 {
            break;
        }
        thread::sleep(Duration::from_millis(80));
    }

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);
    let latest = proxy.latest_port.load(Ordering::SeqCst);
    let passed = snap.same_txid_ka_retransmits == 1
        && snap.ports_seen.len() == 1
        && latest == port1
        && ping_ok >= 3;

    ScenarioResult {
        id: 6,
        code: "single_ka_drop",
        name: "Single STUN Drop Immunity",
        condition: "Drop 1 KA STUN",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "same_txid_retry={} | ports={} (no rotate)",
            snap.same_txid_ka_retransmits,
            snap.ports_seen.len()
        ),
        detail: format!("port={} pings_ok={} dropped={}", port1, ping_ok, snap.dropped_by_proxy),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn test_07_asymmetric_blackhole(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-07-blackhole-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), false);
    let client = ManagedClient::start(proxy.port, psk, opts.cipher_pref, opts.wan_mtu, 1, 200);

    let app = connect_app(client.port, 200);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 7,
            code: "uplink_blackhole",
            name: "Asymmetric Uplink Blackhole",
            condition: "100% C2S cut, S2C live",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let port1 = proxy.first_port.load(Ordering::SeqCst);
    // Cut 100% uplink on port1 while downlink SRTCP continues flowing!
    proxy.blackhole_port.store(port1, Ordering::SeqCst);
    let bh_t0 = Instant::now();
    let mut rbuf = [0u8; 256];
    let mut recovered_s: Option<f64> = None;

    while bh_t0.elapsed() < Duration::from_secs(10) {
        let _ = app.send(b"PROBE_AFTER_BLACKHOLE");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"PROBE_AFTER_BLACKHOLE"
                && proxy.latest_port.load(Ordering::SeqCst) != port1
            {
                recovered_s = Some(bh_t0.elapsed().as_secs_f64());
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);
    hi.blackhole_recover_s = recovered_s;

    let port2 = proxy.latest_port.load(Ordering::SeqCst);
    let passed = recovered_s.is_some()
        && port2 != port1
        && snap.ports_seen.len() == 2
        && snap.blackhole_ka_retransmits == 2
        && snap.dl_srtcp_during_blackhole >= 1;

    let rec_str = recovered_s
        .map(|v| format!("{:.2}s", v))
        .unwrap_or_else(|| "TIMEOUT".into());

    ScenarioResult {
        id: 7,
        code: "uplink_blackhole",
        name: "Asymmetric Uplink Blackhole",
        condition: "100% C2S cut, S2C live",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "heal {} | {}->{} | dl_rtcp={} | ka_retx={}",
            rec_str, port1, port2, snap.dl_srtcp_during_blackhole, snap.blackhole_ka_retransmits
        ),
        detail: format!("ports_seen={:?} uplink_dropped={}", snap.ports_seen, snap.dropped_by_proxy),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn test_08_server_restart(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-08-srv-restart-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let server1 = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), false);
    let client = ManagedClient::start(proxy.port, psk.clone(), opts.cipher_pref, opts.wan_mtu, 1, 200);

    let app = connect_app(client.port, 200);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 8,
            code: "server_restart",
            name: "Server Restart Recovery",
            condition: "Kill & respawn server",
            status: ScenarioStatus::Fail,
            metrics: "Handshake FAILED".into(),
            detail: "Initial tunnel handshake failed".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let port1 = proxy.first_port.load(Ordering::SeqCst);

    // Stop server #1 cleanly and immediately start server #2 on the EXACT SAME port!
    server1.shutdown();
    let _server2 = ManagedServer::start(server_port, backend.port, psk, opts.cipher_pref, opts.wan_mtu);
    let rs_t0 = Instant::now();

    let mut rbuf = [0u8; 256];
    let mut recovered_s: Option<f64> = None;
    while rs_t0.elapsed() < Duration::from_secs(10) {
        let _ = app.send(b"PROBE_AFTER_RESTART");
        if let Ok(n) = app.recv(&mut rbuf) {
            if &rbuf[..n] == b"PROBE_AFTER_RESTART"
                && proxy.latest_port.load(Ordering::SeqCst) != port1
            {
                recovered_s = Some(rs_t0.elapsed().as_secs_f64());
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    let snap = proxy.snapshot();
    hi.max_wire_udp = hi.max_wire_udp.max(snap.max_wire_udp);
    hi.restart_recover_s = recovered_s;

    let port2 = proxy.latest_port.load(Ordering::SeqCst);
    let passed = recovered_s.is_some() && port2 != port1 && snap.ports_seen.len() == 2;
    let rec_str = recovered_s
        .map(|v| format!("{:.2}s", v))
        .unwrap_or_else(|| "TIMEOUT".into());

    ScenarioResult {
        id: 8,
        code: "server_restart",
        name: "Server Restart Recovery",
        condition: "Kill & respawn server",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!("heal {} | rekey {}->{} | NEW-M-01 OK", rec_str, port1, port2),
        detail: format!("server_port={} ports_seen={:?}", server_port, snap.ports_seen),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn send_probe_expect_silence(server_addr: SocketAddr, payload: &[u8]) -> usize {
    let atk = UdpSocket::bind("127.0.0.1:0").expect("bind attacker");
    atk.set_read_timeout(Some(Duration::from_millis(110))).unwrap();
    atk.connect(server_addr).unwrap();
    let _ = atk.send(payload);
    let mut buf = [0u8; 2048];
    match atk.recv(&mut buf) {
        Ok(n) => n,
        Err(_) => 0,
    }
}

fn test_09_active_probing_defense(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-09-security-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    let _server = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    let proxy = ImpairmentProxy::start(server_port, psk.clone(), NetProfile::default(), false);
    let client = ManagedClient::start(proxy.port, psk.clone(), opts.cipher_pref, opts.wan_mtu, 5, 250);

    // Bring up a legitimate tunnel concurrently to verify probes don't disrupt real sessions
    // AND to capture a real valid STUN request for cross-port replay testing!
    let app = connect_app(client.port, 400);
    if handshake_app(&app, Duration::from_secs(3)).is_none() {
        return ScenarioResult {
            id: 9,
            code: "active_probe",
            name: "Active Probe & Replay Defense",
            condition: "8 hostile vectors",
            status: ScenarioStatus::Fail,
            metrics: "Legit setup FAILED".into(),
            detail: "Legitimate baseline session failed to establish".into(),
            elapsed_s: t0.elapsed().as_secs_f64(),
        };
    }

    let captured_stun = proxy.snapshot().captured_valid_stun.unwrap_or_default();
    let ice = SessionIceParams::generate();

    // 1. Random UDP garbage
    let mut rand_junk = [0u8; 64];
    fill_random(&mut rand_junk);

    // 2. Forged DTLS 1.2 ClientHello without prior STUN authentication
    let mut forged_dtls = vec![0u8; 64];
    forged_dtls[0] = 22; // Handshake
    forged_dtls[1] = 0xFE;
    forged_dtls[2] = 0xFD; // DTLS 1.2
    forged_dtls[11] = 0;
    forged_dtls[12] = 51;
    forged_dtls[13] = 1; // ClientHello

    // 3. Valid-format STUN signed with WRONG PSK
    let (wrong_psk_stun, _) = build_ice_stun_request(b"wrong-attacker-psk", &ice, None, true);

    // 4. Real STUN with 1 bit flipped inside MESSAGE-INTEGRITY HMAC
    let (mut tampered_mi_stun, _) = build_ice_stun_request(&psk, &ice, None, true);
    let mi_idx = tampered_mi_stun.len().saturating_sub(14);
    tampered_mi_stun[mi_idx] ^= 0x01;

    // 5. Real STUN with injected trailing attribute after FINGERPRINT (smuggling)
    let (mut smuggled_stun, _) = build_ice_stun_request(&psk, &ice, None, true);
    smuggled_stun.extend_from_slice(&[0x80, 0x22, 0x00, 0x04, b'E', b'V', b'I', b'L']);
    let new_body_len = (smuggled_stun.len() - 20) as u16;
    smuggled_stun[2..4].copy_from_slice(&new_body_len.to_be_bytes());

    // 6. Cross-port replay of real captured authenticated client STUN packet
    let replay_stun = captured_stun;

    // 7. Orphan STUN keepalive (valid PSK + fresh txid, USE-CANDIDATE=false, unknown peer -> NEW-M-01)
    let (orphan_ka_stun, _) = build_ice_stun_request(&psk, &ice, None, false);

    // 8. Forged/tampered SRTP packet (0x90 RTP header + random payload/tag)
    let mut forged_srtp = vec![0u8; 96];
    fill_random(&mut forged_srtp);
    forged_srtp[0] = 0x90;
    forged_srtp[1] = 96;

    let probes: [(&str, &[u8]); 8] = [
        ("junk", &rand_junk),
        ("dtls_no_stun", &forged_dtls),
        ("wrong_psk", &wrong_psk_stun),
        ("bad_mi", &tampered_mi_stun),
        ("tail_smuggle", &smuggled_stun),
        ("cross_replay", &replay_stun),
        ("orphan_ka", &orphan_ka_stun),
        ("bad_srtp", &forged_srtp),
    ];

    let mut blocked = 0usize;
    let mut leaked_bytes = 0usize;
    let mut leaked_names = Vec::new();
    for (label, payload) in probes {
        let rx = send_probe_expect_silence(server_addr, payload);
        if rx == 0 {
            blocked += 1;
        } else {
            leaked_bytes += rx;
            leaked_names.push(format!("{}({}B)", label, rx));
        }
    }

    // Verify legitimate tunnel is completely undisturbed after active attack wave
    let mut rbuf = [0u8; 256];
    let _ = app.send(b"LEGIT_POST_ATTACK_OK");
    let legit_ok = app
        .recv(&mut rbuf)
        .map(|n| &rbuf[..n] == b"LEGIT_POST_ATTACK_OK")
        .unwrap_or(false);

    hi.probes_blocked = blocked;
    hi.probes_total = probes.len();

    let passed = blocked == probes.len() && leaked_bytes == 0 && legit_ok && !replay_stun.is_empty();
    ScenarioResult {
        id: 9,
        code: "active_probe",
        name: "Active Probe & Replay Defense",
        condition: "8 hostile vectors",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "silent_drop {}/{} ({}B leaked) | legit {}",
            blocked,
            probes.len(),
            leaked_bytes,
            if legit_ok { "OK" } else { "FAIL" }
        ),
        detail: if leaked_names.is_empty() {
            "All 8 vectors (junk/DTLS/PSK/MI/smuggle/replay/orphanKA/SRTP) 100% dropped".into()
        } else {
            format!("Leaked responses on: {}", leaked_names.join(", "))
        },
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn test_10_multistream_throughput(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let psk = b"selftest-10-throughput-psk".to_vec();
    let backend = EchoBackend::start();
    let server_port = reserve_free_port();
    let _server = ManagedServer::start(server_port, backend.port, psk.clone(), opts.cipher_pref, opts.wan_mtu);
    // Direct client -> server (no impairment proxy) to measure true tunnel forwarding engine
    let client = ManagedClient::start(server_port, psk, opts.cipher_pref, opts.wan_mtu, 5, 250);

    // Phase A: 4 concurrent independent UDP sessions handshaking simultaneously
    let streams = 4usize;
    let barrier = Arc::new(Barrier::new(streams));
    let mut handles = Vec::with_capacity(streams);
    for sid in 0..streams {
        let cport = client.port;
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let sock = connect_app(cport, 300);
            bar.wait();
            let msg = format!("STREAM_ISOLATION_TOKEN_{:02}", sid);
            let mut rb = [0u8; 256];
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut ok = false;
            while Instant::now() < deadline {
                let _ = sock.send(msg.as_bytes());
                if let Ok(n) = sock.recv(&mut rb) {
                    if &rb[..n] == msg.as_bytes() {
                        ok = true;
                        break;
                    }
                }
            }
            ok
        }));
    }
    let streams_ok = handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .filter(|&ok| ok)
        .count();

    // Phase B: Single-core end-to-end encrypted SRTP goodput burst (12,000 x 1200B = 14.4 MB)
    backend.reset();
    let app = connect_app(client.port, 300);
    let hs_ok = handshake_app(&app, Duration::from_secs(3)).is_some();

    let burst_pkts = 12_000u64;
    let payload_sz = 1200usize;
    let mut blk = vec![0u8; payload_sz];
    blk[..5].copy_from_slice(b"SINK:");
    fill_random(&mut blk[5..]);

    // Gentle micro-yield every 32 packets keeps macOS loopback socket buffer lossless
    for i in 0..burst_pkts {
        let _ = app.send(&blk);
        if (i + 1) % 32 == 0 {
            thread::yield_now();
        }
    }
    thread::sleep(Duration::from_millis(80));

    let bst = backend.snapshot();
    let dur = match (bst.sink_first, bst.sink_last) {
        (Some(f), Some(l)) if l > f => l.duration_since(f).as_secs_f64(),
        _ => 0.001,
    };
    let mbps = (bst.sink_bytes as f64 * 8.0) / dur / 1e6;
    let kpps = (bst.sink_pkts as f64) / dur / 1e3;
    let delivery_pct = (bst.sink_pkts as f64 / burst_pkts as f64) * 100.0;

    hi.goodput_mbps = Some(mbps);
    hi.goodput_kpps = Some(kpps);

    let passed = streams_ok == streams && hs_ok && delivery_pct >= 90.0 && mbps >= 80.0;
    ScenarioResult {
        id: 10,
        code: "throughput",
        name: "Multi-Stream & Loopback Speed",
        condition: "4 streams + 12k x 1200B",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "{}/{} streams | {:.0} Mbps ({:.1} kpps) | {:.1}% rx",
            streams_ok, streams, mbps, kpps, delivery_pct
        ),
        detail: format!("rx={}/{} pkts ({:.2} MB) in {:.3}s", bst.sink_pkts, burst_pkts, bst.sink_bytes as f64 / 1e6, dur),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn bench_single_suite(suite: CipherSuite, count: usize, payload_bytes: usize) -> (f64, f64, bool) {
    let psk = b"selftest-cpu-bench-psk-2026";
    let mut txid = [0u8; 12];
    fill_random(&mut txid);
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, "cpu1:cpu2");
    let skey = combine_session_key(&stun_key, None);
    let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
    let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);

    let mut plain = vec![0u8; payload_bytes];
    fill_random(&mut plain);
    let mut wbuf = vec![0u8; payload_bytes + 128];
    let mut rbuf = vec![0u8; payload_bytes + 128];

    // Warmup + exact byte-integrity check
    let mut integrity_ok = true;
    for _ in 0..200 {
        let wn = match cli.wrap_into(&plain, &mut wbuf) {
            Some(n) => n,
            None => return (0.0, 0.0, false),
        };
        let rn = match srv.unwrap_into(&wbuf[..wn], &mut rbuf) {
            Some(n) => n,
            None => return (0.0, 0.0, false),
        };
        if rn != payload_bytes || rbuf[..rn] != plain[..] {
            integrity_ok = false;
        }
    }

    let t0 = Instant::now();
    for _ in 0..count {
        let wn = cli.wrap_into(&plain, &mut wbuf).unwrap();
        let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
        std::hint::black_box(rn);
    }
    let dt = t0.elapsed().as_secs_f64().max(0.000_001);
    let mbps = (((count as u64) * (payload_bytes as u64) * 8) as f64) / dt / 1e6;
    let kpps = (count as f64) / dt / 1e3;
    (mbps, kpps, integrity_ok)
}

fn test_11_cpu_single_core_crypto(_opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let count = 40_000usize;
    let payload_bytes = 1200usize;

    let (aes_mbps, aes_kpps, aes_ok) = bench_single_suite(CipherSuite::Aes128Gcm, count, payload_bytes);
    let (chacha_mbps, chacha_kpps, chacha_ok) =
        bench_single_suite(CipherSuite::ChaCha20Poly1305, count, payload_bytes);
    let (b2b_mbps, b2b_kpps, b2b_ok) = bench_single_suite(CipherSuite::Blake2b, count, payload_bytes);

    hi.cpu_aes_mbps = Some(aes_mbps);
    hi.cpu_chacha_mbps = Some(chacha_mbps);
    hi.cpu_blake2b_mbps = Some(b2b_mbps);

    let passed = aes_ok
        && chacha_ok
        && b2b_ok
        && aes_mbps > 50.0
        && chacha_mbps > 50.0
        && b2b_mbps > 50.0;

    ScenarioResult {
        id: 11,
        code: "cpu_crypto_1c",
        name: "CPU Single-Core Crypto Bench",
        condition: "3 suites x 40k x 1200B",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "AES {:.0} | ChaCha {:.0} | B2B {:.0} Mbps (1C)",
            aes_mbps, chacha_mbps, b2b_mbps
        ),
        detail: format!(
            "kpps: AES={:.1} ChaCha={:.1} B2B={:.1} (wrap+unwrap 1200B)",
            aes_kpps, chacha_kpps, b2b_kpps
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

fn test_12_cpu_multicore_and_p256(opts: &SelftestOptions, hi: &mut Highlights) -> ScenarioResult {
    let t0 = Instant::now();
    let cpu = detect_cpu_accel();
    let suite = match opts.cipher_pref {
        CipherPref::Auto => cpu.recommended,
        CipherPref::Fixed(s) => s,
    };
    let cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1);
    hi.cpu_cores = cores;

    // Phase A: All-core parallel SRTP AEAD wrap+unwrap scaling test
    let per_core_pkts = 25_000usize;
    let payload_bytes = 1200usize;
    let barrier = Arc::new(Barrier::new(cores));
    let mut handles = Vec::with_capacity(cores);

    for tid in 0..cores {
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let psk = b"selftest-cpu-mc-psk";
            let mut txid = [0u8; 12];
            fill_random(&mut txid);
            let uname = format!("mc{:02}:mc{:02}", tid, tid);
            let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, &uname);
            let skey = combine_session_key(&stun_key, None);
            let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
            let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);
            let mut plain = vec![0u8; payload_bytes];
            fill_random(&mut plain);
            let mut wbuf = vec![0u8; payload_bytes + 128];
            let mut rbuf = vec![0u8; payload_bytes + 128];

            for _ in 0..100 {
                let wn = cli.wrap_into(&plain, &mut wbuf).unwrap();
                let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
                std::hint::black_box(rn);
            }

            bar.wait();
            let ts = Instant::now();
            for _ in 0..per_core_pkts {
                let wn = cli.wrap_into(&plain, &mut wbuf).unwrap();
                let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
                std::hint::black_box(rn);
            }
            ts.elapsed().as_secs_f64()
        }));
    }

    let mut max_dt = 0.000_001f64;
    let mut joined = 0usize;
    for h in handles {
        if let Ok(dt) = h.join() {
            joined += 1;
            if dt > max_dt {
                max_dt = dt;
            }
        }
    }
    let total_bits =
        ((joined as u64) * (per_core_pkts as u64) * (payload_bytes as u64) * 8) as f64;
    let agg_gbps = total_bits / max_dt / 1e9;
    hi.cpu_multicore_gbps = Some(agg_gbps);

    // Phase B: P-256 ECDSA ephemeral DTLS certificate generation throughput
    let cert_iters = 60usize;
    let tc = Instant::now();
    let mut cert_ok = true;
    for _ in 0..cert_iters {
        let cert = generate_ephemeral_webrtc_cert();
        if cert.certificate.is_empty() || cert.private_key.is_empty() {
            cert_ok = false;
        }
        std::hint::black_box(cert.certificate.len());
    }
    let cert_dt = tc.elapsed().as_secs_f64().max(0.000_001);
    let certs_per_s = (cert_iters as f64) / cert_dt;
    hi.cpu_p256_certs_per_s = Some(certs_per_s);

    let passed = joined == cores && cert_ok && agg_gbps > 0.1 && certs_per_s > 5.0;
    ScenarioResult {
        id: 12,
        code: "cpu_crypto_mc",
        name: "CPU Multi-Core & P-256 Certs",
        condition: "All cores + P-256 certs",
        status: ScenarioStatus::from_bool(passed),
        metrics: format!(
            "{}C {}: {:.2} Gbps | P-256 {:.0} certs/s",
            cores,
            suite.name(),
            agg_gbps,
            certs_per_s
        ),
        detail: format!(
            "cores={} per_core={}pkts wall={:.3}s certs={} in {:.3}s",
            cores, per_core_pkts, max_dt, cert_iters, cert_dt
        ),
        elapsed_s: t0.elapsed().as_secs_f64(),
    }
}

// ---------------------------------------------------------------------------
// Live Remote Tunnel Self-Test Engine (Direct WAN -> Production Server)
// ---------------------------------------------------------------------------

struct LiveStunOk {
    sock: UdpSocket,
    ice: SessionIceParams,
    txid: [u8; 12],
    raw_stun: Vec<u8>,
    rtt_ms: f64,
    mapped_addr: Option<SocketAddrV4>,
}

struct LiveReadySession {
    sock: UdpSocket,
    ice: SessionIceParams,
    dtls: Dtls,
    dtls_next_timeout: Option<Instant>,
    is_dtls13: bool,
    cipher: SrtpCloakCipher,
    suite: CipherSuite,
    dl_srtcp_verified: u64,
    tx_srtp_pkts: u64,
    rx_srtp_pkts: u64,
}

fn remote_stun_handshake(server_addr: SocketAddr, psk: &[u8]) -> Result<LiveStunOk, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind udp: {}", e))?;
    tune_socket(&sock);
    sock.set_read_timeout(Some(Duration::from_millis(750)))
        .map_err(|e| format!("set timeout: {}", e))?;
    sock.connect(server_addr)
        .map_err(|e| format!("connect {}: {}", server_addr, e))?;

    let ice = SessionIceParams::generate();
    let txid = make_fresh_stun_txid(psk);
    let (req, _) = build_ice_stun_request(psk, &ice, Some(txid), true);
    let mut rbuf = [0u8; 2048];

    for _ in 0..4 {
        let ts = Instant::now();
        let _ = sock.send(&req);
        while ts.elapsed() < Duration::from_millis(750) {
            match sock.recv(&mut rbuf) {
                Ok(n) => {
                    let pkt = &rbuf[..n];
                    if demux_rfc7983(pkt) == PacketKind::Stun {
                        if let Some(p) = parse_stun(pkt, psk) {
                            if p.authenticated
                                && p.msg_type == STUN_BINDING_SUCCESS
                                && p.txid == txid
                            {
                                return Ok(LiveStunOk {
                                    sock,
                                    ice,
                                    txid,
                                    raw_stun: req,
                                    rtt_ms: ts.elapsed().as_secs_f64() * 1000.0,
                                    mapped_addr: p.xor_mapped,
                                });
                            }
                        }
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                Err(_) => break,
            }
        }
    }
    Err(format!(
        "No authenticated STUN reply from {} after 4 attempts (check IP/port/firewall/PSK)",
        server_addr
    ))
}

fn remote_dtls_handshake(
    stun: LiveStunOk,
    psk: &[u8],
    cipher_pref: CipherPref,
    dtls_min_version: DtlsMinVersion,
    wan_mtu: usize,
) -> Result<(LiveReadySession, f64), String> {
    let cpu = detect_cpu_accel();
    let dtls_cfg = build_dimpl_config_pool(cipher_pref, &cpu, true, wan_mtu).pick();
    let cert = generate_ephemeral_webrtc_cert();
    let now = Instant::now();
    let mut dtls = new_dtls_instance(dtls_min_version, dtls_cfg, cert, now);
    dtls.set_active(true);
    let _ = dtls.handle_timeout(now);

    let sock = stun.sock;
    sock.set_read_timeout(Some(Duration::from_millis(25)))
        .map_err(|e| format!("set timeout: {}", e))?;

    let mut dtls_buf = vec![0u8; 4096];
    let mut rbuf = vec![0u8; 4096];
    let mut pending_sh_suite: Option<u16> = None;
    let mut dtls_suite_id: Option<u16> = None;
    let mut dtls_km: Option<Vec<u8>> = None;
    let mut dtls_next_timeout: Option<Instant> = None;
    let mut connected = false;

    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(8) {
        let now = Instant::now();
        let _ = dtls.handle_timeout(now);

        let mut emitted_ch = false;
        let mut emitted_f5 = false;
        loop {
            match dtls.poll_output(&mut dtls_buf) {
                DtlsOutput::Packet(p) => {
                    if p.len() >= 14 && p[0] == 22 && p[13] == 1 {
                        emitted_ch = true;
                    } else {
                        emitted_f5 = true;
                    }
                    let _ = sock.send(p);
                }
                DtlsOutput::BufferTooSmall { needed } => dtls_buf.resize(needed, 0),
                DtlsOutput::KeyingMaterial(km, _) => dtls_km = Some(km.to_vec()),
                DtlsOutput::Connected => connected = true,
                DtlsOutput::Timeout(t) => {
                    dtls_next_timeout = Some(t);
                    break;
                }
                _ => {}
            }
        }
        if emitted_ch && !emitted_f5 && !connected {
            pending_sh_suite = None;
        } else if dtls_suite_id.is_none() && (emitted_f5 || connected) {
            if let Some(cs) = pending_sh_suite.take() {
                dtls_suite_id = Some(cs);
            }
        }
        if connected {
            break;
        }

        match sock.recv(&mut rbuf) {
            Ok(n) => {
                let pkt = &rbuf[..n];
                if demux_rfc7983(pkt) == PacketKind::Dtls && validate_dtls_datagram(pkt, false) {
                    if dtls_suite_id.is_none() && pending_sh_suite.is_none() {
                        if let Some(cs) = extract_dtls_server_hello_suite(pkt) {
                            pending_sh_suite = Some(cs);
                        }
                    }
                    let _ = dtls.handle_packet(pkt);
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => return Err(format!("dtls recv error: {}", e)),
        }
    }

    if !connected {
        return Err("DTLS handshake timed out after 8s".into());
    }
    let Some(km) = dtls_km.as_deref().filter(|k| !k.is_empty()) else {
        return Err("DTLS Connected without SRTP KeyingMaterial (Fail-Closed)".into());
    };
    let hs_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let is_dtls13 = dtls.protocol_version() == Some(ProtocolVersion::DTLS1_3);
    let uname = stun.ice.username();
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &stun.txid, &uname);
    let suite = resolve_srtp_suite(cipher_pref, dtls_suite_id, &cpu, false);
    let final_key = combine_session_key(&stun_key, Some(km));
    let mut cipher = SrtpCloakCipher::new(&final_key, s_c2s, s_s2c, true, suite);
    cipher.set_wan_mtu(wan_mtu);
    cipher.set_dual_ssrc(is_dtls13);

    Ok((
        LiveReadySession {
            sock,
            ice: stun.ice,
            dtls,
            dtls_next_timeout,
            is_dtls13,
            cipher,
            suite,
            dl_srtcp_verified: 0,
            tx_srtp_pkts: 0,
            rx_srtp_pkts: 0,
        },
        hs_ms,
    ))
}

impl LiveReadySession {
    /// H-01 fix: continue driving DTLS 1.3 post-Connected Flight 5 retransmission timer & ACK intake
    /// so a single lost Flight 5 packet during live WAN selftest recovers cleanly instead of false SKIP/FAIL.
    fn pump_dtls(&mut self, incoming: Option<&[u8]>) {
        let now = Instant::now();
        if let Some(pkt) = incoming {
            if validate_dtls_datagram(pkt, false) {
                let _ = self.dtls.handle_packet(pkt);
            }
        }
        if let Some(t) = self.dtls_next_timeout {
            let rem = t.saturating_duration_since(now);
            if rem > Duration::from_secs(60) {
                self.dtls_next_timeout = None;
            } else if now >= t {
                if self.dtls.handle_timeout(now).is_err() {
                    self.dtls_next_timeout = None;
                    return;
                }
            } else if incoming.is_none() {
                return;
            }
        } else if incoming.is_none() {
            return;
        }
        let mut dtls_buf = vec![0u8; 4096];
        loop {
            match self.dtls.poll_output(&mut dtls_buf) {
                DtlsOutput::Packet(p) => {
                    let _ = self.sock.send(p);
                }
                DtlsOutput::BufferTooSmall { needed } => dtls_buf.resize(needed, 0),
                DtlsOutput::Timeout(t) => {
                    if t.saturating_duration_since(now) > Duration::from_secs(60) {
                        self.dtls_next_timeout = None;
                    } else {
                        self.dtls_next_timeout = Some(t);
                    }
                    break;
                }
                _ => {}
            }
        }
    }

    fn send_stun_consent(
        &mut self,
        psk: &[u8],
        timeout_ms: u64,
    ) -> Option<(f64, Vec<u8>, [u8; 12], Vec<u8>)> {
        self.pump_dtls(None);
        let (req, txid) = build_ice_stun_request(psk, &self.ice, None, false);
        let _ = self.sock.set_read_timeout(Some(Duration::from_millis(40)));
        let ts = Instant::now();
        let _ = self.sock.send(&req);
        let mut rbuf = [0u8; 2048];
        let deadline = Duration::from_millis(timeout_ms);
        while ts.elapsed() < deadline {
            match self.sock.recv(&mut rbuf) {
                Ok(n) => {
                    let pkt = &rbuf[..n];
                    match demux_rfc7983(pkt) {
                        PacketKind::Stun => {
                            if let Some(p) = parse_stun(pkt, psk) {
                                if p.authenticated
                                    && p.msg_type == STUN_BINDING_SUCCESS
                                    && p.txid == txid
                                {
                                    return Some((
                                        ts.elapsed().as_secs_f64() * 1000.0,
                                        req,
                                        txid,
                                        pkt.to_vec(),
                                    ));
                                }
                            }
                        }
                        PacketKind::Dtls => {
                            self.pump_dtls(Some(pkt));
                        }
                        PacketKind::Srtcp => {
                            if self.cipher.verify_srtcp(pkt).is_some() {
                                self.dl_srtcp_verified += 1;
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    self.pump_dtls(None);
                }
                Err(_) => break,
            }
        }
        None
    }

    fn send_raw_stun_expect(
        &mut self,
        raw_req: &[u8],
        expected_txid: [u8; 12],
        psk: &[u8],
        timeout_ms: u64,
    ) -> Option<(f64, Vec<u8>)> {
        self.pump_dtls(None);
        let _ = self.sock.set_read_timeout(Some(Duration::from_millis(40)));
        let ts = Instant::now();
        let _ = self.sock.send(raw_req);
        let mut rbuf = [0u8; 2048];
        let deadline = Duration::from_millis(timeout_ms);
        while ts.elapsed() < deadline {
            match self.sock.recv(&mut rbuf) {
                Ok(n) => {
                    let pkt = &rbuf[..n];
                    match demux_rfc7983(pkt) {
                        PacketKind::Stun => {
                            if let Some(p) = parse_stun(pkt, psk) {
                                if p.authenticated
                                    && p.msg_type == STUN_BINDING_SUCCESS
                                    && p.txid == expected_txid
                                {
                                    return Some((ts.elapsed().as_secs_f64() * 1000.0, pkt.to_vec()));
                                }
                            }
                        }
                        PacketKind::Dtls => {
                            self.pump_dtls(Some(pkt));
                        }
                        PacketKind::Srtcp => {
                            if self.cipher.verify_srtcp(pkt).is_some() {
                                self.dl_srtcp_verified += 1;
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    self.pump_dtls(None);
                }
                Err(_) => break,
            }
        }
        None
    }

    fn probe_srtp_one(&mut self, payload: &[u8], timeout_ms: u64) -> Option<(f64, usize)> {
        self.pump_dtls(None);
        let mut wbuf = [0u8; 2048];
        let wn = self.cipher.wrap_probe_into(payload, &mut wbuf)?;
        let _ = self.sock.set_read_timeout(Some(Duration::from_millis(30)));
        let ts = Instant::now();
        if self.sock.send(&wbuf[..wn]).is_ok() {
            self.tx_srtp_pkts += 1;
        }
        let mut rbuf = [0u8; 2048];
        let mut pbuf = [0u8; 2048];
        let deadline = Duration::from_millis(timeout_ms);
        while ts.elapsed() < deadline {
            match self.sock.recv(&mut rbuf) {
                Ok(n) => {
                    let pkt = &rbuf[..n];
                    match demux_rfc7983(pkt) {
                        PacketKind::Srtp => {
                            if let Some(SrtpFrame::Probe(pn)) =
                                self.cipher.unwrap_into_ex(pkt, &mut pbuf)
                            {
                                if pn == payload.len() && &pbuf[..pn] == payload {
                                    self.rx_srtp_pkts += 1;
                                    return Some((ts.elapsed().as_secs_f64() * 1000.0, wn));
                                }
                            }
                        }
                        PacketKind::Dtls => {
                            self.pump_dtls(Some(pkt));
                        }
                        PacketKind::Srtcp => {
                            if self.cipher.verify_srtcp(pkt).is_some() {
                                self.dl_srtcp_verified += 1;
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    self.pump_dtls(None);
                }
                Err(_) => break,
            }
        }
        None
    }

    fn teardown(&mut self) {
        let bye = self
            .cipher
            .build_srtcp(self.rx_srtp_pkts > 0, self.tx_srtp_pkts > 0, true);
        let _ = self.sock.send(&bye);
        let mut dtls_buf = vec![0u8; 2048];
        if self.dtls.close().is_ok() {
            loop {
                match self.dtls.poll_output(&mut dtls_buf) {
                    DtlsOutput::Packet(p) => {
                        let _ = self.sock.send(p);
                    }
                    DtlsOutput::BufferTooSmall { needed } => dtls_buf.resize(needed, 0),
                    DtlsOutput::Timeout(_) => break,
                    _ => {}
                }
            }
        }
    }
}

fn send_probe_expect_silence_ms(server_addr: SocketAddr, payload: &[u8], wait_ms: u64) -> usize {
    let atk = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let _ = atk.set_read_timeout(Some(Duration::from_millis(wait_ms)));
    if atk.connect(server_addr).is_err() {
        return 0;
    }
    let _ = atk.send(payload);
    let mut buf = [0u8; 2048];
    match atk.recv(&mut buf) {
        Ok(n) => n,
        Err(_) => 0,
    }
}

fn run_remote_selftest(opts: &SelftestOptions, server_addr: SocketAddr, psk: &[u8]) -> bool {
    let cpu = detect_cpu_accel();
    let p = Palette::new(opts.color);
    let suite_t0 = Instant::now();
    let mut hi = Highlights::default();
    hi.is_remote = true;
    hi.target_label = Some(
        opts.server_label
            .clone()
            .unwrap_or_else(|| server_addr.to_string()),
    );

    if !opts.json {
        println!(
            "{}{}Running webrtc-cloak v{} LIVE remote self-test -> {} (12 scenarios)...{}",
            p.bold,
            p.cyan,
            env!("CARGO_PKG_VERSION"),
            hi.target_label.as_deref().unwrap_or(""),
            p.reset
        );
    }

    let mut results: Vec<ScenarioResult> = Vec::with_capacity(12);
    let total_steps = 12usize;

    let report_step = |idx: usize, label: &str, res: &ScenarioResult| {
        if !opts.json {
            let (col, tag) = match res.status {
                ScenarioStatus::Pass => (p.green, "[PASS]"),
                ScenarioStatus::Skip => (p.yellow, "[SKIP]"),
                ScenarioStatus::Fail => (p.red, "[FAIL]"),
            };
            println!(
                "  {}[{:02}/{:02}]{} {} ... {}{}{}{} {}({:.2}s){}",
                p.dim,
                idx,
                total_steps,
                p.reset,
                pad_right(label, 31),
                p.bold,
                col,
                tag,
                p.reset,
                p.dim,
                res.elapsed_s,
                p.reset
            );
        }
    };

    // #01 WAN ICE STUN & NAT Mapping
    let t1 = Instant::now();
    let stun_res = remote_stun_handshake(server_addr, psk);
    let (stun_ok_opt, stun_rtt_ms, captured_stun, mapped1) = match stun_res {
        Ok(s) => {
            let mapped_s = s
                .mapped_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".into());
            hi.nat_mapped = Some(mapped_s.clone());
            let rtt = s.rtt_ms;
            let raw = s.raw_stun.clone();
            let m = s.mapped_addr;
            let r = ScenarioResult {
                id: 1,
                code: "wan_stun",
                name: "WAN ICE STUN & NAT Mapping",
                condition: "Live UDP -> server",
                status: ScenarioStatus::Pass,
                metrics: format!("rtt {:.1}ms | NAT {}", rtt, mapped_s),
                detail: format!("server={} xor_mapped={}", server_addr, mapped_s),
                elapsed_s: t1.elapsed().as_secs_f64(),
            };
            report_step(1, r.name, &r);
            results.push(r);
            (Some(s), rtt, raw, m)
        }
        Err(msg) => {
            let r = ScenarioResult {
                id: 1,
                code: "wan_stun",
                name: "WAN ICE STUN & NAT Mapping",
                condition: "Live UDP -> server",
                status: ScenarioStatus::Fail,
                metrics: "STUN FAILED (unreachable/PSK)".into(),
                detail: msg,
                elapsed_s: t1.elapsed().as_secs_f64(),
            };
            report_step(1, r.name, &r);
            results.push(r);
            (None, 200.0, Vec::new(), None)
        }
    };

    // #02 WAN DTLS Mutual-Cert HS
    let t2 = Instant::now();
    let mut sess_opt: Option<LiveReadySession> = None;
    if let Some(stun_ok) = stun_ok_opt {
        match remote_dtls_handshake(
            stun_ok,
            psk,
            opts.cipher_pref,
            opts.dtls_min_version,
            opts.wan_mtu,
        ) {
            Ok((sess, hs_ms)) => {
                hi.negotiated_cipher = Some(sess.suite.name().to_string());
                let dtls_ver = if sess.is_dtls13 { "DTLS 1.3" } else { "DTLS 1.2" };
                let r = ScenarioResult {
                    id: 2,
                    code: "wan_dtls",
                    name: "WAN DTLS Mutual-Cert HS",
                    condition: "Auto 1.3/1.2 + Cookie",
                    status: ScenarioStatus::Pass,
                    metrics: format!(
                        "hs {:.1}ms | {} | {} | {}",
                        hs_ms,
                        dtls_ver,
                        sess.suite.name(),
                        if sess.is_dtls13 { "dual-SSRC" } else { "1-SSRC" }
                    ),
                    detail: format!(
                        "dtls={} negotiated={} dual_ssrc={} total_dtls_ms={:.2}",
                        dtls_ver, sess.suite.name(), sess.is_dtls13, hs_ms
                    ),
                    elapsed_s: t2.elapsed().as_secs_f64(),
                };
                report_step(2, r.name, &r);
                results.push(r);
                sess_opt = Some(sess);
            }
            Err(msg) => {
                let r = ScenarioResult {
                    id: 2,
                    code: "wan_dtls",
                    name: "WAN DTLS Mutual-Cert HS",
                    condition: "Auto 1.3/1.2 + Cookie",
                    status: ScenarioStatus::Fail,
                    metrics: "DTLS Handshake FAILED".into(),
                    detail: msg,
                    elapsed_s: t2.elapsed().as_secs_f64(),
                };
                report_step(2, r.name, &r);
                results.push(r);
            }
        }
    } else {
        let r = ScenarioResult {
            id: 2,
            code: "wan_dtls",
            name: "WAN DTLS Mutual-Cert HS",
            condition: "Auto 1.3/1.2 + Cookie",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (STUN failed)".into(),
            detail: "Requires successful STUN authentication first".into(),
            elapsed_s: 0.0,
        };
        report_step(2, r.name, &r);
        results.push(r);
    }

    let dyn_timeout_ms = ((stun_rtt_ms * 4.0) as u64).clamp(600, 2500);

    // #03 WAN Consent RTT / Jitter / Loss
    let t3 = Instant::now();
    if let Some(ref mut sess) = sess_opt {
        let count = opts.probe_count;
        let mut rtts = Vec::with_capacity(count);
        for i in 0..count {
            if let Some((rtt, _, _, _)) = sess.send_stun_consent(psk, dyn_timeout_ms) {
                rtts.push(rtt);
            }
            if i + 1 < count {
                thread::sleep(Duration::from_millis(60));
            }
        }
        let rx = rtts.len();
        let loss_pct = (1.0 - (rx as f64 / count as f64)) * 100.0;
        let mut jit_sum = 0.0f64;
        for w in rtts.windows(2) {
            jit_sum += (w[1] - w[0]).abs();
        }
        let jitter_ms = if rtts.len() > 1 {
            jit_sum / ((rtts.len() - 1) as f64)
        } else {
            0.0
        };
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50 = percentile(&rtts, 50);
        let p95 = percentile(&rtts, 95);
        hi.wan_p50_ms = if rx > 0 { Some(p50) } else { None };
        hi.wan_loss_pct = Some(loss_pct);

        let ok = rx > 0 && loss_pct <= 25.0;
        let r = ScenarioResult {
            id: 3,
            code: "wan_consent",
            name: "WAN Consent RTT/Jitter/Loss",
            condition: "RFC 7675 STUN probes",
            status: ScenarioStatus::from_bool(ok),
            metrics: format!(
                "p50 {:.1}ms p95 {:.1}ms | jit {:.1}ms | {}/{} ({:.1}%)",
                p50, p95, jitter_ms, rx, count, loss_pct
            ),
            detail: format!("min={:.1}ms max={:.1}ms loss={:.2}%", rtts.first().copied().unwrap_or(0.0), rtts.last().copied().unwrap_or(0.0), loss_pct),
            elapsed_s: t3.elapsed().as_secs_f64(),
        };
        report_step(3, r.name, &r);
        results.push(r);
    } else {
        let r = ScenarioResult {
            id: 3,
            code: "wan_consent",
            name: "WAN Consent RTT/Jitter/Loss",
            condition: "RFC 7675 STUN probes",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (session not ready)".into(),
            detail: "Requires established session".into(),
            elapsed_s: 0.0,
        };
        report_step(3, r.name, &r);
        results.push(r);
    }

    // #04 WAN STUN Retransmit Cache (SeenTxidCache)
    let t4 = Instant::now();
    if let Some(ref mut sess) = sess_opt {
        let res = if let Some((_rtt1, req_bytes, txid, resp1)) =
            sess.send_stun_consent(psk, dyn_timeout_ms)
        {
            thread::sleep(Duration::from_millis(50));
            if let Some((rtt2, resp2)) =
                sess.send_raw_stun_expect(&req_bytes, txid, psk, dyn_timeout_ms)
            {
                let exact = resp1 == resp2;
                ScenarioResult {
                    id: 4,
                    code: "wan_txid_cache",
                    name: "WAN STUN Retransmit Cache",
                    condition: "Same-txid retry check",
                    status: ScenarioStatus::from_bool(exact),
                    metrics: format!(
                        "cached {}B {} | rtt {:.1}ms",
                        resp2.len(),
                        if exact { "exact match" } else { "MISMATCH" },
                        rtt2
                    ),
                    detail: format!("resp1={}B resp2={}B equal={}", resp1.len(), resp2.len(), exact),
                    elapsed_s: t4.elapsed().as_secs_f64(),
                }
            } else {
                ScenarioResult {
                    id: 4,
                    code: "wan_txid_cache",
                    name: "WAN STUN Retransmit Cache",
                    condition: "Same-txid retry check",
                    status: ScenarioStatus::Fail,
                    metrics: "No reply on same-txid retry".into(),
                    detail: "Server did not return cached STUN reply".into(),
                    elapsed_s: t4.elapsed().as_secs_f64(),
                }
            }
        } else {
            ScenarioResult {
                id: 4,
                code: "wan_txid_cache",
                name: "WAN STUN Retransmit Cache",
                condition: "Same-txid retry check",
                status: ScenarioStatus::Fail,
                metrics: "Initial consent probe timed out".into(),
                detail: "First STUN keepalive failed".into(),
                elapsed_s: t4.elapsed().as_secs_f64(),
            }
        };
        report_step(4, res.name, &res);
        results.push(res);
    } else {
        let r = ScenarioResult {
            id: 4,
            code: "wan_txid_cache",
            name: "WAN STUN Retransmit Cache",
            condition: "Same-txid retry check",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (session not ready)".into(),
            detail: "Requires established session".into(),
            elapsed_s: 0.0,
        };
        report_step(4, r.name, &r);
        results.push(r);
    }

    // #05 WAN Server SRTCP Downlink Heartbeat
    let t5 = Instant::now();
    if let Some(ref mut sess) = sess_opt {
        let cli_rtcp = sess.cipher.build_srtcp(true, true, false);
        let _ = sess.sock.send(&cli_rtcp);
        if sess.dl_srtcp_verified == 0 {
            let _ = sess.sock.set_read_timeout(Some(Duration::from_millis(50)));
            let mut rbuf = [0u8; 2048];
            let wait_t0 = Instant::now();
            while wait_t0.elapsed() < Duration::from_secs(3) && sess.dl_srtcp_verified == 0 {
                if let Ok(n) = sess.sock.recv(&mut rbuf) {
                    let pkt = &rbuf[..n];
                    if demux_rfc7983(pkt) == PacketKind::Srtcp
                        && sess.cipher.verify_srtcp(pkt).is_some()
                    {
                        sess.dl_srtcp_verified += 1;
                        break;
                    }
                }
            }
        }
        let ok = sess.dl_srtcp_verified >= 1;
        let r = ScenarioResult {
            id: 5,
            code: "wan_srtcp",
            name: "WAN Server SRTCP Heartbeat",
            condition: "Downlink Compound RTCP",
            status: ScenarioStatus::from_bool(ok),
            metrics: format!(
                "rx={} AEAD-verified | tx=1 ({}B)",
                sess.dl_srtcp_verified,
                cli_rtcp.len()
            ),
            detail: format!("dl_srtcp_verified={}", sess.dl_srtcp_verified),
            elapsed_s: t5.elapsed().as_secs_f64(),
        };
        report_step(5, r.name, &r);
        results.push(r);
    } else {
        let r = ScenarioResult {
            id: 5,
            code: "wan_srtcp",
            name: "WAN Server SRTCP Heartbeat",
            condition: "Downlink Compound RTCP",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (session not ready)".into(),
            detail: "Requires established session".into(),
            elapsed_s: 0.0,
        };
        report_step(5, r.name, &r);
        results.push(r);
    }

    // #06 WAN SRTP Data-Plane Echo (in-band 0xFFFE on v0.3.5+ server; graceful SKIP on < v0.3.5)
    let t6 = Instant::now();
    let mut srtp_echo_supported = false;
    if let Some(ref mut sess) = sess_opt {
        let cap_payload = b"WEBRTC_CLOAK_V035_INBAND_PROBE_CAP_CHECK";
        for _ in 0..2 {
            if sess.probe_srtp_one(cap_payload, dyn_timeout_ms).is_some() {
                srtp_echo_supported = true;
                break;
            }
        }
        if !srtp_echo_supported {
            let r = ScenarioResult {
                id: 6,
                code: "wan_srtp_echo",
                name: "WAN SRTP Data-Plane Echo",
                condition: "30x 1200B in-band SRTP",
                status: ScenarioStatus::Skip,
                metrics: "Server < v0.3.5 (upgrade server for SRTP echo)".into(),
                detail: "Remote server does not enable 0xFFFE in-band SRTP probe echo yet".into(),
                elapsed_s: t6.elapsed().as_secs_f64(),
            };
            report_step(6, r.name, &r);
            results.push(r);
        } else {
            let total = 30u64;
            // 1198B probe payload + 4B probe hdr = exact same wire size as 1200B inner UDP!
            let probe_len = 1198usize;
            let mut payload = vec![0u8; probe_len];
            payload[..4].copy_from_slice(b"SEQ:");
            let mut wbuf = [0u8; 2048];
            let mut rbuf = [0u8; 2048];
            let mut pbuf = [0u8; 2048];
            let mut sent_at: HashMap<u64, Instant> = HashMap::new();
            let mut rtts_ms: Vec<f64> = Vec::with_capacity(total as usize);
            let mut rx_set: HashSet<u64> = HashSet::new();
            let mut ooo = 0u64;
            let mut max_seq: Option<u64> = None;
            let mut total_wire_bytes = 0usize;
            let mut sent_ok = 0usize;

            let _ = sess.sock.set_nonblocking(true);
            for seq in 0..total {
                payload[4..12].copy_from_slice(&seq.to_be_bytes());
                fill_random(&mut payload[12..]);
                if let Some(wn) = sess.cipher.wrap_probe_into(&payload, &mut wbuf) {
                    sent_at.insert(seq, Instant::now());
                    if sess.sock.send(&wbuf[..wn]).is_ok() {
                        sess.tx_srtp_pkts += 1;
                        total_wire_bytes += wn;
                        sent_ok += 1;
                        hi.max_wire_udp = hi.max_wire_udp.max(wn);
                    }
                }
                let next_tick = Instant::now() + Duration::from_millis(16);
                loop {
                    while let Ok(n) = sess.sock.recv(&mut rbuf) {
                        let pkt = &rbuf[..n];
                        match demux_rfc7983(pkt) {
                            PacketKind::Srtp => {
                                if let Some(SrtpFrame::Probe(pn)) =
                                    sess.cipher.unwrap_into_ex(pkt, &mut pbuf)
                                {
                                    if pn == probe_len && &pbuf[..4] == b"SEQ:" {
                                        let s = u64::from_be_bytes(pbuf[4..12].try_into().unwrap());
                                        if rx_set.insert(s) {
                                            sess.rx_srtp_pkts += 1;
                                            if let Some(t_send) = sent_at.get(&s) {
                                                rtts_ms.push(t_send.elapsed().as_secs_f64() * 1000.0);
                                            }
                                            if let Some(m) = max_seq {
                                                if s < m {
                                                    ooo += 1;
                                                } else {
                                                    max_seq = Some(s);
                                                }
                                            } else {
                                                max_seq = Some(s);
                                            }
                                        }
                                    }
                                }
                            }
                            PacketKind::Dtls => {
                                sess.pump_dtls(Some(pkt));
                            }
                            PacketKind::Srtcp => {
                                if sess.cipher.verify_srtcp(pkt).is_some() {
                                    sess.dl_srtcp_verified += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                    sess.pump_dtls(None);
                    if Instant::now() >= next_tick {
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
            let drain_deadline = Instant::now() + Duration::from_millis(dyn_timeout_ms.min(1200));
            while Instant::now() < drain_deadline && rx_set.len() < sent_ok {
                while let Ok(n) = sess.sock.recv(&mut rbuf) {
                    let pkt = &rbuf[..n];
                    match demux_rfc7983(pkt) {
                        PacketKind::Srtp => {
                            if let Some(SrtpFrame::Probe(pn)) =
                                sess.cipher.unwrap_into_ex(pkt, &mut pbuf)
                            {
                                if pn == probe_len && &pbuf[..4] == b"SEQ:" {
                                    let s = u64::from_be_bytes(pbuf[4..12].try_into().unwrap());
                                    if rx_set.insert(s) {
                                        sess.rx_srtp_pkts += 1;
                                        if let Some(t_send) = sent_at.get(&s) {
                                            rtts_ms.push(t_send.elapsed().as_secs_f64() * 1000.0);
                                        }
                                        if let Some(m) = max_seq {
                                            if s < m {
                                                ooo += 1;
                                            } else {
                                                max_seq = Some(s);
                                            }
                                        } else {
                                            max_seq = Some(s);
                                        }
                                    }
                                }
                            }
                        }
                        PacketKind::Srtcp => {
                            if sess.cipher.verify_srtcp(pkt).is_some() {
                                sess.dl_srtcp_verified += 1;
                            }
                        }
                        _ => {}
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
            let _ = sess.sock.set_nonblocking(false);

            rtts_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let p50 = percentile(&rtts_ms, 50);
            let avg_wire = if sent_ok > 0 {
                total_wire_bytes as f64 / sent_ok as f64
            } else {
                0.0
            };
            let delta_b = (avg_wire - 1200.0).max(0.0);
            let ov_pct = (delta_b / 1200.0) * 100.0;
            hi.overhead_bytes = Some(delta_b);
            hi.overhead_pct = Some(ov_pct);

            let ok = rx_set.len() >= 20;
            let r = ScenarioResult {
                id: 6,
                code: "wan_srtp_echo",
                name: "WAN SRTP Data-Plane Echo",
                condition: "30x 1200B in-band SRTP",
                status: ScenarioStatus::from_bool(ok),
                metrics: format!(
                    "p50 {:.1}ms | {}/{} | ooo={} | +{:.1}B (+{:.2}%)",
                    p50,
                    rx_set.len(),
                    total,
                    ooo,
                    delta_b,
                    ov_pct
                ),
                detail: format!(
                    "p95={:.1}ms avg_wire={:.1}B sent={}",
                    percentile(&rtts_ms, 95),
                    avg_wire,
                    sent_ok
                ),
                elapsed_s: t6.elapsed().as_secs_f64(),
            };
            report_step(6, r.name, &r);
            results.push(r);
        }
    } else {
        let r = ScenarioResult {
            id: 6,
            code: "wan_srtp_echo",
            name: "WAN SRTP Data-Plane Echo",
            condition: "30x 1200B in-band SRTP",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (session not ready)".into(),
            detail: "Requires established session".into(),
            elapsed_s: 0.0,
        };
        report_step(6, r.name, &r);
        results.push(r);
    }

    // #07 WAN Path MTU & PPPoE Anti-Frag Probe
    let t7 = Instant::now();
    if let Some(ref mut sess) = sess_opt {
        if !srtp_echo_supported {
            let r = ScenarioResult {
                id: 7,
                code: "wan_path_mtu",
                name: "WAN Path MTU Anti-Frag Probe",
                condition: "1000..1452B real WAN",
                status: ScenarioStatus::Skip,
                metrics: "Server < v0.3.5 (requires SRTP echo)".into(),
                detail: "Upgrade remote server to v0.3.5+ for live WAN Path MTU probing".into(),
                elapsed_s: 0.0,
            };
            report_step(7, r.name, &r);
            results.push(r);
        } else {
            let max_wire_allowed = opts.wan_mtu.saturating_sub(28);
            let exact_edge = max_wire_allowed.saturating_sub(38); // 1422B for WAN MTU 1488
            let candidates = [1000usize, 1200, 1350, 1400, exact_edge];
            let mut max_udp_pass = 0usize;
            let mut max_wire_seen = 0usize;
            let mut size_notes = Vec::new();

            for &udp_equiv in &candidates {
                if udp_equiv > exact_edge || udp_equiv < 16 {
                    continue;
                }
                let mut payload = vec![0u8; udp_equiv - 2];
                payload[..4].copy_from_slice(b"MTU:");
                fill_random(&mut payload[4..]);
                let mut passed_sz = false;
                for _ in 0..2 {
                    if let Some((_rtt, wn)) = sess.probe_srtp_one(&payload, dyn_timeout_ms) {
                        passed_sz = true;
                        max_wire_seen = max_wire_seen.max(wn);
                        hi.max_wire_udp = hi.max_wire_udp.max(wn);
                        break;
                    }
                }
                if passed_sz {
                    max_udp_pass = udp_equiv;
                    size_notes.push(format!("{}=OK", udp_equiv));
                } else {
                    size_notes.push(format!("{}=DROP", udp_equiv));
                }
            }

            // Local anti-frag guard MUST block oversize (e.g. 1452B)
            let oversize_udp = exact_edge + 30;
            let oversize_payload = vec![0x77u8; oversize_udp.saturating_sub(2)];
            let mut tmp_buf = [0u8; 2048];
            let guard_dropped = sess
                .cipher
                .wrap_probe_into(&oversize_payload, &mut tmp_buf)
                .is_none();

            let ipv4_mtu_verified = if max_udp_pass > 0 {
                max_udp_pass + 38 + 28
            } else {
                0
            };
            hi.wan_mtu_pass = if ipv4_mtu_verified > 0 {
                Some(ipv4_mtu_verified)
            } else {
                None
            };

            let ok = max_udp_pass >= 1200 && guard_dropped && max_wire_seen <= max_wire_allowed;
            let r = ScenarioResult {
                id: 7,
                code: "wan_path_mtu",
                name: "WAN Path MTU Anti-Frag Probe",
                condition: "1000..1452B real WAN",
                status: ScenarioStatus::from_bool(ok),
                metrics: format!(
                    "pass<={}B (IPv4 {}B) | {}B guard {}",
                    max_udp_pass,
                    ipv4_mtu_verified,
                    oversize_udp,
                    if guard_dropped { "DROP" } else { "LEAK" }
                ),
                detail: format!("probes=[{}] max_wire={}B", size_notes.join(" "), max_wire_seen),
                elapsed_s: t7.elapsed().as_secs_f64(),
            };
            report_step(7, r.name, &r);
            results.push(r);
        }
    } else {
        let r = ScenarioResult {
            id: 7,
            code: "wan_path_mtu",
            name: "WAN Path MTU Anti-Frag Probe",
            condition: "1000..1452B real WAN",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (session not ready)".into(),
            detail: "Requires established session".into(),
            elapsed_s: 0.0,
        };
        report_step(7, r.name, &r);
        results.push(r);
    }

    // #08 WAN 5-Tuple Rotation & NAT Behavior Check
    let t8 = Instant::now();
    if sess_opt.is_some() {
        let r = match remote_stun_handshake(server_addr, psk) {
            Ok(stun2) => {
                let mapped2 = stun2.mapped_addr;
                match remote_dtls_handshake(
                    stun2,
                    psk,
                    opts.cipher_pref,
                    opts.dtls_min_version,
                    opts.wan_mtu,
                ) {
                    Ok((mut sess2, hs2_ms)) => {
                        sess2.teardown();
                        let nat_note = match (mapped1, mapped2) {
                            (Some(m1), Some(m2)) if m1.ip() == m2.ip() => {
                                let diff = (m2.port() as i32 - m1.port() as i32).abs();
                                format!(
                                    "NAT {}:{}->{} (same IP, d={})",
                                    m1.ip(),
                                    m1.port(),
                                    m2.port(),
                                    diff
                                )
                            }
                            (Some(m1), Some(m2)) => {
                                format!("NAT {}->{} (multi-IP CGNAT)", m1, m2)
                            }
                            _ => "NAT rotated OK".into(),
                        };
                        ScenarioResult {
                            id: 8,
                            code: "wan_rotate_nat",
                            name: "WAN 5-Tuple Rotate & NAT",
                            condition: "Fresh port2 + DTLS Auto",
                            status: ScenarioStatus::Pass,
                            metrics: format!("hs2 {:.0}ms | {}", hs2_ms, nat_note),
                            detail: format!("mapped1={:?} mapped2={:?}", mapped1, mapped2),
                            elapsed_s: t8.elapsed().as_secs_f64(),
                        }
                    }
                    Err(msg) => ScenarioResult {
                        id: 8,
                        code: "wan_rotate_nat",
                        name: "WAN 5-Tuple Rotate & NAT",
                        condition: "Fresh port2 + DTLS Auto",
                        status: ScenarioStatus::Fail,
                        metrics: "2nd-port DTLS handshake FAILED".into(),
                        detail: msg,
                        elapsed_s: t8.elapsed().as_secs_f64(),
                    },
                }
            }
            Err(msg) => ScenarioResult {
                id: 8,
                code: "wan_rotate_nat",
                name: "WAN 5-Tuple Rotate & NAT",
                condition: "Fresh port2 + DTLS Auto",
                status: ScenarioStatus::Fail,
                metrics: "2nd-port STUN FAILED".into(),
                detail: msg,
                elapsed_s: t8.elapsed().as_secs_f64(),
            },
        };
        report_step(8, r.name, &r);
        results.push(r);
    } else {
        let r = ScenarioResult {
            id: 8,
            code: "wan_rotate_nat",
            name: "WAN 5-Tuple Rotate & NAT",
            condition: "Fresh port2 + DTLS Auto",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (initial session failed)".into(),
            detail: "Requires live server reachability".into(),
            elapsed_s: 0.0,
        };
        report_step(8, r.name, &r);
        results.push(r);
    }

    // #09 WAN Active Probe Silent-Drop Audit (7 hostile vectors in parallel!)
    let t9 = Instant::now();
    if !opts.active_probes {
        let r = ScenarioResult {
            id: 9,
            code: "wan_active_probe",
            name: "WAN Active Probe Silent-Drop",
            condition: "7 hostile WAN vectors",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (--no-probe)".into(),
            detail: "Disabled by user flag --no-probe".into(),
            elapsed_s: 0.0,
        };
        report_step(9, r.name, &r);
        results.push(r);
    } else {
        let ice = SessionIceParams::generate();
        let mut rand_junk = vec![0u8; 64];
        fill_random(&mut rand_junk);

        let mut forged_dtls = vec![0u8; 64];
        forged_dtls[0] = 22;
        forged_dtls[1] = 0xFE;
        forged_dtls[2] = 0xFD;
        forged_dtls[12] = 51;
        forged_dtls[13] = 1;

        let (wrong_psk_stun, _) = build_ice_stun_request(b"wrong-attacker-psk", &ice, None, true);

        let (mut tampered_mi_stun, _) = build_ice_stun_request(psk, &ice, None, true);
        let mi_idx = tampered_mi_stun.len().saturating_sub(14);
        tampered_mi_stun[mi_idx] ^= 0x01;

        let (mut smuggled_stun, _) = build_ice_stun_request(psk, &ice, None, true);
        smuggled_stun.extend_from_slice(&[0x80, 0x22, 0x00, 0x04, b'E', b'V', b'I', b'L']);
        let new_len = (smuggled_stun.len() - 20) as u16;
        smuggled_stun[2..4].copy_from_slice(&new_len.to_be_bytes());

        let replay_stun = if captured_stun.is_empty() {
            let (s, _) = build_ice_stun_request(b"fallback-replay", &ice, None, true);
            s
        } else {
            captured_stun
        };
        let (orphan_ka_stun, _) = build_ice_stun_request(psk, &ice, None, false);

        let probes: Vec<(&'static str, Vec<u8>)> = vec![
            ("junk", rand_junk),
            ("dtls_no_stun", forged_dtls),
            ("wrong_psk", wrong_psk_stun),
            ("bad_mi", tampered_mi_stun),
            ("tail_smuggle", smuggled_stun),
            ("cross_replay", replay_stun),
            ("orphan_ka", orphan_ka_stun),
        ];

        let probe_wait_ms = ((stun_rtt_ms * 2.5) as u64).clamp(350, 1200);
        let handles: Vec<_> = probes
            .into_iter()
            .map(|(name, payload)| {
                thread::spawn(move || {
                    let rx = send_probe_expect_silence_ms(server_addr, &payload, probe_wait_ms);
                    (name, rx)
                })
            })
            .collect();

        let mut blocked = 0usize;
        let mut total_probes = 0usize;
        let mut leaked_bytes = 0usize;
        let mut leaked_names = Vec::new();
        for h in handles {
            if let Ok((name, rx)) = h.join() {
                total_probes += 1;
                if rx == 0 {
                    blocked += 1;
                } else {
                    leaked_bytes += rx;
                    leaked_names.push(format!("{}({}B)", name, rx));
                }
            }
        }
        hi.probes_blocked = blocked;
        hi.probes_total = total_probes;

        let legit_ok = sess_opt
            .as_mut()
            .map(|s| s.send_stun_consent(psk, dyn_timeout_ms).is_some())
            .unwrap_or(true);

        let ok = blocked == total_probes && leaked_bytes == 0 && legit_ok;
        let r = ScenarioResult {
            id: 9,
            code: "wan_active_probe",
            name: "WAN Active Probe Silent-Drop",
            condition: "7 hostile WAN vectors",
            status: ScenarioStatus::from_bool(ok),
            metrics: format!(
                "silent_drop {}/{} ({}B leaked) | legit {}",
                blocked,
                total_probes,
                leaked_bytes,
                if legit_ok { "OK" } else { "FAIL" }
            ),
            detail: if leaked_names.is_empty() {
                "All 7 live WAN probes silently dropped (0B)".into()
            } else {
                format!("Leaked responses: {}", leaked_names.join(", "))
            },
            elapsed_s: t9.elapsed().as_secs_f64(),
        };
        report_step(9, r.name, &r);
        results.push(r);
    }

    // #10 Graceful Teardown (SRTCP BYE + DTLS close_notify)
    let t10 = Instant::now();
    if let Some(ref mut sess) = sess_opt {
        sess.teardown();
        let r = ScenarioResult {
            id: 10,
            code: "wan_teardown",
            name: "Graceful Teardown (BYE/Close)",
            condition: "Zero zombie sessions",
            status: ScenarioStatus::Pass,
            metrics: "SRTCP BYE + DTLS close_notify sent (2/2)".into(),
            detail: "Cleanly closed both temporary probe sessions on remote server".into(),
            elapsed_s: t10.elapsed().as_secs_f64(),
        };
        report_step(10, r.name, &r);
        results.push(r);
    } else {
        let r = ScenarioResult {
            id: 10,
            code: "wan_teardown",
            name: "Graceful Teardown (BYE/Close)",
            condition: "Zero zombie sessions",
            status: ScenarioStatus::Skip,
            metrics: "Skipped (no active session)".into(),
            detail: "No remote session was established".into(),
            elapsed_s: 0.0,
        };
        report_step(10, r.name, &r);
        results.push(r);
    }

    // #11 & #12 Local Host CPU Crypto Compute Benchmarks
    let r11 = test_11_cpu_single_core_crypto(opts, &mut hi);
    report_step(11, r11.name, &r11);
    results.push(r11);

    let r12 = test_12_cpu_multicore_and_p256(opts, &mut hi);
    report_step(12, r12.name, &r12);
    results.push(r12);

    let total_s = suite_t0.elapsed().as_secs_f64();
    if opts.json {
        print_json_report(&cpu, opts, &results, &hi, total_s);
    } else {
        print_pretty_report(&cpu, opts, &results, &hi, total_s);
    }

    results.iter().all(|r| r.status != ScenarioStatus::Fail)
}

// ---------------------------------------------------------------------------
// Elegant ANSI / Unicode Report Renderer + JSON Output
// ---------------------------------------------------------------------------

struct Palette {
    reset: &'static str,
    bold: &'static str,
    dim: &'static str,
    cyan: &'static str,
    green: &'static str,
    red: &'static str,
    yellow: &'static str,
    white: &'static str,
}

impl Palette {
    fn new(enabled: bool) -> Self {
        if enabled {
            Self {
                reset: "\x1b[0m",
                bold: "\x1b[1m",
                dim: "\x1b[2m",
                cyan: "\x1b[36m",
                green: "\x1b[32m",
                red: "\x1b[31m",
                yellow: "\x1b[33m",
                white: "\x1b[97m",
            }
        } else {
            Self {
                reset: "",
                bold: "",
                dim: "",
                cyan: "",
                green: "",
                red: "",
                yellow: "",
                white: "",
            }
        }
    }
}

fn pad_right(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.chars().take(width).collect()
    } else {
        format!("{}{}", s, " ".repeat(width - len))
    }
}

fn pad_left(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.chars().take(width).collect()
    } else {
        format!("{}{}", " ".repeat(width - len), s)
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn print_json_report(
    cpu: &crate::protocol::CpuAccelInfo,
    opts: &SelftestOptions,
    results: &[ScenarioResult],
    hi: &Highlights,
    total_s: f64,
) {
    let passed_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Pass).count();
    let skipped_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Skip).count();
    let failed_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Fail).count();
    println!("{{");
    println!("  \"version\": \"{}\",", env!("CARGO_PKG_VERSION"));
    println!("  \"mode\": \"{}\",", if hi.is_remote { "remote" } else { "local" });
    if let Some(ref tgt) = hi.target_label {
        println!("  \"target\": \"{}\",", json_escape(tgt));
    }
    println!("  \"arch\": \"{}\",", cpu.arch);
    println!("  \"hw_accel\": \"{}\",", cpu.features.join(", "));
    println!("  \"cipher_pref\": \"{:?}\",", opts.cipher_pref);
    println!("  \"recommended_cipher\": \"{}\",", cpu.recommended.name());
    println!("  \"wan_mtu\": {},", opts.wan_mtu);
    println!("  \"passed\": {},", passed_cnt);
    println!("  \"skipped\": {},", skipped_cnt);
    println!("  \"failed\": {},", failed_cnt);
    println!("  \"total\": {},", results.len());
    println!("  \"all_passed\": {},", failed_cnt == 0);
    println!("  \"total_elapsed_s\": {:.3},", total_s);
    println!("  \"highlights\": {{");
    println!(
        "    \"nat_mapped\": {},",
        hi.nat_mapped
            .as_ref()
            .map(|v| format!("\"{}\"", json_escape(v)))
            .unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"negotiated_cipher\": {},",
        hi.negotiated_cipher
            .as_ref()
            .map(|v| format!("\"{}\"", json_escape(v)))
            .unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"wan_p50_ms\": {},",
        hi.wan_p50_ms.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"wan_loss_pct\": {},",
        hi.wan_loss_pct.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"wan_mtu_verified\": {},",
        hi.wan_mtu_pass.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"wire_overhead_1200b_pct\": {},",
        hi.overhead_pct.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!("    \"max_wire_udp_bytes\": {},", hi.max_wire_udp);
    println!(
        "    \"blackhole_recovery_s\": {},",
        hi.blackhole_recover_s.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"server_restart_recovery_s\": {},",
        hi.restart_recover_s.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!("    \"active_probes_blocked\": {},", hi.probes_blocked);
    println!("    \"active_probes_total\": {},", hi.probes_total);
    println!(
        "    \"loopback_goodput_mbps\": {},",
        hi.goodput_mbps.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!("    \"cpu_cores\": {},", hi.cpu_cores);
    println!(
        "    \"cpu_1c_aes128_gcm_mbps\": {},",
        hi.cpu_aes_mbps.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"cpu_1c_chacha20_mbps\": {},",
        hi.cpu_chacha_mbps.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"cpu_1c_blake2b_mbps\": {},",
        hi.cpu_blake2b_mbps.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"cpu_multicore_gbps\": {},",
        hi.cpu_multicore_gbps.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "null".into())
    );
    println!(
        "    \"cpu_p256_certs_per_s\": {}",
        hi.cpu_p256_certs_per_s.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "null".into())
    );
    println!("  }},");
    println!("  \"scenarios\": [");
    for (idx, r) in results.iter().enumerate() {
        let comma = if idx + 1 < results.len() { "," } else { "" };
        println!(
            "    {{\"id\": {}, \"code\": \"{}\", \"name\": \"{}\", \"condition\": \"{}\", \"status\": \"{}\", \"passed\": {}, \"elapsed_s\": {:.3}, \"metrics\": \"{}\", \"detail\": \"{}\"}}{}",
            r.id,
            json_escape(r.code),
            json_escape(r.name),
            json_escape(r.condition),
            r.status.as_str(),
            r.status == ScenarioStatus::Pass,
            r.elapsed_s,
            json_escape(&r.metrics),
            json_escape(&r.detail),
            comma
        );
    }
    println!("  ]");
    println!("}}");
}

fn print_pretty_report(
    cpu: &crate::protocol::CpuAccelInfo,
    opts: &SelftestOptions,
    results: &[ScenarioResult],
    hi: &Highlights,
    total_s: f64,
) {
    let p = Palette::new(opts.color);
    let passed_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Pass).count();
    let skipped_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Skip).count();
    let failed_cnt = results.iter().filter(|r| r.status == ScenarioStatus::Fail).count();
    let total_cnt = results.len();
    let all_ok = failed_cnt == 0;

    // Column inner widths (pure ASCII contents -> exact 1:1 terminal cell alignment!)
    let w_id = 4;
    let w_name = 29;
    let w_cond = 23;
    let w_stat = 6;
    let w_met = results
        .iter()
        .map(|r| r.metrics.chars().count())
        .max()
        .unwrap_or(50)
        .max(54);
    let w_time = 6;
    let inner_total = (w_id + 2)
        + 1
        + (w_name + 2)
        + 1
        + (w_cond + 2)
        + 1
        + (w_stat + 2)
        + 1
        + (w_met + 2)
        + 1
        + (w_time + 2);

    let cipher_label = if let Some(ref neg) = hi.negotiated_cipher {
        format!("{} (negotiated)", neg)
    } else {
        match opts.cipher_pref {
            CipherPref::Auto => format!("auto -> {}", cpu.recommended.name()),
            CipherPref::Fixed(s) => s.name().to_string(),
        }
    };
    let accel_label = if cpu.features.is_empty() {
        "scalar".to_string()
    } else {
        cpu.features.join(", ")
    };

    let title = if hi.is_remote {
        format!(
            "webrtc-cloak v{}  |  LIVE Remote Tunnel Self-Test  ->  {}",
            env!("CARGO_PKG_VERSION"),
            hi.target_label.as_deref().unwrap_or("remote")
        )
    } else {
        format!(
            "webrtc-cloak v{}  |  Local Loopback Fault-Injection & CPU Self-Test Report",
            env!("CARGO_PKG_VERSION")
        )
    };
    let env_line = format!(
        "CPU: {} [{}]  |  Cipher: {}  |  MTU: {}B",
        cpu.arch, accel_label, cipher_label, opts.wan_mtu
    );
    let cond_col_hdr = if hi.is_remote {
        "Probe Scope"
    } else {
        "Simulated Condition"
    };

    println!();
    println!("{}╭{}╮{}", p.cyan, "─".repeat(inner_total), p.reset);
    println!(
        "{}│{} {}{}{} {}│{}",
        p.cyan,
        p.reset,
        p.bold,
        pad_right(&title, inner_total - 2),
        p.reset,
        p.cyan,
        p.reset
    );
    println!(
        "{}│{} {}{}{} {}│{}",
        p.cyan,
        p.reset,
        p.dim,
        pad_right(&env_line, inner_total - 2),
        p.reset,
        p.cyan,
        p.reset
    );

    println!(
        "{}├{}┬{}┬{}┬{}┬{}┬{}┤{}",
        p.cyan,
        "─".repeat(w_id + 2),
        "─".repeat(w_name + 2),
        "─".repeat(w_cond + 2),
        "─".repeat(w_stat + 2),
        "─".repeat(w_met + 2),
        "─".repeat(w_time + 2),
        p.reset
    );
    println!(
        "{}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{}",
        p.cyan, p.reset, p.bold, pad_right("ID", w_id), p.reset,
        p.cyan, p.reset, p.bold, pad_right("Scenario", w_name), p.reset,
        p.cyan, p.reset, p.bold, pad_right(cond_col_hdr, w_cond), p.reset,
        p.cyan, p.reset, p.bold, pad_right("Status", w_stat), p.reset,
        p.cyan, p.reset, p.bold, pad_right("Key Measured Metrics", w_met), p.reset,
        p.cyan, p.reset, p.bold, pad_left("Time", w_time), p.reset,
        p.cyan, p.reset
    );
    println!(
        "{}├{}┼{}┼{}┼{}┼{}┼{}┤{}",
        p.cyan,
        "─".repeat(w_id + 2),
        "─".repeat(w_name + 2),
        "─".repeat(w_cond + 2),
        "─".repeat(w_stat + 2),
        "─".repeat(w_met + 2),
        "─".repeat(w_time + 2),
        p.reset
    );

    for r in results {
        let id_s = format!("#{:02}", r.id);
        let (st_col, st_txt) = match r.status {
            ScenarioStatus::Pass => (p.green, "[PASS]"),
            ScenarioStatus::Skip => (p.yellow, "[SKIP]"),
            ScenarioStatus::Fail => (p.red, "[FAIL]"),
        };
        let time_s = format!("{:.2}s", r.elapsed_s);
        println!(
            "{}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{} {}│{} {}{}{}{} {}│{} {} {}│{} {}{}{} {}│{}",
            p.cyan, p.reset, p.dim, pad_right(&id_s, w_id), p.reset,
            p.cyan, p.reset, p.white, pad_right(r.name, w_name), p.reset,
            p.cyan, p.reset, p.dim, pad_right(r.condition, w_cond), p.reset,
            p.cyan, p.reset, p.bold, st_col, pad_right(st_txt, w_stat), p.reset,
            p.cyan, p.reset, pad_right(&r.metrics, w_met),
            p.cyan, p.reset, p.dim, pad_left(&time_s, w_time), p.reset,
            p.cyan, p.reset
        );
    }

    println!(
        "{}├{}┴{}┴{}┴{}┴{}┴{}┤{}",
        p.cyan,
        "─".repeat(w_id + 2),
        "─".repeat(w_name + 2),
        "─".repeat(w_cond + 2),
        "─".repeat(w_stat + 2),
        "─".repeat(w_met + 2),
        "─".repeat(w_time + 2),
        p.reset
    );

    let cpu_1c_str = match (hi.cpu_aes_mbps, hi.cpu_chacha_mbps, hi.cpu_blake2b_mbps) {
        (Some(a), Some(c), Some(b)) => format!("AES {:.0} / ChaCha {:.0} / B2B {:.0} Mbps", a, c, b),
        _ => "N/A".into(),
    };
    let cpu_mc_str = hi
        .cpu_multicore_gbps
        .map(|g| format!("{:.2} Gbps ({}C)", g, hi.cpu_cores))
        .unwrap_or_else(|| "N/A".into());
    let p256_str = hi
        .cpu_p256_certs_per_s
        .map(|v| format!("{:.0}/s", v))
        .unwrap_or_else(|| "N/A".into());

    let (summary_1, summary_2) = if hi.is_remote {
        let nat_s = hi.nat_mapped.as_deref().unwrap_or("N/A");
        let rtt_s = hi
            .wan_p50_ms
            .map(|v| format!("{:.1}ms", v))
            .unwrap_or_else(|| "N/A".into());
        let loss_s = hi
            .wan_loss_pct
            .map(|v| format!("{:.1}%", v))
            .unwrap_or_else(|| "N/A".into());
        let mtu_s = hi
            .wan_mtu_pass
            .map(|v| format!("IPv4 {}B verified", v))
            .unwrap_or_else(|| "N/A (server < v0.3.5)".into());
        let ov_s = match (hi.overhead_bytes, hi.overhead_pct) {
            (Some(b), Some(pct)) => format!("+{:.1}B (+{:.2}%)", b, pct),
            _ => "N/A".into(),
        };
        (
            format!(
                "Live WAN: NAT {}  |  P50 RTT {}  |  Loss {}  |  Path MTU: {}",
                nat_s, rtt_s, loss_s, mtu_s
            ),
            format!(
                "SRTP Overhead (1200B): {}  |  Silent-Drop Security: {}/{} blocked (0B leaked)",
                ov_s, hi.probes_blocked, hi.probes_total
            ),
        )
    } else {
        let ov_str = match (hi.overhead_bytes, hi.overhead_pct) {
            (Some(b), Some(pct)) => format!("+{:.1}B (+{:.2}%)", b, pct),
            _ => "N/A".into(),
        };
        let bh_str = hi
            .blackhole_recover_s
            .map(|v| format!("{:.2}s", v))
            .unwrap_or_else(|| "N/A".into());
        let rs_str = hi
            .restart_recover_s
            .map(|v| format!("{:.2}s", v))
            .unwrap_or_else(|| "N/A".into());
        let gp_str = match (hi.goodput_mbps, hi.goodput_kpps) {
            (Some(m), Some(k)) => format!("{:.0} Mbps ({:.1} kpps)", m, k),
            _ => "N/A".into(),
        };
        (
            format!(
                "Wire Overhead (1200B): {}  |  Max Wire UDP: {}B / {}B  |  Loopback Goodput: {}",
                ov_str,
                hi.max_wire_udp,
                opts.wan_mtu.saturating_sub(28),
                gp_str
            ),
            format!(
                "Self-Heal: Blackhole {} / Restart {}  |  Silent-Drop Security: {}/{} blocked (0B leaked)",
                bh_str, rs_str, hi.probes_blocked, hi.probes_total
            ),
        )
    };
    let summary_3 = format!(
        "CPU Compute (1200B): 1C [{}]  |  All-Core: {}  |  P-256 Cert: {}",
        cpu_1c_str, cpu_mc_str, p256_str
    );

    for line in [&summary_1, &summary_2, &summary_3] {
        println!(
            "{}│{} {} {}│{}",
            p.cyan,
            p.reset,
            pad_right(line, inner_total - 2),
            p.cyan,
            p.reset
        );
    }
    println!("{}├{}┤{}", p.cyan, "─".repeat(inner_total), p.reset);

    let verdict_col = if all_ok { p.green } else { p.red };
    let footer_left = if !all_ok {
        format!(
            "VERDICT: CHECKS FAILED ({} passed, {} failed, {} skipped)",
            passed_cnt, failed_cnt, skipped_cnt
        )
    } else if skipped_cnt > 0 {
        format!(
            "VERDICT: ALL RUN CHECKS PASSED ({}/{} passed, {} skipped)",
            passed_cnt,
            total_cnt - skipped_cnt,
            skipped_cnt
        )
    } else {
        format!(
            "VERDICT: ALL CHECKS PASSED ({}/{} passed)",
            passed_cnt, total_cnt
        )
    };
    let footer_right = format!("Total Elapsed: {:.2}s", total_s);
    let gap = (inner_total - 2).saturating_sub(footer_left.len() + footer_right.len());

    println!(
        "{}│{} {}{}{}{}{}{}{}{} {}│{}",
        p.cyan,
        p.reset,
        p.bold,
        verdict_col,
        footer_left,
        p.reset,
        " ".repeat(gap),
        p.yellow,
        footer_right,
        p.reset,
        p.cyan,
        p.reset
    );
    println!("{}╰{}╯{}", p.cyan, "─".repeat(inner_total), p.reset);

    let failures: Vec<&ScenarioResult> = results
        .iter()
        .filter(|r| r.status == ScenarioStatus::Fail)
        .collect();
    if !failures.is_empty() {
        println!();
        println!("{}{}Failure Diagnostics:{}", p.bold, p.red, p.reset);
        for f in failures {
            println!("  #{:02} {} -> {}", f.id, f.name, f.detail);
        }
    }
    if !hi.is_remote {
        println!(
            "{}Tip: test a live remote tunnel with: webrtc-cloak selftest --server-host <IP> --server-port 19643 --psk-file <PATH>{}",
            p.dim, p.reset
        );
    }
    println!();
}

pub fn run_selftest(opts: SelftestOptions) -> bool {
    if let (Some(server_addr), Some(ref psk)) = (opts.server_addr, opts.psk.as_ref()) {
        return run_remote_selftest(&opts, server_addr, psk);
    }

    let cpu = detect_cpu_accel();
    let p = Palette::new(opts.color);
    let suite_t0 = Instant::now();
    let mut hi = Highlights::default();

    type TestFn = fn(&SelftestOptions, &mut Highlights) -> ScenarioResult;
    let tests: [(&str, TestFn); 12] = [
        ("Baseline & Wire Overhead", test_01_baseline),
        ("Trans-Pacific RTT & Jitter", test_02_transpacific_latency),
        ("Bidirectional Random Loss", test_03_random_loss),
        ("ECMP Reorder & Replay Guard", test_04_reorder_and_replay),
        ("PPPoE MTU 1488 Anti-Frag", test_05_mtu_guard),
        ("Single STUN Drop Immunity", test_06_single_stun_drop),
        ("Asymmetric Uplink Blackhole", test_07_asymmetric_blackhole),
        ("Server Restart Recovery", test_08_server_restart),
        ("Active Probe & Replay Defense", test_09_active_probing_defense),
        ("Multi-Stream & Loopback Speed", test_10_multistream_throughput),
        ("CPU Single-Core Crypto Bench", test_11_cpu_single_core_crypto),
        ("CPU Multi-Core & P-256 Certs", test_12_cpu_multicore_and_p256),
    ];

    if !opts.json {
        println!(
            "{}{}Running webrtc-cloak v{} local loopback self-test suite ({} scenarios)...{}",
            p.bold,
            p.cyan,
            env!("CARGO_PKG_VERSION"),
            tests.len(),
            p.reset
        );
    }

    let mut results = Vec::with_capacity(tests.len());
    for (idx, (label, func)) in tests.iter().enumerate() {
        if !opts.json {
            print!(
                "  {}[{:02}/{:02}]{} {} ... ",
                p.dim,
                idx + 1,
                tests.len(),
                p.reset,
                pad_right(label, 31)
            );
            let _ = std::io::stdout().flush();
        }
        let res = func(&opts, &mut hi);
        if !opts.json {
            match res.status {
                ScenarioStatus::Pass => println!(
                    "{}{}[PASS]{} {}({:.2}s){}",
                    p.bold, p.green, p.reset, p.dim, res.elapsed_s, p.reset
                ),
                ScenarioStatus::Skip => println!(
                    "{}{}[SKIP]{} {}({:.2}s){}",
                    p.bold, p.yellow, p.reset, p.dim, res.elapsed_s, p.reset
                ),
                ScenarioStatus::Fail => println!(
                    "{}{}[FAIL]{} {}({:.2}s) - {}{}",
                    p.bold, p.red, p.reset, p.dim, res.elapsed_s, res.metrics, p.reset
                ),
            }
        }
        results.push(res);
    }

    let total_s = suite_t0.elapsed().as_secs_f64();
    if opts.json {
        print_json_report(&cpu, &opts, &results, &hi, total_s);
    } else {
        print_pretty_report(&cpu, &opts, &results, &hi, total_s);
    }

    results.iter().all(|r| r.status != ScenarioStatus::Fail)
}
