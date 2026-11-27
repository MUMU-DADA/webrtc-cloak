//! IPv6 端到端隧道与 ECMP 信道抽卡探测（启动预热/多轮重抽/退化 0ms MBB/黑洞 1-RTT 竞速）集成测试。

use super::reserve_free_port;
use crate::client::lane_hunt::{compute_lane_score, LANE_DEGRADE_SCORE_THRESHOLD};
use crate::client::{run_client, ClientConfig, LaneHuntConfig};
use crate::protocol::{demux_rfc7983, CipherPref, DtlsMinVersion, PacketKind};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn reserve_free_v6_port() -> u16 {
    let s = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .expect("bind IPv6 loopback");
    s.local_addr().unwrap().port()
}

/// 确定性 ECMP 仿真代理：按客户端源端口分配高速（0ms）或绕路慢速（210ms）信道，并支持动态退化与黑洞注入。
struct EcmpSimState {
    /// 每个客户端源端口的当前单程延迟（毫秒，0 = 高速，105 = 210ms RTT 慢速）。
    port_oneway_delay_ms: Mutex<HashMap<u16, u64>>,
    /// 按首次出现顺序记录高速端口集合（供断言校验）。
    fast_ports: Mutex<HashSet<u16>>,
    /// 按顺序将第 `idx` 个新出现的端口判为高速的策略闭包结果：
    /// `fast_indices` 中包含的序号为高速（0ms），其余为慢速（210ms RTT）。
    fast_indices: HashSet<usize>,
    /// 动态注入退化的特定端口（设为非 0 时该端口立即变为 220ms RTT 慢速信道）。
    degraded_port: AtomicU16,
    /// 动态注入黑洞的特定端口（设为非 0 时该端口 100% 丢弃所有上行与下行包）。
    blackholed_port: AtomicU16,
    /// 动态注入下行 SRTP 数据面丢包的特定端口（模拟「STUN 0ms 假优但数据面限速丢包 25%」信道）。
    lossy_data_port: AtomicU16,
    /// 确定性下行 SRTP 丢包计数器（每 4 个下行 SRTP 丢弃 1 个 = 精确 25% 数据面丢包）。
    lossy_data_counter: AtomicU32,
}

impl EcmpSimState {
    fn new(fast_indices: &[usize]) -> Arc<Self> {
        Arc::new(Self {
            port_oneway_delay_ms: Mutex::new(HashMap::new()),
            fast_ports: Mutex::new(HashSet::new()),
            fast_indices: fast_indices.iter().copied().collect(),
            degraded_port: AtomicU16::new(0),
            blackholed_port: AtomicU16::new(0),
            lossy_data_port: AtomicU16::new(0),
            lossy_data_counter: AtomicU32::new(0),
        })
    }

    fn should_drop_downlink_data(&self, client_port: u16, pkt: &[u8]) -> bool {
        if self.lossy_data_port.load(Ordering::Relaxed) != client_port {
            return false;
        }
        if demux_rfc7983(pkt) != PacketKind::Srtp {
            return false;
        }
        // 精确丢弃 25% 下行 SRTP 数据包，同时放行 100% STUN/DTLS/SRTCP 控制面！
        self.lossy_data_counter
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(4)
    }

    fn oneway_delay_for(&self, client_port: u16) -> Option<u64> {
        if self.blackholed_port.load(Ordering::Relaxed) == client_port {
            return None;
        }
        if self.degraded_port.load(Ordering::Relaxed) == client_port {
            return Some(115); // 230ms RTT
        }
        let mut map = self.port_oneway_delay_ms.lock().unwrap();
        if let Some(&d) = map.get(&client_port) {
            return Some(d);
        }
        let idx = map.len();
        let is_fast = self.fast_indices.contains(&idx);
        let d = if is_fast { 0 } else { 110 }; // 0ms vs 220ms RTT
        map.insert(client_port, d);
        if is_fast {
            self.fast_ports.lock().unwrap().insert(client_port);
        }
        Some(d)
    }

    fn is_fast_port(&self, port: u16) -> bool {
        self.fast_ports.lock().unwrap().contains(&port)
    }

    fn seen_port_count(&self) -> usize {
        self.port_oneway_delay_ms.lock().unwrap().len()
    }
}

/// 启动带确定性 ECMP 延迟/黑洞注入的本地 UDP 中继代理（每个客户端源端口维持独立上游端口，不破坏五元组隔离）。
fn spawn_ecmp_proxy(
    proxy_port: u16,
    server_addr: SocketAddr,
    state: Arc<EcmpSimState>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let front =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port)).unwrap();
        front.set_nonblocking(true).unwrap();

        // 每个 client_addr 对应一个独立连向 server 的上游 UDP 套接字（保持源端口一一映射）
        let mut upstreams: HashMap<SocketAddr, UdpSocket> = HashMap::new();
        // 延迟投递队列：(deliver_at, direction_to_server, client_addr, payload)
        let mut queue: Vec<(Instant, bool, SocketAddr, Vec<u8>)> = Vec::new();
        let mut buf = [0u8; 4096];

        while !stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            // 1) 读取来自客户端的包
            while let Ok((n, caddr)) = front.recv_from(&mut buf) {
                if let Some(delay_ms) = state.oneway_delay_for(caddr.port()) {
                    upstreams.entry(caddr).or_insert_with(|| {
                        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
                        u.set_nonblocking(true).unwrap();
                        u.connect(server_addr).unwrap();
                        u
                    });
                    if delay_ms == 0 {
                        if let Some(u) = upstreams.get(&caddr) {
                            let _ = u.send(&buf[..n]);
                        }
                    } else {
                        queue.push((
                            now + Duration::from_millis(delay_ms),
                            true,
                            caddr,
                            buf[..n].to_vec(),
                        ));
                    }
                }
            }

            // 2) 读取来自服务端的回包
            for (&caddr, u) in upstreams.iter() {
                while let Ok(n) = u.recv(&mut buf) {
                    if state.should_drop_downlink_data(caddr.port(), &buf[..n]) {
                        continue;
                    }
                    if let Some(delay_ms) = state.oneway_delay_for(caddr.port()) {
                        if delay_ms == 0 {
                            let _ = front.send_to(&buf[..n], caddr);
                        } else {
                            queue.push((
                                now + Duration::from_millis(delay_ms),
                                false,
                                caddr,
                                buf[..n].to_vec(),
                            ));
                        }
                    }
                }
            }

            // 3) 派发到期的延迟报文
            let mut idx = 0;
            while idx < queue.len() {
                if now >= queue[idx].0 {
                    let (_, to_srv, caddr, pkt) = queue.swap_remove(idx);
                    if state.blackholed_port.load(Ordering::Relaxed) != caddr.port() {
                        if to_srv {
                            if let Some(u) = upstreams.get(&caddr) {
                                let _ = u.send(&pkt);
                            }
                        } else {
                            let _ = front.send_to(&pkt, caddr);
                        }
                    }
                } else {
                    idx += 1;
                }
            }

            thread::sleep(Duration::from_millis(2));
        }
    })
}

fn spawn_backend_echo_recording_port(
    backend_port: u16,
    last_src_port: Arc<AtomicU16>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let sock = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            backend_port,
        ))
        .unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(40)))
            .unwrap();
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                last_src_port.store(peer.port(), Ordering::Relaxed);
                let _ = sock.send_to(&buf[..n], peer);
            }
        }
    })
}

fn read_json_file(path: &str) -> Option<serde_json::Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

#[test]
fn ipv6_end_to_end_dtls13_tunnel() {
    // 跳过无 IPv6 回环的环境（极少数精简容器）
    if UdpSocket::bind("[::1]:0").is_err() {
        return;
    }
    let backend_port = reserve_free_port();
    let server_port = reserve_free_v6_port();
    let client_port = reserve_free_port();
    let psk = b"ipv6-e2e-dtls13-test-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));
    let last_backend_port = Arc::new(AtomicU16::new(0));
    let status_file = std::env::temp_dir()
        .join(format!(
            "wc_ipv6_e2e_{}_{}.json",
            std::process::id(),
            client_port
        ))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&status_file);

    let _b = spawn_backend_echo_recording_port(
        backend_port,
        Arc::clone(&last_backend_port),
        Arc::clone(&stop),
    );
    let srv_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), server_port);
    let s_stop = Arc::clone(&stop);
    let s_psk = psk.clone();
    let _s = thread::spawn(move || {
        if let Err(e) = run_server(ServerConfig {
            listen_addr: srv_addr,
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: s_psk,
            stun_scope: None,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 16,
            wan_mtu: 1488,
            udp_batch: 0,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(s_stop),
        }) {
            eprintln!("ipv6 test server error: {}", e);
        }
    });
    thread::sleep(Duration::from_millis(250));

    let c_stop = Arc::clone(&stop);
    let c_status = status_file.clone();
    let _c = thread::spawn(move || {
        if let Err(e) = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: srv_addr,
            psk,
            stun_scope: None,
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 16,
            wan_mtu: 1488,
            udp_batch: 0,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 5,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            lane_hunt: LaneHuntConfig {
                enabled: true,
                probes: 2,
                max_rounds: 2,
                target_rtt_ms: 100,
                degrade_cooldown_secs: 10,
            },
            telemetry: TelemetryConfig {
                status_file: Some(c_status),
                status_http: None,
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(c_stop),
        }) {
            eprintln!("ipv6 test client error: {}", e);
        }
    });

    // Wait for pre-warmed IPv6 DTLS 1.3 session to finish binding & handshaking (avoids slow-CI sleep race).
    let ready_deadline = Instant::now() + Duration::from_secs(10);
    let mut ready_sport = 0u16;
    while Instant::now() < ready_deadline {
        if let Some(j) = read_json_file(&status_file) {
            let sp = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            let active = j["sessions"]["active"].as_u64().unwrap_or(0);
            if sp != 0 && active >= 1 {
                ready_sport = sp;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_ne!(ready_sport, 0, "IPv6 client must bind & pre-warm READY");

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    app.connect(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port,
    ))
    .unwrap();

    let mut rbuf = [0u8; 2048];
    for i in 0..15u32 {
        let msg = format!("IPV6_ECHO_PKT_{:04}", i);
        app.send(msg.as_bytes()).unwrap();
        let n = app.recv(&mut rbuf).expect("IPv6 echo reply");
        assert_eq!(&rbuf[..n], msg.as_bytes());
    }
    // IPv6 外层 MTU=1488 -> UDP 载荷上限 1440B -> 内层上限 1402B（应允许 1390B，拦下 1420B）
    let ok_1390 = vec![0x42u8; 1390];
    app.send(&ok_1390).unwrap();
    let n = app.recv(&mut rbuf).expect("IPv6 1390B MTU edge reply");
    assert_eq!(n, 1390);
    assert_ne!(last_backend_port.load(Ordering::Relaxed), 0);

    stop.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(80));
    let _ = std::fs::remove_file(&status_file);
}

#[test]
fn lane_hunt_startup_multiround_prewarm_and_zero_ms_adopt() {
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let proxy_port = reserve_free_port();
    let client_port = reserve_free_port();
    let psk = b"lane-hunt-startup-multiround-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));
    let last_backend_port = Arc::new(AtomicU16::new(0));

    // 第 1 轮 3 个候选（0,1,2）全慢 220ms，第 2 轮第 2 个候选（序号 4）才是高速 0ms -> 强制验证多轮重抽！
    let sim = EcmpSimState::new(&[4, 8, 12]);
    let status_file = std::env::temp_dir()
        .join(format!("wc_lane_startup_{}.json", client_port))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&status_file);

    let _b = spawn_backend_echo_recording_port(
        backend_port,
        Arc::clone(&last_backend_port),
        Arc::clone(&stop),
    );
    let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    let s_stop = Arc::clone(&stop);
    let s_psk = psk.clone();
    let _s = thread::spawn(move || {
        let _ = run_server(ServerConfig {
            listen_addr: srv_addr,
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: s_psk,
            stun_scope: None,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(s_stop),
        });
    });
    let _p = spawn_ecmp_proxy(proxy_port, srv_addr, Arc::clone(&sim), Arc::clone(&stop));
    thread::sleep(Duration::from_millis(80));

    let c_stop = Arc::clone(&stop);
    let c_status = status_file.clone();
    let _c = thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port),
            psk,
            stun_scope: Some(srv_addr.port().to_string()),
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 2,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            lane_hunt: LaneHuntConfig {
                enabled: true,
                probes: 3,
                max_rounds: 3,
                target_rtt_ms: 90,
                degrade_cooldown_secs: 5,
            },
            telemetry: TelemetryConfig {
                status_file: Some(c_status),
                status_http: None,
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(c_stop),
        });
    });

    // 在发送任何本地应用流量之前，等待启动预热抽卡完成（穿越第 1 轮慢道 -> 第 2 轮抽中高速信道并完成 DTLS 1.3）
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut prewarm_port = 0u16;
    while Instant::now() < deadline {
        if let Some(j) = read_json_file(&status_file) {
            let active = j["sessions"]["active"].as_u64().unwrap_or(0);
            let up_sport = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            let hunts = j["events"]["lane_hunts_total"].as_u64().unwrap_or(0);
            if active >= 1 && up_sport != 0 && hunts >= 1 {
                prewarm_port = up_sport;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_ne!(
        prewarm_port, 0,
        "startup pre-warm must establish a Ready session before local app traffic"
    );
    assert!(
        sim.seen_port_count() >= 5,
        "round 1 (3 slow ports) must retry into round 2 (seen={})",
        sim.seen_port_count()
    );
    assert!(
        sim.is_fast_port(prewarm_port),
        "startup pre-warm MUST pick the fast 0ms lane (got port={})",
        prewarm_port
    );

    // 首次发送应用包应直接 0ms 领用已预热的高速端口，而不是重新握手
    let ports_before_app = sim.seen_port_count();
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    app.connect(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port,
    ))
    .unwrap();
    let t0 = Instant::now();
    app.send(b"ADOPT_PREWARM_0MS").unwrap();
    let mut rbuf = [0u8; 512];
    let n = app.recv(&mut rbuf).expect("0ms prewarm adopt echo");
    let first_rtt = t0.elapsed();
    assert_eq!(&rbuf[..n], b"ADOPT_PREWARM_0MS");
    assert!(
        first_rtt < Duration::from_millis(100),
        "adopted pre-warmed fast lane should echo in <100ms (got {:?})",
        first_rtt
    );
    assert_eq!(
        sim.seen_port_count(),
        ports_before_app,
        "adopting pre-warmed session must not open new upstream sockets"
    );

    stop.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(80));
    let _ = std::fs::remove_file(&status_file);
}

#[test]
fn lane_guard_degradation_triggers_zero_ms_mbb_switch_to_fast_lane() {
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let proxy_port = reserve_free_port();
    let client_port = reserve_free_port();
    let psk = b"lane-guard-mbb-switch-test-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));
    let last_backend_port = Arc::new(AtomicU16::new(0));

    // 首轮序号 2 为高速；后续退化重抽时序号 5 为新高速
    let sim = EcmpSimState::new(&[2, 5, 9, 13]);
    let status_file = std::env::temp_dir()
        .join(format!("wc_lane_guard_{}.json", client_port))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&status_file);

    let _b = spawn_backend_echo_recording_port(
        backend_port,
        Arc::clone(&last_backend_port),
        Arc::clone(&stop),
    );
    let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    let s_stop = Arc::clone(&stop);
    let s_psk = psk.clone();
    let _s = thread::spawn(move || {
        let _ = run_server(ServerConfig {
            listen_addr: srv_addr,
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: s_psk,
            stun_scope: None,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(s_stop),
        });
    });
    let _p = spawn_ecmp_proxy(proxy_port, srv_addr, Arc::clone(&sim), Arc::clone(&stop));
    thread::sleep(Duration::from_millis(80));

    let c_stop = Arc::clone(&stop);
    let c_status = status_file.clone();
    let _c = thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port),
            psk,
            stun_scope: Some(srv_addr.port().to_string()),
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 1,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            lane_hunt: LaneHuntConfig {
                enabled: true,
                probes: 3,
                max_rounds: 3,
                target_rtt_ms: 90,
                degrade_cooldown_secs: 5,
            },
            telemetry: TelemetryConfig {
                status_file: Some(c_status),
                status_http: None,
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(c_stop),
        });
    });

    // 等待预热完成并建立首条高速连接
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut initial_port = 0u16;
    while Instant::now() < deadline {
        if let Some(j) = read_json_file(&status_file) {
            let active = j["sessions"]["active"].as_u64().unwrap_or(0);
            let sp = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            if active >= 1 && sp != 0 {
                initial_port = sp;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(sim.is_fast_port(initial_port));

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    app.connect(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port,
    ))
    .unwrap();
    let mut rbuf = [0u8; 512];
    app.send(b"BEFORE_DEGRADE").unwrap();
    let n = app.recv(&mut rbuf).unwrap();
    assert_eq!(&rbuf[..n], b"BEFORE_DEGRADE");
    let backend_sport_before = last_backend_port.load(Ordering::Relaxed);
    assert_ne!(backend_sport_before, 0);

    // 注入退化：让当前活跃端口突变为 230ms 慢速绕路，等待冷却期 + 3 次 STUN 保活触发 0ms MBB 重抽切换
    sim.degraded_port.store(initial_port, Ordering::SeqCst);

    let switch_deadline = Instant::now() + Duration::from_secs(12);
    let mut new_port = 0u16;
    let mut seq = 0u32;
    while Instant::now() < switch_deadline {
        let msg = format!("KEEP_ACTIVE_{}", seq);
        seq += 1;
        let _ = app.send(msg.as_bytes());
        if let Ok(rn) = app.recv(&mut rbuf) {
            assert_eq!(&rbuf[..rn], msg.as_bytes());
        }
        if let Some(j) = read_json_file(&status_file) {
            let sp = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            let switches = j["events"]["lane_switches_total"].as_u64().unwrap_or(0);
            let mbb = j["events"]["mbb_rotations_total"].as_u64().unwrap_or(0);
            if sp != 0 && sp != initial_port && switches >= 1 && mbb >= 1 {
                new_port = sp;
                break;
            }
        }
        thread::sleep(Duration::from_millis(250));
    }

    assert_ne!(
        new_port, 0,
        "degraded active lane must trigger background MBB lane hunt & switch (initial={})",
        initial_port
    );
    assert!(
        sim.is_fast_port(new_port),
        "switched lane MUST be a fast 0ms port (got {})",
        new_port
    );

    // 验证切到新高速端口后，后端源端口保持 0 变更（0ms MBB 原子交接成功）
    app.send(b"AFTER_LANE_SWITCH").unwrap();
    let n = app.recv(&mut rbuf).unwrap();
    assert_eq!(&rbuf[..n], b"AFTER_LANE_SWITCH");
    assert_eq!(
        last_backend_port.load(Ordering::Relaxed),
        backend_sport_before,
        "MBB lane switch must preserve server backend_lport (zero inner QUIC break!)"
    );

    stop.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(80));
    let _ = std::fs::remove_file(&status_file);
}

#[test]
fn lane_hunt_blackhole_1rtt_migration_picks_fast_lane() {
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let proxy_port = reserve_free_port();
    let client_port = reserve_free_port();
    let psk = b"lane-hunt-1rtt-mig-test-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));
    let last_backend_port = Arc::new(AtomicU16::new(0));

    // 首轮序号 1 为高速；黑洞 1-RTT 竞速（3 候选）中序号 4 为高速，序号 3、5 为慢速
    let sim = EcmpSimState::new(&[1, 4, 8]);
    let status_file = std::env::temp_dir()
        .join(format!("wc_lane_mig_{}.json", client_port))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&status_file);

    let _b = spawn_backend_echo_recording_port(
        backend_port,
        Arc::clone(&last_backend_port),
        Arc::clone(&stop),
    );
    let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    let s_stop = Arc::clone(&stop);
    let s_psk = psk.clone();
    let _s = thread::spawn(move || {
        let _ = run_server(ServerConfig {
            listen_addr: srv_addr,
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: s_psk,
            stun_scope: None,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(s_stop),
        });
    });
    let _p = spawn_ecmp_proxy(proxy_port, srv_addr, Arc::clone(&sim), Arc::clone(&stop));
    thread::sleep(Duration::from_millis(80));

    let c_stop = Arc::clone(&stop);
    let c_status = status_file.clone();
    let _c = thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port),
            psk,
            stun_scope: Some(srv_addr.port().to_string()),
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 1,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            lane_hunt: LaneHuntConfig {
                enabled: true,
                probes: 3,
                max_rounds: 2,
                target_rtt_ms: 90,
                degrade_cooldown_secs: 5,
            },
            telemetry: TelemetryConfig {
                status_file: Some(c_status),
                status_http: None,
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(c_stop),
        });
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut initial_port = 0u16;
    while Instant::now() < deadline {
        if let Some(j) = read_json_file(&status_file) {
            let active = j["sessions"]["active"].as_u64().unwrap_or(0);
            let sp = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            if active >= 1 && sp != 0 {
                initial_port = sp;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(sim.is_fast_port(initial_port));

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    app.connect(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port,
    ))
    .unwrap();
    let mut rbuf = [0u8; 512];
    app.send(b"BEFORE_BH").unwrap();
    let n = app.recv(&mut rbuf).unwrap();
    assert_eq!(&rbuf[..n], b"BEFORE_BH");
    let backend_sport_before = last_backend_port.load(Ordering::Relaxed);

    // 注入当前活跃端口 100% 黑洞 -> 触发 RFC 7675 同意超时 + 1-RTT 多候选竞速迁移
    sim.blackholed_port.store(initial_port, Ordering::SeqCst);

    let mig_deadline = Instant::now() + Duration::from_secs(12);
    let mut migrated_port = 0u16;
    while Instant::now() < mig_deadline {
        let _ = app.send(b"PROBE_AFTER_BH");
        let _ = app.recv(&mut rbuf);
        if let Some(j) = read_json_file(&status_file) {
            let sp = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            let migs = j["events"]["migrations_1rtt_total"].as_u64().unwrap_or(0);
            if sp != 0 && sp != initial_port && migs >= 1 {
                migrated_port = sp;
                break;
            }
        }
        thread::sleep(Duration::from_millis(200));
    }

    assert_ne!(migrated_port, 0, "blackhole must trigger 1-RTT migration");
    assert!(
        sim.is_fast_port(migrated_port),
        "1-RTT migration race MUST pick the fast 0ms candidate (got {})",
        migrated_port
    );

    app.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    app.send(b"AFTER_1RTT_MIG").unwrap();
    let n = app.recv(&mut rbuf).unwrap();
    assert_eq!(&rbuf[..n], b"AFTER_1RTT_MIG");
    assert_eq!(
        last_backend_port.load(Ordering::Relaxed),
        backend_sport_before,
        "1-RTT lane migration must preserve server backend_lport"
    );

    stop.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(80));
    let _ = std::fs::remove_file(&status_file);
}

#[test]
fn lane_score_scale_invariant_and_loss_sensitive() {
    // 1. 跨地域 10ms / 40ms / 150ms / 250ms 基线在最优零丢包下均为满分 100
    for base in [10.0, 40.0, 150.0, 250.0] {
        let ideal = compute_lane_score(base, base, 0.0, 0.0);
        assert!(
            (ideal - 100.0).abs() < 1e-6,
            "ideal score at {}ms must be 100 (got {})",
            base,
            ideal
        );
        // 正常 ±12% 小幅波动 + 1% 偶发丢包仍保持健康（远高于 55 退化线）
        let healthy = compute_lane_score(base * 1.12, base, 0.01, base * 0.05);
        assert!(
            healthy > 75.0,
            "healthy variation at {}ms should score >75 (got {})",
            base,
            healthy
        );
    }

    // 2. 低延迟假优信道（RTT 与基线齐平，但满载数据面丢包 8% 及以上）必须立即被判退化 (< 55)，无 8%~10.2% 死角
    let fake_good_8pct = compute_lane_score(40.0, 40.0, 0.08, 0.0);
    assert!(
        fake_good_8pct < LANE_DEGRADE_SCORE_THRESHOLD,
        "low-RTT 8%-loss lane must degrade below {} (got {})",
        LANE_DEGRADE_SCORE_THRESHOLD,
        fake_good_8pct
    );
    let fake_good_15pct = compute_lane_score(42.0, 40.0, 0.15, 2.0);
    assert!(
        fake_good_15pct < LANE_DEGRADE_SCORE_THRESHOLD,
        "low-RTT 15%-loss lane must degrade below {} (got {})",
        LANE_DEGRADE_SCORE_THRESHOLD,
        fake_good_15pct
    );

    // 3. 跨洲 150ms 链路绕路至 290ms（零丢包）必须判退化，而 175ms 正常波动不误判
    assert!(compute_lane_score(290.0, 150.0, 0.0, 5.0) < LANE_DEGRADE_SCORE_THRESHOLD);
    assert!(compute_lane_score(175.0, 150.0, 0.0, 5.0) > 75.0);

    // 4. 迟滞一致性校验：全地域基线下自动抽卡达标线 (max(1.40*b, b+20)) 严格低于无丢包退化线 (score < 55)
    for base in [5.0f64, 15.0, 40.0, 150.0, 250.0] {
        let auto_target = (base * 1.40).max(base + 20.0);
        let score_at_target = compute_lane_score(auto_target, base, 0.0, 0.0);
        assert!(
            score_at_target > LANE_DEGRADE_SCORE_THRESHOLD,
            "auto_target ({:.1}ms) at base={:.1}ms must score above degrade line (got {:.1}) to prevent trap-band loops",
            auto_target,
            base,
            score_at_target
        );
    }
}

#[test]
fn lane_hunt_auto_cold_start_multiround_calibration_without_target_rtt() {
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let proxy_port = reserve_free_port();
    let client_port = reserve_free_port();
    let psk = b"lane-hunt-auto-cold-cal-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));
    let last_backend_port = Arc::new(AtomicU16::new(0));

    // 纯自动模式（target_rtt_ms = 0）：第 1 轮 3 个端口 (0,1,2) 全是 220ms 慢道，
    // 第 2 轮序号 4 是 0ms 高速道 -> 必须自动跨轮校准选出全局最低延迟信道，不写死任何 ms 阈值！
    let sim = EcmpSimState::new(&[4, 8]);
    let status_file = std::env::temp_dir()
        .join(format!("wc_lane_auto_cal_{}.json", client_port))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&status_file);

    let _b = spawn_backend_echo_recording_port(
        backend_port,
        Arc::clone(&last_backend_port),
        Arc::clone(&stop),
    );
    let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    let s_stop = Arc::clone(&stop);
    let s_psk = psk.clone();
    let _s = thread::spawn(move || {
        let _ = run_server(ServerConfig {
            listen_addr: srv_addr,
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: s_psk,
            stun_scope: None,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(s_stop),
        });
    });
    let _p = spawn_ecmp_proxy(proxy_port, srv_addr, Arc::clone(&sim), Arc::clone(&stop));
    thread::sleep(Duration::from_millis(80));

    let c_stop = Arc::clone(&stop);
    let c_status = status_file.clone();
    let _c = thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port),
            psk,
            stun_scope: Some(srv_addr.port().to_string()),
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 2,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            lane_hunt: LaneHuntConfig {
                enabled: true,
                probes: 3,
                max_rounds: 3,
                target_rtt_ms: 0, // 纯自适应通用模式！
                degrade_cooldown_secs: 5,
            },
            telemetry: TelemetryConfig {
                status_file: Some(c_status),
                status_http: None,
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(c_stop),
        });
    });

    let deadline = Instant::now() + Duration::from_secs(6);
    let mut prewarm_port = 0u16;
    let mut best_rtt_reported = 999.0f64;
    while Instant::now() < deadline {
        if let Some(j) = read_json_file(&status_file) {
            let active = j["sessions"]["active"].as_u64().unwrap_or(0);
            let up_sport = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            let hunts = j["events"]["lane_hunts_total"].as_u64().unwrap_or(0);
            if active >= 1 && up_sport != 0 && hunts >= 1 {
                prewarm_port = up_sport;
                best_rtt_reported = j["link"]["lane_best_rtt_ms"].as_f64().unwrap_or(999.0);
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_ne!(
        prewarm_port, 0,
        "auto cold-start calibration must establish a Ready pre-warm session"
    );
    assert!(
        sim.seen_port_count() >= 6,
        "auto cold-start calibration must probe at least 2 rounds (seen={})",
        sim.seen_port_count()
    );
    assert!(
        sim.is_fast_port(prewarm_port),
        "auto cold-start calibration MUST pick global minimum fast port (got {})",
        prewarm_port
    );
    assert!(
        best_rtt_reported < 50.0,
        "calibrated lane_best_rtt_ms must reflect fast tier (got {:.1}ms)",
        best_rtt_reported
    );

    stop.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(80));
    let _ = std::fs::remove_file(&status_file);
}

#[test]
fn lane_guard_data_plane_packet_loss_triggers_zero_ms_mbb_escape() {
    let backend_port = reserve_free_port();
    let server_port = reserve_free_port();
    let proxy_port = reserve_free_port();
    let client_port = reserve_free_port();
    let psk = b"lane-guard-data-loss-mbb-psk".to_vec();
    let stop = Arc::new(AtomicBool::new(false));
    let last_backend_port = Arc::new(AtomicU16::new(0));

    // 所有候选端口延迟均为 0ms（模拟「延迟全低但某条 ECMP 信道被 QoS 丢包 25%」的假优场景）
    let sim = EcmpSimState::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let status_file = std::env::temp_dir()
        .join(format!("wc_lane_dataloss_{}.json", client_port))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&status_file);

    let _b = spawn_backend_echo_recording_port(
        backend_port,
        Arc::clone(&last_backend_port),
        Arc::clone(&stop),
    );
    let srv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    let s_stop = Arc::clone(&stop);
    let s_psk = psk.clone();
    let _s = thread::spawn(move || {
        let _ = run_server(ServerConfig {
            listen_addr: srv_addr,
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            psk: s_psk,
            stun_scope: None,
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            wire_audit_file: None,
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(s_stop),
        });
    });
    let _p = spawn_ecmp_proxy(proxy_port, srv_addr, Arc::clone(&sim), Arc::clone(&stop));
    thread::sleep(Duration::from_millis(80));

    let c_stop = Arc::clone(&stop);
    let c_status = status_file.clone();
    let _c = thread::spawn(move || {
        let _ = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port),
            psk,
            stun_scope: Some(srv_addr.port().to_string()),
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
            udp_batch: 0,
            retry_ms: 150,
            max_retries: 8,
            keepalive_secs: 1,
            idle_timeout_secs: 60,
            stats_interval_secs: 3600,
            lane_hunt: LaneHuntConfig {
                enabled: true,
                probes: 3,
                max_rounds: 2,
                target_rtt_ms: 0, // 纯自适应多维评分模式！
                degrade_cooldown_secs: 5,
            },
            telemetry: TelemetryConfig {
                status_file: Some(c_status),
                status_http: None,
                status_interval_secs: 1,
            },
            quiet: true,
            stop: Some(c_stop),
        });
    });

    // 等待预热完成
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut initial_port = 0u16;
    while Instant::now() < deadline {
        if let Some(j) = read_json_file(&status_file) {
            let active = j["sessions"]["active"].as_u64().unwrap_or(0);
            let sp = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            if active >= 1 && sp != 0 {
                initial_port = sp;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_ne!(initial_port, 0);

    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_nonblocking(true).unwrap();
    app.connect(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port,
    ))
    .unwrap();
    let payload = vec![0x5Au8; 420]; // >=400B 确保走 Video SSRC 稳定触发已稳定丢包统计
    let mut rbuf = [0u8; 1024];

    // 先建立活跃映射并记录初始后端源端口
    let first_deadline = Instant::now() + Duration::from_secs(3);
    while last_backend_port.load(Ordering::Relaxed) == 0 && Instant::now() < first_deadline {
        let _ = app.send(&payload);
        thread::sleep(Duration::from_millis(30));
        while app.recv(&mut rbuf).is_ok() {}
    }
    let backend_sport_before = last_backend_port.load(Ordering::Relaxed);
    assert_ne!(backend_sport_before, 0);

    // 注入「STUN 0ms 零丢包但下行 SRTP 数据面 25% 丢包」的假优信道故障！
    sim.lossy_data_port.store(initial_port, Ordering::SeqCst);

    let switch_deadline = Instant::now() + Duration::from_secs(14);
    let mut new_port = 0u16;
    while Instant::now() < switch_deadline {
        // 持续产生业务数据面流量（每次循环发 8 个 420B 包），让数据面丢包计分实时生效
        for _ in 0..8 {
            let _ = app.send(&payload);
        }
        while app.recv(&mut rbuf).is_ok() {}
        if let Some(j) = read_json_file(&status_file) {
            let sp = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            let switches = j["events"]["lane_switches_total"].as_u64().unwrap_or(0);
            let mbb = j["events"]["mbb_rotations_total"].as_u64().unwrap_or(0);
            if sp != 0 && sp != initial_port && switches >= 1 && mbb >= 1 {
                new_port = sp;
                break;
            }
        }
        thread::sleep(Duration::from_millis(60));
    }
    assert_ne!(
        new_port, 0,
        "25% data-plane SRTP packet loss (even with 0ms STUN RTT!) MUST trigger 0ms MBB escape from port {}",
        initial_port
    );

    // 切换到新干净信道后继续发流，验证 0ms 后端端口无变且新信道通过试用确认（lane_confirmed=true, data_loss<2%）
    let confirm_deadline = Instant::now() + Duration::from_secs(6);
    let mut confirmed = false;
    let mut final_loss = 100.0;
    let mut final_score = 0.0;
    while Instant::now() < confirm_deadline {
        for _ in 0..8 {
            let _ = app.send(&payload);
        }
        while app.recv(&mut rbuf).is_ok() {}
        if let Some(j) = read_json_file(&status_file) {
            let sp = j["sessions"]["up_sport"].as_u64().unwrap_or(0) as u16;
            let c = j["link"]["lane_confirmed"].as_bool().unwrap_or(false);
            let dl = j["link"]["data_loss_pct"].as_f64().unwrap_or(100.0);
            let sc = j["link"]["lane_score"].as_f64().unwrap_or(0.0);
            if sp == new_port && c && dl < 2.0 && sc >= 70.0 {
                confirmed = true;
                final_loss = dl;
                final_score = sc;
                break;
            }
        }
        thread::sleep(Duration::from_millis(80));
    }
    assert!(
        confirmed,
        "new clean lane {} must pass canary confirmation (loss={:.1}%, score={:.1})",
        new_port, final_loss, final_score
    );
    assert_eq!(
        last_backend_port.load(Ordering::Relaxed),
        backend_sport_before,
        "data-loss MBB escape must preserve server backend_lport (0ms QUIC continuity)"
    );

    stop.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(80));
    let _ = std::fs::remove_file(&status_file);
}
