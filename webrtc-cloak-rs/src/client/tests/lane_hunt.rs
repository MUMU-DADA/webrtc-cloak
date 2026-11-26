//! IPv6 端到端隧道与 ECMP 信道抽卡探测（启动预热/多轮重抽/退化 0ms MBB/黑洞 1-RTT 竞速）集成测试。

use super::reserve_free_port;
use crate::client::{run_client, ClientConfig, LaneHuntConfig};
use crate::protocol::{CipherPref, DtlsMinVersion};
use crate::server::{run_server, ServerConfig};
use crate::telemetry::TelemetryConfig;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
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
}

impl EcmpSimState {
    fn new(fast_indices: &[usize]) -> Arc<Self> {
        Arc::new(Self {
            port_oneway_delay_ms: Mutex::new(HashMap::new()),
            fast_ports: Mutex::new(HashSet::new()),
            fast_indices: fast_indices.iter().copied().collect(),
            degraded_port: AtomicU16::new(0),
            blackholed_port: AtomicU16::new(0),
        })
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
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 16,
            wan_mtu: 1488,
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
    let _c = thread::spawn(move || {
        if let Err(e) = run_client(ClientConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port),
            server_addr: srv_addr,
            psk,
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 16,
            wan_mtu: 1488,
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
            telemetry: TelemetryConfig::default(),
            quiet: true,
            stop: Some(c_stop),
        }) {
            eprintln!("ipv6 test client error: {}", e);
        }
    });
    thread::sleep(Duration::from_millis(400));

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
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
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
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
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
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
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
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
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
            cipher_pref: CipherPref::Auto,
            dtls_required: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
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
            cipher_pref: CipherPref::Auto,
            dtls_decoy: true,
            dtls_min_version: DtlsMinVersion::V13Only,
            rotate_interval_secs: 0,
            rotate_max_bytes: 0,
            rotate_cooldown_secs: 60,
            workers: 1,
            max_sessions: 32,
            wan_mtu: 1488,
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
