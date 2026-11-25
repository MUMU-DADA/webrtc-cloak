//! 远端现网 SRTP 带内回显、路径 MTU、五元组轮换与主动探测防御测试。

use super::remote_session::{
    remote_dtls_handshake, remote_stun_handshake, send_probe_expect_silence_ms, LiveReadySession,
};
use super::{percentile, Highlights, ScenarioResult, ScenarioStatus, SelftestOptions};
use crate::constants::{
    DTLS_CT_HANDSHAKE, DTLS_HS_CLIENT_HELLO, DTLS_VER_MAJOR, DTLS_VER_MINOR_12, IPV4_UDP_HDR_LEN,
    PROBE_IO_BUF_LEN, SRTP_DATA_MIN_WIRE_LEN, STUN_HDR_LEN,
};
use crate::protocol::{
    build_ice_stun_request, demux_rfc7983, fill_random, PacketKind, SessionIceParams, SrtpFrame,
};
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, SocketAddrV4};
use std::thread;
use std::time::{Duration, Instant};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_remote_steps_06_to_09(
    opts: &SelftestOptions,
    server_addr: SocketAddr,
    psk: &[u8],
    dyn_timeout_ms: u64,
    stun_rtt_ms: f64,
    captured_stun: Vec<u8>,
    mapped1: Option<SocketAddrV4>,
    sess_opt: &mut Option<LiveReadySession>,
    hi: &mut Highlights,
    results: &mut Vec<ScenarioResult>,
    report_step: &dyn Fn(usize, &str, &ScenarioResult),
) {
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
            let mut wbuf = [0u8; PROBE_IO_BUF_LEN];
            let mut rbuf = [0u8; PROBE_IO_BUF_LEN];
            let mut pbuf = [0u8; PROBE_IO_BUF_LEN];
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
                                                rtts_ms
                                                    .push(t_send.elapsed().as_secs_f64() * 1000.0);
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
                            PacketKind::Srtcp if sess.cipher.verify_srtcp(pkt).is_some() => {
                                sess.dl_srtcp_verified += 1;
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
                        PacketKind::Srtcp if sess.cipher.verify_srtcp(pkt).is_some() => {
                            sess.dl_srtcp_verified += 1;
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
            let max_wire_allowed = opts.wan_mtu.saturating_sub(IPV4_UDP_HDR_LEN);
            let exact_edge = max_wire_allowed.saturating_sub(SRTP_DATA_MIN_WIRE_LEN); // 1422B for WAN MTU 1488
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
            let mut tmp_buf = [0u8; PROBE_IO_BUF_LEN];
            let guard_dropped = sess
                .cipher
                .wrap_probe_into(&oversize_payload, &mut tmp_buf)
                .is_none();

            let ipv4_mtu_verified = if max_udp_pass > 0 {
                max_udp_pass + SRTP_DATA_MIN_WIRE_LEN + IPV4_UDP_HDR_LEN
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
                detail: format!(
                    "probes=[{}] max_wire={}B",
                    size_notes.join(" "),
                    max_wire_seen
                ),
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
        forged_dtls[0] = DTLS_CT_HANDSHAKE;
        forged_dtls[1] = DTLS_VER_MAJOR;
        forged_dtls[2] = DTLS_VER_MINOR_12;
        forged_dtls[12] = 51;
        forged_dtls[13] = DTLS_HS_CLIENT_HELLO;

        let (wrong_psk_stun, _) = build_ice_stun_request(b"wrong-attacker-psk", &ice, None, true);

        let (mut tampered_mi_stun, _) = build_ice_stun_request(psk, &ice, None, true);
        let mi_idx = tampered_mi_stun.len().saturating_sub(14);
        tampered_mi_stun[mi_idx] ^= 0x01;

        let (mut smuggled_stun, _) = build_ice_stun_request(psk, &ice, None, true);
        smuggled_stun.extend_from_slice(&[0x80, 0x22, 0x00, 0x04, b'E', b'V', b'I', b'L']);
        let new_len = (smuggled_stun.len() - STUN_HDR_LEN) as u16;
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
}
