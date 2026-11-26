//! 客户端 DTLS 握手驱动、优雅关闭与上游会话创建。

use super::lane_hunt::client_outer_hdr_len;
use super::{
    alloc_token, log, make_udp_socket, record_client_media_bytes, schedule_mbb_timers,
    ClientConfig, ClientSession, HandshakeState, CLIENT_SRTCP_INIT_MAX_MS,
    CLIENT_SRTCP_INIT_MIN_MS, MAX_DRAINING_SESSIONS, SOCK_BUF_2MIB, TRICKLE_WINDOW_5MIN_SECS,
};
use crate::constants::{
    unspecified_addr_for, DTLS_CT_HANDSHAKE, DTLS_HS_CLIENT_HELLO, DTLS_PLAINTEXT_HDR_LEN,
    TRICKLE_WINDOW_15S_SECS,
};
use crate::protocol::{
    build_ice_stun_request, combine_session_key, derive_ice_migration_key, derive_stun_material,
    jitter_duration_ms, make_fresh_stun_txid, new_dtls_instance, rand_duration_range_ms,
    resolve_srtp_suite, CertCache, CpuAccelInfo, DtlsConfigPool, RollingByteWindow,
    SessionIceParams, SrtpCloakCipher,
};
use dimpl::{Output as DtlsOutput, ProtocolVersion};
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Interest, Poll, Token};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[allow(clippy::too_many_arguments)]
pub(super) fn drain_client_dtls(
    worker_id: usize,
    sess: &mut ClientSession,
    dtls_buf: &mut Vec<u8>,
    wbuf: &mut [u8],
    cfg: &ClientConfig,
    cpu: &crate::protocol::CpuAccelInfo,
    now: Instant,
    candidate_sh_suite: Option<u16>,
) -> bool {
    if sess.dtls_suite_id.is_none() && sess.pending_sh_suite.is_none() {
        if let Some(cs) = candidate_sh_suite {
            sess.pending_sh_suite = Some(cs);
        }
    }
    let mut emitted_client_hello = false;
    let mut emitted_flight5_or_later = false;
    let mut connected_now = false;
    let mut peer_closed = false;

    if let Some(ref mut dtls) = sess.dtls {
        loop {
            match dtls.poll_output(dtls_buf) {
                DtlsOutput::Packet(p) => {
                    if p.len() > DTLS_PLAINTEXT_HDR_LEN
                        && p[0] == DTLS_CT_HANDSHAKE
                        && p[DTLS_PLAINTEXT_HDR_LEN] == DTLS_HS_CLIENT_HELLO
                    {
                        emitted_client_hello = true;
                    } else {
                        emitted_flight5_or_later = true;
                    }
                    let _ = sess.upstream.send(p);
                }
                DtlsOutput::BufferTooSmall { needed } => {
                    dtls_buf.resize(needed, 0);
                }
                DtlsOutput::Timeout(t) => {
                    sess.dtls_next_timeout = Some(t);
                    break;
                }
                DtlsOutput::KeyingMaterial(km, _profile) => {
                    sess.dtls_km = Some(km.to_vec());
                }
                DtlsOutput::Connected => {
                    connected_now = true;
                }
                DtlsOutput::CloseNotify => {
                    peer_closed = true;
                }
                _ => {}
            }
        }
    }

    // V3-H-05 fix: clear any pre-HVR spoofed ServerHello when re-sending ClientHello,
    // and lock ServerHello cipher suite only once dimpl emits Flight 5+ or reaches Connected!
    if emitted_client_hello && !emitted_flight5_or_later && !connected_now {
        sess.pending_sh_suite = None;
    } else if sess.dtls_suite_id.is_none() && (emitted_flight5_or_later || connected_now) {
        if let Some(cs) = sess.pending_sh_suite.take() {
            sess.dtls_suite_id = Some(cs);
        }
    }

    if connected_now && sess.state == HandshakeState::DtlsHandshake {
        if let Some(stun_key) = sess.stun_key {
            let Some(mut km) = sess.dtls_km.take().filter(|k| !k.is_empty()) else {
                log(
                    worker_id,
                    &format!(
                        "DTLS Connected without SRTP KeyingMaterial up_sport={} (Fail-Closed!)",
                        sess.local_port
                    ),
                );
                return true;
            };
            let is_dtls13 = sess.dtls.as_ref().and_then(|d| d.protocol_version())
                == Some(ProtocolVersion::DTLS1_3);
            let chosen = resolve_srtp_suite(cfg.cipher_pref, sess.dtls_suite_id, cpu, false);
            let final_key = combine_session_key(&stun_key, Some(&km));
            km.fill(0);
            drop(km);
            sess.cached_initial_stun = Vec::new();
            sess.session_key = Some(final_key);
            sess.mi_key_mig = Some(derive_ice_migration_key(&final_key));
            sess.active_cipher = Some(chosen);
            let mut c =
                SrtpCloakCipher::new(&final_key, sess.ssrc_c2s, sess.ssrc_s2c, true, chosen);
            c.set_wan_mtu_for(cfg.wan_mtu, client_outer_hdr_len(cfg.server_addr));
            c.set_dual_ssrc(is_dtls13);
            sess.cipher = Some(c);
            sess.state = HandshakeState::Ready;
            sess.ready_at = Some(now);
            sess.last_data_active = now;
            sess.last_active_burst = now;
            sess.rate_15s =
                RollingByteWindow::new(now, Duration::from_secs(TRICKLE_WINDOW_15S_SECS));
            sess.rate_5min =
                RollingByteWindow::new(now, Duration::from_secs(TRICKLE_WINDOW_5MIN_SECS));
            sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
            sess.ka_txid = None;
            sess.ka_pkt.clear();
            sess.ka_retries = 0;
            sess.ka_rto_at = None;
            sess.next_keepalive_at = now + jitter_duration_ms(cfg.keepalive_secs * 1000);
            sess.next_srtcp_at =
                now + rand_duration_range_ms(CLIENT_SRTCP_INIT_MIN_MS, CLIENT_SRTCP_INIT_MAX_MS);
            schedule_mbb_timers(sess, cfg, now);

            let mut flushed = 0usize;
            let mut flushed_bytes = 0u64;
            sess.pending_bytes = 0;
            if let Some(ref mut cipher) = sess.cipher {
                while let Some(raw) = sess.pending.pop_front() {
                    if let Some(wn) = cipher.wrap_into(&raw, wbuf) {
                        if sess.upstream.send(&wbuf[..wn]).is_ok() {
                            sess.tx_pkts += 1;
                            sess.tx_bytes += raw.len() as u64;
                            flushed_bytes = flushed_bytes.saturating_add(raw.len() as u64);
                            flushed += 1;
                        }
                    }
                }
            }
            sess.pending.shrink_to_fit();
            if flushed_bytes > 0 {
                record_client_media_bytes(sess, cfg, cfg.keepalive_secs * 1000, now, flushed_bytes);
            }
            let total_ms = sess.created_at.elapsed().as_secs_f64() * 1000.0;
            log(
                worker_id,
                &format!(
                    "DTLS {} (dimpl mutual-cert PFS) OK -> READY{} up_sport={} cipher={} dual_ssrc={} total_hs={:.2}ms flushed={}",
                    if is_dtls13 { "1.3" } else { "1.2" },
                    if sess.is_prewarm { " (pre-warmed)" } else { "" },
                    sess.local_port,
                    chosen.name(),
                    is_dtls13,
                    total_ms,
                    flushed
                ),
            );
        }
    }

    peer_closed
}

pub(super) fn graceful_teardown_client(sess: &mut ClientSession, dtls_buf: &mut Vec<u8>) {
    if matches!(
        sess.state,
        HandshakeState::Ready | HandshakeState::HandoverWait | HandshakeState::DrainingBeforeBye(_)
    ) {
        let has_rx = sess.rx_pkts > sess.rx_pkts_at_last_rtcp;
        let is_sender = sess.tx_pkts > sess.tx_pkts_at_last_rtcp;
        if let Some(ref mut cipher) = sess.cipher {
            let bye = cipher.build_srtcp(has_rx, is_sender, true);
            let _ = sess.upstream.send(&bye);
        }
        if let Some(ref mut dtls) = sess.dtls {
            if dtls.close().is_ok() {
                loop {
                    match dtls.poll_output(dtls_buf) {
                        DtlsOutput::Packet(p) => {
                            let _ = sess.upstream.send(p);
                        }
                        DtlsOutput::BufferTooSmall { needed } => dtls_buf.resize(needed, 0),
                        DtlsOutput::Timeout(_) => break,
                        _ => {}
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_client_session(
    worker_id: usize,
    client_addr: SocketAddr,
    cfg: &ClientConfig,
    poll: &mut Poll,
    sessions_by_token: &mut HashMap<Token, ClientSession>,
    token_by_client: &mut HashMap<SocketAddr, Token>,
    standby_by_client: &mut HashMap<SocketAddr, Token>,
    next_token_id: &mut usize,
    dtls_buf: &mut Vec<u8>,
    now: Instant,
    retry_dur: Duration,
    ka_base_ms: u64,
    idle_dur: Duration,
    ka_max_retries: u8,
    standby_for_primary: Option<Token>,
) -> Option<Token> {
    let is_standby = standby_for_primary.is_some();
    // Bound silent receive-only draining sockets so prolonged blackholes cannot leak FDs.
    let mut draining: Vec<(Token, Instant)> = sessions_by_token
        .iter()
        .filter_map(|(&t, s)| match s.state {
            HandshakeState::Closing(deadline) => Some((t, deadline)),
            _ => None,
        })
        .collect();
    if draining.len() >= MAX_DRAINING_SESSIONS {
        draining.sort_by_key(|&(_, d)| d);
        let to_evict = draining.len() - MAX_DRAINING_SESSIONS + 1;
        for (t, _) in draining.into_iter().take(to_evict) {
            if let Some(mut old) = sessions_by_token.remove(&t) {
                let _ = poll.registry().deregister(&mut old.upstream);
                if token_by_client.get(&old.client_addr) == Some(&t) {
                    token_by_client.remove(&old.client_addr);
                }
                if standby_by_client.get(&old.client_addr) == Some(&t) {
                    standby_by_client.remove(&old.client_addr);
                    if let Some(pt) = old.standby_for_primary {
                        if let Some(prim) = sessions_by_token.get_mut(&pt) {
                            prim.standby_spawned = false;
                        }
                    }
                }
            }
        }
    }

    if sessions_by_token.len() >= cfg.max_sessions {
        let expired: Vec<Token> = sessions_by_token
            .iter()
            .filter(|(_, s)| {
                matches!(
                    s.state,
                    HandshakeState::Closing(_) | HandshakeState::DrainingBeforeBye(_)
                ) || now.duration_since(s.last_data_active) > idle_dur
            })
            .map(|(&t, _)| t)
            .collect();
        for t in expired {
            if let Some(mut s) = sessions_by_token.remove(&t) {
                graceful_teardown_client(&mut s, dtls_buf);
                let _ = poll.registry().deregister(&mut s.upstream);
                if token_by_client.get(&s.client_addr) == Some(&t) {
                    token_by_client.remove(&s.client_addr);
                }
                if standby_by_client.get(&s.client_addr) == Some(&t) {
                    standby_by_client.remove(&s.client_addr);
                    if let Some(pt) = s.standby_for_primary {
                        if let Some(prim) = sessions_by_token.get_mut(&pt) {
                            prim.standby_spawned = false;
                        }
                    }
                }
            }
        }
        if sessions_by_token.len() >= cfg.max_sessions {
            log(
                worker_id,
                &format!(
                    "max_sessions={} reached, dropping new client {}",
                    cfg.max_sessions, client_addr
                ),
            );
            return None;
        }
    }

    let bind_any = unspecified_addr_for(cfg.server_addr);
    let mut up = match make_udp_socket(bind_any, Some(cfg.server_addr), false, SOCK_BUF_2MIB) {
        Ok(s) => s,
        Err(e) => {
            log(worker_id, &format!("upstream socket error: {}", e));
            return None;
        }
    };
    let local_port = up.local_addr().map(|a| a.port()).unwrap_or(0);
    let tok = alloc_token(next_token_id);
    if poll
        .registry()
        .register(&mut up, tok, Interest::READABLE)
        .is_err()
    {
        return None;
    }
    let ice = SessionIceParams::generate();
    let stun_txid = make_fresh_stun_txid(&cfg.psk);
    let (stun_pkt, _) = build_ice_stun_request(&cfg.psk, &ice, Some(stun_txid), true);
    let _ = up.send(&stun_pkt);

    log(
        worker_id,
        &format!(
            "new {}session client={} -> up_sport={} target={} ufrag={}",
            if is_standby { "standby(MBB) " } else { "" },
            client_addr,
            local_port,
            cfg.server_addr,
            ice.username()
        ),
    );

    let sess = ClientSession {
        client_addr,
        upstream: up,
        local_port,
        ice,
        stun_txid,
        cached_initial_stun: stun_pkt,
        state: HandshakeState::StunWait,
        created_at: now,
        ready_at: None,
        last_data_active: now,
        last_active_burst: now,
        next_retry_at: now + retry_dur,
        next_keepalive_at: now + jitter_duration_ms(ka_base_ms),
        next_srtcp_at: now
            + rand_duration_range_ms(CLIENT_SRTCP_INIT_MIN_MS, CLIENT_SRTCP_INIT_MAX_MS),
        dtls_next_timeout: None,
        is_standby,
        is_prewarm: false,
        next_keepwarm_at: None,
        lane_rtt_ewma_ms: None,
        lane_rtt_last_ms: None,
        lane_jitter_ms: 0.0,
        lane_data_loss_rate: 0.0,
        lane_prev_settled_exp: 0,
        lane_prev_settled_rx: 0,
        lane_last_ka_settled_exp: 0,
        lane_stun_outcomes: VecDeque::new(),
        lane_score: None,
        lane_confirmed: false,
        lane_good_windows: 0,
        lane_subopt_windows: 0,
        lane_degrade_streak: 0,
        next_lane_hunt_at: now,
        standby_for_primary,
        standby_spawned: false,
        rotate_at: None,
        hard_rotate_at: None,
        rotate_byte_budget: None,
        rate_15s: RollingByteWindow::new(now, Duration::from_secs(TRICKLE_WINDOW_15S_SECS)),
        rate_5min: RollingByteWindow::new(now, Duration::from_secs(TRICKLE_WINDOW_5MIN_SECS)),
        retries: 0,
        ka_txid: None,
        ka_pkt: Vec::new(),
        ka_retries: 0,
        ka_max_retries,
        ka_rto_at: None,
        ka_sent_at: None,
        mig_txid: None,
        mig_retries: 0,
        mig_retry_at: None,
        mig_echo_payload: None,
        mig_echo_next_at: None,
        mig_echo_left: 0,
        handover_payload: None,
        handover_retries: 0,
        handover_retry_at: None,
        stun_key: None,
        session_key: None,
        mi_key_mig: None,
        ssrc_c2s: 0,
        ssrc_s2c: 0,
        dtls: None,
        dtls_resets: 0,
        pending_sh_suite: None,
        dtls_suite_id: None,
        dtls_km: None,
        active_cipher: None,
        cipher: None,
        pending: VecDeque::new(),
        pending_bytes: 0,
        tx_pkts: 0,
        tx_pkts_at_last_rtcp: 0,
        tx_bytes: 0,
        rx_pkts: 0,
        rx_pkts_at_last_rtcp: 0,
        rx_bytes: 0,
        keepalives_ok: 0,
        srtcp_tx: 0,
        srtcp_rx: 0,
        auth_drops: 0,
    };
    if is_standby {
        standby_by_client.insert(client_addr, tok);
    } else {
        token_by_client.insert(client_addr, tok);
    }
    sessions_by_token.insert(tok, sess);
    Some(tok)
}

/// 基于已完成 STUN 抽卡测速的优胜候选套接字直接推进至 DTLS 握手（或无 DTLS 时直达 Ready），零额外 STUN RTT。
#[allow(clippy::too_many_arguments)]
pub(super) fn build_session_after_stun(
    worker_id: usize,
    client_addr: SocketAddr,
    upstream: MioUdpSocket,
    local_port: u16,
    ice: SessionIceParams,
    stun_txid: [u8; 12],
    rtt_ms: f64,
    mapped_addr: Option<SocketAddr>,
    cfg: &ClientConfig,
    cert_cache: &mut CertCache,
    dtls_pool: &DtlsConfigPool,
    cpu: &CpuAccelInfo,
    now: Instant,
    retry_dur: Duration,
    ka_base_ms: u64,
    ka_max_retries: u8,
    standby_for_primary: Option<Token>,
    is_prewarm: bool,
    next_keepwarm_at: Option<Instant>,
    initial_lane_cooldown: Duration,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    dtls_buf: &mut Vec<u8>,
    wbuf: &mut [u8],
) -> ClientSession {
    let uname = ice.username();
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(&cfg.psk, &stun_txid, &uname);
    let mapped_s = mapped_addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".into());
    log(
        worker_id,
        &format!(
            "ICE STUN OK (hunted) up_sport={} rtt={:.2}ms mapped={} ssrc_tx=0x{:08x} ssrc_rx=0x{:08x}",
            local_port, rtt_ms, mapped_s, s_c2s, s_s2c
        ),
    );
    let is_standby = standby_for_primary.is_some();

    let mut sess = ClientSession {
        client_addr,
        upstream,
        local_port,
        ice,
        stun_txid,
        cached_initial_stun: Vec::new(),
        state: HandshakeState::StunWait,
        created_at: now,
        ready_at: None,
        last_data_active: now,
        last_active_burst: now,
        next_retry_at: now + retry_dur,
        next_keepalive_at: now + jitter_duration_ms(ka_base_ms),
        next_srtcp_at: now
            + rand_duration_range_ms(CLIENT_SRTCP_INIT_MIN_MS, CLIENT_SRTCP_INIT_MAX_MS),
        dtls_next_timeout: None,
        is_standby,
        is_prewarm,
        next_keepwarm_at,
        lane_rtt_ewma_ms: Some(rtt_ms),
        lane_rtt_last_ms: Some(rtt_ms),
        lane_jitter_ms: 0.0,
        lane_data_loss_rate: 0.0,
        lane_prev_settled_exp: 0,
        lane_prev_settled_rx: 0,
        lane_last_ka_settled_exp: 0,
        lane_stun_outcomes: VecDeque::new(),
        lane_score: None,
        lane_confirmed: false,
        lane_good_windows: 0,
        lane_subopt_windows: 0,
        lane_degrade_streak: 0,
        next_lane_hunt_at: now + initial_lane_cooldown,
        standby_for_primary,
        standby_spawned: false,
        rotate_at: None,
        hard_rotate_at: None,
        rotate_byte_budget: None,
        rate_15s: RollingByteWindow::new(now, Duration::from_secs(TRICKLE_WINDOW_15S_SECS)),
        rate_5min: RollingByteWindow::new(now, Duration::from_secs(TRICKLE_WINDOW_5MIN_SECS)),
        retries: 0,
        ka_txid: None,
        ka_pkt: Vec::new(),
        ka_retries: 0,
        ka_max_retries,
        ka_rto_at: None,
        ka_sent_at: None,
        mig_txid: None,
        mig_retries: 0,
        mig_retry_at: None,
        mig_echo_payload: None,
        mig_echo_next_at: None,
        mig_echo_left: 0,
        handover_payload: None,
        handover_retries: 0,
        handover_retry_at: None,
        stun_key: Some(stun_key),
        session_key: None,
        mi_key_mig: None,
        ssrc_c2s: s_c2s,
        ssrc_s2c: s_s2c,
        dtls: None,
        dtls_resets: 0,
        pending_sh_suite: None,
        dtls_suite_id: None,
        dtls_km: None,
        active_cipher: None,
        cipher: None,
        pending,
        pending_bytes,
        tx_pkts: 0,
        tx_pkts_at_last_rtcp: 0,
        tx_bytes: 0,
        rx_pkts: 0,
        rx_pkts_at_last_rtcp: 0,
        rx_bytes: 0,
        keepalives_ok: 0,
        srtcp_tx: 0,
        srtcp_rx: 0,
        auth_drops: 0,
    };

    if cfg.dtls_decoy {
        let cert = cert_cache.get(now);
        let mut dtls = Box::new(new_dtls_instance(
            cfg.dtls_min_version,
            dtls_pool.pick(),
            cert,
            now,
        ));
        dtls.set_active(true);
        let _ = dtls.handle_timeout(now);
        sess.dtls = Some(dtls);
        sess.state = HandshakeState::DtlsHandshake;
        let _ = drain_client_dtls(worker_id, &mut sess, dtls_buf, wbuf, cfg, cpu, now, None);
    } else {
        let chosen = resolve_srtp_suite(cfg.cipher_pref, None, cpu, true);
        let final_key = combine_session_key(&stun_key, None);
        sess.session_key = Some(final_key);
        sess.mi_key_mig = Some(derive_ice_migration_key(&final_key));
        sess.active_cipher = Some(chosen);
        let mut c = SrtpCloakCipher::new(&final_key, s_c2s, s_s2c, true, chosen);
        c.set_wan_mtu_for(cfg.wan_mtu, client_outer_hdr_len(cfg.server_addr));
        sess.cipher = Some(c);
        sess.state = HandshakeState::Ready;
        sess.ready_at = Some(now);
        sess.rx_pkts_at_last_rtcp = sess.rx_pkts;
        let mut flushed = 0usize;
        let mut flushed_bytes = 0u64;
        sess.pending_bytes = 0;
        if let Some(ref mut cipher) = sess.cipher {
            while let Some(raw) = sess.pending.pop_front() {
                if let Some(wn) = cipher.wrap_into(&raw, wbuf) {
                    if sess.upstream.send(&wbuf[..wn]).is_ok() {
                        sess.tx_pkts += 1;
                        sess.tx_bytes += raw.len() as u64;
                        flushed_bytes = flushed_bytes.saturating_add(raw.len() as u64);
                        flushed += 1;
                    }
                }
            }
        }
        if flushed_bytes > 0 {
            record_client_media_bytes(&mut sess, cfg, ka_base_ms, now, flushed_bytes);
        }
        log(
            worker_id,
            &format!(
                "session READY{} (hunted, no-dtls) up_sport={} cipher={} flushed={}",
                if is_prewarm { " (pre-warmed)" } else { "" },
                local_port,
                chosen.name(),
                flushed
            ),
        );
    }
    sess
}
