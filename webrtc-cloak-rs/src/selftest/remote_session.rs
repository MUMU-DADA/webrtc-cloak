//! 远端现网测试会话建立（STUN/DTLS 握手）与带内加密探测引擎。

use super::tune_socket;
use crate::constants::{
    outer_udp_hdr_len, unspecified_addr_for, DTLS_CT_HANDSHAKE, DTLS_HS_CLIENT_HELLO,
    DTLS_IDLE_TIMEOUT_THRESHOLD_SECS, DTLS_IO_BUF_LEN, DTLS_PLAINTEXT_HDR_LEN, PROBE_IO_BUF_LEN,
    STUN_BINDING_SUCCESS,
};
use crate::protocol::{
    build_dimpl_config_pool_for, build_ice_stun_request, build_ice_stun_request_with_key,
    combine_session_key, demux_rfc7983, derive_ice_migration_key, derive_stun_material,
    derive_stun_scope_key, detect_cpu_accel, extract_dtls_server_hello_suite,
    generate_ephemeral_webrtc_cert, make_fresh_stun_txid, new_dtls_instance, parse_stun,
    parse_stun_with_key, resolve_srtp_suite, validate_dtls_datagram, CipherPref, CipherSuite,
    DtlsMinVersion, PacketKind, SessionIceParams, SrtpCloakCipher, SrtpFrame,
};
use dimpl::{Dtls, Output as DtlsOutput, ProtocolVersion};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

pub(super) struct LiveStunOk {
    pub(super) sock: UdpSocket,
    pub(super) server_addr: SocketAddr,
    pub(super) stun_auth_psk: [u8; 32],
    pub(super) ice: SessionIceParams,
    pub(super) txid: [u8; 12],
    pub(super) raw_stun: Vec<u8>,
    pub(super) raw_resp: Vec<u8>,
    pub(super) rtt_ms: f64,
    pub(super) mapped_addr: Option<SocketAddr>,
}

pub(super) struct LiveReadySession {
    pub(super) sock: UdpSocket,
    pub(super) stun_auth_psk: [u8; 32],
    pub(super) mi_key_mig: [u8; 32],
    pub(super) ice: SessionIceParams,
    pub(super) dtls: Dtls,
    pub(super) dtls_next_timeout: Option<Instant>,
    pub(super) is_dtls13: bool,
    pub(super) cipher: SrtpCloakCipher,
    pub(super) suite: CipherSuite,
    pub(super) dl_srtcp_verified: u64,
    pub(super) tx_srtp_pkts: u64,
    pub(super) rx_srtp_pkts: u64,
}

pub(super) fn remote_stun_handshake(
    server_addr: SocketAddr,
    psk: &[u8],
) -> Result<LiveStunOk, String> {
    let sock = UdpSocket::bind(unspecified_addr_for(server_addr))
        .map_err(|e| format!("bind udp: {}", e))?;
    tune_socket(&sock);
    sock.set_read_timeout(Some(Duration::from_millis(750)))
        .map_err(|e| format!("set timeout: {}", e))?;
    sock.connect(server_addr)
        .map_err(|e| format!("connect {}: {}", server_addr, e))?;

    let ice = SessionIceParams::generate();
    let stun_auth_psk = derive_stun_scope_key(psk, server_addr.port());
    let txid = make_fresh_stun_txid(&stun_auth_psk);
    let (req, _) = build_ice_stun_request(&stun_auth_psk, &ice, Some(txid), true);
    let mut rbuf = [0u8; PROBE_IO_BUF_LEN];

    for _ in 0..4 {
        let ts = Instant::now();
        let _ = sock.send(&req);
        while ts.elapsed() < Duration::from_millis(750) {
            match sock.recv(&mut rbuf) {
                Ok(n) => {
                    let pkt = &rbuf[..n];
                    if demux_rfc7983(pkt) == PacketKind::Stun {
                        if let Some(p) = parse_stun(pkt, &stun_auth_psk) {
                            if p.authenticated
                                && p.msg_type == STUN_BINDING_SUCCESS
                                && p.txid == txid
                            {
                                return Ok(LiveStunOk {
                                    sock,
                                    server_addr,
                                    stun_auth_psk,
                                    ice,
                                    txid,
                                    raw_stun: req,
                                    raw_resp: pkt.to_vec(),
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

/// Verify pre-DTLS `SeenTxidCache` same-`txid` idempotent retransmit before DTLS starts
/// (in v0.7+, the initial STUN `txid` is burned as soon as DTLS begins).
pub(super) fn check_pre_dtls_stun_retransmit(
    stun: &LiveStunOk,
    timeout_ms: u64,
) -> Option<(f64, Vec<u8>)> {
    let _ = stun.sock.set_read_timeout(Some(Duration::from_millis(40)));
    let ts = Instant::now();
    let _ = stun.sock.send(&stun.raw_stun);
    let mut rbuf = [0u8; PROBE_IO_BUF_LEN];
    let deadline = Duration::from_millis(timeout_ms);
    while ts.elapsed() < deadline {
        match stun.sock.recv(&mut rbuf) {
            Ok(n) => {
                let pkt = &rbuf[..n];
                if demux_rfc7983(pkt) == PacketKind::Stun {
                    if let Some(p) = parse_stun(pkt, &stun.stun_auth_psk) {
                        if p.authenticated
                            && p.msg_type == STUN_BINDING_SUCCESS
                            && p.txid == stun.txid
                        {
                            return Some((ts.elapsed().as_secs_f64() * 1000.0, pkt.to_vec()));
                        }
                    }
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }
    None
}

pub(super) fn remote_dtls_handshake(
    stun: LiveStunOk,
    psk: &[u8],
    cipher_pref: CipherPref,
    dtls_min_version: DtlsMinVersion,
    wan_mtu: usize,
) -> Result<(LiveReadySession, f64), String> {
    let outer_hdr = outer_udp_hdr_len(stun.server_addr);
    let cpu = detect_cpu_accel();
    let dtls_cfg = build_dimpl_config_pool_for(cipher_pref, &cpu, true, wan_mtu, outer_hdr).pick();
    let cert = generate_ephemeral_webrtc_cert();
    let now = Instant::now();
    let mut dtls = new_dtls_instance(dtls_min_version, dtls_cfg, cert, now);
    dtls.set_active(true);
    let _ = dtls.handle_timeout(now);

    let sock = stun.sock;
    sock.set_read_timeout(Some(Duration::from_millis(25)))
        .map_err(|e| format!("set timeout: {}", e))?;

    let mut dtls_buf = vec![0u8; DTLS_IO_BUF_LEN];
    let mut rbuf = vec![0u8; DTLS_IO_BUF_LEN];
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
                    if p.len() > DTLS_PLAINTEXT_HDR_LEN
                        && p[0] == DTLS_CT_HANDSHAKE
                        && p[DTLS_PLAINTEXT_HDR_LEN] == DTLS_HS_CLIENT_HELLO
                    {
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
    let stun_auth_psk = derive_stun_scope_key(psk, stun.server_addr.port());
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(&stun_auth_psk, &stun.txid, &uname);
    let suite = resolve_srtp_suite(cipher_pref, dtls_suite_id, &cpu, false);
    let final_key = combine_session_key(&stun_key, Some(km));
    let mi_key_mig = derive_ice_migration_key(&final_key);
    let mut cipher = SrtpCloakCipher::new(&final_key, s_c2s, s_s2c, true, suite);
    cipher.set_wan_mtu_for(wan_mtu, outer_hdr);
    cipher.set_dual_ssrc(true);

    Ok((
        LiveReadySession {
            sock,
            stun_auth_psk,
            mi_key_mig,
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
    pub(super) fn pump_dtls(&mut self, incoming: Option<&[u8]>) {
        let now = Instant::now();
        if let Some(pkt) = incoming {
            if validate_dtls_datagram(pkt, false) {
                let _ = self.dtls.handle_packet(pkt);
            }
        }
        if let Some(t) = self.dtls_next_timeout {
            let rem = t.saturating_duration_since(now);
            if rem > Duration::from_secs(DTLS_IDLE_TIMEOUT_THRESHOLD_SECS) {
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
        let mut dtls_buf = vec![0u8; DTLS_IO_BUF_LEN];
        loop {
            match self.dtls.poll_output(&mut dtls_buf) {
                DtlsOutput::Packet(p) => {
                    let _ = self.sock.send(p);
                }
                DtlsOutput::BufferTooSmall { needed } => dtls_buf.resize(needed, 0),
                DtlsOutput::Timeout(t) => {
                    if t.saturating_duration_since(now)
                        > Duration::from_secs(DTLS_IDLE_TIMEOUT_THRESHOLD_SECS)
                    {
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

    pub(super) fn send_stun_consent(
        &mut self,
        _psk: &[u8],
        timeout_ms: u64,
    ) -> Option<StunConsentReply> {
        self.pump_dtls(None);
        let (req, txid) = build_ice_stun_request_with_key(
            &self.stun_auth_psk,
            &self.mi_key_mig,
            &self.ice,
            None,
            false,
        );
        let _ = self.sock.set_read_timeout(Some(Duration::from_millis(40)));
        let ts = Instant::now();
        let _ = self.sock.send(&req);
        let mut rbuf = [0u8; PROBE_IO_BUF_LEN];
        let deadline = Duration::from_millis(timeout_ms);
        while ts.elapsed() < deadline {
            match self.sock.recv(&mut rbuf) {
                Ok(n) => {
                    let pkt = &rbuf[..n];
                    match demux_rfc7983(pkt) {
                        PacketKind::Stun => {
                            if let Some(p) =
                                parse_stun_with_key(pkt, &self.stun_auth_psk, &self.mi_key_mig)
                            {
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
                        PacketKind::Srtcp if self.cipher.verify_srtcp(pkt).is_some() => {
                            self.dl_srtcp_verified += 1;
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

    pub(super) fn send_raw_stun_expect(
        &mut self,
        raw_req: &[u8],
        expected_txid: [u8; 12],
        _psk: &[u8],
        timeout_ms: u64,
    ) -> Option<(f64, Vec<u8>)> {
        self.pump_dtls(None);
        let _ = self.sock.set_read_timeout(Some(Duration::from_millis(40)));
        let ts = Instant::now();
        let _ = self.sock.send(raw_req);
        let mut rbuf = [0u8; PROBE_IO_BUF_LEN];
        let deadline = Duration::from_millis(timeout_ms);
        while ts.elapsed() < deadline {
            match self.sock.recv(&mut rbuf) {
                Ok(n) => {
                    let pkt = &rbuf[..n];
                    match demux_rfc7983(pkt) {
                        PacketKind::Stun => {
                            if let Some(p) =
                                parse_stun_with_key(pkt, &self.stun_auth_psk, &self.mi_key_mig)
                            {
                                if p.authenticated
                                    && p.msg_type == STUN_BINDING_SUCCESS
                                    && p.txid == expected_txid
                                {
                                    return Some((
                                        ts.elapsed().as_secs_f64() * 1000.0,
                                        pkt.to_vec(),
                                    ));
                                }
                            }
                        }
                        PacketKind::Dtls => {
                            self.pump_dtls(Some(pkt));
                        }
                        PacketKind::Srtcp if self.cipher.verify_srtcp(pkt).is_some() => {
                            self.dl_srtcp_verified += 1;
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

    pub(super) fn probe_srtp_one(
        &mut self,
        payload: &[u8],
        timeout_ms: u64,
    ) -> Option<(f64, usize)> {
        self.pump_dtls(None);
        let mut wbuf = [0u8; PROBE_IO_BUF_LEN];
        let wn = self.cipher.wrap_probe_into(payload, &mut wbuf)?;
        let _ = self.sock.set_read_timeout(Some(Duration::from_millis(30)));
        let ts = Instant::now();
        if self.sock.send(&wbuf[..wn]).is_ok() {
            self.tx_srtp_pkts += 1;
        }
        let mut rbuf = [0u8; PROBE_IO_BUF_LEN];
        let mut pbuf = [0u8; PROBE_IO_BUF_LEN];
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
                        PacketKind::Srtcp if self.cipher.verify_srtcp(pkt).is_some() => {
                            self.dl_srtcp_verified += 1;
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

    pub(super) fn teardown(&mut self) {
        let bye = self
            .cipher
            .build_srtcp(self.rx_srtp_pkts > 0, self.tx_srtp_pkts > 0, true);
        let _ = self.sock.send(&bye);
        // Separate SRTCP BYE and DTLS close_notify to match v0.7 async teardown cadence
        thread::sleep(Duration::from_millis(25));
        let mut dtls_buf = vec![0u8; PROBE_IO_BUF_LEN];
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

pub(super) fn send_probe_expect_silence_ms(
    server_addr: SocketAddr,
    payload: &[u8],
    wait_ms: u64,
) -> usize {
    let atk = match UdpSocket::bind(unspecified_addr_for(server_addr)) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let _ = atk.set_read_timeout(Some(Duration::from_millis(wait_ms)));
    if atk.connect(server_addr).is_err() {
        return 0;
    }
    let _ = atk.send(payload);
    let mut buf = [0u8; PROBE_IO_BUF_LEN];
    atk.recv(&mut buf).unwrap_or_default()
}

pub(super) type StunConsentReply = (f64, Vec<u8>, [u8; 12], Vec<u8>);
