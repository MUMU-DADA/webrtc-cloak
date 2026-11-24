//! 协议层编解码、DTLS 互操作与密码学不变量单元测试。

use super::dtls::build_dimpl_config;
use super::srtp::derive_audio_ssrc;
use super::stun::{push_stun_attr, ATTR_FINGERPRINT, ATTR_USERNAME, STUN_FINGERPRINT_XOR};
use super::*;
use dimpl::{Dtls, Output};

#[test]
fn v31_full_security_and_protocol_invariants() {
    let psk = b"v31-unit-test-shared-secret-2026";
    let ice = SessionIceParams::generate();
    let (req, txid) = build_ice_stun_request(psk, &ice, None, true);
    let parsed = parse_stun(&req, psk).unwrap();
    assert!(parsed.authenticated);

    // V3-H-02 regression test: trailing ATTR_USERNAME injected AFTER MESSAGE-INTEGRITY MUST be rejected!
    let mut injected = req[..req.len() - 8].to_vec(); // strip old FINGERPRINT
    push_stun_attr(&mut injected, ATTR_USERNAME, b"evil:user");
    let new_len = (injected.len() - 20 + 8) as u16;
    injected[2..4].copy_from_slice(&new_len.to_be_bytes());
    let crc = crc32fast::hash(&injected) ^ STUN_FINGERPRINT_XOR;
    push_stun_attr(&mut injected, ATTR_FINGERPRINT, &crc.to_be_bytes());
    assert!(parse_stun(&injected, psk).is_none(), "Trailing attribute injection MUST fail!");

    // V3-H-01 regression test: malformed DTLS datagrams & Epoch=0 Alerts MUST fail pre-validation!
    assert!(!validate_dtls_datagram(b"\x16\x00\x00", false));
    assert!(!validate_dtls_datagram(b"\x20\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00", false));
    assert!(!validate_dtls_datagram(b"\x15\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02\x28", false)); // Epoch=0 Alert
    assert!(!validate_dtls_datagram(b"\x15\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00", true)); // NEW-L-01: <18B Epoch=1 Alert rejected
    assert!(validate_dtls_datagram(&[0x15, 0xfe, 0xfd, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x00, 0x12, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], true)); // >=18B Epoch=1 Alert allowed
    assert!(!validate_dtls_datagram(b"\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00", true)); // Epoch=0 blocked in Ready

    // V3-H-05: Even ChaCha20-preferred ClientHello advertises all 3 suites!
    let fake_no_aes = CpuAccelInfo {
        arch: "mips",
        features: vec![],
        has_hw_aes_gcm: false,
        recommended: CipherSuite::ChaCha20Poly1305,
    };
    let cli_cfg = build_dimpl_config(CipherPref::Auto, &fake_no_aes, true);
    let srv_cfg = build_dimpl_config(CipherPref::Auto, &detect_cpu_accel(), false);
    assert_eq!(cli_cfg.dtls12_cipher_suites().count(), 3);
    let now = Instant::now();
    let mut cli_dtls = Dtls::new_12(cli_cfg, generate_ephemeral_webrtc_cert(), now);
    cli_dtls.set_active(true);
    cli_dtls.handle_timeout(now).unwrap();
    let mut srv_dtls = Dtls::new_12(srv_cfg, generate_ephemeral_webrtc_cert(), now);
    srv_dtls.handle_timeout(now).unwrap();

    let mut buf = vec![0u8; 4096];
    let mut sh_cs = None;
    let mut cli_km = None;
    let mut srv_km = None;
    for _ in 0..20 {
        let mut c2s = Vec::new();
        loop {
            match cli_dtls.poll_output(&mut buf) {
                Output::Packet(p) => c2s.push(p.to_vec()),
                Output::BufferTooSmall { needed } => buf.resize(needed, 0),
                Output::KeyingMaterial(km, _) => cli_km = Some(km.to_vec()),
                Output::Timeout(_) => break,
                _ => {}
            }
        }
        for p in c2s { srv_dtls.handle_packet(&p).unwrap(); }
        let mut s2c = Vec::new();
        loop {
            match srv_dtls.poll_output(&mut buf) {
                Output::Packet(p) => {
                    if let Some(cs) = extract_dtls_server_hello_suite(p) { sh_cs = Some(cs); }
                    s2c.push(p.to_vec());
                }
                Output::BufferTooSmall { needed } => buf.resize(needed, 0),
                Output::KeyingMaterial(km, _) => srv_km = Some(km.to_vec()),
                Output::Timeout(_) => break,
                _ => {}
            }
        }
        for p in s2c { cli_dtls.handle_packet(&p).unwrap(); }
        if cli_km.is_some() && srv_km.is_some() { break; }
    }
    assert_eq!(sh_cs, Some(0xCCA9), "3-suite ChaCha20-first ClientHello should negotiate 0xCCA9!");
    assert_eq!(cli_km, srv_km);

    // V3-H-03, V3-H-04, V3-M-02, V3-L-03 checks across all 3 suites
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, &ice.username());
    let skey = combine_session_key(&stun_key, cli_km.as_deref());
    for suite in [CipherSuite::Aes128Gcm, CipherSuite::ChaCha20Poly1305, CipherSuite::Blake2b] {
        let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
        let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);

        // V3-H-04: Plaintext SRTCP primary is ALWAYS 200/201, RC=0 on zero rx media, BYE is encrypted!
        let rtcp_zero = cli.build_srtcp(false, false, false);
        assert_eq!(rtcp_zero[0], 0x80); // RC=0!
        assert_eq!(rtcp_zero[1], 201);
        assert_eq!(srv.verify_srtcp(&rtcp_zero), Some(false));
        assert_eq!(srv.verify_srtcp(&rtcp_zero), None); // replay blocked!

        // Out-of-order SRTCP works via 64-bit sliding window (V3-L-03)
        let rtcp_a = cli.build_srtcp(true, true, false);
        let rtcp_bye = cli.build_srtcp(true, true, true);
        assert_eq!(rtcp_bye[0], 0x81);
        assert_eq!(rtcp_bye[1], 200); // Plaintext is STILL SR(200), NEVER 203!
        assert_eq!(srv.verify_srtcp(&rtcp_bye), Some(true)); // Encrypted BYE detected!
        assert_eq!(srv.verify_srtcp(&rtcp_a), Some(false));  // Earlier out-of-order SRTCP still accepted!
        assert_eq!(srv.verify_srtcp(&rtcp_a), None);         // Duplicate still blocked!

        // V3-H-03: Standard 0x90 header, oversized UDP (>MAX_INNER_UDP_LEN) returns None cleanly (no panic!)
        let mut wbuf = vec![0u8; 65536 + 128];
        let mut rbuf = vec![0u8; 65536 + 128];
        let huge = vec![0x42u8; 65_500];
        assert!(cli.wrap_into(&huge, &mut wbuf).is_none());

        // v0.3.3: Default 1488B WAN MTU caps wire UDP <= 1460B (1422B plain fits; 1452B QUIC probe dropped)
        let wg_1420 = vec![0x55u8; 1420];
        let wn_wg = cli.wrap_into(&wg_1420, &mut wbuf).unwrap();
        assert!(wn_wg <= DEFAULT_WAN_MTU - 28, "wire UDP {} exceeded PPPoE-safe ceiling!", wn_wg);
        let rn_wg = srv.unwrap_into(&wbuf[..wn_wg], &mut rbuf).unwrap();
        assert_eq!(rn_wg, 1420);
        let quic_probe_1452 = vec![0x66u8; 1452];
        assert!(cli.wrap_into(&quic_probe_1452, &mut wbuf).is_none(), "1452B probe MUST be dropped before IPv4 frag!");

        // V3-M-02: Burst of 20 small packets in <1ms -> same wall-clock TS, ONLY 1 packet has M=1!
        let mut marked_cnt = 0;
        let mut ts_set = std::collections::HashSet::new();
        for _ in 0..20 {
            let p = vec![0xABu8; 148];
            let wn = cli.wrap_into(&p, &mut wbuf).unwrap();
            assert_eq!(wbuf[0], 0x90); // V=2, P=0, X=1
            if (wbuf[1] & 0x80) != 0 { marked_cnt += 1; }
            ts_set.insert(u32::from_be_bytes([wbuf[4], wbuf[5], wbuf[6], wbuf[7]]));
            let rn = srv.unwrap_into(&wbuf[..wn], &mut rbuf).unwrap();
            assert_eq!(&rbuf[..rn], &p[..]);
        }
        assert!(marked_cnt <= ts_set.len(), "At most 1 M=1 per wall-clock frame!");

        // v0.3.2: RFC 6479 2048-packet anti-replay window handles deep trans-Pacific ECMP reordering
        if suite == CipherSuite::Aes128Gcm {
            let mut pkts: Vec<Vec<u8>> = Vec::with_capacity(2060);
            for idx in 0..2060u32 {
                let payload = idx.to_be_bytes();
                let wn = cli.wrap_into(&payload, &mut wbuf).unwrap();
                pkts.push(wbuf[..wn].to_vec());
            }
            // Receive the newest packet first (index 2059)
            let rn = srv.unwrap_into(&pkts[2059], &mut rbuf).unwrap();
            assert_eq!(&rbuf[..rn], &2059u32.to_be_bytes());
            // Duplicate of newest MUST fail
            assert!(srv.unwrap_into(&pkts[2059], &mut rbuf).is_none());
            // 500 packets behind (previously dropped by 64-bit window!) MUST succeed
            let rn500 = srv.unwrap_into(&pkts[1559], &mut rbuf).unwrap();
            assert_eq!(&rbuf[..rn500], &1559u32.to_be_bytes());
            assert!(srv.unwrap_into(&pkts[1559], &mut rbuf).is_none()); // duplicate blocked
            // Exact window edge (2047 behind -> idx 12) MUST succeed
            let rn_edge = srv.unwrap_into(&pkts[12], &mut rbuf).unwrap();
            assert_eq!(&rbuf[..rn_edge], &12u32.to_be_bytes());
            assert!(srv.unwrap_into(&pkts[12], &mut rbuf).is_none());
            // Just outside window (2048 behind -> idx 11) MUST be rejected!
            assert!(srv.unwrap_into(&pkts[11], &mut rbuf).is_none());
        }
    }
}

#[test]
fn srtp_inband_probe_roundtrip_and_zero_collision() {
    let psk = b"probe-echo-unit-test-psk";
    let txid = make_fresh_stun_txid(psk);
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, "prb1:prb2");
    let skey = combine_session_key(&stun_key, None);
    for suite in [
        CipherSuite::Aes128Gcm,
        CipherSuite::ChaCha20Poly1305,
        CipherSuite::Blake2b,
    ] {
        let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
        let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);
        cli.set_wan_mtu(DEFAULT_WAN_MTU);
        srv.set_wan_mtu(DEFAULT_WAN_MTU);

        let mut wbuf = [0u8; 2048];
        let mut rbuf = [0u8; 2048];

        // Probe packet round-trip must be recognized as Probe, NOT Data
        let probe = b"PING_INBAND_PROBE_123456";
        let wn = cli.wrap_probe_into(probe, &mut wbuf).unwrap();
        assert_eq!(wbuf[0], 0x90);
        assert!(wn <= DEFAULT_WAN_MTU - 28);
        assert_eq!(srv.unwrap_into_ex(&wbuf[..wn], &mut rbuf), Some(SrtpFrame::Probe(probe.len())));
        assert_eq!(&rbuf[..probe.len()], probe);

        // Normal data packet must NEVER be mistaken for Probe, even if payload starts with 0xFF 0xFE
        let tricky_data = [0xFFu8, 0xFE, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let wn2 = cli.wrap_into(&tricky_data, &mut wbuf).unwrap();
        assert_eq!(srv.unwrap_into_ex(&wbuf[..wn2], &mut rbuf), Some(SrtpFrame::Data(tricky_data.len())));
        assert_eq!(&rbuf[..tricky_data.len()], &tricky_data);

        // Exact MTU edge: 1420B probe payload + 40B fixed = 1460B UDP (= 1488B IPv4) passes; 1421B drops
        let max_probe = vec![0x5Au8; 1420];
        assert!(cli.wrap_probe_into(&max_probe, &mut wbuf).is_some());
        let over_probe = vec![0x5Au8; 1421];
        assert!(cli.wrap_probe_into(&over_probe, &mut wbuf).is_none());
    }
}

#[test]
fn dtls13_auto_and_dtls12_fallback_interop() {
    use dimpl::ProtocolVersion;
    let cpu = detect_cpu_accel();
    let cli_cfg = build_dimpl_config(CipherPref::Auto, &cpu, true);
    let srv_cfg = build_dimpl_config(CipherPref::Auto, &cpu, false);
    let now = Instant::now();

    let drive = |mut cli: Dtls, mut srv: Dtls| -> (Option<ProtocolVersion>, Option<ProtocolVersion>, Vec<u8>, Vec<u8>) {
        cli.set_active(true);
        let _ = cli.handle_timeout(now);
        let _ = srv.handle_timeout(now);
        let mut cbuf = vec![0u8; 4096];
        let mut sbuf = vec![0u8; 4096];
        let mut c_km = Vec::new();
        let mut s_km = Vec::new();
        let mut c_ok = false;
        let mut s_ok = false;
        for _ in 0..16 {
            let mut c_pkts = Vec::new();
            loop {
                match cli.poll_output(&mut cbuf) {
                    Output::Packet(p) => {
                        assert!(validate_dtls_datagram(p, false), "client DTLS datagram must pass validator");
                        c_pkts.push(p.to_vec());
                    }
                    Output::KeyingMaterial(km, _) => c_km = km.to_vec(),
                    Output::Connected => c_ok = true,
                    Output::Timeout(_) => break,
                    _ => {}
                }
            }
            for p in c_pkts {
                srv.handle_packet(&p).unwrap();
            }
            let mut s_pkts = Vec::new();
            loop {
                match srv.poll_output(&mut sbuf) {
                    Output::Packet(p) => {
                        assert!(validate_dtls_datagram(p, false), "server DTLS datagram must pass validator");
                        s_pkts.push(p.to_vec());
                    }
                    Output::KeyingMaterial(km, _) => s_km = km.to_vec(),
                    Output::Connected => s_ok = true,
                    Output::Timeout(_) => break,
                    _ => {}
                }
            }
            for p in s_pkts {
                cli.handle_packet(&p).unwrap();
            }
            if c_ok && s_ok {
                break;
            }
        }
        assert!(c_ok && s_ok, "DTLS handshake should complete");
        assert_eq!(c_km, s_km, "Exported SRTP KeyingMaterial must match");
        assert!(!c_km.is_empty());
        (cli.protocol_version(), srv.protocol_version(), c_km, s_km)
    };

    // 1. Auto <-> Auto MUST negotiate DTLS 1.3
    let (cv1, sv1, _, _) = drive(
        Dtls::new_auto(Arc::clone(&cli_cfg), generate_ephemeral_webrtc_cert(), now),
        Dtls::new_auto(Arc::clone(&srv_cfg), generate_ephemeral_webrtc_cert(), now),
    );
    assert_eq!(cv1, Some(ProtocolVersion::DTLS1_3));
    assert_eq!(sv1, Some(ProtocolVersion::DTLS1_3));

    // 2. Auto client <-> legacy DTLS 1.2 server MUST seamlessly fall back to DTLS 1.2
    let (cv2, sv2, _, _) = drive(
        Dtls::new_auto(Arc::clone(&cli_cfg), generate_ephemeral_webrtc_cert(), now),
        Dtls::new_12(Arc::clone(&srv_cfg), generate_ephemeral_webrtc_cert(), now),
    );
    assert_eq!(cv2, Some(ProtocolVersion::DTLS1_2));
    assert_eq!(sv2, Some(ProtocolVersion::DTLS1_2));

    // 3. Legacy DTLS 1.2 client <-> Auto server MUST seamlessly fall back to DTLS 1.2
    let (cv3, sv3, _, _) = drive(
        Dtls::new_12(Arc::clone(&cli_cfg), generate_ephemeral_webrtc_cert(), now),
        Dtls::new_auto(Arc::clone(&srv_cfg), generate_ephemeral_webrtc_cert(), now),
    );
    assert_eq!(cv3, Some(ProtocolVersion::DTLS1_2));
    assert_eq!(sv3, Some(ProtocolVersion::DTLS1_2));
}

#[test]
fn dual_ssrc_audio_video_split_and_replay_isolation() {
    let psk = b"dual-ssrc-test-psk-2026";
    let txid = make_fresh_stun_txid(psk);
    let (stun_key, s_c2s, s_s2c) = derive_stun_material(psk, &txid, "av01:av02");
    let skey = combine_session_key(&stun_key, None);
    for suite in [
        CipherSuite::Aes128Gcm,
        CipherSuite::ChaCha20Poly1305,
        CipherSuite::Blake2b,
    ] {
        let mut cli = SrtpCloakCipher::new(&skey, s_c2s, s_s2c, true, suite);
        let mut srv = SrtpCloakCipher::new(&skey, s_s2c, s_c2s, false, suite);
        cli.set_dual_ssrc(true);
        srv.set_dual_ssrc(true);
        assert_ne!(cli.ssrc_tx, cli.audio_ssrc_tx);
        assert_eq!(cli.audio_ssrc_tx, srv.audio_ssrc_rx);

        let mut wbuf = [0u8; 2048];
        let mut rbuf = [0u8; 2048];

        // Small ACK packet (< 256B) -> Audio SSRC + PT=111 (Opus)
        let small = vec![0x11u8; 64];
        let wn_a = cli.wrap_into(&small, &mut wbuf).unwrap();
        assert_eq!(wbuf[1] & 0x7F, RTP_AUDIO_PT);
        assert_eq!(u32::from_be_bytes([wbuf[8], wbuf[9], wbuf[10], wbuf[11]]), cli.audio_ssrc_tx);
        let twcc1 = u16::from_be_bytes([wbuf[17], wbuf[18]]);
        let rn_a = srv.unwrap_into(&wbuf[..wn_a], &mut rbuf).unwrap();
        assert_eq!(&rbuf[..rn_a], &small[..]);
        // Replay of Audio packet MUST be blocked independently
        assert!(srv.unwrap_into(&wbuf[..wn_a], &mut rbuf).is_none());

        // Large data packet (>= 256B) -> Video SSRC + PT=96, global TWCC increments by +1
        let large = vec![0x22u8; 1200];
        let wn_v = cli.wrap_into(&large, &mut wbuf).unwrap();
        assert_eq!(wbuf[1] & 0x7F, RTP_VIDEO_PT);
        assert_eq!(u32::from_be_bytes([wbuf[8], wbuf[9], wbuf[10], wbuf[11]]), cli.ssrc_tx);
        let twcc2 = u16::from_be_bytes([wbuf[17], wbuf[18]]);
        assert_eq!(twcc2, twcc1.wrapping_add(1));
        let rn_v = srv.unwrap_into(&wbuf[..wn_v], &mut rbuf).unwrap();
        assert_eq!(&rbuf[..rn_v], &large[..]);
        // Replay of Video packet MUST be blocked independently
        assert!(srv.unwrap_into(&wbuf[..wn_v], &mut rbuf).is_none());

        // High-16-bit SSRC disjointness across full 2^48 Nonce space (P0-5 / M-02)
        assert_ne!(cli.ssrc_tx >> 16, cli.audio_ssrc_tx >> 16);
        assert_ne!(cli.ssrc_rx >> 16, cli.audio_ssrc_rx >> 16);
    }
}

#[test]
fn v32_hardening_invariants_crypto_dpi_and_anti_downgrade() {
    // 1. derive_audio_ssrc high-16-bit disjointness even for adversarial edge SSRCs
    let key = [0x42u8; 32];
    for v_ssrc in [0u32, 1, 0x5A3C_A5C3, 0xFFFF_FFFF, 0x1357_9BDF, 0x1234_5678] {
        let a_ssrc = derive_audio_ssrc(&key, v_ssrc);
        assert_ne!(a_ssrc, 0);
        assert_ne!(a_ssrc >> 16, v_ssrc >> 16, "high 16 bits MUST be disjoint for Nonce orthogonality");
    }

    // 2. validate_dtls_datagram rejects plaintext ct=26 in Ready and epoch>=1 (P0-4 / M-01)
    let mut fake_ack = [0u8; 32];
    fake_ack[0] = 26; // plaintext ACK
    fake_ack[1] = 0xFE;
    fake_ack[2] = 0xFD;
    fake_ack[12] = 19; // rec_len = 19
    assert!(validate_dtls_datagram(&fake_ack, false)); // epoch=0 allowed during handshake
    assert!(!validate_dtls_datagram(&fake_ack, true)); // MUST be rejected in Ready!
    fake_ack[4] = 1; // epoch=1 plaintext ct=26 -> rejected always!
    assert!(!validate_dtls_datagram(&fake_ack, false));

    // 3. extract_dtls_server_hello_suite rejects malformed extensions_len (P0-2 / M-03)
    let mut bad_sh = vec![0u8; 13 + 54];
    bad_sh[0] = 0x16;
    bad_sh[1] = 0xFE;
    bad_sh[2] = 0xFD;
    bad_sh[11..13].copy_from_slice(&54u16.to_be_bytes());
    let hs = &mut bad_sh[13..];
    hs[0] = 0x02; // ServerHello
    hs[1..4].copy_from_slice(&[0, 0, 42]); // msg_len = 42
    hs[9..12].copy_from_slice(&[0, 0, 42]); // frag_len = 42
    hs[12] = 0xFE;
    hs[13] = 0xFD;
    hs[46] = 0; // sid_len = 0
    hs[47..49].copy_from_slice(&0x1303u16.to_be_bytes());
    hs[49] = 0; // compression = 0
    hs[50..52].copy_from_slice(&0xFFFFu16.to_be_bytes()); // MALFORMED extensions_len!
    assert_eq!(extract_dtls_server_hello_suite(&bad_sh), None);
    // Valid 2-byte extensions (len=2) succeeds:
    bad_sh[13 + 50..13 + 52].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(extract_dtls_server_hello_suite(&bad_sh), Some(0x1303));

    // 4. Multi-MTU DtlsConfigPool respects --mtu clamping (P1-2 / L-03)
    let cpu = detect_cpu_accel();
    let pool_default = build_dimpl_config_pool(CipherPref::Auto, &cpu, true, DEFAULT_WAN_MTU);
    assert_eq!(pool_default.mtus().len(), 8);
    let pool_small = build_dimpl_config_pool(CipherPref::Auto, &cpu, true, 1000);
    assert!(pool_small.mtus().iter().all(|&m| m <= 972));

    // 5. Strict DTLS 1.3 mode (DtlsMinVersion::V13Only) negotiates DTLS 1.3 cleanly
    let now = Instant::now();
    let cli_cfg = pool_default.pick();
    let srv_cfg = build_dimpl_config_pool(CipherPref::Auto, &cpu, false, DEFAULT_WAN_MTU).pick();
    let mut c13 = new_dtls_instance(DtlsMinVersion::V13Only, cli_cfg, generate_ephemeral_webrtc_cert(), now);
    let mut s13 = new_dtls_instance(DtlsMinVersion::V13Only, srv_cfg, generate_ephemeral_webrtc_cert(), now);
    c13.set_active(true);
    let _ = c13.handle_timeout(now);
    let _ = s13.handle_timeout(now);
    let mut buf = vec![0u8; 4096];
    let (mut c_ok, mut s_ok) = (false, false);
    for _ in 0..12 {
        let mut cp = Vec::new();
        loop {
            match c13.poll_output(&mut buf) {
                Output::Packet(p) => cp.push(p.to_vec()),
                Output::Connected => c_ok = true,
                Output::Timeout(_) => break,
                _ => {}
            }
        }
        for p in cp { s13.handle_packet(&p).unwrap(); }
        let mut sp = Vec::new();
        loop {
            match s13.poll_output(&mut buf) {
                Output::Packet(p) => sp.push(p.to_vec()),
                Output::Connected => s_ok = true,
                Output::Timeout(_) => break,
                _ => {}
            }
        }
        for p in sp { c13.handle_packet(&p).unwrap(); }
        if c_ok && s_ok { break; }
    }
    assert!(c_ok && s_ok);
    assert_eq!(c13.protocol_version(), Some(dimpl::ProtocolVersion::DTLS1_3));
    assert_eq!(s13.protocol_version(), Some(dimpl::ProtocolVersion::DTLS1_3));

    // 6. Opus <=50pps cap (max 1 PT=111 per 20ms frame) + strict Video M=1 causality + Audio SRTCP!
    let mut cli = SrtpCloakCipher::new(&key, 0x1122_3344, 0x5566_7788, true, CipherSuite::Aes128Gcm);
    let mut srv = SrtpCloakCipher::new(&key, 0x5566_7788, 0x1122_3344, false, CipherSuite::Aes128Gcm);
    cli.set_dual_ssrc(true);
    srv.set_dual_ssrc(true);

    let mut wbuf = [0u8; 2048];
    let mut rbuf = [0u8; 2048];
    let mut audio_cnt = 0usize;
    let mut video_cnt = 0usize;
    let mut prev_marked_video_ts: Option<u32> = None;
    for _ in 0..20 {
        let small = [0x77u8; 80];
        let wn = cli.wrap_into(&small, &mut wbuf).unwrap();
        let pt = wbuf[1] & 0x7F;
        let m = (wbuf[1] & 0x80) != 0;
        let ts = u32::from_be_bytes([wbuf[4], wbuf[5], wbuf[6], wbuf[7]]);
        if pt == RTP_AUDIO_PT {
            audio_cnt += 1;
        } else {
            assert_eq!(pt, RTP_VIDEO_PT);
            video_cnt += 1;
            if let Some(closed_ts) = prev_marked_video_ts {
                assert_ne!(ts, closed_ts, "Video packet after M=1 MUST NEVER reuse closed timestamp!");
            }
            if m {
                prev_marked_video_ts = Some(ts);
            }
        }
        assert_eq!(srv.unwrap_into(&wbuf[..wn], &mut rbuf), Some(80));
    }
    assert!(audio_cnt >= 1 && audio_cnt <= 2, "Opus cap MUST limit burst to <=1 pkt/20ms (got {})", audio_cnt);
    assert!(video_cnt >= 18, "Overflow small ACKs MUST spill onto Video SSRC (got {})", video_cnt);

    // 7. Audio-only SRTCP reports on Audio SSRC with 0-based index & verifies cleanly on peer
    let mut cli2 = SrtpCloakCipher::new(&key, 0x1122_3344, 0x5566_7788, true, CipherSuite::Aes128Gcm);
    let mut srv2 = SrtpCloakCipher::new(&key, 0x5566_7788, 0x1122_3344, false, CipherSuite::Aes128Gcm);
    cli2.set_dual_ssrc(true);
    srv2.set_dual_ssrc(true);
    let wn = cli2.wrap_into(&[0x33u8; 64], &mut wbuf).unwrap();
    assert_eq!(wbuf[1] & 0x7F, RTP_AUDIO_PT);
    assert_eq!(srv2.unwrap_into(&wbuf[..wn], &mut rbuf), Some(64));
    let rtcp = cli2.build_srtcp(false, true, false);
    assert_eq!(rtcp[1], 200); // SR on Audio SSRC!
    assert_eq!(u32::from_be_bytes([rtcp[4], rtcp[5], rtcp[6], rtcp[7]]), cli2.audio_ssrc_tx);
    assert_eq!(&rtcp[rtcp.len() - 4..], &0x8000_0000u32.to_be_bytes()); // 0-based SRTCP index!
    assert_eq!(srv2.verify_srtcp(&rtcp), Some(false));
    assert_eq!(srv2.verify_srtcp(&rtcp), None); // replay blocked!
}

#[test]
fn v38_zero_media_srtcp_no_fake_fb_and_lognormal_distributions() {
    let key = [0x99u8; 32];
    let mut cli = SrtpCloakCipher::new(&key, 0x1122_3344, 0x5566_7788, true, CipherSuite::Aes128Gcm);
    let mut srv = SrtpCloakCipher::new(&key, 0x5566_7788, 0x1122_3344, false, CipherSuite::Aes128Gcm);
    cli.set_dual_ssrc(true);
    srv.set_dual_ssrc(true);

    // 1. Zero-media RR MUST NEVER attach fake PT=205/206 feedback (always exact minimal 52B: 8B hdr + 24B SDES + 16B tag + 4B idx)
    for _ in 0..64 {
        let pkt = cli.build_srtcp(false, false, false);
        assert_eq!(pkt[0], 0x80); // RC=0
        assert_eq!(pkt[1], 201);  // RR
        assert_eq!(
            pkt.len(),
            52,
            "zero-media RR MUST omit PT=205/206 feedback subpackets (expected 52B, got {}B)",
            pkt.len()
        );
        assert_eq!(srv.verify_srtcp(&pkt), Some(false));
    }

    // 2. When rx media IS present (has_rx_media=true), FB subpackets (PT=205/206) still attach smoothly (~87.5%)
    let mut fb_seen = 0usize;
    for _ in 0..32 {
        let pkt = cli.build_srtcp(true, false, false);
        assert_eq!(pkt[0], 0x81); // RC=1
        if pkt.len() > 76 {
            fb_seen += 1;
        }
        assert_eq!(srv.verify_srtcp(&pkt), Some(false));
    }
    assert!(fb_seen >= 15, "active-rx RR should still emit PT=205/206 feedback (got {}/32)", fb_seen);

    // 3. Log-normal MBB duration breaks rectangular [0.8R, 1.2R] box edges
    let mut below_80 = 0usize;
    let mut above_120 = 0usize;
    for _ in 0..200 {
        let d = lognormal_duration_ms(10_000).as_millis() as u64;
        assert!(d >= 3_500 && d <= 28_000, "lognormal out of bounds: {}ms", d);
        if d < 8_000 {
            below_80 += 1;
        }
        if d > 12_000 {
            above_120 += 1;
        }
    }
    assert!(below_80 >= 10 && above_120 >= 10, "lognormal must extend beyond [0.8R, 1.2R] (below={} above={})", below_80, above_120);

    // 4. Random byte budget spans [0.50x, 1.85x] smoothly
    let base = 1200u64 * 1024 * 1024;
    let mut min_b = u64::MAX;
    let mut max_b = 0u64;
    for _ in 0..100 {
        let b = rand_byte_budget(base);
        assert!(b >= 600 * 1024 * 1024 && b <= 2220 * 1024 * 1024, "budget out of range: {}", b);
        min_b = min_b.min(b);
        max_b = max_b.max(b);
    }
    assert!(max_b - min_b > 200 * 1024 * 1024, "byte budgets should have meaningful variance");

    // 5. RollingByteWindow accumulates and decays smoothly without cliffs
    let t0 = Instant::now();
    let mut win = RollingByteWindow::new(t0, Duration::from_secs(10));
    win.record(t0, 10_000);
    assert_eq!(win.bytes_in_window(t0), 10_000);
    assert_eq!(win.bytes_in_window(t0 + Duration::from_secs(10)), 10_000);
    let mid = win.bytes_in_window(t0 + Duration::from_secs(15));
    assert!(mid >= 4_500 && mid <= 5_500, "half-decayed window should be ~5000 (got {})", mid);
    assert_eq!(win.bytes_in_window(t0 + Duration::from_secs(21)), 0);
}

#[test]
fn v40_hkdf_stun_per_session_mig_and_control_frames() {
    let psk = b"v040-hkdf-mig-unit-test-psk";
    let global_mi = stun_hmac_key(psk);
    let skey1 = [0x11u8; 32];
    let skey2 = [0x22u8; 32];

    // 1. HKDF per-session ice-pwd-v4 is distinct from global PSK key & distinct per session
    let mig1 = derive_ice_migration_key(&skey1);
    let mig2 = derive_ice_migration_key(&skey2);
    assert_ne!(mig1, global_mi);
    assert_ne!(mig1, mig2);

    // 2. Handover proof binds BOTH old and new session keys (asymmetric & non-forgeable)
    let p12 = compute_handover_proof(&skey1, &skey2);
    let p21 = compute_handover_proof(&skey2, &skey1);
    assert_ne!(p12, p21);

    // 3. Per-session STUN migration request: zero-alloc username peek, exact tie_breaker,
    //    rejected under global PSK key, accepted ONLY under mi_key_mig!
    let ice = SessionIceParams::generate();
    let (mig_pkt, txid) = build_ice_stun_request_with_key(psk, &mig1, &ice, None, true);
    assert_eq!(peek_stun_request_username(&mig_pkt), Some(ice.username().as_str()));
    let bad_global = parse_stun_with_key(&mig_pkt, psk, &global_mi).unwrap();
    assert!(!bad_global.authenticated, "migration STUN MUST fail global PSK verification!");
    let ok_mig = parse_stun_with_key(&mig_pkt, psk, &mig1).unwrap();
    assert!(ok_mig.authenticated);
    assert!(ok_mig.use_candidate);
    assert_eq!(ok_mig.txid, txid);
    assert_eq!(ok_mig.tie_breaker, Some(ice.tie_breaker));

    // 4. 0xFFFD PathChallenge & 0xFFFC Handover AEAD round-trip + replay rejection across all 3 suites
    for suite in [
        CipherSuite::Aes128Gcm,
        CipherSuite::ChaCha20Poly1305,
        CipherSuite::Blake2b,
    ] {
        let mut cli = SrtpCloakCipher::new(&skey1, 0x1020_3040, 0x5060_7080, true, suite);
        let mut srv = SrtpCloakCipher::new(&skey1, 0x5060_7080, 0x1020_3040, false, suite);
        cli.set_dual_ssrc(true);
        srv.set_dual_ssrc(true);

        let mut wbuf = [0u8; 512];
        let mut rbuf = [0u8; 512];

        let ch = [0x01u8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1];
        let wn1 = cli.wrap_control_unpadded_into(SRTP_PATH_CHALLENGE_MAGIC, &ch, &mut wbuf).unwrap();
        assert_eq!(wbuf[0], 0x90);
        // P0-4 strict anti-reflection bound: 20B RTP+ext + 4B ctrl + 17B challenge + 16B tag = exact 57B
        // (64B STUN Success + 57B SRTP Challenge = 121B <= 1.32x against 92B STUN Request)
        assert_eq!(wn1, 57, "unpadded 0xFFFD challenge MUST be exact 57B (<= 1.32x total reply)");
        assert_eq!(srv.unwrap_into_ex(&wbuf[..wn1], &mut rbuf), Some(SrtpFrame::PathChallenge(ch.len())));
        assert_eq!(&rbuf[..ch.len()], &ch);
        assert_eq!(srv.unwrap_into_ex(&wbuf[..wn1], &mut rbuf), None); // replay blocked!

        let ho = [0x01u8, 9, b'a', b'b', b'c', b'd', b':', b'e', b'f', b'g', b'h'];
        let wn2 = cli.wrap_control_into(SRTP_HANDOVER_MAGIC, &ho, &mut wbuf).unwrap();
        assert_eq!(wbuf[0], 0x90);
        assert_eq!(srv.unwrap_into_ex(&wbuf[..wn2], &mut rbuf), Some(SrtpFrame::Handover(ho.len())));
        assert_eq!(&rbuf[..ho.len()], &ho);
        assert_eq!(srv.unwrap_into_ex(&wbuf[..wn2], &mut rbuf), None); // replay blocked!
    }
}
