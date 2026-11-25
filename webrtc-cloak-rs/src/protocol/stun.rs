//! RFC 5389/8445 ICE STUN 报文编解码、新鲜度校验与 HKDF 密钥派生。

use super::{fill_random, rand_u32, rand_ufrag_chrome, unix_secs};
use crate::constants::{
    STUN_BINDING_REQUEST, STUN_BINDING_SUCCESS, STUN_HDR_LEN, STUN_MAX_USERNAME_LEN,
};
use hmac::{Hmac, Mac as _};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use std::net::{Ipv4Addr, SocketAddrV4};
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

/// RFC 5389 STUN Magic Cookie 固定值。
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN 请求事务 ID 嵌入时间戳允许的最大时钟偏差（秒），用于防重放。
const STUN_MAX_SKEW_SECS: i64 = 30;
/// STUN 属性类型：`USERNAME` (0x0006)。
pub(super) const STUN_ATTR_USERNAME: u16 = 0x0006;
/// STUN 属性类型：`MESSAGE-INTEGRITY` (0x0008)。
const STUN_ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
/// STUN 属性类型：`XOR-MAPPED-ADDRESS` (0x0020)。
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// STUN 属性类型：`PRIORITY` (0x0024)。
const STUN_ATTR_PRIORITY: u16 = 0x0024;
/// STUN 属性类型：`USE-CANDIDATE` (0x0025)。
const STUN_ATTR_USE_CANDIDATE: u16 = 0x0025;
/// STUN 属性类型：`FINGERPRINT` (0x8028)。
pub(super) const STUN_ATTR_FINGERPRINT: u16 = 0x8028;
/// STUN 属性类型：`ICE-CONTROLLING` (0x802A)。
const STUN_ATTR_ICE_CONTROLLING: u16 = 0x802A;
/// RFC 5389 `FINGERPRINT` CRC32 异或掩码（ASCII `"STUN"`）。
pub(super) const STUN_FINGERPRINT_XOR: u32 = 0x5354_554E;
/// STUN `MESSAGE-INTEGRITY` HMAC-SHA1 值长度（字节）。
const STUN_MI_ATTR_LEN: usize = 20;
/// STUN `MESSAGE-INTEGRITY` 完整 TLV 长度（4B 头 + 20B 摘要）。
const STUN_MI_TLV_LEN: usize = 24;
/// STUN `FINGERPRINT` 完整 TLV 长度（4B 头 + 4B CRC32）。
const STUN_FP_TLV_LEN: usize = 8;
/// RFC 8445 ICE host 候选地址类型优先级常量。
const ICE_HOST_TYPE_PREF: u32 = 126;
/// RFC 8445 RTP 组件（component_id=1）对应的优先级低位值（256 - 1）。
const ICE_COMPONENT_RTP_REV: u32 = 255;

/// Session-constant ICE attributes per RFC 8445 §5.1.2.1 & §5.2.
#[derive(Debug, Clone)]
pub struct SessionIceParams {
    pub ufrag_local: String,
    pub ufrag_remote: String,
    pub tie_breaker: [u8; 8],
    pub priority: u32,
}

impl SessionIceParams {
    pub fn generate() -> Self {
        let mut tie_breaker = [0u8; 8];
        fill_random(&mut tie_breaker);
        let local_pref = (rand_u32() & 0xFFFF) | 0x8000;
        let priority = (ICE_HOST_TYPE_PREF << 24) | (local_pref << 8) | ICE_COMPONENT_RTP_REV;
        Self {
            ufrag_local: rand_ufrag_chrome(),
            ufrag_remote: rand_ufrag_chrome(),
            tie_breaker,
            priority,
        }
    }

    pub fn username(&self) -> String {
        format!("{}:{}", self.ufrag_remote, self.ufrag_local)
    }
}

fn txid_ts_mask(psk: &[u8], r8: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"webrtc-cloak:txid-ts:");
    h.update(psk);
    h.update(r8);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

pub fn make_fresh_stun_txid(psk: &[u8]) -> [u8; 12] {
    let mut txid = [0u8; 12];
    fill_random(&mut txid[..8]);
    let ts_b = unix_secs().to_be_bytes();
    let mask = txid_ts_mask(psk, &txid[..8]);
    for i in 0..4 {
        txid[8 + i] = ts_b[i] ^ mask[i];
    }
    txid
}

pub fn verify_stun_txid_fresh(psk: &[u8], txid: &[u8; 12]) -> bool {
    let mask = txid_ts_mask(psk, &txid[..8]);
    let ts_b = [
        txid[8] ^ mask[0],
        txid[9] ^ mask[1],
        txid[10] ^ mask[2],
        txid[11] ^ mask[3],
    ];
    let ts = u32::from_be_bytes(ts_b) as i64;
    let now = unix_secs() as i64;
    (now - ts).abs() <= STUN_MAX_SKEW_SECS
}

pub(super) fn push_stun_attr(buf: &mut Vec<u8>, attr_type: u16, val: &[u8]) {
    buf.extend_from_slice(&attr_type.to_be_bytes());
    buf.extend_from_slice(&(val.len() as u16).to_be_bytes());
    buf.extend_from_slice(val);
    let pad = (4 - (val.len() % 4)) % 4;
    for _ in 0..pad {
        buf.push(0);
    }
}

pub fn stun_hmac_key(psk: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"webrtc-cloak:stun-mi:");
    h.update(psk);
    h.finalize().into()
}

type HmacSha256 = Hmac<Sha256>;

/// RFC 5869 HKDF-SHA256 (Extract + single-block 32-byte Expand, pure Rust zero new deps).
pub fn hkdf_sha256_32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut ext = HmacSha256::new_from_slice(salt).expect("HKDF salt");
    ext.update(ikm);
    let prk = ext.finalize().into_bytes();
    let mut exp = HmacSha256::new_from_slice(&prk).expect("HKDF prk");
    exp.update(info);
    exp.update(&[1u8]);
    exp.finalize().into_bytes().into()
}

/// V4: Derive per-session RFC 8445 `ice-pwd` STUN migration key strictly from `session_key`.
/// When DTLS Hybrid PFS is enabled (default), even a peer holding the global PSK cannot forge a
/// 1-RTT path migration for another session (with `--no-dtls-decoy`, relies on PSK + txid entropy).
pub fn derive_ice_migration_key(session_key: &[u8; 32]) -> [u8; 32] {
    hkdf_sha256_32(b"webrtc-cloak-v4-salt", session_key, b"ice-pwd-v4")
}

/// V4: Compute cryptographic handover proof binding BOTH `old_session_key` and `new_session_key`
/// so a scheduled DTLS 1.3 MBB session can atomically inherit `old_sess`'s `backend_sock` with
/// zero source-port change and zero hijack/replay surface.
pub fn compute_handover_proof(old_session_key: &[u8; 32], new_session_key: &[u8; 32]) -> [u8; 32] {
    hkdf_sha256_32(old_session_key, new_session_key, b"handover-v4")
}

fn finalize_stun_with_key(
    msg_type: u16,
    txid: &[u8; 12],
    body_in: &[u8],
    mi_key: &[u8; 32],
) -> Vec<u8> {
    let mut body = body_in.to_vec();
    let len_for_mi = (body.len() + STUN_MI_TLV_LEN) as u16;
    let mut mac = HmacSha1::new_from_slice(mi_key).expect("HMAC key");
    mac.update(&msg_type.to_be_bytes());
    mac.update(&len_for_mi.to_be_bytes());
    mac.update(&STUN_MAGIC_COOKIE.to_be_bytes());
    mac.update(txid);
    mac.update(&body);
    let digest = mac.finalize().into_bytes();
    push_stun_attr(&mut body, STUN_ATTR_MESSAGE_INTEGRITY, &digest);

    let len_final = (body.len() + STUN_FP_TLV_LEN) as u16;
    let mut out = Vec::with_capacity(STUN_HDR_LEN + body.len() + STUN_FP_TLV_LEN);
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&len_final.to_be_bytes());
    out.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(txid);
    out.extend_from_slice(&body);

    let crc = crc32fast::hash(&out) ^ STUN_FINGERPRINT_XOR;
    push_stun_attr(&mut out, STUN_ATTR_FINGERPRINT, &crc.to_be_bytes());
    out
}

fn finalize_stun(msg_type: u16, txid: &[u8; 12], body_in: &[u8], psk: &[u8]) -> Vec<u8> {
    let mi_key = stun_hmac_key(psk);
    finalize_stun_with_key(msg_type, txid, body_in, &mi_key)
}

pub fn encode_xor_mapped_v4(addr: SocketAddrV4) -> [u8; 8] {
    let x_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let ip_u32 = u32::from(*addr.ip());
    let x_ip = ip_u32 ^ STUN_MAGIC_COOKIE;
    let mut out = [0u8; 8];
    out[0] = 0x00;
    out[1] = 0x01;
    out[2..4].copy_from_slice(&x_port.to_be_bytes());
    out[4..8].copy_from_slice(&x_ip.to_be_bytes());
    out
}

pub fn decode_xor_mapped_v4(val: &[u8]) -> Option<SocketAddrV4> {
    if val.len() < 8 || val[1] != 0x01 {
        return None;
    }
    let x_port = u16::from_be_bytes([val[2], val[3]]);
    let x_ip = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
    let port = x_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let ip = Ipv4Addr::from(x_ip ^ STUN_MAGIC_COOKIE);
    Some(SocketAddrV4::new(ip, port))
}

/// Build an RFC 8445 ICE STUN Binding Request matching libwebrtc attribute ordering:
///   USERNAME -> ICE-CONTROLLING -> [USE-CANDIDATE] -> PRIORITY -> MESSAGE-INTEGRITY -> FINGERPRINT
pub fn build_ice_stun_request(
    psk: &[u8],
    ice: &SessionIceParams,
    txid_opt: Option<[u8; 12]>,
    include_use_candidate: bool,
) -> (Vec<u8>, [u8; 12]) {
    let mi_key = stun_hmac_key(psk);
    build_ice_stun_request_with_key(psk, &mi_key, ice, txid_opt, include_use_candidate)
}

/// Build an RFC 8445 ICE STUN Binding Request signed with an explicit 32B `mi_key`
/// (e.g., V4 per-session DTLS-PFS `mi_key_mig` for 1-RTT path migration, 100% standard wire format).
pub fn build_ice_stun_request_with_key(
    psk: &[u8],
    mi_key: &[u8; 32],
    ice: &SessionIceParams,
    txid_opt: Option<[u8; 12]>,
    include_use_candidate: bool,
) -> (Vec<u8>, [u8; 12]) {
    let txid = txid_opt.unwrap_or_else(|| make_fresh_stun_txid(psk));
    let uname = ice.username();
    let mut body = Vec::with_capacity(64);
    push_stun_attr(&mut body, STUN_ATTR_USERNAME, uname.as_bytes());
    push_stun_attr(&mut body, STUN_ATTR_ICE_CONTROLLING, &ice.tie_breaker);
    if include_use_candidate {
        push_stun_attr(&mut body, STUN_ATTR_USE_CANDIDATE, &[]);
    }
    push_stun_attr(&mut body, STUN_ATTR_PRIORITY, &ice.priority.to_be_bytes());

    let pkt = finalize_stun_with_key(STUN_BINDING_REQUEST, &txid, &body, mi_key);
    (pkt, txid)
}

/// Build an authenticated RFC 8445 ICE STUN Binding Success Response (always 64 bytes).
pub fn build_stun_success_response(txid: &[u8; 12], peer: SocketAddrV4, psk: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(48);
    let xma = encode_xor_mapped_v4(peer);
    push_stun_attr(&mut body, STUN_ATTR_XOR_MAPPED_ADDRESS, &xma);
    finalize_stun(STUN_BINDING_SUCCESS, txid, &body, psk)
}

/// Build an authenticated RFC 8445 ICE STUN Binding Success Response (64 bytes) with explicit `mi_key`.
pub fn build_stun_success_response_with_key(
    txid: &[u8; 12],
    peer: SocketAddrV4,
    mi_key: &[u8; 32],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(48);
    let xma = encode_xor_mapped_v4(peer);
    push_stun_attr(&mut body, STUN_ATTR_XOR_MAPPED_ADDRESS, &xma);
    finalize_stun_with_key(STUN_BINDING_SUCCESS, txid, &body, mi_key)
}

/// Zero-allocation pre-auth peek of `USERNAME` on a framed `STUN_BINDING_REQUEST` so the server
/// can select a session's V4 per-session `mi_key_mig` before running constant-time HMAC verification.
pub fn peek_stun_request_username(data: &[u8]) -> Option<&str> {
    if data.len() < STUN_HDR_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if msg_type != STUN_BINDING_REQUEST
        || magic != STUN_MAGIC_COOKIE
        || !msg_len.is_multiple_of(4)
        || STUN_HDR_LEN + msg_len != data.len()
    {
        return None;
    }
    let mut pos = STUN_HDR_LEN;
    let end = STUN_HDR_LEN + msg_len;
    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let val_start = pos + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return None;
        }
        if attr_type == STUN_ATTR_USERNAME {
            if attr_len == 0 || attr_len > STUN_MAX_USERNAME_LEN {
                return None;
            }
            let s = std::str::from_utf8(&data[val_start..val_end]).ok()?;
            return if s.contains(':') { Some(s) } else { None };
        }
        if attr_type == STUN_ATTR_MESSAGE_INTEGRITY {
            return None;
        }
        let pad = (4 - (attr_len % 4)) % 4;
        pos = val_end + pad;
    }
    None
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ParsedStun {
    pub msg_type: u16,
    pub txid: [u8; 12],
    pub username: Option<String>,
    pub tie_breaker: Option<[u8; 8]>,
    pub use_candidate: bool,
    pub xor_mapped: Option<SocketAddrV4>,
    pub fingerprint_ok: bool,
    pub authenticated: bool,
}

/// Strict RFC 5389 §15.4 + RFC 8445 STUN parser (zero heap allocation before HMAC passes!):
///   - Rejects any attribute appearing AFTER MESSAGE-INTEGRITY except a single trailing FINGERPRINT.
///   - Mandates valid FINGERPRINT at the exact end of packet (`val_end == end`).
///   - Enforces valid `ufrag_r:ufrag_l` username format and ±30s timestamp freshness on requests.
pub fn parse_stun(data: &[u8], psk: &[u8]) -> Option<ParsedStun> {
    let mi_key = stun_hmac_key(psk);
    parse_stun_with_key(data, psk, &mi_key)
}

pub fn parse_stun_with_key(data: &[u8], psk: &[u8], mi_key: &[u8; 32]) -> Option<ParsedStun> {
    if data.len() < STUN_HDR_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != STUN_MAGIC_COOKIE
        || !msg_len.is_multiple_of(4)
        || STUN_HDR_LEN + msg_len != data.len()
    {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&data[8..STUN_HDR_LEN]);

    let mut pos = STUN_HDR_LEN;
    let end = STUN_HDR_LEN + msg_len;
    let mut username_range: Option<(usize, usize)> = None;
    let mut tie_breaker: Option<[u8; 8]> = None;
    let mut use_candidate = false;
    let mut xor_mapped = None;
    let mut seen_mi = false;
    let mut mi_ok = false;
    let mut fp_ok = false;

    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let val_start = pos + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return None;
        }
        let val = &data[val_start..val_end];
        let pad = (4 - (attr_len % 4)) % 4;
        let next_pos = val_end + pad;

        if seen_mi {
            // RFC 5389 §15.4: ONLY a single trailing 8-byte FINGERPRINT may follow MESSAGE-INTEGRITY!
            if attr_type == STUN_ATTR_FINGERPRINT && attr_len == 4 && next_pos == end {
                let expected_crc = crc32fast::hash(&data[..pos]) ^ STUN_FINGERPRINT_XOR;
                let got_crc = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
                fp_ok = got_crc == expected_crc;
                pos = next_pos;
                break;
            } else {
                // Any trailing attribute injected after MESSAGE-INTEGRITY -> immediate rejection!
                return None;
            }
        }

        match attr_type {
            STUN_ATTR_USERNAME => {
                username_range = Some((val_start, val_end));
            }
            STUN_ATTR_ICE_CONTROLLING if attr_len == 8 => {
                let mut tb = [0u8; 8];
                tb.copy_from_slice(val);
                tie_breaker = Some(tb);
            }
            STUN_ATTR_XOR_MAPPED_ADDRESS => {
                xor_mapped = decode_xor_mapped_v4(val);
            }
            STUN_ATTR_USE_CANDIDATE if attr_len == 0 => {
                use_candidate = true;
            }
            STUN_ATTR_MESSAGE_INTEGRITY if attr_len == STUN_MI_ATTR_LEN => {
                seen_mi = true;
                // Must be followed by exact 8-byte FINGERPRINT (next_pos + 8 == end)
                if next_pos + STUN_FP_TLV_LEN != end {
                    return None;
                }
                let mi_hdr_len = ((pos - STUN_HDR_LEN) + STUN_MI_TLV_LEN) as u16;
                let mut mac = HmacSha1::new_from_slice(mi_key).expect("HMAC key");
                mac.update(&msg_type.to_be_bytes());
                mac.update(&mi_hdr_len.to_be_bytes());
                mac.update(&STUN_MAGIC_COOKIE.to_be_bytes());
                mac.update(&txid);
                mac.update(&data[STUN_HDR_LEN..pos]);
                let expected = mac.finalize().into_bytes();
                mi_ok = bool::from(val.ct_eq(&expected[..]));
            }
            STUN_ATTR_FINGERPRINT => {
                // FINGERPRINT without preceding MESSAGE-INTEGRITY -> unauthenticated
                return None;
            }
            _ => {}
        }
        pos = next_pos;
    }

    let mut auth_ok = seen_mi && mi_ok && fp_ok && pos == end;
    let username = if auth_ok {
        if let Some((s, e)) = username_range {
            let raw = &data[s..e];
            if msg_type == STUN_BINDING_REQUEST {
                let valid_uname =
                    !raw.is_empty() && raw.len() <= STUN_MAX_USERNAME_LEN && raw.contains(&b':');
                if !valid_uname || !verify_stun_txid_fresh(psk, &txid) {
                    auth_ok = false;
                    None
                } else {
                    Some(String::from_utf8_lossy(raw).into_owned())
                }
            } else {
                Some(String::from_utf8_lossy(raw).into_owned())
            }
        } else {
            if msg_type == STUN_BINDING_REQUEST {
                auth_ok = false;
            }
            None
        }
    } else {
        None
    };

    Some(ParsedStun {
        msg_type,
        txid,
        username,
        tie_breaker: if auth_ok { tie_breaker } else { None },
        use_candidate,
        xor_mapped,
        fingerprint_ok: fp_ok,
        authenticated: auth_ok,
    })
}
