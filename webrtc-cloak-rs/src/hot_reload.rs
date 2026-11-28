//! 零依赖热切换配置文件解析器（支持 `key=value` 与单层扁平 JSON）。
//!
//! 供 `webrtc-cloak relay --hot-config <PATH>` 与 `webrtc-cloak proxy --client --hot-config <PATH>`
//! 在收到 `SIGHUP`（或测试触发器）时原子读取新配置并执行不断网无感热切换。

#[cfg(feature = "embedded-proxy")]
use crate::protocol::{CipherPref, CipherSuite, DtlsMinVersion};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;

/// `relay --hot-config` 支持热更新的配置字段。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayHotConfig {
    pub upstream_mode: Option<String>,
    pub upstream_host: Option<String>,
    pub upstream_port: Option<u16>,
    pub upstream_psk_file: Option<String>,
    pub upstream_psk: Option<String>,
    pub upstream_stun_scope: Option<String>,
    pub psk_file: Option<String>,
    pub psk: Option<String>,
    pub stun_scope: Option<String>,
    pub passthrough_fallback: Option<bool>,
    pub lane_hunt: Option<bool>,
    pub lane_probes: Option<usize>,
    pub lane_rounds: Option<usize>,
    pub rotate_interval_secs: Option<u64>,
}

/// `proxy --client --hot-config` 支持热更新的配置字段。
#[cfg(feature = "embedded-proxy")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyClientHotConfig {
    pub server_host: Option<String>,
    pub server_port: Option<u16>,
    pub psk_file: Option<String>,
    pub psk: Option<String>,
    pub stun_scope: Option<String>,
    pub up_bps: Option<u64>,
    pub down_bps: Option<u64>,
    pub dtls_min_version: Option<DtlsMinVersion>,
    pub cipher_pref: Option<CipherPref>,
    pub lane_hunt: Option<bool>,
    pub lane_probes: Option<usize>,
    pub lane_rounds: Option<usize>,
    pub rotate_interval_secs: Option<u64>,
}

/// 解析 `key=value`（兼容 `#` 注释与引号）或单层扁平 JSON 对象到小写键映射表。
pub fn parse_kv_or_flat_json(raw: &str) -> Result<HashMap<String, String>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }
    if trimmed.starts_with('{') {
        return parse_flat_json(trimmed);
    }
    let mut map = HashMap::new();
    for (idx, line) in trimmed.lines().enumerate() {
        let mut s = line.trim();
        if s.is_empty() || s.starts_with('#') || s.starts_with("//") {
            continue;
        }
        if let Some(rest) = s.strip_prefix("export ") {
            s = rest.trim();
        }
        let Some((k, v)) = s.split_once('=') else {
            return Err(format!("line {}: expected key=value", idx + 1));
        };
        let key = k.trim().to_ascii_lowercase().replace('-', "_");
        if key.is_empty() {
            return Err(format!("line {}: empty key", idx + 1));
        }
        let val = strip_quotes_and_comment(v.trim());
        map.insert(key, val);
    }
    Ok(map)
}

fn strip_quotes_and_comment(val: &str) -> String {
    if val.len() >= 2
        && ((val.starts_with('"') && val.ends_with('"'))
            || (val.starts_with('\'') && val.ends_with('\'')))
    {
        return val[1..val.len() - 1].to_string();
    }
    if let Some((before, _)) = val.split_once(" #") {
        return before.trim().to_string();
    }
    val.to_string()
}

fn parse_flat_json(raw: &str) -> Result<HashMap<String, String>, String> {
    let inner = raw
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| "invalid JSON object: missing closing '}'".to_string())?;
    let mut map = HashMap::new();
    let mut items = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut esc = false;
    for ch in inner.chars() {
        if in_str {
            if esc {
                cur.push(ch);
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
                cur.push(ch);
            } else {
                cur.push(ch);
            }
        } else if ch == '"' {
            in_str = true;
            cur.push(ch);
        } else if ch == ',' {
            items.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    if !cur.trim().is_empty() {
        items.push(cur);
    }
    if in_str {
        return Err("invalid JSON object: unterminated string".to_string());
    }
    for entry in items {
        let e = entry.trim();
        if e.is_empty() {
            continue;
        }
        let Some((k_raw, v_raw)) = e.split_once(':') else {
            return Err(format!("invalid JSON entry: '{}'", e));
        };
        let key = unquote_json_token(k_raw.trim())?
            .to_ascii_lowercase()
            .replace('-', "_");
        if key.is_empty() {
            return Err("invalid JSON entry: empty key".to_string());
        }
        let vt = v_raw.trim();
        if vt == "null" {
            continue;
        }
        let val = unquote_json_token(vt)?;
        map.insert(key, val);
    }
    Ok(map)
}

fn unquote_json_token(tok: &str) -> Result<String, String> {
    if tok.starts_with('"') {
        if tok.len() >= 2 && tok.ends_with('"') {
            Ok(tok[1..tok.len() - 1].to_string())
        } else {
            Err(format!("unterminated JSON string '{}'", tok))
        }
    } else {
        Ok(tok.to_string())
    }
}

fn parse_bool(val: &str, field: &str) -> Result<bool, String> {
    match val.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("invalid boolean for {}: '{}'", field, other)),
    }
}

fn parse_u16(val: &str, field: &str) -> Result<u16, String> {
    val.trim()
        .parse::<u16>()
        .map_err(|_| format!("invalid port/u16 for {}: '{}'", field, val))
}

fn parse_u64(val: &str, field: &str) -> Result<u64, String> {
    val.trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid u64 for {}: '{}'", field, val))
}

fn parse_usize(val: &str, field: &str) -> Result<usize, String> {
    val.trim()
        .parse::<usize>()
        .map_err(|_| format!("invalid usize for {}: '{}'", field, val))
}

#[cfg(feature = "embedded-proxy")]
fn parse_cipher(val: &str) -> Result<CipherPref, String> {
    match val.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(CipherPref::Auto),
        "aes" | "aes128" | "aes-gcm" | "aes-128-gcm" => {
            Ok(CipherPref::Fixed(CipherSuite::Aes128Gcm))
        }
        "chacha" | "chacha20" | "chacha20-poly1305" => {
            Ok(CipherPref::Fixed(CipherSuite::ChaCha20Poly1305))
        }
        "blake2b" | "blake" | "blake2b-128" => Ok(CipherPref::Fixed(CipherSuite::Blake2b)),
        other => Err(format!("invalid cipher '{}'", other)),
    }
}

#[cfg(feature = "embedded-proxy")]
fn parse_dtls_min(val: &str) -> Result<DtlsMinVersion, String> {
    match val.trim().to_ascii_lowercase().as_str() {
        "1.3" | "v1.3" | "1.3-only" | "v13" => Ok(DtlsMinVersion::V13Only),
        "1.2" | "v1.2" | "auto" | "1.3+1.2" => Ok(DtlsMinVersion::Auto),
        other => Err(format!("invalid dtls_min_version '{}'", other)),
    }
}

/// 从磁盘读取并解析 `relay --hot-config` 文件。
pub fn load_relay_hot_config(path: &str) -> Result<RelayHotConfig, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read '{}': {}", path, e))?;
    parse_relay_hot_config(&raw)
}

/// 从文本内容解析 `RelayHotConfig`。
pub fn parse_relay_hot_config(raw: &str) -> Result<RelayHotConfig, String> {
    let map = parse_kv_or_flat_json(raw)?;
    let mut cfg = RelayHotConfig::default();
    if let Some(v) = map.get("upstream_mode") {
        let m = v.trim().to_ascii_lowercase();
        match m.as_str() {
            "passthrough" | "cloak" | "bypass" => cfg.upstream_mode = Some(m),
            other => {
                return Err(format!(
                    "unsupported upstream_mode '{}' (expected passthrough, cloak, or bypass)",
                    other
                ))
            }
        }
    }
    if let Some(v) = map.get("upstream_host").filter(|s| !s.trim().is_empty()) {
        cfg.upstream_host = Some(v.trim().to_string());
    }
    if let Some(v) = map.get("upstream_port").filter(|s| !s.trim().is_empty()) {
        let p = parse_u16(v, "upstream_port")?;
        if p == 0 {
            return Err("upstream_port must be > 0".to_string());
        }
        cfg.upstream_port = Some(p);
    }
    if let Some(v) = map
        .get("upstream_psk_file")
        .filter(|s| !s.trim().is_empty())
    {
        cfg.upstream_psk_file = Some(v.trim().to_string());
    }
    if let Some(v) = map.get("upstream_psk").filter(|s| !s.trim().is_empty()) {
        cfg.upstream_psk = Some(v.trim().to_string());
    }
    if let Some(v) = map.get("upstream_stun_scope") {
        cfg.upstream_stun_scope = Some(v.trim().to_string());
    }
    if let Some(v) = map.get("psk_file").filter(|s| !s.trim().is_empty()) {
        cfg.psk_file = Some(v.trim().to_string());
    }
    if let Some(v) = map.get("psk").filter(|s| !s.trim().is_empty()) {
        cfg.psk = Some(v.trim().to_string());
    }
    if let Some(v) = map.get("stun_scope") {
        cfg.stun_scope = Some(v.trim().to_string());
    }
    if let Some(v) = map
        .get("passthrough_fallback")
        .filter(|s| !s.trim().is_empty())
    {
        cfg.passthrough_fallback = Some(parse_bool(v, "passthrough_fallback")?);
    }
    if let Some(v) = map.get("lane_hunt").filter(|s| !s.trim().is_empty()) {
        cfg.lane_hunt = Some(parse_bool(v, "lane_hunt")?);
    }
    if let Some(v) = map.get("lane_probes").filter(|s| !s.trim().is_empty()) {
        cfg.lane_probes = Some(parse_usize(v, "lane_probes")?);
    }
    if let Some(v) = map.get("lane_rounds").filter(|s| !s.trim().is_empty()) {
        cfg.lane_rounds = Some(parse_usize(v, "lane_rounds")?);
    }
    if let Some(v) = map.get("rotate_interval").filter(|s| !s.trim().is_empty()) {
        cfg.rotate_interval_secs = Some(parse_u64(v, "rotate_interval")?);
    }
    Ok(cfg)
}

/// 从磁盘读取并解析 `proxy --client --hot-config` 文件。
#[cfg(feature = "embedded-proxy")]
pub fn load_proxy_client_hot_config(path: &str) -> Result<ProxyClientHotConfig, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read '{}': {}", path, e))?;
    parse_proxy_client_hot_config(&raw)
}

/// 从文本内容解析 `ProxyClientHotConfig`。
#[cfg(feature = "embedded-proxy")]
pub fn parse_proxy_client_hot_config(raw: &str) -> Result<ProxyClientHotConfig, String> {
    let map = parse_kv_or_flat_json(raw)?;
    let mut cfg = ProxyClientHotConfig::default();
    if let Some(v) = map.get("server_host").filter(|s| !s.trim().is_empty()) {
        cfg.server_host = Some(v.trim().to_string());
    }
    if let Some(v) = map.get("server_port").filter(|s| !s.trim().is_empty()) {
        let p = parse_u16(v, "server_port")?;
        if p == 0 {
            return Err("server_port must be > 0".to_string());
        }
        cfg.server_port = Some(p);
    }
    if let Some(v) = map.get("psk_file").filter(|s| !s.trim().is_empty()) {
        cfg.psk_file = Some(v.trim().to_string());
    }
    if let Some(v) = map.get("psk").filter(|s| !s.trim().is_empty()) {
        cfg.psk = Some(v.trim().to_string());
    }
    if let Some(v) = map.get("stun_scope") {
        cfg.stun_scope = Some(v.trim().to_string());
    }
    if let Some(v) = map
        .get("up")
        .or_else(|| map.get("proxy_up"))
        .filter(|s| !s.trim().is_empty())
    {
        cfg.up_bps = Some(crate::proxy::parse_bandwidth_bps(v)?);
    }
    if let Some(v) = map
        .get("down")
        .or_else(|| map.get("proxy_down"))
        .filter(|s| !s.trim().is_empty())
    {
        cfg.down_bps = Some(crate::proxy::parse_bandwidth_bps(v)?);
    }
    if let Some(v) = map.get("dtls_min_version").filter(|s| !s.trim().is_empty()) {
        cfg.dtls_min_version = Some(parse_dtls_min(v)?);
    }
    if let Some(v) = map.get("cipher").filter(|s| !s.trim().is_empty()) {
        cfg.cipher_pref = Some(parse_cipher(v)?);
    }
    if let Some(v) = map.get("lane_hunt").filter(|s| !s.trim().is_empty()) {
        cfg.lane_hunt = Some(parse_bool(v, "lane_hunt")?);
    }
    if let Some(v) = map.get("lane_probes").filter(|s| !s.trim().is_empty()) {
        cfg.lane_probes = Some(parse_usize(v, "lane_probes")?);
    }
    if let Some(v) = map.get("lane_rounds").filter(|s| !s.trim().is_empty()) {
        cfg.lane_rounds = Some(parse_usize(v, "lane_rounds")?);
    }
    if let Some(v) = map.get("rotate_interval").filter(|s| !s.trim().is_empty()) {
        cfg.rotate_interval_secs = Some(parse_u64(v, "rotate_interval")?);
    }
    Ok(cfg)
}

/// 读取 PSK 文件（去首尾空白，拒绝空密钥）。
pub fn read_psk_file(path: &str) -> Result<Vec<u8>, String> {
    let raw = fs::read_to_string(Path::new(path))
        .map_err(|e| format!("read psk_file '{}': {}", path, e))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("psk_file '{}' is empty", path));
    }
    Ok(trimmed.as_bytes().to_vec())
}

/// 解析 IPv4 / IPv6（兼容方括号）或域名到 `SocketAddr`。
pub fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr, String> {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.is_empty() {
        return Err("empty host".to_string());
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let formatted = if trimmed.contains(':') {
        format!("[{}]:{}", trimmed, port)
    } else {
        format!("{}:{}", trimmed, port)
    };
    formatted
        .to_socket_addrs()
        .map_err(|e| format!("resolve '{}': {}", formatted, e))?
        .next()
        .ok_or_else(|| format!("resolve '{}': no addresses returned", formatted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_relay_hot_config_kv_and_json() {
        let kv = r#"
            # live cutover from cloak to passthrough
            upstream_mode = passthrough
            upstream_host = "198.51.100.20"
            upstream_port = 19643
            passthrough_fallback = true
            lane_hunt = false
        "#;
        let c = parse_relay_hot_config(kv).expect("parse kv");
        assert_eq!(c.upstream_mode.as_deref(), Some("passthrough"));
        assert_eq!(c.upstream_host.as_deref(), Some("198.51.100.20"));
        assert_eq!(c.upstream_port, Some(19643));
        assert_eq!(c.passthrough_fallback, Some(true));
        assert_eq!(c.lane_hunt, Some(false));

        let js = r#"{"upstream_mode":"cloak","upstream_host":"198.51.100.20","upstream_port":19643,"lane_probes":4}"#;
        let c2 = parse_relay_hot_config(js).expect("parse json");
        assert_eq!(c2.upstream_mode.as_deref(), Some("cloak"));
        assert_eq!(c2.upstream_port, Some(19643));
        assert_eq!(c2.lane_probes, Some(4));
    }

    #[cfg(feature = "embedded-proxy")]
    #[test]
    fn parse_proxy_client_hot_config_kv_and_ipv6() {
        let kv = r#"
            SERVER_HOST=2001:db8::15b
            SERVER_PORT=19643
            PSK_FILE=/etc/webrtc-cloak/example.psk
            PROXY_UP=100Mbps
            PROXY_DOWN=450Mbps
            DTLS_MIN_VERSION=1.3
            lane_hunt=true
        "#;
        let c = parse_proxy_client_hot_config(kv).expect("parse proxy kv");
        assert_eq!(c.server_host.as_deref(), Some("2001:db8::15b"));
        assert_eq!(c.server_port, Some(19643));
        assert_eq!(c.psk_file.as_deref(), Some("/etc/webrtc-cloak/example.psk"));
        assert_eq!(c.up_bps, Some(100_000_000));
        assert_eq!(c.down_bps, Some(450_000_000));
        assert_eq!(c.dtls_min_version, Some(DtlsMinVersion::V13Only));
        assert_eq!(c.lane_hunt, Some(true));

        let addr = resolve_host_port("[2001:db8::15b]", 19643).expect("resolve v6");
        assert_eq!(addr.port(), 19643);
        assert!(addr.is_ipv6());
    }

    #[test]
    fn reject_invalid_relay_mode() {
        assert!(parse_relay_hot_config("upstream_mode=bogus").is_err());
        assert!(parse_relay_hot_config("upstream_port=0").is_err());
    }
}
