//! SSRF guard for Bitwarden server URLs — 1:1 port of bitwardenClient.js

use std::net::ToSocketAddrs;

// ─── IPv4 helpers ───────────────────────────────────────────────────────

fn v4_to_int(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    let mut n: u32 = 0;
    for p in &parts {
        let v: u32 = p.parse().ok()?;
        if v > 255 { return None; }
        n = n * 256 + v;
    }
    Some(n)
}

fn in_cidr4(ip: u32, base: u32, bits: u32) -> bool {
    let mask = if bits == 0 { 0u32 } else { (!0u32).wrapping_shl(32 - bits) };
    (ip & mask) == (base & mask)
}

/// True when an IPv4 address must not be contacted by this client.
pub fn is_restricted_ipv4(ip: &str) -> bool {
    let n = match v4_to_int(ip) {
        Some(n) => n,
        None => return false,
    };
    let ranges: &[(u32, u32)] = &[
        (0x00000000,  8), // "this network"
        (0x0A000000,  8), // 10.0.0.0/8 private
        (0x64400000, 10), // 100.64.0.0/10 CGNAT
        (0x7F000000,  8), // 127.0.0.0/8 loopback
        (0xA9FE0000, 16), // 169.254.0.0/16 link-local
        (0xAC100000, 12), // 172.16.0.0/12 private
        (0xC0000000, 24), // 192.0.0.0/24 IETF protocol assignments
        (0xC0000200, 24), // 192.0.2.0/24 TEST-NET-1
        (0xC0586300, 24), // 192.88.99.0/24 6to4 relay
        (0xC0A80000, 16), // 192.168.0.0/16 private
        (0xC6120000, 15), // 198.18.0.0/15 benchmarking
        (0xC6336400, 24), // 198.51.100.0/24 TEST-NET-2
        (0xCB007100, 24), // 203.0.113.0/24 TEST-NET-3
        (0xE0000000,  4), // 224.0.0.0/4 multicast
        (0xF0000000,  4), // 240.0.0.0/4 reserved
    ];
    ranges.iter().any(|&(base, bits)| in_cidr4(n, base, bits))
}

fn int_to_v4(n: u32) -> String {
    format!("{}.{}.{}.{}", (n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255)
}

// ─── IPv6 helpers ───────────────────────────────────────────────────────

/// Expand an IPv6 address into its 8 16-bit groups, handling "::" compression
/// and embedded dotted-quad tail. Returns None if unparseable.
fn expand_ipv6(addr: &str) -> Option<Vec<u16>> {
    let trimmed = addr.trim().to_lowercase();
    let s = trimmed.trim_start_matches('[').trim_end_matches(']');
    if s == "::" { return Some(vec![0; 8]); }

    let s = if s.contains('.') {
        // Handle embedded IPv4 tail: split on last ':', parse the IPv4 part
        if let Some(last_colon) = s.rfind(':') {
            let (ipv6_part, ipv4_part) = s.split_at(last_colon);
            let ipv4_part = &ipv6_part[1..]; // skip the ':'
            let n = v4_to_int(ipv4_part)?;
            let high = ((n >> 16) & 0xFFFF) as u16;
            let low = (n & 0xFFFF) as u16;
            format!("{}:{:x}:{:x}", ipv6_part, high, low)
        } else {
            return None;
        }
    } else {
        s.to_string()
    };

    let dc: Vec<&str> = s.split("::").collect();
    if dc.len() > 2 { return None; }

    let head: Vec<&str> = if !dc[0].is_empty() {
        dc[0].split(':').filter(|s| !s.is_empty()).collect()
    } else {
        vec![]
    };
    let tail: Vec<&str> = if dc.len() == 2 && !dc[1].is_empty() {
        dc[1].split(':').filter(|s| !s.is_empty()).collect()
    } else {
        vec![]
    };

    let missing = 8usize.saturating_sub(head.len() + tail.len());
    if dc.len() == 2 && missing < 1 { return None; }
    if dc.len() == 1 && head.len() != 8 { return None; }

    let mut groups: Vec<u16> = Vec::with_capacity(8);
    for g in &head {
        groups.push(u16::from_str_radix(g, 16).ok()?);
    }
    if dc.len() == 2 {
        for _ in 0..missing { groups.push(0); }
    }
    for g in &tail {
        groups.push(u16::from_str_radix(g, 16).ok()?);
    }
    if groups.len() != 8 { return None; }
    Some(groups)
}

/// Evaluate an IPv6 address; returns true if it must NOT be contacted.
pub fn is_restricted_ipv6(ip: &str) -> bool {
    let g = match expand_ipv6(ip) {
        Some(g) => g,
        None => return true, // unparseable → refuse
    };
    if g.iter().all(|&v| v == 0) { return true; } // unspecified

    let low32 = ((g[6] as u32) << 16 | g[7] as u32) as u32;

    // IPv4-mapped ::ffff:0:0/96 and deprecated IPv4-compatible ::/96
    if g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 {
        if g[5] == 0xFFFF { return is_restricted_ipv4(&int_to_v4(low32)); }
        if g[5] == 0 && low32 != 0 { return is_restricted_ipv4(&int_to_v4(low32)); }
    }
    if g[0] == 0x64 && g[1] == 0xFF9B { return true; } // NAT64
    if g[0] == 0x0100 && g[1] == 0 && g[2] == 0 && g[3] == 0 { return true; } // discard-only
    if g[0] == 0x2001 && (g[1] == 0 || g[1] == 0x0DB8) { return true; } // Teredo / documentation
    if g[0] == 0x2002 { return true; } // 6to4
    if (g[0] & 0xFE00) == 0xFC00 { return true; } // unique-local fc00::/7
    if (g[0] & 0xFFC0) == 0xFE80 { return true; } // link-local fe80::/10
    if (g[0] & 0xFF00) == 0xFF00 { return true; } // multicast ff00::/8

    false
}

/// True when an address (v4 or v6 literal) may not be contacted.
pub fn is_restricted_address(address: &str) -> bool {
    if address.contains(':') {
        is_restricted_ipv6(address)
    } else {
        is_restricted_ipv4(address)
    }
}

// ─── URL validation + DNS resolution ────────────────────────────────────

/// DNS lookup result — one resolved address.
pub struct DnsRecord {
    pub address: String,
    pub family: u32, // 4 or 6
}

/// Default DNS lookup (blocking, for production use).
pub fn default_dns_lookup(hostname: &str) -> anyhow::Result<Vec<DnsRecord>> {
    use std::net::ToSocketAddrs;
    let addrs = format!("{hostname}:0").to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("Cannot resolve \"{hostname}\": {e}"))?;
    let mut results = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        let family = if ip.is_ipv4() { 4 } else { 6 };
        results.push(DnsRecord { address: ip.to_string(), family });
    }
    if results.is_empty() {
        anyhow::bail!("Hostname \"{hostname}\" does not resolve.");
    }
    Ok(results)
}

/// Validate a user-supplied vault server URL and return the normalized base
/// (scheme + host + optional path, no trailing slash). Throws on any unsafe
/// or unusable URL.
pub fn resolve_safe_server_url(server_url: &str) -> anyhow::Result<String> {
    let url = url::Url::parse(server_url.trim())
        .map_err(|_| anyhow::anyhow!("Server URL is not a valid URL."))?;

    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        anyhow::bail!("Server URL must use http:// or https://.");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("Server URL must not contain credentials.");
    }

    let host = url.host_str()
        .ok_or_else(|| anyhow::anyhow!("Server URL has no hostname."))?
        .to_lowercase()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_string();

    if host.is_empty() {
        anyhow::bail!("Server URL has no hostname.");
    }
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
        anyhow::bail!("Local hostnames are not allowed. Use the public hostname of your vault server.");
    }

    // Port check
    if let Some(port) = url.port() {
        // port is u16 so always <= 65535; no check needed
    }

    // Literal IP check
    if host.contains(':') {
        // IPv6 literal
        if is_restricted_ipv6(&host) {
            anyhow::bail!("Reserved or private IP addresses are not allowed.");
        }
    } else if let Some(_n) = v4_to_int(&host) {
        if is_restricted_ipv4(&host) {
            anyhow::bail!("Reserved or private IP addresses are not allowed.");
        }
    }

    // DNS resolution check
    let records = default_dns_lookup(&host)?;
    for record in &records {
        if is_restricted_address(&record.address) {
            anyhow::bail!(
                "\"{host}\" resolves to a private or reserved address ({}). \
                 Self-hosted vaults must be reachable via a public hostname.",
                record.address
            );
        }
    }

    // Build normalized base URL
    let path = url.path().trim_end_matches('/');
    let base = if path.is_empty() || path == "/" {
        format!("{}://{}", scheme, host_port(&url))
    } else {
        format!("{}://{}/{}", scheme, host_port(&url), path.trim_start_matches('/'))
    };

    Ok(base)
}

fn host_port(url: &url::Url) -> String {
    match url.port() {
        Some(port) => format!("{}:{}", url.host_str().unwrap_or(""), port),
        None => url.host_str().unwrap_or("").to_string(),
    }
}
