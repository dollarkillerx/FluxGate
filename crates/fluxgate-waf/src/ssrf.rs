//! SSRF detection. Runs only on URL-shaped values. Flags requests aimed at
//! cloud metadata endpoints (high) and internal/loopback/private hosts (medium),
//! after normalizing obfuscated host forms (decimal/hex IPv4, userinfo, ports).

use fluxgate_core::WafRisk;

/// Parameter names that commonly take a redirect/fetch URL — an *external* URL
/// here is a weak (log-only) signal worth surfacing.
const REDIRECT_PARAMS: &[&str] = &[
    "url",
    "uri",
    "redirect",
    "redirect_uri",
    "next",
    "callback",
    "dest",
    "destination",
    "return",
    "return_to",
    "target",
    "u",
    "link",
    "out",
    "image",
    "img",
    "fetch",
    "feed",
    "host",
    "site",
    "domain",
    "proxy",
];

/// `lower` is the caller's shared lowercased view of the value.
pub fn detect(param: &str, lower: &str) -> Option<(WafRisk, String)> {
    // Metadata paths can appear with any host (or a relative URL).
    const META_PATHS: &[&str] = &[
        "/latest/meta-data/",
        "/computemetadata/",
        "/metadata/instance",
        "/metadata/v1/",
    ];
    for p in META_PATHS {
        if lower.contains(p) {
            return Some((WafRisk::High, "cloud_metadata".into()));
        }
    }

    let scheme = lower.split("://").next().unwrap_or("");
    let dangerous_scheme = matches!(
        scheme,
        s if s.ends_with("file") || s.ends_with("gopher") || s.ends_with("dict") || s.ends_with("ldap") || s.ends_with("tftp")
    ) && lower.contains("://");

    let host = extract_host(lower);

    if let Some(h) = &host {
        // Cloud metadata hostnames / well-known link-local addresses.
        if is_metadata_host(h) {
            return Some((WafRisk::High, "cloud_metadata".into()));
        }
        if is_internal_host(h) {
            return Some((WafRisk::Medium, "internal_host".into()));
        }
    }

    if dangerous_scheme {
        return Some((WafRisk::Medium, format!("scheme:{scheme}")));
    }

    // External URL in a redirect-ish parameter — log-only.
    if host.is_some() && REDIRECT_PARAMS.contains(&param) {
        return Some((WafRisk::Low, "open_redirect_param".into()));
    }

    None
}

/// Extract the host from a `scheme://[user@]host[:port]/…` URL (lowercased
/// input). Returns `None` when there's no authority.
fn extract_host(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    // Authority ends at the first '/', '?', '#'.
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    // Strip userinfo.
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    // IPv6 literal in brackets.
    if let Some(end) = hostport.strip_prefix('[').and_then(|s| s.split(']').next()) {
        return Some(end.to_string());
    }
    // Strip :port.
    let host = hostport.split(':').next().unwrap_or(hostport);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn is_metadata_host(h: &str) -> bool {
    if matches!(
        h,
        "metadata.google.internal" | "metadata.goog" | "169.254.169.254" | "100.100.100.200" // Alibaba Cloud
    ) {
        return true;
    }
    if h.starts_with("metadata.") {
        return true;
    }
    // Numeric-obfuscated forms of 169.254.169.254.
    if let Some(ip) = parse_obfuscated_ipv4(h) {
        return ip == [169, 254, 169, 254];
    }
    false
}

fn is_internal_host(h: &str) -> bool {
    if matches!(h, "localhost" | "0.0.0.0" | "::1" | "::") {
        return true;
    }
    if h.ends_with(".localhost") || h.ends_with(".internal") || h.ends_with(".local") {
        return true;
    }
    if let Some(ip) = parse_obfuscated_ipv4(h) {
        return is_private_v4(ip);
    }
    // Wildcard-DNS-to-internal services (`127.0.0.1.nip.io`, `10.0.0.1.sslip.io`):
    // the leading labels are a private IPv4 that resolves back to the internal
    // host. Flag when the first four dot-labels parse as a private/loopback IP.
    if let Some(rest) = h.splitn(5, '.').nth(4) {
        if !rest.is_empty() {
            let prefix = &h[..h.len() - rest.len() - 1];
            if let Some(ip) = parse_obfuscated_ipv4(prefix) {
                if is_private_v4(ip) {
                    return true;
                }
            }
        }
    }
    // IPv6 loopback / unique-local / link-local.
    if h.starts_with("fd") || h.starts_with("fc") || h.starts_with("fe80:") {
        return true;
    }
    false
}

fn is_private_v4(ip: [u8; 4]) -> bool {
    let a = std::net::Ipv4Addr::from(ip);
    a.is_loopback()        // 127.0.0.0/8
        || a.is_private()  // 10/8, 172.16/12, 192.168/16
        || a.is_link_local() // 169.254/16 (also cloud metadata)
        || ip[0] == 0      // 0.0.0.0/8 ("this network" — resolves to localhost)
        || (ip[0] == 100 && (64..=127).contains(&ip[1])) // 100.64/10 CGNAT
}

/// Parse the obfuscated IPv4 forms attackers use to dodge string filters, with
/// `inet_aton` semantics: each part may be decimal, **octal** (leading `0`, e.g.
/// `0177` = 127) or **hex** (`0x7f`), and 1–4 parts are accepted with the last
/// part absorbing the remaining bytes (`127.1` → 127.0.0.1, `2130706433` →
/// 127.0.0.1). Returns the resolved 4 octets, or `None` if it isn't an IP.
fn parse_obfuscated_ipv4(h: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = h.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let vals: Vec<u32> = parts
        .iter()
        .map(|p| parse_ip_part(p))
        .collect::<Option<_>>()?;
    let n = vals.len();
    // Every part except the last is a single byte; the last absorbs the rest.
    for v in &vals[..n - 1] {
        if *v > 0xff {
            return None;
        }
    }
    let leading = n - 1;
    let last_bits = 8 * (4 - leading) as u32; // 32, 24, 16 or 8
    let last = vals[n - 1];
    if u64::from(last) >= (1u64 << last_bits) {
        return None;
    }
    // Assemble in u64 to avoid an oversized shift on the single-part form.
    let mut addr: u64 = 0;
    for v in &vals[..leading] {
        addr = (addr << 8) | u64::from(*v);
    }
    addr = (addr << last_bits) | u64::from(last);
    Some((addr as u32).to_be_bytes())
}

/// Parse one IPv4 part honoring `inet_aton` base rules (hex `0x…`, octal `0…`,
/// else decimal).
fn parse_ip_part(p: &str) -> Option<u32> {
    if p.is_empty() {
        return None;
    }
    if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if p.len() > 1 && p.starts_with('0') {
        u32::from_str_radix(&p[1..], 8).ok()
    } else {
        p.parse::<u32>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test shim: the real `detect` now takes a pre-lowered view from the caller.
    fn detect(param: &str, v: &str) -> Option<(WafRisk, String)> {
        super::detect(param, &v.to_ascii_lowercase())
    }

    #[test]
    fn metadata_endpoints() {
        assert_eq!(
            detect("url", "http://169.254.169.254/latest/meta-data/")
                .unwrap()
                .0,
            WafRisk::High
        );
        assert_eq!(
            detect("u", "http://metadata.google.internal/").unwrap().0,
            WafRisk::High
        );
    }

    #[test]
    fn obfuscated_metadata_ip() {
        // 169.254.169.254 as a 32-bit decimal.
        let dec = u32::from_be_bytes([169, 254, 169, 254]).to_string();
        assert_eq!(
            detect("url", &format!("http://{dec}/")).unwrap().0,
            WafRisk::High
        );
    }

    #[test]
    fn internal_hosts_medium() {
        assert_eq!(
            detect("u", "http://127.0.0.1:8080/admin").unwrap().0,
            WafRisk::Medium
        );
        assert_eq!(
            detect("u", "http://192.168.1.1/").unwrap().0,
            WafRisk::Medium
        );
        assert_eq!(detect("u", "http://localhost/").unwrap().0, WafRisk::Medium);
    }

    #[test]
    fn external_redirect_param_low() {
        assert_eq!(
            detect("redirect", "https://evil.example.com/").unwrap().0,
            WafRisk::Low
        );
        // Non-redirect param with an external URL → nothing.
        assert!(detect("comment", "https://example.com/").is_none());
    }

    #[test]
    fn file_scheme() {
        assert_eq!(
            detect("u", "file:///etc/passwd").unwrap().0,
            WafRisk::Medium
        );
    }

    #[test]
    fn octal_and_short_loopback_are_internal() {
        // Octal-encoded loopback (inet_aton: 0177 == 127).
        assert_eq!(
            detect("u", "http://0177.0.0.1/").unwrap().0,
            WafRisk::Medium
        );
        // Hex octet.
        assert_eq!(
            detect("u", "http://0x7f.0.0.1/").unwrap().0,
            WafRisk::Medium
        );
        // Short forms.
        assert_eq!(detect("u", "http://127.1/").unwrap().0, WafRisk::Medium);
        assert_eq!(
            detect("u", "http://2130706433/").unwrap().0,
            WafRisk::Medium
        );
    }

    #[test]
    fn obfuscated_metadata_octal() {
        // 169.254.169.254 with an octal first octet (0251 == 169).
        assert_eq!(
            detect("u", "http://0251.254.169.254/").unwrap().0,
            WafRisk::High
        );
    }

    #[test]
    fn relative_metadata_path_high() {
        assert_eq!(
            detect("path", "/latest/meta-data/iam/").unwrap().0,
            WafRisk::High
        );
    }

    #[test]
    fn parse_ip_part_bases() {
        assert_eq!(parse_obfuscated_ipv4("0177.0.0.1"), Some([127, 0, 0, 1]));
        assert_eq!(parse_obfuscated_ipv4("0x7f000001"), Some([127, 0, 0, 1]));
        assert_eq!(parse_obfuscated_ipv4("127.1"), Some([127, 0, 0, 1]));
        assert_eq!(parse_obfuscated_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
        // Not IPs.
        assert_eq!(parse_obfuscated_ipv4("example.com"), None);
        assert_eq!(parse_obfuscated_ipv4("256.0.0.1"), None);
        assert_eq!(parse_obfuscated_ipv4("1.2.3.4.5"), None);
    }
}
