//! Dual-stack (IPv4 + IPv6) IP / CIDR matching.
//!
//! Shared by the WAF `Ip` rule type and the per-site access controls
//! (Cloudflare-only, datacenter blocking). The previous WAF matcher was IPv4-only
//! (`u32`), so IPv6 clients silently slipped past IP/CIDR rules — this replaces it
//! with an `IpAddr`-based matcher that handles both families.

use std::net::IpAddr;

/// A single IP or CIDR matcher. `Never` covers an unparseable pattern — it simply
/// never matches (so a typo'd rule fails closed for *matching*, not for traffic).
#[derive(Clone, Debug)]
pub enum IpMatcher {
    Exact(IpAddr),
    /// Network address (already masked to `prefix` bits) + prefix length.
    Cidr {
        net: IpAddr,
        prefix: u8,
    },
    Never,
}

impl IpMatcher {
    /// Parse `"203.0.113.5"`, `"10.0.0.0/24"`, `"2400:cb00::/32"`, `"::1"`, etc.
    pub fn parse(pattern: &str) -> Self {
        let p = pattern.trim();
        if let Some((base, bits)) = p.split_once('/') {
            let (Ok(addr), Ok(prefix)) = (base.trim().parse::<IpAddr>(), bits.trim().parse::<u8>())
            else {
                return IpMatcher::Never;
            };
            let max = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return IpMatcher::Never;
            }
            IpMatcher::Cidr {
                net: mask(addr, prefix),
                prefix,
            }
        } else {
            match p.parse::<IpAddr>() {
                Ok(ip) => IpMatcher::Exact(ip),
                Err(_) => IpMatcher::Never,
            }
        }
    }

    /// Test a parsed `IpAddr` against this matcher (no allocation).
    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            IpMatcher::Exact(e) => *e == ip,
            // Guard the address family *before* masking: a v6 prefix (>32) applied
            // to a v4 address would underflow `32 - prefix`. A cross-family match
            // is always false anyway.
            IpMatcher::Cidr { net, prefix } => {
                net.is_ipv6() == ip.is_ipv6() && mask(ip, *prefix) == *net
            }
            IpMatcher::Never => false,
        }
    }

    /// Convenience: parse `s` then match. A non-IP string never matches.
    pub fn matches_str(&self, s: &str) -> bool {
        s.parse::<IpAddr>()
            .map(|ip| self.matches(ip))
            .unwrap_or(false)
    }
}

/// Mask `addr` to its first `prefix` bits (the network address). A family
/// mismatch can't occur here — the prefix is validated against the family.
fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix as u32)
            };
            IpAddr::V4((u32::from(v4) & m).into())
        }
        IpAddr::V6(v6) => {
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix as u32)
            };
            IpAddr::V6((u128::from(v6) & m).into())
        }
    }
}

/// A list of CIDRs / IPs (e.g. the published Cloudflare ranges). `contains` is a
/// linear scan, which is fine for the small published lists.
#[derive(Default, Clone)]
pub struct CidrList(pub Vec<IpMatcher>);

impl CidrList {
    /// Parse one CIDR/IP per line; blank lines and `#` comments are skipped, and
    /// unparseable lines are dropped (so a partial feed still yields valid entries).
    pub fn parse_lines(text: &str) -> Self {
        CidrList(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(IpMatcher::parse)
                .filter(|m| !matches!(m, IpMatcher::Never))
                .collect(),
        )
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|m| m.matches(ip))
    }

    #[allow(dead_code)] // used by tests + a convenient public API
    pub fn contains_str(&self, s: &str) -> bool {
        s.parse::<IpAddr>()
            .map(|ip| self.contains(ip))
            .unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[allow(dead_code)] // paired with len() (clippy::len_without_is_empty)
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_exact_and_cidr() {
        assert!(IpMatcher::parse("10.0.0.0/24").matches_str("10.0.0.5"));
        assert!(!IpMatcher::parse("10.0.0.0/24").matches_str("10.0.1.5"));
        assert!(IpMatcher::parse("10.0.0.5").matches_str("10.0.0.5"));
        assert!(!IpMatcher::parse("10.0.0.5").matches_str("10.0.0.6"));
        assert!(IpMatcher::parse("0.0.0.0/0").matches_str("1.2.3.4"));
        assert!(!IpMatcher::parse("not-an-ip").matches_str("1.2.3.4"));
    }

    #[test]
    fn ipv6_exact_and_cidr() {
        assert!(IpMatcher::parse("2400:cb00::/32").matches_str("2400:cb00:1234::1"));
        assert!(!IpMatcher::parse("2400:cb00::/32").matches_str("2a06:98c0::1"));
        assert!(IpMatcher::parse("::1").matches_str("::1"));
        assert!(IpMatcher::parse("2606:4700::/32").matches_str("2606:4700:0:1::abcd"));
        // /128 host route.
        assert!(IpMatcher::parse("2606:4700::1/128").matches_str("2606:4700::1"));
        assert!(!IpMatcher::parse("2606:4700::1/128").matches_str("2606:4700::2"));
    }

    #[test]
    fn family_mismatch_never_matches() {
        // A v4 rule must not match a v6 client and vice-versa.
        assert!(!IpMatcher::parse("10.0.0.0/8").matches_str("2400:cb00::1"));
        assert!(!IpMatcher::parse("2400:cb00::/32").matches_str("10.0.0.5"));
        // Regression: a v6 prefix > 32 applied to a v4 address must not panic
        // (would underflow `32 - prefix` without the family guard).
        assert!(!IpMatcher::parse("2001:db8::/48").matches_str("10.0.0.5"));
        assert!(!IpMatcher::parse("2001:db8::/64").matches_str("8.8.8.8"));
        // …and the symmetric direction (v4 /32 vs a v6 client) stays false.
        assert!(!IpMatcher::parse("10.0.0.0/32").matches_str("2001:db8::1"));
    }

    #[test]
    fn cidr_list_contains_both_families() {
        let list = CidrList::parse_lines("# cf\n103.21.244.0/22\n2400:cb00::/32\n\n");
        assert_eq!(list.len(), 2);
        assert!(list.contains_str("103.21.244.10"));
        assert!(list.contains_str("2400:cb00::dead"));
        assert!(!list.contains_str("8.8.8.8"));
        assert!(!list.contains_str("garbage"));
    }
}
