//! Cloudflare published IP ranges — backing the per-site "only allow Cloudflare"
//! access control.
//!
//! When a site is fronted by Cloudflare, every legitimate connection arrives from
//! a Cloudflare edge IP, so we can drop anything that *doesn't* (a direct-to-origin
//! bypass attempt). The check is against the **TCP peer**, never a forwarded
//! header — a header is trivially spoofable and would defeat the point.
//!
//! Ranges are fetched from Cloudflare at startup (per operator choice), with a
//! bundled snapshot as a fallback when the network is unavailable. Both IPv4 and
//! IPv6 ranges are loaded, so v6 edge connections are matched too.

use std::time::Duration;

use crate::iprange::CidrList;

/// <https://www.cloudflare.com/ips-v4> (snapshot — refreshed by a live fetch at startup).
const BUNDLED_V4: &str = "\
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22";

/// <https://www.cloudflare.com/ips-v6> (snapshot).
const BUNDLED_V6: &str = "\
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32";

const V4_URL: &str = "https://www.cloudflare.com/ips-v4";
const V6_URL: &str = "https://www.cloudflare.com/ips-v6";

/// Fetch one published list; `None` on any network / decode error.
fn fetch(url: &str) -> Option<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(4))
        .timeout_read(Duration::from_secs(4))
        .build();
    let text = agent.get(url).call().ok()?.into_string().ok()?;
    // Sanity check: a valid feed has at least one slash (CIDR).
    if text.contains('/') {
        Some(text)
    } else {
        None
    }
}

/// Load the combined Cloudflare ranges. Each family is fetched live, falling back
/// to the bundled snapshot independently, so a transient failure for one family
/// doesn't discard the other.
pub fn load() -> CidrList {
    let v4 = fetch(V4_URL);
    let v6 = fetch(V6_URL);
    let fetched = v4.is_some() || v6.is_some();
    let combined = format!(
        "{}\n{}",
        v4.as_deref().unwrap_or(BUNDLED_V4),
        v6.as_deref().unwrap_or(BUNDLED_V6),
    );
    let list = CidrList::parse_lines(&combined);
    if fetched {
        tracing::info!("Cloudflare IP ranges loaded ({} CIDRs, live)", list.len());
    } else {
        tracing::warn!(
            "Cloudflare IP ranges: live fetch failed, using bundled snapshot ({} CIDRs)",
            list.len()
        );
    }
    list
}

/// The bundled-only list (no network) — used in tests and as the guaranteed floor.
#[cfg(test)]
pub fn bundled() -> CidrList {
    CidrList::parse_lines(&format!("{BUNDLED_V4}\n{BUNDLED_V6}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_covers_known_cloudflare_ips() {
        let cf = bundled();
        assert!(cf.len() >= 20);
        // Known Cloudflare addresses (v4 + v6) must be inside the ranges.
        assert!(cf.contains_str("104.16.1.1"));
        assert!(cf.contains_str("172.64.0.1"));
        assert!(cf.contains_str("2606:4700:4700::1111")); // 1.1.1.1's v6 sibling space
        assert!(cf.contains_str("2400:cb00::1"));
        // Non-Cloudflare must not match.
        assert!(!cf.contains_str("8.8.8.8"));
        assert!(!cf.contains_str("2001:4860:4860::8888")); // Google v6
    }
}
