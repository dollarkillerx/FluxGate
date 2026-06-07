//! A small but real WAF evaluation engine.
//!
//! Each incoming request is matched against the enabled rules (ascending
//! priority, first match wins). The matched rule's action is returned; if no
//! rule matches, the configured default action applies.
//!
//! The engine runs in **detection mode**: it computes decisions and feeds real
//! hit counters / security events, but the caller does not actually block the
//! request. Enforcement belongs in front of *proxied* traffic, not the admin
//! plane (locking yourself out of the console would be unfortunate). See
//! `docs/INTEGRATION.md`.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use regex::Regex;

use fluxgate_core::*;

/// Per-request context the engine matches against.
pub struct WafContext<'a> {
    pub client_ip: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    /// Lowercased header name → value.
    pub headers: &'a HashMap<String, String>,
}

pub struct WafDecision {
    pub action: WafAction,
    /// Id of the rule that decided this action (the engine itself counts the
    /// hit; exposed for callers/tests that want the matched rule).
    #[allow(dead_code)]
    pub matched_rule_id: Option<String>,
    pub matched_rule_name: Option<String>,
}

#[derive(Default)]
pub struct WafEngine {
    /// Compiled-regex cache (None = pattern failed to compile).
    regex_cache: Mutex<HashMap<String, Option<Regex>>>,
    /// Fixed-window rate counters keyed by `rule_id|client_ip` → (window_sec, count).
    rate: Mutex<HashMap<String, (u64, u32)>>,
    /// Per-rule hit counters (rule_id → count). Kept here instead of mutating the
    /// shared config Store on the request hot path.
    hits: Mutex<HashMap<String, u64>>,
}

impl WafEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate `ctx` against `rules`, falling back to `default` when nothing matches.
    pub fn evaluate(
        &self,
        rules: &[WafRule],
        default: WafAction,
        ctx: &WafContext,
        now_sec: u64,
    ) -> WafDecision {
        let mut enabled: Vec<&WafRule> = rules.iter().filter(|r| r.enabled).collect();
        enabled.sort_by_key(|r| r.priority);

        for rule in enabled {
            if self.matches(rule, ctx, now_sec) {
                // Count the hit here (engine-local) rather than write the Store.
                *self.hits.lock().entry(rule.id.clone()).or_default() += 1;
                return WafDecision {
                    action: rule.action,
                    matched_rule_id: Some(rule.id.clone()),
                    matched_rule_name: Some(rule.name.clone()),
                };
            }
        }
        WafDecision {
            action: default,
            matched_rule_id: None,
            matched_rule_name: None,
        }
    }

    /// Snapshot of per-rule hit counts, overlaid onto rules when listing them.
    pub fn hits(&self) -> HashMap<String, u64> {
        self.hits.lock().clone()
    }

    fn matches(&self, rule: &WafRule, ctx: &WafContext, now_sec: u64) -> bool {
        match rule.match_type {
            WafMatchType::Ip => match_ip(ctx.client_ip, &rule.pattern),
            WafMatchType::Path => self.regex_match(&rule.pattern, ctx.path),
            WafMatchType::Method => self.regex_match(&rule.pattern, ctx.method),
            WafMatchType::Header => self.match_header(&rule.pattern, ctx),
            // GeoIP matching needs a location database we don't ship.
            WafMatchType::Geo => false,
            WafMatchType::RateLimit => self.match_rate_limit(rule, ctx, now_sec),
        }
    }

    /// Header rule pattern format: `Header-Name: <regex>`.
    fn match_header(&self, pattern: &str, ctx: &WafContext) -> bool {
        let Some((name, pat)) = pattern.split_once(':') else {
            return false;
        };
        let value = ctx.headers.get(name.trim().to_lowercase().as_str());
        match value {
            Some(v) => self.regex_match(pat.trim(), v),
            // Empty/missing header: still let the regex decide (e.g. `^$`).
            None => self.regex_match(pat.trim(), ""),
        }
    }

    /// Rate-limit pattern format: `<path-prefix>@<N>r/s`.
    fn match_rate_limit(&self, rule: &WafRule, ctx: &WafContext, now_sec: u64) -> bool {
        let Some((prefix, spec)) = rule.pattern.split_once('@') else {
            return false;
        };
        if !ctx.path.starts_with(prefix.trim()) {
            return false;
        }
        let limit: u32 = spec
            .trim()
            .trim_end_matches("r/s")
            .trim()
            .parse()
            .unwrap_or(0);
        if limit == 0 {
            return false;
        }

        let key = format!("{}|{}", rule.id, ctx.client_ip);
        let mut rate = self.rate.lock();
        let entry = rate.entry(key).or_insert((now_sec, 0));
        if entry.0 != now_sec {
            *entry = (now_sec, 0);
        }
        entry.1 += 1;
        entry.1 > limit
    }

    fn regex_match(&self, pattern: &str, haystack: &str) -> bool {
        let mut cache = self.regex_cache.lock();
        let compiled = cache
            .entry(pattern.to_string())
            .or_insert_with(|| Regex::new(pattern).ok());
        match compiled {
            Some(re) => re.is_match(haystack),
            None => false, // invalid regex never matches
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn rule(match_type: WafMatchType, pattern: &str, action: WafAction) -> WafRule {
        WafRule {
            id: "r1".into(),
            name: "test".into(),
            description: String::new(),
            match_type,
            pattern: pattern.into(),
            action,
            priority: 10,
            enabled: true,
            hit_count: 0,
        }
    }

    fn ctx<'a>(
        ip: &'a str,
        method: &'a str,
        path: &'a str,
        headers: &'a HashMap<String, String>,
    ) -> WafContext<'a> {
        WafContext {
            client_ip: ip,
            method,
            path,
            headers,
        }
    }

    #[test]
    fn ip_cidr_and_exact() {
        assert!(match_ip("10.0.0.5", "10.0.0.0/24"));
        assert!(!match_ip("10.0.1.5", "10.0.0.0/24"));
        assert!(match_ip("10.0.0.5", "10.0.0.5"));
        assert!(!match_ip("10.0.0.6", "10.0.0.5"));
        assert!(match_ip("1.2.3.4", "0.0.0.0/0"));
    }

    #[test]
    fn path_regex_matches_then_default() {
        let h = HashMap::new();
        let engine = WafEngine::new();
        let rules = vec![rule(
            WafMatchType::Path,
            r"(?i)/etc/passwd",
            WafAction::Deny,
        )];
        let d = engine.evaluate(
            &rules,
            WafAction::Allow,
            &ctx("1.1.1.1", "GET", "/etc/passwd", &h),
            0,
        );
        assert_eq!(d.action, WafAction::Deny);
        assert_eq!(d.matched_rule_id.as_deref(), Some("r1"));
        let d2 = engine.evaluate(
            &rules,
            WafAction::Allow,
            &ctx("1.1.1.1", "GET", "/safe", &h),
            0,
        );
        assert_eq!(d2.action, WafAction::Allow);
        assert!(d2.matched_rule_id.is_none());
    }

    #[test]
    fn rate_limit_trips_after_threshold() {
        let h = HashMap::new();
        let engine = WafEngine::new();
        let rules = vec![rule(
            WafMatchType::RateLimit,
            "/@2r/s",
            WafAction::Challenge,
        )];
        let c = ctx("9.9.9.9", "GET", "/api", &h);
        assert_eq!(
            engine.evaluate(&rules, WafAction::Allow, &c, 100).action,
            WafAction::Allow
        ); // 1
        assert_eq!(
            engine.evaluate(&rules, WafAction::Allow, &c, 100).action,
            WafAction::Allow
        ); // 2
        assert_eq!(
            engine.evaluate(&rules, WafAction::Allow, &c, 100).action,
            WafAction::Challenge
        ); // 3 > 2
           // New second window resets.
        assert_eq!(
            engine.evaluate(&rules, WafAction::Allow, &c, 101).action,
            WafAction::Allow
        );
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let h = HashMap::new();
        let engine = WafEngine::new();
        let mut r = rule(WafMatchType::Path, "/", WafAction::Deny);
        r.enabled = false;
        let d = engine.evaluate(&[r], WafAction::Allow, &ctx("1.1.1.1", "GET", "/x", &h), 0);
        assert_eq!(d.action, WafAction::Allow);
    }
}

/// Exact IP match, or IPv4 CIDR (`a.b.c.d/n`).
fn match_ip(client: &str, pattern: &str) -> bool {
    if let Some((base, prefix)) = pattern.split_once('/') {
        let (Ok(net), Ok(ip), Ok(bits)) = (
            base.trim().parse::<Ipv4Addr>(),
            client.parse::<Ipv4Addr>(),
            prefix.trim().parse::<u32>(),
        ) else {
            return false;
        };
        if bits > 32 {
            return false;
        }
        let mask: u32 = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        (u32::from(net) & mask) == (u32::from(ip) & mask)
    } else {
        client == pattern.trim()
    }
}
