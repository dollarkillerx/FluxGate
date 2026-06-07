//! A small but real, **high-performance** WAF evaluation engine.
//!
//! Design goals:
//! * **Fast hot path.** Rules are *compiled once* (regexes built, CIDRs parsed,
//!   priority-sorted) into an immutable `CompiledRuleSet` published behind an
//!   `RwLock<Arc<…>>`. Evaluation clones one `Arc` (cheap) and iterates — no
//!   per-request allocation, no per-request sort, no per-request regex
//!   compilation or lock on the regex cache. Call [`WafEngine::rebuild`] whenever
//!   the rule set changes.
//! * **Hard to evade.** Path rules match the **path *and* query**, after
//!   percent-decoding (defeats `%2e%2e%2f`-style encoded traversal / injection)
//!   and `\`→`/` normalization. The `regex` crate guarantees linear-time
//!   matching, so attacker-supplied patterns can't cause ReDoS.
//! * **Bounded memory.** The rate-limiter map is capped and evicts stale
//!   windows, so a flood of distinct client IPs can't exhaust memory.
//!
//! Enforcement happens on the **data plane** (the reverse proxy); the admin
//! console is never evaluated, so a `deny /` rule can't lock you out.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use regex::Regex;

use fluxgate_core::*;

/// Per-request context the engine matches against.
pub struct WafContext<'a> {
    pub client_ip: &'a str,
    pub method: &'a str,
    /// Request target — **path + query** (raw, still percent-encoded). The engine
    /// normalizes it before matching.
    pub path: &'a str,
    /// Lowercased header name → value.
    pub headers: &'a HashMap<String, String>,
}

pub struct WafDecision {
    pub action: WafAction,
    /// Id of the rule that decided this action (the engine counts the hit
    /// itself; exposed for callers/tests that want the matched rule).
    #[allow(dead_code)]
    pub matched_rule_id: Option<String>,
    pub matched_rule_name: Option<String>,
}

/// Cap on distinct rate-limit keys held in memory (≈ active clients per second).
const MAX_RATE_KEYS: usize = 100_000;

// ---------------------------------------------------------------------------
// Compiled rule forms (built once by `rebuild`)
// ---------------------------------------------------------------------------

/// Pre-parsed IPv4 matcher (exact address or CIDR network).
enum IpMatcher {
    Exact(u32),
    Cidr { net: u32, mask: u32 },
    Never,
}

impl IpMatcher {
    fn parse(pattern: &str) -> Self {
        let pattern = pattern.trim();
        if let Some((base, bits)) = pattern.split_once('/') {
            let (Ok(net), Ok(bits)) = (base.trim().parse::<Ipv4Addr>(), bits.trim().parse::<u8>())
            else {
                return IpMatcher::Never;
            };
            if bits > 32 {
                return IpMatcher::Never;
            }
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            return IpMatcher::Cidr {
                net: u32::from(net) & mask,
                mask,
            };
        }
        match pattern.parse::<Ipv4Addr>() {
            Ok(ip) => IpMatcher::Exact(u32::from(ip)),
            Err(_) => IpMatcher::Never,
        }
    }

    fn matches(&self, client: &str) -> bool {
        let Ok(ip) = client.parse::<Ipv4Addr>() else {
            return false;
        };
        let ip = u32::from(ip);
        match self {
            IpMatcher::Exact(e) => *e == ip,
            IpMatcher::Cidr { net, mask } => (ip & mask) == *net,
            IpMatcher::Never => false,
        }
    }
}

/// A compiled matcher. `Never` covers GeoIP (no database shipped) and any rule
/// whose pattern failed to compile — both simply never match.
enum Matcher {
    Ip(IpMatcher),
    Path(Regex),
    Method(Regex),
    Header {
        name: String,
        re: Regex,
    },
    RateLimit {
        id: String,
        prefix: String,
        limit: u32,
    },
    Never,
}

struct CompiledRule {
    id: String,
    name: String,
    action: WafAction,
    matcher: Matcher,
}

/// Immutable, priority-sorted, ready-to-run rule set.
#[derive(Default)]
struct CompiledRuleSet {
    rules: Vec<CompiledRule>,
}

fn compile_rule(r: &WafRule) -> CompiledRule {
    let matcher = match r.match_type {
        WafMatchType::Ip => Matcher::Ip(IpMatcher::parse(&r.pattern)),
        WafMatchType::Path => Regex::new(&r.pattern)
            .map(Matcher::Path)
            .unwrap_or(Matcher::Never),
        WafMatchType::Method => Regex::new(&r.pattern)
            .map(Matcher::Method)
            .unwrap_or(Matcher::Never),
        WafMatchType::Header => match r.pattern.split_once(':') {
            Some((name, pat)) => match Regex::new(pat.trim()) {
                Ok(re) => Matcher::Header {
                    name: name.trim().to_lowercase(),
                    re,
                },
                Err(_) => Matcher::Never,
            },
            None => Matcher::Never,
        },
        WafMatchType::RateLimit => match r.pattern.split_once('@') {
            Some((prefix, spec)) => {
                let limit: u32 = spec
                    .trim()
                    .trim_end_matches("r/s")
                    .trim()
                    .parse()
                    .unwrap_or(0);
                if limit == 0 {
                    Matcher::Never
                } else {
                    Matcher::RateLimit {
                        id: r.id.clone(),
                        prefix: prefix.trim().to_string(),
                        limit,
                    }
                }
            }
            None => Matcher::Never,
        },
        // GeoIP needs a location database we don't ship.
        WafMatchType::Geo => Matcher::Never,
    };
    CompiledRule {
        id: r.id.clone(),
        name: r.name.clone(),
        action: r.action,
        matcher,
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub struct WafEngine {
    /// Compiled, priority-sorted rule set. Read lock-free-ish: a read clones the
    /// `Arc` (cheap) and releases the lock before iterating.
    compiled: RwLock<Arc<CompiledRuleSet>>,
    /// Fixed-window rate counters keyed by `rule_id|client_ip` → (window_sec, count).
    rate: Mutex<HashMap<String, (u64, u32)>>,
    /// Per-rule hit counters (rule_id → count) — kept off the shared config Store.
    hits: Mutex<HashMap<String, u64>>,
}

impl WafEngine {
    pub fn new() -> Self {
        Self {
            compiled: RwLock::new(Arc::new(CompiledRuleSet::default())),
            rate: Mutex::new(HashMap::new()),
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// (Re)compile the rule set: filter enabled, sort by ascending priority,
    /// build regexes / parse CIDRs once. Call after any rule mutation.
    pub fn rebuild(&self, rules: &[WafRule]) {
        let mut enabled: Vec<&WafRule> = rules.iter().filter(|r| r.enabled).collect();
        enabled.sort_by_key(|r| r.priority);
        let compiled = CompiledRuleSet {
            rules: enabled.into_iter().map(compile_rule).collect(),
        };
        *self.compiled.write() = Arc::new(compiled);
    }

    /// Evaluate `ctx` against the compiled rules (first match wins, ascending
    /// priority), falling back to `default`. Lock-free on the hot path apart from
    /// the rate/hit counters.
    pub fn evaluate(&self, default: WafAction, ctx: &WafContext, now_sec: u64) -> WafDecision {
        let set = self.compiled.read().clone(); // cheap Arc clone, lock released
        let norm_path = normalize_path(ctx.path);

        for rule in &set.rules {
            if self.matches(&rule.matcher, ctx, &norm_path, now_sec) {
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

    fn matches(&self, m: &Matcher, ctx: &WafContext, norm_path: &str, now_sec: u64) -> bool {
        match m {
            Matcher::Ip(ip) => ip.matches(ctx.client_ip),
            Matcher::Path(re) => re.is_match(norm_path),
            Matcher::Method(re) => re.is_match(ctx.method),
            Matcher::Header { name, re } => {
                let value = ctx.headers.get(name).map(String::as_str).unwrap_or("");
                re.is_match(value)
            }
            Matcher::RateLimit { id, prefix, limit } => {
                self.rate_limited(id, prefix, *limit, ctx.client_ip, norm_path, now_sec)
            }
            Matcher::Never => false,
        }
    }

    /// Per-client fixed-window rate check. The map is capped: when it grows past
    /// `MAX_RATE_KEYS` we drop every entry outside the current second, so a flood
    /// of unique IPs can't exhaust memory.
    fn rate_limited(
        &self,
        id: &str,
        prefix: &str,
        limit: u32,
        client_ip: &str,
        norm_path: &str,
        now_sec: u64,
    ) -> bool {
        if !norm_path.starts_with(prefix) {
            return false;
        }
        let key = format!("{id}|{client_ip}");
        let mut rate = self.rate.lock();
        if rate.len() > MAX_RATE_KEYS {
            rate.retain(|_, (window, _)| *window == now_sec);
        }
        let entry = rate.entry(key).or_insert((now_sec, 0));
        if entry.0 != now_sec {
            *entry = (now_sec, 0);
        }
        entry.1 += 1;
        entry.1 > limit
    }
}

// ---------------------------------------------------------------------------
// Request-target normalization (anti-evasion)
// ---------------------------------------------------------------------------

/// Normalize a request target before matching: percent-decode (up to two passes
/// to catch double-encoding) and fold `\` → `/`. This makes encoded payloads
/// (`%2e%2e%2f`, `..%5c`, `%2553`) match the same rules as their decoded form —
/// matching what the origin will actually interpret.
fn normalize_path(raw: &str) -> Cow<'_, str> {
    // Fast path: clean target (the overwhelming majority) — borrow, no allocation.
    if !raw.contains('%') && !raw.contains('\\') {
        return Cow::Borrowed(raw);
    }
    let mut cur = raw.to_string();
    for _ in 0..2 {
        let decoded = percent_decode(&cur);
        if decoded == cur {
            break;
        }
        cur = decoded;
    }
    if cur.contains('\\') {
        cur = cur.replace('\\', "/");
    }
    Cow::Owned(cur)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn engine_with(rules: &[WafRule]) -> WafEngine {
        let e = WafEngine::new();
        e.rebuild(rules);
        e
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
        assert!(IpMatcher::parse("10.0.0.0/24").matches("10.0.0.5"));
        assert!(!IpMatcher::parse("10.0.0.0/24").matches("10.0.1.5"));
        assert!(IpMatcher::parse("10.0.0.5").matches("10.0.0.5"));
        assert!(!IpMatcher::parse("10.0.0.5").matches("10.0.0.6"));
        assert!(IpMatcher::parse("0.0.0.0/0").matches("1.2.3.4"));
        assert!(!IpMatcher::parse("not-an-ip").matches("1.2.3.4"));
    }

    #[test]
    fn path_regex_matches_then_default() {
        let h = HashMap::new();
        let engine = engine_with(&[rule(
            WafMatchType::Path,
            r"(?i)/etc/passwd",
            WafAction::Deny,
        )]);
        let d = engine.evaluate(
            WafAction::Allow,
            &ctx("1.1.1.1", "GET", "/etc/passwd", &h),
            0,
        );
        assert_eq!(d.action, WafAction::Deny);
        assert_eq!(d.matched_rule_id.as_deref(), Some("r1"));
        let d2 = engine.evaluate(WafAction::Allow, &ctx("1.1.1.1", "GET", "/safe", &h), 0);
        assert_eq!(d2.action, WafAction::Allow);
        assert!(d2.matched_rule_id.is_none());
    }

    #[test]
    fn encoded_traversal_is_decoded_before_matching() {
        let h = HashMap::new();
        let engine = engine_with(&[rule(WafMatchType::Path, r"\.\./", WafAction::Deny)]);
        // Percent-encoded `../` must still be caught.
        let d = engine.evaluate(
            WafAction::Allow,
            &ctx("1.1.1.1", "GET", "/x/%2e%2e/y", &h),
            0,
        );
        assert_eq!(d.action, WafAction::Deny);
        // Double-encoded too.
        let d2 = engine.evaluate(
            WafAction::Allow,
            &ctx("1.1.1.1", "GET", "/%252e%252e/y", &h),
            0,
        );
        assert_eq!(d2.action, WafAction::Deny);
    }

    #[test]
    fn query_string_is_inspected() {
        let h = HashMap::new();
        let engine = engine_with(&[rule(
            WafMatchType::Path,
            r"(?i)union\s+select",
            WafAction::Deny,
        )]);
        // SQLi in the query (path+query target), URL-encoded space.
        let d = engine.evaluate(
            WafAction::Allow,
            &ctx("1.1.1.1", "GET", "/list?q=1%20union%20select%201", &h),
            0,
        );
        assert_eq!(d.action, WafAction::Deny);
    }

    /// Microbenchmark: per-request WAF cost over the real production rule set
    /// (baseline + OWASP CRS pack). Run with:
    ///   cargo test --release -p fluxgate-admin -- --ignored --nocapture bench_evaluate
    #[test]
    #[ignore]
    fn bench_evaluate() {
        use std::time::Instant;
        let mut rules = crate::persist::default_waf_rules();
        rules.extend(crate::waf_packs::pack_rules("owasp-crs").unwrap());
        // Drop rate-limit rules: their stateful counter would short-circuit the
        // benign case (every path matches the `/` prefix) and mask the true
        // full-traversal regex cost we want to measure.
        rules.retain(|r| !matches!(r.match_type, WafMatchType::RateLimit));
        let engine = WafEngine::new();
        engine.rebuild(&rules);
        let h = HashMap::new();
        let iters = 1_000_000u32;

        // Benign request = worst case (every rule is evaluated, none matches).
        let benign = ctx("203.0.113.7", "GET", "/api/v1/users?page=2&sort=name", &h);
        for _ in 0..50_000 {
            engine.evaluate(WafAction::Allow, &benign, 0);
        }
        let t = Instant::now();
        for _ in 0..iters {
            engine.evaluate(WafAction::Allow, &benign, 0);
        }
        let ns = t.elapsed().as_nanos() as f64 / iters as f64;

        // Malicious request = early match (typical for a real attack).
        let mal = ctx("203.0.113.7", "GET", "/x?q=1%20union%20select%201", &h);
        let t2 = Instant::now();
        for _ in 0..iters {
            engine.evaluate(WafAction::Allow, &mal, 0);
        }
        let ns2 = t2.elapsed().as_nanos() as f64 / iters as f64;

        println!(
            "\nWAF evaluate ({} rules, single core):\n  benign  (all rules run): {:>6.0} ns/req  (~{:.1}M req/s)\n  malicious (early match): {:>6.0} ns/req  (~{:.1}M req/s)\n",
            rules.len(), ns, 1e3 / ns, ns2, 1e3 / ns2
        );
    }

    #[test]
    fn rate_limit_trips_after_threshold() {
        let h = HashMap::new();
        let engine = engine_with(&[rule(
            WafMatchType::RateLimit,
            "/@2r/s",
            WafAction::Challenge,
        )]);
        let c = ctx("9.9.9.9", "GET", "/api", &h);
        assert_eq!(
            engine.evaluate(WafAction::Allow, &c, 100).action,
            WafAction::Allow
        ); // 1
        assert_eq!(
            engine.evaluate(WafAction::Allow, &c, 100).action,
            WafAction::Allow
        ); // 2
        assert_eq!(
            engine.evaluate(WafAction::Allow, &c, 100).action,
            WafAction::Challenge
        ); // 3 > 2
        assert_eq!(
            engine.evaluate(WafAction::Allow, &c, 101).action,
            WafAction::Allow
        ); // new window
    }

    #[test]
    fn priority_orders_first_match() {
        let h = HashMap::new();
        let mut low = rule(WafMatchType::Path, "/", WafAction::Challenge);
        low.id = "low".into();
        low.priority = 100;
        let mut high = rule(WafMatchType::Path, "/", WafAction::Deny);
        high.id = "high".into();
        high.priority = 1;
        // Insertion order is low-then-high; the engine must sort and pick `high`.
        let engine = engine_with(&[low, high]);
        let d = engine.evaluate(WafAction::Allow, &ctx("1.1.1.1", "GET", "/x", &h), 0);
        assert_eq!(d.action, WafAction::Deny);
        assert_eq!(d.matched_rule_id.as_deref(), Some("high"));
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let h = HashMap::new();
        let mut r = rule(WafMatchType::Path, "/", WafAction::Deny);
        r.enabled = false;
        let engine = engine_with(&[r]);
        let d = engine.evaluate(WafAction::Allow, &ctx("1.1.1.1", "GET", "/x", &h), 0);
        assert_eq!(d.action, WafAction::Allow);
    }

    #[test]
    fn hit_counts_accumulate() {
        let h = HashMap::new();
        let engine = engine_with(&[rule(WafMatchType::Path, "/x", WafAction::Deny)]);
        for _ in 0..3 {
            engine.evaluate(WafAction::Allow, &ctx("1.1.1.1", "GET", "/x", &h), 0);
        }
        assert_eq!(engine.hits().get("r1").copied(), Some(3));
    }
}
