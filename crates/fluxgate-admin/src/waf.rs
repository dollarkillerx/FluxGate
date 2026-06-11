//! A small but real, **high-performance** WAF evaluation engine.
//!
//! Design goals:
//! * **Fast hot path.** Rules are *compiled once* (regexes built, CIDRs parsed,
//!   priority-sorted) into an immutable `CompiledRuleSet` published behind an
//!   `ArcSwap`. Evaluation reads it wait-free (one `Arc` clone, no lock) and
//!   iterates — no per-request allocation, no per-request sort, no per-request
//!   regex compilation. Call [`WafEngine::rebuild`] whenever the rule set changes.
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
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::http::HeaderMap;
use parking_lot::Mutex;
use regex::Regex;

use fluxgate_core::*;

/// Per-request context the engine matches against.
pub struct WafContext<'a> {
    pub client_ip: &'a str,
    pub method: &'a str,
    /// Request target — **path + query** (raw, still percent-encoded). The engine
    /// normalizes it before matching.
    pub path: &'a str,
    /// The raw request headers. Names are matched case-insensitively (`HeaderMap`
    /// already normalizes them); header **values** are lowercased at match time by
    /// the `Header` matcher (only for the headers a rule references).
    pub headers: &'a HeaderMap,
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

// Dual-stack IP/CIDR matching lives in `iprange` (shared with the per-site
// access controls). `Matcher::Ip` wraps an `iprange::IpMatcher`.
use crate::iprange::IpMatcher;

/// Compiled GeoIP matcher: `country in [..]` (or `not in` / `==` / `!=`).
struct GeoMatcher {
    /// Uppercase ISO-3166-1 alpha-2 country codes.
    countries: Vec<String>,
    /// True for `not in` / `!=` (match when the country is NOT listed).
    negate: bool,
}

/// A compiled matcher. `Never` covers a rule whose pattern failed to compile —
/// it simply never matches.
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
    Geo(GeoMatcher),
    /// Matches against the request body — evaluated by [`WafEngine::evaluate_body`]
    /// (the body is read on the data plane), so it is *inert* during the normal
    /// request-line/header pass in [`WafEngine::evaluate`].
    Body(Regex),
    Never,
}

/// Parse a geo rule pattern like `country in [KP, SY]` / `country not in [US]` /
/// `country == CN` into a `GeoMatcher`.
fn parse_geo(pattern: &str) -> GeoMatcher {
    let lower = pattern.to_lowercase();
    let negate = lower.contains("not in") || pattern.contains("!=");
    // Country codes are inside [...] for the list form, else after the operator.
    let codes = if let (Some(a), Some(b)) = (pattern.find('['), pattern.rfind(']')) {
        &pattern[a + 1..b]
    } else if let Some(i) = pattern.rfind(['=', '>', '<']) {
        &pattern[i + 1..]
    } else {
        ""
    };
    let countries = codes
        .split(',')
        .map(|s| {
            s.chars()
                .filter(char::is_ascii_alphabetic)
                .collect::<String>()
                .to_uppercase()
        })
        .filter(|s| s.len() == 2)
        .collect();
    GeoMatcher { countries, negate }
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
    /// Whether any enabled rule inspects the body. Lets the data plane skip the
    /// body-prefix read entirely when no body rules are active (zero cost).
    has_body: bool,
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
        // Real GeoIP matching when a database is loaded (see WafEngine.geo).
        WafMatchType::Geo => Matcher::Geo(parse_geo(&r.pattern)),
        WafMatchType::Body => Regex::new(&r.pattern)
            .map(Matcher::Body)
            .unwrap_or(Matcher::Never),
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
    /// Compiled, priority-sorted rule set. Published behind `ArcSwap` for
    /// **wait-free** reads: the hot path uses `load()` (a guard — no lock and no
    /// per-request `Arc` refcount bump, so no cross-core cache-line bounce), then
    /// the engine iterates the snapshot.
    compiled: ArcSwap<CompiledRuleSet>,
    /// Fixed-window rate counters keyed by `rule_id|client_ip` → (window_sec, count).
    rate: Mutex<HashMap<String, (u64, u32)>>,
    /// Per-rule hit counters (rule_id → count) — kept off the shared config Store.
    hits: Mutex<HashMap<String, u64>>,
    /// Optional GeoIP country database (MaxMind `.mmdb`). When absent, `geo`
    /// rules never match.
    geo: Option<maxminddb::Reader<Vec<u8>>>,
    /// Optional GeoLite2-ASN database. When absent, `is_datacenter` is always false.
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    /// Structure-aware semantic detection engine (12 modules: SQLi/XSS/traversal/…).
    /// Runs *after* the regex rules — only when they reach the default `Allow`,
    /// so an explicit allow/deny rule still short-circuits.
    semantic: fluxgate_waf::SemanticEngine,
    /// Published snapshot of the semantic policy (modes / per-module actions /
    /// exceptions), read on the hot path to map detections to actions.
    semantic_cfg: ArcSwap<WafSemanticConfig>,
    /// Count of times a semantic detector panicked on adversarial input and was
    /// caught (fail-open). A non-zero value is an alert: a payload found an
    /// untested code path. Surfaced to the admin metrics.
    detector_panics: AtomicU64,
}

impl WafEngine {
    /// Create an engine, optionally with loaded GeoIP country + ASN databases.
    pub fn new(
        geo: Option<maxminddb::Reader<Vec<u8>>>,
        asn: Option<maxminddb::Reader<Vec<u8>>>,
    ) -> Self {
        Self {
            compiled: ArcSwap::from_pointee(CompiledRuleSet::default()),
            rate: Mutex::new(HashMap::new()),
            hits: Mutex::new(HashMap::new()),
            geo,
            asn,
            semantic: fluxgate_waf::SemanticEngine::new(),
            semantic_cfg: ArcSwap::from_pointee(WafSemanticConfig::default()),
            detector_panics: AtomicU64::new(0),
        }
    }

    /// How many times a semantic detector panicked and was caught (fail-open).
    pub fn detector_panics(&self) -> u64 {
        self.detector_panics.load(Ordering::Relaxed)
    }

    /// Run a semantic detector pass under a panic boundary. The detectors parse
    /// fully attacker-controlled bytes; a bug there (e.g. the out-of-bounds slice
    /// the audit found) must not abort the request worker. On panic we count it,
    /// log loudly, and **fail open** (no detections) — availability over a
    /// possible single-payload bypass, the commercial-WAF default. `parking_lot`
    /// locks don't poison, so catching the unwind here is sound.
    fn guard_detect(
        &self,
        what: &str,
        f: impl FnOnce() -> Vec<fluxgate_waf::Detection>,
    ) -> Vec<fluxgate_waf::Detection> {
        match std::panic::catch_unwind(AssertUnwindSafe(f)) {
            Ok(v) => v,
            Err(_) => {
                self.detector_panics.fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    target: "fluxgate::waf",
                    detector = what,
                    "semantic WAF detector panicked — failing open for this request"
                );
                Vec::new()
            }
        }
    }

    /// Load a MaxMind `.mmdb` reader from a file (best effort). Used for both the
    /// country and ASN databases.
    pub fn load_geoip(path: &std::path::Path) -> Option<maxminddb::Reader<Vec<u8>>> {
        let bytes = std::fs::read(path).ok()?;
        maxminddb::Reader::from_source(bytes).ok()
    }

    /// (Re)compile the rule set: filter enabled, sort by ascending priority,
    /// build regexes / parse CIDRs once. Call after any rule mutation.
    pub fn rebuild(&self, rules: &[WafRule]) {
        let mut enabled: Vec<&WafRule> = rules.iter().filter(|r| r.enabled).collect();
        enabled.sort_by_key(|r| r.priority);
        let rules: Vec<CompiledRule> = enabled.into_iter().map(compile_rule).collect();
        let has_body = rules.iter().any(|r| matches!(r.matcher, Matcher::Body(_)));
        let compiled = CompiledRuleSet { rules, has_body };
        self.compiled.store(Arc::new(compiled));
    }

    /// Evaluate `ctx` against the compiled rules (first match wins, ascending
    /// priority), falling back to `default`. Lock-free on the hot path apart from
    /// the rate/hit counters.
    pub fn evaluate(&self, default: WafAction, ctx: &WafContext, now_sec: u64) -> WafDecision {
        let set = self.compiled.load(); // wait-free read, no lock, no refcount bump
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

    /// Evaluate the request **body** against `Body` rules only (first match wins,
    /// ascending priority). Returns `Some(decision)` on the first matching body
    /// rule, or `None` if none match (→ caller keeps the request).
    ///
    /// Kept separate from [`evaluate`] for two reasons: the body is read on the
    /// data plane only when needed (so the request-line pass can short-circuit a
    /// deny without ever touching the body), and re-running the full rule set
    /// would double-count the stateful rate-limit counters. `raw` is the decoded
    /// body prefix; it is normalized once here (percent / `+` / `\`).
    pub fn evaluate_body(&self, raw: &str) -> Option<WafDecision> {
        let set = self.compiled.load(); // wait-free read, no lock, no refcount bump
        let norm = normalize_body(raw);
        for rule in &set.rules {
            if let Matcher::Body(re) = &rule.matcher {
                if re.is_match(&norm) {
                    *self.hits.lock().entry(rule.id.clone()).or_default() += 1;
                    return Some(WafDecision {
                        action: rule.action,
                        matched_rule_id: Some(rule.id.clone()),
                        matched_rule_name: Some(rule.name.clone()),
                    });
                }
            }
        }
        None
    }

    /// Whether any enabled rule inspects the request body. The data plane checks
    /// this before reading a body prefix, so body inspection is truly zero-cost
    /// when no body rules are active.
    pub fn has_body_rules(&self) -> bool {
        self.compiled.load().has_body
    }

    /// (Re)load the semantic-engine policy. Call after any `waf.semantic.*` or
    /// `waf.exception.*` mutation (alongside [`rebuild`] for rule changes).
    pub fn rebuild_semantic(&self, cfg: &WafSemanticConfig) {
        self.semantic.rebuild(cfg);
        self.semantic_cfg.store(Arc::new(cfg.clone()));
    }

    /// Whether the data plane should read a body prefix for *either* a regex body
    /// rule or an enabled semantic module.
    pub fn wants_body(&self) -> bool {
        self.has_body_rules() || self.semantic.wants_body()
    }

    /// Run the semantic detectors over the request line + headers and map the
    /// detections through the policy (exceptions, per-module risk actions,
    /// monitor mode). `path` is the request path (without query) for exception
    /// matching. Returns `None` when nothing fires.
    pub fn semantic_evaluate(
        &self,
        path_and_query: &str,
        headers: &HeaderMap,
        path: &str,
        mode_override: Option<WafMode>,
    ) -> Option<crate::waf_semantic::SemanticOutcome> {
        let cfg = self.semantic_cfg.load();
        let dets = self.guard_detect("analyze_request", || {
            self.semantic.analyze_request(path_and_query, headers)
        });
        crate::waf_semantic::decide(&cfg, mode_override.unwrap_or(cfg.mode), path, dets)
    }

    /// Like [`semantic_evaluate`] but for a request **body** prefix.
    pub fn semantic_evaluate_body(
        &self,
        content_type: Option<&str>,
        body: &str,
        path: &str,
        mode_override: Option<WafMode>,
    ) -> Option<crate::waf_semantic::SemanticOutcome> {
        let cfg = self.semantic_cfg.load();
        let dets = self.guard_detect("analyze_body", || {
            self.semantic.analyze_body(content_type, body)
        });
        crate::waf_semantic::decide(&cfg, mode_override.unwrap_or(cfg.mode), path, dets)
    }

    /// Snapshot of per-rule hit counts, overlaid onto rules when listing them.
    pub fn hits(&self) -> HashMap<String, u64> {
        self.hits.lock().clone()
    }

    fn matches(&self, m: &Matcher, ctx: &WafContext, norm_path: &str, now_sec: u64) -> bool {
        match m {
            Matcher::Ip(ip) => ip.matches_str(ctx.client_ip),
            Matcher::Path(re) => re.is_match(norm_path),
            Matcher::Method(re) => re.is_match(ctx.method),
            Matcher::Header { name, re } => {
                // Lowercase the value at match time (only for the headers a rule
                // names) — preserves the prior behavior where the regex matched a
                // lowercased value, without building a lowercased copy of *every*
                // header on every request. `to_str` fails closed on non-UTF-8 bytes.
                let value = ctx
                    .headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                re.is_match(&value)
            }
            Matcher::RateLimit { id, prefix, limit } => {
                self.rate_limited(id, prefix, *limit, ctx.client_ip, norm_path, now_sec)
            }
            Matcher::Geo(gm) => self.geo_matches(gm, ctx.client_ip),
            // Body rules need the request body, which isn't part of the request-line
            // pass; they are evaluated by `evaluate_body` instead. Inert here.
            Matcher::Body(_) => false,
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

    /// Resolve a client IP's ISO-3166-1 alpha-2 country code via the GeoIP DB.
    /// `None` if no DB is loaded, the IP is unparseable, or the country is
    /// unknown (e.g. private / localhost addresses).
    pub fn country_of(&self, client_ip: &str) -> Option<String> {
        let reader = self.geo.as_ref()?;
        let ip = client_ip.parse::<std::net::IpAddr>().ok()?;
        reader
            .lookup::<maxminddb::geoip2::Country>(ip)
            .ok()
            .and_then(|c| c.country.and_then(|x| x.iso_code.map(|s| s.to_uppercase())))
    }

    /// Test a geo rule against the client IP. No database / unknown country →
    /// no match (so private / localhost addresses are never geo-blocked).
    fn geo_matches(&self, gm: &GeoMatcher, client_ip: &str) -> bool {
        match self.country_of(client_ip) {
            Some(code) => gm.countries.contains(&code) ^ gm.negate,
            None => false,
        }
    }

    /// Resolve a client IP's autonomous-system number via the GeoLite2-ASN DB.
    pub fn asn_of(&self, client_ip: &str) -> Option<u32> {
        let reader = self.asn.as_ref()?;
        let ip = client_ip.parse::<std::net::IpAddr>().ok()?;
        reader
            .lookup::<maxminddb::geoip2::Asn>(ip)
            .ok()
            .and_then(|a| a.autonomous_system_number)
    }

    /// Whether the client IP belongs to a known datacenter / cloud / hosting ASN
    /// (the "not residential" approximation). `false` when the ASN DB is absent or
    /// the IP isn't in the blocklist — so private / unknown addresses pass.
    pub fn is_datacenter(&self, client_ip: &str) -> bool {
        match self.asn_of(client_ip) {
            Some(asn) => DATACENTER_ASNS.binary_search(&asn).is_ok(),
            None => false,
        }
    }
}

/// Well-known datacenter / cloud / hosting ASNs — the basis of the per-site
/// "block non-residential" control. **Kept sorted** for `binary_search`.
///
/// This is an honest approximation: it reliably catches the major clouds and VPS
/// providers, but can't cover every small host or residential-proxy network.
/// Treat it as "block known datacenter/cloud sources", not a guarantee of
/// residential-only traffic.
const DATACENTER_ASNS: &[u32] = &[
    8068,   // Microsoft
    8075,   // Microsoft / Azure
    9009,   // M247
    13335,  // Cloudflare
    14061,  // DigitalOcean
    14525,  // DigitalOcean
    14618,  // Amazon AWS
    15169,  // Google
    16276,  // OVH
    16509,  // Amazon AWS
    20473,  // Vultr / Choopa
    24940,  // Hetzner
    31898,  // Oracle Cloud
    36352,  // ColoCrossing
    37963,  // Alibaba Cloud (CN)
    45090,  // Tencent Cloud
    45102,  // Alibaba Cloud (intl)
    49981,  // WorldStream
    51167,  // Contabo
    53667,  // FranTech / BuyVM
    60781,  // LeaseWeb
    62567,  // DigitalOcean
    63949,  // Linode / Akamai
    132203, // Tencent
    209242, // Cloudflare
    393406, // DigitalOcean
    396982, // Google Cloud
];

// ---------------------------------------------------------------------------
// Request-target normalization (anti-evasion)
// ---------------------------------------------------------------------------

/// Normalize a request target before matching, via the **one canonical decoder**
/// shared with the semantic engine (`fluxgate_waf::decode`): percent (incl. the
/// IIS `%uXXXX` form), HTML entities, and `\uXXXX`/`\xHH` escapes — to fixpoint —
/// then fold `\` → `/`. So encoded payloads (`%2e%2e%2f`, `..%5c`, `&lt;`,
/// `<`) match the same rules as their decoded form, and the regex and
/// semantic engines can never disagree about what an input decodes to.
fn normalize_path(raw: &str) -> Cow<'_, str> {
    let decoded = fluxgate_waf::decode::decode_value(raw, WafLocation::Path);
    fold_backslash(decoded.text)
}

/// Normalize a request-body prefix before matching. Like [`normalize_path`] but
/// the `BodyForm` location also folds `+` → space (the form-urlencoded
/// convention).
///
/// This is **detection-only**: the bytes forwarded upstream are the original,
/// unmodified body (see `PrefixBody` in `proxy.rs`). Over-decoding can therefore
/// only ever cause a false positive — never corrupt a proxied request — which is
/// the safe direction for a WAF.
fn normalize_body(raw: &str) -> Cow<'_, str> {
    let decoded = fluxgate_waf::decode::decode_value(raw, WafLocation::BodyForm);
    fold_backslash(decoded.text)
}

/// Fold `\` → `/` (a regex-engine concern the shared decoder leaves alone),
/// borrowing through when there's no backslash.
fn fold_backslash(v: Cow<'_, str>) -> Cow<'_, str> {
    if v.contains('\\') {
        Cow::Owned(v.replace('\\', "/"))
    } else {
        v
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
            user_modified: false,
        }
    }

    fn engine_with(rules: &[WafRule]) -> WafEngine {
        let e = WafEngine::new(None, None);
        e.rebuild(rules);
        e
    }

    fn ctx<'a>(
        ip: &'a str,
        method: &'a str,
        path: &'a str,
        headers: &'a HeaderMap,
    ) -> WafContext<'a> {
        WafContext {
            client_ip: ip,
            method,
            path,
            headers,
        }
    }

    /// What does turning the WAF *on* cost per request? This measures exactly the
    /// work the data plane adds inside `if waf_enabled` — the regex `evaluate`
    /// pass plus (when no regex rule matched) the semantic `semantic_evaluate`
    /// pass — against a realistic OWASP-CRS ruleset with every semantic module on.
    /// "WAF off" skips this block entirely, so the number below *is* the delta.
    /// Run: `cargo test -p fluxgate-admin --release waf_overhead -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_waf_overhead() {
        use std::time::Instant;
        let rules = crate::waf_packs::pack_rules("owasp-crs").unwrap();
        let nrules = rules.len();
        let engine = WafEngine::new(None, None);
        engine.rebuild(&rules);
        engine.rebuild_semantic(&WafSemanticConfig::default());

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64)".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::COOKIE,
            "sid=abc123; theme=dark; lang=en".parse().unwrap(),
        );
        let now = 1_700_000_000u64;
        let iters = 200_000u32;

        // One full WAF pass: regex eval, then semantic eval iff no regex rule
        // decided (the proxy short-circuits the same way).
        let waf_pass = |pq: &str, path: &str| {
            let c = ctx("203.0.113.7", "GET", pq, &headers);
            let d = engine.evaluate(WafAction::Allow, &c, now);
            if d.matched_rule_id.is_none() {
                std::hint::black_box(engine.semantic_evaluate(pq, &headers, path, None));
            }
            std::hint::black_box(d.action);
        };

        let bench = |pq: &str, path: &str| -> f64 {
            for _ in 0..20_000 {
                waf_pass(pq, path);
            }
            let t = Instant::now();
            for _ in 0..iters {
                waf_pass(std::hint::black_box(pq), std::hint::black_box(path));
            }
            t.elapsed().as_nanos() as f64 / iters as f64
        };

        let benign = bench(
            "/api/v1/users?page=2&sort=name&filter=active&q=hello+world",
            "/api/v1/users",
        );
        let attack = bench(
            "/x?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
            "/x",
        );
        println!(
            "\nWAF cost per request (off = 0; CRS {nrules} regex rules + all 12 semantic modules):\n  \
             benign GET (regex eval + semantic, no match): {benign:>7.0} ns/req\n  \
             attack GET (SQLi — regex rule matches early):  {attack:>7.0} ns/req\n"
        );
    }

    // IP/CIDR matching (v4 + v6) is tested in `iprange`; here we only cover the
    // engine wiring through `Matcher::Ip`.
    #[test]
    fn datacenter_asns_are_sorted_and_unique() {
        // `is_datacenter` uses binary_search, which is only correct on a sorted
        // list. Guard against an out-of-order edit.
        let mut sorted = DATACENTER_ASNS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted, DATACENTER_ASNS,
            "DATACENTER_ASNS must stay sorted + unique for binary_search"
        );
    }

    #[test]
    fn detector_panic_fails_open_and_is_counted() {
        let engine = WafEngine::new(None, None);
        // Silence the intentional panic's default stderr backtrace.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let out = engine.guard_detect("test", || panic!("boom"));
        std::panic::set_hook(prev);
        assert!(
            out.is_empty(),
            "a panicking detector must fail open (no detections)"
        );
        assert_eq!(engine.detector_panics(), 1, "the panic must be counted");
        // A normal pass returns its value and leaves the counter untouched.
        let ok = engine.guard_detect("test", Vec::new);
        assert!(ok.is_empty());
        assert_eq!(engine.detector_panics(), 1);
    }

    #[test]
    fn ip_rule_matches_v4_and_v6() {
        let h = HeaderMap::new();
        let engine = engine_with(&[
            rule(WafMatchType::Ip, "10.0.0.0/24", WafAction::Deny),
            rule(WafMatchType::Ip, "2400:cb00::/32", WafAction::Deny),
        ]);
        assert_eq!(
            engine
                .evaluate(WafAction::Allow, &ctx("10.0.0.9", "GET", "/", &h), 0)
                .action,
            WafAction::Deny
        );
        assert_eq!(
            engine
                .evaluate(WafAction::Allow, &ctx("2400:cb00::1", "GET", "/", &h), 0)
                .action,
            WafAction::Deny
        );
        assert_eq!(
            engine
                .evaluate(WafAction::Allow, &ctx("8.8.8.8", "GET", "/", &h), 0)
                .action,
            WafAction::Allow
        );
    }

    #[test]
    fn path_regex_matches_then_default() {
        let h = HeaderMap::new();
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
        let h = HeaderMap::new();
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
    fn canonical_decoder_catches_entity_and_unicode_evasion() {
        // The unified normalizer gives the regex engine the semantic engine's full
        // decoding: HTML entities, `%uXXXX`, and `\xHH`/`\uXXXX` escapes now match.
        let h = HeaderMap::new();
        let engine = engine_with(&[rule(WafMatchType::Path, r"<script", WafAction::Deny)]);
        for target in [
            "/p?q=&lt;script",   // HTML entity
            "/p?q=%3Cscript",    // percent
            "/p?q=%u003Cscript", // IIS %uXXXX
        ] {
            let d = engine.evaluate(WafAction::Allow, &ctx("1.1.1.1", "GET", target, &h), 0);
            assert_eq!(d.action, WafAction::Deny, "should decode + match: {target}");
        }
        // Body: `\x3c` unicode escape decodes to `<`.
        let body_engine = engine_with(&[rule(WafMatchType::Body, r"<script", WafAction::Deny)]);
        let d = body_engine.evaluate_body(r"q=\x3cscript");
        assert_eq!(d.map(|d| d.action), Some(WafAction::Deny));
    }

    #[test]
    fn query_string_is_inspected() {
        let h = HeaderMap::new();
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
        let engine = WafEngine::new(None, None);
        engine.rebuild(&rules);
        let h = HeaderMap::new();
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

    /// Microbenchmark for the **body** pass over the real default body ruleset.
    ///   cargo test --release -p fluxgate-admin -- --ignored --nocapture bench_evaluate_body
    #[test]
    #[ignore]
    fn bench_evaluate_body() {
        use std::hint::black_box;
        use std::time::Instant;
        let engine = WafEngine::new(None, None);
        engine.rebuild(&crate::persist::default_waf_rules());
        let iters = 1_000_000u32;

        // Benign form body = worst case (all 4 body rules run, none matches).
        let benign = "username=alice&password=hunter2&remember=true&token=9f8c2a1b4d6e0011";
        for _ in 0..50_000 {
            black_box(engine.evaluate_body(black_box(benign)));
        }
        let t = Instant::now();
        for _ in 0..iters {
            black_box(engine.evaluate_body(black_box(benign)));
        }
        let ns = t.elapsed().as_nanos() as f64 / iters as f64;

        // Malicious form body = early match; the '+' forces a normalize allocation.
        let mal = "q=1+union+select+username,password+from+users--";
        let t2 = Instant::now();
        for _ in 0..iters {
            black_box(engine.evaluate_body(black_box(mal)));
        }
        let ns2 = t2.elapsed().as_nanos() as f64 / iters as f64;

        println!(
            "\nWAF evaluate_body (4 body rules, single core):\n  benign  (all rules run): {:>6.0} ns/req  (~{:.1}M req/s)\n  malicious (early match): {:>6.0} ns/req  (~{:.1}M req/s)\n",
            ns, 1e3 / ns, ns2, 1e3 / ns2
        );
    }

    #[test]
    fn rate_limit_trips_after_threshold() {
        let h = HeaderMap::new();
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
        let h = HeaderMap::new();
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
    fn geo_pattern_parsing() {
        let g = parse_geo("country in [KP, SY]");
        assert_eq!(g.countries, vec!["KP", "SY"]);
        assert!(!g.negate);
        let g = parse_geo("country not in [US, CA]");
        assert_eq!(g.countries, vec!["US", "CA"]);
        assert!(g.negate);
        let g = parse_geo("country == cn");
        assert_eq!(g.countries, vec!["CN"]);
        assert!(!g.negate);
        let g = parse_geo("country != RU");
        assert_eq!(g.countries, vec!["RU"]);
        assert!(g.negate);
    }

    #[test]
    fn geo_never_matches_without_database() {
        // No DB loaded → geo rules are inert (never match).
        let engine = engine_with(&[rule(WafMatchType::Geo, "country in [KP]", WafAction::Deny)]);
        let h = HeaderMap::new();
        let d = engine.evaluate(WafAction::Allow, &ctx("175.45.176.1", "GET", "/", &h), 0);
        assert_eq!(d.action, WafAction::Allow);
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let h = HeaderMap::new();
        let mut r = rule(WafMatchType::Path, "/", WafAction::Deny);
        r.enabled = false;
        let engine = engine_with(&[r]);
        let d = engine.evaluate(WafAction::Allow, &ctx("1.1.1.1", "GET", "/x", &h), 0);
        assert_eq!(d.action, WafAction::Allow);
    }

    #[test]
    fn body_rule_matches_decoded_body() {
        let engine = engine_with(&[rule(
            WafMatchType::Body,
            r"(?i)union\s+select",
            WafAction::Deny,
        )]);
        // Form-urlencoded SQLi: '+' → space, '%20'/'%27' decoded.
        let d = engine.evaluate_body("q=1+union+select+1").unwrap();
        assert_eq!(d.action, WafAction::Deny);
        let d2 = engine.evaluate_body("name=alice&age=30");
        assert!(d2.is_none());
    }

    #[test]
    fn body_rule_inert_in_request_line_pass() {
        // A Body rule must never fire during the normal (no-body) evaluate pass,
        // otherwise it would block on the request line and never see the body.
        let h = HeaderMap::new();
        let engine = engine_with(&[rule(WafMatchType::Body, r"(?i)evil", WafAction::Deny)]);
        let d = engine.evaluate(WafAction::Allow, &ctx("1.1.1.1", "POST", "/evil", &h), 0);
        assert_eq!(d.action, WafAction::Allow);
    }

    #[test]
    fn body_normalization_catches_encoded_payload() {
        let engine = engine_with(&[rule(WafMatchType::Body, r"<script", WafAction::Deny)]);
        // Percent-encoded `<script` in the body must still match.
        let d = engine.evaluate_body("c=%3Cscript%3Ealert(1)").unwrap();
        assert_eq!(d.action, WafAction::Deny);
    }

    #[test]
    fn hit_counts_accumulate() {
        let h = HeaderMap::new();
        let engine = engine_with(&[rule(WafMatchType::Path, "/x", WafAction::Deny)]);
        for _ in 0..3 {
            engine.evaluate(WafAction::Allow, &ctx("1.1.1.1", "GET", "/x", &h), 0);
        }
        assert_eq!(engine.hits().get("r1").copied(), Some(3));
    }
}
