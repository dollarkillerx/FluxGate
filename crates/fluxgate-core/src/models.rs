//! Domain models for FluxGate.
//!
//! All enums serialize as `snake_case` strings so the TypeScript frontend can
//! use matching string-literal unions without a translation layer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// A **site** groups everything that belongs to one inbound host (domain):
/// the TLS posture (enable / certificate / HTTP→HTTPS redirect) and a default
/// WAF setting. Individual path routes live under it (see `Route.site_id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    /// The inbound host this site serves (e.g. `www.example.com`).
    pub host: String,
    pub tls_enabled: bool,
    /// Certificate presented for this host during the TLS handshake. `None`
    /// falls back to matching a certificate by domain.
    #[serde(default)]
    pub cert_id: Option<String>,
    /// Redirect plaintext HTTP (:80) to HTTPS (:443) with a 308 when TLS is on.
    #[serde(default)]
    pub https_redirect: bool,
    /// Default WAF setting applied to new path routes under this site.
    pub waf_enabled: bool,
    /// Maximum request body (upload) size in **MB**; `0` = unlimited. Default 500.
    #[serde(default = "default_max_body_mb")]
    pub max_body_mb: u64,
    /// Upstream response timeout in **seconds**; `0` falls back to the default. Default 120.
    #[serde(default = "default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,
    /// Block known crawler / bot User-Agents with 403.
    #[serde(default)]
    pub block_crawler_ua: bool,
    /// UA allow-list mode: only accept **web-browser** User-Agents (plus
    /// Cloudflare's own probes); deny everything else (curl, scripts, bots, empty
    /// UA…). Stricter than `block_crawler_ua`.
    #[serde(default)]
    pub browser_only: bool,
    /// Serve a disallow-all `robots.txt` instead of proxying it to the origin.
    #[serde(default)]
    pub rewrite_robots: bool,
    /// Per-path 301/302 redirect rules, evaluated before routing to an upstream.
    /// First match wins (in list order); see `RedirectRule`.
    #[serde(default)]
    pub redirects: Vec<RedirectRule>,
    /// Deny clients whose GeoIP country is in this list (ISO-3166-1 alpha-2 codes).
    /// Empty = no geo restriction. Uses the real client IP (CF-Connecting-IP aware).
    #[serde(default)]
    pub blocked_countries: Vec<String>,
    /// Deny clients on known datacenter / cloud / hosting ASNs (the "block
    /// non-residential" control). Requires the GeoLite2-ASN database.
    #[serde(default)]
    pub block_datacenter: bool,
    /// Only accept connections originating from Cloudflare's IP ranges (the site
    /// must be fronted by Cloudflare). Checked against the **TCP peer**, not headers.
    #[serde(default)]
    pub cloudflare_only: bool,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// A per-site URL redirect: a request whose path matches `path` is answered with
/// `status` (301 permanent or 302 temporary) and a `Location` of `target`,
/// instead of being proxied to an upstream. `path` matches the request path
/// **exactly**, or as a **prefix** when it ends with `*` (e.g. `/old*` matches
/// `/old`, `/old/page`…). `target` may be an absolute URL (`https://host/new`)
/// or a site-relative path (`/new`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectRule {
    pub path: String,
    pub target: String,
    /// HTTP redirect status: 301 (permanent) or 302 (temporary).
    pub status: u16,
}

fn default_max_body_mb() -> u64 {
    500
}
fn default_upstream_timeout_secs() -> u64 {
    120
}

/// A **route** maps a path (under its parent `Site`'s host) to an upstream.
/// Host-level concerns (TLS, certificate, redirect) live on the `Site`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    /// Parent site (host) this path belongs to.
    #[serde(default)]
    pub site_id: String,
    pub name: String,
    pub path: String,
    /// Name of the upstream this route forwards to.
    pub upstream: String,
    /// Per-path WAF toggle (initialised from the site default, overridable).
    pub waf_enabled: bool,
    /// Per-route override of the semantic-engine mode: `None` inherits the global
    /// `WafSemanticConfig.mode`; `Some(Monitor)` logs-without-blocking just this
    /// route (gradual rollout); `Some(Block)` enforces it even if the global is
    /// Monitor. Governs the semantic engine only (regex rules always enforce).
    #[serde(default)]
    pub waf_mode: Option<WafMode>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Upstreams
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbStrategy {
    RoundRobin,
    LeastConn,
    IpHash,
    Weighted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStatus {
    Healthy,
    Degraded,
    Down,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamServer {
    pub address: String,
    pub weight: u32,
    pub healthy: bool,
    pub latency_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    pub id: String,
    pub name: String,
    pub strategy: LbStrategy,
    pub servers: Vec<UpstreamServer>,
    pub healthy_servers: u32,
    pub status: UpstreamStatus,
}

impl Upstream {
    /// Recompute `healthy_servers` and `status` from the current server list.
    pub fn recompute_health(&mut self) {
        let total = self.servers.len() as u32;
        let healthy = self.servers.iter().filter(|s| s.healthy).count() as u32;
        self.healthy_servers = healthy;
        self.status = match (healthy, total) {
            (0, _) => UpstreamStatus::Down,
            (h, t) if h == t => UpstreamStatus::Healthy,
            _ => UpstreamStatus::Degraded,
        };
    }
}

// ---------------------------------------------------------------------------
// WAF
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Deny,
    Challenge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMatchType {
    Ip,
    Path,
    Header,
    Method,
    Geo,
    RateLimit,
    /// Match a regex against the (decoded) **request body** prefix. Inspected on
    /// the data plane only — the proxy reads a bounded body prefix on demand and
    /// evaluates these rules separately (see `WafEngine::evaluate_body`).
    Body,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub match_type: WafMatchType,
    pub pattern: String,
    pub action: WafAction,
    pub priority: u32,
    pub enabled: bool,
    pub hit_count: u64,
    /// Set once the operator edits the rule via the API. Lets a schema migration
    /// tell a hand-customized rule from an untouched shipped default without
    /// relying on a (brittle) pattern-equality check against the current seed.
    /// Defaults false so rules from older stores (and fresh seeds) deserialize.
    #[serde(default)]
    pub user_modified: bool,
}

/// Deserialize an optional enum from a key string, mapping `""`/missing/unknown
/// to `None`. Legacy JSONL stored these as bare strings with `""` for regex-rule
/// events; plain `Option<T>` would fail to parse `""`.
fn de_opt_module<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<WafModule>, D::Error> {
    let s = <Option<String> as Deserialize>::deserialize(d)?;
    Ok(s.as_deref()
        .filter(|x| !x.is_empty())
        .and_then(WafModule::from_key))
}
fn de_opt_risk<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<WafRisk>, D::Error> {
    let s = <Option<String> as Deserialize>::deserialize(d)?;
    Ok(s.as_deref()
        .filter(|x| !x.is_empty())
        .and_then(WafRisk::from_key))
}
fn de_opt_location<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<WafLocation>, D::Error> {
    let s = <Option<String> as Deserialize>::deserialize(d)?;
    Ok(s.as_deref()
        .filter(|x| !x.is_empty())
        .and_then(WafLocation::from_key))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub time: String,
    pub client_ip: String,
    /// Human display label: the matched regex rule name, or a short semantic
    /// summary. Typed detail lives in `module`/`risk`/`detail` below.
    pub rule: String,
    pub action: WafAction,
    pub path: String,
    /// Attacker User-Agent (truncated), for the risk board's UA breakdown.
    #[serde(default)]
    pub user_agent: String,
    // -- Semantic-engine enrichment (`None` for legacy/regex-rule events) --
    /// Detection module that fired, if a semantic detector.
    #[serde(default, deserialize_with = "de_opt_module")]
    pub module: Option<WafModule>,
    /// Risk level the detector assigned.
    #[serde(default, deserialize_with = "de_opt_risk")]
    pub risk: Option<WafRisk>,
    /// Where in the request the hit was found.
    #[serde(default, deserialize_with = "de_opt_location")]
    pub location: Option<WafLocation>,
    /// Parameter / field / header name that carried the payload.
    #[serde(default)]
    pub param: String,
    /// Truncated snippet of the matched value (for the "add exception" UX).
    #[serde(default)]
    pub snippet: String,
    /// Detector-specific fingerprint / detail (e.g. `libinjection:1c`, `tag:script`).
    #[serde(default)]
    pub detail: Option<String>,
    /// Concise machine-readable record of *why* this decision was made — the
    /// substrate for the risk board's forensics and the future anomaly-score trace.
    #[serde(default)]
    pub decision_trace: Option<String>,
    /// Whether the decision was enforced (blocked/challenged) vs. only logged
    /// (monitor mode or a `Log` risk action).
    #[serde(default)]
    pub enforced: bool,
}

// ---------------------------------------------------------------------------
// Semantic WAF engine — modules, risk, policy, exceptions
// ---------------------------------------------------------------------------

/// A semantic detection module. Serializes to the snake-case keys used both in
/// [`WafSemanticConfig::modules`] and the frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafModule {
    Sqli,
    Xss,
    Traversal,
    Cmdi,
    Ssrf,
    Proto,
    Ssti,
    Nosql,
    Xxe,
    Deser,
    Php,
    Java,
}

impl WafModule {
    /// All modules, in display order.
    pub const ALL: [WafModule; 12] = [
        WafModule::Sqli,
        WafModule::Xss,
        WafModule::Traversal,
        WafModule::Cmdi,
        WafModule::Ssrf,
        WafModule::Proto,
        WafModule::Ssti,
        WafModule::Nosql,
        WafModule::Xxe,
        WafModule::Deser,
        WafModule::Php,
        WafModule::Java,
    ];

    /// Stable snake-case key (matches the serde representation).
    pub fn key(self) -> &'static str {
        match self {
            WafModule::Sqli => "sqli",
            WafModule::Xss => "xss",
            WafModule::Traversal => "traversal",
            WafModule::Cmdi => "cmdi",
            WafModule::Ssrf => "ssrf",
            WafModule::Proto => "proto",
            WafModule::Ssti => "ssti",
            WafModule::Nosql => "nosql",
            WafModule::Xxe => "xxe",
            WafModule::Deser => "deser",
            WafModule::Php => "php",
            WafModule::Java => "java",
        }
    }

    /// Parse a [`key`](Self::key) back into a module (inverse of `key`).
    pub fn from_key(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.key() == s)
    }
}

/// Where in the request a value was extracted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafLocation {
    Path,
    Query,
    BodyForm,
    BodyJson,
    BodyMultipart,
    Cookie,
    Header,
}

impl WafLocation {
    pub fn key(self) -> &'static str {
        match self {
            WafLocation::Path => "path",
            WafLocation::Query => "query",
            WafLocation::BodyForm => "body_form",
            WafLocation::BodyJson => "body_json",
            WafLocation::BodyMultipart => "body_multipart",
            WafLocation::Cookie => "cookie",
            WafLocation::Header => "header",
        }
    }

    /// Parse a [`key`](Self::key) back into a location (inverse of `key`).
    pub fn from_key(s: &str) -> Option<Self> {
        const ALL: [WafLocation; 7] = [
            WafLocation::Path,
            WafLocation::Query,
            WafLocation::BodyForm,
            WafLocation::BodyJson,
            WafLocation::BodyMultipart,
            WafLocation::Cookie,
            WafLocation::Header,
        ];
        ALL.into_iter().find(|l| l.key() == s)
    }

    /// Whether this location is part of the request **body** (so it is only seen
    /// in the data plane's body-inspection pass).
    pub fn is_body(self) -> bool {
        matches!(
            self,
            WafLocation::BodyForm | WafLocation::BodyJson | WafLocation::BodyMultipart
        )
    }
}

/// Confidence / severity a detector assigns to a hit. Ordered `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafRisk {
    Low,
    Medium,
    High,
}

impl WafRisk {
    pub fn key(self) -> &'static str {
        match self {
            WafRisk::Low => "low",
            WafRisk::Medium => "medium",
            WafRisk::High => "high",
        }
    }

    /// Parse a [`key`](Self::key) back into a risk level (inverse of `key`).
    pub fn from_key(s: &str) -> Option<Self> {
        match s {
            "low" => Some(WafRisk::Low),
            "medium" => Some(WafRisk::Medium),
            "high" => Some(WafRisk::High),
            _ => None,
        }
    }
}

/// Site-wide posture for the semantic engine. `Monitor` detects and logs but
/// never blocks/challenges (safe rollout).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    #[default]
    Block,
    Monitor,
}

/// What to do with a detection at a given risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    Block,
    Challenge,
    Log,
}

/// Per-module enable flag plus the action taken at each risk level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub enabled: bool,
    pub high: RiskAction,
    pub medium: RiskAction,
    pub low: RiskAction,
}

impl ModuleConfig {
    /// The default low-false-positive posture: high → block, medium → challenge,
    /// low → log.
    pub fn standard() -> Self {
        ModuleConfig {
            enabled: true,
            high: RiskAction::Block,
            medium: RiskAction::Challenge,
            low: RiskAction::Log,
        }
    }

    /// Resolve the configured action for a risk level.
    pub fn action_for(&self, risk: WafRisk) -> RiskAction {
        match risk {
            WafRisk::High => self.high,
            WafRisk::Medium => self.medium,
            WafRisk::Low => self.low,
        }
    }
}

/// A tuning exception that suppresses detections matching its scope (a known
/// false positive an operator has accepted). All set fields must match for the
/// exception to apply; unset fields are wildcards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafException {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Restrict to one module; `None` = any module.
    #[serde(default)]
    pub module: Option<WafModule>,
    /// Match when the request path starts with this prefix; `""` = any path.
    #[serde(default)]
    pub path_prefix: String,
    /// Restrict to a specific parameter / field / header name; `None` = any.
    #[serde(default)]
    pub param: Option<String>,
    /// Restrict to one request location; `None` = any.
    #[serde(default)]
    pub location: Option<WafLocation>,
    #[serde(default)]
    pub note: String,
}

fn default_true() -> bool {
    true
}

/// CRS-style anomaly scoring: sum a severity score across all surviving
/// detections on a request and **escalate** the action when it crosses a
/// threshold — so several individually-weak signals (e.g. three `Low`s) together
/// block, even though no single one would. Opt-in and escalation-only: when off
/// (the default) nothing changes; when on it can only raise the action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyConfig {
    pub enabled: bool,
    /// Summed score at/above which the action is escalated.
    pub threshold: u32,
    /// Action to escalate to once the threshold is crossed.
    pub action: RiskAction,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        // Severities are Low 2 / Medium 3 / High 5, so threshold 6 needs two
        // Mediums or three Lows — combinations a single per-module action misses.
        AnomalyConfig {
            enabled: false,
            threshold: 6,
            action: RiskAction::Challenge,
        }
    }
}

/// Persisted configuration for the semantic detection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafSemanticConfig {
    #[serde(default)]
    pub mode: WafMode,
    /// Per-module config, keyed by [`WafModule::key`]. Missing modules fall back
    /// to [`ModuleConfig::standard`].
    #[serde(default)]
    pub modules: BTreeMap<String, ModuleConfig>,
    /// CRS-style cross-detection anomaly scoring (off by default).
    #[serde(default)]
    pub anomaly: AnomalyConfig,
    #[serde(default)]
    pub exceptions: Vec<WafException>,
}

impl Default for WafSemanticConfig {
    fn default() -> Self {
        let mut modules = BTreeMap::new();
        for m in WafModule::ALL {
            modules.insert(m.key().to_string(), ModuleConfig::standard());
        }
        WafSemanticConfig {
            mode: WafMode::Block,
            modules,
            anomaly: AnomalyConfig::default(),
            exceptions: Vec::new(),
        }
    }
}

impl WafSemanticConfig {
    /// Config for a module, falling back to the standard posture when absent.
    pub fn module(&self, m: WafModule) -> ModuleConfig {
        self.modules
            .get(m.key())
            .cloned()
            .unwrap_or_else(ModuleConfig::standard)
    }

    /// Whether a module is enabled (default-on when unconfigured).
    pub fn is_enabled(&self, m: WafModule) -> bool {
        self.modules.get(m.key()).map(|c| c.enabled).unwrap_or(true)
    }
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    Valid,
    Expiring,
    Expired,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertificate {
    pub id: String,
    pub domain: String,
    pub issuer: String,
    pub expires_at: String,
    pub auto_renew: bool,
    pub status: CertStatus,
    /// Issued via ACME (Let's Encrypt) rather than self-signed/uploaded. Drives
    /// automatic HTTP-01 renewal. Defaults to `false` for older stored data.
    #[serde(default)]
    pub acme: bool,
}

// ---------------------------------------------------------------------------
// Access logs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLog {
    pub id: String,
    pub time: String,
    pub client_ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u32,
    pub upstream: String,
    pub waf_action: WafAction,
    /// Client device / OS class parsed from the User-Agent at log time
    /// (`windows` / `mac` / `linux` / `android` / `ios` / `bot` / `other`).
    #[serde(default)]
    pub device: String,
}

// ---------------------------------------------------------------------------
// Dashboard & metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub total_requests: u64,
    pub current_qps: u32,
    pub waf_blocks: u64,
    pub active_connections: u32,
    pub tls_certificates: u32,
    pub healthy_upstreams: u32,
    pub total_upstreams: u32,
    /// Page views (total requests) in the last 24 hours.
    pub pv_24h: u64,
    /// Unique visitors (distinct client IPs) in the last 24 hours.
    pub uv_24h: u64,
    /// Whole-proxy byte traffic: cumulative / last 30 days / today.
    #[serde(default)]
    pub traffic: TrafficTotals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPoint {
    pub t: String,
    pub requests: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopRoute {
    pub route: String,
    pub requests: u64,
    pub blocked: u64,
}

/// Request count grouped by visitor country (from GeoIP on the client IP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountryStat {
    /// ISO-3166-1 alpha-2 code, or `"??"` for unknown / private addresses.
    pub country: String,
    pub requests: u64,
}

/// Request count grouped by client device / OS class (parsed from User-Agent):
/// `windows` / `mac` / `linux` / `android` / `ios` / `bot` / `other`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStat {
    pub device: String,
    pub requests: u64,
}

/// WAF-block count grouped by attacker User-Agent (for the risk board top-N).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UaStat {
    pub ua: String,
    pub count: u64,
}

/// Risk-board attack analytics over the last 24h, derived from WAF events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttackOverview {
    /// Total WAF blocks (deny + challenge) in the window.
    pub total: u64,
    /// 24 hourly points of block counts (oldest → newest).
    pub timeline: Vec<TrafficPoint>,
    /// Top attacker User-Agents.
    pub top_uas: Vec<UaStat>,
    /// Attack-source country breakdown (GeoIP on the client IP).
    pub top_countries: Vec<CountryStat>,
}

/// Byte-traffic totals for a site (or the whole proxy): cumulative, last 30 days,
/// and today. `total_requests` is the cumulative metered response count.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficTotals {
    pub total_bytes: u64,
    pub bytes_30d: u64,
    pub bytes_today: u64,
    pub total_requests: u64,
}

/// 24-hour analytics for a host+path (or the whole proxy), bucketed hourly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStats {
    pub window_hours: u32,
    /// Page views = total requests in the window.
    pub pv: u64,
    /// Unique visitors = distinct client IPs in the window.
    pub uv: u64,
    pub current_qps: f64,
    pub error_rate: f64,
    pub latency_p50: f64,
    pub latency_p99: f64,
    /// 24 hourly points (oldest → newest).
    pub qps_series: Vec<MetricPoint>,
    /// Visitor-country breakdown (top N), for the pie chart.
    pub countries: Vec<CountryStat>,
    /// Client device / OS breakdown over the window (from User-Agent).
    #[serde(default)]
    pub devices: Vec<DeviceStat>,
    /// Byte-traffic totals for this site (host-level: cumulative / 30d / today).
    #[serde(default)]
    pub traffic: TrafficTotals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub t: String,
    pub value: f64,
}

/// A single system gauge plus its recent history, used by the Metrics page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    pub key: String,
    pub label: String,
    pub unit: String,
    pub current: f64,
    pub series: Vec<MetricPoint>,
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeSettings {
    pub enabled: bool,
    pub directory_url: String,
    pub email: String,
    pub agree_tos: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub admin_username: String,
    pub admin_email: String,
    pub log_level: String,
    pub hot_reload: bool,
    pub default_waf_action: WafAction,
    pub acme: AcmeSettings,
    pub worker_threads: u32,
    pub max_connections: u32,
    pub request_timeout_secs: u32,
    /// Auto-ban: when on, an IP that trips `auto_ban_threshold` WAF **denies**
    /// within 24h is blocked for `auto_ban_duration_secs` (`0` = permanent).
    #[serde(default)]
    pub auto_ban_enabled: bool,
    #[serde(default = "default_auto_ban_threshold")]
    pub auto_ban_threshold: u32,
    #[serde(default = "default_auto_ban_duration_secs")]
    pub auto_ban_duration_secs: i64,
}

fn default_auto_ban_threshold() -> u32 {
    20
}
fn default_auto_ban_duration_secs() -> i64 {
    5 * 3600
}

/// A manual IP/CIDR allow- or block-list entry (admin-managed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpListEntry {
    /// An IP or CIDR (IPv4 or IPv6), e.g. `203.0.113.5` or `10.0.0.0/24`.
    pub value: String,
    #[serde(default)]
    pub note: String,
}

/// An active auto-ban, surfaced to the admin (for the list + unban).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEntry {
    pub ip: String,
    /// Epoch second the ban expires; `0` (or far future) = permanent.
    pub expires_at: i64,
    /// Recorded WAF denies that triggered / sustain the ban.
    pub deny_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub version: String,
    pub build: String,
    pub pingora_version: String,
    pub uptime_secs: u64,
    pub started_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_from_key_roundtrips() {
        for m in WafModule::ALL {
            assert_eq!(WafModule::from_key(m.key()), Some(m));
        }
        for r in [WafRisk::Low, WafRisk::Medium, WafRisk::High] {
            assert_eq!(WafRisk::from_key(r.key()), Some(r));
        }
        assert_eq!(WafModule::from_key("nope"), None);
        assert_eq!(
            WafLocation::from_key("body_json"),
            Some(WafLocation::BodyJson)
        );
    }

    #[test]
    fn semantic_config_without_anomaly_defaults_off() {
        // An older store has no `anomaly` field — it must deserialize to the
        // opt-in default (disabled), so existing installs are unaffected.
        let cfg: WafSemanticConfig =
            serde_json::from_str(r#"{"mode":"block","modules":{},"exceptions":[]}"#).unwrap();
        assert!(!cfg.anomaly.enabled);
        assert_eq!(cfg.anomaly.threshold, 6);
    }

    #[test]
    fn security_event_legacy_strings_deserialize_to_none() {
        // Legacy JSONL stored empty strings for regex-rule events.
        let legacy = r#"{"id":"e1","time":"t","client_ip":"1.2.3.4","rule":"r",
            "action":"deny","path":"/","module":"","risk":"","location":""}"#;
        let e: SecurityEvent = serde_json::from_str(legacy).unwrap();
        assert_eq!(e.module, None);
        assert_eq!(e.risk, None);
        assert_eq!(e.location, None);
        assert_eq!(e.detail, None);

        // Populated semantic event with the typed snake_case strings.
        let sem = r#"{"id":"e2","time":"t","client_ip":"1.2.3.4","rule":"libinjection:1c",
            "action":"deny","path":"/","module":"sqli","risk":"high","location":"query",
            "detail":"libinjection:1c","enforced":true}"#;
        let e: SecurityEvent = serde_json::from_str(sem).unwrap();
        assert_eq!(e.module, Some(WafModule::Sqli));
        assert_eq!(e.risk, Some(WafRisk::High));
        assert_eq!(e.location, Some(WafLocation::Query));
        // Round-trips back to snake_case strings (null for the unset fields).
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["module"], "sqli");
        assert_eq!(json["risk"], "high");
    }
}
