//! Domain models for FluxGate.
//!
//! All enums serialize as `snake_case` strings so the TypeScript frontend can
//! use matching string-literal unions without a translation layer.

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub time: String,
    pub client_ip: String,
    pub rule: String,
    pub action: WafAction,
    pub path: String,
    /// Attacker User-Agent (truncated), for the risk board's UA breakdown.
    #[serde(default)]
    pub user_agent: String,
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
