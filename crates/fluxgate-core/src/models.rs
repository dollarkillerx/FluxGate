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
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub version: String,
    pub build: String,
    pub pingora_version: String,
    pub uptime_secs: u64,
    pub started_at: String,
}
