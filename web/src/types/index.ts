// Domain types — mirror the serde models in `fluxgate-core`.
// Enums match Rust's `#[serde(rename_all = "snake_case")]` string output.

export type StatusTone = 'success' | 'warning' | 'danger' | 'neutral' | 'info'

/** A site groups everything for one inbound host: TLS posture + WAF default. */
export interface Site {
  id: string
  name: string
  host: string
  tls_enabled: boolean
  /** Id of the TLS certificate to present for this host (when tls_enabled). */
  cert_id?: string | null
  /** Redirect plaintext HTTP to HTTPS (when tls_enabled). */
  https_redirect?: boolean
  /** Default WAF setting applied to new paths under this site. */
  waf_enabled: boolean
  /** Max request body (upload) size in MB; 0 = unlimited. */
  max_body_mb?: number
  /** Upstream response timeout in seconds. */
  upstream_timeout_secs?: number
  /** Block known crawler/bot User-Agents with 403. */
  block_crawler_ua?: boolean
  /** Only allow web-browser (or Cloudflare) User-Agents; deny everything else. */
  browser_only?: boolean
  /** Serve a disallow-all robots.txt instead of proxying it. */
  rewrite_robots?: boolean
  /** Deny clients from these ISO-3166-1 alpha-2 countries (GeoIP). */
  blocked_countries?: string[]
  /** Deny clients on known datacenter/cloud/hosting ASNs. */
  block_datacenter?: boolean
  /** Only accept connections from Cloudflare IP ranges. */
  cloudflare_only?: boolean
  enabled: boolean
  created_at: string
  updated_at: string
}

/** A route maps a path (under its parent site's host) to an upstream. */
export interface Route {
  id: string
  site_id: string
  name: string
  path: string
  upstream: string
  waf_enabled: boolean
  enabled: boolean
  created_at: string
  updated_at: string
}

export type LbStrategy = 'round_robin' | 'least_conn' | 'ip_hash' | 'weighted'
export type UpstreamStatus = 'healthy' | 'degraded' | 'down'

export interface UpstreamServer {
  address: string
  weight: number
  healthy: boolean
  latency_ms: number
}

export interface Upstream {
  id: string
  name: string
  strategy: LbStrategy
  servers: UpstreamServer[]
  healthy_servers: number
  status: UpstreamStatus
}

export type WafAction = 'allow' | 'deny' | 'challenge'
export type WafMatchType = 'ip' | 'path' | 'header' | 'method' | 'geo' | 'rate_limit' | 'body'

export interface WafRule {
  id: string
  name: string
  description: string
  match_type: WafMatchType
  pattern: string
  action: WafAction
  priority: number
  enabled: boolean
  hit_count: number
}

export interface SecurityEvent {
  id: string
  time: string
  client_ip: string
  rule: string
  action: WafAction
  path: string
  user_agent?: string
}

export type CertStatus = 'valid' | 'expiring' | 'expired' | 'pending'

export interface TlsCertificate {
  id: string
  domain: string
  issuer: string
  expires_at: string
  auto_renew: boolean
  status: CertStatus
  /** Issued via ACME (Let's Encrypt); renews automatically over HTTP-01. */
  acme?: boolean
}

export interface AccessLog {
  id: string
  time: string
  client_ip: string
  method: string
  host: string
  path: string
  status: number
  latency_ms: number
  upstream: string
  waf_action: WafAction
}

export interface DashboardSummary {
  total_requests: number
  current_qps: number
  waf_blocks: number
  active_connections: number
  tls_certificates: number
  healthy_upstreams: number
  total_upstreams: number
  pv_24h: number
  uv_24h: number
  traffic?: TrafficTotals
}

export interface TrafficPoint {
  t: string
  requests: number
  blocked: number
}

export interface TopRoute {
  route: string
  requests: number
  blocked: number
}

export interface DashboardTraffic {
  points: TrafficPoint[]
  top_routes: TopRoute[]
}

/** Request count by visitor country (GeoIP). `country` is ISO alpha-2 or "??". */
export interface CountryStat {
  country: string
  requests: number
}

/** Request count by client device/OS class parsed from the User-Agent. */
export interface DeviceStat {
  device: string
  requests: number
}

/** WAF-block count by attacker User-Agent (risk board). */
export interface UaStat {
  ua: string
  count: number
}

/** A manual IP/CIDR allow- or block-list entry. */
export interface IpListEntry {
  value: string
  note?: string
}

/** An active auto-ban (`expires_at` 0 = permanent). */
export interface BanEntry {
  ip: string
  expires_at: number
  deny_count: number
}

/** Response of `ip.list`. */
export interface IpAccessData {
  whitelist: IpListEntry[]
  blacklist: IpListEntry[]
  bans: BanEntry[]
  auto_ban_enabled: boolean
  auto_ban_threshold: number
  auto_ban_duration_secs: number
}

/** Risk-board attack analytics over the last 24h. */
export interface AttackOverview {
  total: number
  timeline: TrafficPoint[]
  top_uas: UaStat[]
  top_countries: CountryStat[]
}

/** Byte-traffic totals for a site (or the whole proxy). */
export interface TrafficTotals {
  total_bytes: number
  bytes_30d: number
  bytes_today: number
  total_requests: number
}

export interface MetricPoint {
  t: string
  value: number
}

export interface MetricSeries {
  key: string
  label: string
  unit: string
  current: number
  series: MetricPoint[]
}

/** 24h analytics for a host+path (or whole proxy). */
export interface RouteStats {
  window_hours: number
  pv: number
  uv: number
  current_qps: number
  error_rate: number
  latency_p50: number
  latency_p99: number
  qps_series: MetricPoint[]
  countries: CountryStat[]
  devices?: DeviceStat[]
  traffic?: TrafficTotals
}

export interface AcmeSettings {
  enabled: boolean
  directory_url: string
  email: string
  agree_tos: boolean
}

export interface Settings {
  admin_username: string
  admin_email: string
  log_level: string
  hot_reload: boolean
  default_waf_action: WafAction
  acme: AcmeSettings
  worker_threads: number
  max_connections: number
  request_timeout_secs: number
}

export interface SystemInfo {
  version: string
  build: string
  pingora_version: string
  uptime_secs: number
  started_at: string
}

export interface Paged<T> {
  items: T[]
  total: number
}
