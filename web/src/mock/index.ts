// In-repo mock backend.
//
// Mirrors the JSON-RPC surface of `fluxgate-admin` so the console runs without
// the Rust server (dev fallback / `VITE_USE_MOCK=true`). State is in-memory and
// mutable, so create/update/delete behave realistically during a session.
//
// This is the ONLY place business data is hardcoded on the frontend. Pages
// never import it directly — they always go through `rpc.call`.

import { RpcError } from '@/api/errors'
import type {
  AccessLog,
  DashboardSummary,
  MetricSeries,
  Route,
  Site,
  SecurityEvent,
  Settings,
  TlsCertificate,
  TopRoute,
  TrafficPoint,
  Upstream,
  WafRule,
} from '@/types'

const now = () => new Date().toISOString()
const ago = (mins: number) => new Date(Date.now() - mins * 60_000).toISOString()
const daysFromNow = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString()
const wobble = (seed: number) => ((seed * 2654435761 + 0x9e3779b9) % 10000) / 10000
const sid = (p: string) => `${p}-${Math.random().toString(16).slice(2, 10)}`

// --- seed state -----------------------------------------------------------

const sites: Site[] = [
  st('st-001', 'www.example.com', true, true, true, 35),
  st('st-002', 'api.example.com', true, true, true, 12),
  st('st-003', 'admin.example.com', true, true, true, 240),
  st('st-004', 'cdn.example.com', true, false, true, 900),
  st('st-005', 'hooks.example.com', false, false, false, 4320),
]
function st(id: string, host: string, tls: boolean, waf: boolean, enabled: boolean, upd: number): Site {
  return {
    id, name: host, host,
    tls_enabled: tls, cert_id: null, https_redirect: tls, waf_enabled: waf, enabled,
    created_at: ago(60 * 24 * 30), updated_at: ago(upd),
  }
}

const routes: Route[] = [
  r('rt-001', 'st-001', 'Marketing Site', '/', 'web-frontend', true, true, 35),
  r('rt-002', 'st-002', 'Public API', '/v1', 'api-cluster', true, true, 12),
  r('rt-003', 'st-003', 'Admin Portal', '/', 'admin-backend', true, true, 240),
  r('rt-004', 'st-004', 'Asset CDN', '/assets', 'static-storage', false, true, 900),
  r('rt-005', 'st-005', 'Legacy Webhook', '/legacy', 'legacy-box', false, false, 4320),
]
function r(
  id: string, site_id: string, name: string, path: string, upstream: string,
  waf: boolean, enabled: boolean, upd: number,
): Route {
  return {
    id, site_id, name, path, upstream,
    waf_enabled: waf, enabled,
    created_at: ago(60 * 24 * 30), updated_at: ago(upd),
  }
}

const upstreams: Upstream[] = [
  u('up-001', 'web-frontend', 'round_robin', [s('10.0.1.11:8080', 1, true, 14), s('10.0.1.12:8080', 1, true, 17), s('10.0.1.13:8080', 1, true, 12)]),
  u('up-002', 'api-cluster', 'least_conn', [s('10.0.2.21:9090', 2, true, 22), s('10.0.2.22:9090', 2, true, 25), s('10.0.2.23:9090', 1, false, 0), s('10.0.2.24:9090', 1, true, 19)]),
  u('up-003', 'admin-backend', 'ip_hash', [s('10.0.3.31:7000', 1, true, 9), s('10.0.3.32:7000', 1, true, 11)]),
  u('up-004', 'static-storage', 'weighted', [s('10.0.4.41:80', 3, true, 6), s('10.0.4.42:80', 1, true, 8)]),
  u('up-005', 'auth-cluster', 'least_conn', [s('10.0.5.51:6000', 1, true, 31), s('10.0.5.52:6000', 1, true, 28)]),
  u('up-006', 'legacy-box', 'round_robin', [s('10.0.6.61:5000', 1, false, 0)]),
]
function s(address: string, weight: number, healthy: boolean, latency_ms: number) {
  return { address, weight, healthy, latency_ms }
}
function u(id: string, name: string, strategy: Upstream['strategy'], servers: Upstream['servers']): Upstream {
  const up: Upstream = { id, name, strategy, servers, healthy_servers: 0, status: 'healthy' }
  recompute(up)
  return up
}
function recompute(up: Upstream) {
  const healthy = up.servers.filter((x) => x.healthy).length
  up.healthy_servers = healthy
  up.status = healthy === 0 ? 'down' : healthy === up.servers.length ? 'healthy' : 'degraded'
}

const wafRules: WafRule[] = [
  w('wr-001', 'Block SQLi patterns', 'Deny common SQL injection signatures', 'path', '(?i)(union.+select|or 1=1)', 'deny', 10, true, 18342),
  w('wr-002', 'Block known bad IPs', 'Deny traffic from threat-intel blocklist', 'ip', '203.0.113.0/24', 'deny', 5, true, 9120),
  w('wr-003', 'Challenge suspicious UA', 'JS challenge for empty/bot user agents', 'header', 'User-Agent: ^$', 'challenge', 20, true, 4502),
  w('wr-004', 'Rate-limit login', 'Throttle brute-force on /oauth/token', 'rate_limit', '/oauth/token@10r/s', 'challenge', 15, true, 1287),
  w('wr-005', 'Geo block (sanctioned)', 'Deny requests from restricted regions', 'geo', 'country in [KP, SY]', 'deny', 8, true, 671),
  w('wr-006', 'Allow health checks', 'Always allow internal monitoring', 'path', '/healthz', 'allow', 1, true, 50231),
  w('wr-007', 'Block TRACE/TRACK', 'Disable risky HTTP methods', 'method', 'TRACE|TRACK', 'deny', 12, false, 0),
]
function w(
  id: string, name: string, description: string, match_type: WafRule['match_type'],
  pattern: string, action: WafRule['action'], priority: number, enabled: boolean, hit_count: number,
): WafRule {
  return { id, name, description, match_type, pattern, action, priority, enabled, hit_count }
}

const certs: TlsCertificate[] = [
  c('ct-001', 'www.example.com', "Let's Encrypt R3", daysFromNow(64), true, 'valid'),
  c('ct-002', 'api.example.com', "Let's Encrypt R3", daysFromNow(48), true, 'valid'),
  c('ct-003', 'admin.example.com', "Let's Encrypt R3", daysFromNow(12), true, 'expiring'),
  c('ct-004', 'cdn.example.com', 'DigiCert Global G2', daysFromNow(220), false, 'valid'),
  c('ct-005', 'auth.example.com', "Let's Encrypt R3", daysFromNow(-3), true, 'expired'),
  c('ct-006', 'beta.example.com', "Let's Encrypt R3", daysFromNow(90), true, 'pending'),
]
function c(id: string, domain: string, issuer: string, expires_at: string, auto_renew: boolean, status: TlsCertificate['status']): TlsCertificate {
  return { id, domain, issuer, expires_at, auto_renew, status }
}

const HOSTS: [string, string][] = [
  ['www.example.com', 'web-frontend'],
  ['api.example.com', 'api-cluster'],
  ['admin.example.com', 'admin-backend'],
  ['auth.example.com', 'auth-cluster'],
  ['cdn.example.com', 'static-storage'],
]
const PATHS = ['/', '/v1/users', '/v1/orders', '/login', '/assets/app.js', '/oauth/token', '/healthz', '/admin']
const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'GET', 'GET']
const STATUSES = [200, 200, 200, 304, 404, 500, 403, 401, 502]
const IPS = ['198.51.100.7', '203.0.113.42', '192.0.2.18', '198.51.100.91', '203.0.113.5']

const logs: AccessLog[] = Array.from({ length: 200 }, (_, i) => {
  const [host, up] = HOSTS[i % HOSTS.length]
  const status = STATUSES[Math.floor(wobble(i + 3) * STATUSES.length) % STATUSES.length]
  const waf_action = status === 403 ? 'deny' : status === 401 ? 'challenge' : 'allow'
  return {
    id: `log-${String(i).padStart(4, '0')}`,
    time: ago(Math.floor(i / 2)),
    client_ip: IPS[(i + 1) % IPS.length],
    method: METHODS[i % METHODS.length],
    host,
    path: PATHS[(i * 3) % PATHS.length],
    status,
    latency_ms: 5 + Math.floor(wobble(i + 7) * 480),
    upstream: up,
    waf_action,
  } as AccessLog
})

const EVENT_RULES = ['Block SQLi patterns', 'Block known bad IPs', 'Challenge suspicious UA', 'Rate-limit login', 'Geo block (sanctioned)']
const EVENT_PATHS = ["/v1/users?id=1' OR '1'='1", '/login', '/oauth/token', '/admin', '/v1/search']
const EVENT_IPS = ['203.0.113.42', '203.0.113.5', '198.51.100.200', '192.0.2.99', '203.0.113.77']
const events: SecurityEvent[] = Array.from({ length: 40 }, (_, i) => ({
  id: `ev-${String(i).padStart(4, '0')}`,
  time: ago(i * 7),
  client_ip: EVENT_IPS[i % EVENT_IPS.length],
  rule: EVENT_RULES[i % EVENT_RULES.length],
  action: wobble(i) < 0.5 ? 'deny' : 'challenge',
  path: EVENT_PATHS[i % EVENT_PATHS.length],
}))

let settings: Settings = {
  admin_username: 'admin',
  admin_email: 'ops@example.com',
  log_level: 'info',
  hot_reload: true,
  default_waf_action: 'allow',
  acme: {
    enabled: true,
    directory_url: 'https://acme-v02.api.letsencrypt.org/directory',
    email: 'tls@example.com',
    agree_tos: true,
  },
  worker_threads: 8,
  max_connections: 65536,
  request_timeout_secs: 30,
}

// --- generators -----------------------------------------------------------

function trafficSeries(): TrafficPoint[] {
  return Array.from({ length: 24 }, (_, h) => {
    const base = 60000 + wobble(h) * 40000
    const diurnal = 1 + 0.5 * (1 - Math.abs(h - 13) / 13)
    const requests = Math.floor(base * diurnal)
    const blocked = Math.floor(requests * (0.01 + wobble(h + 9) * 0.03))
    return { t: `${String(h).padStart(2, '0')}:00`, requests, blocked }
  })
}

const TOP_ROUTES: TopRoute[] = [
  { route: 'api.example.com/v1', requests: 18402113, blocked: 142889 },
  { route: 'www.example.com/', requests: 12884201, blocked: 38104 },
  { route: 'cdn.example.com/assets', requests: 9120553, blocked: 211 },
  { route: 'auth.example.com/oauth', requests: 4201998, blocked: 87330 },
  { route: 'admin.example.com/', requests: 1002417, blocked: 9551 },
]

function metricSeries(base: number, amp: number, seed: number): MetricSeries['series'] {
  return Array.from({ length: 24 }, (_, i) => ({
    t: `-${(24 - i - 1) * 5}m`,
    value: Math.round(Math.max(0, base + (wobble(seed + i) - 0.5) * amp) * 100) / 100,
  }))
}
function metric(key: string, label: string, unit: string, base: number, amp: number, seed: number): MetricSeries {
  const series = metricSeries(base, amp, seed)
  return { key, label, unit, current: series[series.length - 1].value, series }
}

// --- dispatch -------------------------------------------------------------

type Params = Record<string, any>

function summary(): DashboardSummary {
  return {
    total_requests: 48201774,
    current_qps: 2417,
    waf_blocks: wafRules.filter((r2) => r2.action !== 'allow').reduce((a, r2) => a + r2.hit_count, 0),
    active_connections: 1842,
    tls_certificates: certs.length,
    healthy_upstreams: upstreams.filter((x) => x.status === 'healthy').length,
    total_upstreams: upstreams.length,
  }
}

const handlers: Record<string, (p: Params) => unknown> = {
  'auth.login': (p) => {
    if (p.username === 'admin' && p.password === 'admin') return { token: 'mock-dev-token', username: 'admin' }
    throw { code: -32001, message: 'Invalid username or password' }
  },

  'dashboard.summary': () => summary(),
  'dashboard.traffic': () => ({ points: trafficSeries(), top_routes: TOP_ROUTES }),
  'dashboard.security_events': (p) => events.slice(0, p.limit ?? 8),

  'site.list': () => sites,
  'site.get': (p) => find(sites, p.id, 'site'),
  'site.create': (p) => {
    const site: Site = {
      id: sid('st'), name: p.name || p.host || '', host: p.host ?? '',
      tls_enabled: p.tls_enabled ?? true, cert_id: p.cert_id || null,
      https_redirect: p.https_redirect ?? true, waf_enabled: p.waf_enabled ?? true,
      enabled: p.enabled ?? true, created_at: now(), updated_at: now(),
    }
    sites.unshift(site)
    return site
  },
  'site.update': (p) => {
    const site = find(sites, p.id, 'site')
    Object.assign(site, pick(p, ['name', 'host', 'tls_enabled', 'cert_id', 'https_redirect', 'waf_enabled', 'enabled']))
    site.updated_at = now()
    return site
  },
  'site.delete': (p) => {
    const out = del(sites, p.id, 'site')
    for (let i = routes.length - 1; i >= 0; i--) if (routes[i].site_id === p.id) routes.splice(i, 1)
    return out
  },

  'route.list': () => routes,
  'route.get': (p) => find(routes, p.id, 'route'),
  'route.create': (p) => {
    const route: Route = {
      id: sid('rt'), site_id: p.site_id ?? '', name: p.name ?? '', path: p.path ?? '/',
      upstream: p.upstream ?? '', waf_enabled: p.waf_enabled ?? true,
      enabled: p.enabled ?? true, created_at: now(), updated_at: now(),
    }
    routes.unshift(route)
    return route
  },
  'route.update': (p) => {
    const route = find(routes, p.id, 'route')
    Object.assign(route, pick(p, ['site_id', 'name', 'path', 'upstream', 'waf_enabled', 'enabled']))
    route.updated_at = now()
    return route
  },
  'route.delete': (p) => del(routes, p.id, 'route'),
  'route.enable': (p) => setFlag(routes, p.id, 'enabled', true, 'route'),
  'route.disable': (p) => setFlag(routes, p.id, 'enabled', false, 'route'),

  'upstream.list': () => upstreams,
  'upstream.get': (p) => find(upstreams, p.id, 'upstream'),
  'upstream.create': (p) => {
    const up: Upstream = { id: sid('up'), name: p.name ?? 'new-upstream', strategy: p.strategy ?? 'round_robin', servers: p.servers ?? [], healthy_servers: 0, status: 'down' }
    recompute(up)
    upstreams.unshift(up)
    return up
  },
  'upstream.update': (p) => {
    const up = find(upstreams, p.id, 'upstream')
    Object.assign(up, pick(p, ['name', 'strategy', 'servers']))
    recompute(up)
    return up
  },
  'upstream.delete': (p) => del(upstreams, p.id, 'upstream'),
  'upstream.health': (p) => {
    const up = find(upstreams, p.id, 'upstream')
    recompute(up)
    return up
  },

  'waf.rule.list': () => wafRules,
  'waf.rule.get': (p) => find(wafRules, p.id, 'waf rule'),
  'waf.rule.create': (p) => {
    const rule: WafRule = {
      id: sid('wr'), name: p.name ?? 'New Rule', description: p.description ?? '',
      match_type: p.match_type ?? 'path', pattern: p.pattern ?? '', action: p.action ?? 'deny',
      priority: p.priority ?? 50, enabled: p.enabled ?? true, hit_count: 0,
    }
    wafRules.unshift(rule)
    return rule
  },
  'waf.rule.update': (p) => {
    const rule = find(wafRules, p.id, 'waf rule')
    Object.assign(rule, pick(p, ['name', 'description', 'match_type', 'pattern', 'action', 'priority', 'enabled']))
    return rule
  },
  'waf.rule.delete': (p) => del(wafRules, p.id, 'waf rule'),
  'waf.rule.enable': (p) => setFlag(wafRules, p.id, 'enabled', true, 'waf rule'),
  'waf.rule.disable': (p) => setFlag(wafRules, p.id, 'enabled', false, 'waf rule'),
  'waf.event.list': (p) => events.slice(0, p.limit ?? 25),

  'tls.cert.list': () => certs,
  'tls.cert.get': (p) => find(certs, p.id, 'certificate'),
  'tls.cert.request': (p) => {
    const cert: TlsCertificate = { id: sid('ct'), domain: p.domain, issuer: "Let's Encrypt R3", expires_at: daysFromNow(90), auto_renew: true, status: 'pending' }
    certs.unshift(cert)
    return cert
  },
  'tls.cert.renew': (p) => {
    const cert = find(certs, p.id, 'certificate')
    cert.expires_at = daysFromNow(90)
    cert.status = 'valid'
    return cert
  },
  'tls.cert.upload': (p) => {
    const cert: TlsCertificate = { id: sid('ct'), domain: p.domain, issuer: p.issuer ?? 'Custom (uploaded)', expires_at: p.expires_at ?? daysFromNow(365), auto_renew: p.auto_renew ?? false, status: 'valid' }
    certs.unshift(cert)
    return cert
  },
  'tls.cert.delete': (p) => del(certs, p.id, 'certificate'),

  'access_log.list': (p) => paginate(logs, p.offset ?? 0, p.limit ?? 50),
  'access_log.search': (p) => {
    const filtered = logs.filter((l) => logMatches(l, p))
    return { items: filtered.slice(p.offset ?? 0, (p.offset ?? 0) + (p.limit ?? 50)), total: filtered.length }
  },

  'metrics.system': () => [
    metric('cpu', 'CPU Usage', '%', 38, 24, 101),
    metric('memory', 'Memory Usage', '%', 61, 12, 202),
    metric('net_in', 'Network In', 'MB/s', 142, 60, 303),
    metric('net_out', 'Network Out', 'MB/s', 188, 70, 404),
  ],
  'metrics.traffic': () => [
    metric('qps', 'Requests / sec', 'req/s', 2400, 900, 505),
    metric('latency_p50', 'Latency p50', 'ms', 18, 8, 606),
    metric('latency_p99', 'Latency p99', 'ms', 96, 60, 707),
    metric('error_rate', 'Error Rate', '%', 0.6, 0.9, 808),
  ],
  'metrics.upstream': () =>
    upstreams.map((up, i) => {
      const pct = up.servers.length ? (up.healthy_servers / up.servers.length) * 100 : 0
      return { key: up.name, label: up.name, unit: '% healthy', current: pct, series: metricSeries(Math.max(1, pct), 6, 900 + i * 10) }
    }),
  'metrics.waf': () => [
    metric('blocks', 'WAF Blocks', 'blocks/min', 320, 200, 1010),
    metric('challenges', 'Challenges', 'ch/min', 140, 90, 1111),
  ],

  'settings.get': () => settings,
  'settings.update': (p) => {
    settings = { ...settings, ...pick(p, ['admin_username', 'admin_email', 'log_level', 'hot_reload', 'default_waf_action', 'worker_threads', 'max_connections', 'request_timeout_secs']) }
    if (p.acme) settings.acme = { ...settings.acme, ...p.acme }
    return settings
  },
  'system.reload': () => ({ success: true, message: 'Configuration reloaded', reloaded_at: now() }),
  'system.info': () => ({ version: '0.1.0', build: 'mock-prototype', pingora_version: '0.3.0', uptime_secs: 372840, started_at: ago(6214) }),
}

// --- helpers --------------------------------------------------------------

function find<T extends { id: string }>(arr: T[], id: string, label: string): T {
  const found = arr.find((x) => x.id === id)
  if (!found) throw { code: -32004, message: `Not found: ${label} ${id}` }
  return found
}
function del<T extends { id: string }>(arr: T[], id: string, label: string) {
  const idx = arr.findIndex((x) => x.id === id)
  if (idx === -1) throw { code: -32004, message: `Not found: ${label} ${id}` }
  arr.splice(idx, 1)
  return { success: true, id }
}
function setFlag<T extends { id: string }>(arr: T[], id: string, key: keyof T, value: any, label: string) {
  const item = find(arr, id, label)
  ;(item as any)[key] = value
  if ('updated_at' in item) (item as any).updated_at = now()
  return item
}
function pick<T extends object>(src: any, keys: string[]): Partial<T> {
  const out: any = {}
  for (const k of keys) if (src[k] !== undefined) out[k] = src[k]
  return out
}
function paginate<T>(arr: T[], offset: number, limit: number) {
  return { items: arr.slice(offset, offset + limit), total: arr.length }
}
function logMatches(l: AccessLog, q: Params): boolean {
  if (q.host && l.host !== q.host) return false
  if (q.status != null && l.status !== q.status) return false
  if (q.waf_action && l.waf_action !== q.waf_action) return false
  if (q.query) {
    const needle = String(q.query).toLowerCase()
    const hay = `${l.client_ip} ${l.method} ${l.host} ${l.path} ${l.upstream} ${l.status}`.toLowerCase()
    if (!hay.includes(needle)) return false
  }
  return true
}

/** Resolve a mocked RPC call, simulating a little network latency. */
export async function mockCall<T>(method: string, params: unknown): Promise<T> {
  await new Promise((res) => setTimeout(res, 120))
  const handler = handlers[method]
  if (!handler) {
    throw new RpcError(-32601, `Method not found: ${method}`)
  }
  try {
    return handler((params ?? {}) as Params) as T
  } catch (e: any) {
    if (e && typeof e.code === 'number') throw new RpcError(e.code, e.message)
    throw new RpcError(-32603, String(e?.message ?? e))
  }
}
