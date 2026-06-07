# FluxGate

English · [中文](./README-CN.md)

A high-performance **reverse proxy + programmable WAF** with a built-in **admin
console**, shipped as a single Rust binary. FluxGate forwards live traffic,
terminates TLS (SNI), enforces a Web Application Firewall, and manages everything
through a JSON-RPC API and an embedded React console.

- **Rust** admin server (`axum` + `tokio` + `hyper`) exposing a **JSON-RPC 2.0**
  API at `/rpc`.
- **React + TypeScript** console (Vite + Tailwind), tri-lingual (English / 中文 /
  日本語), **compiled into the binary** (`rust-embed`) — one executable serves
  the API, the UI, and the proxy.
- **No mock data on the backend.** Dashboards, metrics, logs and health are
  derived from real sources; configuration starts empty, is operator-managed,
  and is persisted to disk.

> The data plane is a `hyper`-based proxy (not Pingora). It implements real
> routing, load balancing, TLS/SNI, WebSocket bridging, streaming, and WAF
> enforcement.

---

## Two planes

FluxGate runs a **control plane** and a **data plane** in one process, sharing
state so config edits take effect live.

| Plane | What | Default listener |
| ----- | ---- | ---------------- |
| **Control** (admin console) | JSON-RPC API + embedded React UI, over **HTTPS** with an auto-generated self-signed certificate | `FLUXGATE_ADMIN_ADDR` = `127.0.0.1:8080` |
| **Data** — HTTP | Plaintext reverse proxy (and HTTP→HTTPS redirects) | `FLUXGATE_PROXY_ADDR` = `0.0.0.0:80` |
| **Data** — HTTPS | TLS reverse proxy with **SNI** certificate selection | `FLUXGATE_PROXY_TLS_ADDR` = `0.0.0.0:443` |

> Ports 80/443 are privileged — run with `sudo`, or point the proxy at high
> ports: `FLUXGATE_PROXY_ADDR=0.0.0.0:8080 FLUXGATE_PROXY_TLS_ADDR=0.0.0.0:8443`.
> The admin console is HTTPS with a self-signed cert, so your browser will warn
> on first visit — accept it to continue.

The control plane (admin console) is **not** subject to the WAF or recorded into
the access log / metrics — those belong to the data plane only.

---

## Sites → Routes

Configuration is two layers, matching how real sites are operated:

- A **Site** is one inbound host (e.g. `www.example.com`). It owns the
  **host-level** concerns: **enable TLS**, the **certificate** to present,
  **HTTP→HTTPS redirect**, and the **default WAF** setting.
- A **Route** is a path under a site (e.g. `/api`). It owns the **path-level**
  concerns: the target **upstream** and a per-path **WAF** toggle (inherits the
  site default, overridable).

Request resolution: `Host` → enabled Site → longest-prefix enabled Route →
load-balanced upstream node.

> Configs from the earlier flat-route schema are **auto-migrated** on startup:
> routes are grouped by host into sites (hoisting TLS/cert/redirect/WAF).

---

## Reverse proxy (data plane)

The proxy shares state with the console, so edits apply live and proxied traffic
flows into the same dashboards / logs / metrics. It:

- matches the incoming `Host` + longest path-prefix against enabled sites/routes;
- selects a healthy node from the route's **upstream** using its strategy
  (`round_robin` / `weighted` / `ip_hash`; `least_conn` ≈ round-robin);
- terminates **TLS with SNI** — a handshake only succeeds for a host that has
  **both** a `tls_enabled` site **and** a matching certificate; the site's chosen
  cert wins, else a domain match;
- **redirects HTTP→HTTPS** (308) for TLS-enabled sites with redirect on;
- runs the **WAF in enforcement mode**: `deny` → 403, and `challenge` → a
  **managed JS proof-of-work interstitial** that real browsers pass automatically
  (signed clearance cookie) while no-JS bots/scanners stay blocked;
- **streams** request/response bodies (SSE, large up/downloads — not buffered);
- proxies **WebSocket / HTTP Upgrade** (handshake forwarded, connections bridged);
- stamps a `Server: FluxGate/1.0` header (replacing the backend's) and records a
  real access-log entry.

```bash
# Create a site (host app.example.com) + a route (path / → upstream "web"), then:
curl -H 'Host: app.example.com' http://127.0.0.1:8088/
# A request matching a deny rule gets a real 403 (when the route has WAF on):
curl -H 'Host: app.example.com' http://127.0.0.1:8088/etc/passwd   # → 403
```

---

## What's real

| Area | Source |
| ---- | ------ |
| **Metrics** (CPU / memory / network) | Host telemetry via [`sysinfo`](https://crates.io/crates/sysinfo), sampled every 3s |
| **Access Logs** | Real HTTP requests served by the **data plane** (ring buffer + JSONL file) |
| **Dashboard** (total requests, QPS, active connections, traffic, top routes) | Derived from the access-log buffer + a data-plane in-flight counter |
| **Per-route analytics** (`metrics.route`) | Real QPS / latency p50·p99 / error-rate for a host+path, last 24 minutes |
| **Upstream health** | Real TCP-connect probe of each node (every 10s + immediately on save); tries **all** resolved addresses (IPv4 **and** IPv6) |
| **WAF hit counts / events / blocks** | Real: the data plane evaluates every proxied request; hit counts live in the engine, security events + `metrics.waf` are recorded |
| **TLS certificates** | Real crypto: `tls.cert.request`/`renew` generate a genuine ECDSA keypair + X.509 cert (`rcgen`); `tls.cert.upload` parses real PEM (`x509-parser`). A default self-signed cert is seeded on first run. Key files are written `0600` under `FLUXGATE_CERT_DIR`. |
| **Sites / Routes / Upstreams / WAF rules / Certificates / Settings** | Operator-managed configuration, persisted to `FLUXGATE_DATA_FILE` |
| **ACME automatic issuance** | Not wired — `tls.cert.request` issues a local self-signed cert as the stand-in (real ACME needs a public domain + reachable challenge). See `docs/INTEGRATION.md`. |

The **WAF engine** (`crates/fluxgate-admin/src/waf.rs`) supports `ip` (exact +
IPv4 CIDR), `path` / `method` / `header` (regex), and `rate_limit`
(`prefix@Nr/s`, real per-client fixed window, bounded memory). `geo` needs a
GeoIP database and never matches. Rules are **compiled once** (regexes/CIDRs
pre-built, priority-sorted) into a lock-free snapshot; path rules match the
**path *and* query**, percent-decoded (so `%2e%2e` encoded traversal can't slip
past). Rust's `regex` is linear-time, so attacker-supplied patterns can't ReDoS.
First match wins, falling back to the default action. The data plane
**enforces**; the admin console is never evaluated (so you can't lock yourself
out).

The **built-in baseline ruleset** covers dangerous methods, SQLi, NoSQLi, XSS,
path traversal/LFI, RCE, Log4Shell (`${jndi:…}`), CRLF, web shells, secret files,
scanner User-Agents, and rate limits. An **OWASP CRS pack** (a curated subset of
the OWASP Core Rule Set, Apache-2.0) can be imported on demand from the WAF page
(or via `waf.rule.import`) for SQLi/XSS/RCE/LFI/RFI/PHP/Java/SSRF/scanner
coverage — no new dependency, since it's reimplemented as regex rules.

**Log retention:** access logs and WAF events older than
`FLUXGATE_LOG_RETENTION_DAYS` (default **6**) are pruned from memory and disk on
startup and hourly.

---

## Project structure

```
fluxgate/
├── Cargo.toml                      # Rust workspace (parking_lot, rustls, hyper, rcgen, …)
├── crates/
│   ├── fluxgate-core/              # Shared domain models (serde): Site, Route, Upstream, …
│   └── fluxgate-admin/
│       └── src/
│           ├── main.rs             # Bootstrap: planes, background tasks, retention
│           ├── rpc.rs              # JSON-RPC 2.0 dispatcher + auth gate + method registry
│           ├── proxy.rs            # Data plane: routing, LB, WAF enforce, WS/streaming
│           ├── serve.rs            # TLS serving + SNI cert resolver (cached)
│           ├── tls.rs              # Cert generation (rcgen) + PEM parsing (x509-parser)
│           ├── waf.rs              # WAF rule-matching engine (+ engine-side hit counters)
│           ├── collector.rs        # Telemetry, access-log/event buffers, metrics, probing
│           ├── state.rs            # AppState (parking_lot mutexes) + Config
│           └── persist.rs          # Config load/save (+ legacy→sites migration)
└── web/                            # React admin console (embedded into the binary)
    └── src/{api,components,context,hooks,i18n,lib,mock,pages,types}
```

---

## Quick start

```bash
# 1. Build the frontend (outputs web/dist, embedded by the binary)
cd web && npm install && npm run build && cd ..

# 2. Run — admin console on HTTPS; proxy on high ports to avoid sudo
FLUXGATE_PROXY_ADDR=0.0.0.0:8088 FLUXGATE_PROXY_TLS_ADDR=0.0.0.0:8443 \
  cargo run -p fluxgate-admin
```

Open **https://127.0.0.1:8080** and accept the self-signed certificate. Default
demo login: `admin` / `admin`.

> The binary embeds `web/dist` at **compile time**. After changing the frontend,
> re-run `npm run build` **and** rebuild the Rust binary.

### Single release binary

```bash
cd web && npm install && npm run build && cd ..
cargo build --release -p fluxgate-admin
sudo ./target/release/fluxgate-admin        # sudo to bind :80/:443
```

### Frontend hot reload

```bash
cargo run -p fluxgate-admin        # terminal 1
cd web && npm run dev              # terminal 2 → http://localhost:5173
```

Vite proxies `/rpc` and `/health` to the Rust server. With no backend running,
the console falls back to the in-repo mock (`web/src/mock/`); force it with
`VITE_USE_MOCK=true`.

---

## Configuration (environment variables)

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `FLUXGATE_ADMIN_ADDR` | `127.0.0.1:8080` | Admin console listen address (served over **HTTPS**). |
| `FLUXGATE_PROXY_ADDR` | `0.0.0.0:80` | Data-plane **HTTP** listen address. Empty = disabled. |
| `FLUXGATE_PROXY_TLS_ADDR` | `0.0.0.0:443` | Data-plane **HTTPS** (SNI) listen address. Empty = disabled. |
| `FLUXGATE_ADMIN_TOKEN` | `fluxgate-dev-token` | **JWT signing secret**. Change in production. |
| `FLUXGATE_ADMIN_USER` | `admin` | Bootstrap login username (first run only; then editable in-app). |
| `FLUXGATE_ADMIN_PASSWORD` | `admin` | Bootstrap login password (first run only; Argon2id-hashed + stored). |
| `FLUXGATE_DATA_FILE` | `fluxgate-data.json` | Config persistence path. Empty = in-memory. |
| `FLUXGATE_CERT_DIR` | `fluxgate-certs` | Directory for certificate + key PEM files. |
| `FLUXGATE_LOG_FILE` | `fluxgate-access.log` | Access-log JSONL file. Empty = disabled. |
| `FLUXGATE_EVENT_FILE` | `fluxgate-events.log` | WAF-event JSONL file. Empty = disabled. |
| `FLUXGATE_LOG_RETENTION_DAYS` | `6` | Days to keep access logs / WAF events (pruned hourly + on boot). |
| `RUST_LOG` | `info` | Tracing filter (e.g. `fluxgate_admin=debug`). |

---

## Authentication

The console opens on a **login screen**. Default demo credentials: `admin` / `admin`.

- **Login is a JSON-RPC call** (`auth.login`, the only method callable without a
  token); it verifies the credentials and returns a **signed, expiring JWT**
  (HS256, 8h TTL, signed with `FLUXGATE_ADMIN_TOKEN`).
- **Passwords are hashed with Argon2id** — only the hash is persisted. Env
  credentials seed the store on first run only; both are editable at runtime
  (Settings → `settings.update` / `auth.change_password`).
- Every other method validates the JWT; failure returns `-32001` and the console
  returns to login.

```bash
TOKEN=$(curl -sk -X POST https://127.0.0.1:8080/rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"auth.login","params":{"username":"admin","password":"admin"}}' \
  | jq -r .result.token)
curl -sk -X POST https://127.0.0.1:8080/rpc -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":2,"method":"site.list"}'
```

---

## HTTP endpoints & JSON-RPC

| Method | Path | Description |
| ------ | ---- | ----------- |
| `POST` | `/rpc` | JSON-RPC 2.0 API. `auth.login` is public; all others require a bearer token. |
| `GET` | `/health` | Liveness probe (public). |
| `GET` | `/*` | Embedded console + SPA fallback. |

```json
// request
{ "jsonrpc": "2.0", "id": 1, "method": "site.list", "params": {} }
// success
{ "jsonrpc": "2.0", "id": 1, "result": [ /* ... */ ] }
// error
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32602, "message": "Invalid params" } }
```

### Methods

| Group | Methods |
| ----- | ------- |
| Auth | `auth.login` (public), `auth.change_password` |
| Dashboard | `dashboard.summary`, `dashboard.traffic`, `dashboard.security_events` |
| Sites | `site.list`, `site.get`, `site.create`, `site.update`, `site.delete` |
| Routes | `route.list`, `route.get`, `route.create`, `route.update`, `route.delete`, `route.enable`, `route.disable` |
| Upstreams | `upstream.list`, `upstream.get`, `upstream.create`, `upstream.update`, `upstream.delete`, `upstream.health` |
| WAF | `waf.rule.list`, `waf.rule.get`, `waf.rule.create`, `waf.rule.update`, `waf.rule.delete`, `waf.rule.enable`, `waf.rule.disable`, `waf.event.list`, `waf.pack.list`, `waf.rule.import` |
| TLS | `tls.cert.list`, `tls.cert.get`, `tls.cert.request`, `tls.cert.renew`, `tls.cert.upload`, `tls.cert.delete` |
| Logs | `access_log.list`, `access_log.search` |
| Metrics | `metrics.system`, `metrics.traffic`, `metrics.route`, `metrics.upstream`, `metrics.waf` |
| Settings | `settings.get`, `settings.update`, `system.reload`, `system.info` |

Error codes: `-32700` parse · `-32600` invalid request · `-32601` method not
found · `-32602` invalid params · `-32603` internal · `-32004` not found ·
`-32001` unauthorized.

---

## Admin console pages

`Dashboard` · `Sites` (hosts → paths, collapsible, with per-path analytics) ·
`Upstreams` · `WAF Rules` · `TLS Certificates` · `Access Logs` · `Metrics` ·
`Settings`.

Features: searchable/sortable tables (TanStack Table), create/edit modals,
confirm dialogs for destructive actions, status badges, toasts, live
auto-refresh, full loading/error states, light/dark themes.

---

## Persistence

Configuration mutations (sites, routes, upstreams, WAF rules, certificates,
settings, credentials) are snapshotted to `FLUXGATE_DATA_FILE` (atomic write) and
reloaded on startup; legacy flat-route configs are migrated to sites. Access logs
and WAF events are appended to their JSONL files and the recent tail is reloaded
on restart. Host telemetry and upstream health are sampled live, not persisted.

---

## Build, test & deploy

```bash
cargo test --workspace        # Rust unit tests (WAF, TLS, auth/JWT, LB, retention, SNI)
cargo fmt --all --check       # formatting (enforced in CI)
cargo clippy --workspace      # lints

docker compose up --build     # single container: console + proxy
```

CI (`.github/workflows/ci.yml`) runs fmt + clippy + `cargo test` and a frontend
typecheck/build on every push and PR.

---

## Performance

Measured on a release build (`cargo build --release`), single host.

**WAF — lock-free, pre-compiled rule set.** Rules are compiled once (regexes
built, CIDRs parsed, priority-sorted) into an immutable snapshot read through an
`Arc`; the request path does no allocation, no sort, and no regex compilation.
Microbenchmark over the **full baseline + OWASP CRS pack (32 regex/IP rules)**
(`cargo test --release -- --ignored bench_evaluate`):

| Case | Cost | Throughput / core |
| ---- | ---- | ----------------- |
| Benign (every rule evaluated) | ~350 ns/req | ~2.8M req/s |
| Attack (early match) | ~190 ns/req | ~5.2M req/s |

End-to-end (`ab -k -c50`, same backend), WAF **off vs on** was within noise
(~25k req/s both, 0 failures) — the sub-microsecond WAF cost is dwarfed by
network + backend latency (the ~25k ceiling there was the test backend, not the
proxy). Note: the built-in `2000 r/s` rate-limit rule legitimately throttles a
single-IP flood, so disable rate-limit rules before micro-measuring CPU cost.

**Other hot-path work is already minimized:** access-log/metric timestamps are
parsed once (no per-poll re-parse or full-buffer clone); the SNI resolver caches
parsed certificates per version (no disk read/parse per handshake); access/event
logs use a long-lived `O_APPEND` handle (no `open()` per request); shared state
uses `parking_lot` mutexes (no poisoning); WAF hit counters live in the engine
(no Store write on the hot path); and admin-console requests are kept out of the
proxy's metrics/logs entirely.

**Known ceiling.** A single config mutex still guards routing (`pick_target`
locks it once per request), control-plane reads, and persistence (which
serializes the whole store under the lock). Under high concurrency this is the
throughput ceiling; publishing an `arc-swap` routing snapshot for lock-free
data-plane reads is the next optimization.

---

## Notes & roadmap

- **Concurrency:** shared state uses `parking_lot` mutexes (no poisoning). The
  single config lock is the main scalability ceiling; an `arc-swap` routing
  snapshot for lock-free data-plane reads is the next step.
- **TLS terminated in-process** (rustls); the SNI resolver caches parsed
  certificates per cert version.
- Sensitive operations are written to the audit log (`tracing` target
  `fluxgate::audit`).

## License

MIT — see [LICENSE](./LICENSE).
