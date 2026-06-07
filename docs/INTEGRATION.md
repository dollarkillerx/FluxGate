# Connecting FluxGate Admin to the real runtime

This document explains how to replace the **mock data plane** with the live
FluxGate (Pingora) runtime. The admin console and the JSON-RPC contract do not
change — only the server-side data sources do.

## Architecture at a glance

```
┌─────────────────────┐   JSON-RPC 2.0    ┌──────────────────────────────┐
│  React console       │  POST /rpc        │  fluxgate-admin (axum)        │
│  (embedded in binary)│ ───────────────►  │                              │
│                      │  Bearer token     │  rpc.rs  ── dispatch() ──┐    │
│  rpc.call<T>(m, p)   │ ◄───────────────  │                          │    │
└─────────────────────┘                   │   ┌──────────────────────▼──┐ │
                                          │   │  Store  (the data plane) │ │
       (auth.login method) ──────────►    │   │  state.rs + mock.rs      │ │
                                          │   └──────────┬───────────────┘ │
                                          │              │ persist.rs       │
                                          └──────────────┼──────────────────┘
                                                         ▼
                                          fluxgate-data.json   ◄── replace this
                                          (or the real runtime)
```

Three seams, in order of effort:

| Seam            | File                              | What it controls                         |
| --------------- | --------------------------------- | ---------------------------------------- |
| Method registry | `crates/fluxgate-admin/src/rpc.rs`| The `dispatch()` match — every RPC method |
| Data plane      | `crates/fluxgate-admin/src/state.rs` (`Store`) | Where data lives |
| Load/save       | `crates/fluxgate-admin/src/persist.rs` | How the data plane is hydrated/snapshotted |

The shared shapes live in `crates/fluxgate-core` and are mirrored 1:1 in
`web/src/types`, so the contract stays consistent across the stack.

---

## Step 1 — Decide where data comes from

The mock keeps everything in a single `Store` struct (in `state.rs`), seeded by
`mock.rs` and snapshotted to JSON by `persist.rs`. For the real runtime you have
two integration styles:

- **Config-backed** (routes, upstreams, WAF rules, TLS, settings): these are
  *configuration* the admin edits. Back them with FluxGate's real config store
  (file, etcd, database) and have writes push a reload into the running proxy.
- **Telemetry-backed** (dashboard, metrics, access logs, security events):
  these are *read-only* observations. Pull them from FluxGate's metrics
  registry / log pipeline instead of the in-memory vectors.

## Step 2 — Replace the data plane

Recommended approach: introduce a trait and make `dispatch()` call it, so the
mock and the real runtime are interchangeable.

```rust
// crates/fluxgate-admin/src/runtime.rs
pub trait ControlPlane: Send + Sync {
    // configuration (read + write)
    fn routes(&self) -> Vec<Route>;
    fn create_route(&self, input: RouteInput) -> Result<Route, ApiError>;
    fn update_route(&self, input: RouteInput) -> Result<Route, ApiError>;
    fn delete_route(&self, id: &str) -> Result<(), ApiError>;
    // ... upstreams, waf rules, tls, settings ...

    // telemetry (read-only)
    fn dashboard_summary(&self) -> DashboardSummary;
    fn metrics_system(&self) -> Vec<MetricSeries>;
    fn access_logs(&self, query: LogQuery) -> Paged<AccessLog>;

    // lifecycle
    fn reload(&self) -> Result<(), ApiError>;
}
```

Then:

1. Put the current in-memory logic behind `struct MockControlPlane(Mutex<Store>)`.
2. Implement `struct PingoraControlPlane { /* handles */ }` for the real runtime.
3. Store `Arc<dyn ControlPlane>` in `AppState` instead of `Arc<Mutex<Store>>`.
4. Select the implementation at startup (e.g. `FLUXGATE_BACKEND=mock|runtime`).

`dispatch()` then becomes a thin translator: parse params → call a trait method
→ serialize the result. The JSON-RPC envelope handling in `rpc.rs` is unchanged.

## Step 3 — Wire writes to a live reload

In the mock, `system.reload` is a no-op that returns success. For the real
runtime:

- On every successful config mutation (`*.create/update/delete/enable/disable`),
  apply the change to FluxGate's config and trigger Pingora's graceful reload
  (zero-downtime upgrade / `SIGHUP`-style config swap).
- Keep the audit log (`tracing` target `fluxgate::audit`) — it already records
  who changed what.

## Step 4 — Map each method to a real source

| RPC method group        | Real source                                        |
| ----------------------- | -------------------------------------------------- |
| `auth.login`            | User store + password verify → issue token (public)|
| `route.*`               | Proxy routing table (config) + reload              |
| `upstream.*`            | Upstream pools + Pingora health-check results       |
| `waf.rule.*`            | WAF ruleset (config) + per-rule hit counters       |
| `waf.event.list`        | WAF enforcement event stream / ring buffer         |
| `tls.cert.*`            | ACME client state + on-disk certificate store      |
| `access_log.*`          | Access-log pipeline (tail / query an index)        |
| `metrics.*`             | Metrics registry (Prometheus handles, gauges)      |
| `dashboard.*`           | Aggregations over the two above                    |
| `settings.*`            | Admin/runtime configuration                        |
| `system.info`           | Build info + process uptime                        |
| `system.reload`         | Trigger the graceful config reload                 |

## Step 5 — Harden auth

**Done:**
- Argon2id password hashing (`auth.rs`); only the hash is persisted.
- Signed, expiring JWTs (HS256, 8h) issued by `auth.login`, validated in the
  `handle_rpc` gate. Secret = `FLUXGATE_ADMIN_TOKEN`.
- Runtime credential changes (`auth.change_password`, username via
  `settings.update`).
- Private key files written `0600`.

**Still recommended for production:**
- Multi-user accounts + per-method authorization (roles) inside `dispatch()`.
- TLS on the admin listener — currently plain HTTP; terminate TLS in front, or
  add native HTTPS via `axum-server` + rustls.
- Tighten CORS in `main.rs` (`CorsLayer::permissive()` → explicit allowlist).
- A cap / complexity guard on user-supplied WAF regex (ReDoS), and a rotating
  store for the JWT signing secret.

## Step 6 — Swap the proxy for Pingora

`proxy.rs` is a real hyper/reqwest reverse proxy implementing FluxGate's routing
+ load-balancing + WAF-enforcement semantics. To run on Pingora instead:

- Implement Pingora's `ProxyHttp` trait in a new service: `upstream_peer()` reads
  the same `Store` (route match → `select_node`), `request_filter()` runs
  `WafEngine::evaluate` (return early on deny/challenge), `logging()` records into
  the `LogBuffer` / `EventBuffer`.
- Run the Pingora `Server` on `FLUXGATE_PROXY_ADDR` instead of the axum proxy.
- The admin plane, config store, collectors and WAF engine are reused unchanged —
  only the request-forwarding shell is replaced.

This is a focused, self-contained swap because the proxy logic is already
factored out of the data-forwarding mechanism.

---

## What you do NOT have to change

- The React frontend — it only ever calls `rpc.call<T>(method, params)`. No
  business data is hardcoded in the UI (`web/src/mock/` is a dev-only fallback).
- The JSON-RPC envelope, error codes, or method names.
- The TypeScript types, as long as `fluxgate-core` models keep the same shape.
