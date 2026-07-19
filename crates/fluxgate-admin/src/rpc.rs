//! JSON-RPC 2.0 endpoint and method registry.
//!
//! A single `POST /rpc` entrypoint parses the envelope, dispatches on `method`,
//! and wraps the result (or error) back into a spec-compliant response. The
//! `dispatch` match IS the registry — every supported method appears there.
//!
//! Standard error codes used:
//!   -32700 parse error · -32600 invalid request · -32601 method not found
//!   -32602 invalid params · -32603 internal error · -32004 not found (custom)

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;

use std::sync::atomic::Ordering;

use fluxgate_core::*;

use crate::{collector, state::AppState};

// ---------------------------------------------------------------------------
// Envelope types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RpcRequest {
    #[serde(default)]
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(-32602, format!("Invalid params: {}", msg.into()))
    }
    fn not_found(what: impl Into<String>) -> Self {
        Self::new(-32004, format!("Not found: {}", what.into()))
    }
}

type RpcResult = Result<Value, RpcError>;

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

pub async fn handle_rpc(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let req: RpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            return Json(error_response(
                Value::Null,
                RpcError::new(-32700, format!("Parse error: {e}")),
            ));
        }
    };

    let id = req.id.clone();

    if req.jsonrpc != "2.0" {
        return Json(error_response(
            id,
            RpcError::new(-32600, "Invalid request: jsonrpc must be \"2.0\""),
        ));
    }

    // Bearer-token gate. Everything goes through /rpc, so auth is enforced here
    // per-method: only PUBLIC methods (login) are reachable without a valid JWT.
    if !is_public(&req.method) {
        let valid = bearer_token(&headers)
            .and_then(|t| crate::auth::verify_jwt(&t, state.admin_token()))
            .is_some();
        if !valid {
            return Json(error_response(
                id,
                RpcError::new(-32001, "Unauthorized: missing or invalid session token"),
            ));
        }
    }

    tracing::debug!(method = %req.method, "rpc call");

    let method = req.method.clone();
    // Brute-force throttle for the admin login. Keyed on the **socket peer IP**
    // (not X-Forwarded-For, which a client could spoof to evade the lockout). The
    // admin console isn't on the WAF/data-plane, so this is its only login guard.
    // The IP string is resolved only on the login path — every other RPC (dashboard
    // polling, config reads) skips the allocation entirely.
    let client_ip = (method == "auth.login").then(|| peer.ip().to_string());
    if let Some(ip) = &client_ip {
        let now = Utc::now().timestamp();
        if let Some(retry) = state.login_throttle.locked_for(ip, now) {
            tracing::warn!(target: "fluxgate::audit", ip = %ip, "login blocked: too many failed attempts");
            return Json(error_response(
                id,
                RpcError::new(
                    -32029,
                    format!("Too many failed login attempts. Try again in {retry}s."),
                ),
            ));
        }
    }

    match dispatch(&state, &method, req.params) {
        Ok(result) => {
            // A successful login clears that IP's failure streak.
            if let Some(ip) = &client_ip {
                state.login_throttle.record_success(ip);
            }
            // Snapshot to disk after any state-changing call succeeds.
            if is_mutation(&method) {
                let store = state.store.lock();
                crate::persist::save(&state.config.data_path, &store);
                // Recompile the WAF rule set when rules changed (keeps the
                // lock-free hot-path snapshot current).
                if method.starts_with("waf.rule") {
                    state.waf.rebuild(&store.waf_rules);
                }
                // Recompile the semantic-engine policy when it changed.
                if method.starts_with("waf.semantic") || method.starts_with("waf.exception") {
                    state.waf.rebuild_semantic(&store.waf_semantic);
                }
                // Recompile the IP allow/block lists when they changed.
                if method.starts_with("ip.") {
                    state
                        .access
                        .rebuild(&store.ip_whitelist, &store.ip_blacklist);
                }
            }
            Json(success_response(id, result))
        }
        Err(err) => {
            // Count only genuine credential rejections (-32001) toward the lockout,
            // not malformed-params or internal errors.
            if let Some(ip) = &client_ip {
                if err.code == -32001 {
                    let locked = state
                        .login_throttle
                        .record_failure(ip, Utc::now().timestamp());
                    if locked > 0 {
                        tracing::warn!(target: "fluxgate::audit", ip = %ip, secs = locked, "login locked out");
                    }
                }
            }
            tracing::warn!(method = %method, code = err.code, msg = %err.message, "rpc error");
            Json(error_response(id, err))
        }
    }
}

/// Methods callable without authentication.
fn is_public(method: &str) -> bool {
    method == "auth.login"
}

/// Extract a `Bearer <token>` value from the Authorization header.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
}

/// Whether a method mutates the store (and therefore should be persisted).
fn is_mutation(method: &str) -> bool {
    matches!(
        method.rsplit('.').next(),
        Some(
            "create"
                | "update"
                | "delete"
                | "enable"
                | "disable"
                | "request"
                | "renew"
                | "upload"
                | "import"
        )
    ) || method == "settings.update"
        || method == "auth.change_password"
        // IP allow/block list mutations (the `.add` / `.remove` / unban suffixes).
        || (method.starts_with("ip.") && method != "ip.list")
}

fn success_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, err: RpcError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": err.code, "message": err.message } })
}

// ---------------------------------------------------------------------------
// Dispatch / method registry
// ---------------------------------------------------------------------------

fn dispatch(state: &AppState, method: &str, params: Value) -> RpcResult {
    let mut store = state.store.lock();

    match method {
        // ---- Auth ----
        "auth.login" => {
            // Public. Verifies the Argon2 hash and issues a signed, expiring JWT.
            let p: LoginParams = parse(params)?;
            let ok_creds = p.username == store.auth.username
                && crate::auth::verify_password(&p.password, &store.auth.password_hash);
            if ok_creds {
                let token = crate::auth::issue_jwt(
                    &store.auth.username,
                    &state.config.admin_token,
                    Utc::now().timestamp(),
                )
                .map_err(|e| RpcError::new(-32603, e))?;
                tracing::info!(target: "fluxgate::audit", user = %p.username, "login succeeded");
                ok(json!({ "token": token, "username": store.auth.username }))
            } else {
                tracing::warn!(target: "fluxgate::audit", user = %p.username, "login failed");
                Err(RpcError::new(-32001, "Invalid username or password"))
            }
        }
        "auth.change_password" => {
            let p: ChangePasswordParams = parse(params)?;
            if !crate::auth::verify_password(&p.current_password, &store.auth.password_hash) {
                return Err(RpcError::new(-32001, "Current password is incorrect"));
            }
            if p.new_password.len() < 6 {
                return Err(RpcError::invalid_params(
                    "new password must be at least 6 characters",
                ));
            }
            store.auth.password_hash = crate::auth::hash_password(&p.new_password)
                .map_err(|e| RpcError::new(-32603, e))?;
            if let Some(u) = p.username.filter(|u| !u.trim().is_empty()) {
                store.auth.username = u.clone();
                store.settings.admin_username = u;
            }
            audit("auth.change_password", &store.auth.username);
            ok(json!({ "success": true, "username": store.auth.username }))
        }

        // ---- Dashboard (derived from real request logs + config) ----
        "dashboard.summary" => {
            // Read the cheap config-derived counts, then release the global store
            // lock *before* the log scan so the proxy data plane (which also takes
            // store on every request) isn't blocked by it.
            let waf_blocks = state.waf_events.lock().total_deny();
            let tls_certificates = store.certs.len() as u32;
            let healthy_upstreams = store
                .upstreams
                .iter()
                .filter(|u| matches!(u.status, fluxgate_core::UpstreamStatus::Healthy))
                .count() as u32;
            let total_upstreams = store.upstreams.len() as u32;
            let inflight = state.inflight.load(Ordering::SeqCst);
            drop(store);
            let (snap, total_requests) = {
                let g = state.logs.lock();
                (g.snapshot(), g.total())
            };
            let mut summary = collector::dashboard_summary(
                &snap,
                Utc::now(),
                collector::SummaryConfig {
                    waf_blocks,
                    tls_certificates,
                    healthy_upstreams,
                    total_upstreams,
                    total_requests,
                    inflight,
                },
            );
            // Whole-proxy byte traffic (summed across all sites).
            summary.traffic = state.traffic.global_totals();
            ok(summary)
        }
        "dashboard.traffic" => {
            // No store needed — release it before scanning logs.
            drop(store);
            let snap = state.logs.lock().snapshot();
            ok(json!({
                "points": collector::traffic_points(&snap),
                "top_routes": collector::top_routes(&snap),
            }))
        }
        "dashboard.security_events" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(8) as usize;
            let mut events = state.waf_events.lock().snapshot();
            events.truncate(limit);
            ok(events)
        }
        "dashboard.countries" => {
            // Visitor countries over 24h (GeoIP on the client IP). Release the
            // store lock, snapshot the logs, then resolve countries outside both.
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(8) as usize;
            drop(store);
            let snap = state.logs.lock().snapshot();
            let stats = collector::window_stats(
                &snap,
                Utc::now(),
                |_| true,
                |ip| state.waf.country_of(ip),
                limit,
            );
            ok(stats.countries)
        }
        "dashboard.devices" => {
            // Whole-proxy client device / OS breakdown over the last 24h, parsed
            // from User-Agents recorded in the access log.
            drop(store);
            let snap = state.logs.lock().snapshot();
            let stats = collector::window_stats(
                &snap,
                Utc::now(),
                |_| true,
                |ip| state.waf.country_of(ip),
                1,
            );
            ok(stats.devices)
        }
        "dashboard.attacks" => {
            // Risk board: 24h WAF-block timeline + top attacker UAs + attack-source
            // countries, from the recorded WAF events.
            drop(store);
            let events = state.waf_events.lock();
            ok(collector::attack_overview(
                &events,
                Utc::now(),
                |ip| state.waf.country_of(ip),
                10,
                12,
            ))
        }

        // ---- IP access control (allow / block lists + auto-ban) ----
        "ip.list" => ok(json!({
            "whitelist": &store.ip_whitelist,
            "blacklist": &store.ip_blacklist,
            "bans": state.access.list_bans(Utc::now().timestamp()),
            "auto_ban_enabled": store.settings.auto_ban_enabled,
            "auto_ban_threshold": store.settings.auto_ban_threshold,
            "auto_ban_duration_secs": store.settings.auto_ban_duration_secs,
        })),
        "ip.whitelist.add" => add_ip_entry(&mut store.ip_whitelist, params),
        "ip.whitelist.remove" => remove_ip_entry(&mut store.ip_whitelist, params),
        "ip.blacklist.add" => add_ip_entry(&mut store.ip_blacklist, params),
        "ip.blacklist.remove" => remove_ip_entry(&mut store.ip_blacklist, params),
        "ip.ban.remove" => {
            let p: IpBanInput = parse(params)?;
            let removed = state.access.unban(&p.ip);
            // Persist immediately so the unban sticks even if we restart before the
            // periodic flush (otherwise the ban would resurrect from disk).
            state.access.flush(Utc::now().timestamp());
            audit("ip.ban.remove", &p.ip);
            ok(json!({ "removed": removed }))
        }

        // ---- Sites (hosts) ----
        "site.list" => ok(&store.sites),
        "site.get" => {
            let p: IdParam = parse(params)?;
            store
                .sites
                .iter()
                .find(|s| s.id == p.id)
                .map(ok_ref)
                .unwrap_or_else(|| Err(RpcError::not_found(format!("site {}", p.id))))
        }
        "site.create" => {
            let input: SiteInput = parse(params)?;
            let host = input.host.unwrap_or_default();
            if host.trim().is_empty() {
                return Err(RpcError::invalid_params("`host` is required"));
            }
            let now = Utc::now().to_rfc3339();
            let site = Site {
                id: short_id("st"),
                name: input
                    .name
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| host.clone()),
                host,
                tls_enabled: input.tls_enabled.unwrap_or(true),
                cert_id: input.cert_id.filter(|s| !s.is_empty()),
                https_redirect: input.https_redirect.unwrap_or(true),
                waf_enabled: input.waf_enabled.unwrap_or(true),
                max_body_mb: input.max_body_mb.unwrap_or(500),
                upstream_timeout_secs: input.upstream_timeout_secs.unwrap_or(120),
                block_crawler_ua: input.block_crawler_ua.unwrap_or(false),
                browser_only: input.browser_only.unwrap_or(false),
                rewrite_robots: input.rewrite_robots.unwrap_or(false),
                redirects: normalize_redirects(input.redirects),
                blocked_countries: normalize_countries(input.blocked_countries),
                block_datacenter: input.block_datacenter.unwrap_or(false),
                cloudflare_only: input.cloudflare_only.unwrap_or(false),
                enabled: input.enabled.unwrap_or(true),
                created_at: now.clone(),
                updated_at: now,
            };
            store.sites.insert(0, site.clone());
            audit("site.create", &site.id);
            ok(site)
        }
        "site.update" => {
            let input: SiteInput = parse(params)?;
            let id = require_id(&input.id)?;
            let s = store
                .sites
                .iter_mut()
                .find(|s| s.id == id)
                .ok_or_else(|| RpcError::not_found(format!("site {id}")))?;
            if let Some(v) = input.name {
                s.name = v;
            }
            if let Some(v) = input.host {
                s.host = v;
            }
            if let Some(v) = input.tls_enabled {
                s.tls_enabled = v;
            }
            if let Some(v) = input.cert_id {
                s.cert_id = if v.is_empty() { None } else { Some(v) };
            }
            if let Some(v) = input.https_redirect {
                s.https_redirect = v;
            }
            if let Some(v) = input.waf_enabled {
                s.waf_enabled = v;
            }
            if let Some(v) = input.max_body_mb {
                s.max_body_mb = v;
            }
            if let Some(v) = input.upstream_timeout_secs {
                s.upstream_timeout_secs = v;
            }
            if let Some(v) = input.block_crawler_ua {
                s.block_crawler_ua = v;
            }
            if let Some(v) = input.browser_only {
                s.browser_only = v;
            }
            if let Some(v) = input.rewrite_robots {
                s.rewrite_robots = v;
            }
            if let Some(v) = input.redirects {
                s.redirects = normalize_redirects(Some(v));
            }
            if let Some(v) = input.blocked_countries {
                s.blocked_countries = normalize_countries(Some(v));
            }
            if let Some(v) = input.block_datacenter {
                s.block_datacenter = v;
            }
            if let Some(v) = input.cloudflare_only {
                s.cloudflare_only = v;
            }
            if let Some(v) = input.enabled {
                s.enabled = v;
            }
            s.updated_at = Utc::now().to_rfc3339();
            let out = s.clone();
            audit("site.update", &id);
            ok(out)
        }
        "site.delete" => {
            let p: IdParam = parse(params)?;
            let before = store.sites.len();
            store.sites.retain(|s| s.id != p.id);
            if store.sites.len() == before {
                return Err(RpcError::not_found(format!("site {}", p.id)));
            }
            // Cascade: remove the site's path routes too.
            store.routes.retain(|r| r.site_id != p.id);
            audit("site.delete", &p.id);
            ok(json!({ "success": true, "id": p.id }))
        }

        // ---- Routes (paths under a site) ----
        "route.list" => ok(&store.routes),
        "route.get" => {
            let p: IdParam = parse(params)?;
            store
                .routes
                .iter()
                .find(|r| r.id == p.id)
                .map(ok_ref)
                .unwrap_or_else(|| Err(RpcError::not_found(format!("route {}", p.id))))
        }
        "route.create" => {
            let input: RouteInput = parse(params)?;
            let site_id = input.site_id.filter(|s| !s.is_empty());
            let Some(site_id) = site_id else {
                return Err(RpcError::invalid_params("`site_id` is required"));
            };
            let site = store
                .sites
                .iter()
                .find(|s| s.id == site_id)
                .ok_or_else(|| RpcError::not_found(format!("site {site_id}")))?;
            // New paths inherit the site's default WAF setting unless specified.
            let waf_default = site.waf_enabled;
            let now = Utc::now().to_rfc3339();
            let route = Route {
                id: short_id("rt"),
                site_id,
                name: input.name.unwrap_or_default(),
                path: input.path.unwrap_or_else(|| "/".into()),
                upstream: input.upstream.unwrap_or_default(),
                waf_enabled: input.waf_enabled.unwrap_or(waf_default),
                waf_mode: parse_route_mode(input.waf_mode.as_deref()),
                strip_prefix: input.strip_prefix.unwrap_or(false),
                enabled: input.enabled.unwrap_or(true),
                created_at: now.clone(),
                updated_at: now,
            };
            store.routes.insert(0, route.clone());
            audit("route.create", &route.id);
            ok(route)
        }
        "route.update" => {
            let input: RouteInput = parse(params)?;
            let id = require_id(&input.id)?;
            let r = store
                .routes
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or_else(|| RpcError::not_found(format!("route {id}")))?;
            if let Some(v) = input.site_id.filter(|s| !s.is_empty()) {
                r.site_id = v;
            }
            if let Some(v) = input.name {
                r.name = v;
            }
            if let Some(v) = input.path {
                r.path = v;
            }
            if let Some(v) = input.upstream {
                r.upstream = v;
            }
            if let Some(v) = input.waf_enabled {
                r.waf_enabled = v;
            }
            if let Some(v) = &input.waf_mode {
                r.waf_mode = parse_route_mode(Some(v));
            }
            if let Some(v) = input.strip_prefix {
                r.strip_prefix = v;
            }
            if let Some(v) = input.enabled {
                r.enabled = v;
            }
            r.updated_at = Utc::now().to_rfc3339();
            let out = r.clone();
            audit("route.update", &id);
            ok(out)
        }
        "route.delete" => {
            let p: IdParam = parse(params)?;
            let before = store.routes.len();
            store.routes.retain(|r| r.id != p.id);
            if store.routes.len() == before {
                return Err(RpcError::not_found(format!("route {}", p.id)));
            }
            audit("route.delete", &p.id);
            ok(json!({ "success": true, "id": p.id }))
        }
        "route.enable" => set_route_enabled(&mut store, params, true),
        "route.disable" => set_route_enabled(&mut store, params, false),

        // ---- L4 (TLS-SNI passthrough) routes ----
        "l4route.list" => ok(&store.l4_routes),
        "l4route.get" => {
            let p: IdParam = parse(params)?;
            store
                .l4_routes
                .iter()
                .find(|r| r.id == p.id)
                .map(ok_ref)
                .unwrap_or_else(|| Err(RpcError::not_found(format!("l4 route {}", p.id))))
        }
        "l4route.create" => {
            let input: L4RouteInput = parse(params)?;
            let now = Utc::now().to_rfc3339();
            let route = L4Route {
                id: short_id("l4"),
                name: input.name.unwrap_or_default(),
                server_names: input.server_names.unwrap_or_default(),
                origins: input.origins.unwrap_or_default(),
                strategy: input.strategy.unwrap_or(LbStrategy::RoundRobin),
                connect_timeout_secs: input.connect_timeout_secs.unwrap_or(0),
                enabled: input.enabled.unwrap_or(true),
                created_at: now.clone(),
                updated_at: now,
            };
            store.l4_routes.insert(0, route.clone());
            audit("l4route.create", &route.id);
            ok(route)
        }
        "l4route.update" => {
            let input: L4RouteInput = parse(params)?;
            let id = require_id(&input.id)?;
            let r = store
                .l4_routes
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or_else(|| RpcError::not_found(format!("l4 route {id}")))?;
            if let Some(v) = input.name {
                r.name = v;
            }
            if let Some(v) = input.server_names {
                r.server_names = v;
            }
            if let Some(v) = input.origins {
                r.origins = v;
            }
            if let Some(v) = input.strategy {
                r.strategy = v;
            }
            if let Some(v) = input.connect_timeout_secs {
                r.connect_timeout_secs = v;
            }
            if let Some(v) = input.enabled {
                r.enabled = v;
            }
            r.updated_at = Utc::now().to_rfc3339();
            let out = r.clone();
            audit("l4route.update", &id);
            ok(out)
        }
        "l4route.delete" => {
            let p: IdParam = parse(params)?;
            let before = store.l4_routes.len();
            store.l4_routes.retain(|r| r.id != p.id);
            if store.l4_routes.len() == before {
                return Err(RpcError::not_found(format!("l4 route {}", p.id)));
            }
            audit("l4route.delete", &p.id);
            ok(json!({ "success": true, "id": p.id }))
        }
        "l4route.enable" => set_l4route_enabled(&mut store, params, true),
        "l4route.disable" => set_l4route_enabled(&mut store, params, false),

        // ---- Upstreams ----
        "upstream.list" => ok(&store.upstreams),
        "upstream.get" => {
            let p: IdParam = parse(params)?;
            store
                .upstreams
                .iter()
                .find(|u| u.id == p.id)
                .map(ok_ref)
                .unwrap_or_else(|| Err(RpcError::not_found(format!("upstream {}", p.id))))
        }
        "upstream.create" => {
            let input: UpstreamInput = parse(params)?;
            let mut servers = input.servers.unwrap_or_default();
            for s in &mut servers {
                s.address = normalize_addr(&s.address);
            }
            let mut up = Upstream {
                id: short_id("up"),
                name: input.name.unwrap_or_else(|| "new-upstream".into()),
                strategy: input.strategy.unwrap_or(LbStrategy::RoundRobin),
                servers,
                healthy_servers: 0,
                status: UpstreamStatus::Down,
                tls: input.tls.unwrap_or(false),
            };
            // Probe immediately so the returned/persisted status reflects reality
            // right away instead of trusting the client-supplied `healthy` flag
            // (which would otherwise show green until the next background sweep).
            collector::probe_one_upstream(&mut up);
            store.upstreams.insert(0, up.clone());
            audit("upstream.create", &up.id);
            ok(up)
        }
        "upstream.update" => {
            let input: UpstreamInput = parse(params)?;
            let id = require_id(&input.id)?;
            let u = store
                .upstreams
                .iter_mut()
                .find(|u| u.id == id)
                .ok_or_else(|| RpcError::not_found(format!("upstream {id}")))?;
            if let Some(v) = input.name {
                u.name = v;
            }
            if let Some(v) = input.strategy {
                u.strategy = v;
            }
            if let Some(mut v) = input.servers {
                for s in &mut v {
                    s.address = normalize_addr(&s.address);
                }
                u.servers = v;
            }
            if let Some(v) = input.tls {
                u.tls = v;
            }
            // Re-probe on every edit so an added/changed node's health is accurate
            // immediately rather than after the next background sweep.
            collector::probe_one_upstream(u);
            let out = u.clone();
            audit("upstream.update", &id);
            ok(out)
        }
        "upstream.delete" => {
            let p: IdParam = parse(params)?;
            let before = store.upstreams.len();
            store.upstreams.retain(|u| u.id != p.id);
            if store.upstreams.len() == before {
                return Err(RpcError::not_found(format!("upstream {}", p.id)));
            }
            audit("upstream.delete", &p.id);
            ok(json!({ "success": true, "id": p.id }))
        }
        "upstream.health" => {
            // Real TCP probe of every node in this upstream, right now.
            let p: IdParam = parse(params)?;
            let u = store
                .upstreams
                .iter_mut()
                .find(|u| u.id == p.id)
                .ok_or_else(|| RpcError::not_found(format!("upstream {}", p.id)))?;
            collector::probe_one_upstream(u);
            ok(u.clone())
        }

        // ---- WAF rule packs (bundled open-source rulesets) ----
        "waf.pack.list" => ok(crate::waf_packs::packs()
            .iter()
            .map(|p| {
                json!({
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "rule_count": (p.rules)().len(),
                })
            })
            .collect::<Vec<_>>()),
        "waf.rule.import" => {
            #[derive(Deserialize)]
            struct ImportParams {
                pack: String,
            }
            let p: ImportParams = parse(params)?;
            let pack = crate::waf_packs::pack_rules(&p.pack)
                .ok_or_else(|| RpcError::not_found(format!("rule pack {}", p.pack)))?;
            // Additive + idempotent: skip rules already present (by id).
            let known: std::collections::HashSet<String> =
                store.waf_rules.iter().map(|r| r.id.clone()).collect();
            let mut imported = 0u32;
            for rule in pack {
                if !known.contains(&rule.id) {
                    store.waf_rules.push(rule);
                    imported += 1;
                }
            }
            audit("waf.rule.import", &p.pack);
            ok(json!({ "imported": imported, "pack": p.pack }))
        }

        // ---- WAF rules ----
        "waf.rule.list" => {
            // Overlay the engine's live hit counters (kept off the hot path).
            let hits = state.waf.hits();
            let rules: Vec<WafRule> = store
                .waf_rules
                .iter()
                .map(|r| {
                    let mut r = r.clone();
                    r.hit_count = hits.get(&r.id).copied().unwrap_or(0);
                    r
                })
                .collect();
            ok(rules)
        }
        "waf.rule.get" => {
            let p: IdParam = parse(params)?;
            store
                .waf_rules
                .iter()
                .find(|r| r.id == p.id)
                .map(ok_ref)
                .unwrap_or_else(|| Err(RpcError::not_found(format!("waf rule {}", p.id))))
        }
        "waf.rule.create" => {
            let input: WafRuleInput = parse(params)?;
            let rule = WafRule {
                id: short_id("wr"),
                name: input.name.unwrap_or_else(|| "New Rule".into()),
                description: input.description.unwrap_or_default(),
                match_type: input.match_type.unwrap_or(WafMatchType::Path),
                pattern: input.pattern.unwrap_or_default(),
                action: input.action.unwrap_or(WafAction::Deny),
                priority: input.priority.unwrap_or(50),
                enabled: input.enabled.unwrap_or(true),
                hit_count: 0,
                // Operator-authored from the start — never a shipped default a
                // migration should auto-demote.
                user_modified: true,
            };
            store.waf_rules.insert(0, rule.clone());
            audit("waf.rule.create", &rule.id);
            ok(rule)
        }
        "waf.rule.update" => {
            let input: WafRuleInput = parse(params)?;
            let id = require_id(&input.id)?;
            let r = store
                .waf_rules
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or_else(|| RpcError::not_found(format!("waf rule {id}")))?;
            if let Some(v) = input.name {
                r.name = v;
            }
            if let Some(v) = input.description {
                r.description = v;
            }
            if let Some(v) = input.match_type {
                r.match_type = v;
            }
            if let Some(v) = input.pattern {
                r.pattern = v;
            }
            if let Some(v) = input.action {
                r.action = v;
            }
            if let Some(v) = input.priority {
                r.priority = v;
            }
            if let Some(v) = input.enabled {
                r.enabled = v;
            }
            // The operator has now hand-tuned this rule: record provenance so a
            // future schema migration won't auto-demote it as a shipped default.
            r.user_modified = true;
            let out = r.clone();
            audit("waf.rule.update", &id);
            ok(out)
        }
        "waf.rule.delete" => {
            let p: IdParam = parse(params)?;
            let before = store.waf_rules.len();
            store.waf_rules.retain(|r| r.id != p.id);
            if store.waf_rules.len() == before {
                return Err(RpcError::not_found(format!("waf rule {}", p.id)));
            }
            audit("waf.rule.delete", &p.id);
            ok(json!({ "success": true, "id": p.id }))
        }
        "waf.rule.enable" => set_rule_enabled(&mut store, params, true),
        "waf.rule.disable" => set_rule_enabled(&mut store, params, false),
        "waf.event.list" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(25) as usize;
            let mut events = state.waf_events.lock().snapshot();
            events.truncate(limit);
            ok(events)
        }

        // ---- Semantic WAF engine (structure-aware detection) ----
        "waf.semantic.get" => ok(store.waf_semantic.clone()),
        "waf.semantic.update" => {
            // Whole-config replace (the UI sends back the full edited config) —
            // except `exceptions`, which are managed via `waf.exception.*`.
            // Preserving them prevents a stale UI snapshot (or a concurrent admin
            // session) from silently deleting exceptions created since it loaded.
            let mut cfg: WafSemanticConfig = parse(params)?;
            cfg.exceptions = store.waf_semantic.exceptions.clone();
            store.waf_semantic = cfg;
            audit("waf.semantic.update", "config");
            ok(store.waf_semantic.clone())
        }
        "waf.exception.list" => ok(store.waf_semantic.exceptions.clone()),
        "waf.exception.create" => {
            let input: ExceptionInput = parse(params)?;
            let path_prefix = input.path_prefix.unwrap_or_default();
            let param = input.param.filter(|s| !s.is_empty());
            // Reject an all-wildcard exception: with no module/path/param/location
            // set it matches every detection and silently disables the entire
            // engine. Require at least one scope field.
            if input.module.is_none()
                && path_prefix.is_empty()
                && param.is_none()
                && input.location.is_none()
            {
                return Err(RpcError::invalid_params(
                    "exception must scope at least one of: module, path_prefix, param, location",
                ));
            }
            let exc = WafException {
                id: short_id("wx"),
                enabled: input.enabled.unwrap_or(true),
                module: input.module,
                path_prefix,
                param,
                location: input.location,
                note: input.note.unwrap_or_default(),
            };
            store.waf_semantic.exceptions.insert(0, exc.clone());
            audit("waf.exception.create", &exc.id);
            ok(exc)
        }
        "waf.exception.delete" => {
            let p: IdParam = parse(params)?;
            let before = store.waf_semantic.exceptions.len();
            store.waf_semantic.exceptions.retain(|e| e.id != p.id);
            if store.waf_semantic.exceptions.len() == before {
                return Err(RpcError::not_found(format!("waf exception {}", p.id)));
            }
            audit("waf.exception.delete", &p.id);
            ok(json!({ "success": true, "id": p.id }))
        }

        // ---- TLS (real keypair generation + PEM parsing) ----
        "tls.cert.list" => {
            // Recompute status from the real expiry on every read — but keep a
            // `Pending` cert (ACME issuance in flight) as Pending. Its placeholder
            // expiry is "now", which would otherwise mis-render as "expiring".
            let mut list = store.certs.clone();
            for c in &mut list {
                if c.status != CertStatus::Pending {
                    if let Some(dt) = crate::tls::parse_dt(&c.expires_at) {
                        c.status = crate::tls::status_for(&dt);
                    }
                }
            }
            ok(list)
        }
        "tls.cert.get" => {
            let p: IdParam = parse(params)?;
            store
                .certs
                .iter()
                .find(|c| c.id == p.id)
                .map(ok_ref)
                .unwrap_or_else(|| Err(RpcError::not_found(format!("certificate {}", p.id))))
        }
        "tls.cert.request" => {
            // When ACME is enabled (and ToS agreed), order a real certificate
            // from the configured CA over HTTP-01. Issuance runs in the
            // background (it can take 10-60s and must not block the RPC nor hold
            // the store lock), so we insert a `Pending` entry and return at once;
            // the cert flips to `Valid` when the order completes. Otherwise we
            // generate a local self-signed certificate as before.
            let p: DomainParam = parse(params)?;
            let id = short_id("ct");
            let acme_on = store.settings.acme.enabled && store.settings.acme.agree_tos;
            if acme_on {
                let cert = TlsCertificate {
                    id: id.clone(),
                    domain: p.domain.clone(),
                    issuer: "Let's Encrypt (issuing…)".into(),
                    expires_at: Utc::now().to_rfc3339(),
                    auto_renew: true,
                    status: CertStatus::Pending,
                    acme: true,
                };
                store.certs.insert(0, cert.clone());
                audit("tls.cert.request", &id);
                spawn_acme_issue(state.clone(), id, p.domain);
                ok(cert)
            } else {
                let (cert_pem, key_pem, expires) = crate::tls::generate_self_signed(&p.domain, 90)
                    .map_err(|e| {
                        RpcError::new(-32603, format!("certificate generation failed: {e}"))
                    })?;
                crate::tls::save_files(&state.config.cert_dir, &id, &cert_pem, Some(&key_pem))
                    .map_err(|e| {
                        RpcError::new(-32603, format!("could not write cert files: {e}"))
                    })?;
                let cert = TlsCertificate {
                    id: id.clone(),
                    domain: p.domain,
                    issuer: "FluxGate self-signed (local)".into(),
                    expires_at: expires.to_rfc3339(),
                    auto_renew: true,
                    status: crate::tls::status_for(&expires),
                    acme: false,
                };
                store.certs.insert(0, cert.clone());
                audit("tls.cert.request", &id);
                ok(cert)
            }
        }
        "tls.cert.renew" => {
            // ACME certs re-issue over HTTP-01 in the background; self-signed
            // certs are re-generated locally and synchronously as before.
            let p: IdParam = parse(params)?;
            let c = store
                .certs
                .iter_mut()
                .find(|c| c.id == p.id)
                .ok_or_else(|| RpcError::not_found(format!("certificate {}", p.id)))?;
            if c.acme {
                // Re-issue in the background. Show `Pending` while it runs, but
                // leave the issuer/expiry intact so a transient failure can't
                // destroy the still-valid cert (finish_acme restores the status
                // from the stored expiry on failure).
                let (id, domain) = (c.id.clone(), c.domain.clone());
                c.status = CertStatus::Pending;
                let out = c.clone();
                spawn_acme_issue(state.clone(), id, domain);
                audit("tls.cert.renew", &p.id);
                ok(out)
            } else {
                let (cert_pem, key_pem, expires) = crate::tls::generate_self_signed(&c.domain, 90)
                    .map_err(|e| RpcError::new(-32603, format!("renewal failed: {e}")))?;
                crate::tls::save_files(&state.config.cert_dir, &p.id, &cert_pem, Some(&key_pem))
                    .map_err(|e| {
                        RpcError::new(-32603, format!("could not write cert files: {e}"))
                    })?;
                c.expires_at = expires.to_rfc3339();
                c.issuer = "FluxGate self-signed (local)".into();
                c.status = crate::tls::status_for(&expires);
                let out = c.clone();
                audit("tls.cert.renew", &p.id);
                ok(out)
            }
        }
        "tls.cert.upload" => {
            // Parse the REAL uploaded PEM: subject/issuer/expiry come from the cert.
            let p: CertUploadParam = parse(params)?;
            let cert_pem = p
                .cert_pem
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| RpcError::invalid_params("missing `cert_pem`"))?;
            let parsed = crate::tls::parse_pem(&cert_pem)
                .map_err(|e| RpcError::invalid_params(e.to_string()))?;
            let id = short_id("ct");
            crate::tls::save_files(&state.config.cert_dir, &id, &cert_pem, p.key_pem.as_deref())
                .map_err(|e| RpcError::new(-32603, format!("could not write cert files: {e}")))?;
            let cert = TlsCertificate {
                id: id.clone(),
                domain: p.domain.filter(|d| !d.is_empty()).unwrap_or(parsed.domain),
                issuer: parsed.issuer,
                expires_at: parsed.not_after.to_rfc3339(),
                auto_renew: p.auto_renew.unwrap_or(false),
                status: crate::tls::status_for(&parsed.not_after),
                acme: false,
            };
            store.certs.insert(0, cert.clone());
            audit("tls.cert.upload", &id);
            ok(cert)
        }
        "tls.cert.delete" => {
            let p: IdParam = parse(params)?;
            let before = store.certs.len();
            store.certs.retain(|c| c.id != p.id);
            if store.certs.len() == before {
                return Err(RpcError::not_found(format!("certificate {}", p.id)));
            }
            crate::tls::delete_files(&state.config.cert_dir, &p.id);
            audit("tls.cert.delete", &p.id);
            ok(json!({ "success": true, "id": p.id }))
        }

        // ---- Access logs (real requests served by this process) ----
        "access_log.list" => {
            let p: LogQuery = parse_or_default(params)?;
            drop(store);
            let logs = state.logs.lock().snapshot();
            ok(paginate(&logs, p.offset, p.limit.unwrap_or(50)))
        }
        "access_log.search" => {
            let p: LogQuery = parse_or_default(params)?;
            drop(store);
            let snap = state.logs.lock().snapshot();
            let filtered: Vec<AccessLog> =
                snap.into_iter().filter(|l| log_matches(l, &p)).collect();
            let total = filtered.len();
            let limit = p.limit.unwrap_or(50);
            let items: Vec<AccessLog> = filtered.into_iter().skip(p.offset).take(limit).collect();
            ok(json!({ "items": items, "total": total }))
        }

        // ---- Metrics (real host telemetry + derived request metrics) ----
        "metrics.system" => ok(state.telemetry.lock().metrics_system()),
        "metrics.traffic" => {
            drop(store);
            let snap = state.logs.lock().snapshot();
            ok(collector::metrics_traffic(&snap))
        }
        "metrics.route" => {
            // 24h analytics for one host+path (PV/UV/QPS/latency/error/countries).
            // Release store, snapshot under the logs lock; analysis + GeoIP run
            // outside both locks.
            let p: RouteMetricsParam = parse(params)?;
            let path = p.path.unwrap_or_else(|| "/".into());
            let host = p.host;
            drop(store);
            let snap = state.logs.lock().snapshot();
            let mut stats = collector::window_stats(
                &snap,
                Utc::now(),
                |l| l.host.eq_ignore_ascii_case(&host) && l.path.starts_with(&path),
                |ip| state.waf.country_of(ip),
                10,
            );
            // Byte traffic is host-level (the meter keys on host), so a site's
            // analytics shows the whole host's total / 30d / today.
            stats.traffic = state.traffic.host_totals(&host);
            ok(stats)
        }
        "metrics.upstream" => ok(collector::metrics_upstream(&store)),
        "metrics.waf" => {
            let events = state.waf_events.lock();
            ok(collector::metrics_waf(&events))
        }

        // ---- Settings / system ----
        "settings.get" => ok(&store.settings),
        "settings.update" => {
            let input: SettingsInput = parse(params)?;
            apply_settings(&mut store.settings, input);
            // Keep the login username in sync with the displayed admin username.
            store.auth.username = store.settings.admin_username.clone();
            audit("settings.update", "settings");
            ok(store.settings.clone())
        }
        "system.reload" => {
            audit("system.reload", "config");
            ok(json!({
                "success": true,
                "message": "Configuration reloaded",
                "reloaded_at": Utc::now().to_rfc3339(),
            }))
        }
        "system.info" => ok(state.telemetry.lock().system_info()),

        _ => Err(RpcError::new(-32601, format!("Method not found: {method}"))),
    }
}

// ---------------------------------------------------------------------------
// Small per-method helpers
// ---------------------------------------------------------------------------

/// Normalize a country-block list: trim, uppercase, keep only 2-letter ISO codes,
/// drop blanks/dupes. Input may be `None` (→ empty list).
fn normalize_countries(input: Option<Vec<String>>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in input.unwrap_or_default() {
        let code: String = c.trim().to_uppercase();
        if code.len() == 2
            && code.chars().all(|ch| ch.is_ascii_alphabetic())
            && !out.contains(&code)
        {
            out.push(code);
        }
    }
    out
}

/// Sanitize site redirect rules: trim path/target, drop entries missing either,
/// and clamp `status` to a supported redirect code (301/302/307/308; default 301).
fn normalize_redirects(input: Option<Vec<RedirectRule>>) -> Vec<RedirectRule> {
    let mut out: Vec<RedirectRule> = Vec::new();
    for r in input.unwrap_or_default() {
        let path = r.path.trim().to_string();
        let target = r.target.trim().to_string();
        if path.is_empty() || target.is_empty() {
            continue;
        }
        let status = match r.status {
            301 | 302 | 307 | 308 => r.status,
            _ => 301,
        };
        out.push(RedirectRule {
            path,
            target,
            status,
        });
    }
    out
}

/// Add a validated IP/CIDR entry to an allow/block list (dedup by value).
fn add_ip_entry(list: &mut Vec<IpListEntry>, params: Value) -> RpcResult {
    let p: IpEntryInput = parse(params)?;
    let value = p.value.trim().to_string();
    if value.is_empty() {
        return Err(RpcError::invalid_params("`value` is required"));
    }
    if matches!(
        crate::iprange::IpMatcher::parse(&value),
        crate::iprange::IpMatcher::Never
    ) {
        return Err(RpcError::invalid_params("not a valid IP or CIDR"));
    }
    if !list.iter().any(|e| e.value == value) {
        list.insert(
            0,
            IpListEntry {
                value: value.clone(),
                note: p.note.unwrap_or_default(),
            },
        );
    }
    audit("ip.list.add", &value);
    ok(json!({ "value": value }))
}

/// Remove an entry from an allow/block list by value.
fn remove_ip_entry(list: &mut Vec<IpListEntry>, params: Value) -> RpcResult {
    let p: IpValueInput = parse(params)?;
    let before = list.len();
    list.retain(|e| e.value != p.value);
    audit("ip.list.remove", &p.value);
    ok(json!({ "removed": before != list.len() }))
}

fn set_route_enabled(store: &mut crate::state::Store, params: Value, enabled: bool) -> RpcResult {
    let p: IdParam = parse(params)?;
    let r = store
        .routes
        .iter_mut()
        .find(|r| r.id == p.id)
        .ok_or_else(|| RpcError::not_found(format!("route {}", p.id)))?;
    r.enabled = enabled;
    r.updated_at = Utc::now().to_rfc3339();
    let out = r.clone();
    audit(
        if enabled {
            "route.enable"
        } else {
            "route.disable"
        },
        &p.id,
    );
    ok(out)
}

fn set_l4route_enabled(store: &mut crate::state::Store, params: Value, enabled: bool) -> RpcResult {
    let p: IdParam = parse(params)?;
    let r = store
        .l4_routes
        .iter_mut()
        .find(|r| r.id == p.id)
        .ok_or_else(|| RpcError::not_found(format!("l4 route {}", p.id)))?;
    r.enabled = enabled;
    r.updated_at = Utc::now().to_rfc3339();
    let out = r.clone();
    audit(
        if enabled {
            "l4route.enable"
        } else {
            "l4route.disable"
        },
        &p.id,
    );
    ok(out)
}

fn set_rule_enabled(store: &mut crate::state::Store, params: Value, enabled: bool) -> RpcResult {
    let p: IdParam = parse(params)?;
    let r = store
        .waf_rules
        .iter_mut()
        .find(|r| r.id == p.id)
        .ok_or_else(|| RpcError::not_found(format!("waf rule {}", p.id)))?;
    r.enabled = enabled;
    let out = r.clone();
    audit(
        if enabled {
            "waf.rule.enable"
        } else {
            "waf.rule.disable"
        },
        &p.id,
    );
    ok(out)
}

fn apply_settings(s: &mut Settings, input: SettingsInput) {
    if let Some(v) = input.admin_username {
        s.admin_username = v;
    }
    if let Some(v) = input.admin_email {
        s.admin_email = v;
    }
    if let Some(v) = input.log_level {
        s.log_level = v;
    }
    if let Some(v) = input.hot_reload {
        s.hot_reload = v;
    }
    if let Some(v) = input.default_waf_action {
        s.default_waf_action = v;
    }
    if let Some(v) = input.worker_threads {
        s.worker_threads = v;
    }
    if let Some(v) = input.max_connections {
        s.max_connections = v;
    }
    if let Some(v) = input.request_timeout_secs {
        s.request_timeout_secs = v;
    }
    if let Some(v) = input.auto_ban_enabled {
        s.auto_ban_enabled = v;
    }
    if let Some(v) = input.auto_ban_threshold {
        s.auto_ban_threshold = v.max(1);
    }
    if let Some(v) = input.auto_ban_duration_secs {
        s.auto_ban_duration_secs = v.max(0);
    }
    if let Some(a) = input.acme {
        if let Some(v) = a.enabled {
            s.acme.enabled = v;
        }
        if let Some(v) = a.directory_url {
            s.acme.directory_url = v;
        }
        if let Some(v) = a.email {
            s.acme.email = v;
        }
        if let Some(v) = a.agree_tos {
            s.acme.agree_tos = v;
        }
    }
}

fn log_matches(l: &AccessLog, q: &LogQuery) -> bool {
    if let Some(host) = &q.host {
        if !host.is_empty() && &l.host != host {
            return false;
        }
    }
    if let Some(status) = q.status {
        if l.status != status {
            return false;
        }
    }
    if let Some(action) = q.waf_action {
        if l.waf_action != action {
            return false;
        }
    }
    if let Some(query) = &q.query {
        let needle = query.to_lowercase();
        if !needle.is_empty() {
            let hay = format!(
                "{} {} {} {} {} {}",
                l.client_ip, l.method, l.host, l.path, l.upstream, l.status
            )
            .to_lowercase();
            if !hay.contains(&needle) {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

/// Audit log for sensitive/state-changing operations.
fn audit(action: &str, target: &str) {
    tracing::info!(target: "fluxgate::audit", action, target, "admin action");
}

fn short_id(prefix: &str) -> String {
    let u = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", &u[..8])
}

/// Run an ACME HTTP-01 order in the background for an existing `Pending` cert
/// entry, then update it to `Valid` (with the real expiry/issuer) on success, or
/// mark it failed on error. Also used by the auto-renewal task.
pub fn spawn_acme_issue(state: AppState, id: String, domain: String) {
    tokio::spawn(async move {
        let (dir_url, email) = {
            let store = state.store.lock();
            (
                store.settings.acme.directory_url.clone(),
                store.settings.acme.email.clone(),
            )
        };
        let dir = state.config.cert_dir.clone();
        tracing::info!("ACME: ordering certificate for {domain} (id {id})");
        match crate::acme::issue_http01(&dir, &dir_url, &email, &domain, &state.acme_challenges)
            .await
        {
            Ok((cert_pem, key_pem)) => {
                if let Err(e) = crate::tls::save_files(&dir, &id, &cert_pem, Some(&key_pem)) {
                    tracing::error!("ACME: issued {domain} but could not write files: {e}");
                    finish_acme(&state, &id, None, "ACME issued, but file write failed");
                    return;
                }
                let parsed = crate::tls::parse_pem(&cert_pem).ok();
                let expires = parsed
                    .as_ref()
                    .map(|p| p.not_after)
                    .unwrap_or_else(|| Utc::now() + chrono::Duration::days(90));
                let issuer = parsed
                    .map(|p| p.issuer)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "Let's Encrypt".into());
                finish_acme(&state, &id, Some((expires, issuer)), "");
                tracing::info!("ACME: certificate for {domain} issued (valid until {expires})");
            }
            Err(e) => {
                tracing::error!("ACME: issuance for {domain} failed: {e:#}");
                finish_acme(
                    &state,
                    &id,
                    None,
                    "ACME issuance failed — check DNS + port 80",
                );
            }
        }
    });
}

/// Apply the outcome of an ACME order to the stored cert entry and persist.
/// `Some((expires, issuer))` → success (Valid); `None` → failure (Expired + the
/// failure reason as the issuer, so it surfaces in the UI).
fn finish_acme(state: &AppState, id: &str, ok: Option<(DateTime<Utc>, String)>, fail_reason: &str) {
    let mut store = state.store.lock();
    if let Some(c) = store.certs.iter_mut().find(|c| c.id == id) {
        match ok {
            Some((expires, issuer)) => {
                c.expires_at = expires.to_rfc3339();
                c.issuer = issuer;
                c.status = crate::tls::status_for(&expires);
                c.acme = true;
            }
            // Failure: never destroy a certificate that still has a usable cert
            // on disk. If the existing entry is still within its validity window
            // (a renewal that failed transiently), keep serving it — just restore
            // its real status from the stored expiry and leave the issuer intact.
            // Only a brand-new request that never obtained a cert (no future
            // expiry) is surfaced as failed.
            None => match crate::tls::parse_dt(&c.expires_at) {
                // Existing cert is still within its validity window — a renewal
                // that failed transiently. Keep serving it; just restore the real
                // status and leave the issuer/expiry untouched.
                Some(dt) if crate::tls::status_for(&dt) != CertStatus::Expired => {
                    c.status = crate::tls::status_for(&dt);
                    tracing::warn!(
                        "ACME renewal for cert {id} failed ({fail_reason}); keeping the existing valid certificate"
                    );
                }
                // No usable cert (a fresh request that never obtained one) — surface the failure.
                _ => {
                    c.status = CertStatus::Expired;
                    c.issuer = fail_reason.to_string();
                }
            },
        }
    }
    crate::persist::save(&state.config.data_path, &store);
}

fn ok<T: Serialize>(value: T) -> RpcResult {
    serde_json::to_value(value).map_err(|e| RpcError::new(-32603, format!("Serialize error: {e}")))
}

fn ok_ref<T: Serialize>(value: &T) -> RpcResult {
    ok(value)
}

fn parse<T: DeserializeOwned>(params: Value) -> Result<T, RpcError> {
    serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))
}

/// Like `parse`, but a missing/`null` params object yields `T::default()`.
fn parse_or_default<T: DeserializeOwned + Default>(params: Value) -> Result<T, RpcError> {
    if params.is_null() {
        return Ok(T::default());
    }
    parse(params)
}

fn require_id(id: &Option<String>) -> Result<String, RpcError> {
    id.clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| RpcError::invalid_params("missing `id`"))
}

fn paginate<T: Clone + Serialize>(items: &[T], offset: usize, limit: usize) -> Value {
    let total = items.len();
    let page: Vec<T> = items.iter().skip(offset).take(limit).cloned().collect();
    json!({ "items": page, "total": total })
}

// ---------------------------------------------------------------------------
// Param structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginParams {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct ChangePasswordParams {
    current_password: String,
    new_password: String,
    username: Option<String>,
}

#[derive(Deserialize)]
struct IdParam {
    id: String,
}

#[derive(Deserialize)]
struct RouteMetricsParam {
    host: String,
    path: Option<String>,
}

#[derive(Deserialize)]
struct DomainParam {
    domain: String,
}

#[derive(Deserialize)]
struct SiteInput {
    id: Option<String>,
    name: Option<String>,
    host: Option<String>,
    tls_enabled: Option<bool>,
    cert_id: Option<String>,
    https_redirect: Option<bool>,
    waf_enabled: Option<bool>,
    max_body_mb: Option<u64>,
    upstream_timeout_secs: Option<u64>,
    block_crawler_ua: Option<bool>,
    browser_only: Option<bool>,
    rewrite_robots: Option<bool>,
    redirects: Option<Vec<RedirectRule>>,
    blocked_countries: Option<Vec<String>>,
    block_datacenter: Option<bool>,
    cloudflare_only: Option<bool>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct RouteInput {
    id: Option<String>,
    site_id: Option<String>,
    name: Option<String>,
    path: Option<String>,
    upstream: Option<String>,
    waf_enabled: Option<bool>,
    /// `"block"` / `"monitor"` / anything else (`"inherit"`) → inherit the global.
    waf_mode: Option<String>,
    /// nginx-style URL rewrite: strip the matched route prefix before forwarding.
    strip_prefix: Option<bool>,
    enabled: Option<bool>,
}

/// Map the UI's per-route WAF-mode string to a `WafMode` override (`None` =
/// inherit the global semantic-engine mode).
fn parse_route_mode(s: Option<&str>) -> Option<fluxgate_core::WafMode> {
    match s {
        Some("block") => Some(fluxgate_core::WafMode::Block),
        Some("monitor") => Some(fluxgate_core::WafMode::Monitor),
        _ => None,
    }
}

#[derive(Deserialize)]
struct UpstreamInput {
    id: Option<String>,
    name: Option<String>,
    strategy: Option<LbStrategy>,
    servers: Option<Vec<UpstreamServer>>,
    /// Connect to this upstream over TLS (`https://`). See `Upstream.tls`.
    tls: Option<bool>,
}

#[derive(Deserialize)]
struct L4RouteInput {
    id: Option<String>,
    name: Option<String>,
    server_names: Option<Vec<String>>,
    origins: Option<Vec<String>>,
    strategy: Option<LbStrategy>,
    connect_timeout_secs: Option<u64>,
    enabled: Option<bool>,
}

/// Normalise an upstream server address to bare `host:port`: drop any `http(s)://`
/// scheme (the scheme is decided by the upstream's `tls` flag) and anything from the
/// first `/` onward — a stray path would otherwise be concatenated onto the request
/// path at forward time and corrupt routing (e.g. `127.0.0.1:7880/twirp` →
/// `/twirp/twirp/…`).
fn normalize_addr(addr: &str) -> String {
    let a = addr.trim();
    let a = a
        .strip_prefix("https://")
        .or_else(|| a.strip_prefix("http://"))
        .unwrap_or(a);
    a.split('/').next().unwrap_or(a).trim().to_string()
}

#[derive(Deserialize)]
struct WafRuleInput {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    match_type: Option<WafMatchType>,
    pattern: Option<String>,
    action: Option<WafAction>,
    priority: Option<u32>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct ExceptionInput {
    enabled: Option<bool>,
    module: Option<WafModule>,
    path_prefix: Option<String>,
    param: Option<String>,
    location: Option<WafLocation>,
    note: Option<String>,
}

#[derive(Deserialize)]
struct CertUploadParam {
    domain: Option<String>,
    cert_pem: Option<String>,
    key_pem: Option<String>,
    auto_renew: Option<bool>,
}

#[derive(Deserialize, Default)]
struct LogQuery {
    query: Option<String>,
    host: Option<String>,
    status: Option<u16>,
    waf_action: Option<WafAction>,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct SettingsInput {
    admin_username: Option<String>,
    admin_email: Option<String>,
    log_level: Option<String>,
    hot_reload: Option<bool>,
    default_waf_action: Option<WafAction>,
    worker_threads: Option<u32>,
    max_connections: Option<u32>,
    request_timeout_secs: Option<u32>,
    auto_ban_enabled: Option<bool>,
    auto_ban_threshold: Option<u32>,
    auto_ban_duration_secs: Option<i64>,
    acme: Option<AcmeInput>,
}

#[derive(Deserialize)]
struct IpEntryInput {
    value: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct IpValueInput {
    value: String,
}

#[derive(Deserialize)]
struct IpBanInput {
    ip: String,
}

#[derive(Deserialize)]
struct AcmeInput {
    enabled: Option<bool>,
    directory_url: Option<String>,
    email: Option<String>,
    agree_tos: Option<bool>,
}
