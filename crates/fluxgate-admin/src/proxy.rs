//! The reverse-proxy data plane.
//!
//! Listens on a dedicated port and forwards traffic using the same Routes /
//! Upstreams / WAF rules the admin console manages (shared `AppState`), so config
//! changes take effect live and proxied traffic flows into the same dashboards,
//! logs and metrics.
//!
//! Built on hyper so it supports:
//!   * **streaming** request and response bodies (no full-buffering — SSE / large
//!     uploads/downloads flow through incrementally);
//!   * **WebSocket / HTTP Upgrade** — the handshake is forwarded and the two
//!     connections are bridged with bidirectional copy.
//!
//! WAF runs in **enforcement mode** here: `deny` → 403, and `challenge` → a
//! managed JS proof-of-work interstitial (see `challenge.rs`) that real browsers
//! pass automatically while no-JS bots stay blocked. Evaluated on the request
//! line + headers (including the WS handshake).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Response},
    Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Bytes, Frame};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};

use fluxgate_core::*;

use crate::state::AppState;
use crate::waf::WafContext;

/// Hyper client used to reach upstreams (HTTP/1, with upgrade support).
pub type ProxyClient = Client<HttpConnector, Body>;

pub fn build_client() -> ProxyClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

/// Hop-by-hop headers stripped on normal (non-upgrade) forwarding.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// How much of the request body the WAF inspects. The overwhelming majority of
/// injection payloads (form fields, JSON values, GraphQL queries) sit in the
/// first few KB; bytes beyond this window are streamed straight through without
/// buffering, so large uploads keep their zero-copy fast path. Bounds per-request
/// scan memory to this value.
const BODY_SCAN_LIMIT: usize = 64 * 1024;

/// Upper bound on how long we wait to receive the inspected body prefix. Reading
/// the prefix introduces a new place a slow client can stall us *before* the
/// upstream is contacted, so a slow-loris that dribbles the body is cut off here
/// with a 408 rather than pinning a worker.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// RAII guard for the real active-connection count: increments on creation and
/// decrements on drop, so every early return / error path is covered.
struct InflightGuard(Arc<AtomicI64>);
impl InflightGuard {
    fn new(counter: &Arc<AtomicI64>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter.clone())
    }
}
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `Server` header advertised on every response we serve.
const SERVER_HEADER: HeaderValue = HeaderValue::from_static("FluxGate/1.0");

/// Response middleware: stamp our `Server` header, replacing any value the
/// upstream sent (also avoids leaking the backend's server identity).
pub async fn set_server_header(mut res: Response) -> Response {
    res.headers_mut().insert(header::SERVER, SERVER_HEADER);
    res
}

/// Build the reverse-proxy data-plane router (shared by the plaintext and TLS
/// listeners).
pub fn router(state: AppState) -> Router {
    Router::new()
        .fallback(proxy_handler)
        .layer(axum::middleware::map_response(set_server_header))
        .with_state(state)
}

pub async fn run(state: AppState, addr: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("  • Proxy   : http://{addr}  (reverse proxy: WAF enforcing, WS + streaming)");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

async fn proxy_handler(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
) -> Response {
    let started = Instant::now();
    // Real active-connection count for the data plane (drops on every return).
    let _inflight = InflightGuard::new(&state.inflight);
    let secure = req.extensions().get::<crate::serve::TlsConn>().is_some();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let path = uri.path().to_string();
    let path_and_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let host = header_str(&headers, "host")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    // Provisional client IP for **pre-routing** use only: the load-balancer
    // IP-hash and ACME / early-return logging. The forwarded client is used if
    // present (so IP-hash stays sticky per real client behind a proxy/CF) — this
    // is *not* a security decision. The authoritative, unspoofable IP is resolved
    // after routing (`real_ip`) and drives every access / analytics decision.
    let mut client_ip = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| peer.ip().to_string());
    // User-Agent (borrowed from the cloned headers, valid for the whole handler):
    // feeds the device breakdown and is recorded on WAF events for the risk board.
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Device/OS class for the dashboard breakdown — parsed once, logged on every
    // request below (a `&'static str`, so it's cheap to pass around).
    let device = device_class(ua);
    let now_ts = Utc::now().timestamp();
    let peer_ip = peer.ip();

    // --- Fast pre-routing block (socket peer) -------------------------------
    // A block-listed / auto-banned **peer** is denied immediately, on any host
    // (even unconfigured ones), before any routing work — a cheap DoS
    // short-circuit. Behind Cloudflare the peer is an edge IP, so the real client
    // is re-checked after routing (`real_ip`). Whitelisted peers skip this.
    if !state.access.is_whitelisted(peer_ip) && state.access.is_blocked(peer_ip, now_ts) {
        log_request(
            &state,
            &client_ip,
            &method,
            &host,
            &path,
            403,
            started,
            "-",
            WafAction::Deny,
            device,
        );
        return (StatusCode::FORBIDDEN, Html(crate::pages::block_banned())).into_response();
    }

    // --- ACME HTTP-01 challenge ---------------------------------------------
    // Served BEFORE any routing/redirect so certificate issuance never disrupts
    // the origin site: only the exact `/.well-known/acme-challenge/<token>` path
    // is intercepted, and only while that token is an active challenge. Every
    // other request (and any unknown token) falls through to normal proxying.
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        if let Some(key_auth) = state.acme_challenges.lock().get(token).cloned() {
            log_request(
                &state,
                &client_ip,
                &method,
                &host,
                &path,
                200,
                started,
                "acme-http-01",
                WafAction::Allow,
                device,
            );
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                key_auth,
            )
                .into_response();
        }
    }

    // --- Routing + load balancing (single store lock, also decides redirect) -
    let target = match pick_target(&state, &host, &path, &client_ip, secure) {
        // Plaintext request for a TLS-enabled site with redirect on → 308 to https.
        RouteOutcome::Redirect => {
            let location = format!("https://{host}{path_and_query}");
            log_request(
                &state,
                &client_ip,
                &method,
                &host,
                &path,
                StatusCode::PERMANENT_REDIRECT.as_u16(),
                started,
                "-",
                WafAction::Allow,
                device,
            );
            return Response::builder()
                .status(StatusCode::PERMANENT_REDIRECT)
                .header(axum::http::header::LOCATION, location)
                .body(Body::empty())
                .map(IntoResponse::into_response)
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
        // A site redirect rule matched → answer with its 301/302 + Location.
        RouteOutcome::CustomRedirect { location, status } => {
            let code = StatusCode::from_u16(status).unwrap_or(StatusCode::FOUND);
            log_request(
                &state,
                &client_ip,
                &method,
                &host,
                &path,
                code.as_u16(),
                started,
                "-",
                WafAction::Allow,
                device,
            );
            return Response::builder()
                .status(code)
                .header(axum::http::header::LOCATION, location)
                .body(Body::empty())
                .map(IntoResponse::into_response)
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
        RouteOutcome::Found(t) => t,
        RouteOutcome::NoRoute => {
            log_request(
                &state,
                &client_ip,
                &method,
                &host,
                &path,
                404,
                started,
                "-",
                WafAction::Allow,
                device,
            );
            return (StatusCode::NOT_FOUND, Html(crate::pages::not_found())).into_response();
        }
        RouteOutcome::NoHealthyUpstream => {
            log_request(
                &state,
                &client_ip,
                &method,
                &host,
                &path,
                502,
                started,
                "-",
                WafAction::Allow,
                device,
            );
            return (
                StatusCode::BAD_GATEWAY,
                Html(crate::pages::upstream_unavailable()),
            )
                .into_response();
        }
    };
    // Bind the fields as locals so the rest of the handler reads naturally;
    // adding a site setting now only touches `Target` + `pick_target`.
    let Target {
        upstream: upstream_name,
        address,
        waf_enabled,
        default_waf,
        max_body_mb,
        upstream_timeout_secs,
        block_crawler_ua,
        browser_only,
        rewrite_robots,
        blocked_countries,
        block_datacenter,
        cloudflare_only,
        auto_ban,
    } = target;

    // Did this (Cloudflare-fronted) site's connection actually arrive from a CF
    // edge? Scanned only for `cloudflare_only` sites (short-circuit), and reused by
    // both the real-IP resolution and the Cloudflare-only gate below.
    let peer_is_cf = cloudflare_only && state.cf_ranges.contains(peer.ip());

    // Real client IP, now that we know the matched site. `CF-Connecting-IP` is
    // trusted **only** when the operator declared this site Cloudflare-fronted
    // ("Only allow Cloudflare") *and* the connection actually arrived from a
    // Cloudflare edge — otherwise a forged header (e.g. via someone else's CF
    // Worker hitting an exposed origin) could spoof it. Every other case uses the
    // unspoofable socket peer. Drives access decisions + logging / rate-limit /
    // analytics. (CF-fronted sites should enable "Only allow Cloudflare" to get
    // real visitor IPs.)
    let real_ip = if peer_is_cf {
        headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
            .unwrap_or_else(|| peer.ip())
    } else {
        peer.ip()
    };
    client_ip = real_ip.to_string();

    // --- IP access control (global allow/block + auto-ban) ------------------
    // Whitelisted IPs are fully trusted and skip everything below. The block list
    // was already checked on the peer pre-routing; re-check only when Cloudflare
    // resolved a *different* real client IP (avoids a redundant scan for direct
    // traffic, where `real_ip == peer`).
    let whitelisted = state.access.is_whitelisted(real_ip);
    if real_ip != peer_ip && !whitelisted && state.access.is_blocked(real_ip, now_ts) {
        log_request(
            &state,
            &client_ip,
            &method,
            &host,
            &path,
            403,
            started,
            "-",
            WafAction::Deny,
            device,
        );
        return (StatusCode::FORBIDDEN, Html(crate::pages::block_banned())).into_response();
    }

    // --- Site IP access controls (site Advanced options) --------------------
    // Whitelisted clients skip all of these (and the WAF). The geo / datacenter
    // gates judge the trusted `real_ip` (Cloudflare-aware, unspoofable).
    let gate_ip = if !whitelisted && (!blocked_countries.is_empty() || block_datacenter) {
        real_ip.to_string()
    } else {
        String::new()
    };

    // Cloudflare-only: the connection must originate from a Cloudflare edge. We
    // check the raw TCP **peer** (a forwarded header would be spoofable), so this
    // blocks direct-to-origin bypass attempts.
    if !whitelisted && cloudflare_only && !peer_is_cf {
        log_request(
            &state,
            &client_ip,
            &method,
            &host,
            &path,
            403,
            started,
            "-",
            WafAction::Deny,
            device,
        );
        return (
            StatusCode::FORBIDDEN,
            Html(crate::pages::block_cloudflare()),
        )
            .into_response();
    }
    // Geo block: deny configured countries (judged on the trusted gate IP).
    if !whitelisted && !blocked_countries.is_empty() {
        if let Some(cc) = state.waf.country_of(&gate_ip) {
            if blocked_countries
                .iter()
                .any(|c| c.eq_ignore_ascii_case(&cc))
            {
                log_request(
                    &state,
                    &client_ip,
                    &method,
                    &host,
                    &path,
                    403,
                    started,
                    "-",
                    WafAction::Deny,
                    device,
                );
                return (StatusCode::FORBIDDEN, Html(crate::pages::block_region())).into_response();
            }
        }
    }
    // Datacenter / cloud block ("non-residential"): deny known hosting ASNs.
    if !whitelisted && block_datacenter && state.waf.is_datacenter(&gate_ip) {
        log_request(
            &state,
            &client_ip,
            &method,
            &host,
            &path,
            403,
            started,
            "-",
            WafAction::Deny,
            device,
        );
        return (
            StatusCode::FORBIDDEN,
            Html(crate::pages::block_datacenter()),
        )
            .into_response();
    }

    // --- Crawler controls (site Advanced options) ---------------------------
    // Serve a disallow-all robots.txt instead of proxying it to the origin.
    if rewrite_robots && path == "/robots.txt" {
        log_request(
            &state,
            &client_ip,
            &method,
            &host,
            &path,
            200,
            started,
            "-",
            WafAction::Allow,
            device,
        );
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "User-agent: *\nDisallow: /\n",
        )
            .into_response();
    }
    // Browser-only: allow only web-browser (or Cloudflare) User-Agents, deny the
    // rest (curl/scripts/bots/empty UA). UA filtering is heuristic (UAs are
    // spoofable), so pair it with the WAF/challenge for real protection.
    if !whitelisted && browser_only && !is_browser_ua(ua) {
        log_request(
            &state,
            &client_ip,
            &method,
            &host,
            &path,
            403,
            started,
            "-",
            WafAction::Deny,
            device,
        );
        return (StatusCode::FORBIDDEN, Html(crate::pages::block_ua())).into_response();
    }
    // Block known crawler / bot User-Agents with 403.
    if !whitelisted && block_crawler_ua && is_crawler_ua(&headers) {
        log_request(
            &state,
            &client_ip,
            &method,
            &host,
            &path,
            403,
            started,
            "-",
            WafAction::Deny,
            device,
        );
        return (StatusCode::FORBIDDEN, Html(crate::pages::block_crawler())).into_response();
    }

    // --- WAF enforcement (only when WAF is enabled and not whitelisted) ------
    if waf_enabled && !whitelisted {
        let lc_headers: HashMap<String, String> = headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_lowercase(), s.to_string()))
            })
            .collect();
        // Default action came from pick_target's lock; rule evaluation runs
        // against the WAF engine's own lock-free compiled snapshot — no re-lock.
        let default = default_waf;
        let now_sec = Utc::now().timestamp().max(0) as u64;
        let ctx = WafContext {
            client_ip: &client_ip,
            method: method.as_str(),
            // Inspect path + query so injection in query params is caught.
            path: &path_and_query,
            headers: &lc_headers,
        };
        let decision = state.waf.evaluate(default, &ctx, now_sec);
        match decision.action {
            WafAction::Allow => {}
            WafAction::Deny => {
                record_event(&state, &client_ip, &path, &decision, decision.action, ua);
                note_deny(&state, real_ip, now_ts, auto_ban);
                log_request(
                    &state,
                    &client_ip,
                    &method,
                    &host,
                    &path,
                    403,
                    started,
                    "-",
                    decision.action,
                    device,
                );
                return (StatusCode::FORBIDDEN, Html(crate::pages::block_waf())).into_response();
            }
            WafAction::Challenge => {
                // A real managed challenge: clients that already solved the
                // proof-of-work carry a valid clearance cookie and pass; others
                // get the interstitial page (and no-JS bots stay blocked).
                let now_ts = Utc::now().timestamp();
                let cookie = headers.get("cookie").and_then(|v| v.to_str().ok());
                if !crate::challenge::has_clearance(cookie, &state.config.admin_token, now_ts) {
                    record_event(&state, &client_ip, &path, &decision, decision.action, ua);
                    log_request(
                        &state,
                        &client_ip,
                        &method,
                        &host,
                        &path,
                        503,
                        started,
                        "-",
                        decision.action,
                        device,
                    );
                    let html = crate::challenge::page(&state.config.admin_token, now_ts);
                    return (StatusCode::SERVICE_UNAVAILABLE, axum::response::Html(html))
                        .into_response();
                }
                // Cleared — fall through and proxy the request.
            }
        }
    }

    // --- Per-site upload size cap (max_body_mb; 0 = unlimited) ---------------
    // Reject oversized uploads up front via Content-Length (the common case for
    // file uploads), with a clean 413. Chunked/unknown-length bodies are bounded
    // by the streaming wrapper below instead.
    let max_body_bytes = max_body_mb.saturating_mul(1024 * 1024);
    if max_body_bytes > 0 {
        if let Some(len) = content_length(&headers) {
            if len > max_body_bytes {
                log_request(
                    &state,
                    &client_ip,
                    &method,
                    &host,
                    &path,
                    413,
                    started,
                    &upstream_name,
                    WafAction::Allow,
                    device,
                );
                return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response();
            }
        }
    }

    let is_ws = is_websocket(&headers);
    // Capture the client-side upgrade future before consuming the request.
    let client_upgrade = if is_ws {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };
    let (parts, body) = req.into_parts();

    // --- WAF body inspection (stage B) --------------------------------------
    // The request-line/header pass above can't see the body (it isn't read yet).
    // When the matched route has WAF on and the request carries an inspectable
    // body, read a bounded prefix, run `Body` rules against it, then rebuild a
    // body that replays the prefix and streams the rest — so forwarding stays
    // zero-copy beyond the scan window. WebSocket handshakes carry no body and
    // are skipped.
    // Order matters: the cheap header predicates run first so a GET / bodyless /
    // non-inspectable request short-circuits *before* `has_body_rules()`, which
    // acquires the engine's read lock. Only an inspectable-bodied request on a
    // WAF route ever takes that lock.
    let forward_body: Body = if waf_enabled
        && !is_ws
        && has_body(&headers, &method)
        && is_inspectable_body(&headers)
        && state.waf.has_body_rules()
    {
        match tokio::time::timeout(BODY_READ_TIMEOUT, read_body_prefix(body, BODY_SCAN_LIMIT)).await
        {
            Ok(Ok((buffered, inspect, rest, complete))) => {
                if let Some(decision) = state.waf.evaluate_body(&inspect) {
                    match decision.action {
                        WafAction::Allow => {}
                        WafAction::Deny => {
                            record_event(&state, &client_ip, &path, &decision, decision.action, ua);
                            note_deny(&state, real_ip, now_ts, auto_ban);
                            log_request(
                                &state,
                                &client_ip,
                                &method,
                                &host,
                                &path,
                                403,
                                started,
                                "-",
                                decision.action,
                                device,
                            );
                            return (StatusCode::FORBIDDEN, Html(crate::pages::block_waf()))
                                .into_response();
                        }
                        WafAction::Challenge => {
                            let now_ts = Utc::now().timestamp();
                            let cookie = headers.get("cookie").and_then(|v| v.to_str().ok());
                            if !crate::challenge::has_clearance(
                                cookie,
                                &state.config.admin_token,
                                now_ts,
                            ) {
                                record_event(
                                    &state,
                                    &client_ip,
                                    &path,
                                    &decision,
                                    decision.action,
                                    ua,
                                );
                                log_request(
                                    &state,
                                    &client_ip,
                                    &method,
                                    &host,
                                    &path,
                                    503,
                                    started,
                                    "-",
                                    decision.action,
                                    device,
                                );
                                let html =
                                    crate::challenge::page(&state.config.admin_token, now_ts);
                                return (
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    axum::response::Html(html),
                                )
                                    .into_response();
                            }
                        }
                    }
                }
                // Cleared / allowed — forward the prefix followed by the rest.
                Body::new(PrefixBody::new(buffered, rest, complete))
            }
            // Body read failed (malformed/aborted stream) → 400.
            Ok(Err(_)) => {
                log_request(
                    &state,
                    &client_ip,
                    &method,
                    &host,
                    &path,
                    400,
                    started,
                    "-",
                    WafAction::Allow,
                    device,
                );
                return (StatusCode::BAD_REQUEST, "Malformed request body").into_response();
            }
            // Slow client never delivered the prefix in time → 408.
            Err(_) => {
                log_request(
                    &state,
                    &client_ip,
                    &method,
                    &host,
                    &path,
                    408,
                    started,
                    "-",
                    WafAction::Allow,
                    device,
                );
                return (StatusCode::REQUEST_TIMEOUT, "Request body read timed out")
                    .into_response();
            }
        }
    } else {
        body
    };

    // --- Build the upstream request -----------------------------------------
    let url = format!("http://{address}{path_and_query}");
    let mut builder = hyper::Request::builder().method(parts.method).uri(&url);
    for (name, value) in &parts.headers {
        if forward_request_header(name, is_ws) {
            builder = builder.header(name, value);
        }
    }
    if let Ok(v) = client_ip.parse::<axum::http::HeaderValue>() {
        builder = builder.header(HeaderName::from_static("x-forwarded-for"), v);
    }
    // WS handshake carries no body; everything else streams through. When a size
    // cap is set, wrap the stream so an oversized chunked upload is aborted
    // (rather than buffered) instead of slipping past the Content-Length check.
    let upstream_body = if is_ws {
        Body::empty()
    } else if max_body_bytes > 0 {
        // Limit still applies to the *whole* body: the prefix we replay came from
        // the original stream, so prefix + rest is counted against the cap.
        Body::new(http_body_util::Limited::new(
            forward_body,
            max_body_bytes as usize,
        ))
    } else {
        forward_body
    };
    let upstream_req = match builder.body(upstream_body) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Bad upstream request").into_response(),
    };

    // --- Send ----------------------------------------------------------------
    // Per-site upstream timeout (0 → fall back to the default).
    let timeout = Duration::from_secs(if upstream_timeout_secs == 0 {
        UPSTREAM_TIMEOUT.as_secs()
    } else {
        upstream_timeout_secs
    });
    let send = state.proxy_client.request(upstream_req);
    let mut resp = match tokio::time::timeout(timeout, send).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            // A streamed upload that blew past the per-site cap surfaces as a body
            // error here — report it as 413 (client error), not a 502.
            let (status, msg) = if is_length_limit(&e) {
                (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large")
            } else {
                tracing::warn!(upstream = %upstream_name, %url, "upstream request failed: {e}");
                (StatusCode::BAD_GATEWAY, "Upstream request failed")
            };
            log_request(
                &state,
                &client_ip,
                &method,
                &host,
                &path,
                status.as_u16(),
                started,
                &upstream_name,
                WafAction::Allow,
                device,
            );
            return (status, msg).into_response();
        }
        Err(_) => {
            log_request(
                &state,
                &client_ip,
                &method,
                &host,
                &path,
                504,
                started,
                &upstream_name,
                WafAction::Allow,
                device,
            );
            return (StatusCode::GATEWAY_TIMEOUT, "Upstream timed out").into_response();
        }
    };

    // --- WebSocket: bridge the two upgraded connections ----------------------
    if is_ws && resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_upgrade = hyper::upgrade::on(&mut resp);

        // Echo the 101 + handshake headers back to the client verbatim.
        let mut rb = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
        for (name, value) in resp.headers() {
            rb = rb.header(name, value);
        }
        let client_resp = rb
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());

        if let Some(client_upgrade) = client_upgrade {
            tokio::spawn(async move {
                match tokio::join!(client_upgrade, upstream_upgrade) {
                    (Ok(client_io), Ok(upstream_io)) => {
                        let mut c = TokioIo::new(client_io);
                        let mut u = TokioIo::new(upstream_io);
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut u).await;
                    }
                    _ => tracing::warn!("websocket upgrade bridge failed"),
                }
            });
        }
        log_request(
            &state,
            &client_ip,
            &method,
            &host,
            &path,
            101,
            started,
            &upstream_name,
            WafAction::Allow,
            device,
        );
        return client_resp;
    }

    // --- Normal: stream the response body straight back ----------------------
    let status = resp.status();
    log_request(
        &state,
        &client_ip,
        &method,
        &host,
        &path,
        status.as_u16(),
        started,
        &upstream_name,
        WafAction::Allow,
        device,
    );
    let mut rb = Response::builder().status(status);
    for (name, value) in resp.headers() {
        if !HOP_BY_HOP.contains(&name.as_str()) {
            rb = rb.header(name, value);
        }
    }
    // Meter site traffic: request body bytes (Content-Length) plus the response
    // bytes actually streamed back. Counted as the body flows, recorded once when
    // it ends or is dropped — so a client that disconnects mid-download still
    // contributes the bytes it received.
    let req_bytes = content_length(&headers).unwrap_or(0);
    let metered = MeteredBody::new(
        Body::new(resp.into_body()),
        state.traffic.clone(),
        host.clone(),
        req_bytes,
    );
    rb.body(Body::new(metered))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

fn is_websocket(headers: &HeaderMap) -> bool {
    let has_upgrade = headers
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    let is_ws = headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    has_upgrade && is_ws
}

/// Whether to forward a request header to the upstream.
fn forward_request_header(name: &HeaderName, is_ws: bool) -> bool {
    let n = name.as_str();
    if n == "content-length" {
        return false; // hyper recomputes from the streamed body
    }
    // For upgrades, the Connection/Upgrade/Sec-WebSocket-* headers must pass through.
    if is_ws {
        return true;
    }
    !HOP_BY_HOP.contains(&n)
}

enum RouteOutcome {
    /// Plaintext request to a TLS-enabled site with HTTP→HTTPS redirect on.
    Redirect,
    /// A site redirect rule matched: answer with `status` (301/302) → `location`.
    CustomRedirect { location: String, status: u16 },
    Found(Target),
    NoRoute,
    NoHealthyUpstream,
}

/// Whether a redirect rule's configured `path` matches the request `path`.
/// A trailing `*` makes it a prefix match (`/old*` ⊇ `/old`, `/old/x`);
/// otherwise the match is exact.
fn redirect_matches(rule_path: &str, path: &str) -> bool {
    match rule_path.strip_suffix('*') {
        Some(prefix) => path.starts_with(prefix),
        None => path == rule_path,
    }
}

/// Everything `pick_target` resolves for a forwardable request — the upstream
/// node plus the site/route settings the handler needs. Read under one store
/// lock so the hot path doesn't re-lock. Add new site settings here (and in
/// `pick_target`) — the handler binds them by name.
struct Target {
    upstream: String,
    address: String,
    waf_enabled: bool,
    default_waf: WafAction,
    /// Site upload cap in MB (`0` = unlimited) and upstream timeout in secs.
    max_body_mb: u64,
    upstream_timeout_secs: u64,
    /// Site crawler controls (Advanced options).
    block_crawler_ua: bool,
    browser_only: bool,
    rewrite_robots: bool,
    /// Site IP access controls (Advanced options).
    blocked_countries: Vec<String>,
    block_datacenter: bool,
    cloudflare_only: bool,
    /// Global auto-ban config (from settings) — applied on WAF denies.
    auto_ban: crate::access::AutoBanCfg,
}

/// Resolve `host` → enabled site → longest-prefix enabled path route, then a
/// load-balanced node — all under a single store lock. Also decides the
/// HTTP→HTTPS redirect (site-level) so the hot path locks the store only once.
fn pick_target(
    state: &AppState,
    host: &str,
    path: &str,
    client_ip: &str,
    secure: bool,
) -> RouteOutcome {
    let store = state.store.lock();
    let Some(site) = store.sites.iter().find(|s| s.enabled && s.host == host) else {
        return RouteOutcome::NoRoute;
    };
    // Plaintext request to a TLS-enabled, redirect-on site → tell caller to 308.
    if !secure && site.tls_enabled && site.https_redirect {
        return RouteOutcome::Redirect;
    }
    // Site redirect rules (301/302) — checked before route lookup so a rule can
    // target a path with no upstream. First match wins, in configured order.
    if let Some(rule) = site
        .redirects
        .iter()
        .find(|r| redirect_matches(&r.path, path))
    {
        return RouteOutcome::CustomRedirect {
            location: rule.target.clone(),
            status: rule.status,
        };
    }
    let route = store
        .routes
        .iter()
        .filter(|r| r.enabled && r.site_id == site.id && path.starts_with(&r.path))
        .max_by_key(|r| r.path.len());
    let Some(route) = route else {
        return RouteOutcome::NoRoute;
    };
    let Some(upstream) = store.upstreams.iter().find(|u| u.name == route.upstream) else {
        return RouteOutcome::NoRoute;
    };
    let waf_enabled = route.waf_enabled;
    let default_waf = store.settings.default_waf_action;
    let max_body_mb = site.max_body_mb;
    let upstream_timeout_secs = site.upstream_timeout_secs;
    let block_crawler_ua = site.block_crawler_ua;
    let browser_only = site.browser_only;
    let rewrite_robots = site.rewrite_robots;
    let blocked_countries = site.blocked_countries.clone();
    let block_datacenter = site.block_datacenter;
    let cloudflare_only = site.cloudflare_only;
    let auto_ban = crate::access::AutoBanCfg {
        enabled: store.settings.auto_ban_enabled,
        threshold: store.settings.auto_ban_threshold,
        duration_secs: store.settings.auto_ban_duration_secs,
    };
    let mut cursor = state.lb_cursor.lock();
    match select_node(upstream, client_ip, &mut cursor) {
        Some(address) => RouteOutcome::Found(Target {
            upstream: upstream.name.clone(),
            address,
            waf_enabled,
            default_waf,
            max_body_mb,
            upstream_timeout_secs,
            block_crawler_ua,
            browser_only,
            rewrite_robots,
            blocked_countries,
            block_datacenter,
            cloudflare_only,
            auto_ban,
        }),
        None => RouteOutcome::NoHealthyUpstream,
    }
}

/// Pick a healthy node per the upstream's load-balancing strategy.
fn select_node(
    up: &Upstream,
    client_ip: &str,
    cursor: &mut HashMap<String, usize>,
) -> Option<String> {
    let healthy: Vec<&UpstreamServer> = up.servers.iter().filter(|s| s.healthy).collect();
    if healthy.is_empty() {
        return None;
    }
    let idx = match up.strategy {
        // least_conn is approximated by round-robin (no per-node in-flight tracking yet).
        LbStrategy::RoundRobin | LbStrategy::LeastConn => {
            let c = cursor.entry(up.id.clone()).or_insert(0);
            let i = *c % healthy.len();
            *c = c.wrapping_add(1);
            i
        }
        LbStrategy::IpHash => (fnv1a(client_ip) as usize) % healthy.len(),
        LbStrategy::Weighted => {
            let total: u32 = healthy.iter().map(|s| s.weight.max(1)).sum();
            let c = cursor.entry(up.id.clone()).or_insert(0);
            let pos = (*c as u32) % total.max(1);
            *c = c.wrapping_add(1);
            let mut acc = 0u32;
            let mut chosen = 0;
            for (i, s) in healthy.iter().enumerate() {
                acc += s.weight.max(1);
                if pos < acc {
                    chosen = i;
                    break;
                }
            }
            chosen
        }
    };
    Some(healthy[idx].address.clone())
}

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Lowercased substrings identifying crawler / scraper User-Agents. Covers
/// search-engine bots, SEO/scraper services, AI crawlers and headless tooling.
/// Generic HTTP clients (curl/wget/etc.) are intentionally excluded to avoid
/// blocking legitimate automation and health checks.
const CRAWLER_UA_MARKERS: &[&str] = &[
    "bot",
    "spider",
    "crawler",
    "crawl",
    "slurp",
    "mediapartners",
    "facebookexternalhit",
    "ahrefs",
    "semrush",
    "mj12",
    "dotbot",
    "petalbot",
    "bytespider",
    "yandex",
    "baiduspider",
    "sogou",
    "gptbot",
    "ccbot",
    "claudebot",
    "anthropic",
    "google-extended",
    "perplexitybot",
    "amazonbot",
    "scrapy",
    "headlesschrome",
    "phantomjs",
];

/// Whether a User-Agent looks like a real **web browser** — or Cloudflare's own
/// probes (so health checks / always-online aren't blocked when behind CF). Used
/// by the per-site browser-only allow-list. Heuristic by nature (UAs are
/// spoofable): it lets genuine browsers + CF through and drops the obvious
/// non-browser clients (curl, scripts, bots, empty UA).
fn is_browser_ua(ua: &str) -> bool {
    let u = ua.to_ascii_lowercase();
    if u.is_empty() {
        return false;
    }
    // Cloudflare's own probe / always-online User-Agents.
    if u.contains("cloudflare") {
        return true;
    }
    // Real browsers all carry a Mozilla token plus an engine/brand marker.
    if !u.starts_with("mozilla/") {
        return false;
    }
    [
        "applewebkit",
        "gecko",
        "chrome",
        "firefox",
        "safari",
        "edg",
        "opr/",
        "trident",
    ]
    .iter()
    .any(|m| u.contains(m))
}

/// Whether the request's `User-Agent` looks like a crawler/bot.
fn is_crawler_ua(headers: &HeaderMap) -> bool {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    !ua.is_empty() && CRAWLER_UA_MARKERS.iter().any(|m| ua.contains(m))
}

/// Parse the `Content-Length` request header, if present and valid.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
}

/// Whether an error chain contains a `Limited` body length-limit error — i.e. a
/// streamed upload exceeded the per-site cap (vs. a genuine upstream failure).
fn is_length_limit(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = source {
        if e.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        source = e.source();
    }
    false
}

/// Whether the request may carry a body worth inspecting. A non-empty
/// `Content-Length` or a `Transfer-Encoding` header is a clear signal, but those
/// aren't sufficient: hyper can strip `Transfer-Encoding` from the surfaced
/// headers once it starts decoding a chunked stream, so a chunked `POST` with no
/// `Content-Length` would otherwise look body-less and **bypass body inspection**.
/// We therefore also treat the body-bearing methods as carrying a body; a request
/// that turns out to be empty just reads zero frames (near-free).
fn has_body(headers: &HeaderMap, method: &Method) -> bool {
    if matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return true;
    }
    if let Some(len) = content_length(headers) {
        if len > 0 {
            return true;
        }
    }
    headers.contains_key(header::TRANSFER_ENCODING)
}

/// Whether the body's media type is worth scanning. Text-ish payloads (forms,
/// JSON, XML, GraphQL, plain text) carry injection; binary uploads (octet-stream,
/// images, video, multipart file parts) are skipped to save CPU and avoid false
/// positives on binary data. A missing Content-Type is treated as inspectable.
fn is_inspectable_body(headers: &HeaderMap) -> bool {
    match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        None => true,
        Some(ct) => {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("application/x-www-form-urlencoded")
                || ct.starts_with("application/json")
                || ct.starts_with("application/graphql")
                || ct.starts_with("application/javascript")
                || ct.starts_with("text/")
                || ct.contains("xml")
        }
    }
}

/// A body that first replays a buffered prefix (the frames the WAF already read
/// and inspected), then streams the remaining original body. Lets the proxy peek
/// at the head of a body for inspection without buffering — or copying — the rest.
struct PrefixBody {
    /// Frames already read for inspection, replayed first (in order).
    buffered: VecDeque<Frame<Bytes>>,
    /// The untouched remainder of the original body.
    rest: Body,
    /// True when the whole body was read into `buffered` (so `rest` is empty).
    /// Only then can we report an exact length.
    complete: bool,
}

impl PrefixBody {
    fn new(buffered: VecDeque<Frame<Bytes>>, rest: Body, complete: bool) -> Self {
        Self {
            buffered,
            rest,
            complete,
        }
    }
}

impl HttpBody for PrefixBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(frame) = this.buffered.pop_front() {
            return Poll::Ready(Some(Ok(frame)));
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.buffered.is_empty() && self.rest.is_end_stream()
    }

    /// Report an exact length **only** when the whole body was buffered (so the
    /// forwarded request keeps its `Content-Length`). For a partially-buffered
    /// body we return an unknown hint and let hyper use chunked transfer-encoding,
    /// rather than trusting the remainder's size hint to have been decremented as
    /// we drained frames — a wrong `Content-Length` would corrupt forwarding.
    fn size_hint(&self) -> hyper::body::SizeHint {
        if self.complete {
            let buffered: u64 = self
                .buffered
                .iter()
                .filter_map(|f| f.data_ref().map(|d| d.len() as u64))
                .sum();
            hyper::body::SizeHint::with_exact(buffered)
        } else {
            hyper::body::SizeHint::new()
        }
    }
}

/// Read up to `cap` bytes of the body for inspection, preserving the frames so
/// they can be replayed downstream. Returns the buffered frames, the decoded
/// inspection string (≤ `cap` bytes), and the still-streamable remainder.
///
/// Stops as soon as `cap` inspection bytes are accumulated (a final frame may
/// carry the body past `cap` — it is preserved whole for replay, but only the
/// first `cap` bytes feed inspection). The whole operation runs under a timeout
/// at the call site, so a stalled client can't pin this indefinitely.
async fn read_body_prefix(
    mut body: Body,
    cap: usize,
) -> Result<(VecDeque<Frame<Bytes>>, String, Body, bool), axum::Error> {
    let mut buffered: VecDeque<Frame<Bytes>> = VecDeque::new();
    let mut inspect: Vec<u8> = Vec::new();
    let mut complete = false;
    while inspect.len() < cap {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    let take = (cap - inspect.len()).min(data.len());
                    inspect.extend_from_slice(&data[..take]);
                }
                buffered.push_back(frame);
            }
            Some(Err(e)) => return Err(e),
            None => {
                complete = true; // body fully consumed within the window
                break;
            }
        }
    }
    let inspect = String::from_utf8_lossy(&inspect).into_owned();
    Ok((buffered, inspect, body, complete))
}

/// Wraps the proxied response body to tally site traffic (request + response
/// bytes) into the per-host meter. The byte count is recorded exactly once — when
/// the stream ends or the body is dropped (e.g. the client disconnects
/// mid-download), whichever happens first.
struct MeteredBody {
    inner: Body,
    meter: Arc<crate::traffic::TrafficMeter>,
    host: String,
    bytes: u64,
    recorded: bool,
}

impl MeteredBody {
    fn new(
        inner: Body,
        meter: Arc<crate::traffic::TrafficMeter>,
        host: String,
        initial: u64,
    ) -> Self {
        Self {
            inner,
            meter,
            host,
            bytes: initial,
            recorded: false,
        }
    }

    fn record(&mut self) {
        if !self.recorded {
            self.recorded = true;
            self.meter.add(&self.host, self.bytes);
        }
    }
}

impl HttpBody for MeteredBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    this.bytes = this.bytes.saturating_add(d.len() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                this.record();
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

impl Drop for MeteredBody {
    fn drop(&mut self) {
        self.record();
    }
}

/// Classify a User-Agent into a coarse device / OS bucket for the dashboard's
/// device breakdown. Order matters: bots first, then mobile OSes (whose UAs also
/// name a desktop OS — Android contains "Linux", iOS contains "Mac OS").
fn device_class(ua: &str) -> &'static str {
    let u = ua.to_ascii_lowercase();
    if u.is_empty() {
        return "unknown";
    }
    if u.contains("bot")
        || u.contains("spider")
        || u.contains("crawl")
        || u.contains("slurp")
        || u.contains("curl")
        || u.contains("wget")
        || u.contains("python")
        || u.contains("go-http")
        || u.contains("java/")
        || u.contains("okhttp")
    {
        return "bot";
    }
    if u.contains("android") {
        return "android";
    }
    if u.contains("iphone") || u.contains("ipad") || u.contains("ipod") {
        return "ios";
    }
    if u.contains("windows") {
        return "windows";
    }
    if u.contains("mac os") || u.contains("macintosh") {
        return "mac";
    }
    if u.contains("linux") || u.contains("x11") {
        return "linux";
    }
    "other"
}

#[allow(clippy::too_many_arguments)]
fn log_request(
    state: &AppState,
    client_ip: &str,
    method: &Method,
    host: &str,
    path: &str,
    status: u16,
    started: Instant,
    upstream: &str,
    waf_action: WafAction,
    device: &str,
) {
    let entry = AccessLog {
        id: format!("px-{}", Utc::now().timestamp_millis()),
        time: Utc::now().to_rfc3339(),
        client_ip: client_ip.to_string(),
        method: method.to_string(),
        host: host.to_string(),
        path: path.to_string(),
        status,
        latency_ms: started.elapsed().as_millis() as u32,
        upstream: upstream.to_string(),
        waf_action,
        device: device.to_string(),
    };
    state.logs.lock().record(entry);
}

/// Feed a WAF **deny** into the auto-ban counter (using the unspoofable real IP).
/// When it trips a ban, log it. No-op when auto-ban is disabled.
fn note_deny(
    state: &AppState,
    real_ip: std::net::IpAddr,
    now: i64,
    cfg: crate::access::AutoBanCfg,
) {
    // Off by default — skip before allocating the IP string on the deny path.
    if !cfg.enabled {
        return;
    }
    if let Some(expires) = state.access.record_deny(&real_ip.to_string(), now, cfg) {
        if expires == 0 {
            tracing::warn!(target: "fluxgate::audit", ip = %real_ip, "auto-banned permanently");
        } else {
            tracing::warn!(target: "fluxgate::audit", ip = %real_ip, until = expires, "auto-banned");
        }
    }
}

fn record_event(
    state: &AppState,
    client_ip: &str,
    path: &str,
    decision: &crate::waf::WafDecision,
    action: WafAction,
    user_agent: &str,
) {
    let event = SecurityEvent {
        id: format!("ev-{}", Utc::now().timestamp_millis()),
        time: Utc::now().to_rfc3339(),
        client_ip: client_ip.to_string(),
        rule: decision
            .matched_rule_name
            .clone()
            .unwrap_or_else(|| "default policy".into()),
        action,
        path: path.to_string(),
        // Bound the stored UA so a pathological header can't bloat the JSONL.
        user_agent: user_agent.chars().take(200).collect(),
    };
    state.waf_events.lock().record(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(strategy: LbStrategy, servers: &[(&str, u32, bool)]) -> Upstream {
        let mut u = Upstream {
            id: "up".into(),
            name: "u".into(),
            strategy,
            servers: servers
                .iter()
                .map(|(a, w, h)| UpstreamServer {
                    address: a.to_string(),
                    weight: *w,
                    healthy: *h,
                    latency_ms: 0,
                })
                .collect(),
            healthy_servers: 0,
            status: UpstreamStatus::Down,
        };
        u.recompute_health();
        u
    }

    #[test]
    fn round_robin_cycles_healthy_nodes() {
        let up = upstream(
            LbStrategy::RoundRobin,
            &[("a:1", 1, true), ("b:1", 1, false), ("c:1", 1, true)],
        );
        let mut cur = HashMap::new();
        let picks: Vec<String> = (0..4)
            .map(|_| select_node(&up, "1.1.1.1", &mut cur).unwrap())
            .collect();
        assert_eq!(picks, vec!["a:1", "c:1", "a:1", "c:1"]);
    }

    #[test]
    fn no_healthy_nodes_returns_none() {
        let up = upstream(LbStrategy::RoundRobin, &[("a:1", 1, false)]);
        let mut cur = HashMap::new();
        assert!(select_node(&up, "1.1.1.1", &mut cur).is_none());
    }

    #[test]
    fn ip_hash_is_deterministic() {
        let up = upstream(LbStrategy::IpHash, &[("a:1", 1, true), ("c:1", 1, true)]);
        let mut cur = HashMap::new();
        let a = select_node(&up, "203.0.113.7", &mut cur).unwrap();
        let b = select_node(&up, "203.0.113.7", &mut cur).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn weighted_favours_higher_weight() {
        let up = upstream(LbStrategy::Weighted, &[("a:1", 3, true), ("b:1", 1, true)]);
        let mut cur = HashMap::new();
        let picks: Vec<String> = (0..4)
            .map(|_| select_node(&up, "x", &mut cur).unwrap())
            .collect();
        assert_eq!(picks.iter().filter(|p| *p == "a:1").count(), 3);
    }

    #[test]
    fn redirect_rule_matching() {
        // Exact match only when there's no trailing star.
        assert!(redirect_matches("/old", "/old"));
        assert!(!redirect_matches("/old", "/old/"));
        assert!(!redirect_matches("/old", "/older"));
        // Trailing `*` is a prefix match.
        assert!(redirect_matches("/old*", "/old"));
        assert!(redirect_matches("/old*", "/old/page"));
        assert!(redirect_matches("/old*", "/older")); // prefix, not path-segment
        assert!(!redirect_matches("/old*", "/new"));
        // Bare `*` (or `/...*`) redirects everything under the prefix.
        assert!(redirect_matches("*", "/anything"));
        assert!(redirect_matches("/*", "/anything"));
        assert!(!redirect_matches("/*", "anything"));
    }

    #[test]
    fn body_gating_by_length_and_content_type() {
        let h = HeaderMap::new();
        // GET with no length/TE → no body.
        assert!(!has_body(&h, &Method::GET));
        // Body-bearing methods are always inspected (covers chunked w/o length,
        // where hyper may have stripped Transfer-Encoding) — the bypass fix.
        assert!(has_body(&h, &Method::POST));
        assert!(has_body(&h, &Method::PUT));
        assert!(has_body(&h, &Method::PATCH));
        // GET that nonetheless declares a body is still inspected.
        let mut g = HeaderMap::new();
        g.insert(header::CONTENT_LENGTH, "0".parse().unwrap());
        assert!(!has_body(&g, &Method::GET));
        g.insert(header::CONTENT_LENGTH, "12".parse().unwrap());
        assert!(has_body(&g, &Method::GET));

        let mut c = HeaderMap::new();
        assert!(is_inspectable_body(&c)); // missing CT → inspect
        for ct in [
            "application/x-www-form-urlencoded",
            "application/json",
            "text/plain",
            "application/graphql",
            "application/soap+xml",
        ] {
            c.insert(header::CONTENT_TYPE, ct.parse().unwrap());
            assert!(is_inspectable_body(&c), "{ct} should be inspectable");
        }
        for ct in [
            "image/png",
            "application/octet-stream",
            "multipart/form-data; boundary=x",
            "video/mp4",
        ] {
            c.insert(header::CONTENT_TYPE, ct.parse().unwrap());
            assert!(!is_inspectable_body(&c), "{ct} should be skipped");
        }
    }

    #[tokio::test]
    async fn prefix_body_replays_buffer_then_rest_in_order() {
        let mut buffered = VecDeque::new();
        buffered.push_back(Frame::data(Bytes::from_static(b"AB")));
        buffered.push_back(Frame::data(Bytes::from_static(b"CD")));
        let pb = PrefixBody::new(buffered, Body::from("REST"), false);
        let out = Body::new(pb).collect().await.unwrap().to_bytes();
        assert_eq!(&out[..], b"ABCDREST");
    }

    #[tokio::test]
    async fn read_prefix_small_body_is_fully_buffered_and_replayed() {
        let body = Body::from("q=1 union select 1");
        let (buffered, inspect, rest, complete) =
            read_body_prefix(body, BODY_SCAN_LIMIT).await.unwrap();
        assert_eq!(inspect, "q=1 union select 1");
        assert!(complete, "a sub-window body is fully consumed");
        let pb = PrefixBody::new(buffered, rest, complete);
        // Fully buffered → exact length reported (keeps Content-Length).
        assert_eq!(pb.size_hint().exact(), Some(18));
        let out = Body::new(pb).collect().await.unwrap().to_bytes();
        assert_eq!(&out[..], b"q=1 union select 1"); // forwarded byte-for-byte
    }

    #[tokio::test]
    async fn read_prefix_caps_inspection_but_forwards_whole_body() {
        // A body larger than the scan window: inspection is bounded, yet the full
        // body must still flow upstream untruncated (large uploads stay intact).
        let big = vec![b'a'; BODY_SCAN_LIMIT * 2 + 7];
        let (buffered, inspect, rest, complete) =
            read_body_prefix(Body::from(big.clone()), BODY_SCAN_LIMIT)
                .await
                .unwrap();
        assert_eq!(
            inspect.len(),
            BODY_SCAN_LIMIT,
            "inspection bounded to scan window"
        );
        // The loop stops on the scan cap before seeing end-of-stream, so this is
        // the partial path (complete == false → forwarded chunked). The invariant
        // under test is that replay loses no bytes regardless.
        assert!(!complete);
        let out = Body::new(PrefixBody::new(buffered, rest, complete))
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(
            out.len(),
            big.len(),
            "entire body forwarded, not just the prefix"
        );
        assert_eq!(&out[..], &big[..]);
    }

    /// Microbenchmark for the full data-plane body path: read the prefix, run the
    /// body rules, and replay+stream the body. Reported as the **overhead vs a
    /// plain drain** of the same body, so body construction/copy cancels out and
    /// what's left is the WAF cost a real inspected request pays.
    ///   cargo test --release -p fluxgate-admin -- --ignored --nocapture bench_body_pipeline
    #[tokio::test]
    #[ignore]
    async fn bench_body_pipeline() {
        use std::hint::black_box;
        use std::time::Instant;
        let engine = crate::waf::WafEngine::new(None, None);
        engine.rebuild(&crate::persist::default_waf_rules());

        for (label, payload) in [
            ("small  200 B ", vec![b'x'; 200]),
            ("large  256 KB", vec![b'x'; 256 * 1024]),
        ] {
            let iters: u32 = if payload.len() > 4096 {
                30_000
            } else {
                300_000
            };

            // Baseline: just construct + drain the body (no inspection).
            let t0 = Instant::now();
            for _ in 0..iters {
                let out = Body::from(payload.clone())
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes();
                black_box(out);
            }
            let base = t0.elapsed().as_nanos() as f64 / iters as f64;

            // Inspected: prefix read + body-rule eval + prefix-replay drain.
            let t1 = Instant::now();
            for _ in 0..iters {
                let (buffered, inspect, rest, complete) =
                    read_body_prefix(Body::from(payload.clone()), BODY_SCAN_LIMIT)
                        .await
                        .unwrap();
                black_box(engine.evaluate_body(&inspect));
                let out = Body::new(PrefixBody::new(buffered, rest, complete))
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes();
                black_box(out);
            }
            let insp = t1.elapsed().as_nanos() as f64 / iters as f64;

            println!(
                "  {label}: baseline {base:>7.0} ns | inspected {insp:>7.0} ns | WAF overhead {:>6.0} ns",
                insp - base
            );
        }
        println!();
    }

    #[test]
    fn browser_ua_allows_browsers_and_cloudflare_only() {
        // Real browsers + Cloudflare probes pass.
        for ua in [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1 Version/17 Safari/605.1",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605 Mobile Safari/604",
            "Cloudflare-Traffic-Manager/1.0",
            "Mozilla/5.0 (compatible; Cloudflare-AlwaysOnline/1.0)",
        ] {
            assert!(is_browser_ua(ua), "should allow: {ua}");
        }
        // Tools / scripts / bots / empty are denied.
        for ua in [
            "curl/8.7.1",
            "python-requests/2.31",
            "Go-http-client/1.1",
            "sqlmap/1.5",
            "",
            "PostmanRuntime/7.0",
        ] {
            assert!(!is_browser_ua(ua), "should deny: {ua:?}");
        }
    }

    #[test]
    fn websocket_detection() {
        let mut h = HeaderMap::new();
        h.insert("connection", "Upgrade".parse().unwrap());
        h.insert("upgrade", "websocket".parse().unwrap());
        assert!(is_websocket(&h));
        let mut h2 = HeaderMap::new();
        h2.insert("connection", "keep-alive".parse().unwrap());
        assert!(!is_websocket(&h2));
    }
}
