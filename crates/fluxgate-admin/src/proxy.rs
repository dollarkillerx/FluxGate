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
//! WAF runs in **enforcement mode** here (`deny` → 403, `challenge` → 429),
//! evaluated on the request line + headers (including the WS handshake). The
//! admin plane stays detection-only so console rules can't lock you out.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderName, Method, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use chrono::Utc;
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

/// Build the reverse-proxy data-plane router (shared by the plaintext and TLS
/// listeners).
pub fn router(state: AppState) -> Router {
    Router::new().fallback(proxy_handler).with_state(state)
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
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| peer.ip().to_string());

    // --- Routing + load balancing (single store lock, also decides redirect) -
    let (upstream_name, address, waf_enabled) =
        match pick_target(&state, &host, &path, &client_ip, secure) {
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
                );
                return Response::builder()
                    .status(StatusCode::PERMANENT_REDIRECT)
                    .header(axum::http::header::LOCATION, location)
                    .body(Body::empty())
                    .map(IntoResponse::into_response)
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
            RouteOutcome::Found {
                upstream,
                address,
                waf_enabled,
            } => (upstream, address, waf_enabled),
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
                );
                return (StatusCode::NOT_FOUND, "No matching route").into_response();
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
                );
                return (StatusCode::BAD_GATEWAY, "No healthy upstream").into_response();
            }
        };

    // --- WAF enforcement (only when the matched path has WAF enabled) --------
    if waf_enabled {
        let lc_headers: HashMap<String, String> = headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_lowercase(), s.to_string()))
            })
            .collect();
        let decision = {
            let store = state.store.lock();
            let default = store.settings.default_waf_action;
            let now_sec = Utc::now().timestamp().max(0) as u64;
            let ctx = WafContext {
                client_ip: &client_ip,
                method: method.as_str(),
                path: &path,
                headers: &lc_headers,
            };
            // evaluate() counts the hit engine-side; no Store write on the hot path.
            state.waf.evaluate(&store.waf_rules, default, &ctx, now_sec)
        };
        if decision.action != WafAction::Allow {
            let (status, msg) = match decision.action {
                WafAction::Deny => (StatusCode::FORBIDDEN, "Forbidden by WAF"),
                _ => (StatusCode::TOO_MANY_REQUESTS, "Challenge required"),
            };
            record_event(&state, &client_ip, &path, &decision, decision.action);
            log_request(
                &state,
                &client_ip,
                &method,
                &host,
                &path,
                status.as_u16(),
                started,
                "-",
                decision.action,
            );
            return (status, msg).into_response();
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
    // WS handshake carries no body; everything else streams through.
    let upstream_body = if is_ws { Body::empty() } else { body };
    let upstream_req = match builder.body(upstream_body) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Bad upstream request").into_response(),
    };

    // --- Send ----------------------------------------------------------------
    let send = state.proxy_client.request(upstream_req);
    let mut resp = match tokio::time::timeout(UPSTREAM_TIMEOUT, send).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::warn!(upstream = %upstream_name, %url, "upstream request failed: {e}");
            log_request(
                &state,
                &client_ip,
                &method,
                &host,
                &path,
                502,
                started,
                &upstream_name,
                WafAction::Allow,
            );
            return (StatusCode::BAD_GATEWAY, "Upstream request failed").into_response();
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
    );
    let mut rb = Response::builder().status(status);
    for (name, value) in resp.headers() {
        if !HOP_BY_HOP.contains(&name.as_str()) {
            rb = rb.header(name, value);
        }
    }
    rb.body(Body::new(resp.into_body()))
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
    Found {
        upstream: String,
        address: String,
        waf_enabled: bool,
    },
    NoRoute,
    NoHealthyUpstream,
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
    let mut cursor = state.lb_cursor.lock();
    match select_node(upstream, client_ip, &mut cursor) {
        Some(address) => RouteOutcome::Found {
            upstream: upstream.name.clone(),
            address,
            waf_enabled,
        },
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
    };
    state.logs.lock().record(entry);
}

fn record_event(
    state: &AppState,
    client_ip: &str,
    path: &str,
    decision: &crate::waf::WafDecision,
    action: WafAction,
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
