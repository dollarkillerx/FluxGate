//! End-to-end integration tests for the data plane: boot the real `proxy::router`
//! against an in-memory `AppState` and a mock upstream, fire real HTTP requests,
//! and assert the WAF block / allow / challenge behavior. These pin the data-plane
//! contracts (especially the recent review fixes) so they can't silently regress —
//! the safety net that makes refactoring `proxy_handler` safe.

#![cfg(test)]

use std::net::SocketAddr;
use std::path::PathBuf;

use serde_json::json;

use crate::state::{AppState, Config, Store};

// ---- harness ---------------------------------------------------------------

fn test_config(cert_dir: PathBuf) -> Config {
    Config {
        admin_token: "test-secret".into(),
        admin_username: "admin".into(),
        admin_password: "admin".into(),
        data_path: None, // fully in-memory; `persist::save` becomes a no-op
        cert_dir,
        log_path: None,
        event_path: None,
        retention_days: 1,
        geoip_path: None,
        asn_path: None,
        traffic_path: None,
        bans_path: None,
    }
}

/// A trivial upstream that echoes a recognizable marker, so a *forwarded* request
/// is distinguishable from a WAF block/challenge page.
async fn spawn_mock_upstream() -> SocketAddr {
    use axum::body::Bytes;
    use axum::http::Method;
    use axum::routing::any;
    use axum::Router;

    async fn handler(method: Method, body: Bytes) -> String {
        format!("UPSTREAM_OK method={method} bodylen={}", body.len())
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(handler)))
            .await
            .unwrap();
    });
    addr
}

/// Build an in-memory `AppState`, run `seed` to populate the store, recompile the
/// WAF engines, and return it. `_tmp` keeps the cert tempdir alive for the test.
fn build_state(seed: impl FnOnce(&mut Store)) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let state = AppState::new(test_config(tmp.path().to_path_buf()));
    {
        let mut store = state.store.lock();
        seed(&mut store);
        state.waf.rebuild(&store.waf_rules);
        state.waf.rebuild_semantic(&store.waf_semantic);
    }
    (state, tmp)
}

/// Insert a site (`test.local`) + root route + an upstream pointing at `upstream`.
fn seed_site(store: &mut Store, upstream: SocketAddr, waf_enabled: bool) {
    // The product default challenges all unmatched traffic; for these tests we want
    // the no-rule-match fallback to be Allow so we isolate rule/semantic behavior.
    store.settings.default_waf_action = fluxgate_core::WafAction::Allow;
    let site: fluxgate_core::Site = serde_json::from_value(json!({
        "id": "s1", "name": "t", "host": "test.local",
        "tls_enabled": false, "waf_enabled": waf_enabled, "enabled": true,
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
    }))
    .unwrap();
    let route: fluxgate_core::Route = serde_json::from_value(json!({
        "id": "r1", "site_id": "s1", "name": "root", "path": "/",
        "upstream": "up1", "waf_enabled": waf_enabled, "enabled": true,
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
    }))
    .unwrap();
    let upstream: fluxgate_core::Upstream = serde_json::from_value(json!({
        "id": "u1", "name": "up1", "strategy": "round_robin",
        "servers": [{ "address": upstream.to_string(), "weight": 1, "healthy": true, "latency_ms": 0 }],
        "healthy_servers": 1, "status": "healthy",
    }))
    .unwrap();
    store.sites.push(site);
    store.routes.push(route);
    store.upstreams.push(upstream);
}

async fn boot_proxy(state: AppState) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = crate::proxy::router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        axum::serve(listener, svc).await.unwrap();
    });
    addr
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Response status + body text for a request to the proxy.
async fn send(
    proxy: SocketAddr,
    method: reqwest::Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<(&str, Vec<u8>)>, // (content-type, bytes)
) -> (u16, String) {
    let mut rb = client()
        .request(method, format!("http://{proxy}{path}"))
        .header(reqwest::header::HOST, "test.local")
        // A normal browser UA: avoids the seeded "empty User-Agent" challenge rule
        // so tests exercise the detection logic, not the bot heuristics.
        .header(
            reqwest::header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        );
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    if let Some((ct, bytes)) = body {
        rb = rb.header(reqwest::header::CONTENT_TYPE, ct).body(bytes);
    }
    let resp = rb.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (status, text)
}

async fn get(proxy: SocketAddr, path: &str) -> (u16, String) {
    send(proxy, reqwest::Method::GET, path, &[], None).await
}

/// Drive `concurrency` keep-alive connections, each sending `per_worker` benign
/// GETs through the proxy, and return `(qps, avg, p50, p99, successes)`.
async fn measure_load(
    addr: SocketAddr,
    path: &str,
    concurrency: usize,
    per_worker: usize,
) -> (
    f64,
    std::time::Duration,
    std::time::Duration,
    std::time::Duration,
    u64,
) {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";
    let client = Arc::new(
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(concurrency)
            .build()
            .unwrap(),
    );
    let url = Arc::new(format!("http://{addr}{path}"));
    // Warm up the connection pool / route resolution.
    for _ in 0..200 {
        let _ = client
            .get(url.as_str())
            .header(reqwest::header::HOST, "test.local")
            .header(reqwest::header::USER_AGENT, UA)
            .send()
            .await;
    }
    let start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let client = client.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let mut lats = Vec::with_capacity(per_worker);
            let mut ok = 0u64;
            for _ in 0..per_worker {
                let t = Instant::now();
                if let Ok(resp) = client
                    .get(url.as_str())
                    .header(reqwest::header::HOST, "test.local")
                    .header(reqwest::header::USER_AGENT, UA)
                    .send()
                    .await
                {
                    if resp.status().is_success() {
                        ok += 1;
                    }
                    let _ = resp.bytes().await;
                }
                lats.push(t.elapsed());
            }
            (lats, ok)
        }));
    }
    let mut all = Vec::with_capacity(concurrency * per_worker);
    let mut ok_total = 0u64;
    for h in handles {
        let (lats, ok) = h.await.unwrap();
        all.extend(lats);
        ok_total += ok;
    }
    let elapsed = start.elapsed();
    let qps = (concurrency * per_worker) as f64 / elapsed.as_secs_f64();
    all.sort_unstable();
    let avg = all.iter().sum::<Duration>() / all.len() as u32;
    let p50 = all[all.len() / 2];
    let p99 = all[all.len() * 99 / 100];
    (qps, avg, p50, p99, ok_total)
}

/// End-to-end throughput/latency with the WAF **off** vs **on** (real proxy over
/// TCP + mock upstream; the WAF-on path runs the OWASP-CRS regex rules + all
/// semantic modules). Run:
///   cargo test -p fluxgate-admin --release waf_qps -- --ignored --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn waf_qps_off_vs_on() {
    let up = spawn_mock_upstream().await;
    let (off_state, _t1) = build_state(|s| seed_site(s, up, false));
    let (on_state, _t2) = build_state(|s| {
        seed_site(s, up, true);
        s.waf_rules = crate::waf_packs::pack_rules("owasp-crs").unwrap();
    });
    let off = boot_proxy(off_state).await;
    let on = boot_proxy(on_state).await;

    let (conc, per) = (32usize, 1500usize);
    let total = conc * per;
    let path = "/api/v1/users?page=2&sort=name&filter=active&q=hello+world";

    let (o_qps, o_avg, o_p50, o_p99, o_ok) = measure_load(off, path, conc, per).await;
    let (n_qps, n_avg, n_p50, n_p99, n_ok) = measure_load(on, path, conc, per).await;

    let us = |d: std::time::Duration| d.as_secs_f64() * 1e6;
    println!("\n=== WAF off vs on — end-to-end ({conc} conns × {per} = {total} req each, loopback + mock upstream) ===");
    println!(
        "{:<8} {:>10} {:>11} {:>11} {:>11} {:>12}",
        "config", "QPS", "avg µs", "p50 µs", "p99 µs", "2xx"
    );
    println!(
        "{:<8} {:>10.0} {:>11.1} {:>11.1} {:>11.1} {:>8}/{}",
        "off",
        o_qps,
        us(o_avg),
        us(o_p50),
        us(o_p99),
        o_ok,
        total
    );
    println!(
        "{:<8} {:>10.0} {:>11.1} {:>11.1} {:>11.1} {:>8}/{}",
        "on",
        n_qps,
        us(n_avg),
        us(n_p50),
        us(n_p99),
        n_ok,
        total
    );
    println!(
        "\n  throughput: {:+.1}%   added avg latency: {:+.1} µs/req\n",
        (n_qps - o_qps) / o_qps * 100.0,
        us(n_avg) - us(o_avg)
    );
    assert!(
        o_ok as usize == total && n_ok as usize == total,
        "all requests should 2xx"
    );
}

fn forwarded(text: &str) -> bool {
    text.contains("UPSTREAM_OK")
}

// ---- tests -----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn benign_request_is_forwarded() {
    let up = spawn_mock_upstream().await;
    let (state, _t) = build_state(|s| seed_site(s, up, true));
    let proxy = boot_proxy(state).await;
    let (status, body) = get(proxy, "/?q=hello+world").await;
    assert_eq!(status, 200);
    assert!(forwarded(&body), "benign request should reach the upstream");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn semantic_sqli_in_query_is_blocked() {
    let up = spawn_mock_upstream().await;
    let (state, _t) = build_state(|s| seed_site(s, up, true));
    let proxy = boot_proxy(state).await;
    // `1' OR '1'='1` -> semantic SQLi, default Block mode -> 403.
    let (status, body) = get(proxy, "/?q=1%27%20OR%20%271%27%3D%271").await;
    assert_eq!(status, 403, "SQLi should be blocked");
    assert!(!forwarded(&body), "blocked request must not reach upstream");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn monitor_mode_forwards_but_records() {
    let up = spawn_mock_upstream().await;
    let (state, _t) = build_state(|s| {
        seed_site(s, up, true);
        s.waf_semantic.mode = fluxgate_core::WafMode::Monitor;
    });
    let probe = state.clone();
    let proxy = boot_proxy(state).await;
    let (status, body) = get(proxy, "/?q=1%27%20OR%20%271%27%3D%271").await;
    assert_eq!(status, 200, "monitor mode must not block");
    assert!(forwarded(&body));
    // The detection is still recorded, un-enforced.
    let events = probe.waf_events.lock().snapshot();
    assert!(
        events.iter().any(|e| !e.enforced),
        "monitor-mode detection should be recorded with enforced=false"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_route_monitor_forwards_while_global_blocks() {
    let up = spawn_mock_upstream().await;
    // Global semantic mode stays Block (default); the route overrides to Monitor —
    // the per-app gradual-rollout case.
    let (state, _t) = build_state(|s| {
        seed_site(s, up, true);
        s.routes[0].waf_mode = Some(fluxgate_core::WafMode::Monitor);
    });
    let probe = state.clone();
    let proxy = boot_proxy(state).await;
    // A SQLi query that a default (Block) route 403s — here it's forwarded + logged.
    let (status, body) = get(proxy, "/?q=1%27%20OR%20%271%27%3D%271").await;
    assert_eq!(status, 200, "a per-route Monitor override must not block");
    assert!(forwarded(&body));
    let events = probe.waf_events.lock().snapshot();
    assert!(
        events.iter().any(|e| !e.enforced),
        "the monitored route should record the detection as enforced=false"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_allow_rule_short_circuits_semantic() {
    let up = spawn_mock_upstream().await;
    let (state, _t) = build_state(|s| {
        seed_site(s, up, true);
        // A regex Allow rule for the path — must short-circuit the semantic engine.
        let allow: fluxgate_core::WafRule = serde_json::from_value(json!({
            "id": "allow-api", "name": "allow", "description": "",
            "match_type": "path", "pattern": "^/api/", "action": "allow",
            "priority": 1, "enabled": true, "hit_count": 0,
        }))
        .unwrap();
        s.waf_rules.push(allow);
    });
    let proxy = boot_proxy(state).await;
    // SQLi in the query, but under the allow-listed path: must be forwarded.
    let (status, body) = get(proxy, "/api/?q=1%27%20OR%20%271%27%3D%271").await;
    assert_eq!(
        status, 200,
        "explicit allow rule must short-circuit the semantic engine"
    );
    assert!(forwarded(&body));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_sqli_is_blocked_but_multipart_file_is_not() {
    let up = spawn_mock_upstream().await;
    let (state, _t) = build_state(|s| seed_site(s, up, true));
    let proxy = boot_proxy(state).await;

    // Form body with SQLi -> blocked.
    let (status, _) = send(
        proxy,
        reqwest::Method::POST,
        "/login",
        &[],
        Some((
            "application/x-www-form-urlencoded",
            b"user=admin%27--+-&p=x".to_vec(),
        )),
    )
    .await;
    assert_eq!(status, 403, "SQLi in a form body should be blocked");

    // A multipart *file* part containing PHP must NOT be blocked (the FP fix:
    // raw multipart/file bytes are not fed to the regex body rules).
    let boundary = "X123";
    let mp = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php system($_GET[0]); ?>\r\n--{b}--\r\n",
        b = boundary
    );
    let (status, body) = send(
        proxy,
        reqwest::Method::POST,
        "/upload",
        &[],
        Some((
            &format!("multipart/form-data; boundary={boundary}"),
            mp.into_bytes(),
        )),
    )
    .await;
    assert_eq!(status, 200, "a benign file upload must not be blocked");
    assert!(forwarded(&body));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn challenge_blocks_without_clearance_and_passes_with_it() {
    let up = spawn_mock_upstream().await;
    let (state, _t) = build_state(|s| {
        seed_site(s, up, true);
        // Force the SQLi module's medium/high actions to Challenge so a detection
        // yields a managed challenge rather than an outright block. (The default
        // config pre-populates every module, so the key exists.)
        let m = s.waf_semantic.modules.get_mut("sqli").unwrap();
        m.high = fluxgate_core::RiskAction::Challenge;
        m.medium = fluxgate_core::RiskAction::Challenge;
    });
    let proxy = boot_proxy(state).await;

    let sqli = "/?q=1%27%20OR%20%271%27%3D%271";
    // No clearance cookie -> 503 interstitial.
    let (status, _) = get(proxy, sqli).await;
    assert_eq!(
        status, 503,
        "challenge without clearance should return the interstitial"
    );

    // With a valid clearance cookie -> forwarded.
    let now = chrono::Utc::now().timestamp();
    let cookie = crate::challenge::mint_clearance("test-secret", now);
    let (status, body) = send(
        proxy,
        reqwest::Method::GET,
        sqli,
        &[("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(status, 200, "a cleared client should pass the challenge");
    assert!(forwarded(&body));
}
