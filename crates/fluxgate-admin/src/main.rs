//! FluxGate Admin server.
//!
//! A single binary that serves:
//! * The **admin console** over HTTPS (`POST /rpc`, `GET /health`, embedded
//!   React SPA) — protected by a default self-signed certificate generated on
//!   first start.
//! * The **reverse-proxy data plane**: plaintext HTTP plus an SNI-gated HTTPS
//!   listener that only serves hosts which have both a certificate and an
//!   enabled `tls_enabled` route.
//!
//! Run with `cargo run -p fluxgate-admin`. Configuration is read from env:
//! * `FLUXGATE_ADMIN_ADDR`     — admin console (HTTPS) listen addr (default `127.0.0.1:8080`)
//! * `FLUXGATE_PROXY_ADDR`     — proxy HTTP plane (default `0.0.0.0:80`; empty = off)
//! * `FLUXGATE_PROXY_TLS_ADDR` — proxy HTTPS plane (default `0.0.0.0:443`; empty = off)
//! * `FLUXGATE_ADMIN_TOKEN`    — bearer token for `/rpc` (default `fluxgate-dev-token`)
//! * `FLUXGATE_ADMIN_USER`     — login username (default `admin`)
//! * `FLUXGATE_ADMIN_PASSWORD` — login password (default `admin`)
//! * `FLUXGATE_CERT_DIR`       — certificate/key storage dir (default `fluxgate-certs`)
//! * `FLUXGATE_DATA_FILE`      — persistence path (default `fluxgate-data.json`; empty = in-memory)
//! * `RUST_LOG`                — tracing filter (default `info`)
//!
//! Ports 80/443 are privileged — run with sudo, or point the proxy at high
//! ports (e.g. `FLUXGATE_PROXY_ADDR=0.0.0.0:8080 FLUXGATE_PROXY_TLS_ADDR=0.0.0.0:8443`).

mod access;
mod acme;
mod assets;
mod auth;
mod challenge;
mod cloudflare;
mod collector;
mod iprange;
mod pages;
mod persist;
mod proxy;
mod rpc;
mod serve;
mod state;
mod throttle;
mod tls;
mod traffic;
mod waf;
mod waf_packs;
mod waf_semantic;

#[cfg(test)]
mod integration_tests;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::{
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use state::{AppState, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let addr: SocketAddr = std::env::var("FLUXGATE_ADMIN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;

    let config = Config {
        admin_token: env_or("FLUXGATE_ADMIN_TOKEN", "fluxgate-dev-token"),
        admin_username: env_or("FLUXGATE_ADMIN_USER", "admin"),
        admin_password: env_or("FLUXGATE_ADMIN_PASSWORD", "admin"),
        data_path: resolve_data_path(),
        cert_dir: PathBuf::from(env_or("FLUXGATE_CERT_DIR", "fluxgate-certs")),
        log_path: resolve_opt_path("FLUXGATE_LOG_FILE", "fluxgate-access.log"),
        event_path: resolve_opt_path("FLUXGATE_EVENT_FILE", "fluxgate-events.log"),
        retention_days: env_or("FLUXGATE_LOG_RETENTION_DAYS", "6")
            .parse()
            .unwrap_or(6)
            .max(1),
        geoip_path: resolve_geoip_path(),
        asn_path: resolve_asn_path(),
        traffic_path: resolve_opt_path("FLUXGATE_TRAFFIC_FILE", "fluxgate-traffic.json"),
        bans_path: resolve_opt_path("FLUXGATE_BANS_FILE", "fluxgate-bans.json"),
    };
    if let Err(e) = std::fs::create_dir_all(&config.cert_dir) {
        tracing::warn!(
            "could not create cert dir {}: {e}",
            config.cert_dir.display()
        );
    }
    tracing::info!("certificates stored in {}", config.cert_dir.display());

    match &config.data_path {
        Some(p) => tracing::info!("persistence ENABLED → {}", p.display()),
        None => tracing::warn!("persistence DISABLED (in-memory only)"),
    }
    // Only surface the demo password; never log a custom secret in plaintext.
    if config.admin_password == "admin" {
        tracing::info!("login: user='{}' password='admin' (demo default — set FLUXGATE_ADMIN_PASSWORD to change)", config.admin_username);
    } else {
        tracing::info!(
            "login: user='{}' password=****** (set via FLUXGATE_ADMIN_PASSWORD)",
            config.admin_username
        );
    }

    // Install the rustls crypto provider before any TLS config is built.
    serve::install_crypto_provider();

    let state = AppState::new(config);
    spawn_background_tasks(state.clone());

    // Reverse-proxy data plane: plaintext HTTP (:80) + SNI-gated HTTPS (:443).
    // The HTTPS listener only completes a handshake for hosts that have BOTH a
    // certificate and an enabled tls_enabled route — "配置了证书且开通 TLS 才代理".
    if let Some(proxy_addr) = resolve_proxy_addr() {
        let proxy_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = proxy::run(proxy_state, proxy_addr).await {
                tracing::error!(
                    "proxy HTTP plane failed to start on {proxy_addr}: {e}{}",
                    bind_hint(&e, proxy_addr)
                );
            }
        });
    } else {
        tracing::warn!("reverse-proxy HTTP plane DISABLED (FLUXGATE_PROXY_ADDR empty)");
    }
    if let Some(tls_addr) = resolve_proxy_tls_addr() {
        let tls_state = state.clone();
        tokio::spawn(async move {
            let cfg = serve::data_plane_config(tls_state.clone());
            tracing::info!("  • Proxy   : https://{tls_addr} (SNI: serves only configured + TLS-enabled hosts)");
            if let Err(e) = serve::serve_tls(proxy::router(tls_state), tls_addr, cfg).await {
                tracing::error!(
                    "proxy HTTPS plane failed to start on {tls_addr}: {e}{}",
                    bind_hint(&e, tls_addr)
                );
            }
        });
    } else {
        tracing::warn!("reverse-proxy HTTPS plane DISABLED (FLUXGATE_PROXY_TLS_ADDR empty)");
    }

    // Admin console over HTTPS with a default self-signed certificate.
    let (admin_cert, admin_key) = tls::ensure_admin_cert(&state.config.cert_dir)
        .map_err(|e| anyhow::anyhow!("could not prepare admin TLS certificate: {e}"))?;
    let admin_tls = serve::single_cert_config(&admin_cert, &admin_key)
        .map_err(|e| anyhow::anyhow!("invalid admin TLS certificate: {e}"))?;

    let app = build_router(state);
    tracing::info!("FluxGate Admin Console listening on https://{addr}");
    tracing::info!(
        "  • Console : https://{addr}/  (self-signed cert — accept the browser warning)"
    );
    tracing::info!("  • RPC     : https://{addr}/rpc  (login via method 'auth.login')");
    tracing::info!("  • Health  : https://{addr}/health");

    serve::serve_tls(app, addr, admin_tls).await?;
    Ok(())
}

/// Periodic real-data collection: host telemetry + upstream health probing.
fn spawn_background_tasks(state: AppState) {
    // Host telemetry sampler (CPU / memory / network).
    let telemetry = state.telemetry.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(3));
        loop {
            ticker.tick().await;
            telemetry.lock().sample();
        }
    });

    // Upstream TCP health probing.
    let store = state.store.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        loop {
            ticker.tick().await;
            // Blocking connects run on a dedicated thread to avoid stalling the runtime.
            let store = store.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                let mut s = store.lock();
                collector::probe_upstreams(&mut s);
            })
            .await
            {
                tracing::warn!("upstream health probe task failed: {e}");
            }
        }
    });

    // ACME auto-renewal: every 12h, re-issue ACME-managed certificates that are
    // within 30 days of expiry (and still have auto_renew on) over HTTP-01. The
    // renewal reuses the persisted account; a pending re-issue swaps in the new
    // cert/key files on success without interrupting the current one.
    let renew_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(12 * 3600));
        loop {
            ticker.tick().await;
            // Only renew when ACME is enabled and the operator agreed to the ToS.
            let due: Vec<(String, String)> = {
                let store = renew_state.store.lock();
                if !(store.settings.acme.enabled && store.settings.acme.agree_tos) {
                    Vec::new()
                } else {
                    store
                        .certs
                        .iter()
                        .filter(|c| c.acme && c.auto_renew)
                        .filter(|c| {
                            tls::parse_dt(&c.expires_at)
                                .map(|dt| (dt - Utc::now()).num_days() <= 30)
                                .unwrap_or(false)
                        })
                        .map(|c| (c.id.clone(), c.domain.clone()))
                        .collect()
                }
            };
            for (id, domain) in due {
                tracing::info!("ACME: auto-renewing {domain} (id {id})");
                rpc::spawn_acme_issue(renew_state.clone(), id, domain);
            }
        }
    });

    // Log/event retention: prune entries older than the configured window
    // (default 6 days) hourly, from both the in-memory buffers and disk.
    let logs = state.logs.clone();
    let events = state.waf_events.clone();
    let retention_days = state.config.retention_days;
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            let (logs, events) = (logs.clone(), events.clone());
            // File rewrite is blocking IO — keep it off the async runtime.
            if let Err(e) = tokio::task::spawn_blocking(move || {
                let cutoff = Utc::now() - chrono::Duration::days(retention_days);
                let removed_logs = logs.lock().prune_older_than(cutoff);
                let removed_events = events.lock().prune_older_than(cutoff);
                if removed_logs > 0 || removed_events > 0 {
                    tracing::info!(
                        "retention: pruned {removed_logs} access-log + {removed_events} event entries older than {retention_days}d"
                    );
                }
            })
            .await
            {
                tracing::warn!("log retention task failed: {e}");
            }
        }
    });

    // Traffic totals: persist (and prune >31d daily buckets) every 30s, so the
    // per-site total / 30d / today figures survive restarts. The in-memory meter
    // is updated live by the data plane; this just snapshots it to disk.
    let traffic = state.traffic.clone();
    let access = state.access.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            let (traffic, access) = (traffic.clone(), access.clone());
            let _ = tokio::task::spawn_blocking(move || {
                traffic.flush();
                access.flush(Utc::now().timestamp());
            })
            .await;
        }
    });
}

/// Assemble the full HTTP router: API routes + embedded static assets.
fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/rpc", post(rpc::handle_rpc))
        .route("/health", get(health))
        .with_state(state.clone());

    api
        // Everything not matched above is served from the embedded frontend,
        // with an index.html SPA fallback so client-side routes deep-link.
        .fallback(assets::static_handler)
        // NOTE: the admin console is the CONTROL plane — its requests are
        // deliberately NOT recorded into the access-log / WAF / in-flight
        // metrics, which belong to the data plane (the reverse proxy). Mixing
        // them polluted dashboards (admin polling showed up as proxy traffic).
        .layer(axum::middleware::map_response(proxy::set_server_header))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}

/// Liveness probe. Always public. Also surfaces the WAF detector-panic counter:
/// a non-zero value means a request hit an untested detector path and the engine
/// failed open — an operational alert worth scraping.
async fn health(
    axum::extract::State(state): axum::extract::State<state::AppState>,
) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "fluxgate-admin",
        "version": env!("CARGO_PKG_VERSION"),
        "waf_detector_panics": state.waf.detector_panics(),
    }))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// `FLUXGATE_DATA_FILE` unset → default file; set to empty → disabled.
fn resolve_data_path() -> Option<PathBuf> {
    match std::env::var("FLUXGATE_DATA_FILE") {
        Ok(v) if v.is_empty() => None,
        Ok(v) => Some(PathBuf::from(v)),
        Err(_) => Some(PathBuf::from("fluxgate-data.json")),
    }
}

/// Env var → optional path: unset → default file; set to empty → disabled (None).
fn resolve_opt_path(key: &str, default: &str) -> Option<PathBuf> {
    match std::env::var(key) {
        Ok(v) if v.is_empty() => None,
        Ok(v) => Some(PathBuf::from(v)),
        Err(_) => Some(PathBuf::from(default)),
    }
}

/// `FLUXGATE_PROXY_ADDR` (plaintext HTTP plane) unset → default `0.0.0.0:80`;
/// set to empty → disabled.
fn resolve_proxy_addr() -> Option<SocketAddr> {
    resolve_addr_env("FLUXGATE_PROXY_ADDR", "0.0.0.0:80")
}

/// `FLUXGATE_PROXY_TLS_ADDR` (HTTPS plane) unset → default `0.0.0.0:443`;
/// set to empty → disabled.
fn resolve_proxy_tls_addr() -> Option<SocketAddr> {
    resolve_addr_env("FLUXGATE_PROXY_TLS_ADDR", "0.0.0.0:443")
}

/// Parse a socket-addr env var: unset → `default`; empty string → `None`
/// (disabled); invalid → logged and `None`.
fn resolve_addr_env(var: &str, default: &str) -> Option<SocketAddr> {
    let raw = match std::env::var(var) {
        Ok(v) if v.is_empty() => return None,
        Ok(v) => v,
        Err(_) => default.to_string(),
    };
    match raw.parse() {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::error!("invalid {var} '{raw}': {e}");
            None
        }
    }
}

/// GeoIP database path:
/// * `FLUXGATE_GEOIP_DB` set to a path → use it (no auto-download).
/// * set to empty → disabled.
/// * unset → default `fluxgate-geoip/GeoLite2-Country.mmdb`; if missing, it's
///   **auto-downloaded** from the P3TERX/GeoLite.mmdb mirror (best effort).
fn resolve_geoip_path() -> Option<PathBuf> {
    // `FLUXGATE_GEOIP_DB` empty → explicitly disabled; set → use that path;
    // unset → default location. In the latter two cases the DB is auto-downloaded
    // when missing (so pointing the env var at a fresh path still self-heals
    // instead of silently leaving country lookups unresolved).
    let path = match std::env::var("FLUXGATE_GEOIP_DB") {
        Ok(v) if v.is_empty() => return None,
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("fluxgate-geoip/GeoLite2-Country.mmdb"),
    };
    const URL: &str =
        "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb";
    if path.exists() {
        return Some(path);
    }
    match download_geoip(&path, URL, "GeoIP country") {
        Ok(()) => Some(path),
        Err(e) => {
            tracing::warn!(
                "GeoIP auto-download failed: {e} — country stats / `geo` rules disabled"
            );
            None
        }
    }
}

/// GeoLite2-**ASN** database path (for the per-site datacenter/cloud block):
/// `FLUXGATE_ASN_DB` set → that path · empty → disabled · unset → default
/// `fluxgate-geoip/GeoLite2-ASN.mmdb`, auto-downloaded from the same mirror.
fn resolve_asn_path() -> Option<PathBuf> {
    let path = match std::env::var("FLUXGATE_ASN_DB") {
        Ok(v) if v.is_empty() => return None,
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("fluxgate-geoip/GeoLite2-ASN.mmdb"),
    };
    const URL: &str =
        "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb";
    if path.exists() {
        return Some(path);
    }
    match download_geoip(&path, URL, "GeoIP ASN") {
        Ok(()) => Some(path),
        Err(e) => {
            tracing::warn!("ASN database auto-download failed: {e} — datacenter blocking disabled");
            None
        }
    }
}

/// Fetch an mmdb database from `url` to `dest` (atomic via a temp file). Blocking;
/// only runs once, at first start. `what` labels it in logs.
fn download_geoip(dest: &std::path::Path, url: &str, what: &str) -> anyhow::Result<()> {
    tracing::info!("{what} database not found — downloading from P3TERX/GeoLite.mmdb …");
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("mmdb.tmp");
    let fetch = || -> anyhow::Result<u64> {
        let agent = ureq::builder()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .build();
        let resp = agent.get(url).call()?;
        let mut file = std::fs::File::create(&tmp)?;
        let bytes = std::io::copy(&mut resp.into_reader(), &mut file)?;
        file.sync_all().ok();
        Ok(bytes)
    };
    match fetch() {
        Ok(bytes) => {
            std::fs::rename(&tmp, dest)?;
            tracing::info!(
                "{what} database downloaded ({} KB) → {}",
                bytes / 1024,
                dest.display()
            );
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp); // don't leave a partial behind
            Err(e)
        }
    }
}

/// Friendly hint appended to a bind failure on a privileged port (<1024).
fn bind_hint(e: &std::io::Error, addr: SocketAddr) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied && addr.port() < 1024 {
        format!(
            " — port {} is privileged; run with sudo or set a high port \
             (e.g. FLUXGATE_PROXY_ADDR=0.0.0.0:8080 / FLUXGATE_PROXY_TLS_ADDR=0.0.0.0:8443)",
            addr.port()
        )
    } else {
        String::new()
    }
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}
