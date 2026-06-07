//! Shared application state.
//!
//! `Store` holds the user-managed **configuration** (routes, upstreams, WAF
//! rules, certificates, settings) and is persisted to disk. Real runtime data
//! (host telemetry, request logs, upstream health) lives in the collectors —
//! see `collector.rs`. There is no fabricated/mock data.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

// parking_lot mutexes: faster, and they don't poison — a panic while holding a
// lock won't take down the whole process's data + control planes.
use parking_lot::Mutex;

use serde::{Deserialize, Serialize};

use fluxgate_core::*;

use crate::collector::{EventBuffer, LogBuffer, Telemetry};
use crate::waf::WafEngine;

/// Startup configuration, resolved from environment variables in `main`.
#[derive(Clone)]
pub struct Config {
    pub admin_token: String,
    pub admin_username: String,
    pub admin_password: String,
    pub data_path: Option<PathBuf>,
    /// Directory where certificate + key PEM files are stored.
    pub cert_dir: PathBuf,
    /// Access-log JSONL file (`None` = in-memory only).
    pub log_path: Option<PathBuf>,
    /// WAF-event JSONL file (`None` = in-memory only).
    pub event_path: Option<PathBuf>,
    /// Retention window in days for access logs / WAF events. Older entries are
    /// pruned periodically from both memory and disk.
    pub retention_days: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// User-managed configuration (persisted).
    pub store: Arc<Mutex<Store>>,
    /// Real host telemetry, sampled by a background task.
    pub telemetry: Arc<Mutex<Telemetry>>,
    /// Ring buffer of real HTTP requests served by this process.
    pub logs: Arc<Mutex<LogBuffer>>,
    /// WAF rule-matching engine (regex cache + rate-limit counters).
    pub waf: Arc<WafEngine>,
    /// Ring buffer of real WAF enforcement decisions.
    pub waf_events: Arc<Mutex<EventBuffer>>,
    /// In-flight request count (real active connections).
    pub inflight: Arc<AtomicI64>,
    /// HTTP client used by the proxy data plane to reach upstreams.
    pub proxy_client: Arc<crate::proxy::ProxyClient>,
    /// Round-robin cursor per upstream id (load balancing state).
    pub lb_cursor: Arc<Mutex<HashMap<String, usize>>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let mut store = crate::persist::load_or_seed(&config.data_path);
        let mut dirty = false;
        // Bootstrap admin credentials on first run (hash the env/default password).
        if store.auth.password_hash.is_empty() {
            store.auth.username = config.admin_username.clone();
            store.auth.password_hash =
                crate::auth::hash_password(&config.admin_password).unwrap_or_default();
            store.settings.admin_username = config.admin_username.clone();
            dirty = true;
        }
        // Seed a default FluxGate self-signed certificate when none exist, so the
        // certificate list is never empty and routes always have one to select.
        if store.certs.is_empty() {
            match crate::tls::default_self_signed_cert(&config.cert_dir) {
                Ok(cert) => {
                    store.certs.push(cert);
                    dirty = true;
                }
                Err(e) => tracing::warn!("could not seed default certificate: {e}"),
            }
        }
        if dirty {
            crate::persist::save(&config.data_path, &store);
        }
        // Capture buffer paths before `config` is moved into the Arc.
        let log_path = config.log_path.clone();
        let event_path = config.event_path.clone();
        Self {
            config: Arc::new(config),
            store: Arc::new(Mutex::new(store)),
            telemetry: Arc::new(Mutex::new(Telemetry::new())),
            logs: Arc::new(Mutex::new(LogBuffer::new(1000, log_path))),
            waf: Arc::new(WafEngine::new()),
            waf_events: Arc::new(Mutex::new(EventBuffer::new(500, event_path))),
            inflight: Arc::new(AtomicI64::new(0)),
            proxy_client: Arc::new(crate::proxy::build_client()),
            lb_cursor: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn admin_token(&self) -> &str {
        &self.config.admin_token
    }
}

/// Persisted configuration. Starts empty — entries are created by the operator.
#[derive(Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub sites: Vec<Site>,
    pub routes: Vec<Route>,
    pub upstreams: Vec<Upstream>,
    pub waf_rules: Vec<WafRule>,
    pub certs: Vec<TlsCertificate>,
    pub settings: Settings,
    /// Admin credentials (never returned by `settings.get`).
    #[serde(default)]
    pub auth: AuthCreds,
}

/// Admin login credentials. The password is stored only as an Argon2 hash.
#[derive(Serialize, Deserialize, Default)]
pub struct AuthCreds {
    pub username: String,
    pub password_hash: String,
}
