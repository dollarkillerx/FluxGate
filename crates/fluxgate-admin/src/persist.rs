//! JSON-file persistence for the configuration store.
//!
//! On first run there is no mock data: the store starts empty with sane default
//! settings. Operators create routes/upstreams/etc., which are then persisted.

use std::path::{Path, PathBuf};

use fluxgate_core::*;

use crate::state::{AuthCreds, Store};

/// Load the store from `path` if present and parseable; otherwise start empty.
pub fn load_or_seed(path: &Option<PathBuf>) -> Store {
    if let Some(p) = path {
        match std::fs::read(p) {
            // Parse to a generic Value first so we can migrate the legacy flat
            // route schema (host/TLS on each route) into the site→route model.
            Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(mut value) => {
                    let migrated = migrate_legacy_routes(&mut value);
                    match serde_json::from_value::<Store>(value) {
                        Ok(store) => {
                            if migrated {
                                tracing::info!("migrated legacy routes into sites");
                            }
                            tracing::info!("loaded configuration from {}", p.display());
                            return store;
                        }
                        Err(e) => {
                            tracing::warn!("failed to parse {} ({e}); starting empty", p.display())
                        }
                    }
                }
                Err(e) => tracing::warn!("failed to parse {} ({e}); starting empty", p.display()),
            },
            Err(_) => tracing::info!("no config file at {}; starting empty", p.display()),
        }
    }
    empty_store()
}

/// Migrate a pre-sites config: when routes still carry `host`/`tls_enabled` and
/// there are no `sites`, group routes by host into sites (hoisting TLS / cert /
/// redirect / WAF-default) and rewrite each route as a path under its site.
/// Returns whether any migration happened.
fn migrate_legacy_routes(value: &mut serde_json::Value) -> bool {
    use serde_json::{json, Value};
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    // Already migrated if sites exist and are non-empty.
    if obj
        .get("sites")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
    {
        return false;
    }
    let Some(routes) = obj.get("routes").and_then(Value::as_array).cloned() else {
        return false;
    };
    // Legacy marker: a route object carrying a `host` field.
    let is_legacy = routes
        .iter()
        .any(|r| r.get("host").and_then(Value::as_str).is_some());
    if !is_legacy {
        return false;
    }

    let mut sites: Vec<Value> = Vec::new();
    let mut site_id_by_host: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut new_routes: Vec<Value> = Vec::new();

    for r in &routes {
        let host = r
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let now = r
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let site_id = site_id_by_host.entry(host.clone()).or_insert_with(|| {
            let id = format!("st-mig{:04}", sites.len() + 1);
            sites.push(json!({
                "id": id,
                "name": host,
                "host": host,
                "tls_enabled": r.get("tls_enabled").and_then(Value::as_bool).unwrap_or(false),
                "cert_id": r.get("cert_id").cloned().unwrap_or(Value::Null),
                "https_redirect": r.get("https_redirect").and_then(Value::as_bool).unwrap_or(false),
                "waf_enabled": r.get("waf_enabled").and_then(Value::as_bool).unwrap_or(true),
                "enabled": true,
                "created_at": now,
                "updated_at": now,
            }));
            id
        });
        new_routes.push(json!({
            "id": r.get("id").cloned().unwrap_or(Value::Null),
            "site_id": site_id,
            "name": r.get("name").cloned().unwrap_or_else(|| json!("")),
            "path": r.get("path").cloned().unwrap_or_else(|| json!("/")),
            "upstream": r.get("upstream").cloned().unwrap_or_else(|| json!("")),
            "waf_enabled": r.get("waf_enabled").and_then(Value::as_bool).unwrap_or(true),
            "enabled": r.get("enabled").and_then(Value::as_bool).unwrap_or(true),
            "created_at": r.get("created_at").cloned().unwrap_or_else(|| json!("")),
            "updated_at": r.get("updated_at").cloned().unwrap_or_else(|| json!("")),
        }));
    }

    obj.insert("sites".into(), Value::Array(sites));
    obj.insert("routes".into(), Value::Array(new_routes));
    true
}

pub fn empty_store() -> Store {
    Store {
        sites: Vec::new(),
        routes: Vec::new(),
        upstreams: Vec::new(),
        // Ship a sensible baseline ruleset out of the box.
        waf_rules: default_waf_rules(),
        certs: Vec::new(),
        settings: default_settings(),
        // Populated by AppState::new on first run (bootstrapped from env).
        auth: AuthCreds::default(),
    }
}

/// Built-in WAF rules seeded on first run. All are real (evaluated by the WAF
/// engine) and only inspect method / path / headers, so they don't trip on
/// normal admin-console traffic. Operators can edit, disable, or delete them.
pub fn default_waf_rules() -> Vec<WafRule> {
    let mk = |id: &str,
              name: &str,
              description: &str,
              match_type,
              pattern: &str,
              action,
              priority,
              enabled| WafRule {
        id: id.into(),
        name: name.into(),
        description: description.into(),
        match_type,
        pattern: pattern.into(),
        action,
        priority,
        enabled,
        hit_count: 0,
    };
    vec![
        mk(
            "waf-default-methods",
            "Block dangerous HTTP methods",
            "Deny TRACE / TRACK / CONNECT which are rarely legitimate.",
            WafMatchType::Method,
            r"^(TRACE|TRACK|CONNECT)$",
            WafAction::Deny,
            5,
            true,
        ),
        mk(
            "waf-default-sqli",
            "Block SQL injection",
            "Common SQLi signatures in the request path/query.",
            WafMatchType::Path,
            r"(?i)(\bunion\b.+\bselect\b|\bor\b\s+1\s*=\s*1|';\s*--|/\*.+\*/)",
            WafAction::Deny,
            10,
            true,
        ),
        mk(
            "waf-default-traversal",
            "Block path traversal",
            "Directory traversal and access to sensitive system files.",
            WafMatchType::Path,
            r"(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self|c:\\windows)",
            WafAction::Deny,
            11,
            true,
        ),
        mk(
            "waf-default-xss",
            "Block reflected XSS",
            "Script / event-handler injection attempts in the URL.",
            WafMatchType::Path,
            r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)",
            WafAction::Deny,
            12,
            true,
        ),
        mk(
            "waf-default-sensitive-files",
            "Block sensitive files",
            "Requests for dotfiles / backups that should never be public.",
            WafMatchType::Path,
            r"(?i)\.(env|git|htaccess|bak|sql|pem|key)(/|$|\?)",
            WafAction::Deny,
            13,
            true,
        ),
        mk(
            "waf-default-empty-ua",
            "Challenge empty User-Agent",
            "JS challenge for requests with a missing/blank User-Agent.",
            WafMatchType::Header,
            r"User-Agent: ^\s*$",
            WafAction::Challenge,
            30,
            true,
        ),
        mk(
            "waf-default-ratelimit",
            "Global rate limit",
            "Challenge clients exceeding 1000 requests/second across all paths.",
            WafMatchType::RateLimit,
            "/@1000r/s",
            WafAction::Challenge,
            40,
            true,
        ),
        mk(
            "waf-default-geo",
            "Geo block (template)",
            "Example GeoIP rule — requires a GeoIP database to take effect; disabled by default.",
            WafMatchType::Geo,
            "country in [KP, SY]",
            WafAction::Deny,
            8,
            false,
        ),
    ]
}

fn default_settings() -> Settings {
    Settings {
        admin_username: "admin".into(),
        admin_email: "".into(),
        log_level: "info".into(),
        hot_reload: true,
        default_waf_action: WafAction::Allow,
        acme: AcmeSettings {
            enabled: false,
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            email: "".into(),
            agree_tos: false,
        },
        worker_threads: num_cpus::get() as u32,
        max_connections: 65536,
        request_timeout_secs: 30,
    }
}

/// Persist the store to `path` (atomic write via temp file + rename).
pub fn save(path: &Option<PathBuf>, store: &Store) {
    let Some(p) = path else { return };
    let bytes = match serde_json::to_vec_pretty(store) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("failed to serialize store: {e}");
            return;
        }
    };
    if let Err(e) = write_atomic(p, &bytes) {
        tracing::error!("failed to persist store to {}: {e}", p.display());
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn default_rules_are_sane() {
        let rules = default_waf_rules();
        assert!(rules.len() >= 5);
        // Unique ids.
        let ids: HashSet<_> = rules.iter().map(|r| r.id.clone()).collect();
        assert_eq!(ids.len(), rules.len());
        // All hit counts start at zero.
        assert!(rules.iter().all(|r| r.hit_count == 0));
    }

    #[test]
    fn empty_store_defaults() {
        let s = empty_store();
        assert!(s.routes.is_empty());
        assert!(s.upstreams.is_empty());
        assert!(s.certs.is_empty());
        assert!(!s.waf_rules.is_empty());
        assert_eq!(s.settings.default_waf_action, WafAction::Allow);
        assert!(s.auth.password_hash.is_empty()); // bootstrapped later
    }
}
