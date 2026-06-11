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
                        Ok(mut store) => {
                            if migrated {
                                tracing::info!("migrated legacy routes into sites");
                            }
                            // One-time schema migration: demote regex rules now
                            // superseded by the semantic engine on existing installs.
                            if migrate_schema(&mut store) {
                                save(path, &store);
                                tracing::info!(
                                    "migrated WAF config to schema v{CURRENT_SCHEMA_VERSION} \
                                     (demoted keyword rules superseded by the semantic engine)"
                                );
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
        // Ship the full built-in ruleset out of the box (baseline + OWASP CRS).
        waf_rules: seed_waf_rules(),
        certs: Vec::new(),
        settings: default_settings(),
        ip_whitelist: Vec::new(),
        ip_blacklist: Vec::new(),
        // Populated by AppState::new on first run (bootstrapped from env).
        auth: AuthCreds::default(),
        // Fresh installs start at the current schema with the semantic engine on.
        waf_semantic: WafSemanticConfig::default(),
        schema_version: CURRENT_SCHEMA_VERSION,
    }
}

/// Current persisted-store schema version. Bumping this triggers
/// [`migrate_schema`] on load for older stores.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// The complete set of built-in WAF rules shipped enabled by default: the
/// baseline rules **plus** the OWASP CRS pack. Used to seed fresh installs and,
/// via the id-based merge in `AppState::new`, to add any missing built-ins to
/// existing installs on restart — so CRS is on by default without an explicit
/// import.
pub fn seed_waf_rules() -> Vec<WafRule> {
    let mut rules = default_waf_rules();
    rules.extend(crate::waf_packs::pack_rules("owasp-crs").unwrap_or_default());
    rules
}

/// Built-in rule ids that the semantic engine now covers with far fewer false
/// positives. On a pre-semantic store they are demoted to disabled (unless the
/// operator customized the pattern).
const DEMOTED_RULE_IDS: &[&str] = &[
    "waf-default-sqli",
    "waf-default-xss",
    "waf-default-rce",
    "waf-default-traversal",
    "waf-default-body-sqli",
    "waf-default-body-xss",
    "waf-default-body-rce",
    "crs-942-sqli-authbypass",
    "crs-942-sqli-keywords",
    "crs-942-sqli-functions",
    "crs-942-sqli-operators",
    "crs-941-xss-tags",
    "crs-941-xss-events",
    "crs-941-xss-uris",
    "crs-930-lfi",
    "crs-932-rce-unix",
    // Superseded by the `php` / `java` semantic modules + extended `deser`.
    "crs-933-php",
    "crs-944-java",
    "crs-ssrf-metadata",
];

/// Run one-time store migrations keyed on `schema_version`. Returns whether the
/// store changed (and should be re-persisted).
///
/// v0 → v1: the semantic engine became the primary detector. Disable the broad
/// keyword rules it supersedes — but only when the operator hasn't customized the
/// pattern (so hand-tuned rules are preserved). A disabled-by-migration rule can
/// always be re-enabled from the console.
fn migrate_schema(store: &mut Store) -> bool {
    if store.schema_version >= CURRENT_SCHEMA_VERSION {
        return false;
    }
    // Map of id → shipped default pattern, to detect operator customization.
    let shipped: std::collections::HashMap<String, String> = seed_waf_rules()
        .into_iter()
        .map(|r| (r.id, r.pattern))
        .collect();

    for rule in &mut store.waf_rules {
        // Demote a superseded built-in only when the operator hasn't customized
        // it. `user_modified` is the durable signal (set on any API edit going
        // forward); `pattern == shipped` is the legacy fallback for stores
        // written before the flag existed (where `user_modified` defaults false).
        if rule.enabled
            && DEMOTED_RULE_IDS.contains(&rule.id.as_str())
            && !rule.user_modified
            && shipped.get(&rule.id).is_some_and(|p| p == &rule.pattern)
        {
            rule.enabled = false;
            if !rule.description.contains("[superseded]") {
                rule.description = format!("[superseded] {}", rule.description);
            }
        }
    }
    store.schema_version = CURRENT_SCHEMA_VERSION;
    true
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
        user_modified: false,
    };
    use WafAction::{Challenge, Deny};
    use WafMatchType::{Body, Geo, Header, Method, Path, RateLimit};
    // Path rules match the decoded path **and query**, so encoded payloads
    // (%2e%2e, %20) are normalized first. Lower priority = evaluated earlier.
    vec![
        mk(
            "waf-default-methods",
            "Block dangerous HTTP methods",
            "Deny TRACE / TRACK / CONNECT / DEBUG which are rarely legitimate.",
            Method,
            r"(?i)^(TRACE|TRACK|CONNECT|DEBUG)$",
            Deny,
            5,
            true,
        ),
        mk(
            "waf-default-jndi",
            "Block Log4Shell (JNDI)",
            "CVE-2021-44228 — ${jndi:ldap/rmi/dns://…} lookups in the request target.",
            Path,
            r"(?i)\$\{jndi:(ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http)://",
            Deny,
            6,
            true,
        ),
        mk(
            "waf-default-jndi-ua",
            "Block Log4Shell in User-Agent",
            "A JNDI lookup string smuggled through the User-Agent header.",
            Header,
            r"User-Agent: (?i)\$\{jndi:",
            Deny,
            7,
            true,
        ),
        mk(
            "waf-default-geo",
            "Geo block (template)",
            "GeoIP rule (`country in [..]` / `not in` / `==`). Active when a MaxMind \
             .mmdb is configured via FLUXGATE_GEOIP_DB; disabled by default.",
            Geo,
            "country in [KP, SY]",
            Deny,
            8,
            false,
        ),
        mk(
            "waf-default-sqli",
            "Block SQL injection",
            "Superseded by the semantic SQLi module (lower false positives); kept \
             disabled. Re-enable for defense-in-depth.",
            Path,
            r"(?i)(\bunion\b\s+(all\s+)?\bselect\b|\b(or|and)\b\s+\d+\s*=\s*\d+|';\s*(--|#)|/\*.*\*/|\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b|\binto\s+(outfile|dumpfile)\b|\bload_file\s*\(|\binformation_schema\b|\bxp_cmdshell\b)",
            Deny,
            10,
            false,
        ),
        mk(
            "waf-default-nosqli",
            "Block NoSQL injection",
            "MongoDB-style operator injection ($ne / $gt / $where / …).",
            Path,
            r"(?i)(\[\$(ne|gt|lt|gte|lte|in|nin|regex|where|exists|or|and)\]|\$where\s*:|\bfunction\s*\(\s*\)\s*\{)",
            Deny,
            11,
            true,
        ),
        mk(
            "waf-default-traversal",
            "Block path traversal / LFI",
            "Superseded by the semantic traversal module (structural resolution, \
             far fewer false positives); kept disabled.",
            Path,
            r"(?i)(\.\./|\.\.\\|/etc/(passwd|shadow|hosts|group)|/proc/self/|/windows/win\.ini|c:\\windows|php://(filter|input)|file://|expect://|data://text)",
            Deny,
            12,
            false,
        ),
        mk(
            "waf-default-rce",
            "Block command injection",
            "Superseded by the semantic command-injection module (requires real \
             shell structure); kept disabled.",
            Path,
            r"(?i)([;|]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|python)\b|&&\s*(cat|ls|id|wget|curl|nc)\b|\$\([^)]*\)|`[^`]*`|/bin/(ba)?sh\b|\bnc\s+-e\b)",
            Deny,
            13,
            false,
        ),
        mk(
            "waf-default-xss",
            "Block reflected XSS",
            "Superseded by the semantic XSS module (HTML-structure aware); kept \
             disabled.",
            Path,
            r"(?i)(<script[\s/>]|</script>|javascript:|vbscript:|\bon(error|load|click|mouseover|focus|toggle|animationstart)\s*=|<svg[\s/>]|<iframe[\s>]|<img[^>]+\bsrc\b|document\.cookie|\balert\s*\(|String\.fromCharCode)",
            Deny,
            14,
            false,
        ),
        mk(
            "waf-default-crlf",
            "Block CRLF / response splitting",
            "Carriage-return/line-feed header injection (decoded %0d%0a).",
            Path,
            r"(?i)(\r\n|\n)\s*(set-cookie|location|content-length|content-type)\s*:",
            Deny,
            15,
            true,
        ),
        mk(
            "waf-default-sensitive-files",
            "Block sensitive files",
            "Dotfiles, secrets, backups and config files that should never be public.",
            Path,
            r"(?i)(/\.(env|git|svn|hg|htaccess|htpasswd|aws|ssh|bash_history|npmrc|dockercfg)\b|/\.git/|\.(bak|backup|old|orig|swp|sql|sqlite|db|pem|key|p12|pfx)(\?|$)|/(wp-config|web|app|settings|configuration)\.(php|config|xml|yml|yaml)(\?|$)|/(id_rsa|id_dsa|authorized_keys)\b)",
            Deny,
            16,
            true,
        ),
        mk(
            "waf-default-webshell",
            "Block web shells",
            "Requests for known web-shell / backdoor filenames.",
            Path,
            r"(?i)/(c99|r57|c100|wso|b374k|webshell|backdoor|adminer)\.(php|phtml|asp|aspx|jsp|jspx)(\?|$)",
            Deny,
            17,
            true,
        ),
        // -- Request-body inspection -------------------------------------------
        // These match the *decoded body prefix* (form fields, JSON values, etc.),
        // closing the gap where an attacker simply moves a GET payload into a POST
        // body. Evaluated by the engine's separate body pass (WafMatchType::Body).
        mk(
            "waf-default-body-sqli",
            "Block SQL injection (body)",
            "Superseded by the semantic SQLi module, which inspects each decoded \
             body field; kept disabled.",
            Body,
            r"(?i)(\bunion\b\s+(all\s+)?\bselect\b|\b(or|and)\b\s+\d+\s*=\s*\d+|';\s*(--|#)|/\*.*\*/|\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b|\binto\s+(outfile|dumpfile)\b|\bload_file\s*\(|\binformation_schema\b|\bxp_cmdshell\b)",
            Deny,
            45,
            false,
        ),
        mk(
            "waf-default-body-xss",
            "Block XSS (body)",
            "Superseded by the semantic XSS module (per-field, HTML-aware); kept disabled.",
            Body,
            r"(?i)(<script[\s/>]|</script>|javascript:|vbscript:|\bon(error|load|click|mouseover|focus|toggle|animationstart)\s*=|<svg[\s/>]|<iframe[\s>]|document\.cookie|\balert\s*\(|String\.fromCharCode)",
            Deny,
            46,
            false,
        ),
        mk(
            "waf-default-body-rce",
            "Block command injection (body)",
            "Superseded by the semantic command-injection module (per-field); kept disabled.",
            Body,
            r"(?i)([;|]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|python)\b|&&\s*(cat|ls|id|wget|curl|nc)\b|\$\([^)]*\)|`[^`]*`|/bin/(ba)?sh\b|\bnc\s+-e\b)",
            Deny,
            47,
            false,
        ),
        mk(
            "waf-default-body-php",
            "Block PHP injection (body)",
            "Dangerous PHP functions, superglobals and object-injection markers in the body. \
             Not covered by the semantic modules — kept enabled.",
            Body,
            r"(?i)(\b(system|exec|shell_exec|passthru|popen|proc_open|assert|eval|create_function|base64_decode|call_user_func)\s*\(|<\?php\b|\$_(get|post|request|cookie|server|files)\b|\bO:\d+:\x22)",
            Deny,
            48,
            true,
        ),
        mk(
            "waf-default-scanner-ua",
            "Block scanner / attack tools",
            "User-Agents of common vulnerability scanners and attack tools.",
            Header,
            r"User-Agent: (?i)\b(sqlmap|nikto|nmap|masscan|nessus|acunetix|netsparker|dirbuster|gobuster|feroxbuster|wpscan|hydra|fimap|joomscan|wfuzz|nuclei|zgrab|httrack)\b",
            Deny,
            20,
            true,
        ),
        mk(
            "waf-default-empty-ua",
            "Challenge empty User-Agent",
            "JS challenge for requests with a missing/blank User-Agent.",
            Header,
            r"User-Agent: ^\s*$",
            Challenge,
            30,
            true,
        ),
        mk(
            "waf-default-login-ratelimit",
            "Rate-limit auth endpoints",
            "Challenge clients exceeding 10 req/s to /login (credential stuffing).",
            RateLimit,
            "/login@10r/s",
            Challenge,
            35,
            true,
        ),
        mk(
            "waf-default-ratelimit",
            "Global rate limit",
            "Challenge clients exceeding 2000 requests/second across all paths.",
            RateLimit,
            "/@2000r/s",
            Challenge,
            40,
            true,
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
        auto_ban_enabled: false,
        auto_ban_threshold: 20,
        auto_ban_duration_secs: 5 * 3600,
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

    /// Every shipped rule's regex must compile — an invalid pattern would
    /// silently never match (a security hole), so fail the build instead.
    #[test]
    fn default_rule_patterns_compile() {
        for r in default_waf_rules() {
            match r.match_type {
                WafMatchType::Path | WafMatchType::Method | WafMatchType::Body => {
                    regex::Regex::new(&r.pattern)
                        .unwrap_or_else(|e| panic!("rule {} bad regex: {e}", r.id));
                }
                WafMatchType::Header => {
                    let (_name, pat) = r.pattern.split_once(':').unwrap_or_else(|| {
                        panic!("rule {} header pattern needs 'Name: regex'", r.id)
                    });
                    regex::Regex::new(pat.trim())
                        .unwrap_or_else(|e| panic!("rule {} bad header regex: {e}", r.id));
                }
                WafMatchType::RateLimit => {
                    let (_prefix, spec) = r.pattern.split_once('@').unwrap_or_else(|| {
                        panic!("rule {} rate pattern needs 'prefix@Nr/s'", r.id)
                    });
                    let n: u32 = spec.trim().trim_end_matches("r/s").trim().parse().unwrap();
                    assert!(n > 0, "rule {} rate limit must be > 0", r.id);
                }
                WafMatchType::Ip | WafMatchType::Geo => {}
            }
        }
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

    #[test]
    fn seed_rules_include_crs_with_unique_ids() {
        let rules = seed_waf_rules();
        // CRS is part of the default seed. Precise rules ship enabled; broad
        // keyword rules superseded by the semantic engine ship disabled.
        assert!(rules.iter().any(|r| r.id.starts_with("crs-") && r.enabled));
        for id in DEMOTED_RULE_IDS {
            if let Some(r) = rules.iter().find(|r| &r.id == id) {
                assert!(!r.enabled, "superseded rule {id} must ship disabled");
            }
        }
        // The id-based merge in AppState::new relies on globally-unique ids.
        let ids: std::collections::HashSet<_> = rules.iter().map(|r| &r.id).collect();
        assert_eq!(
            ids.len(),
            rules.len(),
            "baseline + CRS rule ids must not collide"
        );
    }

    #[test]
    fn migration_demotes_superseded_rules_but_keeps_custom() {
        let mut store = empty_store();
        store.schema_version = 0;
        // A superseded rule with the shipped pattern (operator untouched).
        // It currently ships disabled, so flip one on to simulate an old store.
        let shipped: std::collections::HashMap<_, _> = seed_waf_rules()
            .into_iter()
            .map(|r| (r.id, r.pattern))
            .collect();
        for r in &mut store.waf_rules {
            if r.id == "waf-default-sqli" {
                r.enabled = true; // pre-semantic install had it on
            }
            if r.id == "crs-942-sqli-keywords" {
                r.enabled = true;
                r.pattern = "custom-operator-pattern".into(); // customized (legacy signal)
            }
            if r.id == "crs-942-sqli-functions" {
                // Shipped pattern unchanged, but flagged as operator-edited: the
                // provenance flag must preserve it even though pattern == shipped.
                r.enabled = true;
                r.user_modified = true;
            }
        }
        assert!(migrate_schema(&mut store));
        let sqli = store
            .waf_rules
            .iter()
            .find(|r| r.id == "waf-default-sqli")
            .unwrap();
        assert!(
            !sqli.enabled,
            "untouched superseded rule should be disabled"
        );
        let custom = store
            .waf_rules
            .iter()
            .find(|r| r.id == "crs-942-sqli-keywords")
            .unwrap();
        assert!(
            custom.enabled,
            "operator-customized (pattern) rule must be preserved"
        );
        let flagged = store
            .waf_rules
            .iter()
            .find(|r| r.id == "crs-942-sqli-functions")
            .unwrap();
        assert!(
            flagged.enabled,
            "user_modified rule must be preserved despite shipped pattern"
        );
        assert_eq!(store.schema_version, CURRENT_SCHEMA_VERSION);
        // Idempotent: a second run does nothing.
        assert!(!migrate_schema(&mut store));
        let _ = shipped;
    }
}
