//! # fluxgate-waf — semantic WAF detection engine
//!
//! A structure-aware detection pipeline that replaces broad keyword regexes with
//! **structure-aware** analysis, drastically cutting false positives:
//!
//! 1. **Parameter extraction** ([`extract`]) splits the request into
//!    `(location, name, value)` tuples — query params, form fields, JSON string
//!    values, cookies, selected headers — so detection runs per value instead of
//!    over one concatenated `path?query` blob (which matches across boundaries).
//! 2. **Multi-layer decoding** ([`decode`]) reverses percent / entity / unicode /
//!    base64 encodings before inspection.
//! 3. **Cheap prefilters** ([`prefilter`]) skip the semantic detectors for the
//!    ~99% of values that carry no interesting bytes.
//! 4. **Semantic detectors** (SQLi, XSS, traversal, command injection, SSRF,
//!    protocol) tokenize/parse the value and flag *constructs*, not keywords,
//!    each emitting a [`WafRisk`] level.
//!
//! The engine is **policy-free**: it returns every [`Detection`]; mapping risk →
//! action, applying exceptions, and honoring monitor mode is the caller's job
//! (see `fluxgate-admin`'s `waf_semantic` module). Configuration only tells the
//! engine which modules are enabled (so disabled detectors never run).

use std::borrow::Cow;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http::HeaderMap;

use fluxgate_core::{WafLocation, WafModule, WafRisk, WafSemanticConfig};

pub mod cmdi;
pub mod decode;
pub mod deser;
pub mod extract;
pub mod java;
pub mod nosql;
pub mod php;
pub mod prefilter;
pub mod proto;
pub mod sqli;
pub mod ssrf;
pub mod ssti;
pub mod traversal;
pub mod xss;
pub mod xxe;

/// Truncate snippets stored on a [`Detection`] so a pathological value can't
/// bloat the event log.
const SNIPPET_MAX: usize = 160;

/// A single semantic detection. The caller maps `(module, risk)` to an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub module: WafModule,
    pub risk: WafRisk,
    pub location: WafLocation,
    /// Parameter / field / header name (`""` for the bare path).
    pub param: String,
    /// Truncated copy of the offending (decoded) value.
    pub snippet: String,
    /// Detector-specific detail (e.g. a SQLi fingerprint or `tag:script`).
    pub detail: String,
}

/// Which modules are active — compiled from [`WafSemanticConfig`] so the hot path
/// never touches the config map.
#[derive(Clone, Copy, Default)]
struct Enabled {
    sqli: bool,
    xss: bool,
    traversal: bool,
    cmdi: bool,
    ssrf: bool,
    proto: bool,
    ssti: bool,
    nosql: bool,
    xxe: bool,
    deser: bool,
    php: bool,
    java: bool,
}

impl Enabled {
    fn from_cfg(cfg: &WafSemanticConfig) -> Self {
        Enabled {
            sqli: cfg.is_enabled(WafModule::Sqli),
            xss: cfg.is_enabled(WafModule::Xss),
            traversal: cfg.is_enabled(WafModule::Traversal),
            cmdi: cfg.is_enabled(WafModule::Cmdi),
            ssrf: cfg.is_enabled(WafModule::Ssrf),
            proto: cfg.is_enabled(WafModule::Proto),
            ssti: cfg.is_enabled(WafModule::Ssti),
            nosql: cfg.is_enabled(WafModule::Nosql),
            xxe: cfg.is_enabled(WafModule::Xxe),
            deser: cfg.is_enabled(WafModule::Deser),
            php: cfg.is_enabled(WafModule::Php),
            java: cfg.is_enabled(WafModule::Java),
        }
    }

    fn any(&self) -> bool {
        self.sqli
            || self.xss
            || self.traversal
            || self.cmdi
            || self.ssrf
            || self.proto
            || self.ssti
            || self.nosql
            || self.xxe
            || self.deser
            || self.php
            || self.java
    }
}

/// Immutable compiled snapshot, published behind an `ArcSwap` for wait-free reads
/// exactly like the regex engine's `CompiledRuleSet`.
#[derive(Default)]
struct Compiled {
    enabled: Enabled,
}

/// The semantic engine. Cheap to share; `analyze_*` read the published snapshot
/// wait-free (no lock) before doing any work.
pub struct SemanticEngine {
    compiled: ArcSwap<Compiled>,
}

impl Default for SemanticEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticEngine {
    pub fn new() -> Self {
        SemanticEngine {
            compiled: ArcSwap::from_pointee(Compiled::default()),
        }
    }

    /// Recompile the active-module set from `cfg`. Call after any config change.
    pub fn rebuild(&self, cfg: &WafSemanticConfig) {
        let enabled = Enabled::from_cfg(cfg);
        self.compiled.store(Arc::new(Compiled { enabled }));
    }

    /// Whether any enabled module inspects the request body — lets the data plane
    /// skip the body read entirely. Every detector can fire on a body value, so
    /// this is simply "any module enabled".
    pub fn wants_body(&self) -> bool {
        self.compiled.load().enabled.any()
    }

    /// Analyze the request line + headers (Stage A). `path_and_query` is the raw
    /// target; `headers` is lowercased name → value.
    pub fn analyze_request(&self, path_and_query: &str, headers: &HeaderMap) -> Vec<Detection> {
        let enabled = self.compiled.load().enabled;
        if !enabled.any() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let params = extract::extract_request(path_and_query, headers);
        run_detectors(&enabled, &params, &mut out);
        out
    }

    /// Analyze the request body prefix (Stage B). `content_type` selects the body
    /// parser; `body` is the decoded (already percent/`+` normalized upstream is
    /// *not* assumed) prefix bytes as a string.
    pub fn analyze_body(&self, content_type: Option<&str>, body: &str) -> Vec<Detection> {
        let enabled = self.compiled.load().enabled;
        if !enabled.any() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let params = extract::extract_body(content_type, body);
        run_detectors(&enabled, &params, &mut out);
        out
    }
}

/// Run the enabled detectors over every extracted parameter.
fn run_detectors(enabled: &Enabled, params: &[extract::Param<'_>], out: &mut Vec<Detection>) {
    for p in params {
        // Decode the raw value through the layered pipeline once; all detectors
        // share the decoded view + the "was double-encoded" risk bump.
        let decoded = decode::decode_value(&p.value, p.location);
        let v: &str = decoded.text.as_ref();
        if v.is_empty() {
            continue;
        }
        let flags = prefilter::scan(v);
        // One shared Aho-Corasick pass for the SQLi/deser multi-byte gate
        // substrings (only when one of those modules is on).
        let substr = if enabled.sqli || enabled.deser || enabled.php || enabled.java {
            prefilter::substr_scan(v)
        } else {
            0
        };

        // A single lowercased view, shared by every structural detector and
        // computed at most once per value (and never for a value that opens no
        // structural gate — e.g. all benign traffic). Borrows when `v` is already
        // ASCII-lowercase, so the common case allocates nothing.
        let mut lower_buf: Option<Cow<str>> = None;

        if enabled.proto && flags & prefilter::CTRL != 0 {
            if let Some((risk, detail)) = proto::detect(v, p.location) {
                push(out, p, WafModule::Proto, risk, detail, v);
            }
        }
        if enabled.sqli && prefilter::sqli_gate(flags, substr) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = sqli::detect(v, lower) {
                push(out, p, WafModule::Sqli, decoded.bump(risk), detail, v);
            }
        }
        if enabled.xss && prefilter::xss_gate(flags, v) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = xss::detect(v, lower) {
                push(out, p, WafModule::Xss, decoded.bump(risk), detail, v);
            }
        }
        if enabled.traversal && prefilter::traversal_gate(flags) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = traversal::detect(lower, p.location) {
                push(out, p, WafModule::Traversal, decoded.bump(risk), detail, v);
            }
        }
        if enabled.cmdi && prefilter::cmdi_gate(flags) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = cmdi::detect(lower) {
                push(out, p, WafModule::Cmdi, decoded.bump(risk), detail, v);
            }
        }
        if enabled.ssrf && prefilter::ssrf_gate(flags, v) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = ssrf::detect(&p.name, lower) {
                push(out, p, WafModule::Ssrf, risk, detail, v);
            }
        }
        if enabled.ssti && prefilter::ssti_gate(flags, v) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = ssti::detect(lower) {
                push(out, p, WafModule::Ssti, decoded.bump(risk), detail, v);
            }
        }
        if enabled.nosql && prefilter::nosql_gate(flags, v) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = nosql::detect(lower) {
                push(out, p, WafModule::Nosql, decoded.bump(risk), detail, v);
            }
        }
        if enabled.xxe && prefilter::xxe_gate(flags, v) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = xxe::detect(lower) {
                push(out, p, WafModule::Xxe, decoded.bump(risk), detail, v);
            }
        }
        if enabled.deser && prefilter::deser_gate(flags, substr, v) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = deser::detect(lower) {
                push(out, p, WafModule::Deser, decoded.bump(risk), detail, v);
            }
        }
        if enabled.php && prefilter::php_gate(substr) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = php::detect(lower) {
                push(out, p, WafModule::Php, decoded.bump(risk), detail, v);
            }
        }
        if enabled.java && prefilter::java_gate(substr) {
            let lower: &str = lower_buf.get_or_insert_with(|| to_lower_cow(v));
            if let Some((risk, detail)) = java::detect(lower) {
                push(out, p, WafModule::Java, decoded.bump(risk), detail, v);
            }
        }
    }
}

/// Lowercase `v`, borrowing when it's already ASCII-lowercase (the common case)
/// so a value that passes a gate doesn't always pay a heap copy.
fn to_lower_cow(v: &str) -> Cow<'_, str> {
    if v.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(v.to_ascii_lowercase())
    } else {
        Cow::Borrowed(v)
    }
}

fn push(
    out: &mut Vec<Detection>,
    p: &extract::Param<'_>,
    module: WafModule,
    risk: WafRisk,
    detail: String,
    value: &str,
) {
    out.push(Detection {
        module,
        risk,
        location: p.location,
        param: p.name.clone().into_owned(),
        snippet: snippet(value),
        detail,
    });
}

fn snippet(v: &str) -> String {
    if v.len() <= SNIPPET_MAX {
        return v.to_string();
    }
    // Truncate on a char boundary at/under the limit.
    let mut end = SNIPPET_MAX;
    while end > 0 && !v.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &v[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_lower_cow_borrows_when_already_lowercase() {
        // The common case (value passes a gate but is already lowercase) must not
        // allocate a copy — the whole point of sharing one lowercase view.
        assert!(matches!(to_lower_cow("1' or '1'='1"), Cow::Borrowed(_)));
        assert!(matches!(to_lower_cow(""), Cow::Borrowed(_)));
        match to_lower_cow("SELECT") {
            Cow::Owned(s) => assert_eq!(s, "select"),
            Cow::Borrowed(_) => panic!("mixed-case must be owned+lowercased"),
        }
    }
}
