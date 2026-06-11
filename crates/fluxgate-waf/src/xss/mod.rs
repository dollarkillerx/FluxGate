//! XSS detection — flags **constructs**, not keywords.
//!
//! The old rule matches `on\w+=` and `<svg` anywhere, so a forum post mentioning
//! `onload` or showing `<b>` markup trips it. Here we parse HTML structure: an
//! event-handler attribute only counts inside a tag (or a quoted-attribute
//! breakout), a dangerous tag must actually open a tag, and a `javascript:` URI
//! must sit in URL/attribute context — never bare prose.

pub mod libinjection;

use fluxgate_core::WafRisk;

/// Tags that are dangerous on their own when reflected into a page.
const HIGH_TAGS: &[&str] = &[
    "script", "iframe", "object", "embed", "base", "applet", "frameset", "frame", "isindex",
];

/// Tags that are only dangerous when they also carry an event handler or a
/// dangerous URI (e.g. `<svg onload=…>`, `<img src=x onerror=…>`).
const COND_TAGS: &[&str] = &[
    "svg", "math", "img", "video", "audio", "details", "input", "body", "form", "meta", "link",
    "style", "marquee", "template", "title", "select", "textarea", "button", "a",
];

/// `v` is the raw decoded value (for libinjection); `lower` is the caller's
/// shared lowercased view (for the structural scan).
pub fn detect(v: &str, lower: &str) -> Option<(WafRisk, String)> {
    let bytes = lower.as_bytes();

    if let Some(d) = scan_tags(bytes) {
        return Some(d);
    }
    if attr_breakout(bytes) {
        return Some((WafRisk::High, "event_handler".into()));
    }
    if let Some(scheme) = dangerous_scheme(bytes) {
        return Some((WafRisk::High, format!("scheme:{scheme}")));
    }
    // libinjection XSS — HTML5-tokenizer-driven, the gold-standard low-FP detector
    // (0 FP on the benign corpus). Catches constructs the structural scan above
    // misses: unknown tags carrying an event handler, `style:expression(…)`,
    // nested handler tags. A hit is high-confidence.
    if libinjection::is_xss(v) {
        return Some((WafRisk::High, "libinjection-xss".into()));
    }
    None
}

/// Walk `<tag …>` openings.
fn scan_tags(b: &[u8]) -> Option<(WafRisk, String)> {
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < b.len() && b[j] == b'/' {
            j += 1;
        }
        let name_start = j;
        while j < b.len() && b[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if j == name_start {
            i += 1;
            continue;
        }
        let name = std::str::from_utf8(&b[name_start..j]).unwrap_or("");
        // The tag body up to '>' (or end), capped.
        let body_end = b[j..]
            .iter()
            .position(|&c| c == b'>')
            .map(|p| j + p)
            .unwrap_or(b.len().min(j + 256));
        let body = &b[j..body_end];

        if HIGH_TAGS.contains(&name) {
            return Some((WafRisk::High, format!("tag:{name}")));
        }
        if COND_TAGS.contains(&name) && (has_event_handler(body) || scheme_in(body).is_some()) {
            return Some((WafRisk::High, format!("tag:{name}+attr")));
        }
        i = j;
    }
    None
}

/// A quoted-attribute breakout: a quote followed (within a short window) by a
/// whitespace and an `on<handler>=` — i.e. the value escapes an existing
/// attribute and adds its own event handler.
fn attr_breakout(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' || b[i] == b'\'' || b[i] == b'`' {
            let end = (i + 64).min(b.len());
            if has_event_handler(&b[i + 1..end]) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Find an `on<letters>=` handler where `on` sits at a token boundary
/// (whitespace, `/`, or quote before it) — i.e. an attribute, not the middle of
/// a word like "button" or "iron".
fn has_event_handler(b: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 < b.len() {
        if (b[i] == b'o' || b[i] == b'O') && (b[i + 1] == b'n' || b[i + 1] == b'N') {
            let boundary = i == 0
                || matches!(
                    b[i - 1],
                    b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'"' | b'\'' | b'`' | b';'
                );
            if boundary {
                let mut j = i + 2;
                let letters_start = j;
                while j < b.len() && b[j].is_ascii_alphabetic() {
                    j += 1;
                }
                if j > letters_start {
                    // optional whitespace then '='
                    let mut k = j;
                    while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
                        k += 1;
                    }
                    if k < b.len() && b[k] == b'=' {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

const SCHEMES: &[&str] = &["javascript:", "vbscript:", "data:text/html"];

fn dangerous_scheme(b: &[u8]) -> Option<&'static str> {
    scheme_in(b)
}

/// A dangerous URI scheme in URL/attribute context (preceded by a quote, `=`,
/// `(`, `` ` ``, or at the start followed by non-space). Plain prose mentioning
/// "javascript:" with a following space is ignored.
fn scheme_in(b: &[u8]) -> Option<&'static str> {
    let s = std::str::from_utf8(b).ok()?;
    for scheme in SCHEMES {
        let mut from = 0;
        while let Some(rel) = s[from..].find(scheme) {
            let pos = from + rel;
            let after = pos + scheme.len();
            // Attribute/URL context: at the start, or right after a quote / `=` /
            // `(` / backtick. A whitespace-preceded mention ("learn javascript:")
            // is prose and ignored.
            let attr_ctx = pos == 0 || matches!(b[pos - 1], b'"' | b'\'' | b'`' | b'=' | b'(');
            let followed_by_code = b
                .get(after)
                .map(|&c| !c.is_ascii_whitespace())
                .unwrap_or(false);
            if attr_ctx && followed_by_code {
                return Some(scheme);
            }
            from = pos + scheme.len();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test shim: the real `detect` now takes a pre-lowered view from the caller.
    fn detect(v: &str) -> Option<(WafRisk, String)> {
        super::detect(v, &v.to_ascii_lowercase())
    }

    #[test]
    fn dangerous_tags() {
        assert_eq!(
            detect("<script>alert(1)</script>").unwrap().0,
            WafRisk::High
        );
        assert_eq!(detect("\"><iframe src=x>").unwrap().0, WafRisk::High);
        assert_eq!(detect("<svg onload=alert(1)>").unwrap().0, WafRisk::High);
        assert_eq!(
            detect("<img src=x onerror=alert(1)>").unwrap().0,
            WafRisk::High
        );
    }

    #[test]
    fn attribute_breakout() {
        assert_eq!(
            detect("\" onmouseover=alert(1) x=\"").unwrap().0,
            WafRisk::High
        );
    }

    #[test]
    fn dangerous_schemes() {
        assert_eq!(
            detect("<a href='javascript:alert(1)'>").unwrap().0,
            WafRisk::High
        );
        assert_eq!(
            detect("javascript:alert(document.cookie)").unwrap().0,
            WafRisk::High
        );
    }

    #[test]
    fn benign_markup_and_prose() {
        assert!(detect("<b>bold</b> and <code>x</code>").is_none());
        assert!(detect("I love javascript: it is fun").is_none());
        assert!(detect("the onload event fires when ready").is_none());
        assert!(detect("a < b and c > d").is_none());
        assert!(detect("<p>paragraph</p>").is_none());
        assert!(detect("click here for more info").is_none());
    }
}
