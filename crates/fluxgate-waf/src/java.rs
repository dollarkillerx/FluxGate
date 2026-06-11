//! Java / JVM expression & reflection injection (OGNL, SpEL, Struts, runtime &
//! reflection gadgets). Replaces the broad `crs-944-java` regex. Distinctive JVM
//! markers are essentially never benign in a request value, so they flag High; an
//! OGNL `%{…}` expression is Medium. Input is the shared lowercased view.
//!
//! Overlaps intentionally with `ssti` (template gadgets) and `deser` (serialized
//! streams) — defense in depth; this module owns the JVM-injection surface.

use fluxgate_core::WafRisk;

/// High-signal JVM injection markers (OGNL/SpEL evaluation, runtime exec, dynamic
/// class loading & reflection, scripting engines).
const MARKERS: &[&str] = &[
    "ognl",
    ".classloader",
    "getclassloader",
    "nashorn",
    "javax.script",
    "scriptengine",
    "getruntime",
    "runtime.exec",
    "processbuilder",
    "getdeclaredmethod",
    "forname(",
    "java.lang.runtime",
];

pub fn detect(lower: &str) -> Option<(WafRisk, String)> {
    for m in MARKERS {
        if lower.contains(m) {
            return Some((WafRisk::High, format!("jvm:{m}")));
        }
    }
    // OGNL/Struts expression `%{ … }` — flagged when it carries expression syntax
    // (`@` static refs or a `(` call), so a stray `%{` in benign text doesn't trip.
    if lower.contains("%{") && (lower.contains('@') || lower.contains('(')) {
        return Some((WafRisk::Medium, "ognl_expr".into()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(v: &str) -> Option<WafRisk> {
        detect(&v.to_ascii_lowercase()).map(|(r, _)| r)
    }

    #[test]
    fn jvm_injection_flagged() {
        assert_eq!(
            risk("%{(#a=@java.lang.Runtime@getRuntime()).exec('id')}"),
            Some(WafRisk::High) // getruntime marker
        );
        assert_eq!(
            risk("Class.forName('java.lang.Runtime')"),
            Some(WafRisk::High)
        );
        assert_eq!(risk("org.apache.struts.ClassLoader"), Some(WafRisk::High));
        assert_eq!(risk("payload with nashorn engine"), Some(WafRisk::High));
        assert_eq!(risk("@ognl.OgnlContext"), Some(WafRisk::High));
        // OGNL expression with no known runtime gadget → medium.
        assert_eq!(risk("%{7*7+(2)}"), Some(WafRisk::Medium));
    }

    #[test]
    fn benign_not_flagged() {
        assert!(risk("the java programming language is popular").is_none());
        assert!(risk("a tutorial about classes and methods").is_none());
        assert!(risk("100% complete {done}").is_none()); // `%{` not present
        assert!(risk("progress: 50% {ok}").is_none());
    }
}
