//! XML External Entity (XXE). Flags a DOCTYPE/ENTITY declaration that pulls an
//! external resource — the structure of an XXE payload — not ordinary XML or an
//! HTML5 `<!doctype html>`. Input is the shared lowercased view (so entity-encoded
//! forms are already decoded upstream).

use fluxgate_core::WafRisk;

pub fn detect(lower: &str) -> Option<(WafRisk, String)> {
    if !lower.contains("<!") {
        return None;
    }
    let has_entity = lower.contains("<!entity");
    let has_doctype = lower.contains("<!doctype");

    // An entity that references an external (or parameter) resource → file read / SSRF.
    if has_entity && (lower.contains("system") || lower.contains("public")) {
        return Some((WafRisk::High, "external_entity".into()));
    }
    // A DOCTYPE that declares entities at all is already suspicious.
    if has_doctype && has_entity {
        return Some((WafRisk::High, "doctype_entity".into()));
    }
    // A DOCTYPE *with an internal subset* `[ … ]` is a weaker signal (the plain
    // `<!doctype html>` has no subset, so it isn't flagged).
    if has_doctype && lower.contains('[') {
        return Some((WafRisk::Medium, "doctype_subset".into()));
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
    fn xxe_flagged() {
        assert_eq!(
            risk(r#"<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>"#),
            Some(WafRisk::High)
        );
        assert_eq!(
            risk(r#"<!ENTITY xxe SYSTEM "http://evil/x">"#),
            Some(WafRisk::High)
        );
    }

    #[test]
    fn benign_xml_not_flagged() {
        assert!(risk(r#"<?xml version="1.0"?><root><a>1</a></root>"#).is_none());
        assert!(risk("<!doctype html>").is_none()); // HTML5 doctype
        assert!(risk("<!-- just a comment -->").is_none());
        assert!(risk(r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML//EN">"#).is_none());
    }
}
