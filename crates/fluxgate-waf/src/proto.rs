//! Protocol-anomaly detection: embedded null bytes (handler truncation) and
//! CRLF header injection / response splitting. These are cheap, unconditional
//! byte scans over the decoded value.

use fluxgate_core::{WafLocation, WafRisk};

pub fn detect(v: &str, location: WafLocation) -> Option<(WafRisk, String)> {
    let bytes = v.as_bytes();

    // Embedded NUL — almost always an attempt to truncate a downstream handler
    // (e.g. `shell.php%00.jpg`). Never legitimate in a text value.
    if bytes.contains(&0) {
        return Some((WafRisk::High, "null_byte".into()));
    }

    // CRLF (or bare LF) followed by something that looks like a response header —
    // classic header injection / response splitting.
    if has_crlf_header_injection(bytes) {
        return Some((WafRisk::High, "crlf_injection".into()));
    }

    // A cluster of C0 control characters in a path is anomalous (smuggling /
    // evasion). Plain text bodies legitimately contain newlines/tabs, so only
    // flag for the path itself.
    if matches!(location, WafLocation::Path) {
        let ctrl = bytes
            .iter()
            .filter(|&&b| b < 0x20 && b != b'\t' && b != b'\r' && b != b'\n')
            .count();
        if ctrl >= 4 {
            return Some((WafRisk::Medium, "control_chars".into()));
        }
    }

    None
}

/// Look for a line break immediately followed (after optional spaces) by a
/// `token:` shape — i.e. an attacker-injected header.
fn has_crlf_header_injection(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        // Find a line break.
        if b[i] == b'\n' || b[i] == b'\r' {
            let mut j = i + 1;
            if b[i] == b'\r' && j < b.len() && b[j] == b'\n' {
                j += 1;
            }
            // Skip leading spaces/tabs.
            while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
                j += 1;
            }
            // Expect at least one header-name char, then ':'.
            let name_start = j;
            while j < b.len() && is_header_name_char(b[j]) {
                j += 1;
            }
            if j > name_start && j < b.len() && b[j] == b':' {
                return true;
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    false
}

fn is_header_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_byte_flagged() {
        assert_eq!(
            detect("file\0.jpg", WafLocation::Query).unwrap().0,
            WafRisk::High
        );
    }

    #[test]
    fn crlf_header_injection_flagged() {
        let (r, d) = detect("x\r\nSet-Cookie: evil=1", WafLocation::Query).unwrap();
        assert_eq!(r, WafRisk::High);
        assert_eq!(d, "crlf_injection");
    }

    #[test]
    fn benign_newline_ignored() {
        // A multi-line comment value with no header-shape after the break.
        assert!(detect("line one\nline two please", WafLocation::BodyForm).is_none());
    }
}
