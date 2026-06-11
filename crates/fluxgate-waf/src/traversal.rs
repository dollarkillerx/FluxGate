//! Path-traversal / local-file-inclusion detection — **structural**, not regex.
//!
//! The old `\.\./` regex fires on any value containing `../`, including benign
//! ones like a version string `file..v2` or a `.bak` filename. Instead we
//! simulate resolving the path against a virtual root: traversal is only flagged
//! when `..` segments actually escape above the root (stack underflow), or when
//! the resolved path lands on a known sensitive target. A `../` that stays inside
//! the tree is at most informational.

use fluxgate_core::{WafLocation, WafRisk};

/// Sensitive absolute targets that indicate LFI even without an escape (e.g. an
/// absolute path stuffed into a `file=` parameter).
const SENSITIVE: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/group",
    "/proc/self/",
    "/windows/system32",
    "/windows/win.ini",
    "win.ini",
    "boot.ini",
    ".ssh/id_rsa",
    ".ssh/authorized_keys",
    "id_rsa",
];

/// File/stream wrapper schemes used for LFI/RFI.
const WRAPPERS: &[&str] = &["php://", "phar://", "expect://", "zip://", "glob://"];

/// `lower` is the caller's shared lowercased view of the value.
pub fn detect(lower: &str, location: WafLocation) -> Option<(WafRisk, String)> {
    // Fold backslashes so Windows-style traversal resolves the same way (only
    // allocates when a backslash is present; the lowercase was done once upstream).
    let folded: std::borrow::Cow<str> = if lower.contains('\\') {
        std::borrow::Cow::Owned(lower.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(lower)
    };

    // Wrapper schemes are unambiguously LFI/RFI.
    for w in WRAPPERS {
        if folded.contains(w) {
            return Some((WafRisk::High, format!("wrapper:{w}")));
        }
    }

    // Absolute sensitive targets (no escape required).
    for s in SENSITIVE {
        if folded.contains(s) {
            return Some((WafRisk::High, format!("sensitive:{s}")));
        }
    }

    // Structural traversal: does any `..` escape the root?
    if folded.contains("..") {
        match resolve(&folded) {
            Resolve::Escape => {
                let risk = if matches!(location, WafLocation::Path) {
                    WafRisk::High
                } else {
                    WafRisk::Medium
                };
                return Some((risk, "traversal_escape".into()));
            }
            Resolve::ContainedDotDot => {
                // `..` present but resolves inside the tree — weak signal only.
                return Some((WafRisk::Low, "dotdot_contained".into()));
            }
            Resolve::None => {}
        }
    }

    None
}

enum Resolve {
    /// A `..` popped above the virtual root.
    Escape,
    /// `..` segments present but all stayed within the tree.
    ContainedDotDot,
    /// No meaningful `..` traversal.
    None,
}

fn resolve(path: &str) -> Resolve {
    let mut depth: i32 = 0;
    let mut saw_dotdot = false;
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                saw_dotdot = true;
                depth -= 1;
                if depth < 0 {
                    return Resolve::Escape;
                }
            }
            _ => depth += 1,
        }
    }
    if saw_dotdot {
        Resolve::ContainedDotDot
    } else {
        Resolve::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test shim: the real `detect` now takes a pre-lowered view from the caller.
    fn detect(v: &str, loc: WafLocation) -> Option<(WafRisk, String)> {
        super::detect(&v.to_ascii_lowercase(), loc)
    }

    #[test]
    fn escapes_flagged_high_on_path() {
        assert_eq!(
            detect("/x/../../etc/foo", WafLocation::Path).unwrap().0,
            WafRisk::High
        );
        assert_eq!(
            detect("..%2f".replace("%2f", "/").as_str(), WafLocation::Query)
                .unwrap()
                .0,
            WafRisk::Medium
        );
    }

    #[test]
    fn sensitive_target_without_escape() {
        let (r, d) = detect("/var/www/../../etc/passwd", WafLocation::Query).unwrap();
        assert_eq!(r, WafRisk::High);
        assert!(d.starts_with("sensitive:"));
    }

    #[test]
    fn contained_dotdot_is_low() {
        // Stays within the tree → not a real escape.
        assert_eq!(
            detect("a/b/../c", WafLocation::Query).unwrap().0,
            WafRisk::Low
        );
    }

    #[test]
    fn benign_filenames_not_flagged() {
        assert!(detect("report-2024.bak", WafLocation::Query).is_none());
        assert!(detect("file..v2.txt", WafLocation::Query).is_none()); // ".." but no '/'
    }

    #[test]
    fn windows_traversal() {
        assert_eq!(
            detect("..\\..\\windows\\win.ini", WafLocation::Query)
                .unwrap()
                .0,
            WafRisk::High
        );
    }
}
