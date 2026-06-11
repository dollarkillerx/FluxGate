//! PHP code/function injection. Replaces the broad `crs-933-php` regex with a
//! per-value detector: a dangerous PHP function is flagged only in **call** form
//! (`name(`), so a benign mention ("how to use `shell_exec` in PHP") never trips —
//! only a real `shell_exec(...)` does (the FP win over the regex). These markers
//! also gate the detector via the shared prefilter AC, so the gate and the
//! detector match the same set. Input is the caller's shared lowercased view.

use fluxgate_core::WafRisk;

/// Dangerous PHP functions in **call** form (name immediately followed by `(`).
pub const CALL_MARKERS: &[&str] = &[
    "system(",
    "exec(",
    "shell_exec(",
    "passthru(",
    "popen(",
    "proc_open(",
    "pcntl_exec(",
    "assert(",
    "create_function(",
    "call_user_func(",
    "base64_decode(",
    "gzinflate(",
    "str_rot13(",
    "file_get_contents(",
    "fsockopen(",
    "phpinfo(",
];

/// PHP superglobals — a value carrying one is PHP-injection-shaped (medium).
pub const SUPERGLOBALS: &[&str] = &[
    "$_get",
    "$_post",
    "$_request",
    "$_cookie",
    "$_server",
    "$_files",
    "$_env",
    "$_session",
];

pub fn detect(lower: &str) -> Option<(WafRisk, String)> {
    // A raw PHP open tag in a value is unambiguous code injection.
    if lower.contains("<?php") {
        return Some((WafRisk::High, "php_open_tag".into()));
    }
    // `preg_replace(... /e ...)` — the `/e` modifier executes the replacement as
    // PHP code (classic RCE); a bare mention of preg_replace is not flagged.
    if lower.contains("preg_replace") && preg_replace_eval(lower) {
        return Some((WafRisk::High, "preg_replace_eval".into()));
    }
    // A dangerous function in call form.
    for m in CALL_MARKERS {
        if lower.contains(m) {
            return Some((WafRisk::High, format!("call:{m}")));
        }
    }
    // Superglobal reference — PHP-injection context, weaker on its own.
    for g in SUPERGLOBALS {
        if lower.contains(g) {
            return Some((WafRisk::Medium, format!("superglobal:{g}")));
        }
    }
    None
}

/// `preg_replace` with the `/e` (eval) pattern modifier — `'/…/e'`, `"~…~ie"`, etc.
fn preg_replace_eval(lower: &str) -> bool {
    let b = lower.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        // A regex delimiter `/` followed by modifier letters that include `e`,
        // ending at a quote / comma / `)` / whitespace.
        if b[i] == b'/' {
            let mut j = i + 1;
            let mut saw_e = false;
            while j < b.len() && b[j].is_ascii_alphabetic() {
                saw_e |= b[j] == b'e';
                j += 1;
            }
            if saw_e
                && j > i + 1
                && matches!(
                    b.get(j),
                    None | Some(b'\'') | Some(b'"') | Some(b',') | Some(b')') | Some(b' ')
                )
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(v: &str) -> Option<WafRisk> {
        detect(&v.to_ascii_lowercase()).map(|(r, _)| r)
    }

    #[test]
    fn php_injection_flagged() {
        assert_eq!(risk("system('id')"), Some(WafRisk::High));
        assert_eq!(risk("shell_exec('whoami')"), Some(WafRisk::High));
        assert_eq!(risk("<?php system($_GET['c']); ?>"), Some(WafRisk::High));
        assert_eq!(risk("passthru('ls')"), Some(WafRisk::High));
        assert_eq!(risk("call_user_func('system','id')"), Some(WafRisk::High));
        assert_eq!(risk("base64_decode('ZXZpbA==')"), Some(WafRisk::High));
        assert_eq!(
            risk("preg_replace('/.*/e', $_GET['c'], '')"),
            Some(WafRisk::High)
        );
        assert_eq!(risk("name=admin&id=$_REQUEST"), Some(WafRisk::Medium));
    }

    #[test]
    fn benign_not_flagged() {
        // A *mention* of a dangerous function (no call) must not trip.
        assert!(risk("how to use shell_exec in php safely").is_none());
        assert!(risk("the system administrator approved it").is_none());
        assert!(risk("a preg_replace tutorial for beginners").is_none());
        assert!(risk("subsystem health check").is_none());
        assert!(risk("$_ is a common placeholder name").is_none());
        assert!(risk("base64 encoding explained").is_none());
    }
}
