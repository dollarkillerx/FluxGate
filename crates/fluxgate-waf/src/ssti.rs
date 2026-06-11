//! Server-side template injection (SSTI). Flags template **expressions** that
//! carry injection structure — a known gadget, or arithmetic / a call inside a
//! template delimiter — not the bare `${user.name}` / `{{ count }}` interpolation
//! that fills ordinary templates. Input is the caller's shared lowercased view.

use fluxgate_core::WafRisk;

/// Gadget fragments that essentially never appear outside an SSTI payload.
const GADGETS: &[&str] = &[
    "__class__",
    "__globals__",
    "__import__",
    "__subclasses__",
    "__builtins__",
    "__mro__",
    ".popen(",
    "getruntime",
    "runtime.exec",
    "processbuilder",
    "freemarker",
    "javax.script",
    "scriptengine",
    "t(java.lang",
    "@java.lang",
    "request.application",
];

/// Template delimiters we recognize: `(open, close)`.
const DELIMS: &[(&str, &str)] = &[
    ("{{", "}}"),
    ("${", "}"),
    ("#{", "}"),
    ("<%", "%>"),
    ("*{", "}"),
];

pub fn detect(lower: &str) -> Option<(WafRisk, String)> {
    // High: a known gadget anywhere — these only appear in real SSTI payloads.
    for g in GADGETS {
        if lower.contains(g) {
            return Some((WafRisk::High, format!("gadget:{g}")));
        }
    }
    // Medium: a template delimiter whose body is an *expression* (a call, or
    // arithmetic between two numbers) rather than a bare identifier/path.
    for (open, close) in DELIMS {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(open) {
            let start = from + rel + open.len();
            let end = lower[start..]
                .find(close)
                .map(|p| start + p)
                .unwrap_or(lower.len());
            if expr_like(&lower[start..end]) {
                return Some((WafRisk::Medium, "template_expr".into()));
            }
            // Advance past this delimiter (start > the matched `open`, so the
            // scan always makes progress and terminates).
            from = start.max(end);
            if from >= lower.len() {
                break;
            }
        }
    }
    None
}

/// Calls to these inside a template delimiter are RCE-grade regardless of shape.
const DANGER_CALLS: &[&str] = &[
    "system(", "exec(", "popen(", "eval(", "spawn(", "compile(", "getattr(",
];

/// Whether a template body looks like an *injected expression* rather than a
/// plain interpolation. Flags: arithmetic between two numbers (`7*7`); a call to
/// a known-dangerous function (`system(`…); or a call on a member/attribute chain
/// (`config.items()`) — the shape of object-traversal SSTI. A bare top-level call
/// to an unknown function (`t('x')`, `formatCurrency(total)`) is usually a benign
/// template helper, so it is **not** flagged (was a Medium false-positive source).
fn expr_like(body: &str) -> bool {
    let b = body.as_bytes();
    if has_arith(b) {
        return true;
    }
    for d in DANGER_CALLS {
        if body.contains(d) {
            return true;
        }
    }
    // A `(` that follows a `.` member access in the body (e.g. `obj.method(`).
    let mut seen_dot = false;
    for &c in b {
        match c {
            b'.' => seen_dot = true,
            b'(' if seen_dot => return true,
            _ => {}
        }
    }
    false
}

/// `<digit> <op> <digit>` (ignoring spaces), op in `* + - / %`.
fn has_arith(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let mut j = i + 1;
            while j < b.len() && b[j] == b' ' {
                j += 1;
            }
            if j < b.len() && matches!(b[j], b'*' | b'+' | b'-' | b'/' | b'%') {
                let mut k = j + 1;
                while k < b.len() && b[k] == b' ' {
                    k += 1;
                }
                if k < b.len() && b[k].is_ascii_digit() {
                    return true;
                }
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
    fn injections_flagged() {
        assert_eq!(risk("{{7*7}}"), Some(WafRisk::Medium));
        assert_eq!(risk("${9 * 9}"), Some(WafRisk::Medium));
        assert_eq!(
            risk("${T(java.lang.Runtime).getRuntime().exec('id')}"),
            Some(WafRisk::High)
        );
        assert_eq!(risk("{{config.__class__.__init__}}"), Some(WafRisk::High));
        assert_eq!(risk("<%= system('id') %>"), Some(WafRisk::Medium)); // danger call
        assert_eq!(risk("{{ config.items() }}"), Some(WafRisk::Medium)); // member-call traversal
        assert_eq!(risk("${''.getClass().forName('x')}"), Some(WafRisk::Medium));
    }

    #[test]
    fn benign_templates_not_flagged() {
        assert!(risk("${user.name}").is_none());
        assert!(risk("{{ count }} items remaining").is_none());
        assert!(risk("Hello {{ name }}, welcome").is_none());
        assert!(risk("price: ${total}").is_none());
        assert!(risk("plain text with no template").is_none());
        // A bare top-level helper call is a benign template, not SSTI (the tighter
        // `expr_like` no longer trips on a lone `(`).
        assert!(risk("{{ t('welcome.message') }}").is_none());
        assert!(risk("${formatCurrency(total)}").is_none());
        assert!(risk("{{ trans('home.title') }}").is_none());
    }
}
