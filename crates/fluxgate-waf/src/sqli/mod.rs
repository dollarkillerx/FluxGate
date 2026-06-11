//! SQL-injection detection. Tokenizes the value (see [`tokenizer`]) and looks for
//! *injection structures* — tautologies, UNION SELECT, stacked queries, comment
//! truncation, dangerous functions — rather than bare keywords. To catch
//! string-breakout payloads like `' OR '1'='1`, the checks are also re-run on a
//! **quote-neutralized** view of the value (quotes replaced by spaces); a hit
//! there means the payload escapes a string literal and is rated `High`.
//!
//! The key false-positive guard: a UNION/SELECT with no SQL punctuation —
//! e.g. the search phrase "union select tutorial for beginners" — is rated only
//! `Low` (logged, not blocked).

mod tokenizer;

/// Faithful pure-Rust port of libinjection's SQLi fingerprint engine. Standalone
/// (not wired into [`detect`]); see the module docs and `data/ATTRIBUTION.md`.
pub mod libinjection;

use fluxgate_core::WafRisk;
use tokenizer::{tokenize, Token};

/// Extremely high-signal substrings — essentially never benign in a parameter.
const DANGER: &[&str] = &[
    "information_schema",
    "xp_cmdshell",
    "into outfile",
    "into dumpfile",
    "load_file(",
    "pg_sleep(",
    "waitfor delay",
    "updatexml(",
    "extractvalue(",
    "sysdatabases",
    "@@version",
    "utl_inaddr",
    "dbms_pipe",
];

/// Statement keywords that, after `;`, make a stacked query.
const STATEMENTS: &[&str] = &[
    "select", "insert", "update", "delete", "drop", "alter", "create", "truncate", "exec",
    "execute", "union", "replace", "grant", "declare", "set", "call",
];

/// `v` is the raw decoded value (for libinjection); `lower` is the caller's
/// shared lowercased view (for the structural checks).
pub fn detect(v: &str, lower: &str) -> Option<(WafRisk, String)> {
    for d in DANGER {
        if lower.contains(d) {
            return Some((WafRisk::High, format!("danger:{d}")));
        }
    }

    let orig_quote = lower.contains('\'') || lower.contains('"');
    let mut best: Option<(WafRisk, String)> = None;

    // As-is context.
    let toks = tokenize(lower);
    run_checks(&toks, false, orig_quote, &mut best);

    // Quote-neutralized context (string breakout).
    if orig_quote {
        let neutral: String = lower
            .chars()
            .map(|c| if c == '\'' || c == '"' { ' ' } else { c })
            .collect();
        let toks2 = tokenize(&neutral);
        run_checks(&toks2, true, orig_quote, &mut best);
    }

    // libinjection fingerprint — the gold-standard low-FP detector (its own
    // tries the ANSI/MySQL/quote contexts). A match is high-confidence SQLi, so
    // it escalates to High; it raises recall on obfuscated payloads the local
    // structural checks rate lower, while never firing on the benign corpus.
    // It only ever escalates to High, so skip its (relatively expensive)
    // tokenize+fold pipeline when a local structural check already returned High.
    if !matches!(best, Some((WafRisk::High, _))) {
        if let Some(fp) = libinjection::is_sqli(v) {
            consider(&mut best, WafRisk::High, format!("libinjection:{fp}"));
        }
    }

    best
}

fn consider(best: &mut Option<(WafRisk, String)>, risk: WafRisk, detail: String) {
    match best {
        Some((r, _)) if *r >= risk => {}
        _ => *best = Some((risk, detail)),
    }
}

fn run_checks(
    toks: &[Token],
    quote_ctx: bool,
    orig_quote: bool,
    best: &mut Option<(WafRisk, String)>,
) {
    if toks.is_empty() {
        return;
    }
    let has = |class: u8| toks.iter().any(|t| t.class == class);
    let has_comment = has(b'c');
    let has_paren = has(b'(');
    let has_semi = has(b';');
    let has_number = has(b'1');
    let has_comma = has(b',');
    let has_func = has(b'f');
    let has_keyword = has(b'k') || has(b'U');
    let has_logic = toks
        .iter()
        .any(|t| matches!(t.text, "or" | "and" | "xor" | "||" | "&&"));
    let fp: String = toks.iter().take(16).map(|t| t.class as char).collect();

    // -- UNION SELECT --------------------------------------------------------
    if let Some(u) = toks.iter().position(|t| t.class == b'U') {
        if toks[u + 1..].iter().any(|t| t.text == "select") {
            let risk = if quote_ctx || has_comment || has_paren || has_semi || has_comma || has_func
            {
                // A real column list / subquery / stacked form.
                WafRisk::High
            } else if has_number {
                WafRisk::Medium
            } else {
                // bare "union select <words>" with no SQL punctuation — almost
                // always prose ("union select tutorial"); log only.
                WafRisk::Low
            };
            consider(best, risk, format!("union_select:{fp}"));
        }
    }

    // -- Boolean tautology: <logic> operand <cmp> operand -------------------
    // The logic word must be *adjacent* (right before the left operand), so an
    // unrelated "and" elsewhere in prose ("<b>x</b> and <code>a = b</code>")
    // never combines with a stray comparison into a false tautology.
    for i in 2..toks.len().saturating_sub(1) {
        if toks[i].class == b'o' && is_cmp(toks[i].text) {
            let logic_before = is_logic(toks[i - 2].text);
            let l = &toks[i - 1];
            let r = &toks[i + 1];
            // In a string-breakout (quote) context any operand pair is a strong
            // signal. Unquoted, require numeric operands (`1>0`) or two identical
            // barewords/strings (`a=a`); otherwise ordinary prose with a logic
            // word and a comparison ("a and c > d") would read as a tautology.
            let strong = if quote_ctx {
                is_operand(l.class) && is_operand(r.class)
            } else {
                (l.class == b'1' && r.class == b'1')
                    || (is_operand(l.class)
                        && l.class == r.class
                        && !l.text.is_empty()
                        && l.text == r.text)
            };
            if logic_before && strong {
                let risk = if quote_ctx {
                    WafRisk::High
                } else {
                    WafRisk::Medium
                };
                consider(best, risk, format!("tautology:{fp}"));
                break;
            }
        }
    }

    // -- Stacked query: ; <statement keyword> --------------------------------
    for i in 0..toks.len().saturating_sub(1) {
        if toks[i].class == b';' && STATEMENTS.contains(&toks[i + 1].text) {
            consider(best, WafRisk::High, format!("stacked:{fp}"));
            break;
        }
    }

    // -- Comment truncation --------------------------------------------------
    if has_comment {
        let sql_context = has_logic || has_keyword || has_func || has_cmp(toks) || quote_ctx;
        if sql_context {
            let risk = if quote_ctx || orig_quote {
                WafRisk::High
            } else {
                WafRisk::Medium
            };
            consider(best, risk, format!("comment:{fp}"));
        }
    }
}

fn is_operand(class: u8) -> bool {
    matches!(class, b's' | b'1' | b'n' | b'v')
}

fn is_logic(text: &str) -> bool {
    matches!(text, "or" | "and" | "xor" | "||" | "&&")
}

fn is_cmp(text: &str) -> bool {
    matches!(
        text,
        "=" | "==" | "<>" | "!=" | "<" | ">" | "<=" | ">=" | "like" | "rlike" | "regexp"
    )
}

fn has_cmp(toks: &[Token]) -> bool {
    toks.iter().any(|t| t.class == b'o' && is_cmp(t.text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(v: &str) -> Option<WafRisk> {
        detect(v, &v.to_ascii_lowercase()).map(|(r, _)| r)
    }

    #[test]
    fn classic_injections() {
        assert_eq!(risk("1' OR '1'='1"), Some(WafRisk::High));
        assert_eq!(risk("' OR 1=1 --"), Some(WafRisk::High));
        assert_eq!(risk("admin'--"), Some(WafRisk::High));
        assert_eq!(risk("1; DROP TABLE users"), Some(WafRisk::High));
        assert_eq!(
            risk("1 UNION SELECT username,password FROM users"),
            Some(WafRisk::High)
        );
        assert_eq!(risk("1' AND sleep(5)--"), Some(WafRisk::High));
        assert_eq!(risk("?id=1 OR 1=1"), Some(WafRisk::Medium));
        assert_eq!(risk("' UNION SELECT 1,2,3-- -"), Some(WafRisk::High));
    }

    #[test]
    fn danger_substrings() {
        assert_eq!(
            risk("0 UNION SELECT table_name FROM information_schema.tables"),
            Some(WafRisk::High)
        );
        assert_eq!(risk("'; exec xp_cmdshell('dir')--"), Some(WafRisk::High));
    }

    #[test]
    fn benign_text_not_blocked() {
        // The contract cases: must NOT be Medium+ (Low/None is fine).
        for s in [
            "union select tutorial for beginners",
            "O'Brien",
            "D'Angelo & Sons",
            "I want to learn SQL and databases",
            "select your favourite colour",
            "order by date please",
            "1 + 1 = 2",
            "rock and roll",
            "search for union members",
        ] {
            let r = risk(s);
            assert!(
                r.is_none() || r == Some(WafRisk::Low),
                "benign {s:?} should not be Medium+, got {r:?}"
            );
        }
    }
}
