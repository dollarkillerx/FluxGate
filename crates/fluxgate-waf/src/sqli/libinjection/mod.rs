//! A faithful pure-Rust port of [libinjection]'s SQLi fingerprint engine.
//!
//! This module is a mechanical translation of libinjection's
//! `src/libinjection_sqli.c` and `src/libinjection_sqli_data.h`. It reproduces
//! the three-stage pipeline — tokenize, fold, fingerprint — and the
//! blacklist / not-whitelist heuristics, validated against libinjection's own
//! test vectors (see `tests/libinjection_oracle.rs`).
//!
//! The data (`data/fingerprints.txt` and the generated [`keywords`] table) and
//! the algorithm here are derived from libinjection (BSD-3-Clause); see
//! `data/ATTRIBUTION.md`.
//!
//! ## Public API
//!
//! ```ignore
//! use crate::sqli::libinjection;
//! if let Some(fp) = libinjection::is_sqli("1' OR '1'='1") {
//!     // `fp` is the matched fingerprint, e.g. "s&sos" / "1&1" / ...
//! }
//! ```
//!
//! This module is intentionally **not** wired into any detector or enforcement
//! path; it stands alone and is exercised only by its own tests.
//!
//! [libinjection]: https://github.com/libinjection/libinjection
//!
//! The manual case-insensitive byte comparisons here (`val4_is_into`,
//! `cstrcasecmp`) are literal ports of libinjection's `cstrcasecmp` and are
//! allowed rather than rewritten, to preserve the exact comparison semantics.
#![allow(clippy::manual_ignore_case_cmp)]

mod fold;
mod keywords;
mod tokenizer;

use std::collections::HashSet;
use std::sync::OnceLock;

pub(crate) use tokenizer::{State, Token, MAX_TOKENS, TOKEN_SIZE};

// Token type bytes (mirrors the `sqli_token_types` enum in libinjection).
pub(crate) const TYPE_NONE: u8 = 0;
pub(crate) const TYPE_KEYWORD: u8 = b'k';
pub(crate) const TYPE_UNION: u8 = b'U';
pub(crate) const TYPE_GROUP: u8 = b'B';
pub(crate) const TYPE_EXPRESSION: u8 = b'E';
pub(crate) const TYPE_SQLTYPE: u8 = b't';
pub(crate) const TYPE_FUNCTION: u8 = b'f';
pub(crate) const TYPE_BAREWORD: u8 = b'n';
pub(crate) const TYPE_NUMBER: u8 = b'1';
pub(crate) const TYPE_VARIABLE: u8 = b'v';
pub(crate) const TYPE_STRING: u8 = b's';
pub(crate) const TYPE_OPERATOR: u8 = b'o';
pub(crate) const TYPE_LOGIC_OPERATOR: u8 = b'&';
pub(crate) const TYPE_COMMENT: u8 = b'c';
pub(crate) const TYPE_COLLATE: u8 = b'A';
pub(crate) const TYPE_LEFTPARENS: u8 = b'(';
pub(crate) const TYPE_RIGHTPARENS: u8 = b')';
pub(crate) const TYPE_LEFTBRACE: u8 = b'{';
pub(crate) const TYPE_RIGHTBRACE: u8 = b'}';
pub(crate) const TYPE_DOT: u8 = b'.';
pub(crate) const TYPE_COMMA: u8 = b',';
pub(crate) const TYPE_COLON: u8 = b':';
pub(crate) const TYPE_SEMICOLON: u8 = b';';
pub(crate) const TYPE_TSQL: u8 = b'T';
pub(crate) const TYPE_UNKNOWN: u8 = b'?';
pub(crate) const TYPE_EVIL: u8 = b'X';
pub(crate) const TYPE_BACKSLASH: u8 = b'\\';

pub(crate) const CHAR_NULL: u8 = b'\0';
pub(crate) const CHAR_SINGLE: u8 = b'\'';
pub(crate) const CHAR_DOUBLE: u8 = b'"';
pub(crate) const CHAR_TICK: u8 = b'`';

// Parse-state flags (mirror the C `FLAG_*` bitfield).
pub(crate) const FLAG_QUOTE_NONE: u32 = 1 << 1;
pub(crate) const FLAG_QUOTE_SINGLE: u32 = 1 << 2;
pub(crate) const FLAG_QUOTE_DOUBLE: u32 = 1 << 3;
pub(crate) const FLAG_SQL_ANSI: u32 = 1 << 4;
pub(crate) const FLAG_SQL_MYSQL: u32 = 1 << 5;

/// Fingerprint set, loaded once from the vendored list.
///
/// libinjection's `libinjection_sqli_blacklist` builds the candidate
/// `"0" + uppercase(fingerprint)` and looks it up expecting type `'F'`. The
/// vendored `fingerprints.txt` upper-cased is exactly that set of `'F'`
/// entries (sans the leading `0`), so we store the upper-cased fingerprints
/// and probe membership with the upper-cased fingerprint string.
fn fingerprints() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        include_str!("../../../data/fingerprints.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            // The vendored list is mixed-case (the "v0" form); the lookup is
            // case-insensitive (upper-cased), so we normalise here. All
            // fingerprint characters are ASCII.
            .map(|l| -> &'static str {
                // Leak a tiny number (<=8367) of short upper-cased strings,
                // once, for a 'static set. This is a one-time init cost.
                Box::leak(l.to_ascii_uppercase().into_boxed_str())
            })
            .collect()
    })
}

/// `true` if the (upper-cased) fingerprint is a known SQLi fingerprint.
///
/// Port of `libinjection_sqli_blacklist`.
fn blacklist(state: &State) -> bool {
    let fp = state.fingerprint();
    if fp.is_empty() {
        return false;
    }
    let upper = fp.to_ascii_uppercase();
    fingerprints().contains(upper.as_str())
}

/// Port of `libinjection_sqli_not_whitelist`: returns `true` if SQLi (i.e. the
/// fingerprint is *not* whitelisted away as a false positive).
fn not_whitelist(state: &State) -> bool {
    let fp = state.fingerprint();
    let tlen = fp.len();
    let fpb = fp.as_bytes();

    if tlen > 1 && fpb[tlen - 1] == TYPE_COMMENT {
        // ending comment containing 'sp_password' => SQLi
        if memmem(&state.input, b"sp_password") {
            return true;
        }
    }

    match tlen {
        2 => {
            if fpb[1] == TYPE_UNION {
                return state.stats_tokens != 2;
            }
            // if 'comment' is '#' ignore.. too many FP
            if state.tokenvec[1].val_first() == b'#' {
                return false;
            }
            // 'nc': only /x comments are SQLi
            if state.tokenvec[0].type_ == TYPE_BAREWORD
                && state.tokenvec[1].type_ == TYPE_COMMENT
                && state.tokenvec[1].val_first() != b'/'
            {
                return false;
            }
            // '1c' ending with '/x' is SQLi
            if state.tokenvec[0].type_ == TYPE_NUMBER
                && state.tokenvec[1].type_ == TYPE_COMMENT
                && state.tokenvec[1].val_first() == b'/'
            {
                return true;
            }
            if state.tokenvec[0].type_ == TYPE_NUMBER && state.tokenvec[1].type_ == TYPE_COMMENT {
                if state.stats_tokens > 2 {
                    return true;
                }
                // char after the number
                let idx = state.tokenvec[0].len;
                let ch = *state.input.get(idx).unwrap_or(&0);
                // C compares a *signed* char: a high byte (>=0x80) is negative, so
                // `ch <= 32` holds for it too. Out-of-range reads 0 (also <=32).
                if ch <= 32 || ch >= 128 {
                    return true;
                }
                if ch == b'/' && state.input.get(idx + 1) == Some(&b'*') {
                    return true;
                }
                if ch == b'-' && state.input.get(idx + 1) == Some(&b'-') {
                    return true;
                }
                return false;
            }
            // detect obvious SQLi scans: '--' style only if token len > 2
            if state.tokenvec[1].len > 2 && state.tokenvec[1].val_first() == b'-' {
                return false;
            }
        }
        3 => {
            if fp == "sos" || fp == "s&s" {
                if state.tokenvec[0].str_open == CHAR_NULL
                    && state.tokenvec[2].str_close == CHAR_NULL
                    && state.tokenvec[0].str_close == state.tokenvec[2].str_open
                {
                    return true;
                }
                // ...both these branches in C return FALSE.
                return false;
            } else if fp == "s&n" || fp == "n&1" || fp == "1&1" || fp == "1&v" || fp == "1&s" {
                if state.stats_tokens == 3 {
                    return false;
                }
            } else if state.tokenvec[1].type_ == TYPE_KEYWORD {
                // safe unless "INTO OUTFILE"/"INTO DUMPFILE": len>=5 and
                // value starts with "INTO"
                if state.tokenvec[1].len < 5 || !val4_is_into(&state.tokenvec[1]) {
                    return false;
                }
            }
        }
        4 | 5 => {}
        _ => {}
    }

    true
}

/// `cstrcasecmp("INTO", val, 4) == 0` — true when the first 4 bytes upper-case
/// to "INTO".
fn val4_is_into(tok: &Token) -> bool {
    let v = tok.value();
    v.len() >= 4
        && v[0].to_ascii_uppercase() == b'I'
        && v[1].to_ascii_uppercase() == b'N'
        && v[2].to_ascii_uppercase() == b'T'
        && v[3].to_ascii_uppercase() == b'O'
}

/// `true` if `needle` occurs in `haystack`. Port of `my_memmem` usage.
fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// `libinjection_sqli_check_fingerprint`.
fn check_fingerprint(state: &State) -> bool {
    blacklist(state) && not_whitelist(state)
}

/// Look up a word/operator in the keyword table. Port of `bsearch_keyword_type`
/// over `sql_keywords` (keyword subset). Returns the type byte, or
/// [`CHAR_NULL`] if not found. Case-insensitive on `key`.
pub(crate) fn lookup_word(key: &[u8]) -> u8 {
    let table = keywords::SQL_KEYWORDS;
    // C does a hand-rolled binary search with cstrcasecmp(table_word, key).
    // table words are stored upper-case; compare case-insensitively up to
    // `key.len()`, matching libinjection's prefix-style comparison semantics.
    let mut left = 0usize;
    let mut right = table.len() - 1;
    while left < right {
        let pos = (left + right) >> 1;
        if cstrcasecmp(table[pos].0.as_bytes(), key) < 0 {
            left = pos + 1;
        } else {
            right = pos;
        }
    }
    if left == right && cstrcasecmp(table[left].0.as_bytes(), key) == 0 {
        table[left].1
    } else {
        CHAR_NULL
    }
}

/// Port of libinjection's `cstrcasecmp(a, b, n)` where `a` is an upper-cased
/// C-string (the table word, NUL-terminated) and `b` is an arbitrary byte
/// buffer of length `n`. Returns negative / zero / positive.
fn cstrcasecmp(a: &[u8], b: &[u8]) -> i32 {
    let n = b.len();
    let mut ai = 0usize;
    let mut bi = 0usize;
    let mut rem = n;
    while rem > 0 {
        let av = *a.get(ai).unwrap_or(&0);
        let mut cb = *b.get(bi).unwrap_or(&0);
        if cb.is_ascii_lowercase() {
            cb -= 0x20;
        }
        if av != cb {
            return av as i32 - cb as i32;
        } else if av == 0 {
            return -1;
        }
        ai += 1;
        bi += 1;
        rem -= 1;
    }
    if *a.get(ai).unwrap_or(&0) == 0 {
        0
    } else {
        1
    }
}

/// Compute the fingerprint string for `state` under `flags`.
///
/// Port of `libinjection_sqli_fingerprint`: reset, fold, apply the magic
/// PHP-backquote-comment rule and the `X` (TYPE_EVIL) clear-out, then store the
/// fingerprint on the state.
fn fingerprint(state: &mut State, flags: u32) {
    state.reset(flags);
    let mut tlen = fold::fold(state);

    // magic PHP backquote comment
    if tlen > 2
        && state.tokenvec[tlen - 1].type_ == TYPE_BAREWORD
        && state.tokenvec[tlen - 1].str_open == CHAR_TICK
        && state.tokenvec[tlen - 1].len == 0
        && state.tokenvec[tlen - 1].str_close == CHAR_NULL
    {
        state.tokenvec[tlen - 1].type_ = TYPE_COMMENT;
    }

    let mut fp = [0u8; MAX_TOKENS + 3];
    for (slot, tok) in fp.iter_mut().zip(state.tokenvec.iter()).take(tlen) {
        *slot = tok.type_;
    }
    fp[tlen] = CHAR_NULL;

    // 'X' (TYPE_EVIL) in pattern => clear everything to a single 'X'.
    if fp[..tlen].contains(&TYPE_EVIL) {
        fp = [0u8; MAX_TOKENS + 3];
        fp[0] = TYPE_EVIL;
        tlen = 1;
        state.tokenvec[0].type_ = TYPE_EVIL;
        state.tokenvec[0].val = [0u8; TOKEN_SIZE];
        state.tokenvec[0].val[0] = TYPE_EVIL;
        state.tokenvec[0].len = 1;
        if state.tokenvec.len() > 1 {
            state.tokenvec[1].type_ = CHAR_NULL;
        }
    }

    state.fingerprint_buf = fp;
    state.fingerprint_len = tlen;
}

/// `reparse_as_mysql`: re-run under MySQL flags if MySQL-only comment forms
/// were seen.
fn reparse_as_mysql(state: &State) -> bool {
    state.stats_comment_ddx > 0 || state.stats_comment_hash > 0
}

/// Core driver. Port of `libinjection_is_sqli`. On a match, leaves the matched
/// fingerprint in `state` and returns `true`.
fn is_sqli_state(state: &mut State) -> bool {
    if state.input.is_empty() {
        return false;
    }

    // as-is
    fingerprint(state, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    if check_fingerprint(state) {
        return true;
    } else if reparse_as_mysql(state) {
        fingerprint(state, FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
        if check_fingerprint(state) {
            return true;
        }
    }

    // single-quote context
    if state.input.contains(&CHAR_SINGLE) {
        fingerprint(state, FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI);
        if check_fingerprint(state) {
            return true;
        } else if reparse_as_mysql(state) {
            fingerprint(state, FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL);
            if check_fingerprint(state) {
                return true;
            }
        }
    }

    // double-quote context
    if state.input.contains(&CHAR_DOUBLE) {
        fingerprint(state, FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL);
        if check_fingerprint(state) {
            return true;
        }
    }

    false
}

/// Detect SQL injection in `input`.
///
/// Returns the matched libinjection fingerprint string (e.g. `"s&sos"`,
/// `"1UE"`, `"sos"`) when `input` is SQLi, otherwise `None`. This is a faithful
/// port of libinjection's `libinjection_is_sqli` / `libinjection_sqli` entry
/// points.
pub fn is_sqli(input: &str) -> Option<String> {
    let mut state = State::new(input.as_bytes());
    if is_sqli_state(&mut state) {
        Some(state.fingerprint().to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Oracle test-support helpers. These expose the intermediate tokenize/fold
// stages with the exact flags the libinjection Python test-driver uses, so the
// vendored `--EXPECTED--` vectors can be checked byte-for-byte from the
// `tests/libinjection_oracle.rs` integration test (which compiles against this
// crate as an external dependency and therefore cannot see `#[cfg(test)]`
// items). They are not used by any detector or enforcement path.
// ---------------------------------------------------------------------------

/// Tokenize `input` under the given flags and return the printed token lines in
/// the libinjection test-driver format (`print_token`).
///
/// Oracle test support only; not part of the detection API.
#[doc(hidden)]
pub fn debug_tokenize(input: &[u8], flags: u32) -> Vec<String> {
    let mut state = State::new(input);
    state.reset(flags);
    let mut out = Vec::new();
    while tokenizer::tokenize(&mut state) {
        let cur = state.current_token();
        out.push(print_token(&cur));
    }
    out
}

/// Fold `input` under the given flags and return the printed token lines.
///
/// Oracle test support only; not part of the detection API.
#[doc(hidden)]
pub fn debug_fold(input: &[u8], flags: u32) -> Vec<String> {
    let mut state = State::new(input);
    state.reset(flags);
    let n = fold::fold(&mut state);
    (0..n).map(|i| print_token(&state.tokenvec[i])).collect()
}

/// Byte-level variant of [`is_sqli`] (oracle test support).
#[doc(hidden)]
pub fn is_sqli_bytes(input: &[u8]) -> Option<String> {
    let mut state = State::new(input);
    if is_sqli_state(&mut state) {
        Some(state.fingerprint().to_string())
    } else {
        None
    }
}

/// `FLAG_QUOTE_NONE` (oracle test support).
#[doc(hidden)]
pub const fn flag_quote_none() -> u32 {
    FLAG_QUOTE_NONE
}
/// `FLAG_SQL_ANSI` (oracle test support).
#[doc(hidden)]
pub const fn flag_sql_ansi() -> u32 {
    FLAG_SQL_ANSI
}

/// Port of the Python test-driver's `print_token`.
fn print_token(tok: &Token) -> String {
    let mut out = String::new();
    out.push(tok.type_ as char);
    out.push(' ');
    if tok.type_ == TYPE_STRING {
        out.push_str(&print_token_string(tok));
    } else if tok.type_ == TYPE_VARIABLE {
        match tok.count {
            1 => out.push('@'),
            2 => out.push_str("@@"),
            _ => {}
        }
        out.push_str(&print_token_string(tok));
    } else {
        out.push_str(&String::from_utf8_lossy(tok.value()));
    }
    out.trim().to_string()
}

fn print_token_string(tok: &Token) -> String {
    let mut out = String::new();
    if tok.str_open != CHAR_NULL {
        out.push(tok.str_open as char);
    }
    out.push_str(&String::from_utf8_lossy(tok.value()));
    if tok.str_close != CHAR_NULL {
        out.push(tok.str_close as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_injections_match() {
        assert!(is_sqli("1' OR '1'='1").is_some());
        assert!(is_sqli("' OR 1=1 --").is_some());
        assert!(is_sqli("1 UNION SELECT username,password FROM users").is_some());
        assert!(is_sqli("'; DROP TABLE users--").is_some());
    }

    #[test]
    fn benign_not_matched() {
        assert_eq!(is_sqli("foo 'bar' \"zap\""), None);
        assert_eq!(is_sqli("hello world"), None);
    }
}
