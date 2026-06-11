//! A faithful pure-Rust port of [libinjection]'s XSS engine and its HTML5
//! tokenizer.
//!
//! This module is a mechanical translation of libinjection's
//! `src/libinjection_xss.c` and `src/libinjection_html5.c`. It reproduces the
//! 5-context driver (`libinjection_xss`), the per-context detection logic
//! (`libinjection_is_xss`), the tag/attribute/URL blacklists, and the
//! comment/style/scheme heuristics, validated against libinjection's own
//! HTML5-tokenizer test vectors (see `tests/libinjection_html5_oracle.rs`) and a
//! Rust-vs-C differential test (`fluxgate-waf-difftest`).
//!
//! The data ([`blacklists`]) and the algorithm here are derived from
//! libinjection (BSD-3-Clause); see `data/ATTRIBUTION.md`.
//!
//! ## Public API
//!
//! ```ignore
//! use crate::xss::libinjection;
//! if libinjection::is_xss("<script>alert(1)</script>") {
//!     // XSS detected
//! }
//! ```
//!
//! This module is intentionally **not** wired into [`super::detect`] or any
//! enforcement path; it stands alone and is exercised only by its own tests.
//!
//! [libinjection]: https://github.com/libinjection/libinjection
//!
//! The manual case-insensitive byte comparisons here (`cstrcasecmp_with_null`,
//! `htmlencode_startswith`) are literal ports of libinjection's helpers and are
//! kept verbatim — including the deliberate C-style lints — to preserve the exact
//! comparison semantics.
#![allow(
    clippy::if_same_then_else,
    clippy::manual_is_ascii_check, // `cb >= 'a' && cb <= 'z'` mirrors the C upcasing
    clippy::manual_range_contains,
    clippy::needless_range_loop,
    clippy::nonminimal_bool
)]

pub mod blacklists;
pub mod html5;

use blacklists::{AttrType, BLACKATTR, BLACKATTREVENT, BLACKTAG};
use html5::{H5Flags, H5Type, H5};

/// `gsHexDecodeMap` — maps a byte to its hex value, or 256 if it's not a hex
/// digit (verbatim from libinjection_xss.c).
#[rustfmt::skip]
static GS_HEX_DECODE_MAP: [i32; 256] = [
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 256, 256, 256, 256, 256, 256,
    256, 10, 11, 12, 13, 14, 15, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 10, 11, 12, 13, 14, 15, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
];

/// `IS_HEX_ENTITY_PREFIX(src)` — `src[2]` is `x`/`X`.
#[inline]
fn is_hex_entity_prefix(src: &[u8]) -> bool {
    src.len() > 2 && (src[2] == b'x' || src[2] == b'X')
}

/// Port of `html_decode_char_at`. Decodes a numeric HTML entity at the start of
/// `src` (decimal `&#65;` or hex `&#x41;`); returns `(decoded, consumed)` where
/// `decoded` is the character code or `-1` on the empty/error case.
fn html_decode_char_at(src: &[u8]) -> (i32, usize) {
    let len = src.len();
    if len == 0 {
        return (-1, 0);
    }

    let mut consumed = 1usize;

    // starts with '&' and (len>=3, or hex-prefix and len>=4)?
    if src[0] != b'&' || len < 3 || (is_hex_entity_prefix(src) && len < 4) {
        return (src[0] as i32, consumed);
    }

    if src[1] != b'#' {
        // named entity — we don't handle these, treat as '&'
        return (b'&' as i32, consumed);
    }

    if is_hex_entity_prefix(src) {
        let mut ch = src[3] as usize;
        let mut chv = GS_HEX_DECODE_MAP[ch];
        if chv == 256 {
            // degenerate '&#[?]'
            return (b'&' as i32, consumed);
        }
        let mut val = chv;
        let mut i = 4usize;
        while i < len {
            ch = src[i] as usize;
            if ch == b';' as usize {
                consumed = i + 1;
                return (val, consumed);
            }
            chv = GS_HEX_DECODE_MAP[ch];
            if chv == 256 {
                consumed = i;
                return (val, consumed);
            }
            val = (val * 16) + chv;
            if val > 0x0010_00FF {
                return (b'&' as i32, consumed);
            }
            i += 1;
        }
        consumed = i;
        (val, consumed)
    } else {
        let mut i = 2usize;
        let mut ch = src[i];
        if ch < b'0' || ch > b'9' {
            return (b'&' as i32, consumed);
        }
        let mut val = (ch - b'0') as i32;
        i += 1;
        while i < len {
            ch = src[i];
            if ch == b';' {
                consumed = i + 1;
                return (val, consumed);
            }
            if ch < b'0' || ch > b'9' {
                consumed = i;
                return (val, consumed);
            }
            val = (val * 10) + (ch - b'0') as i32;
            if val > 0x0010_00FF {
                return (b'&' as i32, consumed);
            }
            i += 1;
        }
        consumed = i;
        (val, consumed)
    }
}

/// Port of `cstrcasecmp_with_null`. `a` is an all-uppercase ASCII C-string; `b`
/// is the (binary, possibly NUL-containing) candidate of length `n`. Returns
/// `true` on match (C returns 0 on match — here `true` means equal).
///
/// Embedded NULs in `b` are skipped; the comparison upcases lowercase bytes of
/// `b` and requires `a` to be exactly consumed.
fn cstrcasecmp_with_null(a: &[u8], b: &[u8], n: usize) -> bool {
    let mut ai = 0usize;
    let mut bi = 0usize;
    let mut remaining = n;
    while remaining > 0 {
        remaining -= 1;
        let cb = b[bi];
        bi += 1;
        if cb == 0 {
            continue;
        }
        // a is NUL-terminated; reading a[ai] where ai may reach a.len() means the
        // C string's terminator, i.e. mismatch (cb != '\0' here).
        let ca = if ai < a.len() { a[ai] } else { 0 };
        ai += 1;
        let cb = if (b'a'..=b'z').contains(&cb) {
            cb - 0x20
        } else {
            cb
        };
        if ca != cb {
            return false;
        }
    }
    // final: a[ai] must be the terminator
    let ca = if ai < a.len() { a[ai] } else { 0 };
    ca == 0
}

/// Port of `htmlencode_startswith`. Does the HTML-encoded binary string `b`
/// (length `n`) start with the all-uppercase prefix `a` (case-insensitive),
/// decoding numeric entities and ignoring embedded NULs / leading control chars?
fn htmlencode_startswith(a: &[u8], b: &[u8], n: usize) -> bool {
    let mut ai = 0usize;
    let mut b = b;
    let mut n = n;
    let mut first = true;
    while n > 0 {
        if ai >= a.len() || a[ai] == 0 {
            return true;
        }
        let (cb, consumed) = html_decode_char_at(&b[..n]);
        b = &b[consumed..];
        n -= consumed;

        if first && cb <= 32 {
            // ignore all leading whitespace and control characters
            continue;
        }
        first = false;

        if cb == 0 {
            // always ignore null characters
            continue;
        }

        if cb == 10 {
            // always ignore vertical-tab (sic) characters
            continue;
        }

        let cb = if (b'a' as i32..=b'z' as i32).contains(&cb) {
            cb - 0x20
        } else {
            cb
        };

        if a[ai] as i32 != cb {
            return false;
        }
        ai += 1;
    }

    ai >= a.len() || a[ai] == 0
}

/// Port of `is_black_tag`.
fn is_black_tag(s: &[u8]) -> bool {
    let len = s.len();
    if len < 3 {
        return false;
    }
    for &tag in BLACKTAG {
        if cstrcasecmp_with_null(tag.as_bytes(), s, len) {
            return true;
        }
    }
    // anything SVG related
    if (s[0] == b's' || s[0] == b'S')
        && (s[1] == b'v' || s[1] == b'V')
        && (s[2] == b'g' || s[2] == b'G')
    {
        return true;
    }
    // anything XSL(t) related
    if (s[0] == b'x' || s[0] == b'X')
        && (s[1] == b's' || s[1] == b'S')
        && (s[2] == b'l' || s[2] == b'L')
    {
        return true;
    }
    false
}

/// Port of `is_black_attr`.
fn is_black_attr(s: &[u8]) -> AttrType {
    let len = s.len();
    if len < 2 {
        return AttrType::None;
    }

    if len >= 5 {
        // JavaScript on.* event handlers
        if (s[0] == b'o' || s[0] == b'O') && (s[1] == b'n' || s[1] == b'N') {
            let s_without_on = &s[2..];
            let s_without_on_len = len - 2;
            for &(name, atype) in BLACKATTREVENT {
                let black_name_len = name.len();
                let max_len = s_without_on_len.min(black_name_len);
                if cstrcasecmp_with_null(name.as_bytes(), s_without_on, max_len) {
                    return atype;
                }
            }
        }

        // XMLNS / XLINK can create arbitrary tags
        if cstrcasecmp_with_null(b"XMLNS", s, 5) || cstrcasecmp_with_null(b"XLINK", s, 5) {
            return AttrType::Black;
        }
    }

    for &(name, atype) in BLACKATTR {
        if cstrcasecmp_with_null(name.as_bytes(), s, len) {
            return atype;
        }
    }

    AttrType::None
}

/// Port of `is_black_url`.
fn is_black_url(s: &[u8]) -> bool {
    static DATA_URL: &[u8] = b"DATA";
    static VIEWSOURCE_URL: &[u8] = b"VIEW-SOURCE";
    static VBSCRIPT_URL: &[u8] = b"VBSCRIPT";
    static JAVASCRIPT_URL: &[u8] = b"JAVA";

    let mut s = s;
    // skip whitespace and high-bit bytes (C: `*s <= 32 || *s >= 127` on signed
    // char, i.e. control/space and bytes >= 0x7F).
    while !s.is_empty() && (s[0] <= 32 || s[0] >= 127) {
        s = &s[1..];
    }
    let len = s.len();

    if htmlencode_startswith(DATA_URL, s, len) {
        return true;
    }
    if htmlencode_startswith(VIEWSOURCE_URL, s, len) {
        return true;
    }
    if htmlencode_startswith(JAVASCRIPT_URL, s, len) {
        return true;
    }
    if htmlencode_startswith(VBSCRIPT_URL, s, len) {
        return true;
    }
    false
}

/// `memchr`-equivalent on a `(start, len)` token window.
#[inline]
fn token_contains(s: &[u8], start: usize, len: usize, needle: u8) -> bool {
    memchr::memchr(needle, &s[start..start + len]).is_some()
}

/// Port of `libinjection_is_xss` for one parse context (`flags`).
fn is_xss_context(s: &[u8], flags: H5Flags) -> bool {
    let mut h5 = H5::init(s, flags);
    let mut attr = AttrType::None;

    while h5.next() {
        if h5.token_type != H5Type::AttrValue {
            attr = AttrType::None;
        }

        let tstart = h5.token_start;
        let tlen = h5.token_len;
        let tok = &s[tstart..tstart + tlen];

        match h5.token_type {
            H5Type::Doctype => return true,
            H5Type::TagNameOpen => {
                if is_black_tag(tok) {
                    return true;
                }
            }
            H5Type::AttrName => {
                attr = is_black_attr(tok);
            }
            H5Type::AttrValue => {
                match attr {
                    AttrType::None => {}
                    AttrType::Black => return true,
                    AttrType::AttrUrl => {
                        if is_black_url(tok) {
                            return true;
                        }
                    }
                    AttrType::Style => return true,
                    AttrType::AttrIndirect => {
                        // an attribute name is specified in a value
                        if is_black_attr(tok) != AttrType::None {
                            return true;
                        }
                    }
                }
                attr = AttrType::None;
            }
            H5Type::TagComment => {
                // IE uses a backtick as a tag ending char
                if token_contains(s, tstart, tlen, b'`') {
                    return true;
                }
                // IE conditional comment
                if tlen > 3 {
                    if tok[0] == b'['
                        && (tok[1] == b'i' || tok[1] == b'I')
                        && (tok[2] == b'f' || tok[2] == b'F')
                    {
                        return true;
                    }
                    if (tok[0] == b'x' || tok[0] == b'X')
                        && (tok[1] == b'm' || tok[1] == b'M')
                        && (tok[2] == b'l' || tok[2] == b'L')
                    {
                        return true;
                    }
                }
                if tlen > 5 {
                    // IE <?import pseudo-tag
                    if cstrcasecmp_with_null(b"IMPORT", tok, 6) {
                        return true;
                    }
                    // XML entity definition
                    if cstrcasecmp_with_null(b"ENTITY", tok, 6) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Port of `libinjection_xss` — the 5-context driver. Returns `true` (XSS) /
/// `false` (benign). The C error case cannot arise here.
pub fn is_xss_bytes(input: &[u8]) -> bool {
    if is_xss_context(input, H5Flags::DataState) {
        return true;
    }
    if is_xss_context(input, H5Flags::ValueNoQuote) {
        return true;
    }
    if is_xss_context(input, H5Flags::ValueSingleQuote) {
        return true;
    }
    if is_xss_context(input, H5Flags::ValueDoubleQuote) {
        return true;
    }
    if is_xss_context(input, H5Flags::ValueBackQuote) {
        return true;
    }
    false
}

/// Convenience wrapper for `&str` input.
pub fn is_xss(s: &str) -> bool {
    is_xss_bytes(s.as_bytes())
}

// ---------------------------------------------------------------------------
// Oracle test-support helpers — expose the HTML5 tokenizer output formatted
// exactly like libinjection's testdriver `print_html5_token`, so the vendored
// `test-html5-*` vectors can be checked byte-for-byte from
// `tests/libinjection_html5_oracle.rs`. Not used by any detector.
// ---------------------------------------------------------------------------

/// `h5_type_to_string` — the exact token-type strings the test driver prints.
fn h5_type_to_string(t: H5Type) -> &'static str {
    match t {
        H5Type::DataText => "DATA_TEXT",
        H5Type::TagNameOpen => "TAG_NAME_OPEN",
        H5Type::TagNameClose => "TAG_NAME_CLOSE",
        H5Type::TagNameSelfclose => "TAG_NAME_SELFCLOSE",
        H5Type::TagData => "TAG_DATA",
        H5Type::TagClose => "TAG_CLOSE",
        H5Type::AttrName => "ATTR_NAME",
        H5Type::AttrValue => "ATTR_VALUE",
        H5Type::TagComment => "TAG_COMMENT",
        H5Type::Doctype => "DOCTYPE",
    }
}

/// Tokenize `input` under the given flag and return the printed token lines in
/// the libinjection test-driver format (`print_html5_token`): `TYPE,len,text`.
///
/// `text` is the raw token bytes. The C driver builds the text with `sprintf
/// "%s"`, which stops at the first NUL — replicated here for faithfulness (the
/// vendored vectors contain no NULs, so this is a no-op for them).
///
/// Oracle test support only; not part of the detection API.
#[doc(hidden)]
pub fn debug_html5_tokenize(input: &[u8], flag: u32) -> Vec<String> {
    let flags = flag_to_enum(flag);
    let mut h5 = H5::init(input, flags);
    let mut out = Vec::new();
    while h5.next() {
        let tok = &input[h5.token_start..h5.token_start + h5.token_len];
        // sprintf("%s") stops at the first NUL byte.
        let printable = match memchr::memchr(0, tok) {
            Some(nul) => &tok[..nul],
            None => tok,
        };
        let text = String::from_utf8_lossy(printable);
        out.push(format!(
            "{},{},{}",
            h5_type_to_string(h5.token_type),
            h5.token_len,
            text
        ));
    }
    out
}

fn flag_to_enum(flag: u32) -> H5Flags {
    match flag {
        0 => H5Flags::DataState,
        1 => H5Flags::ValueNoQuote,
        2 => H5Flags::ValueSingleQuote,
        3 => H5Flags::ValueDoubleQuote,
        4 => H5Flags::ValueBackQuote,
        _ => H5Flags::DataState,
    }
}

/// `DATA_STATE` flag (oracle test support).
#[doc(hidden)]
pub const fn flag_data_state() -> u32 {
    0
}
/// `VALUE_NO_QUOTE` flag (oracle test support).
#[doc(hidden)]
pub const fn flag_value_no_quote() -> u32 {
    1
}
/// `VALUE_SINGLE_QUOTE` flag (oracle test support).
#[doc(hidden)]
pub const fn flag_value_single_quote() -> u32 {
    2
}
/// `VALUE_DOUBLE_QUOTE` flag (oracle test support).
#[doc(hidden)]
pub const fn flag_value_double_quote() -> u32 {
    3
}
/// `VALUE_BACK_QUOTE` flag (oracle test support).
#[doc(hidden)]
pub const fn flag_value_back_quote() -> u32 {
    4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_basic_xss() {
        assert!(is_xss("<script>alert(1)</script>"));
        assert!(is_xss("<IMG SRC=javascript:alert(1)>"));
        assert!(is_xss("<a href=\"javascript:alert(1)\">"));
        assert!(is_xss("<div style=expression(alert(1))>"));
        assert!(is_xss("<svg onload=alert(1)>"));
        assert!(is_xss("<!DOCTYPE html>"));
    }

    #[test]
    fn benign_is_not_xss() {
        assert!(!is_xss(""));
        assert!(!is_xss("hello world"));
        assert!(!is_xss("<b>bold</b>"));
        assert!(!is_xss("1 < 2 and 3 > 2"));
    }
}
