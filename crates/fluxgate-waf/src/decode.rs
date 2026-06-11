//! Multi-layer decoding. Attackers wrap payloads in percent / HTML-entity /
//! unicode-escape encodings (often several layers) to slip past naive filters.
//! We iteratively reverse them — bounded — before the detectors see the value,
//! so `%2e%2e%2f` and `&#106;avascript:` are normalized to what the origin will
//! actually interpret.
//!
//! Decoding is **detection-only**: the bytes forwarded upstream are never
//! touched, so over-decoding can at worst cause a false positive — the safe
//! direction for a WAF.

use std::borrow::Cow;

use fluxgate_core::{WafLocation, WafRisk};

/// Max decode rounds (fixpoint). Stops early when a round changes nothing.
const MAX_ROUNDS: u8 = 3;

/// A decoded value plus how many rounds actually changed bytes. Two or more
/// rounds means the payload was multiply-encoded — itself a signal — so
/// [`Decoded::bump`] raises a detection's risk one step.
pub struct Decoded<'a> {
    pub text: Cow<'a, str>,
    pub rounds: u8,
}

impl Decoded<'_> {
    /// Raise `risk` one level when the value was multiply-encoded.
    pub fn bump(&self, risk: WafRisk) -> WafRisk {
        if self.rounds >= 2 {
            match risk {
                WafRisk::Low => WafRisk::Medium,
                WafRisk::Medium | WafRisk::High => WafRisk::High,
            }
        } else {
            risk
        }
    }
}

/// Decode a single parameter value. `+` is treated as a space only for
/// query-string / form-urlencoded locations.
pub fn decode_value<'a>(raw: &'a str, location: WafLocation) -> Decoded<'a> {
    let plus_is_space = matches!(location, WafLocation::Query | WafLocation::BodyForm);

    // Fast path: nothing encoded → borrow, zero work. One SIMD pass over the
    // `% & \` trigger bytes (plus `+` for query/form) instead of up to four
    // separate `contains` scans — this runs on *every* extracted value.
    let bytes = raw.as_bytes();
    let triggered = memchr::memchr3(b'%', b'&', b'\\', bytes).is_some()
        || (plus_is_space && memchr::memchr(b'+', bytes).is_some());
    if !triggered {
        return Decoded {
            text: Cow::Borrowed(raw),
            rounds: 0,
        };
    }

    // Decode layer-by-layer, borrowing through any layer that changes nothing so
    // a value with a trigger byte but no real escape (e.g. a query's `&`
    // separators) never allocates. `rounds` counts rounds that changed bytes.
    let mut cur: Cow<'a, str> = Cow::Borrowed(raw);
    let mut rounds = 0u8;
    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        if plus_is_space && cur.contains('+') {
            cur = Cow::Owned(cur.replace('+', " "));
            changed = true;
        }
        if cur.contains('%') {
            // Normalize dangerous *overlong* UTF-8 percent-encodings (`%c0%af`→`/`)
            // first, so legacy-backend traversal/injection bypasses resolve before
            // the byte-level percent decode (which would otherwise produce invalid
            // UTF-8 and lose the `/`).
            if let Some(s) = overlong_normalize_opt(&cur) {
                cur = Cow::Owned(s);
                changed = true;
            }
            if let Some(s) = percent_decode_opt(&cur) {
                cur = Cow::Owned(s);
                changed = true;
            }
        }
        if cur.contains('&') {
            if let Some(s) = html_entity_decode_opt(&cur) {
                cur = Cow::Owned(s);
                changed = true;
            }
        }
        if cur.contains('\\') {
            if let Some(s) = unicode_escape_decode_opt(&cur) {
                cur = Cow::Owned(s);
                changed = true;
            }
        }
        if !changed {
            break;
        }
        rounds += 1;
    }

    Decoded { text: cur, rounds }
}

/// Replace the dangerous **overlong** UTF-8 percent-encodings of `/`, `.`, `\`
/// (e.g. `%c0%af` → `/`) that some legacy servers accept — a classic traversal /
/// injection filter bypass. Returns `None` (borrow-through) when none are present.
/// Covers lower- and upper-hex; mixed-case hex is rare and left to the operator.
fn overlong_normalize_opt(s: &str) -> Option<String> {
    // (overlong encoding, decoded ASCII char).
    const SEQ: &[(&str, &str)] = &[
        ("%c0%af", "/"),
        ("%C0%AF", "/"),
        ("%e0%80%af", "/"),
        ("%E0%80%AF", "/"),
        ("%c0%ae", "."),
        ("%C0%AE", "."),
        ("%e0%80%ae", "."),
        ("%E0%80%AE", "."),
        ("%c1%9c", "\\"),
        ("%C1%9C", "\\"),
        ("%c0%9c", "\\"),
        ("%C0%9C", "\\"),
    ];
    if !SEQ.iter().any(|(seq, _)| s.contains(seq)) {
        return None;
    }
    let mut out = s.to_string();
    for (seq, ch) in SEQ {
        if out.contains(seq) {
            out = out.replace(seq, ch);
        }
    }
    Some(out)
}

/// Percent-decode `%HH` (and the IIS `%uXXXX` form). Invalid escapes pass through.
pub fn percent_decode(s: &str) -> String {
    percent_decode_opt(s).unwrap_or_else(|| s.to_string())
}

/// Percent-decode, returning `None` (borrow-through) when nothing was decoded —
/// so the hot path doesn't allocate for a value that merely *contains* a `%`.
fn percent_decode_opt(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // %uXXXX (IIS / older browsers).
            if i + 5 < bytes.len() && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U') {
                if let Some(cp) = hex4(&bytes[i + 2..i + 6]) {
                    push_codepoint(out.get_or_insert_with(|| bytes[..i].to_vec()), cp);
                    i += 6;
                    continue;
                }
            }
            if i + 2 < bytes.len() {
                if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.get_or_insert_with(|| bytes[..i].to_vec())
                        .push(h * 16 + l);
                    i += 3;
                    continue;
                }
            }
        }
        if let Some(o) = out.as_mut() {
            o.push(bytes[i]);
        }
        i += 1;
    }
    out.map(|o| String::from_utf8_lossy(&o).into_owned())
}

/// Decode the small set of HTML entities that matter for injection detection:
/// the named set plus numeric `&#NNN;` / `&#xHH;` (lenient on a missing
/// semicolon, as browsers are).
pub fn html_entity_decode(s: &str) -> String {
    html_entity_decode_opt(s).unwrap_or_else(|| s.to_string())
}

/// Like [`html_entity_decode`] but `None` (borrow-through) when no entity decoded.
fn html_entity_decode_opt(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some((decoded, consumed)) = decode_entity(&bytes[i..]) {
                // Seed with the untouched prefix (`&` is ASCII → a char boundary).
                out.get_or_insert_with(|| String::from_utf8_lossy(&bytes[..i]).into_owned())
                    .push(decoded);
                i += consumed;
                continue;
            }
        }
        // Push this byte as part of a UTF-8 char.
        let ch_len = utf8_len(bytes[i]);
        let end = (i + ch_len).min(bytes.len());
        if let Some(o) = out.as_mut() {
            o.push_str(&String::from_utf8_lossy(&bytes[i..end]));
        }
        i = end;
    }
    out
}

fn decode_entity(b: &[u8]) -> Option<(char, usize)> {
    debug_assert_eq!(b[0], b'&');
    if b.len() < 3 {
        return None;
    }
    if b[1] == b'#' {
        // Numeric: &#NNN; or &#xHH;
        let (hex, mut j) = if b[2] == b'x' || b[2] == b'X' {
            (true, 3)
        } else {
            (false, 2)
        };
        let start = j;
        let mut val: u32 = 0;
        while j < b.len() && (j - start) < 8 {
            let d = if hex { hex_val(b[j]) } else { dec_val(b[j]) };
            match d {
                Some(d) => {
                    val = val
                        .saturating_mul(if hex { 16 } else { 10 })
                        .saturating_add(d as u32);
                    j += 1;
                }
                None => break,
            }
        }
        if j == start {
            return None;
        }
        // Optional trailing ';'.
        if j < b.len() && b[j] == b';' {
            j += 1;
        }
        return char::from_u32(val).map(|c| (c, j));
    }
    // Named entities (the injection-relevant subset).
    const NAMED: &[(&[u8], char)] = &[
        (b"lt", '<'),
        (b"gt", '>'),
        (b"quot", '"'),
        (b"apos", '\''),
        (b"amp", '&'),
        (b"colon", ':'),
        (b"semi", ';'),
        (b"sol", '/'),
        (b"bsol", '\\'),
        (b"lpar", '('),
        (b"rpar", ')'),
        (b"num", '#'),
        (b"period", '.'),
        (b"newline", '\n'),
        (b"tab", '\t'),
        (b"nbsp", ' '),
    ];
    for (name, ch) in NAMED {
        let nlen = name.len();
        if b.len() > nlen && &b[1..1 + nlen] == *name {
            let after = b.get(1 + nlen).copied();
            // Accept only when the entity name is terminated: by `;`, end of
            // input, or a non-alphanumeric byte. Without this, `&ltd` would match
            // `lt` and decode to `<d`, injecting a `<` into benign text (a false
            // positive). Browsers likewise won't extend a legacy entity into a
            // following alphanumeric run.
            match after {
                Some(b';') => return Some((*ch, 1 + nlen + 1)),
                Some(c) if c.is_ascii_alphanumeric() => continue,
                _ => return Some((*ch, 1 + nlen)),
            }
        }
    }
    None
}

/// Decode `\uXXXX` / `\xHH` escape sequences (JS / JSON style). Other backslash
/// escapes pass through unchanged.
pub fn unicode_escape_decode(s: &str) -> String {
    unicode_escape_decode_opt(s).unwrap_or_else(|| s.to_string())
}

/// Like [`unicode_escape_decode`] but `None` (borrow-through) when nothing decoded.
fn unicode_escape_decode_opt(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'u' | b'U' if i + 5 < bytes.len() => {
                    if let Some(cp) = hex4(&bytes[i + 2..i + 6]) {
                        push_codepoint(out.get_or_insert_with(|| bytes[..i].to_vec()), cp);
                        i += 6;
                        continue;
                    }
                }
                b'x' | b'X' if i + 3 < bytes.len() => {
                    if let (Some(h), Some(l)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                        out.get_or_insert_with(|| bytes[..i].to_vec())
                            .push(h * 16 + l);
                        i += 4;
                        continue;
                    }
                }
                _ => {}
            }
        }
        if let Some(o) = out.as_mut() {
            o.push(bytes[i]);
        }
        i += 1;
    }
    out.map(|o| String::from_utf8_lossy(&o).into_owned())
}

fn push_codepoint(out: &mut Vec<u8>, cp: u32) {
    if let Some(c) = char::from_u32(cp) {
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
}

/// Parse exactly 4 hex digits into a code point. Shared with [`crate::extract`].
pub(crate) fn hex4(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    let mut v = 0u32;
    for &c in &b[..4] {
        v = v * 16 + hex_val(c)? as u32;
    }
    Some(v)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn dec_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        _ => None,
    }
}

/// Byte length of a UTF-8 char from its leading byte. Shared with [`crate::extract`].
pub(crate) fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else if first >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_basic_and_double() {
        assert_eq!(percent_decode("%2e%2e%2f"), "../");
        let d = decode_value("%252e%252e", WafLocation::Query);
        assert_eq!(d.text, "..");
        assert!(d.rounds >= 2, "double-encoded should take >=2 rounds");
    }

    #[test]
    fn plus_only_for_query() {
        assert_eq!(decode_value("a+b", WafLocation::Query).text, "a b");
        // Header/cookie/path: '+' is literal.
        assert_eq!(decode_value("a+b", WafLocation::Header).text, "a+b");
    }

    #[test]
    fn html_entities() {
        assert_eq!(html_entity_decode("&lt;script&gt;"), "<script>");
        assert_eq!(html_entity_decode("&#106;&#x61;"), "ja");
        // Missing semicolon is tolerated for numeric entities.
        assert_eq!(html_entity_decode("&#106avascript"), "javascript");
    }

    #[test]
    fn named_entity_requires_boundary() {
        // A named entity must be terminated — `&ltd` is NOT `<d` (would be a false
        // positive); only a real `&lt;`/`&lt ` decodes.
        assert_eq!(html_entity_decode("&ltd"), "&ltd");
        assert_eq!(html_entity_decode("&ampere"), "&ampere");
        assert_eq!(html_entity_decode("&lt;script"), "<script");
        assert_eq!(html_entity_decode("&lt x"), "< x");
    }

    #[test]
    fn unicode_escapes() {
        assert_eq!(unicode_escape_decode(r"<script"), "<script");
        assert_eq!(unicode_escape_decode(r"\x3cb\x3e"), "<b>");
    }

    #[test]
    fn fast_path_borrows() {
        let d = decode_value("plain-value_123", WafLocation::Query);
        assert!(matches!(d.text, Cow::Borrowed(_)));
        assert_eq!(d.rounds, 0);
    }

    #[test]
    fn noop_trigger_bytes_borrow_through() {
        // Trigger bytes present but nothing actually decodes → must borrow, not
        // allocate (the regex engine normalizes `?a=1&b=2`-style queries on every
        // request, so a `&` that isn't an entity must stay zero-alloc).
        for v in ["a=1&b=2", "100% done", "C:\\Users\\x", "Tom & Jerry"] {
            let d = decode_value(v, WafLocation::Query);
            assert!(
                matches!(d.text, Cow::Borrowed(_)),
                "{v:?} should borrow through"
            );
            assert_eq!(d.rounds, 0, "{v:?} should not count a decode round");
        }
        // A real escape still decodes (and owns).
        let d = decode_value("a%3Cb", WafLocation::Query);
        assert_eq!(d.text, "a<b");
        assert!(matches!(d.text, Cow::Owned(_)));
    }

    #[test]
    fn bump_raises_on_double_encoding() {
        let d = decode_value("%252e%252e", WafLocation::Query);
        assert_eq!(d.bump(WafRisk::Low), WafRisk::Medium);
        assert_eq!(d.bump(WafRisk::Medium), WafRisk::High);
    }
}
