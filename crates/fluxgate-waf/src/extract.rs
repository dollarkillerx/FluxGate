//! Parameter extraction. Splits a request into `(location, name, value)` tuples
//! so detection runs **per value**. This is the single biggest false-positive
//! win over the old approach of regex-matching one concatenated `path?query`
//! string: a payload in one parameter can no longer "bleed" across the `&`/`=`
//! boundary into adjacent benign data, and each value is decoded independently.
//!
//! All work is bounded by compile-time caps; exceeding a cap stops extraction of
//! that source rather than erroring (a malformed/huge request must never crash
//! the data plane).

use std::borrow::Cow;

use http::HeaderMap;

use fluxgate_core::WafLocation;

use crate::decode::{hex4, utf8_len};

/// Max parameters extracted per stage (Stage A or Stage B).
const MAX_PARAMS: usize = 128;
/// Max bytes of any single value analyzed (longer values are truncated).
const MAX_VALUE_LEN: usize = 8 * 1024;
/// Max JSON nesting depth walked.
const MAX_JSON_DEPTH: usize = 16;
/// Max JSON string scalars extracted.
const MAX_JSON_STRINGS: usize = 64;
/// Max multipart parts walked.
const MAX_MULTIPART_PARTS: usize = 32;
/// Max cookie pairs walked.
const MAX_COOKIES: usize = 32;

/// An extracted value to run detectors against.
pub struct Param<'a> {
    pub location: WafLocation,
    pub name: Cow<'a, str>,
    pub value: Cow<'a, str>,
}

impl<'a> Param<'a> {
    fn borrowed(location: WafLocation, name: &'a str, value: &'a str) -> Self {
        Param {
            location,
            name: Cow::Borrowed(name),
            value: Cow::Borrowed(cap(value)),
        }
    }

    /// Build from `Cow` parts, capping the value while **preserving** a borrow —
    /// only the already-owned slow path can re-allocate. Used by the JSON and
    /// multipart extractors, whose common case is a verbatim slice of the body.
    fn from_cow(location: WafLocation, name: Cow<'a, str>, value: Cow<'a, str>) -> Self {
        let value = match value {
            Cow::Borrowed(v) => Cow::Borrowed(cap(v)),
            Cow::Owned(v) => {
                let capped = cap(&v);
                if capped.len() == v.len() {
                    Cow::Owned(v)
                } else {
                    Cow::Owned(capped.to_string())
                }
            }
        };
        Param {
            location,
            name,
            value,
        }
    }
}

fn cap(v: &str) -> &str {
    if v.len() <= MAX_VALUE_LEN {
        return v;
    }
    let mut end = MAX_VALUE_LEN;
    while end > 0 && !v.is_char_boundary(end) {
        end -= 1;
    }
    &v[..end]
}

/// Extract values from the request line + relevant headers (Stage A). `headers`
/// is the raw request `HeaderMap` — values are read borrowed (no per-request
/// lowercased-copy map needed: detectors lowercase each value themselves).
pub fn extract_request<'a>(path_and_query: &'a str, headers: &'a HeaderMap) -> Vec<Param<'a>> {
    let mut out = Vec::new();
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };

    // The bare path (for traversal / protocol checks).
    out.push(Param::borrowed(WafLocation::Path, "", path));

    if let Some(q) = query {
        parse_pairs(q, '&', WafLocation::Query, &mut out);
    }

    // Cookies.
    if let Some(cookie) = header(headers, "cookie") {
        parse_cookies(cookie, &mut out);
    }

    // Selected headers that commonly carry payloads.
    for name in ["user-agent", "referer"] {
        if let Some(v) = header(headers, name) {
            if out.len() < MAX_PARAMS {
                out.push(Param::borrowed(WafLocation::Header, name, v));
            }
            // The Referer often carries a query string of its own.
            if name == "referer" {
                if let Some((_, q)) = v.split_once('?') {
                    parse_pairs(q, '&', WafLocation::Query, &mut out);
                }
            }
        }
    }

    out
}

/// Extract values from a request body prefix (Stage B), selecting the parser by
/// content type.
pub fn extract_body<'a>(content_type: Option<&str>, body: &'a str) -> Vec<Param<'a>> {
    let mut out = Vec::new();
    let ct = content_type.unwrap_or("");
    // Case-insensitive prefix test that doesn't allocate a lowercased copy of the
    // content-type on every body (the original case is also what multipart needs
    // for its case-sensitive boundary).
    let starts = |p: &str| {
        ct.len() >= p.len() && ct.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes())
    };

    if starts("application/x-www-form-urlencoded") {
        parse_pairs(body, '&', WafLocation::BodyForm, &mut out);
    } else if starts("application/json") || starts("application/graphql") {
        extract_json(body, &mut out);
    } else if starts("multipart/form-data") {
        extract_multipart(ct, body, &mut out);
    } else if !looks_binary(body) {
        // text/*, xml, or unknown: scan the whole prefix as one value — but only
        // when it actually looks like text. A raw binary upload (image, archive,
        // octet-stream, a chunked file PUT) legitimately carries NUL and control
        // bytes, which the text detectors (esp. `proto`'s NUL check) would only
        // false-positive on. Structured text fields (query / header / JSON / form /
        // multipart) are extracted above and keep full NUL detection.
        out.push(Param::borrowed(WafLocation::BodyForm, "body", body));
    }

    out
}

/// Heuristic: does this raw body look like a binary upload (image, archive,
/// octet-stream) rather than text? The proxy reads the body prefix via
/// `from_utf8_lossy`, so non-UTF-8 file bytes surface as `U+FFFD` replacement
/// chars — a strong binary tell — alongside NUL and other C0 controls. A real
/// text body has effectively none of these, so a high ratio means binary and the
/// catch-all raw-body value is skipped (vs. a stray `file\0.jpg`-style value,
/// which stays text and is still flagged). Also used by the data plane to skip
/// the regex body layer on binary uploads.
pub fn looks_binary(body: &str) -> bool {
    let mut total = 0usize;
    let mut bin = 0usize;
    for c in body.chars().take(512) {
        total += 1;
        if c == '\0' || c == '\u{FFFD}' || (c.is_control() && !matches!(c, '\t' | '\r' | '\n')) {
            bin += 1;
        }
    }
    total > 0 && bin * 100 / total >= 15
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    // `HeaderMap` keys are already case-insensitive; `to_str` borrows (no alloc)
    // and fails closed (→ skipped) on non-UTF-8 header bytes.
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
}

/// Parse `a=1&b=2` style pairs (used for query strings and form bodies). Names
/// and values are left percent-encoded; the decode pass handles them.
fn parse_pairs<'a>(s: &'a str, sep: char, location: WafLocation, out: &mut Vec<Param<'a>>) {
    for pair in s.split(sep) {
        if out.len() >= MAX_PARAMS {
            return;
        }
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.split_once('=') {
            Some((n, v)) => (n, v),
            None => ("", pair),
        };
        // Inspect the parameter *name* too: a payload placed in the name
        // (`?<script>=1`) is otherwise never analyzed, since detectors only see
        // values. Skipped when there's no `=` (the whole token is already the
        // value) or the name is empty.
        if !name.is_empty() && out.len() < MAX_PARAMS {
            out.push(Param::borrowed(location, name, name));
        }
        if value.is_empty() {
            continue;
        }
        if out.len() >= MAX_PARAMS {
            return;
        }
        out.push(Param::borrowed(location, name, value));
    }
}

fn parse_cookies<'a>(s: &'a str, out: &mut Vec<Param<'a>>) {
    let mut count = 0;
    for pair in s.split(';') {
        if count >= MAX_COOKIES || out.len() >= MAX_PARAMS {
            return;
        }
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.split_once('=') {
            Some((n, v)) => (n.trim(), v),
            None => continue,
        };
        if !name.is_empty() && out.len() < MAX_PARAMS {
            out.push(Param::borrowed(WafLocation::Cookie, name, name));
        }
        if value.is_empty() {
            continue;
        }
        if out.len() >= MAX_PARAMS {
            return;
        }
        out.push(Param::borrowed(WafLocation::Cookie, name, value));
        count += 1;
    }
}

/// Walk a (possibly truncated) JSON document and emit every string scalar as a
/// `(BodyJson, key, value)` param. Hand-rolled because the 64 KB prefix is often
/// a truncated document — `serde_json` would reject it. Numbers/bools/nulls are
/// skipped (they can't carry an injection payload).
fn extract_json<'a>(s: &'a str, out: &mut Vec<Param<'a>>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    let mut strings = 0usize;
    // The most-recent string literal — becomes the "key" when followed by ':'.
    let mut last_string: Option<Cow<'a, str>> = None;
    let mut pending_key: Option<Cow<'a, str>> = None;

    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > MAX_JSON_DEPTH {
                    return;
                }
                pending_key = None;
                last_string = None;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b':' => {
                // The preceding string was a key.
                pending_key = last_string.take();
                i += 1;
            }
            b',' => {
                pending_key = None;
                last_string = None;
                i += 1;
            }
            b'"' => {
                let (text, next) = scan_json_string(s, i);
                i = next;
                // Look ahead: a string immediately before ':' is a key (captured
                // for the next iteration); otherwise it's a value and is emitted.
                let mut j = i;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                let is_key = j < bytes.len() && bytes[j] == b':';
                if is_key {
                    last_string = Some(text);
                } else {
                    if strings >= MAX_JSON_STRINGS || out.len() >= MAX_PARAMS {
                        return;
                    }
                    let key = pending_key.take().unwrap_or(Cow::Borrowed(""));
                    out.push(Param::from_cow(WafLocation::BodyJson, key, text));
                    strings += 1;
                    last_string = None;
                }
            }
            _ => i += 1,
        }
    }
}

/// Scan a JSON string starting at `s.as_bytes()[start] == '"'`, decoding `\uXXXX`
/// and the standard escapes. Returns `(value, index_after_closing_quote_or_eof)`.
///
/// Fast path: a string with **no** `\` escape is a verbatim slice of the body, so
/// it's returned **borrowed** (no allocation) — byte-identical to what unescaping
/// would produce. Only a string containing a `\` takes the owning slow path. (`"`
/// and `\` are ASCII; UTF-8 continuation bytes are ≥0x80, so the byte scan never
/// mis-detects them and the slice lands on char boundaries.)
fn scan_json_string(s: &str, start: usize) -> (Cow<'_, str>, usize) {
    let bytes = s.as_bytes();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return (Cow::Borrowed(&s[start + 1..i]), i + 1),
            b'\\' => break, // has an escape — fall to the owning decoder
            _ => i += 1,
        }
    }
    if i >= bytes.len() {
        // Unterminated (truncated prefix) with no escape — borrow the remainder.
        return (Cow::Borrowed(&s[start + 1..]), i);
    }

    // Slow path: re-scan from the start, decoding escapes into an owned String.
    let (decoded, next) = scan_json_string_owned(bytes, start);
    (Cow::Owned(decoded), next)
}

/// The original allocating decoder — only reached for strings that contain a `\`.
fn scan_json_string_owned(bytes: &[u8], start: usize) -> (String, usize) {
    let mut out = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return (out, i + 1),
            b'\\' if i + 1 < bytes.len() => {
                match bytes[i + 1] {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'/' => out.push('/'),
                    b'\\' => out.push('\\'),
                    b'"' => out.push('"'),
                    b'u' if i + 5 < bytes.len() => {
                        if let Some(cp) = hex4(&bytes[i + 2..i + 6]) {
                            if let Some(c) = char::from_u32(cp) {
                                out.push(c);
                            }
                            i += 6;
                            continue;
                        }
                        out.push('\\');
                    }
                    other => out.push(other as char),
                }
                i += 2;
            }
            b => {
                let len = utf8_len(b);
                let end = (i + len).min(bytes.len());
                out.push_str(&String::from_utf8_lossy(&bytes[i..end]));
                i = end;
            }
        }
    }
    (out, i) // unterminated (truncated prefix) — tolerated
}

/// Extract text (non-file) parts of a `multipart/form-data` body. File parts
/// (those with a `filename=`) are skipped — binary uploads are a false-positive
/// source and are scanned by content-type filters elsewhere, not here.
fn extract_multipart<'a>(ct: &str, body: &'a str, out: &mut Vec<Param<'a>>) {
    // The `boundary=` parameter *name* is case-insensitive, but its *value* is
    // case-sensitive — browsers send mixed-case boundaries like
    // `----WebKitFormBoundaryAbc123`. Locate the name on a lowercased copy, then
    // slice the value from the original `ct` so its case is preserved (otherwise
    // the delimiter never matches the body and every field is silently skipped —
    // a WAF bypass). ASCII lowercasing is byte-position-preserving, so the index
    // is valid in both strings.
    let lc = ct.to_ascii_lowercase();
    let Some(pos) = lc.find("boundary=") else {
        return;
    };
    let boundary = ct[pos + "boundary=".len()..].trim().trim_matches('"');
    if boundary.is_empty() {
        return;
    }
    let delim = format!("--{boundary}");
    let mut parts = 0;
    for part in body.split(&delim) {
        if parts >= MAX_MULTIPART_PARTS || out.len() >= MAX_PARAMS {
            return;
        }
        // Each part: headers, blank line, then content.
        let Some((head, content)) = part
            .split_once("\r\n\r\n")
            .or_else(|| part.split_once("\n\n"))
        else {
            continue;
        };
        let head_lc = head.to_ascii_lowercase();
        if head_lc.contains("filename=") {
            continue; // file part — skip
        }
        // Pull the field name out of Content-Disposition.
        let name = head_lc
            .split("name=")
            .nth(1)
            .map(|n| {
                n.trim()
                    .trim_matches('"')
                    .split(['"', ';', '\r', '\n'])
                    .next()
                    .unwrap_or("")
            })
            .unwrap_or("")
            .to_string();
        // A multipart text value is a verbatim slice of the body (no unescaping) —
        // borrow it; only the lowercased field `name` is owned.
        let value = content.trim_end_matches(['-', '\r', '\n']);
        if value.is_empty() {
            continue;
        }
        out.push(Param::from_cow(
            WafLocation::BodyMultipart,
            Cow::Owned(name),
            Cow::Borrowed(value),
        ));
        parts += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn names_values(params: &[Param]) -> Vec<(WafLocation, String, String)> {
        params
            .iter()
            .map(|p| (p.location, p.name.to_string(), p.value.to_string()))
            .collect()
    }

    fn hmap(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn query_splits_per_param() {
        let h = HeaderMap::new();
        let p = extract_request("/search?q=hello&sort=name", &h);
        let nv = names_values(&p);
        assert!(nv.contains(&(WafLocation::Path, "".into(), "/search".into())));
        assert!(nv.contains(&(WafLocation::Query, "q".into(), "hello".into())));
        assert!(nv.contains(&(WafLocation::Query, "sort".into(), "name".into())));
    }

    #[test]
    fn cookies_and_headers() {
        let h = hmap(&[
            ("cookie", "sid=abc; theme=dark"),
            ("user-agent", "Mozilla/5.0"),
        ]);
        let p = extract_request("/", &h);
        let nv = names_values(&p);
        assert!(nv.contains(&(WafLocation::Cookie, "sid".into(), "abc".into())));
        assert!(nv.contains(&(WafLocation::Cookie, "theme".into(), "dark".into())));
        assert!(nv.contains(&(
            WafLocation::Header,
            "user-agent".into(),
            "Mozilla/5.0".into()
        )));
    }

    #[test]
    fn json_string_values_only() {
        let body = r#"{"name":"alice","age":30,"note":"hi there","nested":{"q":"x' OR 1=1"}}"#;
        let mut out = Vec::new();
        extract_json(body, &mut out);
        let nv = names_values(&out);
        assert!(nv.contains(&(WafLocation::BodyJson, "name".into(), "alice".into())));
        assert!(nv.contains(&(WafLocation::BodyJson, "note".into(), "hi there".into())));
        assert!(nv.contains(&(WafLocation::BodyJson, "q".into(), "x' OR 1=1".into())));
        // Numbers are not extracted.
        assert!(!nv.iter().any(|(_, k, _)| k == "age"));
        // Keys are not emitted as values.
        assert!(!nv.iter().any(|(_, _, v)| v == "name"));
    }

    #[test]
    fn json_and_multipart_values_borrow_when_unescaped() {
        // An unescaped JSON string value is a verbatim slice → borrowed (no alloc).
        let mut out = Vec::new();
        extract_json(r#"{"q":"hello world"}"#, &mut out);
        let v = out.iter().find(|p| p.value == "hello world").unwrap();
        assert!(
            matches!(v.value, Cow::Borrowed(_)),
            "unescaped JSON value must borrow"
        );

        // An escaped JSON string takes the owning slow path and is decoded
        // correctly (the `\"` becomes a real quote for the SQLi detector).
        let mut out = Vec::new();
        extract_json(r#"{"q":"a\" OR 1=1"}"#, &mut out);
        let v = out.iter().find(|p| p.value.contains("OR 1=1")).unwrap();
        assert_eq!(v.value, r#"a" OR 1=1"#);
        assert!(
            matches!(v.value, Cow::Owned(_)),
            "escaped JSON value must own"
        );

        // A multipart text value is a verbatim slice of the body → borrowed.
        let ct = "multipart/form-data; boundary=ab";
        let body = "--ab\r\nContent-Disposition: form-data; name=\"u\"\r\n\r\nalice\r\n--ab--";
        let params = extract_body(Some(ct), body);
        let v = params.iter().find(|p| p.value == "alice").unwrap();
        assert!(
            matches!(v.value, Cow::Borrowed(_)),
            "multipart value must borrow"
        );
    }

    #[test]
    fn multipart_boundary_is_case_sensitive() {
        // Browsers send mixed-case boundaries; lowercasing the content-type would
        // make the delimiter miss every part (a WAF bypass). The field value must
        // still be extracted.
        let ct = "multipart/form-data; boundary=----WebKitFormBoundaryAbC123";
        let body = "------WebKitFormBoundaryAbC123\r\n\
            Content-Disposition: form-data; name=\"q\"\r\n\r\n\
            1' OR '1'='1\r\n\
            ------WebKitFormBoundaryAbC123--";
        let params = extract_body(Some(ct), body);
        let nv = names_values(&params);
        assert!(
            nv.contains(&(
                WafLocation::BodyMultipart,
                "q".into(),
                "1' OR '1'='1".into()
            )),
            "mixed-case boundary must still extract the field: {nv:?}"
        );
    }

    #[test]
    fn truncated_json_is_tolerated() {
        let body = r#"{"a":"first","b":"second val that is cut o"#;
        let mut out = Vec::new();
        extract_json(body, &mut out);
        let nv = names_values(&out);
        assert!(nv.iter().any(|(_, k, _)| k == "a"));
        assert!(nv
            .iter()
            .any(|(_, k, v)| k == "b" && v.starts_with("second")));
    }

    #[test]
    fn multipart_skips_files() {
        let ct = "multipart/form-data; boundary=X";
        let body = "--X\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhello world\r\n--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01binary' OR 1=1\r\n--X--";
        let mut out = Vec::new();
        extract_multipart(ct, body, &mut out);
        let nv = names_values(&out);
        assert!(nv
            .iter()
            .any(|(_, k, v)| k == "comment" && v.contains("hello")));
        assert!(!nv.iter().any(|(_, k, _)| k == "file"));
    }

    #[test]
    fn form_body() {
        let p = extract_body(
            Some("application/x-www-form-urlencoded"),
            "u=alice&p=secret",
        );
        let nv = names_values(&p);
        assert!(nv.contains(&(WafLocation::BodyForm, "u".into(), "alice".into())));
        assert!(nv.contains(&(WafLocation::BodyForm, "p".into(), "secret".into())));
    }

    #[test]
    fn binary_upload_body_skipped() {
        // A raw PNG chunk PUT with no content-type, read as from_utf8_lossy: the
        // magic + pixel bytes become NUL + U+FFFD. The catch-all must skip it so
        // `proto`'s NUL check never false-positives on a legitimate file upload.
        let png = String::from_utf8_lossy(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x04\x00\x00\xc4\x82\x9c\x08\x02\x00\x00\x00").into_owned();
        assert!(
            extract_body(None, &png).is_empty(),
            "binary body must be skipped"
        );

        // A genuine text body with no content-type is still inspected.
        let text = extract_body(None, "hello world this is plain text");
        assert_eq!(text.len(), 1);

        // A short text value with a stray NUL stays text (low binary ratio) — the
        // null-byte injection case is preserved, not masked by the binary skip.
        let injected = extract_body(None, "file\0.jpg");
        assert_eq!(injected.len(), 1);
    }
}
