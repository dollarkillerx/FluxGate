//! Differential test: for a large generated corpus, the pure-Rust libinjection
//! XSS port must return EXACTLY the same verdict the real C library returns.
//! This auto-catches port drift the fixed HTML5 oracle vectors miss (the SQLi
//! sibling found a NUL bug this way). Runs under `cargo test --workspace` (CI),
//! where a C compiler is available.

use fluxgate_waf::xss::libinjection as rust;
use fluxgate_waf_difftest::{c_is_xss, CXss};

/// Deterministic LCG — reproducible, no rng dependency.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
}

/// Compare one input. Returns `true` if it was compared, `false` if skipped
/// (C returned its rare error result, which the Rust port doesn't model).
fn check(input: &[u8]) -> bool {
    let rust = rust::is_xss_bytes(input);
    match c_is_xss(input) {
        CXss::Error => false,
        CXss::Benign => {
            assert!(!rust, "DIVERGENCE on {input:?}: C=benign, Rust=xss");
            true
        }
        CXss::Xss => {
            assert!(rust, "DIVERGENCE on {input:?}: C=xss, Rust=benign");
            true
        }
    }
}

#[test]
fn structured_edge_cases_match_c() {
    let singles = [
        "",
        "<",
        ">",
        "/",
        "\"",
        "'",
        "`",
        "=",
        "(",
        ")",
        "&",
        ";",
        ":",
        "<!--",
        "-->",
        "<![CDATA[",
        "]]>",
        "<!",
        "<!DOCTYPE",
        "<?",
        "<%",
        "%>",
        "<script",
        "</script>",
        "<svg",
        "<img",
        "javascript:",
        "onerror=",
        "<a",
        "<style",
        "style=",
        "href=",
        "<xml",
        "<xsl",
        "xmlns=",
        "xlink:href=",
        "<![if",
        "<!--[if",
        "&#",
        "&#x",
        "&#x41;",
    ];
    for s in singles {
        check(s.as_bytes());
    }

    let frags: &[&[u8]] = &[
        b"<script",
        b"<script>",
        b"</script>",
        b"<svg",
        b"<svg onload=alert(1)>",
        b"<img src=x onerror=alert(1)>",
        b"<a href=javascript:alert(1)>",
        b"<iframe src=x>",
        b"<!DOCTYPE html>",
        b"<!-- -->",
        b"<!--[if IE]>",
        b"<![CDATA[",
        b"]]>",
        b"<%",
        b"%>",
        b"<?import",
        b"<!ENTITY",
        b"<style>x{}</style>",
        b"javascript:",
        b"onerror=",
        b"on=",
        b"<div style=x>",
        b"\"><script>",
        b"'><svg/onload=alert(1)>",
        b"`",
        b"<x onclick=y>",
        b"<form action=javascript:x>",
        b"<a xlink:href=x>",
        b"<b xmlns=x>",
        b"&#106;avascript:",
        b"\xC0",
        b"\xFF",
        b"\x00",
        b"\xA0",
        b"=",
        b"<>",
        b"</>",
    ];
    for f in frags {
        for n in [1usize, 2, 3, 5, 7, 33, 64] {
            let mut buf = Vec::new();
            for _ in 0..n {
                buf.extend_from_slice(f);
            }
            check(&buf);
            let mut q = vec![b'"'];
            q.extend_from_slice(&buf);
            check(&q);
            let mut q2 = vec![b'\''];
            q2.extend_from_slice(&buf);
            check(&q2);
        }
    }

    for b in 0u16..256 {
        check(&[b as u8]);
        check(&[b'<', b as u8]);
        check(&[b'<', b's', b'v', b'g', b' ', b as u8]);
        check(&[b'<', b'a', b' ', b'h', b'r', b'e', b'f', b'=', b as u8]);
        check(&[b as u8, b'<', b's', b'c', b'r', b'i', b'p', b't', b'>']);
    }
}

#[test]
fn pseudorandom_sweep_matches_c() {
    let mut rng = Lcg(0x00C0_FFEE_1234_5678);
    const ALPHABET: &[u8] = b"abcdefgxyz0123 <>/\"'=()&;:!-%[]?#svgript\x00\xFF\xC0\xA0";
    // Fragments injected to bias the corpus toward interesting structure.
    const FRAGS: &[&[u8]] = &[
        b"<script",
        b"<svg",
        b"onerror=",
        b"javascript:",
        b"<!--",
        b"-->",
        b"<![CDATA[",
        b"<!DOCTYPE",
        b"style=",
        b"href=",
        b"<%",
        b"%>",
        b"<?",
        b"]]>",
        b"<a ",
        b"\"",
        b"'",
        b"`",
        b"=",
    ];
    let mut compared = 0u64;
    let mut skipped = 0u64;
    for _ in 0..300_000 {
        let len = (rng.next() % 40) as usize;
        let mut buf = Vec::with_capacity(len);
        while buf.len() < len {
            let r = rng.next();
            match r % 8 {
                0 | 1 => buf.push(ALPHABET[(rng.next() as usize) % ALPHABET.len()]),
                2 => buf.push(rng.byte()),
                3 => buf.extend_from_slice(FRAGS[(rng.next() as usize) % FRAGS.len()]),
                _ => buf.push(ALPHABET[(rng.next() as usize) % ALPHABET.len()]),
            }
        }
        buf.truncate(len);
        if check(&buf) {
            compared += 1;
        } else {
            skipped += 1;
        }
    }
    eprintln!("xss differential: compared={compared}, skipped(C-error)={skipped}");
    assert!(
        compared > 250_000,
        "too many inputs skipped; oracle may be misbuilt"
    );
}
