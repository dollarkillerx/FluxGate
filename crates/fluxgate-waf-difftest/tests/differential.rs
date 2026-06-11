//! Differential test: for a large generated corpus, the pure-Rust libinjection
//! port must return EXACTLY what the real C library returns (verdict AND
//! fingerprint). This auto-catches port drift the fixed oracle vectors miss — it
//! would have flagged all three bugs the manual audit found. Runs under
//! `cargo test --workspace` (CI), where a C compiler is available.

use fluxgate_waf::sqli::libinjection as rust;
use fluxgate_waf_difftest::{c_is_sqli, CVerdict};

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
    let rust = rust::is_sqli_bytes(input); // Option<String>
    match c_is_sqli(input) {
        CVerdict::Error => false,
        CVerdict::Benign => {
            assert!(
                rust.is_none(),
                "DIVERGENCE on {input:?}: C=benign, Rust={rust:?}"
            );
            true
        }
        CVerdict::Sqli(fp) => {
            assert_eq!(
                rust.as_deref(),
                Some(fp.as_str()),
                "DIVERGENCE on {input:?}: C=Some({fp:?}), Rust={rust:?}"
            );
            true
        }
    }
}

#[test]
fn structured_edge_cases_match_c() {
    let singles = [
        "", "%", "\\", "'", "\"", "`", "/", "-", "#", "(", ")", ",", ";", "@", "0x", "/*", "*/",
        "--", "/*!", "/*!5", "0x", "0X", "'\\", "\"\\", "1e", "1.", ".1", "@@", "q'", "q'(", "{",
        "}", "{`", "$", "$a$",
    ];
    for s in singles {
        check(s.as_bytes());
    }
    let frags: &[&[u8]] = &[
        b"'",
        b"\"",
        b"`",
        b"/*",
        b"*/",
        b"--",
        b"#",
        b"(",
        b")",
        b",",
        b";",
        b"{",
        b"}",
        b"{`",
        b"a {`",
        b"$",
        b"$a$",
        b"q'",
        b"q'(",
        b"[",
        b"]",
        b"0x",
        b"@@",
        b"1e",
        b" or ",
        b" and ",
        b" union select ",
        b"/*!50000",
        b"\xC0",
        b"\xFF",
        b"\x00",
        b"\xA0",
        b"1=1",
        b"1>0",
    ];
    for f in frags {
        for n in [1usize, 2, 3, 5, 7, 33, 64] {
            let mut buf = Vec::new();
            for _ in 0..n {
                buf.extend_from_slice(f);
            }
            check(&buf);
            let mut q = vec![b'\''];
            q.extend_from_slice(&buf);
            check(&q);
        }
    }
    for b in 0u16..256 {
        check(&[b as u8]);
        check(&[b'\'', b as u8]);
        check(&[b'1', b as u8, b'1']);
        check(&[b as u8, b'-', b'-']);
    }
}

#[test]
fn pseudorandom_sweep_matches_c() {
    let mut rng = Lcg(0x00C0_FFEE_1234_5678);
    const ALPHABET: &[u8] = b"abcdefgxyz0123 '\"`()[]{}/*-#,;@=<>|&%$\\.:!~\x00\xFF\xC0\xA0";
    let mut compared = 0u64;
    let mut skipped = 0u64;
    for _ in 0..300_000 {
        let len = (rng.next() % 40) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            if rng.next() & 1 == 0 {
                buf.push(ALPHABET[(rng.next() as usize) % ALPHABET.len()]);
            } else {
                buf.push(rng.byte());
            }
        }
        if check(&buf) {
            compared += 1;
        } else {
            skipped += 1;
        }
    }
    eprintln!("differential: compared={compared}, skipped(C-error)={skipped}");
    assert!(
        compared > 250_000,
        "too many inputs skipped; oracle may be misbuilt"
    );
}
