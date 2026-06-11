//! Panic-safety net for the libinjection port. The engine runs on attacker-
//! controlled request bytes, so `is_sqli` / `is_sqli_bytes` must never panic —
//! no slice-out-of-bounds, no usize underflow, no UTF-8 boundary slice — on any
//! input. This throws a large deterministic set of adversarial byte strings at
//! it (structured edge cases + a pseudo-random sweep) and asserts it returns
//! rather than unwinds. Correctness vs. libinjection is covered separately by
//! `libinjection_oracle.rs`; this file only guards liveness.

use fluxgate_waf::sqli::libinjection as li;

/// Deterministic LCG so the sweep is reproducible (no rng dependency).
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

/// Every input must run to completion (the test panics → fails if `is_sqli` does).
fn probe(bytes: &[u8]) {
    let _ = li::is_sqli_bytes(bytes);
    if let Ok(s) = std::str::from_utf8(bytes) {
        let _ = li::is_sqli(s);
    }
}

#[test]
fn structured_edge_cases_do_not_panic() {
    // Lone trailing metacharacters (truncated escapes / unterminated tokens).
    let singles = [
        "", "%", "\\", "'", "\"", "`", "/", "-", "#", "(", ")", ",", ";", "@", "0x", "%u", "%uX",
        "\\u", "\\x", "/*", "*/", "--", "/*!", "/*!5", "0x", "0X", "'\\", "\"\\", "`\\", "1e",
        "1.", ".1", "0b", "00", "@@", "@@@",
    ];
    for s in singles {
        probe(s.as_bytes());
    }

    // Long repetitions of each tricky fragment at various lengths.
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
        b"} ",
        b"a {`",
        b"$",
        b"$a$",
        b"q'",
        b"q'(",
        b"[",
        b"]",
        b"0x",
        b"\\u",
        b"%u",
        b"@@",
        b"1e",
        b" or ",
        b"union select ",
        b"/*!50000",
        b"\xC0",
        b"\xFF",
        b"\x00",
        b"\xA0",
        b"\xE0\x80",
        b"\xF0",
    ];
    for f in frags {
        for n in [1usize, 2, 3, 7, 64, 257, 1024] {
            let mut buf = Vec::with_capacity(f.len() * n);
            for _ in 0..n {
                buf.extend_from_slice(f);
            }
            probe(&buf);
            // Same, with a leading quote to force the alternate parse contexts.
            let mut q = vec![b'\''];
            q.extend_from_slice(&buf);
            probe(&q);
        }
    }

    // Every single byte value, alone and doubled.
    for b in 0u16..256 {
        probe(&[b as u8]);
        probe(&[b as u8, b as u8]);
        probe(&[b'\'', b as u8]);
        probe(&[b'1', b as u8, b'1']);
    }
}

#[test]
fn pseudorandom_sweep_does_not_panic() {
    let mut rng = Lcg(0x1234_5678_9abc_def0);
    // Bias toward SQL-ish bytes so deep code paths (fold, contexts) get hit.
    const ALPHABET: &[u8] = b"abcdefgxyz0123 '\"`()[]{}/*-#,;@=<>|&%$\\.\x00\xFF\xC0\xA0";
    for _ in 0..20_000 {
        let len = (rng.next() % 96) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            // Half the time a structured SQL byte, half a fully random byte.
            if rng.next() & 1 == 0 {
                let idx = (rng.next() as usize) % ALPHABET.len();
                buf.push(ALPHABET[idx]);
            } else {
                buf.push(rng.byte());
            }
        }
        probe(&buf);
    }
}
