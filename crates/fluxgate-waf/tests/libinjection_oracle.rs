//! Oracle test: validates the pure-Rust libinjection port against
//! libinjection's OWN vendored test vectors.
//!
//! The vector files live in the (read-only) sibling clone at
//! `/Users/github/Documents/workspace/libinjection/tests/` — they are NOT part
//! of the FluxGate repo, so this test is skipped (passes vacuously) if that
//! directory is absent.
//!
//! The parsing/printing contract replicates libinjection's
//! `python/test_driver.py` exactly:
//!   * `readtestdata`: rstrip each line; sections are `--TEST--`, `--INPUT--`,
//!     `--EXPECTED--`; INPUT has its trailing newline removed then `.strip()`;
//!     EXPECTED is `.strip()`.
//!   * tokens   : FLAG_QUOTE_NONE | FLAG_SQL_ANSI, loop tokenize, print tokens.
//!   * folding  : FLAG_QUOTE_NONE | FLAG_SQL_ANSI, fold, print tokens.
//!   * fingerprints: flags = 0, is_sqli; output = fingerprint if sqli else "".

use std::path::{Path, PathBuf};

// Pull in the port's test-only debug helpers via the crate.
use fluxgate_waf::sqli::libinjection as li;

const TESTS_DIR: &str = "/Users/github/Documents/workspace/libinjection/tests";

/// `bytes.rstrip()` — strip trailing ASCII whitespace (` \t\n\v\f\r`).
fn rstrip(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && matches!(b[end - 1], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        end -= 1;
    }
    &b[..end]
}

/// `bytes.strip()` — strip leading+trailing ASCII whitespace.
fn strip(b: &[u8]) -> &[u8] {
    let r = rstrip(b);
    let mut start = 0;
    while start < r.len() && matches!(r[start], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        start += 1;
    }
    &r[start..]
}

/// Parse a `--TEST--/--INPUT--/--EXPECTED--` file the same way the Python
/// driver's `readtestdata` does, but byte-faithfully (one vector file uses a
/// 0xA0 byte that isn't valid UTF-8). Returns `(input_bytes, expected_string)`.
///
/// EXPECTED is the printed-token form which is always valid UTF-8.
fn read_testdata(path: &Path) -> (Vec<u8>, String) {
    let raw = std::fs::read(path).expect("read test file");
    let mut section: Option<&str> = None;
    let mut input: Vec<u8> = Vec::new();
    let mut expected: Vec<u8> = Vec::new();

    for line in raw.split(|&b| b == b'\n') {
        let line = rstrip(line);
        match line {
            b"--TEST--" => section = Some("test"),
            b"--INPUT--" => section = Some("input"),
            b"--EXPECTED--" => section = Some("expected"),
            _ => match section {
                Some("input") => {
                    input.extend_from_slice(line);
                    input.push(b'\n');
                }
                Some("expected") => {
                    expected.extend_from_slice(line);
                    expected.push(b'\n');
                }
                _ => {}
            },
        }
    }

    // remove last newline from input (Python: info['--INPUT--'][0:-1])
    if input.last() == Some(&b'\n') {
        input.pop();
    }
    let input = strip(&input).to_vec();
    let expected = String::from_utf8_lossy(strip(&expected)).into_owned();
    (input, expected)
}

fn glob_tests(prefix: &str) -> Vec<PathBuf> {
    let dir = Path::new(TESTS_DIR);
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(prefix) && n.ends_with(".txt"))
                .unwrap_or(false)
        })
        .collect();
    out.sort();
    out
}

fn tests_available() -> bool {
    Path::new(TESTS_DIR).is_dir()
}

#[test]
fn oracle_tokens() {
    if !tests_available() {
        eprintln!("skip: {TESTS_DIR} not present");
        return;
    }
    let files = glob_tests("test-tokens-");
    assert!(!files.is_empty(), "no token test files found");
    let mut total = 0;
    let mut pass = 0;
    let mut fails = Vec::new();
    for f in &files {
        total += 1;
        let (input, expected) = read_testdata(f);
        let actual =
            li::debug_tokenize(&input, li::flag_quote_none() | li::flag_sql_ansi()).join("\n");
        let actual = actual.trim().to_string();
        let input = String::from_utf8_lossy(&input).into_owned();
        if actual == expected {
            pass += 1;
        } else {
            fails.push((f.clone(), input, expected, actual));
        }
    }
    report("tokens", pass, total, &fails);
}

#[test]
fn oracle_folding() {
    if !tests_available() {
        eprintln!("skip: {TESTS_DIR} not present");
        return;
    }
    let files = glob_tests("test-folding-");
    assert!(!files.is_empty(), "no folding test files found");
    let mut total = 0;
    let mut pass = 0;
    let mut fails = Vec::new();
    for f in &files {
        total += 1;
        let (input, expected) = read_testdata(f);
        let actual = li::debug_fold(&input, li::flag_quote_none() | li::flag_sql_ansi()).join("\n");
        let actual = actual.trim().to_string();
        let input = String::from_utf8_lossy(&input).into_owned();
        if actual == expected {
            pass += 1;
        } else {
            fails.push((f.clone(), input, expected, actual));
        }
    }
    report("folding", pass, total, &fails);
}

#[test]
fn oracle_sqli() {
    if !tests_available() {
        eprintln!("skip: {TESTS_DIR} not present");
        return;
    }
    let files = glob_tests("test-sqli-");
    assert!(!files.is_empty(), "no sqli test files found");
    let mut total = 0;
    let mut pass = 0;
    let mut fails = Vec::new();
    for f in &files {
        total += 1;
        let (input, expected) = read_testdata(f);
        // fingerprints mode uses flags = 0 (== default ANSI/NONE) via is_sqli.
        let actual = li::is_sqli_bytes(&input).unwrap_or_default();
        let input = String::from_utf8_lossy(&input).into_owned();
        if actual == expected {
            pass += 1;
        } else {
            fails.push((f.clone(), input, expected, actual));
        }
    }
    report("sqli", pass, total, &fails);
}

#[allow(clippy::type_complexity)]
fn report(name: &str, pass: usize, total: usize, fails: &[(PathBuf, String, String, String)]) {
    eprintln!("[{name}] {pass}/{total}");
    for (f, input, expected, actual) in fails {
        eprintln!(
            "  FAIL {}\n    INPUT:    {:?}\n    EXPECTED: {:?}\n    GOT:      {:?}",
            f.file_name().unwrap().to_string_lossy(),
            input,
            expected,
            actual
        );
    }
    assert_eq!(pass, total, "{name}: {} failure(s)", total - pass);
}
