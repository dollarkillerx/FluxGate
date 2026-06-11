//! Oracle test: validates the pure-Rust HTML5 tokenizer port against
//! libinjection's OWN vendored `test-html5-*` vectors.
//!
//! The vector files live in the (read-only) sibling clone at
//! `/Users/github/Documents/workspace/libinjection/tests/` — they are NOT part
//! of the FluxGate repo, so this test is skipped (passes vacuously) if that
//! directory is absent.
//!
//! The parsing/printing contract replicates libinjection's C `testdriver.c`
//! (`read_file` + `print_html5_token`, testtype 3):
//!   * sections are `--TEST--`, `--INPUT--`, `--EXPECTED--`.
//!   * INPUT and EXPECTED are each right-trimmed (`modp_rtrim`).
//!   * tokenize with `DATA_STATE`, print each token as `TYPE,len,text` joined by
//!     `\n`.

use std::path::{Path, PathBuf};

use fluxgate_waf::xss::libinjection as li;

const TESTS_DIR: &str = "/Users/github/Documents/workspace/libinjection/tests";

/// `modp_rtrim` — strip trailing ASCII whitespace (` \t\n\v\f\r`).
fn rtrim(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && matches!(b[end - 1], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        end -= 1;
    }
    &b[..end]
}

/// Parse a `--TEST--/--INPUT--/--EXPECTED--` file byte-faithfully, mirroring the
/// C `read_file`: accumulate each section's lines verbatim, then right-trim the
/// INPUT and EXPECTED blocks. Returns `(input_bytes, expected_string)`.
fn read_testdata(path: &Path) -> (Vec<u8>, String) {
    let raw = std::fs::read(path).expect("read test file");
    let mut section: Option<&str> = None;
    let mut input: Vec<u8> = Vec::new();
    let mut expected: Vec<u8> = Vec::new();

    // The C driver reads with fgets and keeps the trailing '\n' on every line
    // (including the section markers' own newline). We replicate by re-adding a
    // '\n' after each non-marker line, matching `strcat(bufptr, linebuf)`.
    for line in raw.split(|&b| b == b'\n') {
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

    let input = rtrim(&input).to_vec();
    let expected = String::from_utf8_lossy(rtrim(&expected)).into_owned();
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
fn oracle_html5() {
    if !tests_available() {
        eprintln!("skip: {TESTS_DIR} not present");
        return;
    }
    let files = glob_tests("test-html5-");
    assert!(!files.is_empty(), "no html5 test files found");
    let mut total = 0;
    let mut pass = 0;
    let mut fails = Vec::new();
    for f in &files {
        total += 1;
        let (input, expected) = read_testdata(f);
        // The C testdriver `modp_rtrim`s both `g_actual` and `g_expected` before
        // comparing, so a token whose text ends in whitespace has that trailing
        // whitespace stripped from the printed output (test-html5-040).
        let actual_joined = li::debug_html5_tokenize(&input, li::flag_data_state()).join("\n");
        let actual = String::from_utf8_lossy(rtrim(actual_joined.as_bytes())).into_owned();
        let input_s = String::from_utf8_lossy(&input).into_owned();
        if actual == expected {
            pass += 1;
        } else {
            fails.push((f.clone(), input_s, expected, actual));
        }
    }
    eprintln!("[html5] {pass}/{total}");
    for (f, input, expected, actual) in &fails {
        eprintln!(
            "  FAIL {}\n    INPUT:    {:?}\n    EXPECTED: {:?}\n    GOT:      {:?}",
            f.file_name().unwrap().to_string_lossy(),
            input,
            expected,
            actual
        );
    }
    assert_eq!(pass, total, "html5: {} failure(s)", total - pass);
}
