//! Regression tests for bugs found by the post-port audit — cases the upstream
//! libinjection oracle vectors do NOT cover (which is why the port shipped with
//! them). Each asserts the port now matches libinjection's C behavior.

use fluxgate_waf::sqli::libinjection as li;

/// Audit finding 1 (HIGH): the `{`-bareword EVIL fold case returns `left + 2`,
/// which can reach 7 and overflowed the undersized 6-byte fingerprint buffer at
/// `fp[tlen] = NUL` — a remotely-triggerable panic AND a missed detection. C uses
/// an 8-byte buffer and returns the EVIL fingerprint `"X"`.
#[test]
fn brace_bareword_evil_does_not_panic() {
    assert_eq!(li::is_sqli("a a a a {`"), Some("X".to_string()));
    // The minimal raw-byte trigger the fuzzer surfaced.
    assert_eq!(
        li::is_sqli_bytes(&[0x35, 0xf9, 0x5d, 0xe7, 0x7b, 0x60]),
        Some("X".to_string())
    );
}

/// Audit finding 3 (MEDIUM, false negative): the `1c` not-whitelist rule reads
/// the byte after the number with C's *signed* char semantics — a high byte
/// (>=0x80) is negative there, so `ch <= 32` holds and the input is SQLi. With
/// `u8` and no high-byte branch, the port wrongly returned benign.
#[test]
fn number_comment_high_byte_is_sqli() {
    // `1`, then 0xA0 (a whitespace byte per char_is_white), then a `--` comment:
    // folds to the "1c" fingerprint; the high byte after the number => SQLi.
    assert_eq!(
        li::is_sqli_bytes(&[b'1', 0xa0, b'-', b'-', b' ']),
        Some("1c".to_string())
    );
}

/// Differential-test finding (false negative): C's `strlenspn`/`strlencspn` use
/// `strchr`, which matches `accept`'s NUL terminator — so a NUL byte counts as a
/// member of every set. `$\0` therefore parses as a NUMBER (not a bareword), and
/// `$\0--` is SQLi `"1c"`. The port now replicates the quirk.
#[test]
fn nul_byte_is_a_member_of_every_accept_set() {
    assert_eq!(li::is_sqli_bytes(b"$\x00--"), Some("1c".to_string()));
}

/// Audit finding 2 (MEDIUM, fidelity): `q'` followed by a high byte must fall
/// back to a word (C's signed-char `< 33`), not be parsed as a q-string. We can
/// at least pin that it tokenizes without error and is treated as benign here.
#[test]
fn qstring_high_byte_parses_as_word() {
    assert_eq!(
        li::is_sqli_bytes(&[b'q', b'\'', 0xa0, b'a', b'b', b'c']),
        None
    );
}
