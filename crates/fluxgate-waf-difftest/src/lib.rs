//! FFI binding to the vendored C `libinjection_sqli`, used as the ground-truth
//! oracle in the differential test. The C source is BSD-3 (see
//! `vendor/libinjection/` and `crates/fluxgate-waf/data/ATTRIBUTION.md`).

use std::os::raw::{c_char, c_int};

extern "C" {
    /// `injection_result_t libinjection_sqli(const char *s, size_t slen, char fingerprint[])`.
    /// Returns 1 (SQLi), 0 (benign), or -1 (parse error); writes the fingerprint
    /// (NUL-terminated) into `fingerprint` on a positive result.
    fn libinjection_sqli(s: *const c_char, slen: usize, fingerprint: *mut c_char) -> c_int;

    /// `injection_result_t libinjection_xss(const char *s, size_t slen)`.
    /// Returns 1 (XSS), 0 (benign), or -1 (error).
    fn libinjection_xss(s: *const c_char, slen: usize) -> c_int;
}

/// The C engine's verdict for one input.
#[derive(Debug, PartialEq, Eq)]
pub enum CVerdict {
    /// SQLi, with the libinjection fingerprint.
    Sqli(String),
    Benign,
    /// The rare `LIBINJECTION_RESULT_ERROR` (e.g. a pgsql double-comment edge):
    /// the Rust port has no error variant, so the differential test skips these.
    Error,
}

/// Run the vendored C `libinjection_sqli` over raw bytes.
pub fn c_is_sqli(input: &[u8]) -> CVerdict {
    // libinjection's fingerprint buffer is documented as 8 bytes; use a little
    // extra headroom. The C writes a NUL-terminated string into it.
    let mut fp = [0 as c_char; 16];
    let ret = unsafe {
        libinjection_sqli(
            input.as_ptr() as *const c_char,
            input.len(),
            fp.as_mut_ptr(),
        )
    };
    match ret {
        1 => {
            let bytes: Vec<u8> = fp
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            CVerdict::Sqli(String::from_utf8_lossy(&bytes).into_owned())
        }
        0 => CVerdict::Benign,
        _ => CVerdict::Error,
    }
}

/// The C XSS engine's verdict for one input.
#[derive(Debug, PartialEq, Eq)]
pub enum CXss {
    /// `LIBINJECTION_RESULT_TRUE` — XSS.
    Xss,
    /// `LIBINJECTION_RESULT_FALSE` — benign.
    Benign,
    /// `LIBINJECTION_RESULT_ERROR` — the Rust port has no error variant, so the
    /// differential test skips these.
    Error,
}

/// Run the vendored C `libinjection_xss` over raw bytes.
pub fn c_is_xss(input: &[u8]) -> CXss {
    let ret = unsafe { libinjection_xss(input.as_ptr() as *const c_char, input.len()) };
    match ret {
        1 => CXss::Xss,
        0 => CXss::Benign,
        _ => CXss::Error,
    }
}
