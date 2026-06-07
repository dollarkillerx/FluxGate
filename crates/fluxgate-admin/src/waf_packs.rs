//! Bundled WAF rule packs the operator can import on demand.
//!
//! The **OWASP CRS pack** is a curated subset of detection signatures adapted
//! from the OWASP ModSecurity **Core Rule Set** (Apache-2.0). CRS itself targets
//! the ModSecurity/Coraza SecLang engine (anomaly scoring, transformations,
//! libinjection, phrase files) which our simpler regex engine doesn't run, so
//! these are *reimplemented as standalone regex rules* for our model. They are
//! NOT enabled by default — import them explicitly. All rules benefit from the
//! engine's path+query inspection and percent-decode normalization.
//!
//! Attribution: derived from OWASP CRS — https://github.com/coreruleset/coreruleset

use fluxgate_core::*;

/// A pack the operator can list and import.
pub struct Pack {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub rules: fn() -> Vec<WafRule>,
}

/// All available packs.
pub fn packs() -> Vec<Pack> {
    vec![Pack {
        id: "owasp-crs",
        name: "OWASP CRS (subset)",
        description: "Curated detection signatures adapted from the OWASP Core Rule Set: \
             SQLi, XSS, RCE, LFI/RFI, PHP/Java injection, SSRF, protocol attacks, \
             scanners, and sensitive admin paths.",
        rules: owasp_crs_pack,
    }]
}

/// Look up a pack's rules by id.
pub fn pack_rules(id: &str) -> Option<Vec<WafRule>> {
    packs()
        .into_iter()
        .find(|p| p.id == id)
        .map(|p| (p.rules)())
}

fn rule(
    id: &str,
    name: &str,
    description: &str,
    match_type: WafMatchType,
    pattern: &str,
    action: WafAction,
    priority: u32,
) -> WafRule {
    WafRule {
        id: id.into(),
        name: name.into(),
        description: description.into(),
        match_type,
        pattern: pattern.into(),
        action,
        priority,
        enabled: true,
        hit_count: 0,
    }
}

/// OWASP CRS-derived signatures. Precise/high-confidence patterns use `Deny`
/// (403); broader patterns use `Challenge` (429) to reduce breakage. Operators
/// can tune actions or disable individual rules after import. Priorities sit in
/// the 50–99 band, after the built-in baseline (5–40).
fn owasp_crs_pack() -> Vec<WafRule> {
    use WafAction::{Challenge, Deny};
    use WafMatchType::{Header, Path};
    vec![
        // -- SQL injection (CRS 942) -------------------------------------------
        rule(
            "crs-942-sqli-authbypass",
            "CRS: SQLi auth bypass",
            "Classic ' OR 1=1 / ' OR 'a'='a authentication bypass.",
            Path,
            r"(?i)['\x22]\s*(or|and)\s+['\x22]?\w+['\x22]?\s*(=|like)\s*['\x22]?\w+",
            Deny,
            50,
        ),
        rule(
            "crs-942-sqli-keywords",
            "CRS: SQLi keywords",
            "UNION SELECT / stacked DDL / INTO OUTFILE / information_schema.",
            Path,
            r"(?i)(\bunion\b\s+(all\s+)?\bselect\b|;\s*(drop|alter|create|truncate|rename)\s+(table|database|schema)\b|\binto\s+(out|dump)file\b|\binformation_schema\b|\bsysdatabases\b|\bxp_cmdshell\b|\bopenrowset\b)",
            Deny,
            51,
        ),
        rule(
            "crs-942-sqli-functions",
            "CRS: SQLi functions / time-based",
            "Blind/time-based and error-based SQLi functions.",
            Path,
            r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.receive_message|extractvalue|updatexml|exp|load_file|group_concat|concat_ws|json_keys)\s*\(",
            Deny,
            52,
        ),
        rule(
            "crs-942-sqli-operators",
            "CRS: SQLi operators / comments",
            "Inline comments, version comments, hex blobs and SQL meta-operators.",
            Path,
            r"(?i)(/\*![0-9]*|\bxor\b|\brlike\b|\bregexp\b|0x[0-9a-f]{8,}|\bchar\s*\(\s*\d+|\bunhex\s*\(|@@(version|datadir|hostname)\b|\bcast\s*\(.*\bas\b)",
            Challenge,
            53,
        ),
        // -- XSS (CRS 941) -----------------------------------------------------
        rule(
            "crs-941-xss-tags",
            "CRS: XSS HTML tags",
            "Script/SVG/iframe/object/embed and other active-content tags.",
            Path,
            r"(?i)<\s*(script|svg|iframe|object|embed|applet|meta|base|form|isindex|marquee|video|audio|details|math|template|frame|frameset|link|style)\b",
            Deny,
            55,
        ),
        rule(
            "crs-941-xss-events",
            "CRS: XSS event handlers / sinks",
            "Inline on* handlers and common JS sinks.",
            Path,
            r"(?i)(\bon(error|load|click|mouseover|mouseenter|focus|blur|submit|toggle|animationstart|animationend|transitionend|pointerover|beforescriptexecute)\s*=|document\s*\.\s*(cookie|write|location)|window\s*\.\s*(location|name)|\.innerhtml\b|\beval\s*\(|set(timeout|interval)\s*\(|new\s+function\b|fromcharcode\b|expression\s*\()",
            Deny,
            56,
        ),
        rule(
            "crs-941-xss-uris",
            "CRS: XSS dangerous URIs",
            "javascript:/vbscript:/data:text-html and @import payloads.",
            Path,
            r"(?i)(javascript:|vbscript:|livescript:|mocha:|data:text/html|data:application/|@import\b|<!\[cdata\[)",
            Deny,
            57,
        ),
        // -- Local/Remote file inclusion (CRS 930/931) -------------------------
        rule(
            "crs-930-lfi",
            "CRS: Local file inclusion",
            "Traversal sequences and sensitive system files / proc entries.",
            Path,
            r"(?i)((\.\.[\\/]){2,}|/etc/(passwd|shadow|group|hosts|mysql|apache2|nginx)\b|/proc/(self|\d+)/(environ|cmdline|fd|maps)|boot\.ini|/windows/(system32|win\.ini)|\\windows\\)",
            Deny,
            60,
        ),
        rule(
            "crs-931-rfi",
            "CRS: Remote file inclusion",
            "Remote URL passed to an include/require or fetched via a wrapper.",
            Path,
            r"(?i)((include|require)(_once)?\s*\(\s*['\x22]?(https?|ftp|php|data|expect)://|=\s*(https?|ftp)://[^&]+\?$|(php|file|data|expect|zip|phar|glob|ssh2|ogg)://)",
            Deny,
            61,
        ),
        // -- Remote command execution (CRS 932) -------------------------------
        rule(
            "crs-932-rce-unix",
            "CRS: Unix command injection",
            "Shell metacharacter followed by a common unix command.",
            Path,
            r"(?i)[;&|`$(]\s*/?\b(cat|nc|ncat|netcat|wget|curl|chmod|chown|rm|mv|cp|ls|ps|kill|crontab|nohup|telnet|ssh|ftp|tftp|base64|xxd|perl|python[23]?|ruby|lua|gcc|tcpdash|tcpdump|whoami|uname|id|hostname)\b",
            Deny,
            65,
        ),
        rule(
            "crs-932-rce-windows",
            "CRS: Windows command injection",
            "cmd/powershell/certutil/bitsadmin/wmic and LOLBins.",
            Path,
            r"(?i)(\bcmd(\.exe)?\s*/c\b|\bpowershell(\.exe)?\b|\bcertutil\b|\bbitsadmin\b|\bwmic\b|\bmshta\b|\bregsvr32\b|\bnet\s+(user|localgroup|use)\b|\breg\s+add\b|\bschtasks\b)",
            Deny,
            66,
        ),
        rule(
            "crs-933-php",
            "CRS: PHP injection",
            "Dangerous PHP functions, wrappers and superglobals.",
            Path,
            r"(?i)(\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|assert|create_function|call_user_func(_array)?|base64_decode|gzinflate|str_rot13|file_get_contents|fsockopen)\s*\(|<\?php\b|\bphpinfo\s*\(|\$_(get|post|request|cookie|server|files|env|session)\b|preg_replace\s*\(\s*['\x22].*/e)",
            Deny,
            67,
        ),
        rule(
            "crs-944-java",
            "CRS: Java / template injection",
            "OGNL/SpEL expression injection and Java runtime/deserialization markers.",
            Path,
            r"(?i)(#\{.*\}|%\{.*\}|\bognl\b|getruntime\s*\(\s*\)|processbuilder\b|classloader\b|\bnashorn\b|javax\.script|runtime\.exec|\bforname\s*\(|rO0AB[A-Za-z0-9+/])",
            Deny,
            68,
        ),
        // -- SSRF / cloud metadata --------------------------------------------
        rule(
            "crs-ssrf-metadata",
            "CRS: SSRF to cloud metadata",
            "Access to cloud-instance metadata endpoints (AWS/GCP/Azure).",
            Path,
            r"(?i)(169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/|/computemetadata/|/metadata/instance\b)",
            Deny,
            70,
        ),
        // -- Protocol / evasion (CRS 921/920) ---------------------------------
        rule(
            "crs-921-nullbyte",
            "CRS: Null-byte / control chars",
            "Embedded null byte (decoded %00) used to truncate handlers.",
            Path,
            r"\x00",
            Deny,
            72,
        ),
        // -- Scanners & attack tools (CRS 913) --------------------------------
        rule(
            "crs-913-scanner-ua",
            "CRS: Scanner / attack-tool User-Agent",
            "Extended list of vulnerability scanners and offensive tools.",
            Header,
            r"User-Agent: (?i)\b(arachni|brutus|cgichk|commix|dirb|whatweb|skipfish|w3af|openvas|qualys|burpsuite|burp|paros|webinspect|appscan|grendel|jaeles|xsstrike|sqlninja|havij|pangolin|metasploit|nuclei|ffuf|katana|sqlmap|nikto|nmap|masscan|nessus|acunetix|netsparker|wpscan|gobuster|feroxbuster)\b",
            Deny,
            75,
        ),
        rule(
            "crs-913-scanner-header",
            "CRS: Scanner fingerprint headers",
            "Headers injected by Acunetix / generic scanners.",
            Header,
            r"Acunetix-Aspect: (?i).+",
            Deny,
            76,
        ),
        // -- Sensitive paths / admin surfaces ---------------------------------
        rule(
            "crs-sensitive-paths",
            "CRS: Sensitive admin paths",
            "Common admin consoles, VCS metadata and debug endpoints.",
            Path,
            r"(?i)/(phpmyadmin|pma|adminer|wp-admin/install|\.git/(config|head)|\.svn/entries|\.hg/|actuator/(env|heapdump|threaddump|mappings)|server-status|server-info|jmx-console|web-console|manager/html|/solr/admin|/_cat/indices|/owa/auth)",
            Challenge,
            80,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_lookup_and_uniqueness() {
        let rules = pack_rules("owasp-crs").expect("owasp-crs pack exists");
        assert!(rules.len() >= 15);
        let ids: std::collections::HashSet<_> = rules.iter().map(|r| r.id.clone()).collect();
        assert_eq!(ids.len(), rules.len(), "pack rule ids must be unique");
        assert!(pack_rules("does-not-exist").is_none());
    }

    /// Every pack rule's pattern must compile — a broken regex would silently
    /// never match (a security hole).
    #[test]
    fn pack_patterns_compile() {
        for r in pack_rules("owasp-crs").unwrap() {
            match r.match_type {
                WafMatchType::Path | WafMatchType::Method => {
                    regex::Regex::new(&r.pattern)
                        .unwrap_or_else(|e| panic!("rule {} bad regex: {e}", r.id));
                }
                WafMatchType::Header => {
                    let (_n, pat) = r.pattern.split_once(':').unwrap();
                    regex::Regex::new(pat.trim())
                        .unwrap_or_else(|e| panic!("rule {} bad header regex: {e}", r.id));
                }
                _ => {}
            }
        }
    }
}
