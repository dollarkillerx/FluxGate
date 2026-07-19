# FluxGate

English · [中文](./README-CN.md)

A **reverse proxy with a built-in WAF and admin panel** — a single Rust binary
that forwards traffic, terminates TLS (with automatic Let's Encrypt / ACME
certificates), enforces a Web Application Firewall, and is managed entirely
through a clean web console (English / 中文 / 日本語).

![FluxGate](image.png)

## Features

- 🔁 **Reverse proxy** — sites & path routes, load balancing, WebSocket & streaming
- 🔀 **L4 / TLS-SNI passthrough** — match a **ClientHello SNI** on the shared `:443` and forward the raw TCP stream **verbatim** to an origin, **never terminating TLS** — so TLS and the app protocol stay end-to-end (VLESS-**Reality**, **AnyTLS**, or any opaque-TLS backend). Exact **and** one-label wildcard (`*.example.com`) SNI rules, origins load-balanced (round-robin / least-conn / IP-hash). Any SNI that matches no L4 route **falls through to the normal L7 HTTPS proxy**, so L4 and L7 coexist on **one port**. Managed from the **L4** console page — see [**L4 / TLS-SNI passthrough**](#l4--tls-sni-passthrough)
- ↪️ **Redirects** — per-site **301 / 302** rules: match a path **exactly** or by **prefix** (`/old*`) and send visitors to a full URL or a `/path`, answered at the edge before proxying. Plus a one-toggle **HTTP→HTTPS** (308) redirect per site
- 🛡️ **WAF — semantic, structure-aware** — a **12-module detection engine** that *parses each request's structure* instead of keyword-matching, with **libinjection-grade** SQLi/XSS, plus SSTI / NoSQL / XXE / deserialization / **PHP** & **Java-OGNL/SpEL** injection and **HTTP request-smuggling** — catching evasions with **far fewer false positives**. CRS-style **anomaly scoring**, **per-route monitor/block** mode, one-click **false-positive → exception**. A thin regex layer keeps IP (IPv4 **+ IPv6**) / path / method / geo / rate-limit / **body** policy rules + virtual patching; managed human-verification challenge; per-IP admin **brute-force lockout**. Inspects request line, headers **_and_** body — see [**Web Application Firewall**](#web-application-firewall)
- 🌍 **Per-site access control** — block by **country** (GeoIP), block **datacenter / cloud IPs** (ASN ≈ "residential only"), accept **only Cloudflare** traffic, or **browser-only** (User-Agent allow-list). Bound to the site and enforced **even when the WAF is off**; Cloudflare-aware (`CF-Connecting-IP`)
- 🚫 **IP allow / block lists + auto-ban** — manual allow (full-trust) & block lists, plus optional **auto-ban**: block an IP after _N_ WAF denies in 24h, for a set duration or permanently. Dual-stack (IPv4/IPv6), with one-click unban
- 🔐 **TLS** — SNI certificate selection + **automatic ACME (Let's Encrypt) issuance & renewal** over HTTP-01
- 📊 **Analytics & risk board** — real-time 24h QPS / PV / UV, latency, error rate, visitor-country map, **device / OS breakdown**, per-site **traffic totals** (lifetime / 30-day / today), and a **risk board** (WAF blocks 24h, top attacker User-Agents, attack-origin countries)
- 🖥️ **Admin console** — embedded in the binary, no separate deploy; tri-lingual UI; branded block / challenge / 404 pages

## Install

```bash
curl https://raw.githubusercontent.com/dollarkillerx/FluxGate/refs/heads/main/install.sh | bash
```

That's it. The installer (run as root; prepend `sudo` if you're not) will:

1. let you **pick a language**, then an admin **account + password**
2. install a **systemd service**, with the proxy on `:80` / `:443` and the
   console on a **random high port**
3. print the **console URL, account and password** when done

Re-run the same command later to get a **stop / restart / update** menu
(`--update` does a zero-downtime upgrade with automatic rollback).

> The console uses a self-signed HTTPS certificate — accept the browser warning
> on first visit. ACME issuance needs your domain to resolve to the host and
> port 80 reachable from the internet.
>
> Each site supports **301 / 302 redirect rules** (match a path exactly or by
> `/old*` prefix → a full URL or `/path`), evaluated at the edge before routing.
>
> Each site also has **Advanced options** — upload cap (default 500 MB), upstream
> timeout (120 s), crawler blocking, browser-only, and **IP access control**
> (block countries, block datacenter/cloud IPs, or Cloudflare-only).
>
> **IP-based controls** (geo / datacenter / blacklist / auto-ban) judge the real
> client IP — the socket peer by default, or `CF-Connecting-IP` for sites with
> **Only allow Cloudflare** enabled (that toggle both locks the origin to
> Cloudflare _and_ marks the site CF-fronted). So enable it on Cloudflare-fronted
> sites to get real visitor IPs; behind a **non-Cloudflare** proxy you'll get the
> proxy IP — whitelist it, or prefer Cloudflare / direct exposure.

## Run from source

```bash
cd web && npm install && npm run build    # build the console (embedded into the binary)
cargo run -p fluxgate-admin                # start FluxGate
```

The **admin console** is then at **`https://127.0.0.1:8080/`** — HTTPS with a
self-signed cert (accept the browser warning); default login **`admin` / `admin`**.
The reverse-proxy data plane defaults to `:80` / `:443`; on a dev machine point it
at high ports so it doesn't need root:

```bash
FLUXGATE_PROXY_ADDR=127.0.0.1:8888 FLUXGATE_PROXY_TLS_ADDR= cargo run -p fluxgate-admin
```

**Frontend hot-reload** (optional): with FluxGate running, start the Vite dev
server in a second terminal — `cd web && npm run dev` — and open
**`http://localhost:5173/`**; it proxies `/rpc` and `/health` to the backend.
GeoIP / ASN databases auto-download on first start (or set `FLUXGATE_GEOIP_DB`
/ `FLUXGATE_ASN_DB`).

## L4 / TLS-SNI passthrough

Most routes in FluxGate are **L7**: it terminates TLS, inspects the HTTP request,
runs the WAF, and proxies to an upstream. Some backends can't be terminated —
they run their **own** TLS on top of a raw TCP stream (VLESS-Reality, AnyTLS, a
private mTLS service). For those, FluxGate offers **L4 passthrough**.

An **L4 route** claims one or more **SNI** names. On the shared `:443` ingress
FluxGate peeks *only* the TLS **ClientHello** — just enough to read the SNI, never
decrypting — then:

- **SNI matches an L4 route** → the ClientHello (byte-for-byte) **and** the rest of
  the connection are spliced straight through to the selected origin. TLS is
  **never terminated**; the client and origin do a normal end-to-end handshake.
- **SNI matches nothing** → the peeked bytes are replayed into the **normal L7
  HTTPS proxy** (WAF, ACME, routing). Nothing is lost.

So L4 and L7 **share port 443** — no second listener, no port juggling.

Matching is **exact first, then the most-specific one-label wildcard**
(`*.example.com` matches `a.example.com`, but not the apex or `a.b.example.com`).
Each route lists one or more `host:port` **origins**, load-balanced by
**round-robin / least-conn / IP-hash** (IP-hash keeps a client pinned to one
origin — handy for stateful TLS protocols), with a configurable connect timeout.

Manage it all on the **L4** page of the console (or the `l4route.*` RPC methods):
give the route a name, the SNI(s), the origin(s), a strategy, and toggle it on.

## Web Application Firewall

Most WAFs match attacks with broad keyword regexes — easy to evade, and noisy with
false positives. FluxGate leads with a **semantic engine** that *parses the
structure* of every request value (decode → tokenize/parse → judge the construct),
and keeps regex only for what it's genuinely good at: policy and virtual patching.

- **Structure-aware detection — 12 modules.** SQLi, XSS, path traversal, command
  injection, SSRF, protocol (NUL/CRLF), SSTI, NoSQL, XXE, deserialization,
  **PHP function injection**, and **Java / OGNL / SpEL** injection — plus
  transport-level **HTTP request-smuggling** (CL.TE / TE.CL) detection.
- **libinjection-grade SQLi & XSS.** A byte-faithful pure-Rust port of
  libinjection's SQLi fingerprint engine and HTML5 XSS tokenizer, validated against
  the original C by a **300k-input differential test** plus its own oracle vectors.
- **Far fewer false positives.** `union select tutorial` (prose) and a *mention* of
  `shell_exec` are **not** flagged; a real `' OR 1=1--` or `shell_exec(...)` **call**
  is. Detection runs **per extracted value**, so a payload can't bleed across
  `&`/`=` boundaries, and each value is multi-layer decoded first.
- **Anomaly scoring (CRS-style).** Several individually-weak signals on one request
  add up and escalate the action — catching what no single rule would.
- **Operator workflow.** Per-route **Monitor / Block** mode (gradual rollout),
  one-click **false-positive → exception**, and a decision trace on every event.
- **Regex is for policy, not detection.** IP / path / method / geo / rate-limit /
  body rules, explicit allow, and instant **virtual patching** for 0-days. The broad
  CRS *detection* rules are superseded by the semantic engine and ship disabled.
- **Fast & safe.** ~2 µs/request, **lock-free** hot path (scales linearly across
  cores); detector panics fail-open; body inspection is bounded to a 64 KB prefix,
  so large uploads stream through without buffering.

### Adversarial validation — does it actually catch attacks?

A **red-team battery** ships with the engine and runs as a regression guard: real
attack payloads + known WAF-evasion variants across all 12 modules, look-alike
benign traffic, and a set of *hard* bypass techniques.

| | Result |
| --- | --- |
| **Attack recall** | **81 / 81 caught (100 %)** — SQLi · XSS · RCE · traversal · SSRF · SSTI · NoSQL · XXE · deserialization · PHP · OGNL/SpEL, incl. comment/case/encoding evasions |
| **False positives** | **0 / 35** — prose (`union select tutorial`), code talk (`how to use shell_exec`), templates (`${user.name}`), names (`O'Brien`), URLs — all pass clean |
| **Hard evasions** | **13 / 14 caught** — overlong-UTF-8 `%c0%af`, space-less `${IFS}` RCE, `nip.io` DNS-rebind to loopback, double/percent-encoding, MySQL versioned comments… |

The `100 % recall + 0 false positives` is **asserted** (a permanent guard — it can't
silently regress), and SQLi/XSS are additionally checked **byte-for-byte against C
libinjection** by a **300 k-input differential test** + a fuzzer. The single
documented miss (a unicode-digit IP that no real HTTP stack resolves) is tracked,
not hidden — adversarial testing you can re-run, not a marketing claim:

```bash
cargo test -p fluxgate-waf --release --test corpus -- --ignored --nocapture red_team
```

## Performance

One Rust binary, no sidecars. Measured on an Apple Silicon laptop, `--release`,
single core unless noted. Every figure below is reproducible from an `#[ignore]`
bench in the tree (commands inline).

### What enabling the WAF costs per request

The semantic engine is **structure-aware** — parameter extraction → multi-layer
decode → byte-class prefilter + one shared Aho-Corasick pass → gated detectors —
so the benign hot path is allocation-free and lock-free (`ArcSwap` wait-free
config reads). Turning the WAF *on* adds exactly the regex-rule pass plus the
semantic pass; *off* skips them entirely (0 added):

| Full WAF cost per request (OWASP-CRS rules + all 12 semantic modules) | added |
| --- | --- |
| benign `GET` (regex eval + semantic, no match) | **~1.9 µs** |
| attack `GET` (SQLi — a regex rule matches early) | **~2.5 µs** |

<sub>`cargo test -p fluxgate-admin --release waf_overhead -- --ignored --nocapture`</sub>

The semantic analysis is the dominant part, and most of it never runs on benign
traffic (the prefilter gates keep values out of the detectors):

| Semantic analysis (per request) | cost |
| --- | --- |
| benign (5 params + UA + 3 cookies → ~18 inspected values) | ~1.2 µs |
| SQLi in query | ~1.7 µs |
| benign JSON API body (6 fields) | ~0.5 µs |

<sub>`cargo test -p fluxgate-waf --release --test corpus -- --ignored bench_semantic`</sub>

### End-to-end throughput — WAF off vs on

Real proxy over TCP + mock upstream, 32 keep-alive connections × 1500 benign
`GET`s (loopback; client, proxy and upstream all share the runtime):

| | QPS | p50 | p99 |
| --- | --- | --- | --- |
| WAF **off** | ~52,000 | ~580 µs | ~1.0 ms |
| WAF **on** (CRS + all semantic modules) | ~51,000 | ~620 µs | ~1.1 ms |

<sub>`cargo test -p fluxgate-admin --release waf_qps -- --ignored --nocapture`</sub>

The on/off gap (~0–10 % run-to-run) sits **within the measurement noise** of this
saturated loopback setup — i.e. the ~2 µs of CPU the WAF adds is too small to
reliably distinguish from scheduler jitter at 50k+ QPS. In a real deployment,
where the upstream round-trip is milliseconds and the proxy has its own cores, the
WAF is a low-single-digit-percent tax at most.

The WAF is **per-route** (disabled routes pay nothing) and the benign hot path is
**lock-free**, so it scales linearly across cores. Body inspection reads only a
bounded **64 KB** prefix — a malicious `…union select…from users` POST body is
blocked while larger uploads **stream through without buffering** (zero-copy past
the scan window).
