# FluxGate

English · [中文](./README-CN.md)

A **reverse proxy with a built-in WAF and admin panel** — a single Rust binary
that forwards traffic, terminates TLS (with automatic Let's Encrypt / ACME
certificates), enforces a Web Application Firewall, and is managed entirely
through a clean web console (English / 中文 / 日本語).

![FluxGate](image.png)

## Features

- 🔁 **Reverse proxy** — sites & path routes, load balancing, WebSocket & streaming
- 🛡️ **WAF** — OWASP **Core Rule Set (CRS)** built in (SQLi, XSS, RCE, LFI/RFI, scanner detection…), inspecting the **request line, headers _and_ body**; custom IP / path / method / geo / rate-limit / **body** rules; a managed human-verification challenge; and per-IP **brute-force lockout** on the admin login
- 🔐 **TLS** — SNI certificate selection + **automatic ACME (Let's Encrypt) issuance & renewal** over HTTP-01
- 📊 **Dashboard** — real-time 24h QPS / PV / UV, latency, error rate, visitor-country map (GeoIP)
- 🖥️ **Admin console** — embedded in the binary, no separate deploy; tri-lingual UI

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
> Each site defaults to a **500 MB upload cap** and a **120 s upstream timeout**
> — change them in **Edit Site → Advanced options** (set the cap to 0 for
> unlimited).

## Performance

One Rust binary, no sidecars. Measured on an Apple M5, `--release`.

**WAF rule engine** — per request, single core:

| Pass | Benign (all rules run) | Early match |
| --- | --- | --- |
| request line + headers | ~440 ns | ~210 ns |
| request body (default body rules) | ~280 ns | ~190 ns |

**End-to-end reverse proxy** — ApacheBench, 30k POSTs, concurrency 50, keep-alive,
single box (proxy + upstream local):

| | Throughput | p50 / p99 | Result |
| --- | --- | --- | --- |
| WAF **off** | **~26,900 req/s** | 1 / 7 ms | malicious body passes |
| WAF **on** (full detection + body inspection) | **~21,800 req/s** | 2 / 12 ms | **malicious body → 403** |

Body inspection reads only a bounded **64 KB** prefix, so a malicious
`…union select…from users` payload in a POST body is blocked while larger uploads
still **stream through without buffering** (zero-copy past the scan window). WAF is
per-route — disabled routes pay no WAF cost at all.
