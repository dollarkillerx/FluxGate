# FluxGate

English · [中文](./README-CN.md)

A **reverse proxy with a built-in WAF and admin panel** — a single Rust binary
that forwards traffic, terminates TLS (with automatic Let's Encrypt / ACME
certificates), enforces a Web Application Firewall, and is managed entirely
through a clean web console (English / 中文 / 日本語).

![FluxGate](image.png)

## Features

- 🔁 **Reverse proxy** — sites & path routes, load balancing, WebSocket & streaming
- 🛡️ **WAF** — ships with the full **OWASP Core Rule Set (CRS)** built in (SQLi, XSS, RCE, LFI/RFI, scanner detection…), plus custom IP / path / method / geo / rate-limit rules and a managed human-verification challenge
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
