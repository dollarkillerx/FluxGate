//! Branded HTML pages served by the data plane for blocks and errors.
//!
//! These share one visual language with the WAF challenge interstitial
//! (`challenge.rs`) — the FluxGate wordmark + project link — so an end user who
//! hits a block or an unconfigured host sees a polished page instead of bare
//! text. All content is static (no user input is interpolated), so no escaping
//! is required.

/// FluxGate project URL, linked on every page.
pub const REPO: &str = "https://github.com/dollarkillerx/FluxGate";

/// Inline SVG glyph (a shield with a bolt) — no external assets. Reused by the
/// challenge page too.
pub const GLYPH: &str = r##"<svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 8.3 8 11 4.6-2.7 8-6 8-11V5l-8-3Z" fill="url(#fg)" opacity=".18"/><path d="M12 2 4 5v6c0 5 3.4 8.3 8 11 4.6-2.7 8-6 8-11V5l-8-3Z" stroke="url(#fg)" stroke-width="1.5" stroke-linejoin="round"/><path d="M13 7l-4 6h3l-1 4 4-6h-3l1-4Z" fill="url(#fg)"/><defs><linearGradient id="fg" x1="4" y1="2" x2="20" y2="22"><stop stop-color="#60a5fa"/><stop offset="1" stop-color="#6366f1"/></linearGradient></defs></svg>"##;

/// Shared `<style>` block (dark, glassy card on a soft gradient). The `--accent`
/// custom property tints the status code; callers set it per page.
pub const STYLE: &str = r##"*{box-sizing:border-box}html,body{height:100%;margin:0}
body{display:flex;align-items:center;justify-content:center;padding:1.5rem;
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
color:#e2e8f0;background:#0b1120;background-image:radial-gradient(60rem 40rem at 50% -12%,rgba(99,102,241,.20),transparent),radial-gradient(46rem 36rem at 112% 116%,rgba(56,189,248,.13),transparent)}
.card{width:100%;max-width:30rem;text-align:center;padding:2.5rem 2rem;border-radius:18px;
background:rgba(15,23,42,.62);border:1px solid rgba(148,163,184,.14);
box-shadow:0 24px 60px -20px rgba(0,0,0,.6);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}
.brand{display:inline-flex;align-items:center;gap:.5rem;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;font-size:1.05rem}
.code{margin:1.4rem 0 .2rem;font-size:3.4rem;font-weight:800;line-height:1;
background:linear-gradient(135deg,var(--accent,#60a5fa),#a78bfa);-webkit-background-clip:text;background-clip:text;color:transparent}
h1{font-size:1.15rem;font-weight:650;margin:.5rem 0 .35rem;color:#f8fafc}
p{margin:.35rem auto 0;max-width:24rem;color:#94a3b8}
.sp{width:34px;height:34px;margin:.4rem auto .2rem;border:3px solid rgba(148,163,184,.18);
border-top-color:#818cf8;border-radius:50%;animation:r .8s linear infinite}@keyframes r{to{transform:rotate(360deg)}}
.foot{display:flex;align-items:center;justify-content:center;gap:.35rem;margin-top:1.8rem;padding-top:1.2rem;
border-top:1px solid rgba(148,163,184,.12);font-size:.8rem;color:#64748b}
.foot a{color:#818cf8;text-decoration:none}.foot a:hover{text-decoration:underline}"##;

/// Render a standard page: a status badge, title and subtitle inside the card.
fn render(status: u16, accent: &str, title: &str, subtitle: &str) -> String {
    format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>{title} · FluxGate</title><style>:root{{--accent:{accent}}}{STYLE}</style></head>
<body><div class="card"><div class="brand">{GLYPH}<span>FluxGate</span></div>
<div class="code">{status}</div><h1>{title}</h1><p>{subtitle}</p>
<div class="foot">Protected by&nbsp;<a href="{REPO}" target="_blank" rel="noopener noreferrer">FluxGate</a></div>
</div></body></html>"##
    )
}

// Accent colours per page class.
const RED: &str = "#fb7185";
const SLATE: &str = "#94a3b8";
const AMBER: &str = "#fbbf24";

/// Render once into `slot` and return a `&'static str`. The block / error pages
/// carry no per-request data, so they're built a single time and then served by
/// reference — the block path (which is exactly what a flood of attacks hits) does
/// zero per-request allocation.
fn cached(
    slot: &'static std::sync::OnceLock<String>,
    status: u16,
    accent: &str,
    title: &str,
    subtitle: &str,
) -> &'static str {
    slot.get_or_init(|| render(status, accent, title, subtitle))
}

macro_rules! page {
    ($name:ident, $status:expr, $accent:expr, $title:expr, $detail:expr) => {
        pub fn $name() -> &'static str {
            static SLOT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            cached(&SLOT, $status, $accent, $title, $detail)
        }
    };
}

// 404 — FluxGate has no site/route for this address (never reaches an upstream).
page!(
    not_found,
    404,
    SLATE,
    "Nothing here",
    "No site is configured for this address."
);
// 502 — FluxGate couldn't select a healthy backend.
page!(
    upstream_unavailable,
    502,
    AMBER,
    "Upstream unavailable",
    "No healthy backend is available to serve this request."
);
// 403 blocks — one cached page per access-control reason.
page!(
    block_cloudflare,
    403,
    RED,
    "Cloudflare only",
    "This site only accepts traffic routed through Cloudflare."
);
page!(
    block_region,
    403,
    RED,
    "Region blocked",
    "Access to this site from your location is not permitted."
);
page!(
    block_datacenter,
    403,
    RED,
    "Datacenter blocked",
    "Access from datacenter / cloud networks is not permitted on this site."
);
page!(
    block_crawler,
    403,
    RED,
    "Automated access blocked",
    "Crawlers and bots are not allowed on this site."
);
page!(
    block_waf,
    403,
    RED,
    "Request blocked",
    "Your request was blocked by the FluxGate Web Application Firewall."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_render_branded() {
        for html in [
            not_found(),
            upstream_unavailable(),
            block_region(),
            block_cloudflare(),
            block_datacenter(),
            block_crawler(),
            block_waf(),
        ] {
            assert!(html.contains("FluxGate"));
            assert!(html.contains(REPO));
            assert!(html.starts_with("<!doctype html>"));
        }
    }

    #[test]
    fn cached_page_is_stable() {
        // Same call returns the identical cached instance (built once).
        assert!(std::ptr::eq(not_found().as_ptr(), not_found().as_ptr()));
    }
}
