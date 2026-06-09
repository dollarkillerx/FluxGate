//! Managed challenge for the WAF `challenge` action.
//!
//! Instead of a bare `429`, a challenged request gets an **interstitial page**
//! that runs a small JavaScript proof-of-work, sets a signed clearance cookie,
//! and reloads. Real browsers pass automatically in well under a second; clients
//! that don't run JS or don't keep cookies (curl, sqlmap, most scanners) never
//! get past it.
//!
//! Clearance cookie `fg_clear = {ts}.{sig}.{nonce}`:
//! * `sig = sha256(secret . ts)[..16]` — a keyed tag, so the client can't mint a
//!   fresh seed (only the server, which knows `secret`, can).
//! * `nonce` solves the proof-of-work: `sha256("{ts}.{sig}:{nonce}")` must start
//!   with [`DIFFICULTY`] hex zeros.
//!
//! Clearance is valid for [`TTL_SECS`]; after that the client is re-challenged.

use std::fmt::Write;

use sha2::{Digest, Sha256};

/// Proof-of-work difficulty as a hex-zero prefix (4 nibbles ≈ 16 bits ≈ 65536
/// hashes average — still well under a second in a browser, but enough real work
/// that scripted/no-JS clients won't grind it).
const DIFFICULTY: &str = "0000";
/// How long a solved clearance is accepted before re-challenging.
const TTL_SECS: i64 = 1800;
/// Cookie name carrying the clearance token.
const COOKIE: &str = "fg_clear";

fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut s = String::with_capacity(64);
    for b in digest {
        // Writing into the preallocated String is infallible; no per-byte alloc.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `sig` for a given timestamp (keyed by the server secret).
fn sig(secret: &str, ts: i64) -> String {
    sha256_hex(&format!("{secret}.{ts}"))[..16].to_string()
}

/// Issue a fresh seed `"{ts}.{sig}"` to embed in the challenge page.
fn issue_seed(secret: &str, now: i64) -> String {
    format!("{now}.{}", sig(secret, now))
}

/// Does the request carry a valid, unexpired, proof-of-work-backed clearance?
pub fn has_clearance(cookie_header: Option<&str>, secret: &str, now: i64) -> bool {
    let Some(value) = cookie_header.and_then(|h| cookie_value(h, COOKIE)) else {
        return false;
    };
    // value = "{ts}.{sig}.{nonce}"
    let parts: Vec<&str> = value.split('.').collect();
    let [ts_str, sig_str, nonce] = parts.as_slice() else {
        return false;
    };
    let Ok(ts) = ts_str.parse::<i64>() else {
        return false;
    };
    // Issued by us, and still fresh (allow small clock skew).
    if sig(secret, ts) != *sig_str || !(-5..TTL_SECS).contains(&(now - ts)) {
        return false;
    }
    // Proof-of-work holds.
    let seed = format!("{ts}.{sig_str}");
    sha256_hex(&format!("{seed}:{nonce}")).starts_with(DIFFICULTY)
}

/// Pull a cookie value by name out of a `Cookie:` header.
fn cookie_value(header: &str, name: &str) -> Option<String> {
    header.split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.trim() == name).then(|| v.trim().to_string())
    })
}

/// The interstitial HTML page (status 503) for an unsolved challenge.
pub fn page(secret: &str, now: i64) -> String {
    let seed = issue_seed(secret, now);
    PAGE_TEMPLATE
        .replace("__STYLE__", crate::pages::STYLE)
        .replace("__GLYPH__", crate::pages::GLYPH)
        .replace("__REPO__", crate::pages::REPO)
        .replace("__SEED__", &seed)
        .replace("__DIFF__", DIFFICULTY)
        .replace("__COOKIE__", COOKIE)
        .replace("__TTL__", &TTL_SECS.to_string())
}

// A compact, self-contained interstitial sharing the branded look of the block
// pages (see `pages.rs`). The embedded `sha256` is the public-domain
// implementation by Geraint Luff (tiny-sha256), used for the synchronous
// proof-of-work loop.
const PAGE_TEMPLATE: &str = r##"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Checking your browser… · FluxGate</title>
<style>:root{--accent:#60a5fa}__STYLE__</style></head>
<body><div class="card"><div class="brand">__GLYPH__<span>FluxGate</span></div>
<div class="sp"></div>
<h1>Checking your browser</h1><p id="m">Running a quick security check before you continue…</p>
<div class="foot">Protected by&nbsp;<a href="__REPO__" target="_blank" rel="noopener noreferrer">FluxGate</a></div></div>
<script>
function sha256(ascii){function rr(v,a){return (v>>>a)|(v<<(32-a));}var mp=Math.pow,mw=mp(2,32),res="",words=[],bitLen=ascii.length*8;var hash=sha256.h=sha256.h||[],k=sha256.k=sha256.k||[],pc=k.length,comp={};for(var cand=2;pc<64;cand++){if(!comp[cand]){for(var i=0;i<313;i+=cand)comp[i]=cand;hash[pc]=(mp(cand,.5)*mw)|0;k[pc++]=(mp(cand,1/3)*mw)|0;}}ascii+="\x80";while(ascii.length%64-56)ascii+="\x00";for(var i=0;i<ascii.length;i++){var j=ascii.charCodeAt(i);if(j>>8)return;words[i>>2]|=j<<((3-i)%4)*8;}words[words.length]=(bitLen/mw)|0;words[words.length]=bitLen;for(var j=0;j<words.length;){var w=words.slice(j,j+=16),oh=hash;hash=hash.slice(0,8);for(var i=0;i<64;i++){var w15=w[i-15],w2=w[i-2],a=hash[0],e=hash[4];var t1=hash[7]+(rr(e,6)^rr(e,11)^rr(e,25))+((e&hash[5])^((~e)&hash[6]))+k[i]+(w[i]=(i<16)?w[i]:(w[i-16]+(rr(w15,7)^rr(w15,18)^(w15>>>3))+w[i-7]+(rr(w2,17)^rr(w2,19)^(w2>>>10)))|0);var t2=(rr(a,2)^rr(a,13)^rr(a,22))+((a&hash[1])^(a&hash[2])^(hash[1]&hash[2]));hash=[(t1+t2)|0].concat(hash);hash[4]=(hash[4]+t1)|0;}for(var i=0;i<8;i++)hash[i]=(hash[i]+oh[i])|0;}for(var i=0;i<8;i++)for(var j=3;j+1;j--){var b=(hash[i]>>(j*8))&255;res+=((b<16)?"0":"")+b.toString(16);}return res;}
(function(){var seed="__SEED__",diff="__DIFF__";
setTimeout(function(){try{var n=0;while(sha256(seed+":"+n).indexOf(diff)!==0)n++;
document.cookie="__COOKIE__="+seed+"."+n+"; path=/; max-age=__TTL__; samesite=lax";
location.reload();}catch(e){document.getElementById("m").textContent="JavaScript is required to continue.";}},50);})();
</script></body></html>"##;

#[cfg(test)]
mod tests {
    use super::*;

    /// Solve the PoW the way the browser would (server-side, for the test).
    fn solve(secret: &str, now: i64) -> String {
        let seed = issue_seed(secret, now);
        let mut n: u64 = 0;
        while !sha256_hex(&format!("{seed}:{n}")).starts_with(DIFFICULTY) {
            n += 1;
        }
        format!("{seed}.{n}")
    }

    #[test]
    fn clearance_round_trip() {
        let secret = "test-secret";
        let now = 1_000_000i64;
        let token = solve(secret, now);
        let header = format!("other=1; {COOKIE}={token}; x=y");
        assert!(has_clearance(Some(&header), secret, now));
        assert!(has_clearance(Some(&header), secret, now + 100)); // still fresh
    }

    #[test]
    fn clearance_rejects_forgery_and_expiry() {
        let secret = "test-secret";
        let now = 1_000_000i64;
        let token = solve(secret, now);
        let header = format!("{COOKIE}={token}");
        // Wrong secret → bad sig.
        assert!(!has_clearance(Some(&header), "other-secret", now));
        // Expired.
        assert!(!has_clearance(Some(&header), secret, now + TTL_SECS + 1));
        // Tampered nonce breaks the proof-of-work.
        let bad = header.replace(
            &token,
            &format!("{}.{}", issue_seed(secret, now), "999999999"),
        );
        assert!(!has_clearance(Some(&bad), secret, now));
        // No cookie.
        assert!(!has_clearance(Some("foo=bar"), secret, now));
        assert!(!has_clearance(None, secret, now));
    }

    #[test]
    fn page_embeds_seed_and_params() {
        let p = page("s", 42);
        assert!(p.contains("__SEED__") == false);
        assert!(p.contains(&format!("42.{}", sig("s", 42))));
        assert!(p.contains("Checking your browser"));
    }
}
