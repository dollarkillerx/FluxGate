//! HTTPS / TLS serving for both planes.
//!
//! * The **data plane** (reverse proxy, :443) uses an SNI-aware certificate
//!   resolver: a TLS handshake only succeeds for a hostname that has BOTH a
//!   matching certificate in the store AND an enabled route with `tls_enabled`.
//!   That is the "只有配置了证书且开通 TLS 才代理" rule, enforced at the
//!   handshake — no cert / no TLS route ⇒ no handshake ⇒ no proxying.
//! * The **control plane** (admin console) is served over HTTPS with a default
//!   self-signed certificate that is auto-generated on first start.
//!
//! Serving is done with `tokio-rustls` + a raw `hyper` HTTP/1 connection so we
//! keep full control over SNI and WebSocket upgrades (the proxy needs both).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt; // for `oneshot`

use crate::state::AppState;

/// Install the process-wide rustls crypto provider (ring). Idempotent.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Request-extension marker: this request arrived over a TLS connection. The
/// proxy uses it to decide whether to honour a route's HTTP→HTTPS redirect.
#[derive(Clone, Copy)]
pub struct TlsConn;

// ---------------------------------------------------------------------------
// PEM → rustls types
// ---------------------------------------------------------------------------

fn certs_from_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .filter_map(Result::ok)
        .collect()
}

fn key_from_pem(pem: &str) -> Option<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .ok()
        .flatten()
}

/// Build a rustls `CertifiedKey` from cert + key PEM strings.
fn certified_key(cert_pem: &str, key_pem: &str) -> Option<Arc<CertifiedKey>> {
    let chain = certs_from_pem(cert_pem);
    if chain.is_empty() {
        return None;
    }
    let key = key_from_pem(key_pem)?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).ok()?;
    Some(Arc::new(CertifiedKey::new(chain, signing_key)))
}

// ---------------------------------------------------------------------------
// SNI resolver for the data plane
// ---------------------------------------------------------------------------

/// Resolves a server certificate per the TLS SNI hostname, but ONLY when the
/// hostname is both certificate-backed and TLS-enabled by a route.
struct SniCertResolver {
    state: AppState,
    /// Cache of parsed certificates keyed by `"{cert_id}:{mtime}"`, so the
    /// expensive disk-read + PEM/key parse runs once per cert version instead of
    /// on every TLS handshake.
    cache: parking_lot::Mutex<std::collections::HashMap<String, Arc<CertifiedKey>>>,
}

// `ResolvesServerCert` requires `Debug`; `AppState` is not `Debug`, so provide a
// minimal manual impl.
impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SniCertResolver")
    }
}

impl SniCertResolver {
    /// Look up the certificate `id` to serve for `sni`: there must be an enabled
    /// site with `tls_enabled` for that host (开通了 TLS), AND a certificate
    /// (配置了证书). The site's explicitly selected `cert_id` wins; otherwise
    /// fall back to a certificate whose domain matches the SNI hostname.
    fn cert_id_for(&self, sni: &str) -> Option<String> {
        let store = self.state.store.lock();
        let site = store
            .sites
            .iter()
            .find(|s| s.enabled && s.tls_enabled && host_matches(&s.host, sni))?;
        // Prefer the certificate the operator picked on the site.
        if let Some(cid) = site.cert_id.as_ref() {
            if store.certs.iter().any(|c| &c.id == cid) {
                return Some(cid.clone());
            }
        }
        // Fall back: any certificate whose domain matches the SNI hostname.
        store
            .certs
            .iter()
            .find(|c| host_matches(&c.domain, sni))
            .map(|c| c.id.clone())
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?.to_string();
        let id = self.cert_id_for(&sni)?;
        let dir = &self.state.config.cert_dir;
        // Include the file mtime so renew/upload (new file) busts the cache.
        let key = format!("{id}:{:?}", crate::tls::cert_file_mtime(dir, &id));

        if let Some(ck) = self.cache.lock().get(&key) {
            return Some(ck.clone());
        }
        // Cache miss: do the disk read + PEM/key parse exactly once.
        let (cert_pem, key_pem) = crate::tls::read_cert_files(dir, &id)?;
        let ck = certified_key(&cert_pem, &key_pem)?;
        {
            let mut cache = self.cache.lock();
            // Keep only the newest version per cert id to bound growth.
            let prefix = format!("{id}:");
            cache.retain(|k, _| !k.starts_with(&prefix));
            cache.insert(key, ck.clone());
        }
        Some(ck)
    }
}

/// Match a configured host/domain (possibly a `*.example.com` wildcard) against
/// a concrete SNI hostname, case-insensitively.
fn host_matches(configured: &str, sni: &str) -> bool {
    if configured.eq_ignore_ascii_case(sni) {
        return true;
    }
    if let Some(suffix) = configured.strip_prefix("*.") {
        // "*.example.com" matches exactly one extra label: "api.example.com".
        if let Some((_, rest)) = sni.split_once('.') {
            return rest.eq_ignore_ascii_case(suffix);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::host_matches;

    #[test]
    fn exact_match_is_case_insensitive() {
        assert!(host_matches("Example.com", "example.com"));
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(!host_matches("example.com", "evil.com"));
    }

    #[test]
    fn wildcard_matches_one_label() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "www.example.com"));
        // Wildcard covers exactly one label, not the bare apex or nested subs.
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "api.other.com"));
    }
}

/// TLS config for the reverse-proxy data plane (SNI-gated, no client auth).
pub fn data_plane_config(state: AppState) -> Arc<ServerConfig> {
    let resolver = Arc::new(SniCertResolver {
        state,
        cache: parking_lot::Mutex::new(std::collections::HashMap::new()),
    });
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// TLS config presenting a single fixed certificate (used by the admin console).
pub fn single_cert_config(cert_pem: &str, key_pem: &str) -> anyhow::Result<Arc<ServerConfig>> {
    let chain = certs_from_pem(cert_pem);
    let key = key_from_pem(key_pem).ok_or_else(|| anyhow::anyhow!("no private key in PEM"))?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

// ---------------------------------------------------------------------------
// Generic HTTPS serving loop
// ---------------------------------------------------------------------------

/// Serve `app` over TLS on `addr`. Each accepted connection is handed to a
/// per-connection hyper HTTP/1 service (with WebSocket upgrades enabled). The
/// real peer address is injected as `ConnectInfo<SocketAddr>` so existing
/// extractors keep working exactly as on the plaintext path.
pub async fn serve_tls(
    app: Router,
    addr: SocketAddr,
    config: Arc<ServerConfig>,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("tls accept error on {addr}: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(_) => return, // handshake failure (e.g. no cert for SNI) — drop quietly
            };
            let io = TokioIo::new(tls_stream);
            let svc = service_fn(move |req: hyper::Request<Incoming>| {
                // Convert hyper's incoming body to an axum body and attach peer info.
                let (parts, body) = req.into_parts();
                let mut req = hyper::Request::from_parts(parts, axum::body::Body::new(body));
                req.extensions_mut().insert(ConnectInfo(peer));
                req.extensions_mut().insert(TlsConn);
                app.clone().oneshot(req)
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                tracing::debug!("tls connection from {peer} ended: {e}");
            }
        });
    }
}
