//! L4 (byte-transparent TCP / TLS-SNI passthrough) data plane.
//!
//! Runs on the shared :443 ingress. Only the TLS ClientHello is inspected: it is
//! retained verbatim and replayed to the selected origin, so TLS and the app
//! protocol stay end-to-end (VLESS-Reality, AnyTLS, any TLS backend). A ClientHello
//! whose SNI matches no `L4Route` falls through to the normal L7 HTTPS proxy, so L4
//! and L7 coexist on one port.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::state::AppState;
use fluxgate_core::{L4Route, LbStrategy};

const CLIENT_HELLO_LIMIT: usize = 64 * 1024;
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum L4Error {
    HelloTimeout,
    HelloTooLarge,
    InvalidHello(&'static str),
    MissingSni,
    Io(io::Error),
}

impl std::fmt::Display for L4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L4Error::HelloTimeout => write!(f, "client hello timed out"),
            L4Error::HelloTooLarge => write!(f, "client hello too large"),
            L4Error::InvalidHello(s) => write!(f, "invalid client hello: {s}"),
            L4Error::MissingSni => write!(f, "client hello has no SNI"),
            L4Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}
impl std::error::Error for L4Error {}
impl From<io::Error> for L4Error {
    fn from(e: io::Error) -> Self {
        L4Error::Io(e)
    }
}

/// A stream plus the bytes consumed while inspecting its ClientHello.
pub struct PeekedStream<S> {
    pub stream: S,
    pub prefix: Vec<u8>,
    pub server_name: String,
}

/// Async stream that replays `prefix` before reading the underlying stream, so a
/// peeked connection can be handed to rustls unchanged for the L7 fallback.
pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    offset: usize,
}

impl<S> PrefixedStream<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && dst.remaining() > 0 {
            let n = dst.remaining().min(self.prefix.len() - self.offset);
            dst.put_slice(&self.prefix[self.offset..self.offset + n]);
            self.offset += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, dst)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Incrementally read and parse a fragmented TLS ClientHello, preserving every
/// consumed byte for replay to the origin (or the local TLS terminator).
pub async fn peek_client_hello<S>(mut stream: S) -> Result<PeekedStream<S>, L4Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let future = async {
        let mut raw = Vec::with_capacity(2048);
        loop {
            match parse_client_hello(&raw)? {
                ParseResult::Complete(server_name) => {
                    return Ok(PeekedStream {
                        stream,
                        prefix: raw,
                        server_name,
                    });
                }
                ParseResult::NeedMore => {}
            }
            if raw.len() >= CLIENT_HELLO_LIMIT {
                return Err(L4Error::HelloTooLarge);
            }
            let remaining = CLIENT_HELLO_LIMIT - raw.len();
            let mut chunk = vec![0u8; remaining.min(4096)];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(L4Error::InvalidHello("unexpected EOF"));
            }
            raw.extend_from_slice(&chunk[..n]);
        }
    };
    tokio::time::timeout(CLIENT_HELLO_TIMEOUT, future)
        .await
        .map_err(|_| L4Error::HelloTimeout)?
}

enum ParseResult {
    NeedMore,
    Complete(String),
}

/// Assemble handshake bytes across TLS records and extract the first DNS SNI.
fn parse_client_hello(raw: &[u8]) -> Result<ParseResult, L4Error> {
    let mut record_at = 0usize;
    let mut handshake = Vec::new();
    loop {
        if raw.len() < record_at + 5 {
            return Ok(ParseResult::NeedMore);
        }
        if raw[record_at] != 22 {
            return Err(L4Error::InvalidHello("first flight is not TLS handshake data"));
        }
        let record_len = u16::from_be_bytes([raw[record_at + 3], raw[record_at + 4]]) as usize;
        if record_len > 18_432 {
            return Err(L4Error::InvalidHello("TLS record is too large"));
        }
        let end = record_at + 5 + record_len;
        if raw.len() < end {
            return Ok(ParseResult::NeedMore);
        }
        handshake.extend_from_slice(&raw[record_at + 5..end]);
        record_at = end;

        if handshake.len() < 4 {
            continue;
        }
        if handshake[0] != 1 {
            return Err(L4Error::InvalidHello("first handshake message is not ClientHello"));
        }
        let hello_len = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | handshake[3] as usize;
        if hello_len + 4 > CLIENT_HELLO_LIMIT {
            return Err(L4Error::HelloTooLarge);
        }
        if handshake.len() < hello_len + 4 {
            continue;
        }
        return parse_sni(&handshake[4..4 + hello_len]).map(ParseResult::Complete);
    }
}

fn parse_sni(body: &[u8]) -> Result<String, L4Error> {
    if body.len() < 35 {
        return Err(L4Error::InvalidHello("truncated ClientHello"));
    }
    let mut at = 34usize;
    let sid_len = body[at] as usize;
    at = checked_advance(body, at + 1, sid_len, "session id")?;
    let cipher_len = read_u16(body, at, "cipher suites")? as usize;
    at = checked_advance(body, at + 2, cipher_len, "cipher suites")?;
    if at >= body.len() {
        return Err(L4Error::InvalidHello("missing compression methods"));
    }
    let compression_len = body[at] as usize;
    at = checked_advance(body, at + 1, compression_len, "compression methods")?;
    if at == body.len() {
        return Err(L4Error::MissingSni);
    }
    let extensions_len = read_u16(body, at, "extensions")? as usize;
    at += 2;
    let extensions_end = checked_advance(body, at, extensions_len, "extensions")?;
    while at < extensions_end {
        let kind = read_u16(body, at, "extension type")?;
        let len = read_u16(body, at + 2, "extension length")? as usize;
        at += 4;
        let end = checked_advance(body, at, len, "extension")?;
        if end > extensions_end {
            return Err(L4Error::InvalidHello("extension exceeds extension block"));
        }
        if kind == 0 {
            return parse_server_name_extension(&body[at..end]);
        }
        at = end;
    }
    Err(L4Error::MissingSni)
}

fn parse_server_name_extension(ext: &[u8]) -> Result<String, L4Error> {
    let list_len = read_u16(ext, 0, "server name list")? as usize;
    if list_len + 2 != ext.len() {
        return Err(L4Error::InvalidHello("bad server name list length"));
    }
    let mut at = 2usize;
    while at < ext.len() {
        if at + 3 > ext.len() {
            return Err(L4Error::InvalidHello("truncated server name"));
        }
        let kind = ext[at];
        let len = u16::from_be_bytes([ext[at + 1], ext[at + 2]]) as usize;
        at += 3;
        let end = checked_advance(ext, at, len, "server name")?;
        if kind == 0 {
            let name = std::str::from_utf8(&ext[at..end])
                .map_err(|_| L4Error::InvalidHello("SNI is not UTF-8"))?;
            let normalized =
                normalize_server_name(name).ok_or(L4Error::InvalidHello("invalid SNI hostname"))?;
            return Ok(normalized);
        }
        at = end;
    }
    Err(L4Error::MissingSni)
}

fn checked_advance(bytes: &[u8], at: usize, len: usize, field: &'static str) -> Result<usize, L4Error> {
    let end = at
        .checked_add(len)
        .ok_or(L4Error::InvalidHello("length overflow"))?;
    if end > bytes.len() {
        return Err(L4Error::InvalidHello(field));
    }
    Ok(end)
}

fn read_u16(bytes: &[u8], at: usize, field: &'static str) -> Result<u16, L4Error> {
    if at + 2 > bytes.len() {
        return Err(L4Error::InvalidHello(field));
    }
    Ok(u16::from_be_bytes([bytes[at], bytes[at + 1]]))
}

fn normalize_server_name(name: &str) -> Option<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || name.parse::<IpAddr>().is_ok()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        None
    } else {
        Some(name)
    }
}

/// Resolve an enabled L4 route for `sni`: an exact match wins; otherwise the
/// most-specific one-label wildcard (`*.suffix`). Pure over the route slice so it
/// can be unit-tested without an `AppState`.
fn match_l4_route<'a>(routes: &'a [L4Route], sni: &str) -> Option<&'a L4Route> {
    let mut wildcard: Option<(&L4Route, usize)> = None;
    for r in routes.iter().filter(|r| r.enabled) {
        for cn in &r.server_names {
            let cn = cn.trim_end_matches('.').to_ascii_lowercase();
            if cn == sni {
                return Some(r);
            }
            if let Some(suffix) = cn.strip_prefix("*.") {
                if let Some((_, rest)) = sni.split_once('.') {
                    if rest == suffix {
                        let better = match &wildcard {
                            Some((_, best)) => suffix.len() > *best,
                            None => true,
                        };
                        if better {
                            wildcard = Some((r, suffix.len()));
                        }
                    }
                }
            }
        }
    }
    wildcard.map(|(r, _)| r)
}

/// Resolve an enabled L4 route for `sni` against the live store.
pub fn lookup_l4_route(state: &AppState, sni: &str) -> Option<L4Route> {
    let store = state.store.lock();
    match_l4_route(&store.l4_routes, sni).cloned()
}

/// Pick an origin for this connection per the route's LB strategy. IpHash keeps a
/// client sticky to one origin (useful for stateful TLS protocols); everything
/// else round-robins.
fn pick_origin(state: &AppState, route: &L4Route, peer: SocketAddr) -> Option<String> {
    let n = route.origins.len();
    if n == 0 {
        return None;
    }
    let idx = match route.strategy {
        LbStrategy::IpHash => {
            let mut h: usize = 0;
            for b in peer.ip().to_string().bytes() {
                h = h.wrapping_mul(31).wrapping_add(b as usize);
            }
            h % n
        }
        _ => {
            let mut cur = state.lb_cursor.lock();
            let i = cur.entry(format!("l4:{}", route.id)).or_insert(0);
            let idx = *i % n;
            *i = i.wrapping_add(1);
            idx
        }
    };
    Some(route.origins[idx].clone())
}

/// Forward a matched connection to its origin: connect, replay the peeked
/// ClientHello, then splice bytes both ways until either side closes.
pub async fn serve_passthrough(
    peeked: PeekedStream<TcpStream>,
    peer: SocketAddr,
    route: L4Route,
    state: AppState,
) -> io::Result<()> {
    let origin_addr = pick_origin(&state, &route, peer)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "L4 route has no origin"))?;
    let secs = if route.connect_timeout_secs == 0 {
        5
    } else {
        route.connect_timeout_secs.clamp(1, 60)
    };
    let mut origin = tokio::time::timeout(Duration::from_secs(secs), TcpStream::connect(&origin_addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "L4 origin connect timed out"))??;
    origin.set_nodelay(true).ok();
    let PeekedStream {
        mut stream, prefix, ..
    } = peeked;
    origin.write_all(&prefix).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut origin).await?;
    Ok(())
}

/// accept_resilient wraps `listener.accept()` so a PER-CONNECTION accept error
/// (ECONNABORTED when a client resets between the SYN and our accept, or
/// EMFILE/ENFILE/ENOBUFS under fd/buffer pressure) never kills the listener.
async fn accept_resilient(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(pair) => return pair,
            Err(e) => match e.raw_os_error() {
                Some(24) | Some(23) | Some(105) => {
                    tracing::warn!(error = %e, "accept: resource exhaustion, backing off");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                _ => tracing::debug!(error = %e, "accept failed; retrying"),
            },
        }
    }
}

/// Unified :443 ingress: peek each ClientHello's SNI, forward matching L4 routes
/// verbatim to their origin, and replay everything else into the L7 HTTPS proxy.
pub async fn run_shared(
    state: AppState,
    app: Router,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    tracing::info!("  • Ingress : tls://{addr} (shared HTTPS + L4 SNI passthrough)");
    loop {
        let (stream, peer) = accept_resilient(&listener).await;
        // Client-facing leg: without nodelay, Nagle + delayed-ACK stalls the
        // TLS handshake flights and small responses (the origin legs set it).
        let _ = stream.set_nodelay(true);
        let Ok(permit) = state.l4_handshake_slots.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "shared ingress ClientHello concurrency limit reached");
            continue;
        };
        let state = state.clone();
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let peeked = match peek_client_hello(stream).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "shared ingress rejected ClientHello");
                    return;
                }
            };
            drop(permit);
            if let Some(route) = lookup_l4_route(&state, &peeked.server_name) {
                if let Err(e) = serve_passthrough(peeked, peer, route, state).await {
                    tracing::debug!(%peer, error = %e, "L4 passthrough closed");
                }
            } else {
                let stream = PrefixedStream::new(peeked.stream, peeked.prefix);
                crate::serve::serve_tls_connection(app, stream, peer, acceptor).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, server_names: &[&str], enabled: bool) -> L4Route {
        L4Route {
            id: format!("l4_{name}"),
            name: name.to_string(),
            server_names: server_names.iter().map(|s| s.to_string()).collect(),
            origins: vec!["127.0.0.1:9000".to_string()],
            strategy: LbStrategy::RoundRobin,
            connect_timeout_secs: 0,
            enabled,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    /// Minimal TLS 1.x ClientHello record carrying a single host_name SNI.
    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0); // host_name type
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes()); // server_name (0)
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);
        let mut body = vec![0x03, 0x03]; // client_version
        body.extend_from_slice(&[7u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        body.push(1); // compression methods len
        body.push(0); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![
            1, // ClientHello
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 0x03, 0x01]; // handshake record, TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_sni_from_client_hello() {
        let hello = client_hello("reality.example.com");
        match parse_client_hello(&hello).unwrap() {
            ParseResult::Complete(sni) => assert_eq!(sni, "reality.example.com"),
            ParseResult::NeedMore => panic!("expected complete parse"),
        }
    }

    #[test]
    fn partial_client_hello_needs_more() {
        let hello = client_hello("reality.example.com");
        // Feed everything but the last byte: the record is incomplete.
        assert!(matches!(
            parse_client_hello(&hello[..hello.len() - 1]).unwrap(),
            ParseResult::NeedMore
        ));
        // Even fewer than a record header of bytes must not error.
        assert!(matches!(
            parse_client_hello(&hello[..3]).unwrap(),
            ParseResult::NeedMore
        ));
    }

    #[test]
    fn non_handshake_first_byte_is_rejected() {
        // 0x16 (22) marks handshake; anything else is not L4-eligible.
        let mut junk = client_hello("a.example.com");
        junk[0] = 0x17; // application_data
        assert!(matches!(
            parse_client_hello(&junk),
            Err(L4Error::InvalidHello(_))
        ));
    }

    #[test]
    fn exact_match_beats_wildcard() {
        let routes = vec![
            route("wild", &["*.example.com"], true),
            route("exact", &["api.example.com"], true),
        ];
        assert_eq!(
            match_l4_route(&routes, "api.example.com").unwrap().name,
            "exact"
        );
    }

    #[test]
    fn most_specific_wildcard_wins() {
        let routes = vec![
            route("broad", &["*.com"], true),
            route("narrow", &["*.example.com"], true),
        ];
        assert_eq!(
            match_l4_route(&routes, "a.example.com").unwrap().name,
            "narrow"
        );
    }

    #[test]
    fn wildcard_matches_one_label_only() {
        let routes = vec![route("wild", &["*.example.com"], true)];
        assert!(match_l4_route(&routes, "a.example.com").is_some());
        // Two labels deep must NOT match a one-label wildcard.
        assert!(match_l4_route(&routes, "a.b.example.com").is_none());
        // The bare apex is not covered by *.example.com either.
        assert!(match_l4_route(&routes, "example.com").is_none());
    }

    #[test]
    fn disabled_route_is_skipped() {
        let routes = vec![route("off", &["api.example.com"], false)];
        assert!(match_l4_route(&routes, "api.example.com").is_none());
    }

    #[test]
    fn match_is_case_and_trailing_dot_insensitive() {
        let routes = vec![route("r", &["API.Example.COM."], true)];
        assert_eq!(match_l4_route(&routes, "api.example.com").unwrap().name, "r");
    }

    #[test]
    fn normalize_rejects_ips_and_bad_labels() {
        assert_eq!(
            normalize_server_name("Host.Example.COM."),
            Some("host.example.com".to_string())
        );
        assert!(normalize_server_name("127.0.0.1").is_none());
        assert!(normalize_server_name("::1").is_none());
        assert!(normalize_server_name("").is_none());
        assert!(normalize_server_name("a..b").is_none());
        assert!(normalize_server_name("-lead.example.com").is_none());
        assert!(normalize_server_name("under_score.example.com").is_none());
    }

    #[tokio::test]
    async fn peek_preserves_every_byte_and_replays_via_prefixed_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let hello = client_hello("reality.example.com");
        let extra = b"post-handshake application bytes";

        let (mut client, server) = tokio::io::duplex(8192);
        let hello_clone = hello.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&hello_clone).await.unwrap();
            client.write_all(extra).await.unwrap();
            client.flush().await.unwrap();
            client
        });

        let peeked = peek_client_hello(server).await.unwrap();
        assert_eq!(peeked.server_name, "reality.example.com");
        // The peeked prefix begins with the full ClientHello. It may also contain
        // bytes read past the handshake (a single read can grab more) — those are
        // preserved for replay, not dropped, which the round-trip below proves.
        assert!(peeked.prefix.starts_with(&hello));

        // Replaying through PrefixedStream must yield hello ++ extra, in order.
        let _client = writer.await.unwrap();
        let mut replay = PrefixedStream::new(peeked.stream, peeked.prefix);
        let mut got = Vec::new();
        let want = hello.len() + extra.len();
        while got.len() < want {
            let mut buf = [0u8; 512];
            let n = replay.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let mut expected = hello.clone();
        expected.extend_from_slice(extra);
        assert_eq!(got, expected);
    }
}
