//! Real TLS certificate handling.
//!
//! * `generate_self_signed` — produces a genuine ECDSA keypair + X.509
//!   certificate via `rcgen` (real crypto, real validity window). This is the
//!   local stand-in for ACME issuance; a real ACME client would slot in here.
//! * `parse_pem` — parses an uploaded certificate with `x509-parser` and pulls
//!   out the real subject / issuer / expiry.
//! * `status_for` — derives valid/expiring/expired from the real `notAfter`.
//!
//! Certificate + key PEM files are written under the configured cert directory.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use chrono::{DateTime, TimeZone, Utc};
use rcgen::{CertificateParams, DnType, KeyPair};
use time::{Duration as TimeDuration, OffsetDateTime};

use fluxgate_core::{CertStatus, TlsCertificate};

pub struct ParsedCert {
    pub domain: String,
    pub issuer: String,
    pub not_after: DateTime<Utc>,
}

/// Generate a real self-signed certificate for `domain`, valid for `days`.
/// Returns `(cert_pem, key_pem, expires_at)`.
pub fn generate_self_signed(domain: &str, days: i64) -> Result<(String, String, DateTime<Utc>)> {
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| anyhow!("invalid domain: {e}"))?;
    let not_before = OffsetDateTime::now_utc();
    let not_after = not_before + TimeDuration::days(days);
    params.not_before = not_before;
    params.not_after = not_after;
    params.distinguished_name.push(DnType::CommonName, domain);

    let key_pair = KeyPair::generate().map_err(|e| anyhow!("key generation failed: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("signing failed: {e}"))?;

    let expires = Utc
        .timestamp_opt(not_after.unix_timestamp(), 0)
        .single()
        .unwrap_or_else(Utc::now);
    Ok((cert.pem(), key_pair.serialize_pem(), expires))
}

/// Parse a PEM certificate, extracting the real subject CN, issuer CN and expiry.
pub fn parse_pem(cert_pem: &str) -> Result<ParsedCert> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow!("not a valid PEM certificate: {e}"))?;
    let x509 = pem
        .parse_x509()
        .map_err(|e| anyhow!("not a valid X.509 certificate: {e}"))?;

    let cn = |entity: &x509_parser::x509::X509Name| {
        entity
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .map(|s| s.to_string())
    };

    let domain = cn(x509.subject()).unwrap_or_else(|| "unknown".into());
    let issuer = cn(x509.issuer()).unwrap_or_else(|| "unknown".into());
    let not_after = Utc
        .timestamp_opt(x509.validity().not_after.timestamp(), 0)
        .single()
        .ok_or_else(|| anyhow!("certificate has no valid notAfter date"))?;

    Ok(ParsedCert {
        domain,
        issuer,
        not_after,
    })
}

/// Map a real expiry date to a status badge.
pub fn status_for(not_after: &DateTime<Utc>) -> CertStatus {
    let days = (*not_after - Utc::now()).num_days();
    if days < 0 {
        CertStatus::Expired
    } else if days <= 30 {
        CertStatus::Expiring
    } else {
        CertStatus::Valid
    }
}

pub fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn paths(dir: &Path, id: &str) -> (PathBuf, PathBuf) {
    (dir.join(format!("{id}.crt")), dir.join(format!("{id}.key")))
}

/// Persist cert (and optional key) PEM to disk. The private key is written with
/// owner-only (0600) permissions on Unix.
pub fn save_files(
    dir: &Path,
    id: &str,
    cert_pem: &str,
    key_pem: Option<&str>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let (crt, key) = paths(dir, id);
    std::fs::write(crt, cert_pem)?;
    if let Some(k) = key_pem {
        std::fs::write(&key, k)?;
        restrict_permissions(&key);
    }
    Ok(())
}

/// Modification time of a stored certificate's `.crt` file — used as part of the
/// SNI cache key so a renew/upload (which rewrites the file) invalidates it.
pub fn cert_file_mtime(dir: &Path, id: &str) -> Option<std::time::SystemTime> {
    let (crt, _key) = paths(dir, id);
    std::fs::metadata(crt).ok()?.modified().ok()
}

/// Read a stored certificate's `(cert_pem, key_pem)` by id, if both files exist.
pub fn read_cert_files(dir: &Path, id: &str) -> Option<(String, String)> {
    let (crt, key) = paths(dir, id);
    Some((
        std::fs::read_to_string(crt).ok()?,
        std::fs::read_to_string(key).ok()?,
    ))
}

/// Stable id under which the admin console's self-signed certificate is stored.
pub const ADMIN_CERT_ID: &str = "_admin_console";

/// Stable id of the default self-signed certificate seeded into the store on
/// first run so the certificate list is never empty and routes always have a
/// certificate to select.
pub const DEFAULT_CERT_ID: &str = "ct-fluxgate-default";

/// Generate the default "FluxGate" self-signed certificate (for `localhost`),
/// write its files, and return the store metadata. Used to seed an empty store.
pub fn default_self_signed_cert(dir: &Path) -> Result<TlsCertificate> {
    let domain = "localhost";
    let (cert_pem, key_pem, expires) = generate_self_signed(domain, 825)?;
    save_files(dir, DEFAULT_CERT_ID, &cert_pem, Some(&key_pem))?;
    Ok(TlsCertificate {
        id: DEFAULT_CERT_ID.into(),
        domain: domain.into(),
        issuer: "FluxGate self-signed (local)".into(),
        expires_at: expires.to_rfc3339(),
        auto_renew: true,
        status: status_for(&expires),
        acme: false,
    })
}

/// Ensure a self-signed certificate exists for the admin console, generating one
/// on first start (or regenerating if the stored one has expired). Returns the
/// `(cert_pem, key_pem)` to serve. This is the "系统默认给管理面板一个自签证书".
pub fn ensure_admin_cert(dir: &Path) -> Result<(String, String)> {
    if let Some((cert_pem, key_pem)) = read_cert_files(dir, ADMIN_CERT_ID) {
        // Reuse unless it has actually expired.
        if let Ok(parsed) = parse_pem(&cert_pem) {
            if status_for(&parsed.not_after) != CertStatus::Expired {
                return Ok((cert_pem, key_pem));
            }
        }
    }
    // ~27 months keeps it comfortably valid; it's a local self-signed cert.
    let (cert_pem, key_pem, _expires) = generate_self_signed("localhost", 825)?;
    save_files(dir, ADMIN_CERT_ID, &cert_pem, Some(&key_pem))?;
    Ok((cert_pem, key_pem))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_parse_round_trip() {
        let (cert_pem, key_pem, expires) = generate_self_signed("test.example.com", 90).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
        assert!((expires - Utc::now()).num_days() >= 89);

        let parsed = parse_pem(&cert_pem).unwrap();
        assert_eq!(parsed.domain, "test.example.com");
        assert_eq!(status_for(&parsed.not_after), CertStatus::Valid);
    }

    #[test]
    fn status_reflects_expiry() {
        assert_eq!(
            status_for(&(Utc::now() + chrono::Duration::days(60))),
            CertStatus::Valid
        );
        assert_eq!(
            status_for(&(Utc::now() + chrono::Duration::days(10))),
            CertStatus::Expiring
        );
        assert_eq!(
            status_for(&(Utc::now() - chrono::Duration::days(1))),
            CertStatus::Expired
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_pem("definitely not a certificate").is_err());
    }
}

/// Remove a certificate's files (best effort).
pub fn delete_files(dir: &Path, id: &str) {
    let (crt, key) = paths(dir, id);
    let _ = std::fs::remove_file(crt);
    let _ = std::fs::remove_file(key);
}
