//! ACME (RFC 8555) certificate issuance via the **HTTP-01** challenge.
//!
//! Flow: create/restore an ACME account → place an order for the domain →
//! provision each HTTP-01 challenge token into the shared [`ChallengeStore`]
//! (served by the reverse proxy at `/.well-known/acme-challenge/<token>`) →
//! tell the CA we're ready → poll until the order is `Ready` → finalize (the
//! library generates a fresh keypair and CSR) → download the certificate chain.
//!
//! The challenge tokens are the ONLY thing intercepted on the data plane, and
//! only while an order is in flight — normal traffic to the origin is never
//! disturbed (see `proxy::proxy_handler`).
//!
//! The account credentials (including the account key) are persisted to
//! `acme-account.json` in the certificate directory so renewals reuse the same
//! registered account instead of re-registering each time.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use parking_lot::Mutex;

/// Shared map of in-flight HTTP-01 challenges: `token` → full key authorization.
/// The proxy serves the value as the response body at
/// `/.well-known/acme-challenge/<token>` on the plaintext (:80) plane.
pub type ChallengeStore = Arc<Mutex<HashMap<String, String>>>;

/// File (under the cert dir) holding the serialized ACME account credentials.
const ACCOUNT_FILE: &str = "acme-account.json";

/// Restore the persisted ACME account, or register a fresh one bound to `email`
/// and persist its credentials for reuse on renewal.
///
/// Registration agrees to the CA's terms of service. This is only ever reached
/// because the operator enabled ACME *and* ticked "agree to ToS" — every caller
/// of [`issue_http01`] gates on `settings.acme.agree_tos` first (see the
/// `tls.cert.request` handler and the auto-renewal task).
async fn account(dir: &Path, directory_url: &str, email: &str) -> Result<Account> {
    let path = dir.join(ACCOUNT_FILE);
    if let Ok(bytes) = std::fs::read(&path) {
        match serde_json::from_slice::<AccountCredentials>(&bytes) {
            Ok(creds) => match Account::builder()?.from_credentials(creds).await {
                Ok(acc) => return Ok(acc),
                Err(e) => tracing::warn!("stored ACME account unusable ({e}); registering anew"),
            },
            Err(e) => tracing::warn!("ACME account file unreadable ({e}); registering anew"),
        }
    }

    let contact: Vec<String> = if email.is_empty() {
        Vec::new()
    } else {
        vec![format!("mailto:{email}")]
    };
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (acc, creds) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_owned(),
            None,
        )
        .await
        .context("registering ACME account")?;

    if let Ok(json) = serde_json::to_vec_pretty(&creds) {
        let _ = std::fs::create_dir_all(dir);
        if std::fs::write(&path, json).is_ok() {
            restrict_permissions(&path);
        }
    }
    Ok(acc)
}

/// Issue a certificate for `domain` over HTTP-01. On success returns
/// `(cert_chain_pem, private_key_pem)`. Challenge tokens provisioned during the
/// order are always cleaned up before returning.
pub async fn issue_http01(
    dir: &Path,
    directory_url: &str,
    email: &str,
    domain: &str,
    challenges: &ChallengeStore,
) -> Result<(String, String)> {
    let account = account(dir, directory_url, email).await?;
    let mut order = account
        .new_order(&NewOrder::new(&[Identifier::Dns(domain.to_string())]))
        .await
        .context("creating ACME order")?;

    // Drive the order, tracking which challenge tokens we provisioned. The work
    // is split out so we can ALWAYS remove those tokens afterwards — including
    // when provisioning itself fails partway through (otherwise stale tokens
    // would linger in the shared map).
    let mut provisioned: Vec<String> = Vec::new();
    let outcome = run_order(&mut order, domain, challenges, &mut provisioned).await;

    let mut map = challenges.lock();
    for t in &provisioned {
        map.remove(t);
    }
    outcome
}

/// Provision the HTTP-01 challenges (recording each token in `provisioned`),
/// signal readiness, then drive the order to a finished certificate. Any error
/// here returns to `issue_http01`, which still cleans up `provisioned`.
async fn run_order(
    order: &mut instant_acme::Order,
    domain: &str,
    challenges: &ChallengeStore,
    provisioned: &mut Vec<String>,
) -> Result<(String, String)> {
    // Scoped so the `&mut order` borrow from `authorizations()` ends before we
    // poll/finalize the order below.
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => return Err(anyhow!("unexpected authorization status: {other:?}")),
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow!("CA offered no http-01 challenge for {domain}"))?;
            // Key authorization is `token.thumbprint` (RFC 8555 §8.1); the URL
            // path carries just the token, the response body is the whole thing.
            let body = challenge.key_authorization().as_str().to_string();
            let token = body
                .split('.')
                .next()
                .ok_or_else(|| anyhow!("malformed key authorization"))?
                .to_string();
            challenges.lock().insert(token.clone(), body);
            provisioned.push(token);
            challenge.set_ready().await?;
        }
    }

    drive_to_certificate(order, domain).await
}

/// Poll the order to `Ready`, finalize (library generates the keypair + CSR) and
/// download the certificate chain.
async fn drive_to_certificate(
    order: &mut instant_acme::Order,
    domain: &str,
) -> Result<(String, String)> {
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .context("waiting for ACME order to become ready")?;
    if status != OrderStatus::Ready {
        return Err(anyhow!(
            "ACME validation for {domain} failed (order status {status:?}). \
             Check that the domain resolves to this host and port 80 is reachable from the internet."
        ));
    }
    let private_key_pem = order.finalize().await.context("finalizing ACME order")?;
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("downloading issued certificate")?;
    Ok((cert_chain_pem, private_key_pem))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}
