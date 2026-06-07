//! Authentication primitives: Argon2 password hashing and JWT issue/verify.
//!
//! Credentials live in the persisted config (`Store::auth`), not in env, so they
//! can be changed at runtime via the console. The bearer token returned by
//! `auth.login` is a signed, expiring JWT validated on every protected RPC.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

/// Token lifetime in seconds (8 hours).
const TOKEN_TTL_SECS: i64 = 8 * 3600;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (username).
    pub sub: String,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Issued-at (unix seconds).
    pub iat: i64,
}

/// Hash a plaintext password with Argon2id.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("hash error: {e}"))
}

/// Verify a plaintext password against a stored Argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Issue a signed JWT for `username`, valid for `TOKEN_TTL_SECS`.
pub fn issue_jwt(username: &str, secret: &str, now: i64) -> Result<String, String> {
    let claims = Claims {
        sub: username.to_string(),
        iat: now,
        exp: now + TOKEN_TTL_SECS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| format!("jwt encode error: {e}"))
}

/// Validate a JWT (signature + expiry). Returns the claims on success.
pub fn verify_jwt(token: &str, secret: &str) -> Option<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .ok()
    .map(|data| data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let h = hash_password("s3cr3t").unwrap();
        assert!(verify_password("s3cr3t", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("s3cr3t", "not-a-hash"));
    }

    #[test]
    fn jwt_round_trip_and_rejects_wrong_secret() {
        // Far-future issue time so the token is unexpired regardless of test clock.
        let now = 4_000_000_000;
        let token = issue_jwt("admin", "secret", now).unwrap();
        let claims = verify_jwt(&token, "secret").expect("valid token");
        assert_eq!(claims.sub, "admin");
        assert!(verify_jwt(&token, "other").is_none());
    }

    #[test]
    fn jwt_expired_is_rejected() {
        // iat far in the past → exp far in the past → expired.
        let token = issue_jwt("admin", "secret", 1_000_000_000).unwrap();
        assert!(verify_jwt(&token, "secret").is_none());
    }
}
