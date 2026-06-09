//! Brute-force protection for the **admin login**.
//!
//! The control-plane login (`auth.login`) is deliberately *not* run through the
//! WAF/data-plane rate-limiter (the admin console isn't evaluated, so a bad rule
//! can't lock you out). That left the login with no throttle at all — an exposed
//! admin port could be brute-forced offline-fast. This adds a small per-IP
//! **exponential-backoff** lockout: the first few failures are free (fat-finger
//! tolerance), then each further failure locks the IP for a doubling window.
//!
//! Keyed on the **socket peer IP**, never `X-Forwarded-For` — a spoofable header
//! must not be able to evade (or weaponize) a lockout.
//!
//! Bounded memory: the map is capped and stale entries are evicted, so a flood of
//! distinct source IPs can't exhaust memory (same guard as the WAF rate-limiter).

use parking_lot::Mutex;
use std::collections::HashMap;

/// Failures allowed before lockout begins (forgiving of genuine mistakes).
const FREE_ATTEMPTS: u32 = 5;
/// First lockout duration, in seconds. Doubles on each subsequent failure.
const BASE_LOCK_SECS: i64 = 60;
/// Upper bound on a single lockout window (15 minutes).
const MAX_LOCK_SECS: i64 = 900;
/// Cap on tracked IPs, to bound memory under a distributed flood.
const MAX_KEYS: usize = 50_000;

struct Entry {
    /// Consecutive failed attempts (reset on success).
    fails: u32,
    /// Epoch second until which this IP is locked (`0` = not locked).
    locked_until: i64,
}

/// Per-IP login throttle (exponential backoff). Cheap to clone via `Arc` in state.
pub struct LoginThrottle {
    inner: Mutex<HashMap<String, Entry>>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// If `ip` is currently locked out, return the remaining lock time in seconds
    /// (always ≥ 1). `None` means the IP may attempt a login.
    pub fn locked_for(&self, ip: &str, now: i64) -> Option<i64> {
        let map = self.inner.lock();
        map.get(ip)
            .filter(|e| e.locked_until > now)
            .map(|e| e.locked_until - now)
    }

    /// Record a failed login. Returns the lock duration just applied in seconds
    /// (`0` while still within the free-attempt grace band).
    pub fn record_failure(&self, ip: &str, now: i64) -> i64 {
        let mut map = self.inner.lock();
        // Evict stale, no-longer-locked entries when the map grows too large.
        if map.len() >= MAX_KEYS {
            map.retain(|_, e| e.locked_until > now);
        }
        let entry = map.entry(ip.to_string()).or_insert(Entry {
            fails: 0,
            locked_until: 0,
        });
        entry.fails = entry.fails.saturating_add(1);
        if entry.fails <= FREE_ATTEMPTS {
            return 0;
        }
        // 6th failure → 60s, 7th → 120s, 8th → 240s … capped at MAX_LOCK_SECS.
        let steps = (entry.fails - FREE_ATTEMPTS - 1).min(20);
        let secs = BASE_LOCK_SECS
            .saturating_mul(1i64 << steps)
            .min(MAX_LOCK_SECS);
        entry.locked_until = now + secs;
        secs
    }

    /// Clear all failure state for `ip` after a successful login.
    pub fn record_success(&self, ip: &str) {
        self.inner.lock().remove(ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_attempts_do_not_lock() {
        let t = LoginThrottle::new();
        for _ in 0..FREE_ATTEMPTS {
            assert_eq!(t.record_failure("1.2.3.4", 1000), 0);
            assert!(t.locked_for("1.2.3.4", 1000).is_none());
        }
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let t = LoginThrottle::new();
        for _ in 0..FREE_ATTEMPTS {
            t.record_failure("9.9.9.9", 0);
        }
        // 6th → 60, 7th → 120, 8th → 240, 9th → 480, 10th → 900 (cap, not 960).
        assert_eq!(t.record_failure("9.9.9.9", 0), 60);
        assert_eq!(t.record_failure("9.9.9.9", 0), 120);
        assert_eq!(t.record_failure("9.9.9.9", 0), 240);
        assert_eq!(t.record_failure("9.9.9.9", 0), 480);
        assert_eq!(t.record_failure("9.9.9.9", 0), MAX_LOCK_SECS);
        assert_eq!(t.record_failure("9.9.9.9", 0), MAX_LOCK_SECS);
    }

    #[test]
    fn lock_reports_remaining_then_expires() {
        let t = LoginThrottle::new();
        for _ in 0..=FREE_ATTEMPTS {
            t.record_failure("5.5.5.5", 1000);
        }
        assert_eq!(t.locked_for("5.5.5.5", 1000), Some(60)); // locked now
        assert_eq!(t.locked_for("5.5.5.5", 1030), Some(30)); // 30s remaining
        assert!(t.locked_for("5.5.5.5", 1060).is_none()); // expired
        assert!(t.locked_for("5.5.5.5", 1100).is_none());
    }

    #[test]
    fn success_resets() {
        let t = LoginThrottle::new();
        for _ in 0..=FREE_ATTEMPTS {
            t.record_failure("7.7.7.7", 0);
        }
        assert!(t.locked_for("7.7.7.7", 0).is_some());
        t.record_success("7.7.7.7");
        assert!(t.locked_for("7.7.7.7", 0).is_none());
        // After reset, the grace band is full again.
        assert_eq!(t.record_failure("7.7.7.7", 0), 0);
    }

    #[test]
    fn ips_are_independent() {
        let t = LoginThrottle::new();
        for _ in 0..=FREE_ATTEMPTS {
            t.record_failure("1.1.1.1", 0);
        }
        assert!(t.locked_for("1.1.1.1", 0).is_some());
        assert!(t.locked_for("2.2.2.2", 0).is_none()); // a different IP is unaffected
    }
}
