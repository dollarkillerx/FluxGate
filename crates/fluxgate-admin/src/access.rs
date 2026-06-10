//! IP access control: manual allow/block lists + optional **auto-ban**.
//!
//! * **Whitelist** — fully trusted; the data plane skips the block-list, auto-ban,
//!   per-site access controls and the WAF for these IPs.
//! * **Blacklist** — always denied (manual, admin-managed).
//! * **Auto-ban** — when enabled, an IP that trips `threshold` WAF *denies* within
//!   a 24h window is banned for a configured duration (or permanently). Auto-bans
//!   are persisted (so a permanent ban survives a restart); the deny-count window
//!   is in-memory and bounded.
//!
//! Matching reuses the dual-stack [`crate::iprange::CidrList`]. All decisions are
//! made on the **real client IP** (Cloudflare-aware, unspoofable) supplied by the
//! caller — see `proxy.rs`.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use fluxgate_core::{BanEntry, IpListEntry};

use crate::iprange::CidrList;

/// Rolling window for the deny-count threshold.
const WINDOW_SECS: i64 = 24 * 3600;
/// Cap on distinct IPs tracked for the deny count (bounds memory).
const MAX_TRACKED_IPS: usize = 100_000;
/// Cap on stored auto-bans.
const MAX_AUTO_BANS: usize = 50_000;
/// Sentinel expiry for a permanent ban.
const PERMANENT: i64 = i64::MAX;

/// Auto-ban parameters for one evaluation (mirrors the `Settings` fields).
#[derive(Clone, Copy)]
pub struct AutoBanCfg {
    pub enabled: bool,
    pub threshold: u32,
    /// `<= 0` → permanent.
    pub duration_secs: i64,
}

#[derive(Clone, Serialize, Deserialize)]
struct BanRecord {
    expires_at: i64,
    deny_count: u32,
}

#[derive(Default, Serialize, Deserialize)]
struct BanSnapshot {
    bans: HashMap<String, BanRecord>,
}

pub struct AccessControl {
    /// Compiled manual allow-list (rebuilt from config).
    allow: RwLock<Arc<CidrList>>,
    /// Compiled manual block-list.
    block: RwLock<Arc<CidrList>>,
    /// ip → recent deny timestamps within the window (bounded).
    deny_window: Mutex<HashMap<String, VecDeque<i64>>>,
    /// ip → auto-ban record (persisted).
    bans: Mutex<HashMap<String, BanRecord>>,
    /// Fast path: true while any auto-ban exists, so `is_blocked` can skip the
    /// `bans` lock entirely when none are active.
    has_bans: AtomicBool,
    path: Option<PathBuf>,
}

impl AccessControl {
    /// Load persisted auto-bans (if any), start with empty compiled lists
    /// (`rebuild` is called with the config right after).
    pub fn new(path: Option<PathBuf>) -> Self {
        let bans: HashMap<String, BanRecord> = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<BanSnapshot>(&s).ok())
            .map(|s| s.bans)
            .unwrap_or_default();
        let has = !bans.is_empty();
        Self {
            allow: RwLock::new(Arc::new(CidrList::default())),
            block: RwLock::new(Arc::new(CidrList::default())),
            deny_window: Mutex::new(HashMap::new()),
            bans: Mutex::new(bans),
            has_bans: AtomicBool::new(has),
            path,
        }
    }

    /// Recompile the manual allow / block lists from the persisted config.
    pub fn rebuild(&self, whitelist: &[IpListEntry], blacklist: &[IpListEntry]) {
        *self.allow.write() = Arc::new(compile(whitelist));
        *self.block.write() = Arc::new(compile(blacklist));
    }

    /// Whether `ip` is fully trusted (skips all blocking).
    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        let allow = self.allow.read().clone(); // cheap Arc clone, lock released
        allow.contains(ip)
    }

    /// Whether `ip` is currently denied (manual block-list or an active auto-ban).
    pub fn is_blocked(&self, ip: IpAddr, now: i64) -> bool {
        let block = self.block.read().clone();
        if block.contains(ip) {
            return true;
        }
        if !self.has_bans.load(Ordering::Relaxed) {
            return false;
        }
        self.bans
            .lock()
            .get(&ip.to_string())
            .map(|b| b.expires_at > now)
            .unwrap_or(false)
    }

    /// Record a WAF deny for `ip`. When auto-ban is on and the IP crosses the
    /// threshold within the window, ban it. Returns the ban's expiry (`0` =
    /// permanent) iff a ban was just created — for the caller to log.
    pub fn record_deny(&self, ip: &str, now: i64, cfg: AutoBanCfg) -> Option<i64> {
        if !cfg.enabled || cfg.threshold == 0 {
            return None;
        }
        // Already banned → just bump its deny tally, don't re-ban.
        if self.has_bans.load(Ordering::Relaxed) {
            let mut bans = self.bans.lock();
            if let Some(b) = bans.get_mut(ip) {
                if b.expires_at > now {
                    b.deny_count = b.deny_count.saturating_add(1);
                    return None;
                }
            }
        }
        let count = {
            let mut win = self.deny_window.lock();
            if win.len() >= MAX_TRACKED_IPS {
                win.retain(|_, q| q.back().map(|&t| now - t < WINDOW_SECS).unwrap_or(false));
            }
            let q = win.entry(ip.to_string()).or_default();
            while q.front().map(|&t| now - t >= WINDOW_SECS).unwrap_or(false) {
                q.pop_front();
            }
            q.push_back(now);
            // Only the threshold matters — never keep more than that many stamps.
            while q.len() > cfg.threshold as usize {
                q.pop_front();
            }
            q.len() as u32
        };
        if count < cfg.threshold {
            return None;
        }
        let expires = if cfg.duration_secs <= 0 {
            PERMANENT
        } else {
            now.saturating_add(cfg.duration_secs)
        };
        {
            let mut bans = self.bans.lock();
            if bans.len() >= MAX_AUTO_BANS {
                bans.retain(|_, b| b.expires_at > now);
            }
            bans.insert(
                ip.to_string(),
                BanRecord {
                    expires_at: expires,
                    deny_count: count,
                },
            );
            self.has_bans.store(true, Ordering::Relaxed);
        }
        self.deny_window.lock().remove(ip); // banned now — stop counting
        Some(if expires == PERMANENT { 0 } else { expires })
    }

    /// Lift an auto-ban (admin unban). Returns whether one existed.
    pub fn unban(&self, ip: &str) -> bool {
        self.deny_window.lock().remove(ip);
        let mut bans = self.bans.lock();
        let existed = bans.remove(ip).is_some();
        self.has_bans.store(!bans.is_empty(), Ordering::Relaxed);
        existed
    }

    /// Active auto-bans (purges expired in passing), most-active first.
    pub fn list_bans(&self, now: i64) -> Vec<BanEntry> {
        let mut bans = self.bans.lock();
        bans.retain(|_, b| b.expires_at > now);
        self.has_bans.store(!bans.is_empty(), Ordering::Relaxed);
        let mut v: Vec<BanEntry> = bans
            .iter()
            .map(|(ip, b)| BanEntry {
                ip: ip.clone(),
                expires_at: if b.expires_at == PERMANENT {
                    0
                } else {
                    b.expires_at
                },
                deny_count: b.deny_count,
            })
            .collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.deny_count));
        v
    }

    /// Persist auto-bans (purging expired). Best-effort; called periodically.
    pub fn flush(&self, now: i64) {
        let Some(path) = &self.path else {
            return;
        };
        let snapshot = {
            let mut bans = self.bans.lock();
            bans.retain(|_, b| b.expires_at > now);
            self.has_bans.store(!bans.is_empty(), Ordering::Relaxed);
            BanSnapshot { bans: bans.clone() }
        };
        if let Ok(s) = serde_json::to_string(&snapshot) {
            let _ = std::fs::write(path, s);
        }
    }
}

fn compile(entries: &[IpListEntry]) -> CidrList {
    let text = entries
        .iter()
        .map(|e| e.value.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    CidrList::parse_lines(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(v: &str) -> IpListEntry {
        IpListEntry {
            value: v.into(),
            note: String::new(),
        }
    }
    fn cfg(threshold: u32, dur: i64) -> AutoBanCfg {
        AutoBanCfg {
            enabled: true,
            threshold,
            duration_secs: dur,
        }
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn whitelist_and_blacklist_match_dual_stack() {
        let ac = AccessControl::new(None);
        ac.rebuild(
            &[entry("10.0.0.0/8"), entry("2001:db8::/32")],
            &[entry("1.2.3.4")],
        );
        assert!(ac.is_whitelisted(ip("10.9.9.9")));
        assert!(ac.is_whitelisted(ip("2001:db8::1")));
        assert!(!ac.is_whitelisted(ip("8.8.8.8")));
        assert!(ac.is_blocked(ip("1.2.3.4"), 1000));
        assert!(!ac.is_blocked(ip("1.2.3.5"), 1000));
    }

    #[test]
    fn auto_ban_trips_at_threshold_and_expires() {
        let ac = AccessControl::new(None);
        let c = cfg(3, 100); // 3 denies → ban 100s
        assert_eq!(ac.record_deny("9.9.9.9", 1000, c), None); // 1
        assert_eq!(ac.record_deny("9.9.9.9", 1001, c), None); // 2
        assert_eq!(ac.record_deny("9.9.9.9", 1002, c), Some(1102)); // 3 → banned
        assert!(ac.is_blocked(ip("9.9.9.9"), 1050));
        assert!(!ac.is_blocked(ip("9.9.9.9"), 1102)); // expired (expires_at not > now)
                                                      // A different IP is unaffected.
        assert!(!ac.is_blocked(ip("8.8.8.8"), 1050));
    }

    #[test]
    fn permanent_ban_and_unban() {
        let ac = AccessControl::new(None);
        let c = cfg(1, 0); // 1 deny → permanent
        assert_eq!(ac.record_deny("5.5.5.5", 1000, c), Some(0)); // 0 = permanent
        assert!(ac.is_blocked(ip("5.5.5.5"), i64::MAX - 1));
        assert!(ac.unban("5.5.5.5"));
        assert!(!ac.is_blocked(ip("5.5.5.5"), 1000));
        assert!(!ac.unban("5.5.5.5")); // already gone
    }

    #[test]
    fn disabled_or_old_denies_dont_ban() {
        let ac = AccessControl::new(None);
        let off = AutoBanCfg {
            enabled: false,
            threshold: 1,
            duration_secs: 100,
        };
        assert_eq!(ac.record_deny("1.1.1.1", 1000, off), None);
        assert!(!ac.is_blocked(ip("1.1.1.1"), 1000));
        // Denies older than the 24h window don't accumulate.
        let c = cfg(2, 100);
        ac.record_deny("2.2.2.2", 1000, c);
        assert_eq!(ac.record_deny("2.2.2.2", 1000 + WINDOW_SECS, c), None); // old one pruned
    }
}
