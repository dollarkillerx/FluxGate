//! Per-site **byte traffic** accounting: cumulative total, last 30 days, today.
//!
//! The access log (a ~6-day ring) can't answer "how much traffic has this site
//! ever served", so traffic is aggregated here independently: each metered
//! response adds its byte count to the host's running total and to a per-day
//! bucket. State is persisted to a small JSON file (flushed periodically by a
//! background task) so totals survive restarts; daily buckets older than ~31
//! days are pruned on flush to bound the file.
//!
//! Counting is fed by `MeteredBody` on the data plane (request Content-Length +
//! actual response bytes streamed), so it reflects real bytes — including chunked
//! / streamed responses — not just declared Content-Length.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use chrono::{Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use fluxgate_core::TrafficTotals;

/// Daily buckets kept on disk (≥ the 30-day window, with a day of slack).
const KEEP_DAYS: i64 = 31;
/// Rolling window for the "last 30 days" figure (inclusive of today).
const WINDOW_DAYS: i64 = 30;

#[derive(Default, Clone, Serialize, Deserialize)]
struct HostTraffic {
    total_bytes: u64,
    total_requests: u64,
    /// `YYYY-MM-DD` → bytes served that day (UTC).
    daily: BTreeMap<String, u64>,
}

#[derive(Default, Serialize, Deserialize)]
struct Snapshot {
    hosts: HashMap<String, HostTraffic>,
}

/// Per-host traffic aggregator. Cheap to share via `Arc`; all methods lock briefly.
pub struct TrafficMeter {
    inner: Mutex<HashMap<String, HostTraffic>>,
    path: Option<PathBuf>,
}

impl TrafficMeter {
    /// Load prior totals from `path` if present, else start empty.
    pub fn new(path: Option<PathBuf>) -> Self {
        let inner = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<Snapshot>(&s).ok())
            .map(|s| s.hosts)
            .unwrap_or_default();
        Self {
            inner: Mutex::new(inner),
            path,
        }
    }

    fn today() -> String {
        Utc::now().date_naive().to_string()
    }

    /// Record one metered response of `bytes` for `host`.
    pub fn add(&self, host: &str, bytes: u64) {
        if host.is_empty() {
            return;
        }
        let today = Self::today();
        let mut g = self.inner.lock();
        let h = g.entry(host.to_string()).or_default();
        h.total_bytes = h.total_bytes.saturating_add(bytes);
        h.total_requests = h.total_requests.saturating_add(1);
        *h.daily.entry(today).or_default() += bytes;
    }

    /// Totals for a single host.
    pub fn host_totals(&self, host: &str) -> TrafficTotals {
        let g = self.inner.lock();
        g.get(host).map(totals_of).unwrap_or_default()
    }

    /// Totals summed across every host (whole-proxy view).
    pub fn global_totals(&self) -> TrafficTotals {
        let g = self.inner.lock();
        let mut out = TrafficTotals::default();
        for h in g.values() {
            let t = totals_of(h);
            out.total_bytes += t.total_bytes;
            out.bytes_30d += t.bytes_30d;
            out.bytes_today += t.bytes_today;
            out.total_requests += t.total_requests;
        }
        out
    }

    /// Prune buckets older than `KEEP_DAYS` and persist to disk (best effort).
    pub fn flush(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let keep_cutoff = (Utc::now().date_naive() - Duration::days(KEEP_DAYS)).to_string();
        let snapshot = {
            let mut g = self.inner.lock();
            for h in g.values_mut() {
                h.daily.retain(|d, _| d.as_str() >= keep_cutoff.as_str());
            }
            Snapshot { hosts: g.clone() }
        };
        if let Ok(s) = serde_json::to_string(&snapshot) {
            let _ = std::fs::write(path, s);
        }
    }
}

/// Derive cumulative / 30-day / today figures from a host's buckets. Date strings
/// are `YYYY-MM-DD`, which sort chronologically, so a lexical compare is correct.
fn totals_of(h: &HostTraffic) -> TrafficTotals {
    let today = Utc::now().date_naive();
    let today_s = today.to_string();
    // 30-day window inclusive of today = dates >= today-29.
    let cutoff_30 = (today - Duration::days(WINDOW_DAYS - 1)).to_string();
    let bytes_30d = h
        .daily
        .iter()
        .filter(|(d, _)| d.as_str() >= cutoff_30.as_str())
        .map(|(_, b)| *b)
        .sum();
    let bytes_today = h.daily.get(&today_s).copied().unwrap_or(0);
    TrafficTotals {
        total_bytes: h.total_bytes,
        bytes_30d,
        bytes_today,
        total_requests: h.total_requests,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_with(today_bytes: u64, days: &[(&str, u64)]) -> HostTraffic {
        let mut daily = BTreeMap::new();
        let today = Utc::now().date_naive().to_string();
        daily.insert(today, today_bytes);
        for (d, b) in days {
            daily.insert((*d).to_string(), *b);
        }
        let total = today_bytes + days.iter().map(|(_, b)| *b).sum::<u64>();
        HostTraffic {
            total_bytes: total,
            total_requests: 1 + days.len() as u64,
            daily,
        }
    }

    #[test]
    fn totals_split_today_30d_and_lifetime() {
        let old = (Utc::now().date_naive() - Duration::days(45)).to_string();
        let within = (Utc::now().date_naive() - Duration::days(10)).to_string();
        let h = host_with(100, &[(&within, 50), (&old, 999)]);
        let t = totals_of(&h);
        assert_eq!(t.bytes_today, 100);
        assert_eq!(
            t.bytes_30d, 150,
            "today + the 10-day-old bucket, not the 45-day-old"
        );
        assert_eq!(t.total_bytes, 1149, "lifetime keeps everything");
    }

    #[test]
    fn add_and_global_sum() {
        let m = TrafficMeter::new(None);
        m.add("a.com", 1000);
        m.add("a.com", 500);
        m.add("b.com", 200);
        assert_eq!(m.host_totals("a.com").total_bytes, 1500);
        assert_eq!(m.host_totals("a.com").bytes_today, 1500);
        assert_eq!(m.host_totals("a.com").total_requests, 2);
        let g = m.global_totals();
        assert_eq!(g.total_bytes, 1700);
        assert_eq!(g.bytes_today, 1700);
        assert_eq!(g.total_requests, 3);
        // Unknown host → zeroes, empty host → ignored.
        assert_eq!(m.host_totals("nope").total_bytes, 0);
        m.add("", 9999);
        assert_eq!(m.global_totals().total_bytes, 1700);
    }
}
