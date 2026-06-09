//! Real data collectors that replace the former mock generators.
//!
//! * `Telemetry`  — samples real host CPU / memory / network via `sysinfo`.
//! * `LogBuffer`  — a ring buffer of real HTTP requests served by this process.
//! * free fns     — derive dashboard / metrics figures from those real sources,
//!   and probe upstream TCP reachability.
//!
//! Nothing here fabricates numbers. Quantities that would require a real proxy
//! data plane (WAF hits, security events) are reported as empty/zero rather than
//! invented.

use std::collections::VecDeque;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use sysinfo::{Networks, System};

use fluxgate_core::*;

use crate::state::Store;

/// Open a file for appending (create if missing). The handle uses `O_APPEND`,
/// so writes always go to the current end — even after the retention pass
/// truncates the file in place — which lets us keep one handle for the whole
/// process instead of re-`open()`ing on every request.
fn open_append(path: &PathBuf) -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

/// Warn the first time a JSONL persistence write fails (and again only after it
/// recovers), so a full / read-only disk is surfaced without spamming per-line.
/// Returns the new "write ok" state.
fn warn_on_log_write(what: &str, res: std::io::Result<()>, was_ok: bool) -> bool {
    match res {
        Ok(()) => true,
        Err(e) => {
            if was_ok {
                tracing::warn!("{what} persistence write failed: {e}");
            }
            false
        }
    }
}

/// Read a JSONL file → (total line count, last `cap` parsed, newest-first).
fn load_jsonl<T: serde::de::DeserializeOwned>(path: &PathBuf, cap: usize) -> (u64, VecDeque<T>) {
    let mut entries = VecDeque::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return (0, entries);
    };
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let total = lines.len() as u64;
    for line in lines.iter().rev().take(cap) {
        if let Ok(v) = serde_json::from_str::<T>(line) {
            entries.push_back(v); // rev() => newest first
        }
    }
    (total, entries)
}

// ---------------------------------------------------------------------------
// Host telemetry (sysinfo)
// ---------------------------------------------------------------------------

pub struct Telemetry {
    sys: System,
    networks: Networks,
    started_at: DateTime<Utc>,
    start: Instant,
    interval_secs: f64,
    cap: usize,
    cpu: VecDeque<f64>,
    mem: VecDeque<f64>,
    net_in: VecDeque<f64>,
    net_out: VecDeque<f64>,
}

impl Telemetry {
    pub fn new() -> Self {
        let mut t = Self {
            sys: System::new_all(),
            networks: Networks::new_with_refreshed_list(),
            started_at: Utc::now(),
            start: Instant::now(),
            interval_secs: 3.0,
            cap: 40,
            cpu: VecDeque::new(),
            mem: VecDeque::new(),
            net_in: VecDeque::new(),
            net_out: VecDeque::new(),
        };
        // Prime CPU counters; the first reading is meaningful on the next sample.
        t.sys.refresh_cpu_all();
        t
    }

    /// Take one real sample of the host. Called periodically by a background task.
    pub fn sample(&mut self) {
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
        self.networks.refresh();

        let cpu = self.sys.global_cpu_usage() as f64;
        let total = self.sys.total_memory() as f64;
        let used = self.sys.used_memory() as f64;
        let mem = if total > 0.0 {
            used / total * 100.0
        } else {
            0.0
        };

        let (mut rx, mut tx) = (0u64, 0u64);
        for (_, data) in &self.networks {
            rx += data.received();
            tx += data.transmitted();
        }
        let net_in = rx as f64 / self.interval_secs / 1_000_000.0;
        let net_out = tx as f64 / self.interval_secs / 1_000_000.0;

        push_cap(&mut self.cpu, cpu, self.cap);
        push_cap(&mut self.mem, mem, self.cap);
        push_cap(&mut self.net_in, net_in, self.cap);
        push_cap(&mut self.net_out, net_out, self.cap);
    }

    pub fn metrics_system(&self) -> Vec<MetricSeries> {
        vec![
            self.build("cpu", "CPU Usage", "%", &self.cpu),
            self.build("memory", "Memory Usage", "%", &self.mem),
            self.build("net_in", "Network In", "MB/s", &self.net_in),
            self.build("net_out", "Network Out", "MB/s", &self.net_out),
        ]
    }

    pub fn system_info(&self) -> SystemInfo {
        SystemInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            build: format!(
                "{} {}",
                System::name().unwrap_or_else(|| "host".into()),
                System::os_version().unwrap_or_default()
            ),
            // The data plane is a hyper-based reverse proxy (field name kept for
            // API compatibility; it reports the actual proxy engine).
            pingora_version: concat!("hyper ", env!("CARGO_PKG_VERSION")).into(),
            uptime_secs: self.start.elapsed().as_secs(),
            started_at: self.started_at.to_rfc3339(),
        }
    }

    fn build(&self, key: &str, label: &str, unit: &str, data: &VecDeque<f64>) -> MetricSeries {
        let n = data.len();
        let series = data
            .iter()
            .enumerate()
            .map(|(i, v)| MetricPoint {
                t: format!("-{}s", ((n - 1 - i) as f64 * self.interval_secs) as u64),
                value: round2(*v),
            })
            .collect();
        MetricSeries {
            key: key.into(),
            label: label.into(),
            unit: unit.into(),
            current: round2(data.back().copied().unwrap_or(0.0)),
            series,
        }
    }
}

fn push_cap(q: &mut VecDeque<f64>, v: f64, cap: usize) {
    q.push_back(v);
    while q.len() > cap {
        q.pop_front();
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

// ---------------------------------------------------------------------------
// Real access-log ring buffer
// ---------------------------------------------------------------------------

pub struct LogBuffer {
    entries: VecDeque<AccessLog>, // newest first
    total: u64,
    cap: usize,
    path: Option<PathBuf>,
    file: Option<std::fs::File>, // long-lived O_APPEND handle
    write_ok: bool,              // false after a write failed (warn once per streak)
}

impl LogBuffer {
    /// Create a buffer, loading the tail from `path` if persistence is enabled.
    pub fn new(cap: usize, path: Option<PathBuf>) -> Self {
        let (total, entries) = match &path {
            Some(p) => load_jsonl::<AccessLog>(p, cap),
            None => (0, VecDeque::new()),
        };
        let file = path.as_ref().and_then(open_append);
        Self {
            entries,
            total,
            cap,
            path,
            file,
            write_ok: true,
        }
    }

    pub fn record(&mut self, entry: AccessLog) {
        self.total += 1;
        if let Some(f) = self.file.as_mut() {
            if let Ok(line) = serde_json::to_string(&entry) {
                let res = writeln!(f, "{line}");
                self.write_ok = warn_on_log_write("access-log", res, self.write_ok);
            }
        }
        self.entries.push_front(entry);
        while self.entries.len() > self.cap {
            self.entries.pop_back();
        }
    }

    /// Total requests served since startup (not just those still buffered).
    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn snapshot(&self) -> Vec<AccessLog> {
        self.entries.iter().cloned().collect()
    }

    /// Drop entries older than `cutoff` from memory and the on-disk JSONL.
    /// Returns the number of disk lines removed.
    pub fn prune_older_than(&mut self, cutoff: DateTime<Utc>) -> u64 {
        self.entries
            .retain(|e| parse(&e.time).map(|t| t >= cutoff).unwrap_or(true));
        self.path
            .as_ref()
            .map(|p| prune_jsonl_by_time(p, cutoff))
            .unwrap_or(0)
    }
}

/// Rewrite a JSONL file in place, keeping only records whose `time` field is at
/// or after `cutoff`. Lines that fail to parse are kept (never silently lost).
/// Returns how many lines were removed.
fn prune_jsonl_by_time(path: &PathBuf, cutoff: DateTime<Utc>) -> u64 {
    let Ok(content) = std::fs::read_to_string(path) else {
        return 0;
    };
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = 0u64;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let keep = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| v.get("time").and_then(|t| t.as_str()).map(str::to_string))
            .and_then(|s| parse(&s))
            .map(|t| t >= cutoff)
            .unwrap_or(true);
        if keep {
            kept.push(line);
        } else {
            removed += 1;
        }
    }
    if removed > 0 {
        let mut out = kept.join("\n");
        if !out.is_empty() {
            out.push('\n');
        }
        let _ = std::fs::write(path, out);
    }
    removed
}

// ---------------------------------------------------------------------------
// Real WAF security-event ring buffer
// ---------------------------------------------------------------------------

pub struct EventBuffer {
    entries: VecDeque<SecurityEvent>, // newest first
    total_deny: u64,
    total_challenge: u64,
    cap: usize,
    path: Option<PathBuf>,
    file: Option<std::fs::File>, // long-lived O_APPEND handle
    write_ok: bool,
}

impl EventBuffer {
    /// Create a buffer, loading recent events + recomputing totals from `path`.
    pub fn new(cap: usize, path: Option<PathBuf>) -> Self {
        let mut total_deny = 0;
        let mut total_challenge = 0;
        let entries = match &path {
            Some(p) => {
                // Count every recorded action over the whole file for accurate totals.
                if let Ok(content) = std::fs::read_to_string(p) {
                    for line in content.lines() {
                        if let Ok(e) = serde_json::from_str::<SecurityEvent>(line) {
                            match e.action {
                                WafAction::Deny => total_deny += 1,
                                WafAction::Challenge => total_challenge += 1,
                                WafAction::Allow => {}
                            }
                        }
                    }
                }
                load_jsonl::<SecurityEvent>(p, cap).1
            }
            None => VecDeque::new(),
        };
        let file = path.as_ref().and_then(open_append);
        Self {
            entries,
            total_deny,
            total_challenge,
            cap,
            path,
            file,
            write_ok: true,
        }
    }

    pub fn record(&mut self, event: SecurityEvent) {
        match event.action {
            WafAction::Deny => self.total_deny += 1,
            WafAction::Challenge => self.total_challenge += 1,
            WafAction::Allow => {}
        }
        if let Some(f) = self.file.as_mut() {
            if let Ok(line) = serde_json::to_string(&event) {
                let res = writeln!(f, "{line}");
                self.write_ok = warn_on_log_write("waf-event", res, self.write_ok);
            }
        }
        self.entries.push_front(event);
        while self.entries.len() > self.cap {
            self.entries.pop_back();
        }
    }

    pub fn total_deny(&self) -> u64 {
        self.total_deny
    }

    pub fn snapshot(&self) -> Vec<SecurityEvent> {
        self.entries.iter().cloned().collect()
    }

    /// Borrow the events without cloning (newest first).
    pub fn entries(&self) -> &VecDeque<SecurityEvent> {
        &self.entries
    }

    /// Drop events older than `cutoff` from memory and the on-disk JSONL.
    /// Returns the number of disk lines removed.
    pub fn prune_older_than(&mut self, cutoff: DateTime<Utc>) -> u64 {
        self.entries
            .retain(|e| parse(&e.time).map(|t| t >= cutoff).unwrap_or(true));
        self.path
            .as_ref()
            .map(|p| prune_jsonl_by_time(p, cutoff))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Derived dashboard / metrics figures (from real logs + config)
// ---------------------------------------------------------------------------

fn parse(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Bucket items into 24 one-minute windows over the last 24 minutes, oldest
/// first (index 0 = 23m ago … index 23 = the current minute). Each item's
/// timestamp is parsed **exactly once** (vs. 24× when filtering per bucket), and
/// the source collection is borrowed — no clone. `keep` pre-filters items.
fn bucket_last_24m<'a, T: 'a>(
    items: impl IntoIterator<Item = &'a T>,
    now: DateTime<Utc>,
    time_of: impl Fn(&T) -> &str,
    keep: impl Fn(&T) -> bool,
) -> Vec<Vec<&'a T>> {
    let mut buckets: Vec<Vec<&T>> = (0..24).map(|_| Vec::new()).collect();
    for it in items {
        if !keep(it) {
            continue;
        }
        let Some(t) = parse(time_of(it)) else {
            continue;
        };
        let secs = (now - t).num_seconds();
        if !(0..24 * 60).contains(&secs) {
            continue; // outside the window (or a future timestamp)
        }
        let mins_ago = (secs / 60) as usize;
        buckets[23 - mins_ago].push(it);
    }
    buckets
}

/// Labels matching `bucket_last_24m` order: "-23m" … "-0m". Built once and
/// reused — they're constant, and several polled metric endpoints ask for them.
fn bucket_labels() -> &'static [String] {
    static LABELS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    LABELS.get_or_init(|| (0..24).rev().map(|i| format!("-{}m", i)).collect())
}

/// Cheap config-derived counts, read under the `store` lock by the caller so the
/// lock can be released before the (heavier) log scan in `dashboard_summary`.
pub struct SummaryConfig {
    pub waf_blocks: u64,
    pub tls_certificates: u32,
    pub healthy_upstreams: u32,
    pub total_upstreams: u32,
    pub total_requests: u64,
    pub inflight: i64,
}

/// Build the dashboard KPI summary from an owned log `snap` in a **single pass**
/// (each timestamp parsed once): QPS over the last 5s, plus PV / UV over the 24h
/// window. Operates on a snapshot so no lock is held during the scan — the caller
/// clones under the logs lock and releases it first.
pub fn dashboard_summary(
    snap: &[AccessLog],
    now: DateTime<Utc>,
    cfg: SummaryConfig,
) -> DashboardSummary {
    let window = WINDOW_HOURS * BUCKET_SECS;
    let mut uniq: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let (mut pv_24h, mut recent5) = (0u64, 0u64);
    for l in snap {
        let Some(t) = parse(&l.time) else { continue };
        let age = (now - t).num_seconds();
        if (0..5).contains(&age) {
            recent5 += 1;
        }
        if (0..window).contains(&age) {
            pv_24h += 1;
            uniq.insert(l.client_ip.as_str());
        }
    }

    DashboardSummary {
        total_requests: cfg.total_requests,
        current_qps: (recent5 / 5) as u32,
        waf_blocks: cfg.waf_blocks,
        active_connections: cfg.inflight.max(0) as u32,
        tls_certificates: cfg.tls_certificates,
        healthy_upstreams: cfg.healthy_upstreams,
        total_upstreams: cfg.total_upstreams,
        pv_24h,
        uv_24h: uniq.len() as u64,
        // Filled by the RPC layer from the traffic meter.
        traffic: TrafficTotals::default(),
    }
}

/// 24 one-hour buckets of real request counts over the last 24 hours (oldest
/// first) — matches the dashboard's "last 24 hours" chart.
pub fn traffic_points(snap: &[AccessLog]) -> Vec<TrafficPoint> {
    let now = Utc::now();
    let mut reqs = [0u64; 24];
    let mut blocked = [0u64; 24];
    for l in snap {
        let Some(t) = parse(&l.time) else { continue };
        let age = (now - t).num_seconds();
        if !(0..WINDOW_HOURS * BUCKET_SECS).contains(&age) {
            continue;
        }
        let idx = (23 - age / BUCKET_SECS) as usize;
        reqs[idx] += 1;
        if l.waf_action != WafAction::Allow {
            blocked[idx] += 1;
        }
    }
    (0..24)
        .map(|i| TrafficPoint {
            t: format!("-{}h", 23 - i),
            requests: reqs[i],
            blocked: blocked[i],
        })
        .collect()
}

/// Hourly window length for the 24h analytics.
const WINDOW_HOURS: i64 = 24;
const BUCKET_SECS: i64 = 3600;

/// Compute 24-hour analytics (PV / UV / hourly QPS / latency / error-rate /
/// country breakdown) over `snap` for entries matching `keep`. Operates on an
/// owned snapshot, so the caller can clone under the logs lock and release it
/// before this runs — GeoIP lookups never hold the lock. Each distinct client IP
/// is geo-resolved once (cached).
pub fn window_stats(
    snap: &[AccessLog],
    now: DateTime<Utc>,
    keep: impl Fn(&AccessLog) -> bool,
    country_of: impl Fn(&str) -> Option<String>,
    top_countries: usize,
) -> RouteStats {
    use std::collections::{HashMap, HashSet};
    let window = WINDOW_HOURS * BUCKET_SECS;
    let mut bucket_reqs = [0u64; 24];
    let mut latencies: Vec<u32> = Vec::new();
    let mut uniq: HashSet<&str> = HashSet::new();
    let mut ip_country: HashMap<&str, String> = HashMap::new();
    let mut country_counts: HashMap<String, u64> = HashMap::new();
    let mut device_counts: HashMap<&str, u64> = HashMap::new();
    let (mut pv, mut errors, mut recent60) = (0u64, 0u64, 0u64);

    for l in snap {
        if !keep(l) {
            continue;
        }
        let Some(t) = parse(&l.time) else { continue };
        let age = (now - t).num_seconds();
        if !(0..window).contains(&age) {
            continue;
        }
        pv += 1;
        if age < 60 {
            recent60 += 1;
        }
        uniq.insert(l.client_ip.as_str());
        bucket_reqs[(23 - age / BUCKET_SECS) as usize] += 1;
        latencies.push(l.latency_ms);
        if l.status >= 400 {
            errors += 1;
        }
        let cc = ip_country
            .entry(l.client_ip.as_str())
            .or_insert_with(|| country_of(&l.client_ip).unwrap_or_else(|| "??".into()));
        *country_counts.entry(cc.clone()).or_default() += 1;
        let dev = if l.device.is_empty() {
            "unknown"
        } else {
            l.device.as_str()
        };
        *device_counts.entry(dev).or_default() += 1;
    }

    latencies.sort_unstable();
    let pct = |p: f64| {
        if latencies.is_empty() {
            0.0
        } else {
            latencies[((latencies.len() - 1) as f64 * p).round() as usize] as f64
        }
    };
    let qps_series = (0..24)
        .map(|i| MetricPoint {
            t: format!("-{}h", 23 - i),
            value: round2(bucket_reqs[i] as f64 / BUCKET_SECS as f64),
        })
        .collect();
    let mut countries: Vec<CountryStat> = country_counts
        .into_iter()
        .map(|(country, requests)| CountryStat { country, requests })
        .collect();
    countries.sort_by_key(|c| std::cmp::Reverse(c.requests));
    countries.truncate(top_countries);
    let mut devices: Vec<DeviceStat> = device_counts
        .into_iter()
        .map(|(device, requests)| DeviceStat {
            device: device.to_string(),
            requests,
        })
        .collect();
    devices.sort_by_key(|d| std::cmp::Reverse(d.requests));

    RouteStats {
        window_hours: WINDOW_HOURS as u32,
        pv,
        uv: uniq.len() as u64,
        current_qps: round2(recent60 as f64 / 60.0),
        error_rate: if pv == 0 {
            0.0
        } else {
            round2(errors as f64 / pv as f64 * 100.0)
        },
        latency_p50: pct(0.50),
        latency_p99: pct(0.99),
        qps_series,
        countries,
        devices,
        // Host-level byte traffic is attached by the RPC layer (it owns the meter).
        traffic: TrafficTotals::default(),
    }
}

pub fn top_routes(snap: &[AccessLog]) -> Vec<TopRoute> {
    use std::collections::HashMap;
    let mut counts: HashMap<String, u64> = HashMap::new();
    for l in snap {
        *counts.entry(format!("{}{}", l.host, l.path)).or_default() += 1;
    }
    let mut v: Vec<TopRoute> = counts
        .into_iter()
        .map(|(route, requests)| TopRoute {
            route,
            requests,
            blocked: 0,
        })
        .collect();
    v.sort_by_key(|r| std::cmp::Reverse(r.requests));
    v.truncate(5);
    v
}

/// Real request throughput / latency / error-rate over the last 24 minutes.
pub fn metrics_traffic(snap: &[AccessLog]) -> Vec<MetricSeries> {
    let now = Utc::now();
    let buckets = bucket_last_24m(snap, now, |l| l.time.as_str(), |_| true);
    let labels = bucket_labels();

    let qps = series_from(labels, &buckets, |b| b.len() as f64 / 60.0);
    let p50 = series_from(labels, &buckets, |b| latency_pct(b, 0.50));
    let p99 = series_from(labels, &buckets, |b| latency_pct(b, 0.99));
    let err = series_from(labels, &buckets, |b| {
        if b.is_empty() {
            0.0
        } else {
            let bad = b.iter().filter(|l| l.status >= 400).count() as f64;
            bad / b.len() as f64 * 100.0
        }
    });

    vec![
        named(qps, "qps", "Requests / sec", "req/s"),
        named(p50, "latency_p50", "Latency p50", "ms"),
        named(p99, "latency_p99", "Latency p99", "ms"),
        named(err, "error_rate", "Error Rate", "%"),
    ]
}

pub fn metrics_upstream(store: &Store) -> Vec<MetricSeries> {
    store
        .upstreams
        .iter()
        .map(|u| {
            let pct = if u.servers.is_empty() {
                0.0
            } else {
                u.healthy_servers as f64 / u.servers.len() as f64 * 100.0
            };
            MetricSeries {
                key: u.name.clone(),
                label: u.name.clone(),
                unit: "% healthy".into(),
                current: round2(pct),
                series: vec![MetricPoint {
                    t: "now".into(),
                    value: round2(pct),
                }],
            }
        })
        .collect()
}

/// Real WAF blocks / challenges per minute, bucketed from recorded events.
pub fn metrics_waf(events: &EventBuffer) -> Vec<MetricSeries> {
    let now = Utc::now();
    let buckets = bucket_last_24m(events.entries(), now, |e| e.time.as_str(), |_| true);
    let labels = bucket_labels();

    let count = |b: &[&SecurityEvent], action: WafAction| {
        b.iter().filter(|e| e.action == action).count() as f64
    };
    let blocks = labels
        .iter()
        .zip(buckets.iter())
        .map(|(t, b)| MetricPoint {
            t: t.clone(),
            value: count(b, WafAction::Deny),
        })
        .collect();
    let challenges = labels
        .iter()
        .zip(buckets.iter())
        .map(|(t, b)| MetricPoint {
            t: t.clone(),
            value: count(b, WafAction::Challenge),
        })
        .collect();

    vec![
        named(blocks, "blocks", "WAF Blocks", "/min"),
        named(challenges, "challenges", "Challenges", "/min"),
    ]
}

fn series_from(
    labels: &[String],
    buckets: &[Vec<&AccessLog>],
    f: impl Fn(&[&AccessLog]) -> f64,
) -> Vec<MetricPoint> {
    labels
        .iter()
        .zip(buckets.iter())
        .map(|(t, b)| MetricPoint {
            t: t.clone(),
            value: round2(f(b)),
        })
        .collect()
}

fn named(series: Vec<MetricPoint>, key: &str, label: &str, unit: &str) -> MetricSeries {
    let current = series.last().map(|p| p.value).unwrap_or(0.0);
    MetricSeries {
        key: key.into(),
        label: label.into(),
        unit: unit.into(),
        current,
        series,
    }
}

fn latency_pct(bucket: &[&AccessLog], p: f64) -> f64 {
    if bucket.is_empty() {
        return 0.0;
    }
    let mut lat: Vec<u32> = bucket.iter().map(|l| l.latency_ms).collect();
    lat.sort_unstable();
    let idx = ((lat.len() as f64 - 1.0) * p).round() as usize;
    lat[idx] as f64
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    fn log_at(time: DateTime<Utc>, host: &str, path: &str, status: u16) -> AccessLog {
        AccessLog {
            id: "x".into(),
            time: time.to_rfc3339(),
            client_ip: "127.0.0.1".into(),
            method: "GET".into(),
            host: host.into(),
            path: path.into(),
            status,
            latency_ms: 5,
            upstream: "u".into(),
            waf_action: WafAction::Allow,
            device: "windows".into(),
        }
    }

    #[test]
    fn prune_drops_entries_older_than_cutoff() {
        let mut buf = LogBuffer::new(100, None);
        let now = Utc::now();
        buf.record(log_at(now - chrono::Duration::days(10), "a.com", "/", 200)); // stale
        buf.record(log_at(now - chrono::Duration::hours(1), "a.com", "/", 200)); // fresh
        assert_eq!(buf.snapshot().len(), 2);

        let cutoff = now - chrono::Duration::days(6);
        buf.prune_older_than(cutoff);
        let kept = buf.snapshot();
        assert_eq!(kept.len(), 1, "only the within-window entry should remain");
        assert!(kept.iter().all(|l| parse(&l.time).unwrap() >= cutoff));
    }

    #[test]
    fn window_stats_filters_and_counts_pv_uv() {
        let now = Utc::now();
        let snap = vec![
            log_ip(now, "a.com", "/api/x", 200, "1.1.1.1"), // match
            log_ip(now, "a.com", "/api/y", 200, "1.1.1.1"), // match (same IP)
            log_ip(now, "a.com", "/api/z", 500, "2.2.2.2"), // match (error, new IP)
            log_ip(now, "a.com", "/other", 200, "3.3.3.3"), // wrong path
            log_ip(now, "b.com", "/api/q", 200, "4.4.4.4"), // wrong host
        ];
        let stats = window_stats(
            &snap,
            now,
            |l| l.host.eq_ignore_ascii_case("a.com") && l.path.starts_with("/api"),
            |_| None, // no GeoIP in test → all "??"
            10,
        );
        assert_eq!(stats.pv, 3, "3 requests match host+path");
        assert_eq!(stats.uv, 2, "2 distinct client IPs");
        assert_eq!(stats.window_hours, 24);
        assert!((stats.error_rate - round2(100.0 / 3.0)).abs() < 1e-6); // 1 of 3 is 5xx
        assert_eq!(
            stats.countries,
            vec![CountryStat {
                country: "??".into(),
                requests: 3
            }]
        );
        // Newest hourly bucket holds the 3 just-recorded requests.
        assert_eq!(stats.qps_series.last().unwrap().value, round2(3.0 / 3600.0));
    }

    fn log_ip(time: DateTime<Utc>, host: &str, path: &str, status: u16, ip: &str) -> AccessLog {
        let mut l = log_at(time, host, path, status);
        l.client_ip = ip.into();
        l
    }
}

// ---------------------------------------------------------------------------
// Real upstream TCP health probing
// ---------------------------------------------------------------------------

/// TCP-connect to every upstream server, updating `healthy`/`latency_ms`.
pub fn probe_upstreams(store: &mut Store) {
    for up in &mut store.upstreams {
        probe_one_upstream(up);
    }
}

/// Probe a single upstream's nodes.
pub fn probe_one_upstream(up: &mut Upstream) {
    let timeout = Duration::from_millis(800);
    for srv in &mut up.servers {
        match probe_one(&srv.address, timeout) {
            Some(ms) => {
                srv.healthy = true;
                srv.latency_ms = ms;
            }
            None => {
                srv.healthy = false;
                srv.latency_ms = 0;
            }
        }
    }
    up.recompute_health();
}

fn probe_one(address: &str, timeout: Duration) -> Option<u32> {
    // A hostname like "localhost" can resolve to several addresses (e.g. IPv6
    // ::1 *and* IPv4 127.0.0.1). Trying only the first would wrongly report a
    // node down when it listens on a different family than the one resolved
    // first, so probe every candidate and succeed if any connects.
    let addrs: Vec<_> = address.to_socket_addrs().ok()?.collect();
    let start = Instant::now();
    for addr in addrs {
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return Some(start.elapsed().as_millis() as u32);
        }
    }
    None
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn probes_ipv4_listener_via_localhost_hostname() {
        // Bind an IPv4-only listener, then probe through the "localhost" name —
        // which on many systems resolves to IPv6 ::1 first. The probe must still
        // find the IPv4 socket rather than giving up after the first candidate.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ipv4");
        let port = listener.local_addr().unwrap().port();
        let latency = probe_one(&format!("localhost:{port}"), Duration::from_millis(500));
        assert!(
            latency.is_some(),
            "healthy IPv4 listener should be reachable via localhost"
        );
    }

    #[test]
    fn reports_none_for_dead_port() {
        // Reserve a port then drop the listener so nothing is accepting.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(probe_one(&format!("127.0.0.1:{port}"), Duration::from_millis(300)).is_none());
    }
}
