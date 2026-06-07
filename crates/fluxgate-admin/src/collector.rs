//! Real data collectors that replace the former mock generators.
//!
//! * `Telemetry`  — samples real host CPU / memory / network via `sysinfo`.
//! * `LogBuffer`  — a ring buffer of real HTTP requests served by this process.
//! * free fns     — derive dashboard / metrics figures from those real sources,
//!                  and probe upstream TCP reachability.
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
        }
    }

    pub fn record(&mut self, entry: AccessLog) {
        self.total += 1;
        if let Some(f) = self.file.as_mut() {
            if let Ok(line) = serde_json::to_string(&entry) {
                let _ = writeln!(f, "{line}");
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

    /// Borrow the entries without cloning (newest first). Used by the metric
    /// derivations, which only read.
    pub fn entries(&self) -> &VecDeque<AccessLog> {
        &self.entries
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
                let _ = writeln!(f, "{line}");
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
fn bucket_last_24m<T>(
    items: &VecDeque<T>,
    now: DateTime<Utc>,
    time_of: impl Fn(&T) -> &str,
    keep: impl Fn(&T) -> bool,
) -> Vec<Vec<&T>> {
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

/// Labels matching `bucket_last_24m` order: "-23m" … "-0m".
fn bucket_labels() -> Vec<String> {
    (0..24).rev().map(|i| format!("-{}m", i)).collect()
}

pub fn dashboard_summary(
    store: &Store,
    logs: &LogBuffer,
    events: &EventBuffer,
    inflight: i64,
) -> DashboardSummary {
    let now = Utc::now();
    // Count requests in the last 5s — parse each timestamp once, no clone.
    let qps = logs
        .entries()
        .iter()
        .filter(|l| {
            parse(&l.time)
                .map(|t| {
                    let s = (now - t).num_seconds();
                    (0..5).contains(&s)
                })
                .unwrap_or(false)
        })
        .count() as u32
        / 5;
    let healthy_upstreams = store
        .upstreams
        .iter()
        .filter(|u| matches!(u.status, UpstreamStatus::Healthy))
        .count() as u32;

    DashboardSummary {
        total_requests: logs.total(),
        current_qps: qps,
        // Real count of requests denied by the WAF engine.
        waf_blocks: events.total_deny(),
        active_connections: inflight.max(0) as u32,
        tls_certificates: store.certs.len() as u32,
        healthy_upstreams,
        total_upstreams: store.upstreams.len() as u32,
    }
}

/// 24 one-minute buckets of real request counts (oldest first).
pub fn traffic_points(logs: &LogBuffer) -> Vec<TrafficPoint> {
    let now = Utc::now();
    let buckets = bucket_last_24m(logs.entries(), now, |l| l.time.as_str(), |_| true);
    buckets
        .iter()
        .enumerate()
        .map(|(idx, b)| TrafficPoint {
            t: format!("-{}m", 23 - idx),
            requests: b.len() as u64,
            blocked: b
                .iter()
                .filter(|l| l.waf_action != WafAction::Allow)
                .count() as u64,
        })
        .collect()
}

pub fn top_routes(logs: &LogBuffer) -> Vec<TopRoute> {
    use std::collections::HashMap;
    let mut counts: HashMap<String, u64> = HashMap::new();
    for l in logs.entries() {
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
    v.sort_by(|a, b| b.requests.cmp(&a.requests));
    v.truncate(5);
    v
}

/// Real request throughput / latency / error-rate over the last 24 minutes.
pub fn metrics_traffic(logs: &LogBuffer) -> Vec<MetricSeries> {
    let now = Utc::now();
    let buckets = bucket_last_24m(logs.entries(), now, |l| l.time.as_str(), |_| true);
    let labels = bucket_labels();

    let qps = series_from(&labels, &buckets, |b| b.len() as f64 / 60.0);
    let p50 = series_from(&labels, &buckets, |b| latency_pct(b, 0.50));
    let p99 = series_from(&labels, &buckets, |b| latency_pct(b, 0.99));
    let err = series_from(&labels, &buckets, |b| {
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

/// Per-route throughput / latency / error-rate over the last 24 minutes, for the
/// requests matching `host` (exact) and `path` (prefix) — powers the route
/// drill-in analytics view.
pub fn metrics_route(logs: &LogBuffer, host: &str, path: &str) -> Vec<MetricSeries> {
    let now = Utc::now();
    let buckets = bucket_last_24m(
        logs.entries(),
        now,
        |l| l.time.as_str(),
        |l| l.host.eq_ignore_ascii_case(host) && l.path.starts_with(path),
    );
    let labels = bucket_labels();

    let qps = series_from(&labels, &buckets, |b| b.len() as f64 / 60.0);
    let p50 = series_from(&labels, &buckets, |b| latency_pct(b, 0.50));
    let p99 = series_from(&labels, &buckets, |b| latency_pct(b, 0.99));
    let err = series_from(&labels, &buckets, |b| {
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
    fn metrics_route_filters_by_host_and_path_prefix() {
        let mut buf = LogBuffer::new(100, None);
        let now = Utc::now();
        buf.record(log_at(now, "a.com", "/api/x", 200)); // matches host + prefix
        buf.record(log_at(now, "a.com", "/other", 200)); // wrong path
        buf.record(log_at(now, "b.com", "/api/y", 200)); // wrong host

        let series = metrics_route(&buf, "a.com", "/api");
        let qps = series.iter().find(|s| s.key == "qps").unwrap();
        // Exactly one matching request in the latest minute bucket → 1/60 req/s,
        // rounded to 2 decimals by the series builder.
        let last = qps.series.last().unwrap().value;
        assert_eq!(
            last,
            round2(1.0 / 60.0),
            "expected one matching request, got {last}"
        );
        // The wrong-host / wrong-path requests must not leak into the series.
        let total: f64 = qps.series.iter().map(|p| p.value).sum();
        assert!(
            total > 0.0 && total < 0.05,
            "only one matching request expected, total={total}"
        );
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
