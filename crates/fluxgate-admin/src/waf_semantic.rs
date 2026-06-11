//! Policy layer for the semantic WAF engine.
//!
//! `fluxgate-waf` is deliberately policy-free: it returns every [`Detection`] it
//! finds. This module turns those detections into an enforcement decision —
//! applying operator **exceptions** (accepted false positives), mapping each
//! detection's risk to a per-module **action** (block / challenge / log), and
//! honoring the site **mode** (monitor downgrades everything to log-only).

use fluxgate_core::{RiskAction, WafAction, WafException, WafMode, WafRisk, WafSemanticConfig};
use fluxgate_waf::Detection;

/// The result of evaluating a request's detections against the policy.
pub struct SemanticOutcome {
    /// The action to take (`Allow` when everything resolved to log-only).
    pub action: WafAction,
    /// The detection that drove the decision — recorded as a security event.
    pub detection: Detection,
    /// Whether the action is enforced (blocked/challenged) vs. only observed
    /// (monitor mode or a `Log` action).
    pub enforced: bool,
    /// Summed anomaly score across all surviving detections on the request.
    pub score: u32,
}

/// Anomaly-score severity per risk level (CRS-ish). Summed across detections.
fn severity(risk: WafRisk) -> u32 {
    match risk {
        WafRisk::Low => 2,
        WafRisk::Medium => 3,
        WafRisk::High => 5,
    }
}

/// Reduce a set of detections to a single outcome. Returns `None` when no
/// detection survives the exceptions.
pub fn decide(
    cfg: &WafSemanticConfig,
    mode: WafMode,
    path: &str,
    detections: Vec<Detection>,
) -> Option<SemanticOutcome> {
    // `mode` is the *effective* mode for this request — the per-route override
    // (`Route.waf_mode`) when set, else the global `cfg.mode`.
    let monitor = matches!(mode, WafMode::Monitor);
    let mut best: Option<(u8, SemanticOutcome)> = None;
    // CRS-style anomaly score: severities of *all* surviving detections add up.
    let mut score = 0u32;

    for d in detections {
        if suppressed(cfg, path, &d) {
            continue;
        }
        score = score.saturating_add(severity(d.risk));
        let module = cfg.module(d.module);
        let (action, enforced) = if monitor {
            (WafAction::Allow, false)
        } else {
            match module.action_for(d.risk) {
                RiskAction::Block => (WafAction::Deny, true),
                RiskAction::Challenge => (WafAction::Challenge, true),
                RiskAction::Log => (WafAction::Allow, false),
            }
        };
        // Rank by enforced action severity first, then by risk, so the most
        // serious detection is the one surfaced/enforced.
        let rank = action_rank(action) * 16 + d.risk as u8;
        let take = best.as_ref().map(|(r, _)| rank > *r).unwrap_or(true);
        if take {
            best = Some((
                rank,
                SemanticOutcome {
                    action,
                    detection: d,
                    enforced,
                    score: 0,
                },
            ));
        }
    }

    let (_, mut outcome) = best?;
    // Anomaly escalation — opt-in and escalation-only: it can raise the action
    // (never lower it), and monitor mode still never enforces.
    if cfg.anomaly.enabled && !monitor && score >= cfg.anomaly.threshold {
        let escalated = match cfg.anomaly.action {
            RiskAction::Block => WafAction::Deny,
            RiskAction::Challenge => WafAction::Challenge,
            RiskAction::Log => WafAction::Allow,
        };
        if action_rank(escalated) > action_rank(outcome.action) {
            outcome.action = escalated;
            outcome.enforced = !matches!(escalated, WafAction::Allow);
        }
    }
    outcome.score = score;
    Some(outcome)
}

fn action_rank(a: WafAction) -> u8 {
    match a {
        WafAction::Allow => 0,
        WafAction::Challenge => 1,
        WafAction::Deny => 2,
    }
}

/// Whether an exception suppresses this detection. Every *set* field of the
/// exception must match; unset fields are wildcards.
fn suppressed(cfg: &WafSemanticConfig, path: &str, d: &Detection) -> bool {
    cfg.exceptions.iter().any(|e| matches(e, path, d))
}

fn matches(e: &WafException, path: &str, d: &Detection) -> bool {
    if !e.enabled {
        return false;
    }
    if let Some(m) = e.module {
        if m != d.module {
            return false;
        }
    }
    if !e.path_prefix.is_empty() && !path.starts_with(&e.path_prefix) {
        return false;
    }
    if let Some(p) = &e.param {
        if p != &d.param {
            return false;
        }
    }
    if let Some(loc) = e.location {
        if loc != d.location {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxgate_core::{AnomalyConfig, WafLocation, WafModule, WafRisk};

    /// Test shim: the real `decide` now takes the effective mode explicitly; these
    /// tests use the config's own mode (the no-override case).
    fn decide(
        cfg: &WafSemanticConfig,
        path: &str,
        detections: Vec<Detection>,
    ) -> Option<SemanticOutcome> {
        super::decide(cfg, cfg.mode, path, detections)
    }

    fn det(module: WafModule, risk: WafRisk) -> Detection {
        Detection {
            module,
            risk,
            location: WafLocation::Query,
            param: "q".into(),
            snippet: "x".into(),
            detail: "t".into(),
        }
    }

    /// Three independent `Low` detections (default policy: each → Log/Allow).
    fn three_lows() -> Vec<Detection> {
        vec![
            det(WafModule::Sqli, WafRisk::Low),
            det(WafModule::Xss, WafRisk::Low),
            det(WafModule::Cmdi, WafRisk::Low),
        ]
    }

    fn anomaly_cfg(enabled: bool) -> WafSemanticConfig {
        WafSemanticConfig {
            anomaly: AnomalyConfig {
                enabled,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn anomaly_escalates_summed_weak_signals() {
        // 3 × Low = 6 ≥ threshold(6); each Low alone is Log/Allow → together escalate.
        let out = decide(&anomaly_cfg(true), "/", three_lows()).unwrap();
        assert_eq!(out.score, 6);
        assert_eq!(out.action, WafAction::Challenge);
        assert!(out.enforced);
    }

    #[test]
    fn anomaly_below_threshold_does_not_escalate() {
        // 2 × Low = 4 < 6.
        let two = vec![
            det(WafModule::Sqli, WafRisk::Low),
            det(WafModule::Xss, WafRisk::Low),
        ];
        let out = decide(&anomaly_cfg(true), "/", two).unwrap();
        assert_eq!(out.score, 4);
        assert_eq!(out.action, WafAction::Allow);
        assert!(!out.enforced);
    }

    #[test]
    fn anomaly_disabled_is_a_noop() {
        // Score is still computed (telemetry), but nothing escalates.
        let out = decide(&anomaly_cfg(false), "/", three_lows()).unwrap();
        assert_eq!(out.score, 6);
        assert_eq!(out.action, WafAction::Allow);
    }

    #[test]
    fn anomaly_never_downgrades() {
        let mut cfg = anomaly_cfg(true);
        cfg.anomaly.action = RiskAction::Challenge;
        // A High SQLi already blocks; a Challenge escalation must not lower it.
        let out = decide(&cfg, "/", vec![det(WafModule::Sqli, WafRisk::High)]).unwrap();
        assert_eq!(out.action, WafAction::Deny);
    }

    #[test]
    fn anomaly_respects_monitor_mode() {
        let cfg = WafSemanticConfig {
            mode: WafMode::Monitor,
            anomaly: AnomalyConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let out = decide(&cfg, "/", three_lows()).unwrap();
        assert!(
            !out.enforced,
            "monitor mode must never enforce, even when scored"
        );
        assert_eq!(out.action, WafAction::Allow);
    }

    #[test]
    fn per_route_mode_override_wins_over_config() {
        // Global config is Block, but a per-route Monitor override → never enforced.
        let block_cfg = WafSemanticConfig::default();
        let out = super::decide(
            &block_cfg,
            WafMode::Monitor,
            "/",
            vec![det(WafModule::Sqli, WafRisk::High)],
        )
        .unwrap();
        assert_eq!(out.action, WafAction::Allow);
        assert!(!out.enforced);

        // Inverse: global Monitor, but a per-route Block override → enforced.
        let mon_cfg = WafSemanticConfig {
            mode: WafMode::Monitor,
            ..Default::default()
        };
        let out = super::decide(
            &mon_cfg,
            WafMode::Block,
            "/",
            vec![det(WafModule::Sqli, WafRisk::High)],
        )
        .unwrap();
        assert_eq!(out.action, WafAction::Deny);
        assert!(out.enforced);
    }

    #[test]
    fn standard_policy_maps_risk_to_action() {
        let cfg = WafSemanticConfig::default();
        let high = decide(&cfg, "/", vec![det(WafModule::Sqli, WafRisk::High)]).unwrap();
        assert_eq!(high.action, WafAction::Deny);
        assert!(high.enforced);

        let med = decide(&cfg, "/", vec![det(WafModule::Sqli, WafRisk::Medium)]).unwrap();
        assert_eq!(med.action, WafAction::Challenge);

        let low = decide(&cfg, "/", vec![det(WafModule::Sqli, WafRisk::Low)]).unwrap();
        assert_eq!(low.action, WafAction::Allow);
        assert!(!low.enforced);
    }

    #[test]
    fn monitor_mode_never_enforces() {
        let cfg = WafSemanticConfig {
            mode: WafMode::Monitor,
            ..Default::default()
        };
        let out = decide(&cfg, "/", vec![det(WafModule::Sqli, WafRisk::High)]).unwrap();
        assert_eq!(out.action, WafAction::Allow);
        assert!(!out.enforced);
    }

    #[test]
    fn exception_suppresses() {
        let mut cfg = WafSemanticConfig::default();
        cfg.exceptions.push(WafException {
            id: "x1".into(),
            enabled: true,
            module: Some(WafModule::Sqli),
            path_prefix: "/api/".into(),
            param: Some("q".into()),
            location: None,
            note: String::new(),
        });
        assert!(decide(
            &cfg,
            "/api/search",
            vec![det(WafModule::Sqli, WafRisk::High)]
        )
        .is_none());
        // Different path → not suppressed.
        assert!(decide(&cfg, "/other", vec![det(WafModule::Sqli, WafRisk::High)]).is_some());
    }

    #[test]
    fn all_wildcard_exception_suppresses_everything() {
        // An exception with no scope set matches every detection on every path —
        // it disables the whole engine. This is the hazard `waf.exception.create`
        // rejects; the test documents why that server-side guard exists.
        let mut cfg = WafSemanticConfig::default();
        cfg.exceptions.push(WafException {
            id: "x".into(),
            enabled: true,
            module: None,
            path_prefix: String::new(),
            param: None,
            location: None,
            note: String::new(),
        });
        for m in [WafModule::Sqli, WafModule::Xss, WafModule::Cmdi] {
            assert!(
                decide(&cfg, "/anything", vec![det(m, WafRisk::High)]).is_none(),
                "all-wildcard exception should suppress {m:?}"
            );
        }
    }

    #[test]
    fn most_severe_wins() {
        let cfg = WafSemanticConfig::default();
        let out = decide(
            &cfg,
            "/",
            vec![
                det(WafModule::Xss, WafRisk::Low),
                det(WafModule::Sqli, WafRisk::High),
            ],
        )
        .unwrap();
        assert_eq!(out.action, WafAction::Deny);
        assert_eq!(out.detection.module, WafModule::Sqli);
    }
}
