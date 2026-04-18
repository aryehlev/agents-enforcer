//! Mapping layer: CR -> View. Pure functions so every JSON field is
//! testable without a live cluster. The router only has to combine
//! a kube list with a prom lookup + call into here.

use std::collections::BTreeMap;

use agent_gateway_enforcer_controller::{
    AgentCapability, AgentPolicy, AgentViolation, EgressAction, Schedule, Weekday,
};
use kube::ResourceExt;

use crate::views::{CapabilityView, OverviewView, PolicyView, ViolationView};

pub fn policy_view(p: &AgentPolicy) -> PolicyView {
    let namespace = p.namespace().unwrap_or_else(|| "<none>".into());
    let name = p.name_any();
    let match_labels = p.spec.pod_selector.match_labels.clone();
    let (enforced, bundle_hash, message) = match &p.status {
        Some(s) => (
            s.enforced_pods,
            s.last_bundle_hash.clone(),
            s.message.clone(),
        ),
        None => (0, None, None),
    };
    let default_egress_action = p.spec.egress.as_ref().map(|e| egress_action_name(e.default_action));
    let schedule_summary = p
        .spec
        .schedule
        .as_ref()
        .map(describe_schedule)
        .unwrap_or_default();
    PolicyView {
        namespace,
        name,
        match_labels,
        enforced_pods: enforced,
        bundle_hash,
        message,
        default_egress_action,
        schedule_summary,
    }
}

pub fn capability_view(
    c: &AgentCapability,
    spend_by_agent: &BTreeMap<String, f64>,
    prom_available: bool,
) -> CapabilityView {
    let namespace = c.namespace().unwrap_or_else(|| "<none>".into());
    let name = c.name_any();
    let agent_id = format!("{}/{}", namespace, name);
    let spent_today_usd = if prom_available {
        Some(spend_by_agent.get(&agent_id).copied().unwrap_or(0.0))
    } else {
        None
    };
    CapabilityView {
        namespace,
        name,
        allowed_models: c.spec.allowed_models.clone(),
        allowed_tools: c.spec.allowed_tools.clone(),
        max_daily_spend_usd: c.spec.max_daily_spend_usd,
        spent_today_usd,
        max_output_tokens: c.spec.max_output_tokens,
    }
}

pub fn violation_view(v: &AgentViolation) -> ViolationView {
    let namespace = v.namespace().unwrap_or_else(|| "<none>".into());
    let spec = &v.spec;
    ViolationView {
        namespace,
        pod: spec.pod_name.clone(),
        policy: spec.policy_name.clone(),
        kind: format!("{:?}", spec.kind),
        detail: spec.detail.clone(),
        count: spec.count,
        first_seen: spec.first_seen.clone(),
        last_seen: spec.last_seen.clone(),
    }
}

/// Aggregate view: counts + total spend. Takes already-fetched data
/// so the router can be tested as a unit.
pub fn overview_view(
    policies: &[AgentPolicy],
    capabilities: &[AgentCapability],
    violations: &[AgentViolation],
    nodes_up: u64,
    spend_total_today: f64,
) -> OverviewView {
    let now = chrono::Utc::now();
    let one_hour_ago = now - chrono::Duration::hours(1);
    let recent = violations
        .iter()
        .filter(|v| {
            chrono::DateTime::parse_from_rfc3339(&v.spec.last_seen)
                .map(|t| t.to_utc() >= one_hour_ago)
                .unwrap_or(false)
        })
        .count() as u64;
    OverviewView {
        nodes_up,
        policy_count: policies.len() as u64,
        capability_count: capabilities.len() as u64,
        violation_count_last_hour: recent,
        total_spend_today_usd: spend_total_today,
    }
}

fn egress_action_name(a: EgressAction) -> String {
    match a {
        EgressAction::Deny => "Deny".into(),
        EgressAction::Audit => "Audit".into(),
        EgressAction::Allow => "Allow".into(),
    }
}

fn describe_schedule(s: &Schedule) -> String {
    if s.active_windows.is_empty() {
        return "schedule: no active windows (never active)".into();
    }
    // "Mon,Tue,Wed,Thu,Fri 09:00-18:00" shape — one line per window
    // joined with `; ` if multiple.
    s.active_windows
        .iter()
        .map(|w| {
            let days: Vec<&str> = w.days.iter().map(weekday_short).collect();
            format!("{} {}-{} UTC", days.join(","), w.start, w.end)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn weekday_short(d: &Weekday) -> &'static str {
    match d {
        Weekday::Mon => "Mon",
        Weekday::Tue => "Tue",
        Weekday::Wed => "Wed",
        Weekday::Thu => "Thu",
        Weekday::Fri => "Fri",
        Weekday::Sat => "Sat",
        Weekday::Sun => "Sun",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_gateway_enforcer_controller::{
        ActiveWindow, AgentCapabilitySpec, AgentPolicySpec, AgentPolicyStatus, AgentViolationSpec,
        EgressPolicy, LabelSelector, ViolationKind,
    };
    use kube::api::ObjectMeta;

    fn mk_policy(
        name: &str,
        ns: &str,
        labels: &[(&str, &str)],
        schedule: Option<Schedule>,
    ) -> AgentPolicy {
        let mut ml = BTreeMap::new();
        for (k, v) in labels {
            ml.insert((*k).into(), (*v).into());
        }
        AgentPolicy {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            spec: AgentPolicySpec {
                pod_selector: LabelSelector { match_labels: ml },
                egress: Some(EgressPolicy {
                    default_action: EgressAction::Deny,
                    gateway_refs: vec!["openai".into()],
                    cidrs: vec![],
                }),
                file_access: None,
                exec: None,
                block_mutations: false,
                schedule,
            },
            status: Some(AgentPolicyStatus {
                last_bundle_hash: Some("deadbeefdeadbeef".into()),
                enforced_pods: 4,
                message: None,
            }),
        }
    }

    #[test]
    fn policy_view_flattens_selector_and_status() {
        let p = mk_policy("agent", "prod", &[("app", "ai")], None);
        let v = policy_view(&p);
        assert_eq!(v.namespace, "prod");
        assert_eq!(v.enforced_pods, 4);
        assert_eq!(v.default_egress_action.as_deref(), Some("Deny"));
        assert!(v.schedule_summary.is_empty());
    }

    #[test]
    fn policy_view_describes_schedule_windows() {
        let s = Schedule {
            active_windows: vec![ActiveWindow {
                days: vec![Weekday::Mon, Weekday::Tue, Weekday::Fri],
                start: "09:00".into(),
                end: "18:00".into(),
            }],
            inactive_action: EgressAction::Allow,
        };
        let p = mk_policy("agent", "prod", &[], Some(s));
        let v = policy_view(&p);
        assert!(v.schedule_summary.contains("Mon,Tue,Fri"));
        assert!(v.schedule_summary.contains("09:00-18:00"));
    }

    #[test]
    fn capability_view_reads_prom_lookup() {
        let c = AgentCapability {
            metadata: ObjectMeta {
                name: Some("agent".into()),
                namespace: Some("prod".into()),
                ..Default::default()
            },
            spec: AgentCapabilitySpec {
                pod_selector: LabelSelector::default(),
                allowed_models: vec!["gpt-4o".into()],
                allowed_tools: vec![],
                max_daily_spend_usd: 10.0,
                max_output_tokens: None,
            },
            status: None,
        };
        let mut spend = BTreeMap::new();
        spend.insert("prod/agent".into(), 3.25);
        let v = capability_view(&c, &spend, true);
        assert_eq!(v.spent_today_usd, Some(3.25));
    }

    #[test]
    fn capability_view_absent_prom_is_none_not_zero() {
        let c = AgentCapability {
            metadata: ObjectMeta {
                name: Some("agent".into()),
                namespace: Some("prod".into()),
                ..Default::default()
            },
            spec: AgentCapabilitySpec {
                pod_selector: LabelSelector::default(),
                allowed_models: vec!["gpt-4o".into()],
                allowed_tools: vec![],
                max_daily_spend_usd: 10.0,
                max_output_tokens: None,
            },
            status: None,
        };
        let v = capability_view(&c, &BTreeMap::new(), false);
        // None, not Some(0.0) — distinguishes "Prom absent" from
        // "agent genuinely hasn't spent anything".
        assert_eq!(v.spent_today_usd, None);
    }

    #[test]
    fn overview_counts_only_recent_violations() {
        let recent = AgentViolation {
            metadata: ObjectMeta {
                name: Some("v1".into()),
                namespace: Some("prod".into()),
                ..Default::default()
            },
            spec: AgentViolationSpec {
                pod_name: "p".into(),
                pod_uid: "u".into(),
                policy_name: "x".into(),
                kind: ViolationKind::EgressBlocked,
                detail: "d".into(),
                count: 1,
                first_seen: chrono::Utc::now().to_rfc3339(),
                last_seen: chrono::Utc::now().to_rfc3339(),
            },
        };
        let old = AgentViolation {
            metadata: ObjectMeta {
                name: Some("v2".into()),
                namespace: Some("prod".into()),
                ..Default::default()
            },
            spec: AgentViolationSpec {
                pod_name: "p".into(),
                pod_uid: "u".into(),
                policy_name: "x".into(),
                kind: ViolationKind::EgressBlocked,
                detail: "d".into(),
                count: 1,
                first_seen: "2000-01-01T00:00:00Z".into(),
                last_seen: "2000-01-01T00:00:00Z".into(),
            },
        };
        let v = overview_view(&[], &[], &[recent, old], 3, 7.5);
        assert_eq!(v.violation_count_last_hour, 1);
        assert_eq!(v.nodes_up, 3);
        assert_eq!(v.total_spend_today_usd, 7.5);
    }
}
