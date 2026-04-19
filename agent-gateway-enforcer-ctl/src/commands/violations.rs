//! `enforcerctl violations list`.
//!
//! `AgentViolation` CRs are created by the aggregator (Phase D.3,
//! not yet wired) — this command works against whatever the
//! aggregator has produced plus any manually-applied fixtures.

use agent_gateway_enforcer_controller::AgentViolation;
use anyhow::Context;
use chrono::Duration;
use kube::{Api, Client, ResourceExt};

use crate::format::{violations_table, ViolationRow};

pub async fn list(
    client: &Client,
    namespace: Option<&str>,
    since: Option<Duration>,
) -> anyhow::Result<String> {
    let items = fetch(client, namespace).await?;
    let cutoff = since.map(|d| chrono::Utc::now() - d);
    let rows: Vec<ViolationRow> = items
        .into_iter()
        .filter(|v| within(v, cutoff))
        .map(to_row)
        .collect();
    Ok(violations_table(&rows))
}

async fn fetch(
    client: &Client,
    namespace: Option<&str>,
) -> anyhow::Result<Vec<AgentViolation>> {
    let api: Api<AgentViolation> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api
        .list(&Default::default())
        .await
        .context("list AgentViolation")?;
    Ok(list.items)
}

fn within(v: &AgentViolation, cutoff: Option<chrono::DateTime<chrono::Utc>>) -> bool {
    let Some(cutoff) = cutoff else { return true };
    chrono::DateTime::parse_from_rfc3339(&v.spec.last_seen)
        .map(|t| t.to_utc() >= cutoff)
        .unwrap_or(true)
}

pub fn to_row(v: AgentViolation) -> ViolationRow {
    let namespace = v.namespace().unwrap_or_else(|| "<none>".into());
    let spec = v.spec;
    ViolationRow {
        namespace,
        pod: spec.pod_name,
        policy: spec.policy_name,
        // The enum serializes to CamelCase; stringify gives us
        // "EgressBlocked" etc. directly.
        kind: format!("{:?}", spec.kind),
        detail: spec.detail,
        count: spec.count,
        last_seen: spec.last_seen,
    }
}

/// Parse `--since` values: "1h", "30m", "7d". Returns `None` when
/// the flag wasn't supplied; `Err` on malformed input.
pub fn parse_since(s: &str) -> anyhow::Result<Duration> {
    // Intentionally narrow — cron-style expressions would need a
    // full crate and we don't need them.
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| anyhow::anyhow!("--since missing unit: {}", s))?,
    );
    let n: i64 = num.parse().with_context(|| format!("bad number in --since {}", s))?;
    Ok(match unit {
        "s" => Duration::seconds(n),
        "m" => Duration::minutes(n),
        "h" => Duration::hours(n),
        "d" => Duration::days(n),
        other => anyhow::bail!("unknown --since unit '{}' (want s/m/h/d)", other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_gateway_enforcer_controller::{AgentViolation, AgentViolationSpec, ViolationKind};
    use kube::api::ObjectMeta;

    fn viol(last_seen: &str) -> AgentViolation {
        AgentViolation {
            metadata: ObjectMeta {
                name: Some("v1".into()),
                namespace: Some("prod".into()),
                ..Default::default()
            },
            spec: AgentViolationSpec {
                pod_name: "agent-0".into(),
                pod_uid: "uid-1".into(),
                policy_name: "p".into(),
                kind: ViolationKind::EgressBlocked,
                detail: "1.2.3.4:443".into(),
                count: 3,
                first_seen: last_seen.into(),
                last_seen: last_seen.into(),
            },
        }
    }

    #[test]
    fn parse_since_accepts_common_units() {
        assert_eq!(parse_since("1h").unwrap(), Duration::hours(1));
        assert_eq!(parse_since("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_since("7d").unwrap(), Duration::days(7));
        assert_eq!(parse_since("45s").unwrap(), Duration::seconds(45));
    }

    #[test]
    fn parse_since_rejects_bad_input() {
        assert!(parse_since("hour").is_err());
        assert!(parse_since("5y").is_err());
        assert!(parse_since("1h30m").is_err()); // complex durations punt to follow-up
    }

    #[test]
    fn within_without_cutoff_keeps_everything() {
        assert!(within(&viol("2026-01-01T00:00:00Z"), None));
    }

    #[test]
    fn within_drops_old_items() {
        let cutoff = chrono::Utc::now();
        assert!(!within(&viol("1999-01-01T00:00:00Z"), Some(cutoff)));
    }

    #[test]
    fn within_keeps_items_with_unparseable_timestamps() {
        // Defensive: a CR we can't parse is still worth showing so
        // operators don't miss real events.
        assert!(within(&viol("not-a-timestamp"), Some(chrono::Utc::now())));
    }

    #[test]
    fn to_row_stringifies_violation_kind() {
        let row = to_row(viol("2026-01-01T00:00:00Z"));
        assert_eq!(row.kind, "EgressBlocked");
        assert_eq!(row.count, 3);
    }
}
