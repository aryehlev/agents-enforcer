//! Raw per-decision events the aggregator consumes.
//!
//! One event ≈ one deny or audit decision from the data plane
//! (eBPF hooks, LLM proxy, …). The aggregator buckets events into
//! `AgentViolation` CRs so Kubernetes doesn't see millions of
//! objects per day on a busy policy.
//!
//! This type deliberately lives in the controller crate instead of
//! `core`: the node-agent emits structurally identical proto
//! messages, but the wire-adjacent bits (timestamps as strings,
//! optional provider fields) vary. Keeping one canonical in-memory
//! type here means the aggregator's contract is small and
//! table-testable.

use chrono::{DateTime, Utc};

use crate::crds::ViolationKind;

/// One deny / audit decision, ready for aggregation.
///
/// Field choices come from what `AgentViolation.spec` needs to
/// display: `detail` is free-form (a destination host, a file path,
/// an exec'd binary), so the aggregator truncates it for bucketing
/// to keep cardinality bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionEvent {
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    /// Name of the `AgentPolicy` that produced this decision. Empty
    /// string when the event comes from a source that doesn't know
    /// (e.g. a proxy reject that never made it past the `NoCapability`
    /// gate); the aggregator treats "" as the policy label
    /// `<unknown>`.
    pub policy_name: String,
    pub kind: ViolationKind,
    /// Human-readable, context-dependent: `1.2.3.4:443`, `/etc/shadow`,
    /// `/bin/sh`, …. Never interpret semantically — it's a label.
    pub detail: String,
    pub timestamp: DateTime<Utc>,
}

impl DecisionEvent {
    /// A stable bucket key for aggregation. Intentionally a `String`
    /// rather than a struct hash so operators can inspect the key
    /// in logs when debugging why two events didn't merge.
    pub fn bucket_key(&self, detail_cap: usize) -> String {
        let detail = truncate_for_bucket(&self.detail, detail_cap);
        let policy = if self.policy_name.is_empty() {
            "<unknown>"
        } else {
            &self.policy_name
        };
        format!(
            "{}|{}|{}|{:?}|{}",
            self.namespace, self.pod_uid, policy, self.kind, detail
        )
    }
}

/// Bound each detail string's contribution to the key so a noisy
/// label like a fully-qualified URL doesn't blow up cardinality.
/// 128 chars preserves enough to distinguish distinct destinations
/// while keeping key length bounded.
pub(crate) fn truncate_for_bucket(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    let mut out: String = s.chars().take(cap.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(detail: &str) -> DecisionEvent {
        DecisionEvent {
            namespace: "prod".into(),
            pod_name: "agent".into(),
            pod_uid: "uid-1".into(),
            policy_name: "p".into(),
            kind: ViolationKind::EgressBlocked,
            detail: detail.into(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn same_key_for_same_tuple() {
        let a = evt("1.2.3.4:443");
        let b = evt("1.2.3.4:443");
        assert_eq!(a.bucket_key(128), b.bucket_key(128));
    }

    #[test]
    fn different_detail_different_key() {
        assert_ne!(
            evt("1.2.3.4:443").bucket_key(128),
            evt("1.2.3.4:80").bucket_key(128)
        );
    }

    #[test]
    fn empty_policy_renders_as_unknown() {
        let mut e = evt("1.2.3.4:443");
        e.policy_name = String::new();
        assert!(e.bucket_key(128).contains("<unknown>"));
    }

    #[test]
    fn long_detail_is_truncated_into_key() {
        let long = "x".repeat(200);
        let k = evt(&long).bucket_key(32);
        // 32-char cap, not 200. Trailing ellipsis present.
        assert!(k.len() < 200);
        assert!(k.contains('…'));
    }

    #[test]
    fn cap_of_zero_does_not_panic() {
        // Guard-rail: cap=0 exercises `saturating_sub(1)`. Behavior
        // ("just an ellipsis" vs empty) is documentation-less; the
        // only real contract here is "doesn't panic".
        let _ = evt("anything").bucket_key(0);
    }
}
