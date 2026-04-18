//! Rolling-window aggregator for `DecisionEvent`s.
//!
//! Events come in hot (thousands per second per node on a misbehaving
//! agent); we bucket them by `(namespace, pod_uid, policy, kind,
//! detail_bucket)` and emit one `AgentViolation` CR per bucket per
//! flush. One minute buckets mean Kubernetes sees at most a few
//! dozen CRs per misbehaving pod per hour, not one per blocked
//! connect().
//!
//! This module is pure. `Aggregator::ingest` buffers in memory;
//! `Aggregator::flush` returns the batched `AgentViolationSpec`s
//! plus names for the `kubectl apply` caller to use. Writing them
//! to the apiserver is the aggregator loop's job.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::crds::AgentViolationSpec;
use crate::events::{truncate_for_bucket, DecisionEvent};

/// How long a bucket key is allowed to grow (chars of `detail`).
/// Beyond this we collapse — otherwise a pod connecting to N
/// distinct URLs produces N unbounded CRs.
pub const DEFAULT_DETAIL_CAP: usize = 128;

/// One bucket's state. Reset to empty on every flush.
#[derive(Debug, Clone)]
struct BucketState {
    sample_event: DecisionEvent,
    count: u32,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

/// In-memory bucketer. Thread-unsafe by design — put it behind a
/// Mutex in the caller; the flush loop takes the lock for the
/// drain, ingestion for the push.
#[derive(Debug, Default)]
pub struct Aggregator {
    buckets: BTreeMap<String, BucketState>,
    detail_cap: usize,
}

/// What `flush` returns. `name` is the suggested CR name (derived
/// from the bucket key so retries are idempotent); `spec` populates
/// `AgentViolation.spec` directly. Caller sets the namespace from
/// `spec.pod_namespace` equivalent (we keep it on the event).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushedViolation {
    pub name: String,
    pub namespace: String,
    pub spec: AgentViolationSpec,
}

impl Aggregator {
    pub fn new() -> Self {
        Self::with_detail_cap(DEFAULT_DETAIL_CAP)
    }

    pub fn with_detail_cap(detail_cap: usize) -> Self {
        Self {
            buckets: BTreeMap::new(),
            detail_cap,
        }
    }

    /// Number of active buckets; a cheap gauge for `/metrics` export.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Add an event. Events with the same bucket key merge: `count`
    /// grows, `last_seen` advances, `first_seen` stays pinned to the
    /// window's first occurrence.
    pub fn ingest(&mut self, event: DecisionEvent) {
        let key = event.bucket_key(self.detail_cap);
        match self.buckets.get_mut(&key) {
            Some(b) => {
                b.count = b.count.saturating_add(1);
                if event.timestamp > b.last_seen {
                    b.last_seen = event.timestamp;
                }
                if event.timestamp < b.first_seen {
                    b.first_seen = event.timestamp;
                }
            }
            None => {
                self.buckets.insert(
                    key,
                    BucketState {
                        first_seen: event.timestamp,
                        last_seen: event.timestamp,
                        count: 1,
                        sample_event: event,
                    },
                );
            }
        }
    }

    /// Drain every bucket into an AgentViolationSpec. Clears state —
    /// the next window starts empty.
    ///
    /// CR names are `{kind-lowercased}-{hash(bucket_key)[..16]}`;
    /// stable across windows for the same tuple so SSA patches
    /// converge. Truncated detail (`…`) is represented in the key
    /// hash but not in the final CR's detail field — we store the
    /// sample event's verbatim detail, which is at least as
    /// informative.
    pub fn flush(&mut self) -> Vec<FlushedViolation> {
        let taken = std::mem::take(&mut self.buckets);
        let mut out = Vec::with_capacity(taken.len());
        for (key, bucket) in taken {
            let e = &bucket.sample_event;
            let name = format!("{}-{}", kind_slug(&e.kind), short_hash(&key));
            out.push(FlushedViolation {
                name,
                namespace: e.namespace.clone(),
                spec: AgentViolationSpec {
                    pod_name: e.pod_name.clone(),
                    pod_uid: e.pod_uid.clone(),
                    policy_name: if e.policy_name.is_empty() {
                        "<unknown>".into()
                    } else {
                        e.policy_name.clone()
                    },
                    kind: e.kind,
                    detail: truncate_for_bucket(&e.detail, 512),
                    count: bucket.count,
                    first_seen: bucket.first_seen.to_rfc3339(),
                    last_seen: bucket.last_seen.to_rfc3339(),
                },
            });
        }
        out
    }
}

fn kind_slug(k: &crate::crds::ViolationKind) -> &'static str {
    match k {
        crate::crds::ViolationKind::EgressBlocked => "egress",
        crate::crds::ViolationKind::FileBlocked => "file",
        crate::crds::ViolationKind::ExecBlocked => "exec",
        crate::crds::ViolationKind::MutationBlocked => "mutation",
    }
}

/// 16-hex prefix of a SHA-256 over the bucket key. Stable across
/// windows so flush-emit-apply converges when the same tuple fires
/// in back-to-back windows.
fn short_hash(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(key.as_bytes());
    hex::encode(&d[..8]) // first 8 bytes = 16 hex chars
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::ViolationKind;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().to_utc()
    }

    fn ev(detail: &str, t: &str) -> DecisionEvent {
        DecisionEvent {
            namespace: "prod".into(),
            pod_name: "agent".into(),
            pod_uid: "uid-1".into(),
            policy_name: "p".into(),
            kind: ViolationKind::EgressBlocked,
            detail: detail.into(),
            timestamp: at(t),
        }
    }

    #[test]
    fn identical_events_collapse_into_one_bucket() {
        let mut a = Aggregator::new();
        for _ in 0..5 {
            a.ingest(ev("1.2.3.4:443", "2026-04-18T10:00:00Z"));
        }
        assert_eq!(a.len(), 1);
        let flushed = a.flush();
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].spec.count, 5);
        assert!(a.is_empty(), "flush resets state");
    }

    #[test]
    fn different_details_split_buckets() {
        let mut a = Aggregator::new();
        a.ingest(ev("1.2.3.4:443", "2026-04-18T10:00:00Z"));
        a.ingest(ev("1.2.3.4:80", "2026-04-18T10:00:01Z"));
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn first_and_last_seen_track_earliest_and_latest() {
        let mut a = Aggregator::new();
        a.ingest(ev("1.2.3.4:443", "2026-04-18T10:00:05Z"));
        a.ingest(ev("1.2.3.4:443", "2026-04-18T10:00:01Z"));
        a.ingest(ev("1.2.3.4:443", "2026-04-18T10:00:10Z"));
        let f = a.flush();
        assert_eq!(f[0].spec.first_seen, "2026-04-18T10:00:01+00:00");
        assert_eq!(f[0].spec.last_seen, "2026-04-18T10:00:10+00:00");
    }

    #[test]
    fn names_are_deterministic_across_windows() {
        // Same tuple → same CR name → SSA patches converge instead
        // of creating new objects per window.
        let mut a = Aggregator::new();
        a.ingest(ev("1.2.3.4:443", "2026-04-18T10:00:00Z"));
        let name_a = a.flush()[0].name.clone();

        let mut b = Aggregator::new();
        b.ingest(ev("1.2.3.4:443", "2026-04-18T11:00:00Z"));
        let name_b = b.flush()[0].name.clone();
        assert_eq!(name_a, name_b);
    }

    #[test]
    fn name_starts_with_kind_slug() {
        let mut a = Aggregator::new();
        a.ingest(ev("1.2.3.4:443", "2026-04-18T10:00:00Z"));
        assert!(a.flush()[0].name.starts_with("egress-"));
    }

    #[test]
    fn different_pods_do_not_merge() {
        let mut a = Aggregator::new();
        let mut e1 = ev("1.2.3.4:443", "2026-04-18T10:00:00Z");
        let mut e2 = ev("1.2.3.4:443", "2026-04-18T10:00:00Z");
        e1.pod_uid = "uid-A".into();
        e2.pod_uid = "uid-B".into();
        a.ingest(e1);
        a.ingest(e2);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn empty_policy_name_still_flushes_with_unknown_label() {
        let mut a = Aggregator::new();
        let mut e = ev("1.2.3.4:443", "2026-04-18T10:00:00Z");
        e.policy_name = String::new();
        a.ingest(e);
        let f = a.flush();
        assert_eq!(f[0].spec.policy_name, "<unknown>");
    }

    #[test]
    fn detail_cap_collapses_high_cardinality_into_one_bucket() {
        let mut a = Aggregator::with_detail_cap(4);
        for i in 0..10 {
            a.ingest(ev(&format!("prefix-{}", i), "2026-04-18T10:00:00Z"));
        }
        // All collapse because the first 3 chars "pre" match;
        // detail_cap=4 leaves room for "pre…".
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn count_saturates_rather_than_overflowing() {
        // Runaway pod theoretically hits u32::MAX events in a
        // window. We saturate so the flushed CR still serializes.
        let mut a = Aggregator::new();
        a.ingest(ev("x", "2026-04-18T10:00:00Z"));
        // Poke internals via public API: 4 billion ingests is not
        // feasible in a test, so directly force the state.
        let key = ev("x", "2026-04-18T10:00:00Z").bucket_key(DEFAULT_DETAIL_CAP);
        a.buckets.get_mut(&key).unwrap().count = u32::MAX - 1;
        a.ingest(ev("x", "2026-04-18T10:00:00Z"));
        a.ingest(ev("x", "2026-04-18T10:00:00Z")); // would overflow
        assert_eq!(a.buckets.get(&key).unwrap().count, u32::MAX);
    }
}
