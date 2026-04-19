//! Decision events emitted by the data plane and the wiring that
//! lets a consumer (the node-agent binary) subscribe to them.
//!
//! Two concerns live here on purpose:
//!
//! 1. A wire-level type ([`DecisionEventWire`]) that serializes into
//!    exactly the shape the controller's `/events/batch` HTTP endpoint
//!    accepts. Keeping the JSON contract in the library (not in the
//!    binary) lets unit tests pin it independent of the reporter.
//!
//! 2. A [`DecisionEventSource`] trait so the node-agent binary can
//!    subscribe to events without taking a concrete dependency on the
//!    eBPF backend. Tests use an in-memory fake that produces events
//!    on demand.
//!
//! Attribution — mapping a kernel `cgroup_id` back to an enforcing
//! pod — is the [`Attributor`] struct. It's a simple read-side hashmap
//! over the backend's pod registry; keeping it here (vs. inlining) means
//! a test can attribute events without standing up the whole backend.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Violation kinds as the controller's CRD accepts them. Kept a
/// stand-alone mirror of [`agent_gateway_enforcer_controller::crds::ViolationKind`]
/// so this crate doesn't depend on the controller crate (which would
/// pull in kube-rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationKind {
    /// `cgroup/connect4|6` denied a connection.
    EgressBlocked,
    /// `lsm/file_open` or `lsm/file_permission` denied a file op.
    FileBlocked,
    /// `lsm/bprm_check_security` denied an execve().
    ExecBlocked,
    /// `lsm/path_unlink|mkdir|rmdir` denied a mutation.
    MutationBlocked,
}

/// One decision event, attributed and ready to POST.
///
/// Matches the controller's HTTP `EventWire` shape bit-for-bit so we
/// can serialize with `serde_json::to_value` and ship to
/// `/events/batch` without a second transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionEventWire {
    /// Kubernetes namespace of the pod that triggered the decision.
    pub namespace: String,
    /// Pod name.
    pub pod_name: String,
    /// Pod UID.
    pub pod_uid: String,
    /// AgentPolicy name, empty when the node-agent wasn't told which
    /// policy produced the binding (see the `policy_name` field on
    /// `AttachPodRequest`).
    pub policy_name: String,
    /// Violation kind mirrored from the controller's CRD.
    pub kind: ViolationKind,
    /// Human-readable detail for this decision (`host:port`, path, …).
    pub detail: String,
    /// RFC3339 UTC. Always populated by the data-plane emitter so the
    /// controller doesn't race with the wall clock when batching.
    pub timestamp: String,
}

impl DecisionEventWire {
    /// Helper for constructing an event with a `chrono::Utc::now()`
    /// timestamp. Tests pass a fixed clock instead.
    pub fn now(
        namespace: impl Into<String>,
        pod_name: impl Into<String>,
        pod_uid: impl Into<String>,
        policy_name: impl Into<String>,
        kind: ViolationKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            pod_name: pod_name.into(),
            pod_uid: pod_uid.into(),
            policy_name: policy_name.into(),
            kind,
            detail: detail.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Subscription handle to the backend's decision event stream.
///
/// Implemented by [`crate::EbpfLinuxBackend`] and by test doubles.
/// Using `broadcast::Receiver` (rather than `mpsc`) on purpose: a
/// slow consumer must not block the emitter, and in practice the
/// reporter and tests are the only subscribers.
pub trait DecisionEventSource: Send + Sync {
    /// Subscribe to decisions. Late subscribers miss prior events,
    /// which is the right behavior for the reporter (we don't want to
    /// replay blocked connects from before the process was ready).
    fn subscribe(&self) -> broadcast::Receiver<DecisionEventWire>;
}

/// Pod attribution metadata per cgroup_id. The ebpf-linux backend
/// writes into this when [`super::EbpfLinuxBackend::attach_pod`] runs
/// and reads from it when it translates a ringbuf event into a
/// [`DecisionEventWire`].
#[derive(Debug, Clone)]
pub struct PodAttribution {
    /// Kubernetes namespace the pod lives in.
    pub namespace: String,
    /// Pod name (metadata.name).
    pub pod_name: String,
    /// Pod UID (metadata.uid) — the stable identifier the controller
    /// uses to key per-pod state.
    pub pod_uid: String,
    /// Controller-supplied policy label. Empty = `<unknown>` per the
    /// aggregator's contract.
    pub policy_name: String,
}

/// Pure, in-memory reverse lookup table from `cgroup_id` to pod
/// metadata. Kept small and lock-free (the caller wraps in a mutex)
/// so unit tests can exercise attribution without a tokio runtime.
#[derive(Default, Debug, Clone)]
pub struct Attributor {
    by_cgroup: HashMap<u64, PodAttribution>,
}

impl Attributor {
    /// Construct an empty attribution table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cgroup id → pod mapping. Overwrites any prior entry
    /// for the same id (kernel reuses inode numbers when cgroups are
    /// torn down and recreated).
    pub fn insert(&mut self, cgroup_id: u64, attr: PodAttribution) {
        self.by_cgroup.insert(cgroup_id, attr);
    }

    /// Remove the entry for `cgroup_id` on detach, returning it for
    /// logging.
    pub fn remove(&mut self, cgroup_id: u64) -> Option<PodAttribution> {
        self.by_cgroup.remove(&cgroup_id)
    }

    /// Look up a cgroup id. `None` means "unattributed", which is the
    /// right answer for host-networking and for decisions emitted
    /// before attach_pod ran.
    pub fn get(&self, cgroup_id: u64) -> Option<&PodAttribution> {
        self.by_cgroup.get(&cgroup_id)
    }

    /// Number of attributed cgroups.
    pub fn len(&self) -> usize {
        self.by_cgroup.len()
    }

    /// True when nothing is attributed.
    pub fn is_empty(&self) -> bool {
        self.by_cgroup.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_serializes_to_controller_shape() {
        let ev = DecisionEventWire {
            namespace: "prod".into(),
            pod_name: "agent-0".into(),
            pod_uid: "uid-A".into(),
            policy_name: "openai-only".into(),
            kind: ViolationKind::EgressBlocked,
            detail: "1.2.3.4:443".into(),
            timestamp: "2026-04-19T00:00:00Z".into(),
        };
        // Controller's EventWire uses camelCase field names and a
        // pascal-case enum tag. Pin both here so a rename on either
        // side trips the test rather than breaking the wire silently.
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["namespace"], "prod");
        assert_eq!(v["podName"], "agent-0");
        assert_eq!(v["podUid"], "uid-A");
        assert_eq!(v["policyName"], "openai-only");
        assert_eq!(v["kind"], "EgressBlocked");
        assert_eq!(v["detail"], "1.2.3.4:443");
        assert_eq!(v["timestamp"], "2026-04-19T00:00:00Z");
    }

    #[test]
    fn attributor_round_trips() {
        let mut a = Attributor::new();
        a.insert(
            42,
            PodAttribution {
                namespace: "ns".into(),
                pod_name: "p".into(),
                pod_uid: "u".into(),
                policy_name: "pol".into(),
            },
        );
        assert_eq!(a.get(42).unwrap().pod_uid, "u");
        assert!(a.get(43).is_none());
        a.remove(42);
        assert!(a.is_empty());
    }

    #[test]
    fn now_stamps_recent_timestamp() {
        let ev = DecisionEventWire::now(
            "ns",
            "p",
            "u",
            "pol",
            ViolationKind::EgressBlocked,
            "x",
        );
        // Round-trip the timestamp so we confirm it parses as RFC3339.
        let ts = chrono::DateTime::parse_from_rfc3339(&ev.timestamp)
            .expect("timestamp must be RFC3339");
        let drift = (chrono::Utc::now() - ts.to_utc()).num_seconds().abs();
        assert!(drift < 5, "drift {}s too large", drift);
    }
}
