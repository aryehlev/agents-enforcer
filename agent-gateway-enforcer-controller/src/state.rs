//! Controller-side state that persists across reconciles.
//!
//! The pure [`crate::reconcile_policy`] function takes
//! `previously_attached` as an argument — it doesn't manage any state
//! itself on purpose. This module owns the small amount of state the
//! kube-rs `Controller` loop needs to thread between reconciles: for
//! each AgentPolicy (keyed by namespace + name), the set of pods that
//! were attached on the last successful pass.
//!
//! Keeping this in a separate module means the pure reconciler stays
//! pure and this store can be swapped for a persistent backing (e.g.
//! K8s ConfigMap, sled, …) if we want reconciler state to survive a
//! controller restart. v1alpha1 just uses an in-memory map because
//! the first reconcile after a restart re-derives the set from the
//! apiserver anyway.

use std::collections::HashMap;
use std::sync::RwLock;

use agent_gateway_enforcer_core::backend::PodIdentity;

/// Fully-qualified reference to an AgentPolicy across the cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyKey {
    /// Kubernetes namespace.
    pub namespace: String,
    /// Resource name.
    pub name: String,
}

impl PolicyKey {
    /// Construct a key from a pair of owned strings.
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }
}

/// Thread-safe store of pods attached per policy on the last reconcile.
/// All operations take &self so the store can sit inside an Arc shared
/// with the kube-rs Controller.
#[derive(Default, Debug)]
pub struct PolicyStateStore {
    inner: RwLock<HashMap<PolicyKey, Vec<PodIdentity>>>,
}

impl PolicyStateStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the last-known attached pods for a policy. Returns an
    /// empty Vec when the policy hasn't reconciled yet — the
    /// reconciler treats that identically to "no pods previously
    /// attached", which is the correct behavior.
    pub fn get(&self, key: &PolicyKey) -> Vec<PodIdentity> {
        self.inner
            .read()
            .expect("PolicyStateStore poisoned")
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    /// Replace the attached set for a policy after a successful
    /// reconcile. Failed reconciles must not call this — the point is
    /// that the next pass sees what *actually* landed on the last
    /// successful pass, so a mid-reconcile crash just re-applies.
    pub fn set(&self, key: PolicyKey, pods: Vec<PodIdentity>) {
        self.inner
            .write()
            .expect("PolicyStateStore poisoned")
            .insert(key, pods);
    }

    /// Drop all state for a policy that has been deleted from the
    /// cluster. Leaks memory across controller restarts are benign
    /// (the map is bounded by the CR count) but removing on delete
    /// keeps `kubectl delete` and `kubectl apply` cycles clean.
    pub fn remove(&self, key: &PolicyKey) -> Option<Vec<PodIdentity>> {
        self.inner
            .write()
            .expect("PolicyStateStore poisoned")
            .remove(key)
    }

    /// Current number of policies tracked. Mostly for metrics /
    /// debugging; no hot paths call this.
    pub fn len(&self) -> usize {
        self.inner.read().expect("PolicyStateStore poisoned").len()
    }

    /// Whether any policies are tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(uid: &str) -> PodIdentity {
        PodIdentity {
            uid: uid.into(),
            namespace: "ns".into(),
            name: format!("pod-{}", uid),
            cgroup_path: format!("/fake/{}", uid),
        }
    }

    #[test]
    fn get_on_unknown_key_returns_empty() {
        let store = PolicyStateStore::new();
        assert!(store.get(&PolicyKey::new("ns", "x")).is_empty());
    }

    #[test]
    fn set_then_get_round_trips() {
        let store = PolicyStateStore::new();
        let key = PolicyKey::new("prod", "agents");
        store.set(key.clone(), vec![pod("a"), pod("b")]);
        assert_eq!(store.get(&key).len(), 2);
    }

    #[test]
    fn set_replaces_rather_than_appends() {
        let store = PolicyStateStore::new();
        let key = PolicyKey::new("prod", "agents");
        store.set(key.clone(), vec![pod("a"), pod("b")]);
        store.set(key.clone(), vec![pod("c")]);
        let got = store.get(&key);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].uid, "c");
    }

    #[test]
    fn remove_takes_and_returns_stored_value() {
        let store = PolicyStateStore::new();
        let key = PolicyKey::new("prod", "agents");
        store.set(key.clone(), vec![pod("a")]);
        let taken = store.remove(&key).expect("value present");
        assert_eq!(taken.len(), 1);
        assert!(store.get(&key).is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn remove_unknown_key_is_none() {
        let store = PolicyStateStore::new();
        assert!(store.remove(&PolicyKey::new("ns", "x")).is_none());
    }

    #[test]
    fn policy_key_hash_distinguishes_namespace_and_name() {
        use std::collections::HashMap;
        let mut m = HashMap::new();
        m.insert(PolicyKey::new("a", "p"), 1);
        m.insert(PolicyKey::new("b", "p"), 2);
        m.insert(PolicyKey::new("a", "q"), 3);
        assert_eq!(m.len(), 3);
    }
}
