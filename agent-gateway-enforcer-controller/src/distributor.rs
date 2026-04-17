//! Transport abstraction for pushing compiled [`PolicyBundle`]s to node
//! agents.
//!
//! The controller runs on the control plane and emits bundles; node
//! agents apply them to their local eBPF maps. Between the two sits a
//! distributor — gRPC streaming in production, but the interface lets
//! tests wire the reconciler directly into an in-process
//! [`EnforcementBackend`] without any networking, and gives us a seam
//! for a future CSI-style socket or HTTP long-poll variant without
//! touching the reconciler.
//!
//! A distributor is responsible for three things:
//! 1. **Staging bundles** (`update_policy`) so node agents have them
//!    ready when an `attach_pod` arrives for a referenced hash.
//! 2. **Per-pod enforcement** (`attach_pod` / `detach_pod`) that
//!    instructs the node hosting a pod to program its local eBPF maps.
//! 3. **Idempotency.** The reconciler may call these methods many
//!    times with identical inputs; implementations must treat repeats
//!    as no-ops, not errors.

use std::sync::Arc;

use agent_gateway_enforcer_core::backend::{
    EnforcementBackend, PodIdentity, PolicyBundle, PolicyHash, Result,
};
use async_trait::async_trait;

/// The minimal interface a reconciler needs to push state toward node
/// agents. Mirrors the per-pod slice of [`EnforcementBackend`] on
/// purpose — an implementation that fans out to N nodes can forward
/// each call verbatim, while a unit-test implementation can point at a
/// single in-process backend.
#[async_trait]
pub trait BundleDistributor: Send + Sync {
    /// Stage a compiled bundle. Distributors must deduplicate by
    /// `bundle.hash` and deliver at-least-once across node restarts.
    async fn update_policy(&self, bundle: &PolicyBundle) -> Result<()>;

    /// Ask the node agent hosting this pod to enforce `bundle_hash`.
    async fn attach_pod(&self, pod: &PodIdentity, bundle_hash: &PolicyHash) -> Result<()>;

    /// Ask the node agent to stop enforcing on this pod. Must tolerate
    /// being called for a pod that never attached.
    async fn detach_pod(&self, pod: &PodIdentity) -> Result<()>;
}

/// In-process distributor backed by a single [`EnforcementBackend`].
///
/// This is what tests and single-node deployments use: the reconciler
/// calls into the distributor, the distributor calls straight into the
/// backend's per-pod trait methods. No network, no serialization.
pub struct InMemoryDistributor {
    backend: Arc<dyn EnforcementBackend>,
}

impl InMemoryDistributor {
    /// Wrap a backend. The backend's lifetime is tied to the
    /// distributor via `Arc`; cloning the distributor is cheap.
    pub fn new(backend: Arc<dyn EnforcementBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl BundleDistributor for InMemoryDistributor {
    async fn update_policy(&self, bundle: &PolicyBundle) -> Result<()> {
        self.backend.update_policy(bundle).await
    }

    async fn attach_pod(&self, pod: &PodIdentity, bundle_hash: &PolicyHash) -> Result<()> {
        self.backend.attach_pod(pod, bundle_hash).await
    }

    async fn detach_pod(&self, pod: &PodIdentity) -> Result<()> {
        self.backend.detach_pod(pod).await
    }
}

/// Test-only helpers. Lives under `pub(crate)` so the reconciler
/// tests can pull the `RecordingDistributor` in without re-deriving
/// the trait plumbing.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Mutex;

    /// Recording distributor used by reconciler tests. Captures every
    /// call so assertions can check ordering and idempotency without
    /// plumbing a real backend.
    #[derive(Default)]
    pub struct RecordingDistributor {
        pub updates: Mutex<Vec<PolicyHash>>,
        pub attaches: Mutex<Vec<(String, PolicyHash)>>, // (pod uid, hash)
        pub detaches: Mutex<Vec<String>>,               // pod uid
    }

    #[async_trait]
    impl BundleDistributor for RecordingDistributor {
        async fn update_policy(&self, bundle: &PolicyBundle) -> Result<()> {
            self.updates.lock().unwrap().push(bundle.hash.clone());
            Ok(())
        }
        async fn attach_pod(&self, pod: &PodIdentity, hash: &PolicyHash) -> Result<()> {
            self.attaches
                .lock()
                .unwrap()
                .push((pod.uid.clone(), hash.clone()));
            Ok(())
        }
        async fn detach_pod(&self, pod: &PodIdentity) -> Result<()> {
            self.detaches.lock().unwrap().push(pod.uid.clone());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::testing::RecordingDistributor;

    fn sample_pod(uid: &str) -> PodIdentity {
        PodIdentity {
            uid: uid.into(),
            namespace: "ns".into(),
            name: format!("pod-{}", uid),
            cgroup_path: format!("/fake/{}", uid),
        }
    }

    #[tokio::test]
    async fn recording_distributor_captures_calls() {
        let d = RecordingDistributor::default();
        d.update_policy(&PolicyBundle {
            hash: PolicyHash::new("abc"),
            ..Default::default()
        })
        .await
        .unwrap();
        d.attach_pod(&sample_pod("p1"), &PolicyHash::new("abc"))
            .await
            .unwrap();
        d.detach_pod(&sample_pod("p1")).await.unwrap();

        assert_eq!(d.updates.lock().unwrap().len(), 1);
        assert_eq!(d.attaches.lock().unwrap().len(), 1);
        assert_eq!(d.detaches.lock().unwrap().len(), 1);
    }
}
