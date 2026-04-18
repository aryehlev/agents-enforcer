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

use std::collections::HashMap;
use std::sync::Arc;

use agent_gateway_enforcer_core::backend::{
    EnforcementBackend, PodIdentity, PolicyBundle, PolicyHash, Result,
};
use agent_gateway_enforcer_node_agent::NodeAgentClient;
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

/// Dry-run distributor that only logs its inputs. Useful for
/// bringing up the controller against a cluster you don't want to
/// enforce on yet — every reconcile is observable through
/// `kubectl describe agentpolicy` and the controller logs, but no
/// pods are actually programmed.
#[derive(Default)]
pub struct LoggingDistributor;

impl LoggingDistributor {
    /// Construct a logging distributor. It's stateless; use it by value.
    pub fn new() -> Self {
        Self
    }
}

/// gRPC-backed distributor: one `NodeAgentClient` per Kubernetes
/// node, resolved via a pluggable [`NodeEndpointResolver`].
///
/// Fan-out strategy:
/// - `update_policy` is broadcast to every node the distributor has
///   seen at least one pod on. Idempotent by design (node agents
///   dedupe by bundle hash), so double-stage on a racy new node is a
///   no-op.
/// - `attach_pod` / `detach_pod` are routed to `pod.node_name`. An
///   empty `node_name` surfaces as an error — the reconciler treats
///   it as "pod not yet bound" and retries on the next pass.
pub struct GrpcDistributor {
    resolver: Arc<dyn NodeEndpointResolver>,
    // Cached client per node. `tokio::sync::RwLock` so attach/detach
    // can run in parallel on hot nodes while a cold new-node insert
    // takes the write lock briefly.
    clients: tokio::sync::RwLock<HashMap<String, NodeClient>>,
}

/// Resolve a Kubernetes node name to the host:port the node-agent is
/// listening on. A production resolver queries the kube `Node` API
/// for `status.addresses` + a known port; tests and single-node
/// setups plug in a `StaticNodeEndpointResolver`.
#[async_trait]
pub trait NodeEndpointResolver: Send + Sync {
    /// Return `http://host:port` for `node_name`, or an error if the
    /// node isn't known.
    async fn endpoint_for(&self, node_name: &str) -> anyhow::Result<String>;
}

/// Hard-coded resolver used by tests and single-node clusters.
pub struct StaticNodeEndpointResolver {
    default_port: u16,
}

impl StaticNodeEndpointResolver {
    /// Every node maps to `http://{node_name}:{default_port}`. Works
    /// when the kube service name resolves via DNS to the per-node
    /// agent — i.e., a headless Service over the DaemonSet.
    pub fn new(default_port: u16) -> Self {
        Self { default_port }
    }
}

#[async_trait]
impl NodeEndpointResolver for StaticNodeEndpointResolver {
    async fn endpoint_for(&self, node_name: &str) -> anyhow::Result<String> {
        if node_name.is_empty() {
            anyhow::bail!("empty node_name; pod not yet bound");
        }
        Ok(format!("http://{}:{}", node_name, self.default_port))
    }
}

type NodeClient = NodeAgentClient<tonic::transport::Channel>;

impl GrpcDistributor {
    /// Construct a distributor. No dials happen here — clients are
    /// lazily created on first use and cached.
    pub fn new(resolver: Arc<dyn NodeEndpointResolver>) -> Self {
        Self {
            resolver,
            clients: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    async fn client_for(&self, node_name: &str) -> Result<NodeClient> {
        {
            let guard = self.clients.read().await;
            if let Some(c) = guard.get(node_name) {
                return Ok(c.clone());
            }
        }
        let endpoint = self.resolver.endpoint_for(node_name).await?;
        let client = NodeAgentClient::connect(endpoint.clone())
            .await
            .map_err(|e| anyhow::anyhow!("dial {}: {}", endpoint, e))?;
        let mut guard = self.clients.write().await;
        // Double-check in case a concurrent caller beat us to the insert.
        let entry = guard.entry(node_name.to_string()).or_insert(client);
        Ok(entry.clone())
    }

    async fn broadcast<F, Fut>(&self, call: F) -> Result<()>
    where
        F: Fn(NodeClient) -> Fut + Send + Sync,
        // Note: explicit std::result::Result — our crate-level
        // `Result<T>` is a single-arg alias over anyhow::Error and
        // silently collides with the name here.
        Fut: std::future::Future<Output = std::result::Result<(), tonic::Status>> + Send,
    {
        // Snapshot the clients so we don't hold the lock across
        // the network calls. Copying Arc'd channels is cheap.
        let snapshot: Vec<(String, NodeClient)> = {
            let guard = self.clients.read().await;
            guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (node, client) in snapshot {
            if let Err(e) = call(client).await {
                // A single flaky node shouldn't block programming the
                // rest of the fleet; log + continue. The reconciler
                // retries on its own schedule.
                tracing::warn!(node = %node, err = %e, "broadcast call failed");
            }
        }
        Ok(())
    }
}

#[async_trait]
impl BundleDistributor for GrpcDistributor {
    async fn update_policy(&self, bundle: &PolicyBundle) -> Result<()> {
        let wire = agent_gateway_enforcer_node_agent::bundle_to_proto(bundle);
        self.broadcast(move |mut c| {
            let w = wire.clone();
            async move {
                c.update_policy(tonic::Request::new(
                    agent_gateway_enforcer_node_agent::UpdatePolicyRequest { bundle: Some(w) },
                ))
                .await
                .map(|_| ())
            }
        })
        .await
    }

    async fn attach_pod(&self, pod: &PodIdentity, bundle_hash: &PolicyHash) -> Result<()> {
        let client = self.client_for(&pod.node_name).await?;
        let req = agent_gateway_enforcer_node_agent::AttachPodRequest {
            pod: Some(agent_gateway_enforcer_node_agent::pod_to_proto(pod)),
            bundle_hash: bundle_hash.as_str().to_string(),
        };
        let mut c = client;
        // On first-attach for a node we also need to have seen
        // update_policy; callers always run reconcile_policy which
        // orders update_policy before attach_pod.
        c.attach_pod(tonic::Request::new(req))
            .await
            .map_err(|s| anyhow::anyhow!("attach_pod: {}", s))?;
        Ok(())
    }

    async fn detach_pod(&self, pod: &PodIdentity) -> Result<()> {
        // If we never had a client for this node, there's nothing to
        // detach — treat as a no-op rather than bubbling up an error.
        let client = match self.client_for(&pod.node_name).await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(node=%pod.node_name, err=%e, "detach_pod: no client, skipping");
                return Ok(());
            }
        };
        let mut c = client;
        c.detach_pod(tonic::Request::new(
            agent_gateway_enforcer_node_agent::DetachPodRequest {
                pod: Some(agent_gateway_enforcer_node_agent::pod_to_proto(pod)),
            },
        ))
        .await
        .map_err(|s| anyhow::anyhow!("detach_pod: {}", s))?;
        Ok(())
    }
}

#[async_trait]
impl BundleDistributor for LoggingDistributor {
    async fn update_policy(&self, bundle: &PolicyBundle) -> Result<()> {
        tracing::info!(
            hash = bundle.hash.as_str(),
            gateways = bundle.gateways.len(),
            exec_rules = bundle.exec_allowlist.len(),
            "dry-run: update_policy",
        );
        Ok(())
    }

    async fn attach_pod(&self, pod: &PodIdentity, bundle_hash: &PolicyHash) -> Result<()> {
        tracing::info!(
            pod = %format!("{}/{}", pod.namespace, pod.name),
            uid = %pod.uid,
            hash = bundle_hash.as_str(),
            "dry-run: attach_pod",
        );
        Ok(())
    }

    async fn detach_pod(&self, pod: &PodIdentity) -> Result<()> {
        tracing::info!(
            pod = %format!("{}/{}", pod.namespace, pod.name),
            uid = %pod.uid,
            "dry-run: detach_pod",
        );
        Ok(())
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
            node_name: "node".into(),
        }
    }

    #[tokio::test]
    async fn logging_distributor_always_succeeds() {
        let d = LoggingDistributor::new();
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
    }

    #[tokio::test]
    async fn static_resolver_formats_node_url() {
        let r = StaticNodeEndpointResolver::new(9091);
        assert_eq!(
            r.endpoint_for("node-1").await.unwrap(),
            "http://node-1:9091"
        );
    }

    #[tokio::test]
    async fn static_resolver_rejects_empty_node_name() {
        let r = StaticNodeEndpointResolver::new(9091);
        let err = r.endpoint_for("").await.unwrap_err();
        assert!(err.to_string().contains("not yet bound"));
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
