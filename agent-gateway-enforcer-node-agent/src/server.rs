//! gRPC server implementation. Wraps an [`EnforcementBackend`] and
//! exposes the four `NodeAgent` RPCs to the controller.
//!
//! This module is compiled only with the `server` feature, so the
//! controller can depend on the crate for client-side types and
//! conversions without pulling in aya + libbpf.

use std::sync::Arc;

use agent_gateway_enforcer_core::backend::{EnforcementBackend, PolicyHash};
use tonic::{Request, Response, Status};

use crate::conversions::{bundle_from_proto, pod_from_proto};
use crate::proto::{
    node_agent_server::NodeAgent, AttachPodRequest, AttachPodResponse, DetachPodRequest,
    DetachPodResponse, HealthRequest, HealthResponse, UpdatePolicyRequest, UpdatePolicyResponse,
};

/// gRPC service wrapping an [`EnforcementBackend`].
///
/// Holds the backend behind an `Arc<dyn>` so the service can be cloned
/// freely and shared across tonic's internal task pool.
pub struct NodeAgentService {
    backend: Arc<dyn EnforcementBackend>,
}

impl NodeAgentService {
    /// Create a service from a pre-initialized backend. The backend
    /// must already be `start`'d — this constructor does no lifecycle
    /// work itself so the binary can share backend ownership with
    /// other subsystems (metrics exporter, health server).
    pub fn new(backend: Arc<dyn EnforcementBackend>) -> Self {
        Self { backend }
    }
}

#[tonic::async_trait]
impl NodeAgent for NodeAgentService {
    async fn update_policy(
        &self,
        req: Request<UpdatePolicyRequest>,
    ) -> Result<Response<UpdatePolicyResponse>, Status> {
        let bundle = req
            .into_inner()
            .bundle
            .ok_or_else(|| Status::invalid_argument("bundle is required"))?;
        let bundle = bundle_from_proto(bundle);
        tracing::debug!(
            hash = bundle.hash.as_str(),
            gateways = bundle.gateways.len(),
            "UpdatePolicy"
        );
        self.backend
            .update_policy(&bundle)
            .await
            .map_err(to_status)?;
        Ok(Response::new(UpdatePolicyResponse {}))
    }

    async fn attach_pod(
        &self,
        req: Request<AttachPodRequest>,
    ) -> Result<Response<AttachPodResponse>, Status> {
        let inner = req.into_inner();
        let pod = inner
            .pod
            .ok_or_else(|| Status::invalid_argument("pod is required"))?;
        if inner.bundle_hash.is_empty() {
            return Err(Status::invalid_argument("bundle_hash is required"));
        }
        let pod = pod_from_proto(pod);
        let hash = PolicyHash::new(inner.bundle_hash);
        tracing::debug!(uid = %pod.uid, hash = hash.as_str(), "AttachPod");
        self.backend
            .attach_pod(&pod, &hash)
            .await
            .map_err(to_status)?;
        Ok(Response::new(AttachPodResponse {}))
    }

    async fn detach_pod(
        &self,
        req: Request<DetachPodRequest>,
    ) -> Result<Response<DetachPodResponse>, Status> {
        let pod = req
            .into_inner()
            .pod
            .ok_or_else(|| Status::invalid_argument("pod is required"))?;
        let pod = pod_from_proto(pod);
        tracing::debug!(uid = %pod.uid, "DetachPod");
        self.backend.detach_pod(&pod).await.map_err(to_status)?;
        Ok(Response::new(DetachPodResponse {}))
    }

    async fn health(
        &self,
        _req: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        match self.backend.health_check().await {
            Ok(h) => Ok(Response::new(HealthResponse {
                ok: matches!(
                    h.status,
                    agent_gateway_enforcer_core::backend::HealthStatus::Healthy
                ),
                details: h.details,
            })),
            Err(e) => Ok(Response::new(HealthResponse {
                ok: false,
                details: e.to_string(),
            })),
        }
    }
}

/// Map anyhow errors to gRPC Status. Attach-bundle-not-staged comes
/// through as the distinctive "not staged" string from the backend —
/// surfacing NotFound gives the controller a clean retry signal.
fn to_status(err: anyhow::Error) -> Status {
    let s = err.to_string();
    if s.contains("not staged") {
        Status::failed_precondition(s)
    } else {
        Status::internal(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_gateway_enforcer_core::backend::{
        BackendCapabilities, BackendHealth, BackendType, EventHandler, HealthStatus,
        MetricsCollector, Platform, PodIdentity, PolicyBundle, Result, UnifiedConfig,
        FileAccessConfig, GatewayConfig,
    };
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Backend that records calls so RPC plumbing can be tested
    /// without a real kernel.
    #[derive(Default)]
    struct FakeBackend {
        pub updates: Mutex<Vec<PolicyHash>>,
        pub attaches: Mutex<Vec<(String, PolicyHash)>>,
        pub detaches: Mutex<Vec<String>>,
        pub fail_attach_with: Mutex<Option<String>>,
    }

    #[async_trait]
    impl EnforcementBackend for FakeBackend {
        fn backend_type(&self) -> BackendType {
            BackendType::EbpfLinux
        }
        fn platform(&self) -> Platform {
            Platform::Linux
        }
        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities::default()
        }
        async fn initialize(&mut self, _: &UnifiedConfig) -> Result<()> {
            Ok(())
        }
        async fn start(&mut self) -> Result<()> {
            Ok(())
        }
        async fn stop(&mut self) -> Result<()> {
            Ok(())
        }
        async fn configure_gateways(&self, _: &[GatewayConfig]) -> Result<()> {
            Ok(())
        }
        async fn configure_file_access(&self, _: &FileAccessConfig) -> Result<()> {
            Ok(())
        }
        fn metrics_collector(&self) -> Option<Arc<dyn MetricsCollector>> {
            None
        }
        fn event_handler(&self) -> Option<Arc<dyn EventHandler>> {
            None
        }
        async fn health_check(&self) -> Result<BackendHealth> {
            Ok(BackendHealth {
                status: HealthStatus::Healthy,
                last_check: std::time::SystemTime::now(),
                details: "ok".into(),
            })
        }
        async fn cleanup(&mut self) -> Result<()> {
            Ok(())
        }
        async fn update_policy(&self, b: &PolicyBundle) -> Result<()> {
            self.updates.lock().unwrap().push(b.hash.clone());
            Ok(())
        }
        async fn attach_pod(&self, p: &PodIdentity, h: &PolicyHash) -> Result<()> {
            if let Some(msg) = self.fail_attach_with.lock().unwrap().clone() {
                return Err(anyhow::anyhow!(msg));
            }
            self.attaches
                .lock()
                .unwrap()
                .push((p.uid.clone(), h.clone()));
            Ok(())
        }
        async fn detach_pod(&self, p: &PodIdentity) -> Result<()> {
            self.detaches.lock().unwrap().push(p.uid.clone());
            Ok(())
        }
    }

    fn sample_pod_proto() -> crate::proto::PodIdentity {
        crate::proto::PodIdentity {
            uid: "u1".into(),
            namespace: "ns".into(),
            name: "p".into(),
            cgroup_path: "/c".into(),
            node_name: "n".into(),
        }
    }

    fn sample_bundle_proto(hash: &str) -> crate::proto::PolicyBundle {
        crate::proto::PolicyBundle {
            hash: hash.into(),
            gateways: vec![],
            file_access: None,
            exec_allowlist: vec![],
            block_mutations: false,
        }
    }

    #[tokio::test]
    async fn update_policy_forwards_to_backend() {
        let backend: Arc<FakeBackend> = Arc::new(FakeBackend::default());
        let svc = NodeAgentService::new(backend.clone());
        svc.update_policy(Request::new(UpdatePolicyRequest {
            bundle: Some(sample_bundle_proto("h1")),
        }))
        .await
        .unwrap();
        assert_eq!(backend.updates.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn update_policy_rejects_missing_bundle() {
        let backend: Arc<FakeBackend> = Arc::new(FakeBackend::default());
        let svc = NodeAgentService::new(backend);
        let err = svc
            .update_policy(Request::new(UpdatePolicyRequest { bundle: None }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn attach_pod_rejects_missing_fields() {
        let backend: Arc<FakeBackend> = Arc::new(FakeBackend::default());
        let svc = NodeAgentService::new(backend);
        let err = svc
            .attach_pod(Request::new(AttachPodRequest {
                pod: None,
                bundle_hash: "h".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        let err = svc
            .attach_pod(Request::new(AttachPodRequest {
                pod: Some(sample_pod_proto()),
                bundle_hash: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn attach_pod_maps_not_staged_error_to_failed_precondition() {
        // "not staged" is the string the registry check emits when
        // update_policy hasn't run yet; see
        // EbpfLinuxBackend::attach_pod. The controller relies on this
        // code to back off and retry rather than treat it as a
        // permanent error.
        let backend = Arc::new(FakeBackend::default());
        *backend.fail_attach_with.lock().unwrap() =
            Some("bundle foo not staged".into());
        let svc = NodeAgentService::new(backend);
        let err = svc
            .attach_pod(Request::new(AttachPodRequest {
                pod: Some(sample_pod_proto()),
                bundle_hash: "foo".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn detach_pod_forwards_to_backend() {
        let backend: Arc<FakeBackend> = Arc::new(FakeBackend::default());
        let svc = NodeAgentService::new(backend.clone());
        svc.detach_pod(Request::new(DetachPodRequest {
            pod: Some(sample_pod_proto()),
        }))
        .await
        .unwrap();
        assert_eq!(backend.detaches.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn health_reports_backend_status() {
        let backend: Arc<FakeBackend> = Arc::new(FakeBackend::default());
        let svc = NodeAgentService::new(backend);
        let resp = svc
            .health(Request::new(HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.ok);
    }
}
