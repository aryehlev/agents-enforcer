//! End-to-end smoke test wiring the controller-side reconciler all
//! the way into the Linux eBPF backend through `InMemoryDistributor`.
//!
//! The backend's per-pod API is a hard boundary for the reconciler
//! — if this test passes, a single-node deployment where the
//! controller and node agent share a process is already functional,
//! and swapping in a gRPC distributor is the only remaining step for
//! multi-node.

use std::collections::BTreeMap;
use std::sync::Arc;

use agent_gateway_enforcer_backend_ebpf_linux::EbpfLinuxBackend;
use agent_gateway_enforcer_controller::{
    compile_policy, reconcile_policy, AgentPolicySpec, InMemoryDistributor, LabelSelector,
    ReconcileRequest,
};
use agent_gateway_enforcer_core::backend::{EnforcementBackend, PodIdentity, UnifiedConfig};

fn pod_in(dir: &tempfile::TempDir, uid: &str) -> PodIdentity {
    // attach_pod will stat() cgroup_path; point it at a real dir so the
    // codepath succeeds without root or mounted cgroup v2 access.
    PodIdentity {
        uid: uid.into(),
        namespace: "prod".into(),
        name: format!("agent-{}", uid),
        cgroup_path: dir.path().to_string_lossy().into_owned(),
    }
}

#[tokio::test]
async fn reconcile_drives_backend_per_pod_api_end_to_end() {
    let mut backend = EbpfLinuxBackend::new();
    backend
        .initialize(&UnifiedConfig::default())
        .await
        .unwrap();
    let backend: Arc<dyn EnforcementBackend> = Arc::new(backend);
    let distributor = InMemoryDistributor::new(Arc::clone(&backend));

    let policy = AgentPolicySpec {
        pod_selector: LabelSelector::default(),
        egress: None,
        file_access: None,
        exec: None,
        block_mutations: false,
    };

    let dir_a = tempfile::TempDir::new().unwrap();
    let dir_b = tempfile::TempDir::new().unwrap();
    let pods = [pod_in(&dir_a, "a"), pod_in(&dir_b, "b")];

    let outcome = reconcile_policy(
        ReconcileRequest {
            policy: &policy,
            catalogs: &BTreeMap::new(),
            matching_pods: &pods,
            previously_attached: &[],
        },
        &distributor,
    )
    .await
    .unwrap();

    // The outcome's hash matches what the compiler would independently
    // produce — confirms end-to-end determinism.
    let expected = compile_policy(&policy, &BTreeMap::new()).unwrap().hash;
    assert_eq!(outcome.bundle_hash, expected);
    assert_eq!(outcome.enforced_pods, 2);

    // Detach one and confirm the second reconcile moves the backend
    // state without error.
    let outcome = reconcile_policy(
        ReconcileRequest {
            policy: &policy,
            catalogs: &BTreeMap::new(),
            matching_pods: &pods[..1],
            previously_attached: &pods,
        },
        &distributor,
    )
    .await
    .unwrap();
    assert_eq!(outcome.enforced_pods, 1);
}
