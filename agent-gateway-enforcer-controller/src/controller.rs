//! Kubernetes Controller loop for AgentPolicy.
//!
//! This module glues the pure reconciler to the apiserver. Most of
//! it is I/O — fetching related resources, patching status — so it
//! isn't unit-testable against a mock client; the logic that
//! warrants tests (the pure [`crate::reconciler::reconcile_policy`])
//! was already covered in `reconciler::tests` and in the e2e test
//! under `tests/reconciler_e2e.rs`.
//!
//! Scope for this pass:
//! - Watch `AgentPolicy` + `GatewayCatalog` + `Pod` (Pod watches so
//!   policies re-reconcile when matching pods appear / disappear).
//! - Per reconcile: collect the relevant catalogs, list matching
//!   pods, call [`crate::reconciler::reconcile_policy`], patch status.
//! - Deletion: if `.metadata.deletionTimestamp` is set, detach every
//!   pod we attached for this policy and drop the state entry. A
//!   proper finalizer (so we can clean up *after* K8s removes the
//!   object) is a follow-up; for v1alpha1 the window between delete
//!   and cache eviction is short enough that in-memory cleanup is
//!   sufficient.

use std::sync::Arc;
use std::time::Duration;

use agent_gateway_enforcer_core::backend::PodIdentity;
use futures::StreamExt;
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event, EventType, Recorder, Reporter};
use kube::runtime::finalizer::{finalizer, Event as FinalizerEvent};
use kube::runtime::watcher;
use kube::{Api, Client, Resource, ResourceExt};
use serde_json::json;
use thiserror::Error;

use crate::crds::{AgentPolicy, AgentPolicyStatus, EgressPolicy, GatewayCatalog, GatewayCatalogSpec};
use crate::distributor::BundleDistributor;
use crate::matching::{pod_identity_from, pod_matches_selector};
use crate::reconciler::{reconcile_policy, ReconcileError, ReconcileRequest};
use crate::state::{PolicyKey, PolicyStateStore};

/// Configuration the controller needs at startup.
#[derive(Clone, Debug)]
pub struct ControllerConfig {
    /// Template for a pod's cgroup v2 directory; `{uid}` is replaced
    /// with the pod UID. Default matches cgroupfs + systemd kubelets
    /// on most distros. Override via `--cgroup-template`.
    pub cgroup_template: String,
    /// How long to wait before re-reconciling an object when nothing
    /// else triggers it. Short-ish in v1alpha1 because we don't
    /// watch resolver TTLs yet.
    pub requeue_interval: Duration,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            cgroup_template: "/sys/fs/cgroup/kubepods.slice/kubepods-pod{uid}.slice".to_string(),
            requeue_interval: Duration::from_secs(30),
        }
    }
}

/// Per-reconcile context handed to every invocation by the kube-rs
/// `Controller`. Cloning is cheap — every field is `Arc` or behind
/// one.
pub struct Context {
    /// Live apiserver client, used for List and Patch calls.
    pub client: Client,
    /// Where staged bundles and per-pod enforcement get pushed.
    pub distributor: Arc<dyn BundleDistributor>,
    /// Per-policy attach history so the next reconcile knows what to
    /// detach when the selector's match set shrinks.
    pub state: Arc<PolicyStateStore>,
    /// Runtime config.
    pub config: ControllerConfig,
    /// Reporter identifying this controller instance in
    /// `kubectl get events`. Set once at startup.
    pub reporter: Reporter,
}

/// Event reason strings. Stable — operators filter on these. Keep
/// the set small; noisy controllers train people to ignore events.
pub mod event_reasons {
    /// Emitted when a reconcile successfully pushes a bundle and
    /// the attached pod count is non-zero.
    pub const PROGRAMMED: &str = "Programmed";
    /// Emitted when compilation or distribution failed. Paired with
    /// a message explaining why.
    pub const DEGRADED: &str = "Degraded";
}

/// Error taxonomy for the reconcile loop. kube-rs hands us whatever
/// this returns to [`error_policy`] to decide on backoff.
#[derive(Debug, Error)]
pub enum ReconcileLoopError {
    /// Policy compilation or distributor RPC failed. Carries the
    /// inner error unchanged so callers can inspect the cause.
    #[error(transparent)]
    Reconcile(#[from] ReconcileError),
    /// Anything the apiserver rejected.
    #[error("kube api error: {0}")]
    Kube(#[from] kube::Error),
}

/// Finalizer name written into `metadata.finalizers`. Scoped under
/// our API group so other controllers don't accidentally clash.
pub const FINALIZER: &str = "agents.enforcer.io/cleanup";

/// Reconcile a single `AgentPolicy`. Called by the kube-rs `Controller`.
///
/// This is just the finalizer adapter — the real work lives in
/// [`reconcile_apply`] (normal reconciles) and [`reconcile_cleanup`]
/// (detach everything and let the deletion complete). Using
/// `kube::runtime::finalizer` means Kubernetes holds the object until
/// we finish cleanup, closing the previous branch's "fast delete"
/// gap where detach calls could be lost.
pub async fn reconcile(
    policy: Arc<AgentPolicy>,
    ctx: Arc<Context>,
) -> Result<Action, ReconcileLoopError> {
    let namespace = policy.namespace().ok_or_else(|| {
        kube::Error::Api(kube::core::ErrorResponse {
            status: "Failure".into(),
            message: "AgentPolicy missing namespace".into(),
            reason: "BadRequest".into(),
            code: 400,
        })
    })?;
    let policies: Api<AgentPolicy> = Api::namespaced(ctx.client.clone(), &namespace);

    finalizer(&policies, FINALIZER, policy, |event| async {
        match event {
            FinalizerEvent::Apply(p) => reconcile_apply(p, ctx.clone()).await,
            FinalizerEvent::Cleanup(p) => reconcile_cleanup(p, ctx.clone()).await,
        }
    })
    .await
    .map_err(|e| match e {
        kube::runtime::finalizer::Error::ApplyFailed(inner)
        | kube::runtime::finalizer::Error::CleanupFailed(inner) => inner,
        other => ReconcileLoopError::Kube(kube::Error::Api(kube::core::ErrorResponse {
            status: "Failure".into(),
            message: format!("finalizer: {other}"),
            reason: "FinalizerError".into(),
            code: 500,
        })),
    })
}

/// Apply branch: policy is live; reconcile matches + status.
async fn reconcile_apply(
    policy: Arc<AgentPolicy>,
    ctx: Arc<Context>,
) -> Result<Action, ReconcileLoopError> {
    let namespace = policy.namespace().expect("checked in reconcile");
    let name = policy.name_any();
    let key = PolicyKey::new(namespace.clone(), name.clone());

    let policies: Api<AgentPolicy> = Api::namespaced(ctx.client.clone(), &namespace);
    let pods: Api<k8s_openapi::api::core::v1::Pod> =
        Api::namespaced(ctx.client.clone(), &namespace);
    let catalogs: Api<GatewayCatalog> = Api::all(ctx.client.clone());

    let catalog_names = referenced_catalog_names(&policy.spec.egress);
    let catalog_map = fetch_catalogs(&catalogs, &catalog_names).await?;

    let matching_pods =
        list_matching_pods(&pods, &policy, &ctx.config.cgroup_template).await?;
    let previously_attached = ctx.state.get(&key);

    let outcome = match reconcile_policy(
        ReconcileRequest {
            policy: &policy.spec,
            catalogs: &catalog_map,
            matching_pods: &matching_pods,
            previously_attached: &previously_attached,
        },
        ctx.distributor.as_ref(),
    )
    .await
    {
        Ok(o) => {
            ctx.state.set(key.clone(), matching_pods);
            o
        }
        Err(e) => {
            let message = e.to_string();
            let _ = patch_status(
                &policies,
                &name,
                &AgentPolicyStatus {
                    last_bundle_hash: None,
                    enforced_pods: 0,
                    message: Some(message.clone()),
                },
            )
            .await;
            emit_event(&ctx, &policy, EventType::Warning, event_reasons::DEGRADED, &message).await;
            return Err(e.into());
        }
    };

    patch_status(
        &policies,
        &name,
        &AgentPolicyStatus {
            last_bundle_hash: Some(outcome.bundle_hash.as_str().to_string()),
            enforced_pods: outcome.enforced_pods,
            message: outcome.message.clone(),
        },
    )
    .await?;

    emit_event(
        &ctx,
        &policy,
        EventType::Normal,
        event_reasons::PROGRAMMED,
        &format!(
            "Programmed bundle {} on {} pod(s)",
            &outcome.bundle_hash.as_str()[..outcome.bundle_hash.as_str().len().min(12)],
            outcome.enforced_pods
        ),
    )
    .await;

    Ok(Action::requeue(ctx.config.requeue_interval))
}

/// Cleanup branch: Kubernetes has set `deletionTimestamp` and is
/// waiting for our finalizer. Detach everything we had attached,
/// drop state, then return Ok — kube::runtime::finalizer removes the
/// finalizer from `metadata.finalizers` so the object can actually
/// disappear.
async fn reconcile_cleanup(
    policy: Arc<AgentPolicy>,
    ctx: Arc<Context>,
) -> Result<Action, ReconcileLoopError> {
    let namespace = policy.namespace().expect("checked in reconcile");
    let name = policy.name_any();
    let key = PolicyKey::new(namespace, name.clone());
    tracing::info!(policy = %format!("{}/{}", key.namespace, key.name), "finalizer cleanup");

    if let Some(attached) = ctx.state.remove(&key) {
        for pod in &attached {
            if let Err(e) = ctx.distributor.detach_pod(pod).await {
                // Retry — Kubernetes keeps the object pending on the
                // finalizer so no pods can sneak back in.
                tracing::warn!(err=%e, pod=%pod.uid, "detach during cleanup failed");
                return Err(ReconcileLoopError::Reconcile(ReconcileError::Distribute(e)));
            }
        }
    }
    Ok(Action::await_change())
}

/// Failure handler invoked by kube-rs when reconcile returns Err. We
/// log and request a short retry — no exponential backoff in
/// v1alpha1; kube-rs jitters internally.
pub fn error_policy(obj: Arc<AgentPolicy>, err: &ReconcileLoopError, _ctx: Arc<Context>) -> Action {
    tracing::warn!(
        policy = %format!("{}/{}", obj.namespace().unwrap_or_default(), obj.name_any()),
        err = %err,
        "reconcile error; backing off",
    );
    Action::requeue(Duration::from_secs(5))
}

/// Entry point: run the Controller until cancelled. Blocks forever
/// on the happy path.
pub async fn run(
    client: Client,
    distributor: Arc<dyn BundleDistributor>,
    config: ControllerConfig,
) -> anyhow::Result<()> {
    let context = Arc::new(Context {
        client: client.clone(),
        distributor,
        state: Arc::new(PolicyStateStore::new()),
        config,
        reporter: Reporter {
            controller: "agents.enforcer.io/controller".into(),
            instance: std::env::var("POD_NAME").ok(),
        },
    });

    let policies: Api<AgentPolicy> = Api::all(client.clone());
    let catalogs: Api<GatewayCatalog> = Api::all(client.clone());
    let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::all(client);

    // Watching Pods + GatewayCatalogs means any change to either
    // triggers the reconciler for policies that might be affected.
    // We don't narrow the pod watcher because label selectors across
    // policies don't share a single filter; kube-rs de-duplicates
    // the resulting reconcile calls.
    Controller::new(policies, watcher::Config::default())
        .owns(pods, watcher::Config::default())
        .owns(catalogs, watcher::Config::default())
        .run(reconcile, error_policy, context)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => tracing::debug!(
                    policy = %format!("{}/{}", obj.namespace.unwrap_or_default(), obj.name),
                    "reconciled",
                ),
                Err(e) => tracing::warn!(err = %e, "controller stream error"),
            }
        })
        .await;

    Ok(())
}

/// Emit a Kubernetes Event on behalf of an AgentPolicy. Failures to
/// write the event are logged but don't propagate: if the apiserver
/// can't accept events we have bigger problems than a missing line
/// in `kubectl get events`, and the reconcile result itself is
/// already durable via status.
async fn emit_event(
    ctx: &Context,
    policy: &AgentPolicy,
    event_type: EventType,
    reason: &str,
    note: &str,
) {
    let recorder = Recorder::new(
        ctx.client.clone(),
        ctx.reporter.clone(),
        policy.object_ref(&()),
    );
    if let Err(e) = recorder
        .publish(Event {
            type_: event_type,
            reason: reason.to_string(),
            note: Some(note.to_string()),
            action: reason.to_string(),
            secondary: None,
        })
        .await
    {
        tracing::debug!(err=%e, "failed to publish k8s event");
    }
}

fn referenced_catalog_names(egress: &Option<EgressPolicy>) -> Vec<String> {
    egress
        .as_ref()
        .map(|e| e.gateway_refs.clone())
        .unwrap_or_default()
}

async fn fetch_catalogs(
    api: &Api<GatewayCatalog>,
    _names: &[String],
) -> Result<std::collections::BTreeMap<String, GatewayCatalogSpec>, kube::Error> {
    // We don't currently filter by name — catalog count is small
    // (platform-curated) and listing all of them costs nothing extra
    // for the informer. If that ever changes, narrow this to
    // Api::get() per name with a NotFound-tolerant wrapper.
    let list = api.list(&ListParams::default()).await?;
    let mut out = std::collections::BTreeMap::new();
    for c in list.items {
        out.insert(c.name_any(), c.spec);
    }
    Ok(out)
}

async fn list_matching_pods(
    api: &Api<k8s_openapi::api::core::v1::Pod>,
    policy: &AgentPolicy,
    cgroup_template: &str,
) -> Result<Vec<PodIdentity>, kube::Error> {
    let list = api.list(&ListParams::default()).await?;
    let mut out = Vec::new();
    for pod in list.items {
        if !pod_matches_selector(&pod, &policy.spec.pod_selector) {
            continue;
        }
        if let Some(id) = pod_identity_from(&pod, cgroup_template) {
            out.push(id);
        }
    }
    Ok(out)
}

async fn patch_status(
    api: &Api<AgentPolicy>,
    name: &str,
    status: &AgentPolicyStatus,
) -> Result<(), kube::Error> {
    let patch = json!({
        "apiVersion": "agents.enforcer.io/v1alpha1",
        "kind": "AgentPolicy",
        "status": status,
    });
    api.patch_status(
        name,
        &PatchParams::apply("agents.enforcer.io").force(),
        &Patch::Apply(&patch),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{CidrRule, EgressAction, EgressPolicy};

    #[test]
    fn referenced_catalog_names_empty_when_no_egress() {
        assert!(referenced_catalog_names(&None).is_empty());
    }

    #[test]
    fn referenced_catalog_names_pulls_from_egress() {
        let egress = EgressPolicy {
            default_action: EgressAction::Deny,
            gateway_refs: vec!["openai".into(), "anthropic".into()],
            cidrs: vec![CidrRule {
                cidr: "10.0.0.1/32".into(),
                ports: vec![443],
            }],
        };
        let names = referenced_catalog_names(&Some(egress));
        assert_eq!(names, vec!["openai".to_string(), "anthropic".to_string()]);
    }

    #[test]
    fn default_controller_config_is_reasonable() {
        let cfg = ControllerConfig::default();
        assert!(cfg.cgroup_template.contains("{uid}"));
        assert!(cfg.requeue_interval >= Duration::from_secs(1));
    }

    #[test]
    fn event_reasons_are_stable_strings() {
        // Operators filter on these — if we rename them we need to
        // rev the crate minor version and document the break.
        assert_eq!(event_reasons::PROGRAMMED, "Programmed");
        assert_eq!(event_reasons::DEGRADED, "Degraded");
    }

    #[test]
    fn finalizer_name_is_api_group_scoped() {
        // Must be a valid finalizer (domain/name) and live in our
        // API group so other controllers never remove it by
        // accident. Any change here is a breaking change because
        // existing objects in the cluster will already carry this
        // finalizer under `metadata.finalizers`.
        assert!(FINALIZER.starts_with("agents.enforcer.io/"));
        assert!(FINALIZER.contains('/'));
    }
}
