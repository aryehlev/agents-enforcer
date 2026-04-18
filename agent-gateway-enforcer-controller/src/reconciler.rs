//! Pure reconciliation logic: `AgentPolicy` + matching pods →
//! distributor calls + status to patch back onto the CR.
//!
//! The kube-rs `Controller` wiring in [`crate::run`] pulls the
//! ingredients together (fetches the CR, its matching pods, the
//! referenced catalogs) and then calls [`reconcile_policy`]. Keeping
//! the decision logic here — no API calls, no async kube clients —
//! means every branch is covered by table-style tests instead of
//! needing a live cluster.
//!
//! The reconciler's contract:
//! 1. The caller tells us which pods currently match and which were
//!    attached on the previous pass. Membership computation stays in
//!    the caller because it involves the pod informer cache; the
//!    reconciler just diffs the two sets.
//! 2. We compile the bundle, stage it with the distributor, attach
//!    every currently-matching pod, then detach every pod that
//!    matched last time but doesn't now.
//! 3. Attach-before-detach is intentional: if a pod moved between two
//!    policies, the new policy programs its cgroup before the old one
//!    clears it, so there's no observable unenforced window.

use std::collections::{BTreeMap, HashSet};

use agent_gateway_enforcer_core::backend::{PodIdentity, PolicyHash};

use crate::compiler::{compile_inactive, compile_policy, CompileError};
use crate::crds::{AgentPolicySpec, GatewayCatalogSpec};
use crate::distributor::BundleDistributor;
use crate::metrics::{record_reconcile, time_phase};
use crate::schedule::{is_active, next_transition};

/// Everything [`reconcile_policy`] needs to make a decision without
/// touching the Kubernetes API. The caller owns each reference — the
/// reconciler only reads.
#[derive(Debug)]
pub struct ReconcileRequest<'a> {
    /// The AgentPolicy being reconciled.
    pub policy: &'a AgentPolicySpec,
    /// Every GatewayCatalog visible to this policy, keyed by catalog
    /// name (kube metadata.name). Order doesn't matter; compilation
    /// is deterministic.
    pub catalogs: &'a BTreeMap<String, GatewayCatalogSpec>,
    /// Pods currently matching the policy's `podSelector`.
    pub matching_pods: &'a [PodIdentity],
    /// Pods the controller attached for this policy on the previous
    /// reconcile. Empty on the very first pass. The caller persists
    /// this across reconciles (kube's informer cache is a good home).
    pub previously_attached: &'a [PodIdentity],
}

/// What the reconciler wants written back to
/// `AgentPolicy.status`. Translating this into a patch and pushing it
/// to the apiserver is the Controller wrapper's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Hash of the bundle that ended up staged this pass.
    pub bundle_hash: PolicyHash,
    /// Pod count after applying the diff.
    pub enforced_pods: u32,
    /// Human-readable status message, shown in
    /// `kubectl describe agentpolicy` for easier triage. `None` means
    /// everything reconciled cleanly.
    pub message: Option<String>,
    /// When the scheduler wants the controller to re-check this
    /// policy. `None` means "no pending transition, use the
    /// default requeue interval". Populated only when
    /// `policy.spec.schedule` is set.
    pub requeue_after: Option<std::time::Duration>,
}

/// Errors that leave the CR in `Degraded`. Compile errors bubble up
/// unchanged — the caller turns them into a message on the status.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// Policy compilation failed. The CR spec itself is invalid
    /// (unknown gateway ref, unresolved host, …).
    #[error(transparent)]
    Compile(#[from] CompileError),
    /// A distributor RPC failed. `.0` preserves the underlying
    /// `anyhow::Error` so tests can assert on it.
    #[error("distributor failed: {0}")]
    Distribute(#[source] anyhow::Error),
}

/// Drive one reconcile pass.
///
/// See module docs for the ordering contract. Any distributor error
/// short-circuits — subsequent pods aren't attached — but whatever
/// succeeded before the failure stays applied. This matches kube
/// convention: the next reconcile pass will converge the residual.
pub async fn reconcile_policy(
    req: ReconcileRequest<'_>,
    distributor: &dyn BundleDistributor,
) -> Result<ReconcileOutcome, ReconcileError> {
    // Wrap the body so compile / distribute errors can be tagged in
    // the reconcile-total counter before bubbling up. The caller
    // (controller.rs) already patches status; the metric is the
    // machine-readable equivalent for dashboards.
    //
    // Schedule branch: when the policy has a schedule and the
    // current wall-clock is outside all active windows, swap the
    // compiled bundle for the "inactive" shape (typically no
    // gateways + inactive_action). The hash differs from the active
    // bundle so node-agents reprogram on transition.
    let now = chrono::Utc::now();
    let (bundle, requeue_after) = if let Some(schedule) = &req.policy.schedule {
        let after = next_transition(schedule, now);
        if is_active(schedule, now) {
            let _t = time_phase("compile").start_timer();
            let b = compile_policy(req.policy, req.catalogs).map_err(|e| {
                record_reconcile("compile_error");
                ReconcileError::from(e)
            })?;
            (b, after)
        } else {
            // Inactive path doesn't hit the compiler's fallible code
            // path; still record a compile phase-timer to keep the
            // histogram's {phase=compile} bucket comparable.
            let _t = time_phase("compile").start_timer();
            (compile_inactive(req.policy), after)
        }
    } else {
        let _t = time_phase("compile").start_timer();
        let b = match compile_policy(req.policy, req.catalogs) {
            Ok(b) => b,
            Err(e) => {
                record_reconcile("compile_error");
                return Err(e.into());
            }
        };
        (b, None)
    };
    let bundle_hash = bundle.hash.clone();

    {
        // Phase label matches the plan's {compile, push, attach}
        // bucket names. `start_timer()` returns a HistogramTimer
        // that observes its duration on drop.
        let _t = time_phase("push").start_timer();
        if let Err(e) = distributor.update_policy(&bundle).await {
            record_reconcile("distribute_error");
            return Err(ReconcileError::Distribute(e));
        }
    }

    // Diff current vs previous. Using UIDs means rename/move doesn't
    // trip us up — a pod UID survives everything except recreation.
    let currently: HashSet<&str> = req.matching_pods.iter().map(|p| p.uid.as_str()).collect();

    {
        let _t = time_phase("attach").start_timer();
        for pod in req.matching_pods {
            if let Err(e) = distributor.attach_pod(pod, &bundle_hash).await {
                record_reconcile("distribute_error");
                return Err(ReconcileError::Distribute(e));
            }
        }

        for pod in req.previously_attached {
            if !currently.contains(pod.uid.as_str()) {
                if let Err(e) = distributor.detach_pod(pod).await {
                    record_reconcile("distribute_error");
                    return Err(ReconcileError::Distribute(e));
                }
            }
        }
    }

    record_reconcile("ok");
    Ok(ReconcileOutcome {
        bundle_hash,
        enforced_pods: req.matching_pods.len() as u32,
        message: None,
        requeue_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{EgressAction, EgressPolicy, LabelSelector};
    use crate::distributor::testing::RecordingDistributor;

    fn empty_policy() -> AgentPolicySpec {
        AgentPolicySpec {
            pod_selector: LabelSelector::default(),
            egress: None,
            file_access: None,
            exec: None,
            block_mutations: false,
            schedule: None,
        }
    }

    fn pod(uid: &str) -> PodIdentity {
        PodIdentity {
            uid: uid.into(),
            namespace: "prod".into(),
            name: format!("pod-{}", uid),
            cgroup_path: format!("/fake/{}", uid),
            node_name: "node".into(),
        }
    }

    #[tokio::test]
    async fn first_reconcile_stages_bundle_and_attaches_every_matching_pod() {
        let dist = RecordingDistributor::default();
        let matching = vec![pod("a"), pod("b")];
        let outcome = reconcile_policy(
            ReconcileRequest {
                policy: &empty_policy(),
                catalogs: &BTreeMap::new(),
                matching_pods: &matching,
                previously_attached: &[],
            },
            &dist,
        )
        .await
        .unwrap();

        assert_eq!(outcome.enforced_pods, 2);
        assert!(outcome.message.is_none());

        let updates = dist.updates.lock().unwrap();
        assert_eq!(updates.len(), 1, "bundle staged exactly once");
        let attaches = dist.attaches.lock().unwrap();
        assert_eq!(attaches.len(), 2);
        assert!(dist.detaches.lock().unwrap().is_empty());
        // Every attach uses the bundle hash returned in the outcome.
        for (_, h) in attaches.iter() {
            assert_eq!(*h, outcome.bundle_hash);
        }
    }

    #[tokio::test]
    async fn detaches_pods_that_no_longer_match() {
        let dist = RecordingDistributor::default();
        // a and b matched last time; only b still matches now.
        let previous = vec![pod("a"), pod("b")];
        let current = vec![pod("b")];

        let outcome = reconcile_policy(
            ReconcileRequest {
                policy: &empty_policy(),
                catalogs: &BTreeMap::new(),
                matching_pods: &current,
                previously_attached: &previous,
            },
            &dist,
        )
        .await
        .unwrap();

        assert_eq!(outcome.enforced_pods, 1);
        let detaches = dist.detaches.lock().unwrap();
        assert_eq!(detaches.len(), 1);
        assert_eq!(detaches[0], "a");
        // b is still attached (reconciler re-attaches on every pass for
        // idempotency — the distributor dedupes).
        assert_eq!(dist.attaches.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn compile_error_does_not_touch_distributor() {
        let dist = RecordingDistributor::default();
        let mut policy = empty_policy();
        policy.egress = Some(EgressPolicy {
            default_action: EgressAction::Deny,
            gateway_refs: vec!["nope".into()],
            cidrs: vec![],
        });

        let err = reconcile_policy(
            ReconcileRequest {
                policy: &policy,
                catalogs: &BTreeMap::new(),
                matching_pods: &[pod("a")],
                previously_attached: &[],
            },
            &dist,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ReconcileError::Compile(CompileError::UnknownGateway(n)) if n == "nope"));
        // Nothing distributed — a broken policy must not partially
        // land anywhere.
        assert!(dist.updates.lock().unwrap().is_empty());
        assert!(dist.attaches.lock().unwrap().is_empty());
        assert!(dist.detaches.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rerun_is_idempotent_when_nothing_changed() {
        let dist = RecordingDistributor::default();
        let matching = vec![pod("a")];
        // First pass.
        reconcile_policy(
            ReconcileRequest {
                policy: &empty_policy(),
                catalogs: &BTreeMap::new(),
                matching_pods: &matching,
                previously_attached: &[],
            },
            &dist,
        )
        .await
        .unwrap();
        // Second pass with same inputs.
        reconcile_policy(
            ReconcileRequest {
                policy: &empty_policy(),
                catalogs: &BTreeMap::new(),
                matching_pods: &matching,
                previously_attached: &matching,
            },
            &dist,
        )
        .await
        .unwrap();

        // update_policy + attach fire each pass (distributor dedupes
        // by hash / uid). detach never fires because nothing moved.
        assert_eq!(dist.updates.lock().unwrap().len(), 2);
        assert_eq!(dist.attaches.lock().unwrap().len(), 2);
        assert!(dist.detaches.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pod_moving_between_policies_attaches_before_detaching() {
        // Regression guard for the "attach-before-detach" invariant
        // documented at the top of the module. If this ordering ever
        // flips, a pod moved between policies would see a brief
        // unenforced window.
        let dist = RecordingDistributor::default();
        reconcile_policy(
            ReconcileRequest {
                policy: &empty_policy(),
                catalogs: &BTreeMap::new(),
                matching_pods: &[pod("a")],
                previously_attached: &[pod("b")],
            },
            &dist,
        )
        .await
        .unwrap();

        // Order: update_policy, attach("a"), detach("b").
        let attaches_first = dist
            .attaches
            .lock()
            .unwrap()
            .first()
            .map(|(u, _)| u.clone());
        let detaches_any = dist.detaches.lock().unwrap().first().cloned();
        assert_eq!(attaches_first.as_deref(), Some("a"));
        assert_eq!(detaches_any.as_deref(), Some("b"));
    }
}
