//! Pure validation rules for `AgentPolicy`. The handler turns
//! [`ValidationError`] into a `v1.AdmissionResponse` allowed=false
//! with a useful message.
//!
//! Split out so every rule is unit-testable without an apiserver.

use std::collections::BTreeMap;

use agent_gateway_enforcer_controller::{
    compile_policy, AgentPolicySpec, CompileError, GatewayCatalogSpec,
};
use thiserror::Error;

/// Validation failures surfaced to the user. Every variant carries
/// enough detail to fix the CR without reading the controller log.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// Policy references a `GatewayCatalog` entry that doesn't exist.
    #[error("egress.gatewayRefs: unknown gateway '{0}'")]
    UnknownGatewayRef(String),
    /// A referenced gateway's `host` isn't a pre-resolved IPv4
    /// literal. The reconciler side has a resolver to turn hostnames
    /// into IPs; if the webhook sees a non-IP here it means the
    /// catalog was applied before the resolver ran, which is a CR
    /// ordering bug the user needs to fix.
    #[error("gateway '{name}' host '{host}' is not an IPv4 literal — resolve the DNS name and re-apply the GatewayCatalog")]
    UnresolvedHost { name: String, host: String },
    /// Two AgentPolicies in the same namespace select overlapping
    /// pod sets with contradicting default actions. The controller
    /// can still handle this (intersect-deny semantics, see plan
    /// §8.4) but making the user resolve it at apply time produces
    /// more predictable enforcement.
    #[error("conflicts with existing policy '{0}' — same namespace, overlapping pods, different defaultAction")]
    ConflictsWith(String),
    /// podSelector is empty. An omitted selector matches every pod
    /// in the namespace, which is almost always a mistake; require
    /// the user to explicitly opt in by setting an empty but present
    /// `matchLabels: {}`.
    #[error("podSelector is required; use 'matchLabels: {{}}' to explicitly target every pod in the namespace")]
    EmptyPodSelector,
}

/// Validate a single `AgentPolicySpec` given its visible catalogs
/// and the other policies in the same namespace.
///
/// Returns `Ok(())` iff every rule passes.
pub fn validate_agent_policy(
    policy: &AgentPolicySpec,
    catalogs: &BTreeMap<String, GatewayCatalogSpec>,
    sibling_policies: &[(&str, &AgentPolicySpec)],
) -> Result<(), ValidationError> {
    // Rule 1: an explicit selector is required. We treat a selector
    // that was never written as invalid — `kube` deserializes a
    // missing field into an empty default, and an empty selector
    // "matches everything" by Kubernetes convention, which is a
    // foot-gun for a deny-by-default enforcer.
    if policy.pod_selector.match_labels.is_empty() {
        // Fail closed here rather than continuing — the downstream
        // compiler/conflict checks would all cascade off a selector
        // that's secretly matching the entire namespace.
        return Err(ValidationError::EmptyPodSelector);
    }

    // Rule 2: let the compiler tell us whether egress refs + hosts
    // are well-formed. Reusing compile_policy keeps webhook and
    // reconciler in lockstep — whatever the reconciler would reject
    // as Degraded, the webhook rejects at apply time.
    match compile_policy(policy, catalogs) {
        Ok(_) => {}
        Err(CompileError::UnknownGateway(name)) => {
            return Err(ValidationError::UnknownGatewayRef(name))
        }
        Err(CompileError::UnresolvedHost { name, host }) => {
            return Err(ValidationError::UnresolvedHost { name, host })
        }
    }

    // Rule 3: conflicts against already-admitted policies. Two
    // policies that both select some pod P need to agree on
    // defaultAction or one of them has to be narrowed. We approximate
    // "overlap" with pod_selector equality — good enough for
    // v1alpha1, given matchLabels is our only selector shape. Cross-
    // policy priority / intersect-deny lands with matchExpressions.
    for (name, other) in sibling_policies {
        if selectors_overlap(policy, other) && default_actions_differ(policy, other) {
            return Err(ValidationError::ConflictsWith((*name).to_string()));
        }
    }

    Ok(())
}

fn selectors_overlap(a: &AgentPolicySpec, b: &AgentPolicySpec) -> bool {
    // matchLabels are AND'd — two policies overlap iff one's set is
    // a subset of the other's (identical counts as subset-both-ways).
    let al = &a.pod_selector.match_labels;
    let bl = &b.pod_selector.match_labels;
    if al.is_empty() || bl.is_empty() {
        return false; // we already rejected empty selectors
    }
    let (small, large) = if al.len() <= bl.len() {
        (al, bl)
    } else {
        (bl, al)
    };
    small
        .iter()
        .all(|(k, v)| large.get(k).map(|lv| lv == v).unwrap_or(false))
}

fn default_actions_differ(a: &AgentPolicySpec, b: &AgentPolicySpec) -> bool {
    let a_default = a.egress.as_ref().map(|e| e.default_action);
    let b_default = b.egress.as_ref().map(|e| e.default_action);
    a_default != b_default
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_gateway_enforcer_controller::crds::{
        CatalogGateway, EgressAction, EgressPolicy, LabelSelector,
    };

    fn policy_with(labels: &[(&str, &str)], egress: Option<EgressPolicy>) -> AgentPolicySpec {
        let mut match_labels = BTreeMap::new();
        for (k, v) in labels {
            match_labels.insert((*k).into(), (*v).into());
        }
        AgentPolicySpec {
            pod_selector: LabelSelector { match_labels },
            egress,
            file_access: None,
            exec: None,
            block_mutations: false,
            schedule: None,
        }
    }

    fn deny_refs(refs: Vec<&str>) -> EgressPolicy {
        EgressPolicy {
            default_action: EgressAction::Deny,
            gateway_refs: refs.into_iter().map(String::from).collect(),
            cidrs: vec![],
        }
    }

    #[test]
    fn rejects_empty_selector() {
        let p = policy_with(&[], None);
        let err = validate_agent_policy(&p, &BTreeMap::new(), &[]).unwrap_err();
        assert!(matches!(err, ValidationError::EmptyPodSelector));
    }

    #[test]
    fn accepts_well_formed_policy_with_resolved_gateway() {
        let p = policy_with(&[("app", "ai")], Some(deny_refs(vec!["openai"])));
        let mut catalogs = BTreeMap::new();
        catalogs.insert(
            "platform".into(),
            GatewayCatalogSpec {
                gateways: vec![CatalogGateway {
                    name: "openai".into(),
                    host: "1.2.3.4".into(),
                    ports: vec![443],
                    description: None,
                }],
            },
        );
        validate_agent_policy(&p, &catalogs, &[]).unwrap();
    }

    #[test]
    fn rejects_unknown_gateway_ref() {
        let p = policy_with(&[("app", "ai")], Some(deny_refs(vec!["nope"])));
        let err = validate_agent_policy(&p, &BTreeMap::new(), &[]).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::UnknownGatewayRef(n) if n == "nope"
        ));
    }

    #[test]
    fn rejects_unresolved_host() {
        let p = policy_with(&[("app", "ai")], Some(deny_refs(vec!["openai"])));
        let mut catalogs = BTreeMap::new();
        catalogs.insert(
            "platform".into(),
            GatewayCatalogSpec {
                gateways: vec![CatalogGateway {
                    name: "openai".into(),
                    host: "api.openai.com".into(),
                    ports: vec![443],
                    description: None,
                }],
            },
        );
        let err = validate_agent_policy(&p, &catalogs, &[]).unwrap_err();
        assert!(matches!(err, ValidationError::UnresolvedHost { .. }));
    }

    #[test]
    fn rejects_conflicting_siblings_on_overlap() {
        let a = policy_with(&[("app", "ai")], Some(deny_refs(vec![])));
        let b = policy_with(
            &[("app", "ai")],
            Some(EgressPolicy {
                default_action: EgressAction::Audit,
                gateway_refs: vec![],
                cidrs: vec![],
            }),
        );
        let err =
            validate_agent_policy(&a, &BTreeMap::new(), &[("existing-policy", &b)]).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::ConflictsWith(n) if n == "existing-policy"
        ));
    }

    #[test]
    fn non_overlapping_selectors_do_not_conflict() {
        let a = policy_with(&[("app", "ai")], Some(deny_refs(vec![])));
        let b = policy_with(
            &[("app", "logger")],
            Some(EgressPolicy {
                default_action: EgressAction::Audit,
                gateway_refs: vec![],
                cidrs: vec![],
            }),
        );
        validate_agent_policy(&a, &BTreeMap::new(), &[("other", &b)]).unwrap();
    }

    #[test]
    fn identical_default_action_on_overlap_is_fine() {
        // Two policies with the same default both fire together —
        // that's additive, not a conflict.
        let a = policy_with(&[("app", "ai")], Some(deny_refs(vec![])));
        let b = policy_with(&[("app", "ai")], Some(deny_refs(vec![])));
        validate_agent_policy(&a, &BTreeMap::new(), &[("other", &b)]).unwrap();
    }
}
