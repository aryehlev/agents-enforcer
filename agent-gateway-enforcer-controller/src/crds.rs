//! CRD types for the `agents.enforcer.io` API group.
//!
//! Keep these structs flat and use `#[serde(rename_all = "camelCase")]`
//! on every spec so the generated OpenAPI schema matches what a
//! platform engineer would write in YAML — no surprise case
//! translations, no tag-union gymnastics.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Top-level CR: selects a set of pods in a namespace and declares
/// which egress destinations, file paths, and exec binaries they're
/// allowed to use.
///
/// See §3.1 of `docs/k8s-controller-plan.md` for the YAML shape.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[kube(
    group = "agents.enforcer.io",
    version = "v1alpha1",
    kind = "AgentPolicy",
    namespaced,
    status = "AgentPolicyStatus",
    shortname = "agentpol",
    printcolumn = r#"{"name":"Selector","type":"string","jsonPath":".spec.podSelector.matchLabels"}"#,
    printcolumn = r#"{"name":"Enforced","type":"integer","jsonPath":".status.enforcedPods"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct AgentPolicySpec {
    /// Selects pods this policy applies to.
    pub pod_selector: LabelSelector,

    /// Egress rules. Omitted = audit-only egress (connections observed
    /// but not blocked); required when the controller enforces
    /// default-deny cluster-wide via `EnforcerConfig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressPolicy>,

    /// File access rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_access: Option<FileAccessPolicy>,

    /// Exec rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecPolicy>,

    /// Block path mutations (unlink/mkdir/rmdir) from matched pods.
    /// Defaults to false so audit-mode rollouts don't accidentally
    /// brick sidecar log rotation.
    #[serde(default)]
    pub block_mutations: bool,
}

/// A label selector subset of Kubernetes' `LabelSelector` — we only
/// support `matchLabels` in v1alpha1 to keep the reconciler trivially
/// deterministic; `matchExpressions` can land in v1beta1 without a
/// breaking API change.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub match_labels: std::collections::BTreeMap<String, String>,
}

/// Egress defaults + per-destination rules.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EgressPolicy {
    /// What to do with destinations not explicitly allowed.
    #[serde(default)]
    pub default_action: EgressAction,

    /// Named gateways resolved via `GatewayCatalog`. Reference-only;
    /// the catalog defines the actual (host, port) pairs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway_refs: Vec<String>,

    /// Inline (CIDR, port) allow entries for destinations that don't
    /// fit the catalog (e.g. a cluster-internal database).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidrs: Vec<CidrRule>,
}

/// Action applied to traffic that doesn't match any explicit rule.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub enum EgressAction {
    /// Block the connection. Use for production enforcement.
    Deny,
    /// Emit a decision event but allow the connection. Use during
    /// rollout to gather an inventory before flipping to Deny.
    #[default]
    Audit,
    /// Allow everything. Equivalent to the policy not existing for
    /// egress but useful for staging.
    Allow,
}

/// Inline (CIDR, port) egress entry.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CidrRule {
    /// IPv4/IPv6 CIDR; today only exact-IP /32 and /128 are honored by
    /// the ebpf-linux backend. Broader prefixes compile but only the
    /// host-bit portion is enforced until LPM maps land.
    pub cidr: String,
    /// Ports to allow to this CIDR. Empty = any port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
}

/// File access rules.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileAccessPolicy {
    /// Whether file operations from matched pods are default-denied.
    #[serde(default)]
    pub default_deny: bool,
    /// Path prefixes the pod is allowed to read/write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_paths: Vec<String>,
    /// Path prefixes the pod must not touch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_paths: Vec<String>,
}

/// Exec allowlist.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExecPolicy {
    /// Binary paths (prefix match) the pod may exec. All other execs
    /// are denied at `bprm_check_security`.
    pub allowed_binaries: Vec<String>,
}

/// Runtime status written back by the controller.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AgentPolicyStatus {
    /// Last compiled bundle hash, so operators can cross-reference
    /// against node-agent metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_bundle_hash: Option<String>,
    /// Count of pods currently enforcing this policy across the cluster.
    #[serde(default)]
    pub enforced_pods: u32,
    /// Human-readable message for `kubectl describe` when something
    /// went wrong (e.g. an unresolved gateway reference).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// -------------------------------------------------------------------
// GatewayCatalog
// -------------------------------------------------------------------

/// Cluster-scoped catalog of named gateways. Platform teams curate
/// this; app teams reference entries by name from their
/// `AgentPolicy.egress.gatewayRefs`.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[kube(
    group = "agents.enforcer.io",
    version = "v1alpha1",
    kind = "GatewayCatalog",
    shortname = "gwcat"
)]
#[serde(rename_all = "camelCase")]
pub struct GatewayCatalogSpec {
    /// Named gateway entries. Names are referenced from
    /// `AgentPolicy.egress.gatewayRefs`.
    pub gateways: Vec<CatalogGateway>,
}

/// A single entry in a `GatewayCatalog`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CatalogGateway {
    /// Key that policies reference.
    pub name: String,
    /// Target host. Either an IPv4 literal or a DNS name that the
    /// controller resolves at compile time (and re-resolves on TTL).
    pub host: String,
    /// Ports; empty means "any port".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Optional free-form description surfaced in `kubectl describe`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// -------------------------------------------------------------------
// AgentViolation
// -------------------------------------------------------------------

/// Structured record of a sustained policy violation, created by the
/// controller from aggregated node-agent events. Namespaced so
/// operators can `kubectl get agentviolations -n prod` to see only
/// the ones they own.
///
/// These are intentionally cheap objects: one CR per (pod, policy,
/// rule, bucket) tuple with a short TTL. The aggregator buckets raw
/// events into windows (default 60s) so a single misbehaving pod
/// produces a handful of CRs rather than millions.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[kube(
    group = "agents.enforcer.io",
    version = "v1alpha1",
    kind = "AgentViolation",
    namespaced,
    shortname = "agentvio",
    printcolumn = r#"{"name":"Pod","type":"string","jsonPath":".spec.podName"}"#,
    printcolumn = r#"{"name":"Policy","type":"string","jsonPath":".spec.policyName"}"#,
    printcolumn = r#"{"name":"Kind","type":"string","jsonPath":".spec.kind"}"#,
    printcolumn = r#"{"name":"Count","type":"integer","jsonPath":".spec.count"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct AgentViolationSpec {
    /// Name of the pod that triggered the violation.
    pub pod_name: String,
    /// UID of the pod. Used for exact identification in case
    /// namespaces contain pods with the same name after recreation.
    pub pod_uid: String,
    /// The AgentPolicy that was being enforced when this violation
    /// fired. Unqualified name — namespace is the CR's namespace.
    pub policy_name: String,
    /// What kind of rule was violated. Matched to the decision tag
    /// emitted from the data plane (see `events.c` event types).
    pub kind: ViolationKind,
    /// Human-readable detail, e.g. `connect to 1.2.3.4:443` or
    /// `exec /bin/sh`. Format depends on `kind`; callers shouldn't
    /// pattern-match on it.
    pub detail: String,
    /// How many times this exact (kind, detail) fired inside the
    /// aggregation window. At least 1.
    pub count: u32,
    /// RFC3339 timestamp of the first occurrence in the window.
    pub first_seen: String,
    /// RFC3339 timestamp of the most recent occurrence in the window.
    pub last_seen: String,
}

/// Category of violation. Kept narrow on purpose: the aggregator
/// maps data-plane event types to these and we'd rather add variants
/// here than let free-form strings creep into the API.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub enum ViolationKind {
    /// `cgroup/connect4|6` denied a connection to an unlisted gateway.
    EgressBlocked,
    /// `lsm/file_open` or `lsm/file_permission` denied a file op.
    FileBlocked,
    /// `lsm/bprm_check_security` denied an exec.
    ExecBlocked,
    /// `lsm/path_unlink|mkdir|rmdir` denied a mutation.
    MutationBlocked,
}

// -------------------------------------------------------------------
// EnforcerConfig
// -------------------------------------------------------------------

/// Cluster-scoped singleton for operational knobs. The controller
/// treats `metadata.name == "cluster"` as the canonical instance;
/// additional instances are ignored with a warning.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[kube(
    group = "agents.enforcer.io",
    version = "v1alpha1",
    kind = "EnforcerConfig",
    shortname = "enfcfg"
)]
#[serde(rename_all = "camelCase")]
pub struct EnforcerConfigSpec {
    /// Namespaces the controller enforces. Empty = all namespaces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enabled_namespaces: Vec<String>,
    /// When true, the data plane opts into uprobe-based TLS inspection
    /// for payload audit. Off by default — this is legally and
    /// ethically sensitive and should be opt-in per cluster.
    #[serde(default)]
    pub enable_tls_inspection: bool,
    /// When true, policy reloads forcibly drain in-flight flows via RST
    /// injection. Off by default to avoid correlated failures during
    /// rolling policy changes.
    #[serde(default)]
    pub strict_reload: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn agent_policy_crd_yaml_is_valid() {
        // CustomResourceExt generates the full CRD definition; make
        // sure it at least serializes to YAML without panicking.
        let yaml = serde_yaml::to_string(&AgentPolicy::crd()).expect("yaml");
        assert!(yaml.contains("agents.enforcer.io"));
        assert!(yaml.contains("AgentPolicy"));
    }

    #[test]
    fn gateway_catalog_crd_is_cluster_scoped() {
        let crd = GatewayCatalog::crd();
        assert_eq!(crd.spec.scope, "Cluster");
    }

    #[test]
    fn agent_policy_crd_is_namespaced() {
        let crd = AgentPolicy::crd();
        assert_eq!(crd.spec.scope, "Namespaced");
    }

    #[test]
    fn egress_action_defaults_to_audit() {
        assert_eq!(EgressAction::default(), EgressAction::Audit);
    }

    #[test]
    fn agent_violation_crd_is_namespaced_with_printer_columns() {
        let crd = AgentViolation::crd();
        assert_eq!(crd.spec.scope, "Namespaced");
        // Five printer columns so `kubectl get agentviolations` is
        // useful without -o wide.
        let v = &crd.spec.versions[0];
        let cols = v.additional_printer_columns.as_ref().unwrap();
        assert_eq!(cols.len(), 5);
    }

    #[test]
    fn violation_kind_round_trips() {
        for k in [
            ViolationKind::EgressBlocked,
            ViolationKind::FileBlocked,
            ViolationKind::ExecBlocked,
            ViolationKind::MutationBlocked,
        ] {
            let s = serde_json::to_string(&k).unwrap();
            let back: ViolationKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn agent_policy_round_trips_through_yaml() {
        use std::collections::BTreeMap;
        let spec = AgentPolicySpec {
            pod_selector: LabelSelector {
                match_labels: {
                    let mut m = BTreeMap::new();
                    m.insert("app".into(), "ai-agent".into());
                    m
                },
            },
            egress: Some(EgressPolicy {
                default_action: EgressAction::Deny,
                gateway_refs: vec!["openai".into()],
                cidrs: vec![CidrRule {
                    cidr: "10.0.0.0/32".into(),
                    ports: vec![5432],
                }],
            }),
            file_access: None,
            exec: Some(ExecPolicy {
                allowed_binaries: vec!["/usr/bin/python3".into()],
            }),
            block_mutations: true,
        };
        let yaml = serde_yaml::to_string(&spec).unwrap();
        let back: AgentPolicySpec = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(spec, back);
    }
}
