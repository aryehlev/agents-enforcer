//! JSON shapes the admin API serves. Deliberately narrower than the
//! raw CRs — we return only what UIs need, so a UI doesn't have to
//! know about Kubernetes metadata like `resourceVersion`,
//! `generation`, or `managedFields`.
//!
//! Every view has `From<&CRD>` conversions in `api.rs` so the tests
//! can exercise the mapping without pulling up a kube client.

use serde::Serialize;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct PolicyView {
    pub namespace: String,
    pub name: String,
    #[serde(rename = "selector")]
    pub match_labels: std::collections::BTreeMap<String, String>,
    pub enforced_pods: u32,
    pub bundle_hash: Option<String>,
    pub message: Option<String>,
    /// `Deny` / `Audit` / `Allow` / `null` if the policy has no
    /// egress block. Flattened out of spec.egress.defaultAction
    /// so UIs don't have to know about the nested shape.
    pub default_egress_action: Option<String>,
    /// Pretty-printed schedule — empty string when not scheduled.
    pub schedule_summary: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CapabilityView {
    pub namespace: String,
    pub name: String,
    pub allowed_models: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub max_daily_spend_usd: f64,
    /// Live spend from Prometheus; `None` when prom was unavailable.
    pub spent_today_usd: Option<f64>,
    pub max_output_tokens: Option<u32>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct ViolationView {
    pub namespace: String,
    pub pod: String,
    pub policy: String,
    pub kind: String,
    pub detail: String,
    pub count: u32,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct OverviewView {
    pub nodes_up: u64,
    pub policy_count: u64,
    pub capability_count: u64,
    pub violation_count_last_hour: u64,
    pub total_spend_today_usd: f64,
}
