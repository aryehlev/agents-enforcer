//! `enforcerctl policies <subcmd>`.
//!
//! Reads live state from the apiserver. Writes go through `kubectl`
//! so they keep hitting the admission webhook — this CLI is
//! deliberately read-only for v1alpha1.

use std::collections::BTreeMap;

use agent_gateway_enforcer_controller::{AgentPolicy, LabelSelector};
use anyhow::Context;
use kube::{Api, Client, ResourceExt};

use crate::format::{policies_table, PolicyRow};

pub async fn list(client: &Client, namespace: Option<&str>) -> anyhow::Result<String> {
    let policies = fetch(client, namespace).await?;
    let rows: Vec<PolicyRow> = policies.into_iter().map(to_row).collect();
    Ok(policies_table(&rows))
}

async fn fetch(client: &Client, namespace: Option<&str>) -> anyhow::Result<Vec<AgentPolicy>> {
    let api: Api<AgentPolicy> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api
        .list(&Default::default())
        .await
        .context("list AgentPolicy")?;
    Ok(list.items)
}

/// Free function so the formatter is unit-testable without a live
/// kube cluster — `tests::` constructs `AgentPolicy` objects in-memory
/// and asserts on the rendered row.
pub fn to_row(p: AgentPolicy) -> PolicyRow {
    let namespace = p.namespace().unwrap_or_else(|| "<none>".to_string());
    let name = p.name_any();
    let selector = render_selector(&p.spec.pod_selector);
    let (enforced, hash, message) = p
        .status
        .as_ref()
        .map(|s| {
            (
                s.enforced_pods,
                s.last_bundle_hash.clone().unwrap_or_default(),
                s.message.clone().unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    PolicyRow {
        namespace,
        name,
        selector,
        enforced_pods: enforced,
        hash: short_hash(&hash),
        message,
    }
}

/// Render a matchLabels map in `k=v,k=v` form — kubectl's style.
fn render_selector(sel: &LabelSelector) -> String {
    if sel.match_labels.is_empty() {
        return "<empty>".into();
    }
    // BTreeMap iter() is sorted, so output is stable.
    let pairs: Vec<String> = sel
        .match_labels
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    pairs.join(",")
}

/// Truncate to the conventional 12-char git/sha256 prefix so the
/// table doesn't wrap.
fn short_hash(hash: &str) -> String {
    if hash.is_empty() {
        return "<pending>".into();
    }
    hash.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_gateway_enforcer_controller::{AgentPolicy, AgentPolicySpec, AgentPolicyStatus};
    use kube::api::ObjectMeta;

    fn policy(name: &str, namespace: &str, labels: &[(&str, &str)]) -> AgentPolicy {
        let mut match_labels = BTreeMap::new();
        for (k, v) in labels {
            match_labels.insert((*k).into(), (*v).into());
        }
        AgentPolicy {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(namespace.into()),
                ..Default::default()
            },
            spec: AgentPolicySpec {
                pod_selector: LabelSelector { match_labels },
                egress: None,
                file_access: None,
                exec: None,
                block_mutations: false,
                schedule: None,
            },
            status: Some(AgentPolicyStatus {
                last_bundle_hash: Some(
                    "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789ab".into(),
                ),
                enforced_pods: 7,
                message: None,
            }),
        }
    }

    #[test]
    fn to_row_formats_selector_in_kubectl_style() {
        let p = policy("agent", "prod", &[("app", "ai"), ("tier", "front")]);
        let row = to_row(p);
        // BTreeMap is sorted; "app" precedes "tier".
        assert_eq!(row.selector, "app=ai,tier=front");
    }

    #[test]
    fn to_row_renders_empty_selector_explicitly() {
        let row = to_row(policy("agent", "prod", &[]));
        assert_eq!(row.selector, "<empty>");
    }

    #[test]
    fn to_row_truncates_hash_to_12() {
        let row = to_row(policy("agent", "prod", &[("app", "ai")]));
        assert_eq!(row.hash.len(), 12);
        assert_eq!(row.hash, "deadbeefcafe");
    }

    #[test]
    fn to_row_shows_pending_when_status_missing_hash() {
        let mut p = policy("agent", "prod", &[("app", "ai")]);
        p.status.as_mut().unwrap().last_bundle_hash = None;
        let row = to_row(p);
        assert_eq!(row.hash, "<pending>");
    }

    #[test]
    fn to_row_with_no_status_uses_defaults() {
        let mut p = policy("agent", "prod", &[("app", "ai")]);
        p.status = None;
        let row = to_row(p);
        assert_eq!(row.enforced_pods, 0);
        assert_eq!(row.hash, "<pending>");
        assert_eq!(row.message, "");
    }
}
