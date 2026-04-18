//! `enforcerctl capabilities <subcmd>`.
//!
//! `list` pulls `AgentCapability` CRs and — optionally — current
//! spend from a Prometheus-compatible query endpoint so the table
//! shows **what's configured** and **what's actually being spent**
//! side by side.

use std::collections::BTreeMap;

use agent_gateway_enforcer_controller::AgentCapability;
use anyhow::Context;
use kube::{Api, Client, ResourceExt};

use crate::format::{capabilities_table, CapabilityRow};
use crate::prom::{PromClient, Sample};

pub async fn list(
    client: &Client,
    namespace: Option<&str>,
    prom: Option<&PromClient>,
) -> anyhow::Result<String> {
    let caps = fetch(client, namespace).await?;
    let spend_by_agent = match prom {
        Some(p) => spend_by_agent(p).await.unwrap_or_else(|e| {
            // Prometheus is often offline in dev; degrade gracefully
            // rather than failing the whole CLI invocation.
            tracing::warn!(err = %e, "prometheus query failed; spend columns will be 0");
            BTreeMap::new()
        }),
        None => BTreeMap::new(),
    };
    let rows: Vec<CapabilityRow> = caps
        .into_iter()
        .map(|c| to_row(c, &spend_by_agent))
        .collect();
    Ok(capabilities_table(&rows))
}

async fn fetch(
    client: &Client,
    namespace: Option<&str>,
) -> anyhow::Result<Vec<AgentCapability>> {
    let api: Api<AgentCapability> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api
        .list(&Default::default())
        .await
        .context("list AgentCapability")?;
    Ok(list.items)
}

/// Query today's running spend per agent. The LLM proxy emits
/// `enforcer_llm_spend_usd_total{agent="ns/name", model="..."}`; a
/// sum over `model` gives per-agent spend.
async fn spend_by_agent(prom: &PromClient) -> anyhow::Result<BTreeMap<String, f64>> {
    let samples: Vec<Sample> = prom
        .query("sum by (agent) (enforcer_llm_spend_usd_total)")
        .await?;
    let mut out = BTreeMap::new();
    for s in samples {
        if let Some(agent) = s.labels.get("agent") {
            out.insert(agent.clone(), s.value);
        }
    }
    Ok(out)
}

/// Construct a table row from a CR + the per-agent spend map.
pub fn to_row(c: AgentCapability, spend: &BTreeMap<String, f64>) -> CapabilityRow {
    let namespace = c.namespace().unwrap_or_else(|| "<none>".into());
    let name = c.name_any();
    let agent_id = format!("{}/{}", namespace, name);
    let spent_usd = spend.get(&agent_id).copied().unwrap_or(0.0);
    // Short forms so the table doesn't wrap; full lists live in
    // `enforcerctl capabilities describe` (follow-up).
    let models = short_list(&c.spec.allowed_models);
    let tools = short_list(&c.spec.allowed_tools);
    CapabilityRow {
        namespace,
        name,
        models,
        tools,
        budget_usd: c.spec.max_daily_spend_usd,
        spent_usd,
    }
}

fn short_list(items: &[String]) -> String {
    // Match kubectl's "a, b, c (+N more)" idiom above 3.
    if items.is_empty() {
        return "<none>".into();
    }
    let mut first: Vec<String> = items.iter().take(3).cloned().collect();
    if items.len() > 3 {
        first.push(format!("+{} more", items.len() - 3));
    }
    first.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_gateway_enforcer_controller::{AgentCapability, AgentCapabilitySpec, LabelSelector};
    use kube::api::ObjectMeta;

    fn cap(name: &str, ns: &str, models: &[&str], tools: &[&str], budget: f64) -> AgentCapability {
        AgentCapability {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            spec: AgentCapabilitySpec {
                pod_selector: LabelSelector::default(),
                allowed_models: models.iter().map(|s| s.to_string()).collect(),
                allowed_tools: tools.iter().map(|s| s.to_string()).collect(),
                max_daily_spend_usd: budget,
                max_output_tokens: None,
            },
            status: None,
        }
    }

    #[test]
    fn to_row_looks_up_spend_by_ns_slash_name() {
        let mut spend = BTreeMap::new();
        spend.insert("prod/agent".into(), 2.5);
        let row = to_row(cap("agent", "prod", &["gpt-4o"], &[], 10.0), &spend);
        assert!((row.spent_usd - 2.5).abs() < 1e-9);
    }

    #[test]
    fn to_row_missing_from_prom_has_zero_spend() {
        let row = to_row(
            cap("agent", "prod", &["gpt-4o"], &[], 10.0),
            &BTreeMap::new(),
        );
        assert_eq!(row.spent_usd, 0.0);
    }

    #[test]
    fn short_list_truncates_above_three_entries() {
        assert_eq!(short_list(&[]), "<none>");
        assert_eq!(
            short_list(&["a".into(), "b".into(), "c".into()]),
            "a,b,c"
        );
        assert_eq!(
            short_list(&[
                "a".into(),
                "b".into(),
                "c".into(),
                "d".into(),
                "e".into(),
            ]),
            "a,b,c,+2 more"
        );
    }
}
