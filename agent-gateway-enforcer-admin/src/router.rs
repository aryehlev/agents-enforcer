//! axum router for the admin API + embedded static dashboard.
//!
//! Endpoints:
//!   GET /api/v1/policies?namespace=ns            -> [PolicyView]
//!   GET /api/v1/capabilities?namespace=ns        -> [CapabilityView]
//!   GET /api/v1/violations?namespace=ns&since=1h -> [ViolationView]
//!   GET /api/v1/overview                          -> OverviewView
//!   GET /healthz
//!   GET /                                         -> static dashboard HTML
//!   GET /app.js                                   -> bundled JS
//!
//! The static assets are `include_str!`'d so deployment is a single
//! binary + a Helm Deployment + a Service. No separate web-build
//! step; the whole UI fits in ~300 lines of vanilla JS.

use std::collections::BTreeMap;
use std::sync::Arc;

use agent_gateway_enforcer_controller::{AgentCapability, AgentPolicy, AgentViolation};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use kube::{Api, Client};
use serde::Deserialize;

use crate::api::{capability_view, overview_view, policy_view, violation_view};
use crate::views::{CapabilityView, OverviewView, PolicyView, ViolationView};

/// Shared app state.
pub struct AppState {
    pub client: Client,
    /// Optional Prometheus endpoint. When present, capability + overview
    /// views get live spend; when absent, spend fields render as null.
    pub prom_url: Option<String>,
    pub http: reqwest::Client,
}

/// Build the router. Any non-/api path falls through to the static
/// dashboard so SPAs that use client-side routing work with an
/// ingress that doesn't rewrite.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/policies", get(list_policies))
        .route("/api/v1/capabilities", get(list_capabilities))
        .route("/api/v1/violations", get(list_violations))
        .route("/api/v1/overview", get(overview))
        .route("/healthz", get(|| async { "ok" }))
        .route("/", get(index_html))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(app_css))
        .with_state(state)
}

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
const APP_CSS: &str = include_str!("../static/styles.css");

async fn index_html() -> impl IntoResponse {
    Html(INDEX_HTML)
}

async fn app_js() -> impl IntoResponse {
    ([("content-type", "application/javascript")], APP_JS)
}

async fn app_css() -> impl IntoResponse {
    ([("content-type", "text/css")], APP_CSS)
}

#[derive(Debug, Deserialize, Default)]
struct NsQuery {
    namespace: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ViolationsQuery {
    namespace: Option<String>,
    since: Option<String>,
}

async fn list_policies(
    State(state): State<Arc<AppState>>,
    Query(q): Query<NsQuery>,
) -> Result<Json<Vec<PolicyView>>, (StatusCode, String)> {
    let items = list_cr::<AgentPolicy>(&state.client, q.namespace.as_deref())
        .await
        .map_err(internal)?;
    Ok(Json(items.iter().map(policy_view).collect()))
}

async fn list_capabilities(
    State(state): State<Arc<AppState>>,
    Query(q): Query<NsQuery>,
) -> Result<Json<Vec<CapabilityView>>, (StatusCode, String)> {
    let items = list_cr::<AgentCapability>(&state.client, q.namespace.as_deref())
        .await
        .map_err(internal)?;

    let (spend, prom_available) = match state.prom_url.as_deref() {
        Some(url) => match spend_by_agent(&state.http, url).await {
            Ok(map) => (map, true),
            Err(e) => {
                tracing::warn!(err = %e, "prometheus query failed; returning capabilities without spend");
                (BTreeMap::new(), false)
            }
        },
        None => (BTreeMap::new(), false),
    };

    Ok(Json(
        items
            .iter()
            .map(|c| capability_view(c, &spend, prom_available))
            .collect(),
    ))
}

async fn list_violations(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ViolationsQuery>,
) -> Result<Json<Vec<ViolationView>>, (StatusCode, String)> {
    let items = list_cr::<AgentViolation>(&state.client, q.namespace.as_deref())
        .await
        .map_err(internal)?;
    let cutoff = match q.since.as_deref() {
        Some(s) => Some(parse_since(s).map_err(bad_request)?),
        None => None,
    };
    let now = chrono::Utc::now();
    let mut views: Vec<ViolationView> = items
        .iter()
        .filter(|v| match cutoff {
            Some(d) => chrono::DateTime::parse_from_rfc3339(&v.spec.last_seen)
                .map(|t| t.to_utc() >= now - d)
                .unwrap_or(false),
            None => true,
        })
        .map(violation_view)
        .collect();
    // Newest first so the UI's first page is what operators usually want.
    views.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    Ok(Json(views))
}

async fn overview(
    State(state): State<Arc<AppState>>,
) -> Result<Json<OverviewView>, (StatusCode, String)> {
    let policies = list_cr::<AgentPolicy>(&state.client, None)
        .await
        .map_err(internal)?;
    let capabilities = list_cr::<AgentCapability>(&state.client, None)
        .await
        .map_err(internal)?;
    let violations = list_cr::<AgentViolation>(&state.client, None)
        .await
        .map_err(internal)?;

    // These metric lookups are best-effort: the overview page should
    // still render with placeholder zeros when prom is offline.
    let (nodes_up, spend_total) = match state.prom_url.as_deref() {
        Some(url) => {
            let nodes = query_scalar(&state.http, url, "sum(enforcer_node_agent_up)")
                .await
                .unwrap_or(0.0) as u64;
            let spend =
                query_scalar(&state.http, url, "sum(enforcer_llm_spend_usd_total)")
                    .await
                    .unwrap_or(0.0);
            (nodes, spend)
        }
        None => (0, 0.0),
    };

    Ok(Json(overview_view(
        &policies,
        &capabilities,
        &violations,
        nodes_up,
        spend_total,
    )))
}

async fn list_cr<K>(client: &Client, namespace: Option<&str>) -> anyhow::Result<Vec<K>>
where
    K: kube::Resource<Scope = kube::core::NamespaceResourceScope>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + 'static,
    <K as kube::Resource>::DynamicType: Default,
{
    let api: Api<K> = match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let list = api.list(&Default::default()).await?;
    Ok(list.items)
}

async fn spend_by_agent(
    http: &reqwest::Client,
    prom_url: &str,
) -> anyhow::Result<BTreeMap<String, f64>> {
    let results = query_vector(http, prom_url, "sum by (agent) (enforcer_llm_spend_usd_total)")
        .await?;
    let mut out = BTreeMap::new();
    for (labels, value) in results {
        if let Some(agent) = labels.get("agent") {
            out.insert(agent.clone(), value);
        }
    }
    Ok(out)
}

async fn query_scalar(
    http: &reqwest::Client,
    prom_url: &str,
    promql: &str,
) -> anyhow::Result<f64> {
    let vec = query_vector(http, prom_url, promql).await?;
    Ok(vec.first().map(|(_, v)| *v).unwrap_or(0.0))
}

/// Minimal Prometheus HTTP instant-query call. Admin doesn't take a
/// dep on the `enforcerctl` crate's prom module to avoid cross-crate
/// coupling; this stays a dozen lines.
async fn query_vector(
    http: &reqwest::Client,
    prom_url: &str,
    promql: &str,
) -> anyhow::Result<Vec<(BTreeMap<String, String>, f64)>> {
    let url = format!("{}/api/v1/query", prom_url.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .query(&[("query", promql)])
        .send()
        .await?
        .error_for_status()?;
    let v: serde_json::Value = resp.json().await?;
    if v.get("status").and_then(|s| s.as_str()) != Some("success") {
        anyhow::bail!("prom error: {:?}", v.get("error"));
    }
    let results = v
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::with_capacity(results.len());
    for r in results {
        let metric: BTreeMap<String, String> = serde_json::from_value(
            r.get("metric").cloned().unwrap_or_default(),
        )?;
        let pair = r
            .get("value")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("missing value"))?;
        let value_str = pair
            .get(1)
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("malformed value"))?;
        out.push((metric, value_str.parse().unwrap_or(0.0)));
    }
    Ok(out)
}

fn parse_since(s: &str) -> anyhow::Result<chrono::Duration> {
    let s = s.trim();
    let pos = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| anyhow::anyhow!("missing unit (e.g. 1h, 30m)"))?;
    let (num, unit) = s.split_at(pos);
    let n: i64 = num.parse()?;
    Ok(match unit {
        "s" => chrono::Duration::seconds(n),
        "m" => chrono::Duration::minutes(n),
        "h" => chrono::Duration::hours(n),
        "d" => chrono::Duration::days(n),
        other => anyhow::bail!("bad unit '{}'", other),
    })
}

fn internal(e: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn bad_request(e: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_since_accepts_common_units() {
        assert_eq!(parse_since("1h").unwrap(), chrono::Duration::hours(1));
        assert_eq!(parse_since("30m").unwrap(), chrono::Duration::minutes(30));
        assert_eq!(parse_since("2d").unwrap(), chrono::Duration::days(2));
    }

    #[test]
    fn parse_since_rejects_bad_input() {
        assert!(parse_since("abc").is_err());
        assert!(parse_since("5y").is_err());
    }
}
