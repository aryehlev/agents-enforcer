//! axum router that speaks the `admission.k8s.io/v1.AdmissionReview`
//! wire protocol. kube-rs provides the request/response types so we
//! don't need to redefine the schema.

use std::collections::BTreeMap;
use std::sync::Arc;

use agent_gateway_enforcer_controller::{AgentPolicy, AgentPolicySpec, GatewayCatalog};
use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use kube::core::DynamicObject;
use kube::{Api, Client, ResourceExt};

use crate::validate::{validate_agent_policy, ValidationError};

/// Shared state for webhook handlers: the kube Client is needed so
/// validation can fetch `GatewayCatalog` + sibling `AgentPolicy`
/// objects live. Shared via `Arc` because axum clones the state per
/// request.
#[derive(Clone)]
pub struct AppState {
    /// Live apiserver client.
    pub client: Client,
}

/// Build the webhook's HTTP router. Mounted at `/validate` per the
/// MutatingWebhookConfiguration we ship in the Helm chart.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/validate", post(validate_handler))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(Arc::new(state))
}

async fn validate_handler(
    State(state): State<Arc<AppState>>,
    Json(review): Json<AdmissionReview<AgentPolicy>>,
) -> Result<Json<AdmissionReview<DynamicObject>>, (StatusCode, String)> {
    // kube-core guarantees `AdmissionResponse::from(&req)` copies the
    // request UID into the response, so we don't need to thread it
    // ourselves — v1 apiservers reject a mismatch at admission time.
    let req: AdmissionRequest<AgentPolicy> = match review.try_into() {
        Ok(r) => r,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("malformed AdmissionReview: {}", e),
            ))
        }
    };

    let response = match &req.object {
        Some(policy) => validate_one(state.as_ref(), policy, &req).await,
        None => AdmissionResponse::from(&req)
            .deny("AdmissionRequest.object is missing an AgentPolicy payload"),
    };
    Ok(Json(response.into_review()))
}

async fn validate_one(
    state: &AppState,
    policy: &AgentPolicy,
    req: &AdmissionRequest<AgentPolicy>,
) -> AdmissionResponse {
    let namespace = policy
        .namespace()
        .or_else(|| req.namespace.clone())
        .unwrap_or_default();
    let name = policy.name_any();

    // Fetch catalogs + siblings. A failure to read here should never
    // silently admit — if the apiserver is unreachable, reject and
    // let the user retry.
    let catalogs = match fetch_catalogs(&state.client).await {
        Ok(c) => c,
        Err(e) => {
            return AdmissionResponse::from(req).deny(format!(
                "unable to read GatewayCatalogs for validation: {}",
                e
            ));
        }
    };

    let siblings = match fetch_siblings(&state.client, &namespace, &name).await {
        Ok(s) => s,
        Err(e) => {
            return AdmissionResponse::from(req).deny(format!(
                "unable to read sibling AgentPolicies for validation: {}",
                e
            ));
        }
    };
    let sibling_refs: Vec<(&str, &AgentPolicySpec)> =
        siblings.iter().map(|(n, s)| (n.as_str(), s)).collect();

    match validate_agent_policy(&policy.spec, &catalogs, &sibling_refs) {
        Ok(()) => AdmissionResponse::from(req),
        Err(err) => {
            tracing::info!(
                policy = %format!("{}/{}", namespace, name),
                err = %err,
                "rejecting AgentPolicy"
            );
            AdmissionResponse::from(req).deny(format_user_error(&err))
        }
    }
}

async fn fetch_catalogs(
    client: &Client,
) -> anyhow::Result<BTreeMap<String, agent_gateway_enforcer_controller::GatewayCatalogSpec>> {
    let api: Api<GatewayCatalog> = Api::all(client.clone());
    let list = api.list(&Default::default()).await?;
    Ok(list
        .items
        .into_iter()
        .map(|c| (c.name_any(), c.spec))
        .collect())
}

async fn fetch_siblings(
    client: &Client,
    namespace: &str,
    skip_name: &str,
) -> anyhow::Result<Vec<(String, AgentPolicySpec)>> {
    let api: Api<AgentPolicy> = Api::namespaced(client.clone(), namespace);
    let list = api.list(&Default::default()).await?;
    Ok(list
        .items
        .into_iter()
        .filter(|p| p.name_any() != skip_name)
        .map(|p| (p.name_any(), p.spec))
        .collect())
}

/// Render a ValidationError with a hint operators can act on. The
/// bare Display is already decent; we prepend the rule category
/// so UI tooling can filter on it.
fn format_user_error(err: &ValidationError) -> String {
    match err {
        ValidationError::UnknownGatewayRef(_) | ValidationError::UnresolvedHost { .. } => {
            format!("[catalog] {}", err)
        }
        ValidationError::ConflictsWith(_) => format!("[conflict] {}", err),
        ValidationError::EmptyPodSelector => format!("[schema] {}", err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_user_error_tags_by_category() {
        assert!(format_user_error(&ValidationError::EmptyPodSelector).starts_with("[schema]"));
        assert!(format_user_error(&ValidationError::UnknownGatewayRef("x".into()))
            .starts_with("[catalog]"));
        assert!(format_user_error(&ValidationError::ConflictsWith("other".into()))
            .starts_with("[conflict]"));
    }
}
