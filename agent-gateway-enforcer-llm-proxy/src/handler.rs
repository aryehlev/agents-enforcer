//! HTTP router that speaks the OpenAI-compatible Chat Completions
//! wire shape. The request / response are forwarded upstream on
//! allow; on deny the proxy returns the OpenAI error envelope so
//! existing SDKs surface the rejection naturally.

use std::sync::Arc;

use agent_gateway_enforcer_controller::CapabilityBundle;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::budget::BudgetStore;
use crate::capabilities::CapabilityStore;
use crate::enforce::{check, RejectReason, RequestFacts};
use crate::metrics::{LLM_BUDGET_SPENT, LLM_REJECTIONS, LLM_REQUESTS, LLM_SPEND, LLM_TOKENS};
use crate::pricing::price_for;

/// Runtime state the axum router threads through every request.
pub struct AppState {
    pub caps: Arc<CapabilityStore>,
    pub budget: Arc<BudgetStore>,
    pub upstream_base: String,
    pub http: reqwest::Client,
}

/// Build the axum router. `/v1/chat/completions` is the one hot
/// endpoint; `/healthz` and `/readyz` exist so the Helm chart
/// can wire kubelet probes.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get({
                let s = state.clone();
                move || {
                    let s = s.clone();
                    async move {
                        if s.caps.is_empty() {
                            // No capabilities loaded = proxy would
                            // reject every request. That's not
                            // "ready" in the kubelet sense.
                            (StatusCode::SERVICE_UNAVAILABLE, "no capabilities loaded")
                        } else {
                            (StatusCode::OK, "ok")
                        }
                    }
                }
            }),
        )
        .with_state(state)
}

async fn chat_completions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // Agent identity — matches the AgentCapability's
    // `namespace/name`. SDKs set this via env: `OPENAI_DEFAULT_HEADERS`
    // or equivalent. No X-Agent-Id → no capability → reject.
    let agent_id = match headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(a) if !a.is_empty() => a,
        _ => return deny(&"unknown", &RejectReason::NoCapability),
    };

    let bundle = match state.caps.get(&agent_id) {
        Some(b) => b,
        None => return deny(&agent_id, &RejectReason::NoCapability),
    };

    let facts = match extract_facts(&body) {
        Ok(f) => f,
        Err(msg) => {
            LLM_REJECTIONS
                .with_label_values(&[&agent_id, "malformed_request"])
                .inc();
            return openai_error(StatusCode::BAD_REQUEST, &msg);
        }
    };

    let now = chrono::Utc::now();
    let spent = state.budget.spent_today(&agent_id, now);
    let rf = facts.as_request_facts();
    if let Err(reason) = check(&bundle, &rf, spent) {
        return deny(&agent_id, &reason);
    }

    forward(&state, &agent_id, &bundle, headers, body, facts, now).await
}

/// Fields extracted from the inbound JSON body. Borrowing from the
/// Value would require a longer-lived reference; owned strings are
/// fine here — we only pull a small number of fields.
fn extract_facts(body: &Value) -> Result<ExtractedFacts, String> {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| "field 'model' is required".to_string())?
        .to_string();

    // Input-token estimate: byte count over 4. Crude but effective
    // for budget enforcement — we only care about a lower bound, and
    // this is ~2x the real count in practice which errs on the side
    // of rejecting marginal requests rather than overspending.
    let bytes = serde_json::to_vec(body).map(|v| v.len()).unwrap_or(0);
    let estimated_input_tokens = (bytes / 4) as u64;

    let tool_names = body
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| {
                    // OpenAI shape: { "type": "function", "function": { "name": "..." } }
                    t.get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_else(Vec::new);

    let requested_max_output = body
        .get("max_tokens")
        .or_else(|| body.get("max_completion_tokens"))
        .and_then(Value::as_u64)
        .and_then(|u| u32::try_from(u).ok());

    Ok(ExtractedFacts {
        model,
        tool_names,
        estimated_input_tokens,
        requested_max_output,
    })
}

#[derive(Debug)]
struct ExtractedFacts {
    model: String,
    tool_names: Vec<String>,
    estimated_input_tokens: u64,
    requested_max_output: Option<u32>,
}

impl ExtractedFacts {
    fn as_request_facts(&self) -> RequestFacts<'_> {
        RequestFacts {
            model: &self.model,
            tool_names: self.tool_names.clone(),
            estimated_input_tokens: self.estimated_input_tokens,
            requested_max_output: self.requested_max_output,
        }
    }
}

/// Forward the request upstream, stream the response back to the
/// caller, and record tokens + spend from the response's `usage`
/// object.
async fn forward(
    state: &AppState,
    agent_id: &str,
    bundle: &CapabilityBundle,
    mut headers: HeaderMap,
    body: Value,
    facts: ExtractedFacts,
    now: chrono::DateTime<chrono::Utc>,
) -> Response {
    // Bridge http 1.x (axum 0.7) → http 0.2 (reqwest 0.11). Forward
    // only the headers the upstream actually needs — we don't want
    // to leak hop-by-hop bits and the http-crate mismatch makes
    // "just pass the map" impossible anyway. Authorization is the
    // critical one; Anthropic's `x-api-key` is the other provider's
    // equivalent.
    let mut reqwest_headers = reqwest::header::HeaderMap::new();
    for forwarded in [
        "authorization",
        "x-api-key",
        "anthropic-version",
        "openai-organization",
    ] {
        if let Some(v) = headers.get(forwarded) {
            if let Ok(s) = v.to_str() {
                if let (Ok(name), Ok(value)) = (
                    reqwest::header::HeaderName::from_bytes(forwarded.as_bytes()),
                    reqwest::header::HeaderValue::from_str(s),
                ) {
                    reqwest_headers.insert(name, value);
                }
            }
        }
    }
    // Strip caller-side control headers; we've now built the
    // forwarded map separately.
    headers.remove("x-agent-id");

    let url = format!(
        "{}/v1/chat/completions",
        state.upstream_base.trim_end_matches('/')
    );
    let resp = match state
        .http
        .post(&url)
        .headers(reqwest_headers)
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(err = %e, upstream = %url, "upstream call failed");
            return openai_error(
                StatusCode::BAD_GATEWAY,
                &format!("upstream call failed: {}", e),
            );
        }
    };

    // axum 0.7 uses http 1.x and reqwest 0.11 uses http 0.2 — the
    // types don't interop directly. Bridge by coercing to the raw
    // u16 / string forms.
    let status_code = resp.status().as_u16();
    let ctype_str: String = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    // Non-streaming path only in v1alpha1; streaming SSE lands with
    // a follow-up. Buffer the body so we can parse `usage` before
    // forwarding. For large / multi-MB responses this is fine — the
    // wire protocol is already JSON-bounded and OpenAI's maximum
    // response is tens of KB.
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return openai_error(
                StatusCode::BAD_GATEWAY,
                &format!("reading upstream body: {}", e),
            )
        }
    };

    // Pull token counts from OpenAI-shaped `usage`.
    let is_success = (200..300).contains(&status_code);
    if is_success {
        if let Ok(parsed) = serde_json::from_slice::<UpstreamResponse>(&body_bytes) {
            let input = parsed.usage.as_ref().map(|u| u.prompt_tokens).unwrap_or(0);
            let output = parsed
                .usage
                .as_ref()
                .map(|u| u.completion_tokens)
                .unwrap_or(0);
            record_success(state, agent_id, &facts.model, input, output, bundle, now);
        } else {
            // No usage object — forward anyway; skip accounting.
            LLM_REQUESTS
                .with_label_values(&[agent_id, &facts.model, "forwarded"])
                .inc();
        }
    } else {
        LLM_REQUESTS
            .with_label_values(&[agent_id, &facts.model, "upstream_error"])
            .inc();
    }

    let _ = bundle; // suppress unused when metrics features off
    Response::builder()
        .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY))
        .header(header::CONTENT_TYPE, ctype_str)
        .body(Body::from(body_bytes))
        .unwrap()
}

fn record_success(
    state: &AppState,
    agent_id: &str,
    model: &str,
    input: u64,
    output: u64,
    _bundle: &CapabilityBundle,
    now: chrono::DateTime<chrono::Utc>,
) {
    LLM_REQUESTS
        .with_label_values(&[agent_id, model, "forwarded"])
        .inc();
    LLM_TOKENS
        .with_label_values(&[agent_id, model, "input"])
        .inc_by(input);
    LLM_TOKENS
        .with_label_values(&[agent_id, model, "output"])
        .inc_by(output);

    if let Some(p) = price_for(model) {
        let cost = p.input_cost(input) + p.output_cost(output);
        LLM_SPEND
            .with_label_values(&[agent_id, model])
            .inc_by(cost);
        let new_total = state.budget.add(agent_id, now, cost);
        // Track in cents so the int gauge is lossless enough for dashboards.
        LLM_BUDGET_SPENT
            .with_label_values(&[agent_id])
            .set((new_total * 100.0).round() as i64);
    }
}

fn deny(agent_id: &str, reason: &RejectReason) -> Response {
    LLM_REJECTIONS
        .with_label_values(&[agent_id, reason.metric_label()])
        .inc();
    // OpenAI error envelope — Python + TS SDKs display the message
    // field directly.
    openai_error(
        StatusCode::from_u16(reason.http_status()).unwrap_or(StatusCode::FORBIDDEN),
        &reason.user_message(),
    )
}

fn openai_error(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "agents_enforcer_error",
            "code": null,
        }
    });
    (status, Json(body)).into_response()
}

// The two shapes the proxy parses off the upstream response.
#[derive(Deserialize, Serialize)]
struct UpstreamResponse {
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Deserialize, Serialize)]
struct Usage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_facts_pulls_model_and_tools() {
        let body = serde_json::json!({
            "model": "gpt-4o",
            "tools": [
                { "type": "function", "function": { "name": "search" } },
                { "type": "function", "function": { "name": "read_file" } }
            ],
            "max_tokens": 256
        });
        let f = extract_facts(&body).unwrap();
        assert_eq!(f.model, "gpt-4o");
        assert_eq!(f.tool_names, vec!["search", "read_file"]);
        assert_eq!(f.requested_max_output, Some(256));
        assert!(f.estimated_input_tokens > 0);
    }

    #[test]
    fn extract_facts_rejects_missing_model() {
        let body = serde_json::json!({});
        let err = extract_facts(&body).unwrap_err();
        assert!(err.contains("model"));
    }

    #[test]
    fn openai_error_has_expected_envelope() {
        let r = openai_error(StatusCode::FORBIDDEN, "nope");
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
}
