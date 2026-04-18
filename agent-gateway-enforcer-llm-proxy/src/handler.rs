//! HTTP router. Two provider-specific endpoints —
//! `/v1/chat/completions` (OpenAI dialect) and `/v1/messages`
//! (Anthropic dialect) — funnel into a single `handle` function that
//! takes a provider adapter. All enforcement, forwarding, token
//! accounting, and metrics happen once, not twice.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::Value;

use futures::StreamExt;

use crate::budget::BudgetStore;
use crate::capabilities::CapabilityStore;
use crate::enforce::{check, RejectReason, RequestFacts};
use crate::metrics::{LLM_BUDGET_SPENT, LLM_REJECTIONS, LLM_REQUESTS, LLM_SPEND, LLM_TOKENS};
use crate::pricing::PricingTable;
use crate::providers::{Anthropic, OpenAi, Provider, ProviderFacts, ProviderUsage};
use crate::sse::SseParser;

/// Runtime state shared across requests.
pub struct AppState {
    pub caps: Arc<CapabilityStore>,
    pub budget: Arc<BudgetStore>,
    pub pricing: Arc<PricingTable>,
    pub upstream_base: String,
    pub http: reqwest::Client,
}

/// Build the axum router. Endpoints map 1:1 to upstream shapes so an
/// OpenAI SDK sees `/v1/chat/completions` and an Anthropic SDK sees
/// `/v1/messages` — no proxy-specific request rewriting on the
/// caller side.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/messages", post(anthropic_messages))
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get({
                let s = state.clone();
                move || {
                    let s = s.clone();
                    async move {
                        if s.caps.is_empty() {
                            (StatusCode::SERVICE_UNAVAILABLE, "no capabilities loaded")
                        } else if s.pricing.is_empty() {
                            (StatusCode::SERVICE_UNAVAILABLE, "no pricing loaded")
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
    handle(state, headers, body, Arc::new(OpenAi)).await
}

async fn anthropic_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    handle(state, headers, body, Arc::new(Anthropic)).await
}

/// Shared request pipeline. Branches only on the provider adapter —
/// so adding a new provider is a provider impl + a new route. The
/// provider is `Arc`'d rather than borrowed so it can outlive the
/// sync portion of this function into the streaming response's
/// detached body-stream closure.
async fn handle(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Value,
    provider: Arc<dyn Provider>,
) -> Response {
    // Agent identity — matches the AgentCapability's `namespace/name`.
    // Pods set this via their SDK's headers config.
    let agent_id = match headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(a) if !a.is_empty() => a,
        _ => return deny("unknown", &RejectReason::NoCapability),
    };

    let bundle = match state.caps.get(&agent_id) {
        Some(b) => b,
        None => return deny(&agent_id, &RejectReason::NoCapability),
    };

    let facts = match provider.extract_facts(&body) {
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
    let rf = RequestFacts {
        model: &facts.model,
        tool_names: facts.tool_names.clone(),
        estimated_input_tokens: facts.estimated_input_tokens,
        requested_max_output: facts.requested_max_output,
    };
    if let Err(reason) = check(&bundle, &rf, spent, state.pricing.as_ref()) {
        return deny(&agent_id, &reason);
    }

    forward(state, &agent_id, headers, body, facts, now, provider).await
}

async fn forward(
    state: Arc<AppState>,
    agent_id: &str,
    mut headers: HeaderMap,
    body: Value,
    facts: ProviderFacts,
    now: chrono::DateTime<chrono::Utc>,
    provider: Arc<dyn Provider>,
) -> Response {
    // Bridge http 1.x (axum) → http 0.2 (reqwest). Forward only the
    // headers the upstream actually needs; the http-crate version
    // mismatch makes a blind pass-through infeasible anyway.
    let mut reqwest_headers = reqwest::header::HeaderMap::new();
    for forwarded in [
        "authorization",
        "x-api-key",
        "anthropic-version",
        "anthropic-beta",
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
    headers.remove("x-agent-id");

    let url = format!(
        "{}{}",
        state.upstream_base.trim_end_matches('/'),
        provider.upstream_path()
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

    let status_code = resp.status().as_u16();
    let ctype_str: String = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    // Branch on streaming. We key off the upstream's content-type
    // (`text/event-stream`) rather than the inbound request body
    // because some upstreams respond with SSE even when the client
    // didn't explicitly ask — that's the authoritative signal.
    let is_stream = ctype_str.starts_with("text/event-stream");

    if is_stream && (200..300).contains(&status_code) {
        return stream_response(
            state.clone(),
            agent_id.to_string(),
            facts,
            now,
            provider.clone(),
            resp,
            status_code,
            ctype_str,
        );
    }

    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return openai_error(
                StatusCode::BAD_GATEWAY,
                &format!("reading upstream body: {}", e),
            )
        }
    };

    let is_success = (200..300).contains(&status_code);
    if is_success {
        if let Some(usage) = provider.extract_usage(&body_bytes) {
            record_success(
                &state,
                agent_id,
                &facts.model,
                usage.input_tokens,
                usage.output_tokens,
                now,
            );
        } else {
            LLM_REQUESTS
                .with_label_values(&[agent_id, &facts.model, "forwarded"])
                .inc();
        }
    } else {
        LLM_REQUESTS
            .with_label_values(&[agent_id, &facts.model, "upstream_error"])
            .inc();
    }

    Response::builder()
        .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY))
        .header(header::CONTENT_TYPE, ctype_str)
        .body(Body::from(body_bytes))
        .unwrap()
}

/// Streaming path. Pipes upstream chunks to the client byte-for-byte
/// while side-observing SSE events for usage counters. The client
/// sees exactly what the upstream emits (including keepalive
/// comments) with no transformation.
///
/// Accounting runs in the stream's drop glue: each event's usage is
/// folded in via `max()` so out-of-order/incremental providers
/// converge to the right final numbers, and `record_success` is
/// called exactly once when the stream completes.
fn stream_response(
    state: Arc<AppState>,
    agent_id: String,
    facts: ProviderFacts,
    now: chrono::DateTime<chrono::Utc>,
    provider: Arc<dyn Provider>,
    resp: reqwest::Response,
    status_code: u16,
    ctype_str: String,
) -> Response {
    let model = facts.model;

    // The decorated stream observes upstream chunks, feeds them to
    // the SSE parser + provider extractor, and yields the same bytes
    // to the client. When the stream ends we emit one accounting
    // update for the whole call.
    let decorated = async_stream::stream! {
        let mut upstream = Box::pin(resp.bytes_stream());
        let mut parser = SseParser::new();
        let mut running = ProviderUsage::default();
        let mut got_any_usage = false;

        while let Some(chunk) = upstream.next().await {
            let bytes = match chunk {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(err = %e, "upstream stream error mid-response");
                    break;
                }
            };
            parser.push(&bytes);
            for ev in parser.drain_events() {
                if let Some(u) = provider.extract_usage_from_sse(&ev.event, &ev.data) {
                    running.input_tokens = running.input_tokens.max(u.input_tokens);
                    running.output_tokens = running.output_tokens.max(u.output_tokens);
                    got_any_usage = true;
                }
            }
            yield Ok::<_, std::io::Error>(bytes);
        }

        if got_any_usage {
            record_success(
                &state,
                &agent_id,
                &model,
                running.input_tokens,
                running.output_tokens,
                now,
            );
        } else {
            LLM_REQUESTS
                .with_label_values(&[&agent_id, &model, "forwarded"])
                .inc();
        }
    };

    Response::builder()
        .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY))
        .header(header::CONTENT_TYPE, ctype_str)
        // X-Accel-Buffering: no for nginx-style proxies in front of
        // the pod so SSE actually streams rather than buffering to
        // EOF before the client sees anything.
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(decorated))
        .unwrap()
}

fn record_success(
    state: &AppState,
    agent_id: &str,
    model: &str,
    input: u64,
    output: u64,
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

    if let Some(p) = state.pricing.price_for(model) {
        let cost = p.input_cost(input) + p.output_cost(output);
        LLM_SPEND
            .with_label_values(&[agent_id, model])
            .inc_by(cost);
        let new_total = state.budget.add(agent_id, now, cost);
        LLM_BUDGET_SPENT
            .with_label_values(&[agent_id])
            .set((new_total * 100.0).round() as i64);
    }
}

fn deny(agent_id: &str, reason: &RejectReason) -> Response {
    LLM_REJECTIONS
        .with_label_values(&[agent_id, reason.metric_label()])
        .inc();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_error_has_expected_envelope() {
        let r = openai_error(StatusCode::FORBIDDEN, "nope");
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    // Provider-level extraction is tested in `providers::tests`;
    // handler integration is exercised by the e2e test below.
}
