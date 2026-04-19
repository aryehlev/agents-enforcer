//! End-to-end integration tests. A real tokio server answers as the
//! fake upstream, the proxy forwards to it, and assertions run on
//! actual HTTP status + response bodies. No mocks — the same code
//! paths hit in production run here.
//!
//! Scope: validates routing, authorization flow, denial reasons, and
//! both provider dialects. Upstream streaming and network failures
//! are covered by unit tests against the provider trait.

use std::collections::HashMap;
use std::sync::Arc;

use agent_gateway_enforcer_controller::CapabilityBundle;
use agent_gateway_enforcer_llm_proxy::{
    budget::BudgetStore,
    capabilities::CapabilityStore,
    handler::{router, AppState},
    pricing::PricingTable,
    reporter::EventReporter,
};
use axum::routing::post;
use axum::Router;
use reqwest::StatusCode;

const PRICING: &str = r#"
models:
  - { name: gpt-4o, inputPerMillion: 2.5, outputPerMillion: 10.0 }
  - { name: claude-sonnet-4.6, inputPerMillion: 3.0, outputPerMillion: 15.0 }
"#;

/// Spin up a fake upstream. OpenAI handler returns a fixed
/// completion + usage; Anthropic handler returns an Anthropic-shaped
/// one. Returns `(base_url, shutdown_tx)`.
async fn spawn_upstream() -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(|| async {
                axum::Json(serde_json::json!({
                    "id": "chatcmpl-fake",
                    "object": "chat.completion",
                    "model": "gpt-4o",
                    "choices": [{ "message": { "role": "assistant", "content": "ok" }, "finish_reason": "stop" }],
                    "usage": { "prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150 }
                }))
            }),
        )
        .route(
            "/v1/messages",
            post(|| async {
                axum::Json(serde_json::json!({
                    "id": "msg_fake",
                    "type": "message",
                    "model": "claude-sonnet-4.6",
                    "content": [{ "type": "text", "text": "ok" }],
                    "usage": { "input_tokens": 80, "output_tokens": 40 }
                }))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .ok();
    });
    (format!("http://{}", addr), tx)
}

async fn spawn_proxy_with(
    upstream: &str,
    caps: HashMap<String, CapabilityBundle>,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    let caps_store = Arc::new(CapabilityStore::new());
    caps_store.replace(caps);
    let pricing = Arc::new(PricingTable::from_yaml_str(PRICING).unwrap());
    let state = Arc::new(AppState {
        caps: caps_store,
        budget: Arc::new(BudgetStore::new()),
        pricing,
        upstream_base: upstream.to_string(),
        http: reqwest::Client::new(),
        reporter: Arc::new(EventReporter::disabled()),
    });
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .ok();
    });
    (format!("http://{}", addr), tx)
}

fn cap_bundle(models: &[&str], tools: &[&str], spend: f64) -> CapabilityBundle {
    CapabilityBundle {
        hash: "test".into(),
        allowed_models: models.iter().map(|s| s.to_ascii_lowercase()).collect(),
        allowed_tools: tools.iter().map(|s| s.to_string()).collect(),
        max_daily_spend_usd: spend,
        max_output_tokens: None,
    }
}

#[tokio::test]
async fn openai_happy_path_forwards_and_accounts() {
    let (upstream, up_shutdown) = spawn_upstream().await;
    let mut caps = HashMap::new();
    caps.insert("prod/agent-1".into(), cap_bundle(&["gpt-4o"], &[], 100.0));
    let (proxy, proxy_shutdown) = spawn_proxy_with(&upstream, caps).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy))
        .header("x-agent-id", "prod/agent-1")
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["usage"]["prompt_tokens"], 100);

    let _ = proxy_shutdown.send(());
    let _ = up_shutdown.send(());
}

#[tokio::test]
async fn missing_agent_id_rejected_as_no_capability() {
    let (upstream, up_shutdown) = spawn_upstream().await;
    let (proxy, proxy_shutdown) = spawn_proxy_with(&upstream, HashMap::new()).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy))
        .json(&serde_json::json!({ "model": "gpt-4o", "messages": [] }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "agents_enforcer_error");

    let _ = proxy_shutdown.send(());
    let _ = up_shutdown.send(());
}

#[tokio::test]
async fn wrong_model_is_denied_before_upstream() {
    let (upstream, up_shutdown) = spawn_upstream().await;
    let mut caps = HashMap::new();
    // Agent is only allowed Sonnet; they ask for gpt-4o.
    caps.insert(
        "prod/agent-1".into(),
        cap_bundle(&["claude-sonnet-4.6"], &[], 100.0),
    );
    let (proxy, proxy_shutdown) = spawn_proxy_with(&upstream, caps).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy))
        .header("x-agent-id", "prod/agent-1")
        .json(&serde_json::json!({ "model": "gpt-4o", "messages": [] }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let _ = proxy_shutdown.send(());
    let _ = up_shutdown.send(());
}

#[tokio::test]
async fn anthropic_happy_path_via_messages_endpoint() {
    let (upstream, up_shutdown) = spawn_upstream().await;
    let mut caps = HashMap::new();
    caps.insert(
        "prod/agent-1".into(),
        cap_bundle(&["claude-sonnet-4.6"], &[], 100.0),
    );
    let (proxy, proxy_shutdown) = spawn_proxy_with(&upstream, caps).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", proxy))
        .header("x-agent-id", "prod/agent-1")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4.6",
            "max_tokens": 256,
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    // Round-trips the Anthropic usage shape exactly.
    assert_eq!(body["usage"]["input_tokens"], 80);
    assert_eq!(body["usage"]["output_tokens"], 40);

    let _ = proxy_shutdown.send(());
    let _ = up_shutdown.send(());
}

#[tokio::test]
async fn unknown_model_when_cost_enforcement_on_returns_400() {
    let (upstream, up_shutdown) = spawn_upstream().await;
    let mut caps = HashMap::new();
    // Allowed but not in pricing table.
    caps.insert(
        "prod/agent-1".into(),
        cap_bundle(&["made-up-model"], &[], 5.0),
    );
    let (proxy, proxy_shutdown) = spawn_proxy_with(&upstream, caps).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy))
        .header("x-agent-id", "prod/agent-1")
        .json(&serde_json::json!({ "model": "made-up-model", "messages": [] }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let _ = proxy_shutdown.send(());
    let _ = up_shutdown.send(());
}

#[tokio::test]
async fn readyz_reflects_pricing_loaded() {
    // No capabilities, no pricing → not ready.
    let caps = Arc::new(CapabilityStore::new());
    let pricing = Arc::new(PricingTable::new());
    let state = Arc::new(AppState {
        caps,
        budget: Arc::new(BudgetStore::new()),
        pricing,
        upstream_base: "http://127.0.0.1:1".into(),
        http: reqwest::Client::new(),
        reporter: Arc::new(EventReporter::disabled()),
    });
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .ok();
    });
    let resp = reqwest::get(format!("http://{}/readyz", addr))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let _ = tx.send(());
}
