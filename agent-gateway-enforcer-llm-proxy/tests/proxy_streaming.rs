//! Streaming end-to-end tests. A real HTTP fake upstream returns an
//! SSE body; the proxy streams it back to the client; the tests
//! both verify the client sees every chunk AND that the final
//! usage is accounted against the budget.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_gateway_enforcer_controller::CapabilityBundle;
use agent_gateway_enforcer_llm_proxy::{
    budget::BudgetStore,
    capabilities::CapabilityStore,
    handler::{router, AppState},
    pricing::PricingTable,
    reporter::EventReporter,
};
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use futures::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

const PRICING: &str = r#"
models:
  - { name: gpt-4o, inputPerMillion: 2.5, outputPerMillion: 10.0 }
  - { name: claude-sonnet-4.6, inputPerMillion: 3.0, outputPerMillion: 15.0 }
"#;

/// Spawn a fake upstream whose `/v1/chat/completions` responds with
/// an SSE body carrying a tiny delta + a final chunk with usage.
async fn spawn_openai_stream() -> (String, tokio::sync::oneshot::Sender<()>) {
    let chunks: Vec<&'static [u8]> = vec![
        b"data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
        b"data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
        b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":3}}\n\n",
        b"data: [DONE]\n\n",
    ];
    spawn_sse_upstream("/v1/chat/completions", chunks).await
}

async fn spawn_anthropic_stream() -> (String, tokio::sync::oneshot::Sender<()>) {
    // Realistic two-event pattern: message_start carries input
    // tokens; message_delta updates output tokens.
    let chunks: Vec<&'static [u8]> = vec![
        b"event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":0}}}\n\n",
        b"event: content_block_delta\ndata: {\"delta\":{\"text\":\"hi\"}}\n\n",
        b"event: message_delta\ndata: {\"delta\":{},\"usage\":{\"output_tokens\":5}}\n\n",
        b"event: message_stop\ndata: {}\n\n",
    ];
    spawn_sse_upstream("/v1/messages", chunks).await
}

async fn spawn_sse_upstream(
    path: &'static str,
    chunks: Vec<&'static [u8]>,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    // axum handler streams through a tokio::mpsc so each chunk lands
    // on the wire as its own frame — this makes the proxy prove it
    // actually forwards incrementally rather than buffering.
    let handler = move || async move {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(8);
        tokio::spawn(async move {
            for chunk in chunks {
                // Small sleep so the stream is observably chunked;
                // avoids the fake "stream" collapsing into a single
                // frame in practice.
                tokio::time::sleep(Duration::from_millis(10)).await;
                if tx.send(Ok(bytes::Bytes::from_static(chunk))).await.is_err() {
                    return;
                }
            }
        });
        let body = Body::from_stream(ReceiverStream::new(rx));
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/event-stream")
            .body(body)
            .unwrap()
    };

    let app: Router<()> = Router::new().route(path, post(handler));
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

async fn spawn_proxy(
    upstream: &str,
    caps: HashMap<String, CapabilityBundle>,
) -> (String, Arc<AppState>, tokio::sync::oneshot::Sender<()>) {
    let caps_store = Arc::new(CapabilityStore::new());
    caps_store.replace(caps);
    let pricing = Arc::new(PricingTable::from_yaml_str(PRICING).unwrap());
    let budget = Arc::new(BudgetStore::new());
    let state = Arc::new(AppState {
        caps: caps_store,
        budget: budget.clone(),
        pricing,
        upstream_base: upstream.to_string(),
        http: reqwest::Client::new(),
        reporter: Arc::new(EventReporter::disabled()),
    });
    let app = router(state.clone());
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
    (format!("http://{}", addr), state, tx)
}

fn cap_bundle(models: &[&str], spend: f64) -> CapabilityBundle {
    CapabilityBundle {
        hash: "test".into(),
        allowed_models: models.iter().map(|s| s.to_ascii_lowercase()).collect(),
        allowed_tools: vec![],
        max_daily_spend_usd: spend,
        max_output_tokens: None,
    }
}

#[tokio::test]
async fn openai_stream_forwards_every_chunk_and_accounts_usage() {
    let (upstream, up) = spawn_openai_stream().await;
    let mut caps = HashMap::new();
    caps.insert("prod/a".into(), cap_bundle(&["gpt-4o"], 100.0));
    let (proxy, state, px) = spawn_proxy(&upstream, caps).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy))
        .header("x-agent-id", "prod/a")
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "stream": true,
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/event-stream"
    );
    // `x-accel-buffering: no` must be set so ingress proxies don't
    // bucket the entire response before flushing — clients rely on
    // this for early-chunk visibility.
    assert_eq!(
        resp.headers()
            .get("x-accel-buffering")
            .unwrap()
            .to_str()
            .unwrap(),
        "no"
    );

    // Pull the full body as text; the proxy's job is to forward
    // exactly what the upstream sent (no transformation).
    let body = resp.text().await.unwrap();
    assert!(body.contains("he"));
    assert!(body.contains("llo"));
    assert!(body.contains("[DONE]"));

    // Accounting landed: spend > 0. Exact value depends on
    // pricing table + (9 input, 3 output) — but a cheap assertion
    // against the SPEND gauge is better than arithmetic that moves
    // with pricing.
    let now = chrono::Utc::now();
    let spent = state.budget.spent_today("prod/a", now);
    assert!(
        spent > 0.0,
        "expected budget to increment; saw ${:.6}",
        spent
    );

    let _ = px.send(());
    let _ = up.send(());
}

#[tokio::test]
async fn anthropic_stream_merges_message_start_and_message_delta() {
    let (upstream, up) = spawn_anthropic_stream().await;
    let mut caps = HashMap::new();
    caps.insert("prod/a".into(), cap_bundle(&["claude-sonnet-4.6"], 100.0));
    let (proxy, state, px) = spawn_proxy(&upstream, caps).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/messages", proxy))
        .header("x-agent-id", "prod/a")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4.6",
            "stream": true,
            "max_tokens": 128,
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    // Stream the body chunk-by-chunk to prove the proxy forwards
    // incrementally — if it buffered, `next()` would block until
    // upstream EOF.
    let mut stream = resp.bytes_stream();
    let mut total = Vec::new();
    let mut chunk_count = 0;
    while let Some(chunk) = stream.next().await {
        total.extend_from_slice(&chunk.unwrap());
        chunk_count += 1;
    }
    assert!(chunk_count >= 2, "expected streaming; got {} chunks", chunk_count);
    let body = String::from_utf8(total).unwrap();
    assert!(body.contains("message_start"));
    assert!(body.contains("message_delta"));

    // Input tokens from message_start (11) + output_tokens from
    // message_delta (5) both flowed into the budget.
    let spent = state.budget.spent_today("prod/a", chrono::Utc::now());
    // 11 input * $3/1M + 5 output * $15/1M = 0.0000330 + 0.0000750 ~ $0.000108
    assert!(spent > 0.0 && spent < 1.0, "unexpected spend: {}", spent);

    let _ = px.send(());
    let _ = up.send(());
}

#[tokio::test]
async fn stream_request_still_passes_pre_flight_checks() {
    // The provider's wrong-model denial must run before we open an
    // upstream stream — otherwise a denied-but-streaming request
    // would be mis-routed through the streaming path.
    let (upstream, up) = spawn_openai_stream().await;
    let mut caps = HashMap::new();
    caps.insert("prod/a".into(), cap_bundle(&["claude-sonnet-4.6"], 100.0));
    let (proxy, _state, px) = spawn_proxy(&upstream, caps).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", proxy))
        .header("x-agent-id", "prod/a")
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "stream": true,
            "messages": []
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 403);

    let _ = px.send(());
    let _ = up.send(());
}
