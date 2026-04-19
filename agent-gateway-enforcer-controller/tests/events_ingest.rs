//! End-to-end test for the event ingest HTTP endpoint paired with
//! the aggregator. Spins up the real axum router + an Aggregator
//! (without the flush-to-kube half, which requires a cluster), POSTs
//! events, and verifies the aggregator would emit the right CR shape.

use std::sync::Arc;
use std::time::Duration;

use agent_gateway_enforcer_controller::aggregator::Aggregator;
use agent_gateway_enforcer_controller::aggregator_loop::AggregatorHandle;
use agent_gateway_enforcer_controller::events_server::router;
use parking_lot::Mutex;

/// Stand up the ingest server backed by a bare Aggregator (no kube
/// flush loop). Returns the URL and a shutdown channel. Also hands
/// back the shared aggregator so tests can flush + assert.
async fn spawn_ingest() -> (
    String,
    Arc<Mutex<Aggregator>>,
    tokio::sync::oneshot::Sender<()>,
) {
    let agg = Arc::new(Mutex::new(Aggregator::new()));
    let handle = AggregatorHandle::for_test(agg.clone());

    let app = router(handle);
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
    (format!("http://{}", addr), agg, tx)
}

#[tokio::test]
async fn single_event_posts_and_buckets() {
    let (base, agg, stop) = spawn_ingest().await;

    let resp = reqwest::Client::new()
        .post(format!("{}/events", base))
        .json(&serde_json::json!({
            "namespace": "prod",
            "podName": "agent-0",
            "podUid": "uid-A",
            "policyName": "openai-only",
            "kind": "EgressBlocked",
            "detail": "1.2.3.4:443"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);

    assert_eq!(agg.lock().len(), 1);
    let flushed = agg.lock().flush();
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].spec.pod_name, "agent-0");
    assert_eq!(flushed[0].spec.count, 1);
    assert!(flushed[0].name.starts_with("egress-"));

    let _ = stop.send(());
}

#[tokio::test]
async fn batch_ingest_merges_identical_events() {
    let (base, agg, stop) = spawn_ingest().await;

    let payload: Vec<serde_json::Value> = (0..5)
        .map(|_| {
            serde_json::json!({
                "namespace": "prod",
                "podName": "agent-0",
                "podUid": "uid-A",
                "policyName": "p",
                "kind": "EgressBlocked",
                "detail": "1.2.3.4:443",
            })
        })
        .collect();

    let resp = reqwest::Client::new()
        .post(format!("{}/events/batch", base))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);

    let flushed = agg.lock().flush();
    assert_eq!(flushed.len(), 1, "5 identical events collapse to 1 bucket");
    assert_eq!(flushed[0].spec.count, 5);

    let _ = stop.send(());
}

#[tokio::test]
async fn batch_with_one_malformed_entry_rejects_whole_batch() {
    // Half-submission would leave the aggregator inconsistent with
    // the caller's view. Entire-batch failure is the safer contract.
    let (base, agg, stop) = spawn_ingest().await;
    let payload = serde_json::json!([
        {
            "namespace": "prod",
            "podName": "agent-0",
            "podUid": "uid-A",
            "policyName": "p",
            "kind": "EgressBlocked",
            "detail": "ok.example:443"
        },
        {
            "namespace": "prod",
            "podName": "agent-0",
            "podUid": "uid-A",
            "policyName": "p",
            "kind": "EgressBlocked",
            "detail": "broken.example:443",
            "timestamp": "not-a-timestamp"
        }
    ]);

    let resp = reqwest::Client::new()
        .post(format!("{}/events/batch", base))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    assert_eq!(agg.lock().len(), 0, "partial batches must not land");
    let _ = stop.send(());
}

#[tokio::test]
async fn malformed_timestamp_on_single_ingest_is_400() {
    let (base, _agg, stop) = spawn_ingest().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/events", base))
        .json(&serde_json::json!({
            "namespace": "prod",
            "podName": "p",
            "podUid": "u",
            "policyName": "p",
            "kind": "EgressBlocked",
            "detail": "x",
            "timestamp": "not-a-timestamp"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let _ = stop.send(());
}

#[tokio::test]
async fn different_pods_split_buckets_through_the_http_path() {
    let (base, agg, stop) = spawn_ingest().await;
    let client = reqwest::Client::new();
    for uid in ["A", "B", "C"] {
        let _ = client
            .post(format!("{}/events", base))
            .json(&serde_json::json!({
                "namespace": "prod",
                "podName": format!("agent-{}", uid),
                "podUid": format!("uid-{}", uid),
                "policyName": "p",
                "kind": "EgressBlocked",
                "detail": "1.2.3.4:443"
            }))
            .send()
            .await;
    }
    // Small settle delay — axum's response returns before the
    // handler finishes writing to the shared mutex in some runtimes.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(agg.lock().len(), 3);
    let _ = stop.send(());
}
