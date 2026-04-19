//! Decision-event reporter.
//!
//! Subscribes to a backend-provided [`DecisionEventSource`], batches
//! events, and POSTs them to the controller's `/events/batch`
//! endpoint. The batching parameters mirror the llm-proxy's reporter
//! on purpose — both write to the same aggregator contract.
//!
//! Only compiled under the `server` feature because the
//! [`DecisionEventSource`] trait lives in the eBPF backend crate,
//! which this feature already brings in.
//!
//! Design
//! - Bounded broadcast subscription + bounded internal mpsc. A slow
//!   controller can drop our events — that's strictly better than
//!   pausing the ringbuf consumer and letting kernel buffers overflow.
//! - Flush on either size (`batch_size`) or time (`flush_interval`).
//! - Disabled mode (no URL configured) is a valid deployment — the
//!   eBPF path still enforces, the controller just doesn't see
//!   per-decision events. Kept here as a constructor so the binary
//!   can wire it up uniformly.

#![cfg(feature = "server")]

use std::time::Duration;

use agent_gateway_enforcer_backend_ebpf_linux::decision_events::{
    DecisionEventSource, DecisionEventWire,
};

/// Handle returned by `spawn`. Drop to stop the reporter.
pub struct ReporterHandle {
    _shutdown: tokio::sync::oneshot::Sender<()>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ReporterHandle {
    /// Wait for the reporter to finish draining in-flight events.
    /// Useful in tests; production shutdown just drops the handle.
    pub async fn join(mut self) {
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// Tuning knobs for the reporter's batching behavior. The defaults
/// match the llm-proxy reporter (see
/// `agent-gateway-enforcer-llm-proxy::reporter`) so operators don't
/// have two different batching latencies to reason about.
#[derive(Debug, Clone)]
pub struct ReporterConfig {
    /// Controller URL, ending in `/events/batch`.
    pub url: String,
    /// Maximum events per POST. 64 keeps bodies under 32KB at
    /// realistic event sizes.
    pub batch_size: usize,
    /// Flush even when the batch isn't full.
    pub flush_interval: Duration,
    /// Internal mpsc depth. When the source is faster than our HTTP
    /// POST, events past this point are dropped (and counted).
    pub queue_depth: usize,
}

impl Default for ReporterConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            batch_size: 64,
            flush_interval: Duration::from_secs(5),
            queue_depth: 1024,
        }
    }
}

/// Start the reporter. Returns a handle; dropping it stops the task.
///
/// `src` is any decision-event source — tests pass an in-memory
/// double; the node-agent binary passes the eBPF backend.
pub fn spawn<S>(
    src: &S,
    http: reqwest::Client,
    cfg: ReporterConfig,
) -> ReporterHandle
where
    S: DecisionEventSource,
{
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<DecisionEventWire>(cfg.queue_depth);

    // Bridge broadcast → mpsc. A broadcast::Receiver lagging is a
    // signal that the reporter is falling behind; we surface it via
    // tracing and drop rather than stall the producer.
    let mut rx = src.subscribe();
    let ev_tx_bridge = ev_tx.clone();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if ev_tx_bridge.try_send(ev).is_err() {
                        // Reporter queue full — drop.
                        tracing::debug!("reporter queue full; dropping event");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("reporter lagged; dropped {} events", n);
                }
            }
        }
    });

    let task = tokio::spawn(async move {
        let mut pending: Vec<DecisionEventWire> = Vec::with_capacity(cfg.batch_size);
        let mut tick = tokio::time::interval(cfg.flush_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // First tick is immediate; skip so we don't flush an empty
        // batch on startup.
        tick.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    // Best-effort final flush.
                    if !pending.is_empty() {
                        flush(&http, &cfg.url, std::mem::take(&mut pending)).await;
                    }
                    return;
                }
                maybe_ev = ev_rx.recv() => {
                    match maybe_ev {
                        Some(ev) => {
                            pending.push(ev);
                            if pending.len() >= cfg.batch_size {
                                let batch = std::mem::take(&mut pending);
                                flush(&http, &cfg.url, batch).await;
                            }
                        }
                        None => {
                            // Sender dropped; drain and exit.
                            if !pending.is_empty() {
                                flush(&http, &cfg.url, std::mem::take(&mut pending)).await;
                            }
                            return;
                        }
                    }
                }
                _ = tick.tick() => {
                    if !pending.is_empty() {
                        let batch = std::mem::take(&mut pending);
                        flush(&http, &cfg.url, batch).await;
                    }
                }
            }
        }
    });

    ReporterHandle {
        _shutdown: shutdown_tx,
        task: Some(task),
    }
}

/// POST a batch. On failure we log and drop — the aggregator is a
/// best-effort audit trail, not a guaranteed delivery channel. If
/// reliable delivery becomes a requirement, the right answer is a
/// sidecar queue (e.g. NATS), not an in-process retry loop.
async fn flush(http: &reqwest::Client, url: &str, batch: Vec<DecisionEventWire>) {
    let n = batch.len();
    match http.post(url).json(&batch).send().await {
        Ok(r) if r.status().is_success() => {
            tracing::debug!(count = n, "reporter flushed batch");
        }
        Ok(r) => {
            tracing::warn!(count = n, status = %r.status(), "reporter: non-2xx");
        }
        Err(e) => {
            tracing::warn!(count = n, err = %e, "reporter: POST failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_gateway_enforcer_backend_ebpf_linux::decision_events::ViolationKind;
    use tokio::sync::broadcast;

    struct FakeSource {
        tx: broadcast::Sender<DecisionEventWire>,
    }

    impl DecisionEventSource for FakeSource {
        fn subscribe(&self) -> broadcast::Receiver<DecisionEventWire> {
            self.tx.subscribe()
        }
    }

    fn ev(detail: &str) -> DecisionEventWire {
        DecisionEventWire::now(
            "prod",
            "agent-0",
            "uid-A",
            "pol",
            ViolationKind::EgressBlocked,
            detail,
        )
    }

    #[tokio::test]
    async fn batch_posts_json_array_in_wire_shape() {
        // Spin up a minimal recorder HTTP server. We'd normally mock
        // this with `mockito` but the extra dep isn't worth it — a
        // seven-line axum listener does the same thing.
        use axum::{routing::post, Router};
        use std::sync::{Arc, Mutex};

        let received: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let received_c = received.clone();
        let app = Router::new().route(
            "/events/batch",
            post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let received = received_c.clone();
                async move {
                    received.lock().unwrap().push(body);
                    axum::http::StatusCode::ACCEPTED
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stop_rx.await;
                })
                .await
                .ok();
        });

        let (tx, _) = broadcast::channel::<DecisionEventWire>(64);
        let src = FakeSource { tx: tx.clone() };

        let cfg = ReporterConfig {
            url: format!("http://{}/events/batch", addr),
            batch_size: 3,
            flush_interval: Duration::from_secs(60),
            queue_depth: 64,
        };
        let handle = spawn(&src, reqwest::Client::new(), cfg);

        // Three events → one flush (hit batch_size).
        tx.send(ev("1.1.1.1:443")).unwrap();
        tx.send(ev("2.2.2.2:443")).unwrap();
        tx.send(ev("3.3.3.3:443")).unwrap();

        // Poll the recorder until we see the batch.
        for _ in 0..50 {
            if !received.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let received = received.lock().unwrap().clone();
        assert_eq!(received.len(), 1, "expected one batch POST");
        let arr = received[0].as_array().expect("JSON array");
        assert_eq!(arr.len(), 3);
        // Sanity-pin the wire shape: field names must match the
        // controller's EventWire (camelCase).
        assert_eq!(arr[0]["kind"], "EgressBlocked");
        assert!(arr[0]["podUid"].as_str().unwrap().starts_with("uid-"));

        let _ = stop_tx.send(());
        drop(handle);
    }

    #[tokio::test]
    async fn lagged_subscriber_is_logged_not_fatal() {
        // Broadcast with capacity 2 + 10 events queued before subscribe
        // forces the Lagged path. Reporter must keep going.
        let (tx, _rx_keepalive) = broadcast::channel::<DecisionEventWire>(2);
        let src = FakeSource { tx: tx.clone() };

        let cfg = ReporterConfig {
            url: "http://127.0.0.1:1".into(), // Unreachable on purpose.
            batch_size: 1024,
            flush_interval: Duration::from_secs(60),
            queue_depth: 4,
        };
        let handle = spawn(&src, reqwest::Client::new(), cfg);

        for i in 0..10 {
            let _ = tx.send(ev(&format!("x-{}", i)));
        }
        // Task must stay alive regardless of the lag.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(handle);
    }
}
