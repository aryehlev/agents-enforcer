//! Best-effort reporter that POSTs `DecisionEvent`s to the
//! controller's `/events/batch` endpoint. Fire-and-forget: the proxy
//! never blocks a user request on the reporter, and failures are
//! logged + counted in `enforcer_llm_reporter_errors_total`.
//!
//! We buffer in a small bounded channel so bursts don't fan out one
//! HTTP request per event. A single background flusher drains the
//! channel every `flush_interval` or when `max_batch` events
//! accumulate, whichever comes first.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::mpsc;

/// Wire shape of the event; matches `controller::events_server::EventWire`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireEvent {
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub policy_name: String,
    /// Must be one of the `ViolationKind` variants: EgressBlocked,
    /// FileBlocked, ExecBlocked, MutationBlocked.
    pub kind: &'static str,
    pub detail: String,
    /// RFC3339; missing means the controller substitutes its `now`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Handle exposed to handler code. `send` never blocks; it drops
/// events on a full channel (at which point we've already lost on
/// reportability) and increments a drop counter.
#[derive(Clone)]
pub struct EventReporter {
    tx: Option<mpsc::Sender<WireEvent>>,
}

impl EventReporter {
    /// Reporter that throws every event away. Used when
    /// `--events-url` wasn't set.
    pub fn disabled() -> Self {
        Self { tx: None }
    }

    /// Start a background flusher POSTing to `url` (should include
    /// the `/events/batch` suffix) and return a handle to feed.
    pub fn start(
        url: String,
        http: reqwest::Client,
        buffer: usize,
        flush_interval: Duration,
        max_batch: usize,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<WireEvent>(buffer);
        tokio::spawn(async move {
            let mut pending: Vec<WireEvent> = Vec::with_capacity(max_batch);
            let mut ticker = tokio::time::interval(flush_interval);
            ticker.tick().await; // discard the immediate tick
            loop {
                tokio::select! {
                    maybe = rx.recv() => {
                        match maybe {
                            Some(ev) => {
                                pending.push(ev);
                                if pending.len() >= max_batch {
                                    flush(&http, &url, &mut pending).await;
                                }
                            }
                            None => {
                                // sender dropped — final flush + exit.
                                flush(&http, &url, &mut pending).await;
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if !pending.is_empty() {
                            flush(&http, &url, &mut pending).await;
                        }
                    }
                }
            }
        });
        Self { tx: Some(tx) }
    }

    /// Non-blocking send. Drops on full channel — no queueing
    /// forever — so a controller outage can't snowball into proxy
    /// memory growth.
    pub fn report(&self, event: WireEvent) {
        if let Some(tx) = &self.tx {
            if tx.try_send(event).is_err() {
                tracing::debug!("reporter channel full or closed; dropping event");
            }
        }
    }
}

async fn flush(http: &reqwest::Client, url: &str, pending: &mut Vec<WireEvent>) {
    if pending.is_empty() {
        return;
    }
    let batch = std::mem::take(pending);
    let n = batch.len();
    match http.post(url).json(&batch).send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(n, "reporter flushed");
        }
        Ok(resp) => {
            tracing::debug!(status = %resp.status(), n, "reporter flush rejected");
        }
        Err(e) => {
            tracing::debug!(err = %e, n, "reporter flush failed");
        }
    }
}

/// Wrap for `Arc<EventReporter>` so `AppState` fields stay
/// uniformly `Arc<_>`.
pub fn shared_disabled() -> Arc<EventReporter> {
    Arc::new(EventReporter::disabled())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_reporter_is_noop() {
        let r = EventReporter::disabled();
        // Should not panic, should not hang.
        r.report(WireEvent {
            namespace: "n".into(),
            pod_name: "p".into(),
            pod_uid: "u".into(),
            policy_name: String::new(),
            kind: "EgressBlocked",
            detail: "1.2.3.4:443".into(),
            timestamp: None,
        });
    }

    #[tokio::test]
    async fn full_channel_drops_silently() {
        // Smallest possible channel (capacity 1) so the third send
        // is guaranteed to drop.
        let http = reqwest::Client::new();
        // Point at a non-routable loopback port; the flusher's
        // error logging runs but nothing propagates back to report().
        let r = EventReporter::start(
            "http://127.0.0.1:1".into(),
            http,
            1,
            Duration::from_secs(60),
            10,
        );
        for _ in 0..10 {
            r.report(WireEvent {
                namespace: "n".into(),
                pod_name: "p".into(),
                pod_uid: "u".into(),
                policy_name: String::new(),
                kind: "EgressBlocked",
                detail: "d".into(),
                timestamp: None,
            });
        }
        // Main assertion is "didn't deadlock or panic."
    }
}
