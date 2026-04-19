//! Periodic flush loop: drains the in-memory aggregator into
//! `AgentViolation` CRs and server-side-applies them through the
//! existing apiserver credentials.
//!
//! The aggregator itself is pure (see `aggregator.rs`); this module
//! is the I/O half — so it gets its own integration test against a
//! `kube::Api`-shaped trait, and the aggregator's own unit tests
//! don't need a cluster.
//!
//! Shutdown is cooperative: callers drop the `AggregatorHandle` to
//! stop the loop. `ingest()` is safe to call during shutdown; the
//! last window's buffered events are lost (acceptable for rolling
//! aggregation — the next window on restart will repopulate).

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Patch, PatchParams};
use kube::{Api, Client};
use parking_lot::Mutex;

use crate::aggregator::{Aggregator, FlushedViolation};
use crate::crds::AgentViolation;
use crate::events::DecisionEvent;

/// Handle returned by `run`. Drop to stop the background task.
/// `ingest` is cheap (one lock + hashmap lookup) so the fast path
/// of a node-agent stream fan-in keeps up fine.
#[derive(Clone)]
pub struct AggregatorHandle {
    agg: Arc<Mutex<Aggregator>>,
    _shutdown: Arc<tokio::sync::oneshot::Sender<()>>,
}

impl AggregatorHandle {
    /// Add one event to the current window.
    pub fn ingest(&self, e: DecisionEvent) {
        self.agg.lock().ingest(e);
    }

    /// Snapshot bucket count — cheap, used by `/metrics`.
    pub fn len(&self) -> usize {
        self.agg.lock().len()
    }

    /// Test-only constructor that wraps a pre-built aggregator
    /// without starting the flush loop. Integration tests use this
    /// to stand up the ingest server in-process and inspect buckets
    /// directly.
    pub fn for_test(agg: Arc<Mutex<Aggregator>>) -> Self {
        let (tx, _rx) = tokio::sync::oneshot::channel::<()>();
        Self {
            agg,
            _shutdown: Arc::new(tx),
        }
    }
}

/// Start the flush loop. The task exits when the returned handle is
/// dropped (the oneshot sender goes out of scope and the receiver
/// resolves).
pub fn run(client: Client, window: Duration) -> AggregatorHandle {
    let agg = Arc::new(Mutex::new(Aggregator::new()));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let agg_bg = agg.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(window);
        // First tick fires immediately; skip it so the first flush
        // actually has a full window of events.
        interval.tick().await;
        let mut rx = rx;
        loop {
            tokio::select! {
                _ = &mut rx => break,
                _ = interval.tick() => {
                    let flushed = agg_bg.lock().flush();
                    if let Err(e) = apply_all(&client, flushed).await {
                        // Individual upsert failures are logged inside
                        // `apply_all`; this only fires for the list-
                        // building level. Fine to continue the loop.
                        tracing::warn!(err = %e, "aggregator flush failed");
                    }
                }
            }
        }
        tracing::debug!("aggregator loop exiting");
    });
    AggregatorHandle {
        agg,
        _shutdown: Arc::new(tx),
    }
}

/// Apply one CR per flushed violation via server-side apply. The
/// CR's `name` is deterministic from the bucket key so re-applies
/// in subsequent windows are idempotent updates, not duplicates.
async fn apply_all(
    client: &Client,
    flushed: Vec<FlushedViolation>,
) -> anyhow::Result<()> {
    if flushed.is_empty() {
        return Ok(());
    }
    for v in flushed {
        let api: Api<AgentViolation> = Api::namespaced(client.clone(), &v.namespace);
        let cr = AgentViolation {
            metadata: kube::api::ObjectMeta {
                name: Some(v.name.clone()),
                namespace: Some(v.namespace.clone()),
                ..Default::default()
            },
            spec: v.spec,
        };
        let params = PatchParams::apply("agents.enforcer.io/aggregator").force();
        match api
            .patch(&v.name, &params, &Patch::Apply(&cr))
            .await
        {
            Ok(_) => tracing::debug!(
                namespace = %v.namespace,
                name = %v.name,
                "violation applied"
            ),
            Err(e) => tracing::warn!(
                namespace = %v.namespace,
                name = %v.name,
                err = %e,
                "violation apply failed"
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::ViolationKind;

    fn ev() -> DecisionEvent {
        DecisionEvent {
            namespace: "prod".into(),
            pod_name: "agent".into(),
            pod_uid: "uid-1".into(),
            policy_name: "p".into(),
            kind: ViolationKind::EgressBlocked,
            detail: "1.2.3.4:443".into(),
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn handle_ingest_and_len_do_not_block_each_other() {
        // Integration-style: the in-memory store is Arc<Mutex<_>>,
        // so concurrent ingest + len should not deadlock. Single-
        // threaded smoke test — if we'd used a RwLock recursively
        // it'd hang.
        let agg = Arc::new(Mutex::new(Aggregator::new()));
        let (tx, _rx) = tokio::sync::oneshot::channel::<()>();
        let h = AggregatorHandle {
            agg: agg.clone(),
            _shutdown: Arc::new(tx),
        };
        h.ingest(ev());
        h.ingest(ev());
        assert_eq!(h.len(), 1);
    }
}
