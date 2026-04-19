//! HTTP endpoint for pushing `DecisionEvent`s into the aggregator.
//!
//! Intended callers: the LLM proxy (on every reject/forward), and
//! the node-agent (when the ringbuf consumer lands — for v1alpha1
//! the node-agent still has a TODO there). A gRPC streaming variant
//! is tracked as a follow-up; HTTP POSTs are good enough while
//! event rates stay in the low-hundreds-per-second per controller
//! replica.
//!
//! The endpoint is intentionally cluster-local: no auth, bound to a
//! ClusterIP Service. Add a NetworkPolicy if your threat model has
//! other tenants in the namespace.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use crate::aggregator_loop::AggregatorHandle;
use crate::crds::ViolationKind;
use crate::events::DecisionEvent;

/// The handle is Arc-wrapped for axum state sharing; every request
/// takes a lock for the few microseconds it needs to push into the
/// aggregator's hashmap.
pub fn router(handle: AggregatorHandle) -> Router {
    Router::new()
        .route("/events", post(ingest))
        .route("/events/batch", post(ingest_batch))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(Arc::new(handle))
}

/// Wire-level shape. Timestamp is ISO8601 so the caller doesn't have
/// to know which epoch base the controller uses internally.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventWire {
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    #[serde(default)]
    pub policy_name: String,
    pub kind: ViolationKind,
    pub detail: String,
    /// RFC3339 UTC. Missing → treated as "now", which covers
    /// callers that don't carry their own clock (browser-delivered
    /// audit events, for example).
    #[serde(default)]
    pub timestamp: Option<String>,
}

impl EventWire {
    fn into_event(self) -> Result<DecisionEvent, String> {
        let timestamp = match self.timestamp.as_deref() {
            None | Some("") => chrono::Utc::now(),
            Some(s) => chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("bad timestamp '{}': {}", s, e))?
                .to_utc(),
        };
        Ok(DecisionEvent {
            namespace: self.namespace,
            pod_name: self.pod_name,
            pod_uid: self.pod_uid,
            policy_name: self.policy_name,
            kind: self.kind,
            detail: self.detail,
            timestamp,
        })
    }
}

async fn ingest(
    State(h): State<Arc<AggregatorHandle>>,
    Json(body): Json<EventWire>,
) -> Result<StatusCode, (StatusCode, String)> {
    let ev = body
        .into_event()
        .map_err(|m| (StatusCode::BAD_REQUEST, m))?;
    h.ingest(ev);
    Ok(StatusCode::ACCEPTED)
}

/// Batch variant — preferred for hot paths (llm-proxy reject events
/// land here). A malformed entry rejects the whole batch so callers
/// don't half-submit.
async fn ingest_batch(
    State(h): State<Arc<AggregatorHandle>>,
    Json(body): Json<Vec<EventWire>>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Validate all first so we don't ingest half a batch.
    let events = body
        .into_iter()
        .map(|w| w.into_event())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|m| (StatusCode::BAD_REQUEST, m))?;
    for e in events {
        h.ingest(e);
    }
    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_timestamp_uses_now() {
        let w = EventWire {
            namespace: "prod".into(),
            pod_name: "p".into(),
            pod_uid: "u".into(),
            policy_name: "p".into(),
            kind: ViolationKind::EgressBlocked,
            detail: "x".into(),
            timestamp: None,
        };
        let e = w.into_event().unwrap();
        // A fresh `now()` against a fresh `now()` is within a second.
        let dt = (chrono::Utc::now() - e.timestamp).num_seconds().abs();
        assert!(dt <= 1, "expected recent timestamp; drift = {}s", dt);
    }

    #[test]
    fn bad_timestamp_rejects_with_400() {
        let w = EventWire {
            namespace: "prod".into(),
            pod_name: "p".into(),
            pod_uid: "u".into(),
            policy_name: "p".into(),
            kind: ViolationKind::EgressBlocked,
            detail: "x".into(),
            timestamp: Some("not-a-timestamp".into()),
        };
        assert!(w.into_event().is_err());
    }

    #[test]
    fn empty_timestamp_string_falls_back_to_now() {
        // Some clients stringify-null, some emit an empty string.
        // Both must behave the same.
        let w = EventWire {
            namespace: "prod".into(),
            pod_name: "p".into(),
            pod_uid: "u".into(),
            policy_name: String::new(),
            kind: ViolationKind::ExecBlocked,
            detail: "/bin/sh".into(),
            timestamp: Some(String::new()),
        };
        assert!(w.into_event().is_ok());
    }
}
