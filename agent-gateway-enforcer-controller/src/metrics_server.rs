//! HTTP `/metrics` exporter. Serves the Prometheus text exposition
//! format from [`crate::metrics::REGISTRY`] on a configurable bind
//! address.
//!
//! Prometheus-format on purpose: VictoriaMetrics' `vmagent` and
//! `vmsingle` scrape it natively, Mimir / Cortex / Thanos do too, and
//! the Prometheus Operator's `ServiceMonitor` targets this endpoint
//! straight. An OTLP metrics pipeline would add surface area without
//! gaining us anything over scrape.

use std::net::SocketAddr;

use prometheus::{Encoder, TextEncoder};

use crate::metrics::REGISTRY;

/// Serve until `shutdown` completes. Returns any bind / accept
/// error.
pub async fn serve(addr: SocketAddr, shutdown: impl std::future::Future<Output = ()> + Send + 'static)
    -> anyhow::Result<()>
{
    use axum::{routing::get, Router};
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        // /healthz is cheap to expose here too so the same Service
        // port can be used for kubelet readiness probes.
        .route("/healthz", get(|| async { "ok" }));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind {}: {}", addr, e))?;
    tracing::info!(%addr, "metrics server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| anyhow::anyhow!("serve: {}", e))?;
    Ok(())
}

async fn metrics_handler() -> Result<axum::response::Response<String>, (axum::http::StatusCode, String)> {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buf = Vec::new();
    encoder.encode(&metric_families, &mut buf).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode metrics: {}", e),
        )
    })?;
    let body = String::from_utf8(buf).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("utf8: {}", e),
        )
    })?;
    Ok(axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, encoder.format_type())
        .body(body)
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::record_reconcile;

    #[tokio::test]
    async fn metrics_endpoint_returns_text_format_with_enforcer_prefix() {
        // Touch a metric so gather() produces a family.
        record_reconcile("ok");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/metrics", axum::routing::get(metrics_handler));

        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let body = reqwest::get(format!("http://{}/metrics", addr))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        assert!(
            body.contains("enforcer_controller_reconcile_total"),
            "expected enforcer_-prefixed metric names; got:\n{}",
            body
        );

        server.abort();
    }
}
