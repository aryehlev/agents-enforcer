//! `/metrics` endpoint for the LLM proxy. Mirrors the controller /
//! node-agent exporters; separate registry so label cardinality is
//! scoped to this process.

use std::net::SocketAddr;

use prometheus::{Encoder, TextEncoder};

use crate::metrics::REGISTRY;

/// Serve until `shutdown` resolves.
pub async fn serve(
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    use axum::{routing::get, Router};
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind {}: {}", addr, e))?;
    tracing::info!(%addr, "llm-proxy metrics server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| anyhow::anyhow!("serve: {}", e))?;
    Ok(())
}

async fn metrics_handler(
) -> Result<axum::response::Response<String>, (axum::http::StatusCode, String)> {
    let encoder = TextEncoder::new();
    let mut buf = Vec::new();
    encoder.encode(&REGISTRY.gather(), &mut buf).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode: {}", e),
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
