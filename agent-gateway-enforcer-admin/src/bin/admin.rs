//! enforcer-admin — HTTP API + static dashboard binary.

use std::sync::Arc;

use agent_gateway_enforcer_admin::{router, AppState};
use anyhow::Context;
use clap::Parser;
use kube::Client;

#[derive(Debug, Parser)]
#[command(name = "enforcer-admin", about = "Read-only admin API + dashboard for agents-enforcer")]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: std::net::SocketAddr,
    /// Prometheus-compatible endpoint. Omit to serve capabilities /
    /// overview without live spend.
    #[arg(long, env = "ENFORCER_PROM_URL")]
    prom_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let client = Client::try_default()
        .await
        .context("connect to Kubernetes apiserver")?;
    let state = Arc::new(AppState {
        client,
        prom_url: args.prom_url,
        http: reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()?,
    });
    tracing::info!(%args.listen, "enforcer-admin listening");
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
