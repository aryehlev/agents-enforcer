//! Node-agent binary entry point.
//!
//! Loads the eBPF programs, starts the `EbpfLinuxBackend`, and serves
//! the gRPC `NodeAgent` API on `--listen`. Deployed as a DaemonSet
//! per Kubernetes node; see `deploy/helm/charts/agents-enforcer`.

use std::sync::Arc;

use agent_gateway_enforcer_backend_ebpf_linux::EbpfLinuxBackend;
use agent_gateway_enforcer_core::backend::{EnforcementBackend, UnifiedConfig};
use agent_gateway_enforcer_node_agent::{
    metrics::NODE_AGENT_UP, metrics_server, server::NodeAgentService, NodeAgentServer,
};
use anyhow::Context;
use clap::Parser;
use tonic::transport::Server;

#[derive(Debug, Parser)]
#[command(
    name = "enforcer-node-agent",
    about = "Per-node gRPC agent: receives PolicyBundles from the controller and programs eBPF."
)]
struct Args {
    /// Address to listen on. Default binds the standard DaemonSet
    /// port on all interfaces so the controller can reach it via the
    /// node's hostIP.
    #[arg(long, default_value = "0.0.0.0:9091")]
    listen: String,

    /// Bind address for the Prometheus /metrics exporter.
    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_addr: std::net::SocketAddr,
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

    // Initialize + start the backend. initialize/start take &mut self;
    // after that we freeze ownership into an Arc<dyn> for the service.
    let mut backend = EbpfLinuxBackend::new();
    backend
        .initialize(&UnifiedConfig::default())
        .await
        .context("backend initialize")?;
    backend.start().await.context("backend start")?;
    let backend: Arc<dyn EnforcementBackend> = Arc::new(backend);

    let addr = args
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {}", args.listen))?;
    tracing::info!(%addr, metrics = %args.metrics_addr, "enforcer-node-agent listening");

    // Mark ourselves up; a scrape after startup sees 1, a missing
    // target (pod down) surfaces as `up == 0` or absent series.
    let node = std::env::var("NODE_NAME").unwrap_or_else(|_| "unknown".into());
    NODE_AGENT_UP.with_label_values(&[&node]).set(1);

    // Run metrics + gRPC concurrently. Either failure takes the
    // process down so kubelet restarts it.
    let (metrics_stop_tx, metrics_stop_rx) = tokio::sync::oneshot::channel();
    let metrics_task = tokio::spawn(async move {
        let _ = metrics_server::serve(args.metrics_addr, async move {
            let _ = metrics_stop_rx.await;
        })
        .await;
    });

    let grpc_result = Server::builder()
        .add_service(NodeAgentServer::new(NodeAgentService::new(backend)))
        .serve_with_shutdown(addr, async {
            // SIGTERM on DaemonSet eviction; tokio's ctrl_c covers
            // SIGINT for local dev. Either signal drains gracefully.
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received; draining");
        })
        .await
        .context("serve");

    let _ = metrics_stop_tx.send(());
    let _ = metrics_task.await;
    grpc_result?;
    Ok(())
}
