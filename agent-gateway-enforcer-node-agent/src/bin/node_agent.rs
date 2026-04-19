//! Node-agent binary entry point.
//!
//! Loads the eBPF programs, starts the `EbpfLinuxBackend`, and serves
//! the gRPC `NodeAgent` API on `--listen`. Deployed as a DaemonSet
//! per Kubernetes node; see `deploy/helm/charts/agents-enforcer`.

use std::sync::Arc;

use agent_gateway_enforcer_backend_ebpf_linux::EbpfLinuxBackend;
use agent_gateway_enforcer_core::backend::{EnforcementBackend, UnifiedConfig};
use agent_gateway_enforcer_node_agent::{
    metrics::NODE_AGENT_UP, metrics_server, reporter, server::NodeAgentService, NodeAgentServer,
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

    /// Controller's event-ingest URL, ending in `/events/batch`. Set
    /// empty (the default) to run without a reporter — eBPF still
    /// enforces, but per-decision events aren't surfaced as
    /// `AgentViolation` CRs.
    #[arg(long, default_value = "", env = "ENFORCER_EVENTS_URL")]
    controller_events_url: String,

    /// Directory mounted from the same `AgentCapability` ConfigMap
    /// the LLM proxy reads. Drives the eBPF-only LLM enforcement
    /// path: the TLS uprobe consumer looks up `<ns>/<pod>` here on
    /// every captured request. Empty/missing dir = LLM enforcement
    /// is observe-only (no caps loaded → every captured request
    /// denies as `no_capability` if attribution is set).
    #[arg(
        long,
        default_value = "/etc/agents-enforcer/capabilities",
        env = "ENFORCER_CAPABILITIES_DIR"
    )]
    capabilities_dir: std::path::PathBuf,
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
    let backend = Arc::new(backend);

    // Load LLM capability bundles for the eBPF-only enforcement
    // path. Same ConfigMap the LLM proxy reads — operators write
    // one policy and both modes apply it.
    let llm_caps = backend.llm_capabilities();
    match agent_gateway_enforcer_backend_ebpf_linux::llm::load_from_dir(&args.capabilities_dir) {
        Ok(map) => {
            let n = map.len();
            llm_caps.replace(map);
            tracing::info!(
                count = n,
                dir = %args.capabilities_dir.display(),
                "llm capabilities loaded"
            );
        }
        Err(e) => tracing::warn!(
            err = %e,
            dir = %args.capabilities_dir.display(),
            "llm capability load failed; eBPF-only LLM enforcement degraded"
        ),
    }

    // SIGHUP reload — operators kubectl-edit the ConfigMap then
    // `kill -HUP`. Tracks the LLM proxy's behavior verbatim so
    // operations stay symmetric across enforcement modes.
    {
        let llm_caps = llm_caps.clone();
        let dir = args.capabilities_dir.clone();
        tokio::spawn(async move {
            let mut sig = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(err = %e, "SIGHUP unavailable; reload disabled");
                    return;
                }
            };
            while sig.recv().await.is_some() {
                match agent_gateway_enforcer_backend_ebpf_linux::llm::load_from_dir(&dir) {
                    Ok(map) => {
                        let n = map.len();
                        llm_caps.replace(map);
                        tracing::info!(count = n, "llm capabilities reloaded via SIGHUP");
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "llm capability reload failed; keeping old set")
                    }
                }
            }
        });
    }

    // Reporter — subscribes to the backend's decision events and
    // POSTs to the controller. Disabled when no URL is configured.
    let _reporter_handle = if args.controller_events_url.is_empty() {
        tracing::info!("reporter disabled (ENFORCER_EVENTS_URL unset)");
        None
    } else {
        tracing::info!(url = %args.controller_events_url, "reporter enabled");
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .context("reqwest client")?;
        let cfg = reporter::ReporterConfig {
            url: args.controller_events_url.clone(),
            ..reporter::ReporterConfig::default()
        };
        Some(reporter::spawn(backend.as_ref(), http, cfg))
    };

    let backend: Arc<dyn EnforcementBackend> = backend;

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
