//! LLM proxy binary — loads `AgentCapability` bundles from a
//! directory, serves the OpenAI-compatible endpoint, forwards
//! upstream, and exposes Prometheus metrics.
//!
//! Deploys as a cluster-scoped Service fronted by the node-agent
//! eBPF gateway rules — pods send traffic to the proxy's Service
//! DNS name instead of the LLM provider directly, and the proxy
//! forwards with its own credentials.

use std::path::PathBuf;
use std::sync::Arc;

use agent_gateway_enforcer_llm_proxy::{
    budget::BudgetStore,
    capabilities::{load_from_dir, CapabilityStore},
    handler::{router, AppState},
    metrics_server,
    pricing::PricingTable,
};
use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "enforcer-llm-proxy",
    about = "OpenAI-compatible LLM gateway enforcing AgentCapability"
)]
struct Args {
    /// Proxy listen address for the OpenAI-shaped endpoints.
    #[arg(long, default_value = "0.0.0.0:4180")]
    listen: std::net::SocketAddr,

    /// Metrics listen address. Separated so the API port can be
    /// exposed through an ingress while metrics stay cluster-local.
    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_addr: std::net::SocketAddr,

    /// Upstream base URL. Every forwarded request lands at
    /// `<upstream>/v1/chat/completions`.
    #[arg(long, default_value = "https://api.openai.com")]
    upstream: String,

    /// Directory mounted from a ConfigMap of `AgentCapability` YAMLs.
    /// The proxy reads this on startup and on SIGHUP.
    #[arg(long, default_value = "/etc/agents-enforcer/capabilities")]
    capabilities_dir: PathBuf,

    /// Path to pricing YAML. Shipped default lives in
    /// `deploy/pricing/default.yaml`; operators override by mounting
    /// their own ConfigMap. Reloaded in-place on SIGHUP along with
    /// capabilities, so a price change doesn't need a rollout.
    #[arg(long, default_value = "/etc/agents-enforcer/pricing/pricing.yaml")]
    pricing_file: PathBuf,
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

    // Load capabilities + pricing.
    let caps = Arc::new(CapabilityStore::new());
    let initial = load_from_dir(&args.capabilities_dir)
        .with_context(|| format!("load caps from {}", args.capabilities_dir.display()))?;
    caps.replace(initial);
    tracing::info!(
        count = caps.len(),
        dir = %args.capabilities_dir.display(),
        "capabilities loaded"
    );

    let pricing = Arc::new(PricingTable::new());
    if args.pricing_file.exists() {
        pricing
            .reload_from_file(&args.pricing_file)
            .with_context(|| format!("load pricing from {}", args.pricing_file.display()))?;
        tracing::info!(
            count = pricing.len(),
            file = %args.pricing_file.display(),
            "pricing loaded"
        );
    } else {
        tracing::warn!(
            file = %args.pricing_file.display(),
            "pricing file missing; cost enforcement will reject every request until it's mounted",
        );
    }

    // Reload on SIGHUP. One handler refreshes both capabilities and
    // pricing — operators edit one ConfigMap, hup once, done.
    {
        let caps = caps.clone();
        let pricing = pricing.clone();
        let cap_dir = args.capabilities_dir.clone();
        let pricing_file = args.pricing_file.clone();
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
                match load_from_dir(&cap_dir) {
                    Ok(new_map) => {
                        let n = new_map.len();
                        caps.replace(new_map);
                        tracing::info!(count = n, "capabilities reloaded via SIGHUP");
                    }
                    Err(e) => tracing::warn!(err = %e, "capability reload failed; keeping old set"),
                }
                if pricing_file.exists() {
                    match pricing.reload_from_file(&pricing_file) {
                        Ok(()) => tracing::info!(
                            count = pricing.len(),
                            "pricing reloaded via SIGHUP"
                        ),
                        Err(e) => tracing::warn!(err = %e, "pricing reload failed; keeping old table"),
                    }
                }
            }
        });
    }

    let state = Arc::new(AppState {
        caps,
        budget: Arc::new(BudgetStore::new()),
        pricing,
        upstream_base: args.upstream.clone(),
        http: reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .context("reqwest client")?,
    });

    tracing::info!(
        %args.listen,
        metrics = %args.metrics_addr,
        upstream = %args.upstream,
        "enforcer-llm-proxy listening",
    );

    let (metrics_stop_tx, metrics_stop_rx) = tokio::sync::oneshot::channel();
    let metrics_task = tokio::spawn(async move {
        let _ = metrics_server::serve(args.metrics_addr, async move {
            let _ = metrics_stop_rx.await;
        })
        .await;
    });

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    let serve = axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    let result = serve.await.context("serve");

    let _ = metrics_stop_tx.send(());
    let _ = metrics_task.await;
    result?;
    Ok(())
}
