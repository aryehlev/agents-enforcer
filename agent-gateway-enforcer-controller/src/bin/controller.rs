//! Controller binary entry point.
//!
//! Runs the kube-rs Controller loop for `AgentPolicy` resources. On
//! startup: connect to the apiserver via `KUBECONFIG` / in-cluster
//! config, pick a distributor (log-only by default, so a misconfigured
//! deployment can't silently drop traffic), and hand everything to
//! [`agent_gateway_enforcer_controller::run`].

use std::sync::Arc;
use std::time::Duration;

use agent_gateway_enforcer_controller::{
    aggregator_loop, events_server, metrics_server, run, BundleDistributor, ControllerConfig,
    GrpcDistributor, LoggingDistributor, StaticNodeEndpointResolver,
};
use anyhow::Context;
use clap::Parser;
use kube::Client;

#[derive(Debug, Parser)]
#[command(
    name = "enforcer-controller",
    about = "Kubernetes controller for agents.enforcer.io CRDs"
)]
struct Args {
    /// Distributor mode. `log` is a dry run that logs decisions
    /// without enforcing; `grpc` dials one node-agent per Kubernetes
    /// node via the DaemonSet's node-scoped DNS.
    #[arg(long, value_enum, default_value = "log")]
    distributor: DistributorKind,

    /// Port the node-agent DaemonSet listens on. Only used when
    /// --distributor=grpc.
    #[arg(long, default_value_t = 9091)]
    node_agent_port: u16,

    /// Cgroup v2 path template; `{uid}` is replaced with the pod UID.
    #[arg(
        long,
        default_value = "/sys/fs/cgroup/kubepods.slice/kubepods-pod{uid}.slice"
    )]
    cgroup_template: String,

    /// Seconds between mandatory reconciles when nothing has changed.
    #[arg(long, default_value_t = 30)]
    requeue_seconds: u64,

    /// Bind address for the Prometheus /metrics exporter. Prometheus,
    /// VictoriaMetrics vmagent, Grafana Mimir, Thanos, Cortex all
    /// scrape this endpoint directly — no OTLP metrics pipeline
    /// needed.
    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_addr: std::net::SocketAddr,

    /// Bind address for the violation aggregator's ingest API.
    /// Disable by passing an empty value. Reachable cluster-local
    /// only; secure with a NetworkPolicy if your namespace is
    /// multi-tenant.
    #[arg(long, default_value = "0.0.0.0:9092")]
    events_addr: String,

    /// Flush window for the aggregator. Every window, buckets
    /// collapse into at most one AgentViolation CR per
    /// (namespace, pod_uid, policy, kind, detail_prefix).
    #[arg(long, default_value_t = 60)]
    aggregator_window_seconds: u64,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DistributorKind {
    /// Log decisions only; do not enforce.
    Log,
    /// Dial one node-agent per Kubernetes node.
    Grpc,
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

    let distributor: Arc<dyn BundleDistributor> = match args.distributor {
        DistributorKind::Log => {
            tracing::info!("running in dry-run mode (distributor=log)");
            Arc::new(LoggingDistributor::new())
        }
        DistributorKind::Grpc => {
            tracing::info!(port = args.node_agent_port, "using gRPC distributor");
            let resolver = Arc::new(StaticNodeEndpointResolver::new(args.node_agent_port));
            Arc::new(GrpcDistributor::new(resolver))
        }
    };

    let client = Client::try_default()
        .await
        .context("connect to Kubernetes apiserver")?;

    let config = ControllerConfig {
        cgroup_template: args.cgroup_template,
        requeue_interval: Duration::from_secs(args.requeue_seconds),
    };

    tracing::info!(
        requeue_s = args.requeue_seconds,
        cgroup_template = %config.cgroup_template,
        metrics_addr = %args.metrics_addr,
        "starting enforcer-controller"
    );

    // Start the aggregator first — we need its handle for the
    // events HTTP server, and both can start before the controller
    // loop blocks.
    let agg = aggregator_loop::run(
        client.clone(),
        Duration::from_secs(args.aggregator_window_seconds),
    );

    // Run the controller, metrics server, and events server
    // concurrently. A failure in any of them takes the process
    // down — kubelet restarts us, which is the correct behavior for
    // a control-plane pod.
    let (metrics_stop_tx, metrics_stop_rx) = tokio::sync::oneshot::channel();
    let metrics_task = tokio::spawn(async move {
        let _ = metrics_server::serve(args.metrics_addr, async move {
            let _ = metrics_stop_rx.await;
        })
        .await;
    });

    let (events_stop_tx, events_stop_rx) = tokio::sync::oneshot::channel();
    let events_task = if args.events_addr.is_empty() {
        None
    } else {
        let addr: std::net::SocketAddr = args
            .events_addr
            .parse()
            .with_context(|| format!("invalid events-addr {}", args.events_addr))?;
        let router = events_server::router(agg.clone());
        Some(tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!(%addr, "events ingest listening");
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = events_stop_rx.await;
                })
                .await?;
            Ok::<_, anyhow::Error>(())
        }))
    };

    let result = run(client, distributor, config).await;

    let _ = metrics_stop_tx.send(());
    let _ = events_stop_tx.send(());
    let _ = metrics_task.await;
    if let Some(h) = events_task {
        let _ = h.await;
    }
    // Dropping `agg` stops the aggregator flush loop.
    drop(agg);
    result
}
