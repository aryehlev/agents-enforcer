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
    ControllerConfig, LoggingDistributor, run, BundleDistributor,
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
    /// Distributor mode. `log` is a dry run that only logs decisions;
    /// `grpc-stub` is a placeholder for the upcoming node-agent RPC
    /// transport. The node-agent transport is tracked separately and
    /// this flag exists so ops have a single knob to flip when it lands.
    #[arg(long, value_enum, default_value = "log")]
    distributor: DistributorKind,

    /// Cgroup v2 path template; `{uid}` is replaced with the pod UID.
    #[arg(
        long,
        default_value = "/sys/fs/cgroup/kubepods.slice/kubepods-pod{uid}.slice"
    )]
    cgroup_template: String,

    /// Seconds between mandatory reconciles when nothing has changed.
    #[arg(long, default_value_t = 30)]
    requeue_seconds: u64,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DistributorKind {
    /// Log decisions only; do not enforce.
    Log,
    /// Placeholder for the gRPC transport; not yet implemented.
    GrpcStub,
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
        DistributorKind::GrpcStub => {
            anyhow::bail!(
                "distributor=grpc-stub is not yet implemented; see roadmap Phase B.4"
            );
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
        "starting enforcer-controller"
    );
    run(client, distributor, config).await
}
