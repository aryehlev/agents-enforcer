//! `enforcerctl` — the operator CLI for the agents-enforcer control
//! plane. Pairs with `kubectl`: `kubectl` for the direct CRUD,
//! `enforcerctl` for the higher-level views (policy status across
//! the cluster, capability spend vs budget, violation search, local
//! simulation).

mod commands;
mod format;
mod prom;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use kube::Client;

use commands::simulate::Format as SimulateFormat;

#[derive(Debug, Parser)]
#[command(name = "enforcerctl", about = "Operator CLI for agents.enforcer.io")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Work with AgentPolicy CRs cluster-wide.
    Policies {
        #[command(subcommand)]
        sub: PoliciesSub,
    },
    /// Work with AgentCapability CRs + live spend.
    Capabilities {
        #[command(subcommand)]
        sub: CapabilitiesSub,
    },
    /// Query AgentViolation CRs.
    Violations {
        #[command(subcommand)]
        sub: ViolationsSub,
    },
    /// Compile a policy YAML locally against catalogs on disk.
    Simulate {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long = "catalog")]
        catalogs: Vec<PathBuf>,
        #[arg(long, value_enum, default_value = "yaml")]
        format: SimulateFormat,
    },
    /// Regenerate the five CRD YAML manifests.
    GenCrds {
        #[arg(long, default_value = "deploy/crds")]
        out_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PoliciesSub {
    /// List policies and their programmed status.
    List {
        #[arg(short, long)]
        namespace: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum CapabilitiesSub {
    /// List capabilities with current-day spend alongside the budget.
    List {
        #[arg(short, long)]
        namespace: Option<String>,
        /// Prometheus-compatible endpoint for spend lookups.
        /// Example: http://prometheus.monitoring:9090 or a
        /// VictoriaMetrics vmsingle service URL. Omit to render
        /// only configured budgets.
        #[arg(long, env = "ENFORCERCTL_PROM_URL")]
        prom_url: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ViolationsSub {
    /// List recent violations.
    List {
        #[arg(short, long)]
        namespace: Option<String>,
        /// Only show violations newer than this (e.g. "1h", "30m").
        #[arg(long)]
        since: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Policies { sub } => match sub {
            PoliciesSub::List { namespace } => {
                let client = client().await?;
                println!(
                    "{}",
                    commands::policies::list(&client, namespace.as_deref()).await?
                );
            }
        },
        Cmd::Capabilities { sub } => match sub {
            CapabilitiesSub::List {
                namespace,
                prom_url,
            } => {
                let client = client().await?;
                let prom = prom_url.map(prom::PromClient::new);
                println!(
                    "{}",
                    commands::capabilities::list(&client, namespace.as_deref(), prom.as_ref())
                        .await?
                );
            }
        },
        Cmd::Violations { sub } => match sub {
            ViolationsSub::List { namespace, since } => {
                let client = client().await?;
                let since =
                    since.as_deref().map(commands::violations::parse_since).transpose()?;
                println!(
                    "{}",
                    commands::violations::list(&client, namespace.as_deref(), since).await?
                );
            }
        },
        Cmd::Simulate {
            policy,
            catalogs,
            format,
        } => {
            let out = commands::simulate::run(&policy, &catalogs, format)?;
            print!("{}", out);
        }
        Cmd::GenCrds { out_dir } => {
            commands::gen_crds::run(&out_dir)?;
        }
    }
    Ok(())
}

async fn client() -> anyhow::Result<Client> {
    Client::try_default()
        .await
        .context("connect to Kubernetes apiserver (check KUBECONFIG)")
}
