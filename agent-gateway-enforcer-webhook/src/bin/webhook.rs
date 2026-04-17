//! Admission webhook entry point.
//!
//! Serves HTTPS using a TLS cert mounted from a Secret (cert-manager
//! provisions the Secret via the Helm chart). The webhook itself is
//! stateless — ValidationFailures map 1:1 to deny responses.

use agent_gateway_enforcer_webhook::{handler::AppState, router};
use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use kube::Client;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "enforcer-webhook",
    about = "Validating admission webhook for agents.enforcer.io"
)]
struct Args {
    /// Path to TLS cert in PEM format (cert-manager writes
    /// `tls.crt` into the mounted Secret).
    #[arg(long, default_value = "/tls/tls.crt")]
    tls_cert: PathBuf,
    /// Path to TLS key.
    #[arg(long, default_value = "/tls/tls.key")]
    tls_key: PathBuf,
    /// Bind address for the HTTPS listener.
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: std::net::SocketAddr,
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
    let app = router(AppState { client });

    let tls = RustlsConfig::from_pem_file(&args.tls_cert, &args.tls_key)
        .await
        .with_context(|| {
            format!(
                "load TLS from {} / {}",
                args.tls_cert.display(),
                args.tls_key.display()
            )
        })?;

    tracing::info!(
        %args.listen,
        cert = %args.tls_cert.display(),
        "enforcer-webhook listening on HTTPS"
    );

    axum_server::bind_rustls(args.listen, tls)
        .serve(app.into_make_service())
        .await
        .context("serve")?;
    Ok(())
}
