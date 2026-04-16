//! Simple runner for the Agent Gateway Enforcer with web dashboard
//!
//! This connects the actual Rust backend to the web dashboard

use agent_gateway_enforcer_core::backend::{BackendRegistry, BackendType, UnifiedConfig};
use agent_gateway_enforcer_core::events::EventBus;
use agent_gateway_enforcer_core::metrics::MetricsRegistry;
use agent_gateway_enforcer_core::web;
use std::sync::Arc;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   🚀 Agent Gateway Enforcer - Web Server                ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // Create backend registry
    let mut registry = BackendRegistry::new();

    // Register platform-specific backend
    #[cfg(target_os = "macos")]
    {
        use agent_gateway_enforcer_backend_macos::registry;
        registry::register_backend(&mut registry)?;
        println!("✅ Registered macOS Desktop backend");
    }

    #[cfg(target_os = "linux")]
    {
        use agent_gateway_enforcer_backend_ebpf_linux::registry;
        registry::register_backend(&mut registry)?;
        println!("✅ Registered eBPF Linux backend");
    }

    // Create default configuration
    let config = Arc::new(UnifiedConfig::default());

    // Create event bus
    let event_bus = Arc::new(EventBus::new());

    // Create metrics registry
    let metrics = Arc::new(MetricsRegistry::new_default()?);

    println!();
    println!("🌐 Starting web server...");
    println!("   • Dashboard: http://127.0.0.1:8080");
    println!("   • API: http://127.0.0.1:8080/api/*");
    println!("   • Metrics: http://127.0.0.1:9090/metrics");
    println!("   • Health: http://127.0.0.1:9090/health");
    println!();
    println!("📊 Static files: agent-gateway-enforcer-core/static/");
    println!();
    println!("Press Ctrl+C to stop...");
    println!();

    // Start the web server
    let web_handle = tokio::spawn(async move {
        if let Err(e) = web::start_server(
            ([127, 0, 0, 1], 8080).into(),
            config.clone(),
            event_bus.clone(),
            metrics.clone(),
            std::path::PathBuf::from("agent-gateway-enforcer-core/static"),
        ).await {
            eprintln!("Web server error: {}", e);
        }
    });

    // Wait for Ctrl+C
    signal::ctrl_c().await?;

    println!("\n\n👋 Shutting down...");
    web_handle.abort();

    Ok(())
}
