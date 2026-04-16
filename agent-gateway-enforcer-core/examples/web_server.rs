//! Web server example for Agent Gateway Enforcer
//!
//! This starts a web server that serves the dashboard and provides API endpoints

use agent_gateway_enforcer_core::backend::UnifiedConfig;
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
    println!("║   🚀 Agent Gateway Enforcer - Web Dashboard             ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // Create configuration
    let config = Arc::new(UnifiedConfig::default());

    // Create event bus for real-time events
    let event_bus = Arc::new(EventBus::new());

    // Create metrics registry
    let metrics = Arc::new(MetricsRegistry::new_default()?);

    println!("🔧 Initialized:");
    println!("   • Configuration system");
    println!("   • Event bus");
    println!("   • Metrics registry");
    println!();
    println!("🌐 Starting web server...");
    println!();
    println!("   📊 Dashboard:  http://127.0.0.1:8080");
    println!("   🔌 API Status: http://127.0.0.1:8080/api/status");
    println!("   📈 Metrics:    http://127.0.0.1:9090/metrics");
    println!("   💚 Health:     http://127.0.0.1:9090/health");
    println!();
    println!("📁 Serving static files from: agent-gateway-enforcer-core/static/");
    println!();
    println!("⌨️  Press Ctrl+C to stop...");
    println!();

    // Start the web server
    let static_dir = std::path::PathBuf::from("static");

    let web_handle = tokio::spawn(async move {
        match web::start_server(
            ([127, 0, 0, 1], 8080).into(),
            config,
            event_bus,
            metrics,
            static_dir,
        ).await {
            Ok(_) => println!("Web server stopped"),
            Err(e) => eprintln!("❌ Web server error: {}", e),
        }
    });

    // Wait for Ctrl+C
    match signal::ctrl_c().await {
        Ok(()) => {
            println!("\n\n👋 Received shutdown signal...");
            web_handle.abort();
            println!("✅ Server stopped");
        }
        Err(err) => {
            eprintln!("Error waiting for signal: {}", err);
        }
    }

    Ok(())
}
