// Example: Running the Web Dashboard
//
// This example demonstrates how to start the web dashboard server
// with the REST API and WebSocket support.

use agent_gateway_enforcer_core::{
    config::manager::ConfigManager,
    events::bus::EventBus,
    metrics::registry::MetricsRegistry,
    web::{WebConfig, WebServer},
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,agent_gateway_enforcer_core=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    println!("Starting Agent Gateway Enforcer Web Dashboard...");

    // Create configuration manager
    let config_path =
        std::env::var("CONFIG_PATH").unwrap_or_else(|_| "examples/config-example.yaml".to_string());

    println!("Loading configuration from: {}", config_path);
    let config_manager = Arc::new(RwLock::new(ConfigManager::new(&config_path)));

    // Create metrics registry
    let metrics_registry = Arc::new(MetricsRegistry::new_default()?);

    // Create event bus (capacity of 1000 events)
    let event_bus = Arc::new(EventBus::new(1000));

    // Configure web server
    let web_config = WebConfig {
        host: std::env::var("WEB_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        port: std::env::var("WEB_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080),
        enable_cors: std::env::var("WEB_ENABLE_CORS")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true),
        static_dir: std::env::var("WEB_STATIC_DIR")
            .unwrap_or_else(|_| "agent-gateway-enforcer-core/static".to_string()),
    };

    println!("Web server configuration:");
    println!("  Host: {}", web_config.host);
    println!("  Port: {}", web_config.port);
    println!("  CORS: {}", web_config.enable_cors);
    println!("  Static dir: {}", web_config.static_dir);

    // Create and start web server
    let server = WebServer::new(
        web_config.clone(),
        config_manager,
        metrics_registry,
        event_bus,
    );

    println!("\n===========================================");
    println!("Web Dashboard is ready!");
    println!("===========================================");
    println!(
        "  Dashboard: http://{}:{}",
        web_config.host, web_config.port
    );
    println!(
        "  API: http://{}:{}/api/v1/status",
        web_config.host, web_config.port
    );
    println!(
        "  WebSocket: ws://{}:{}/ws",
        web_config.host, web_config.port
    );
    println!("===========================================\n");
    println!("Press Ctrl+C to stop the server");

    // Start server (blocks until shutdown)
    server.start().await?;

    Ok(())
}
