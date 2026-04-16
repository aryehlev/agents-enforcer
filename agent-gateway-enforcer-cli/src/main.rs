//! Agent Gateway Enforcer - Unified CLI
//!
//! This is the main CLI application that provides a consistent interface across all platforms.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use agent_gateway_enforcer_common::config::{
    BackendType, ConfigTemplate, DefaultPolicy, FileAccessConfig, GatewayConfig, UnifiedConfig,
};
use agent_gateway_enforcer_core::{
    backend::{BackendLifecycleManager, BackendRegistry},
    config::manager::ConfigManager,
    events::bus::EventBus,
    metrics::registry::MetricsRegistry,
    web::{WebConfig, WebServer},
};

// Import platform-specific backend registration functions
#[cfg(all(target_os = "linux", feature = "ebpf-linux"))]
use ebpf_linux::registry as ebpf_registry;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the enforcer
    Run {
        /// Gateway addresses to allow (can be specified multiple times)
        #[arg(short, long)]
        gateway: Vec<SocketAddr>,

        /// Metrics endpoint address
        #[arg(long, default_value = "127.0.0.1:9090")]
        metrics_addr: SocketAddr,

        /// Web dashboard address
        #[arg(long, default_value = "127.0.0.1:8080")]
        web_addr: SocketAddr,

        /// Enable file enforcement
        #[arg(long)]
        enable_file_enforcement: bool,

        /// Allowed file paths (can be specified multiple times)
        #[arg(long)]
        allow_path: Vec<String>,

        /// Denied file paths (can be specified multiple times)
        #[arg(long)]
        deny_path: Vec<String>,

        /// Default deny files (allowlist mode)
        #[arg(long)]
        default_deny_files: bool,

        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Backend type (auto, ebpf_linux, macos_desktop, windows_desktop)
        #[arg(short, long)]
        backend: Option<String>,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Show enforcer status
    Status,

    /// List available backends
    Backends,

    /// Stop the enforcer
    Stop,
}

/// Application state
#[allow(dead_code)]
struct AppState {
    start_time: Instant,
    lifecycle_manager: BackendLifecycleManager,
    config_manager: Arc<RwLock<ConfigManager>>,
    metrics_registry: Arc<MetricsRegistry>,
    event_bus: Arc<EventBus>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            gateway,
            metrics_addr,
            web_addr,
            enable_file_enforcement,
            allow_path,
            deny_path,
            default_deny_files,
            config,
            backend,
            log_level,
        } => {
            // Initialize logging based on log level
            init_logging(&log_level)?;

            info!(
                "Starting Agent Gateway Enforcer v{}",
                env!("CARGO_PKG_VERSION")
            );

            // Load or build configuration
            let unified_config = if let Some(config_path) = &config {
                load_config_from_file(config_path).await?
            } else {
                build_config_from_args(
                    gateway,
                    metrics_addr,
                    web_addr,
                    enable_file_enforcement,
                    allow_path,
                    deny_path,
                    default_deny_files,
                    backend,
                )?
            };

            // Run the application
            run_enforcer(unified_config, config, web_addr).await?;
        }

        Commands::Status => {
            println!("Status command - checking enforcer status...");
            // TODO: Connect to running instance and query status
            println!("This feature requires connecting to a running enforcer instance.");
        }

        Commands::Backends => {
            list_backends();
        }

        Commands::Stop => {
            println!("Stop command - requesting shutdown...");
            // TODO: Send shutdown signal to running instance
            println!("This feature requires connecting to a running enforcer instance.");
        }
    }

    Ok(())
}

/// Initialize logging with the specified level
fn init_logging(log_level: &str) -> Result<()> {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => {
            eprintln!("Invalid log level '{}', using 'info'", log_level);
            tracing::Level::INFO
        }
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .init();

    Ok(())
}

/// Load configuration from file
async fn load_config_from_file(config_path: &PathBuf) -> Result<UnifiedConfig> {
    info!("Loading configuration from {:?}", config_path);

    let mut config_manager = ConfigManager::new(config_path);
    let config = config_manager
        .load()
        .await
        .context("Failed to load configuration file")?;

    info!("Configuration loaded successfully");
    debug!("Configuration: {:?}", config);

    Ok(config)
}

/// Build configuration from CLI arguments
fn build_config_from_args(
    gateways: Vec<SocketAddr>,
    metrics_addr: SocketAddr,
    web_addr: SocketAddr,
    enable_file_enforcement: bool,
    allow_paths: Vec<String>,
    deny_paths: Vec<String>,
    default_deny_files: bool,
    backend: Option<String>,
) -> Result<UnifiedConfig> {
    info!("Building configuration from CLI arguments");

    // Start with default config
    let mut config = ConfigTemplate::Development.generate_config();

    // Configure backend
    config.backend.backend_type = if let Some(backend_str) = backend {
        match backend_str.to_lowercase().as_str() {
            "auto" => BackendType::Auto,
            "ebpf_linux" => BackendType::EbpfLinux,
            "macos_desktop" => BackendType::MacOSDesktop,
            "windows_desktop" => BackendType::WindowsDesktop,
            _ => {
                warn!("Unknown backend type '{}', using auto-detect", backend_str);
                BackendType::Auto
            }
        }
    } else {
        BackendType::Auto
    };

    // Configure gateways
    config.gateways = gateways
        .into_iter()
        .map(|addr| GatewayConfig {
            address: addr.to_string(),
            description: Some(format!("Gateway at {}", addr)),
            protocols: vec![],
            enabled: true,
            priority: 0,
            tags: vec![],
        })
        .collect();

    // Configure file access
    config.file_access = FileAccessConfig {
        enabled: enable_file_enforcement,
        default_policy: if default_deny_files {
            DefaultPolicy::Deny
        } else {
            DefaultPolicy::Allow
        },
        rules: vec![],
        protected_paths: vec![],
        allowed_extensions: allow_paths,
        monitored_processes: deny_paths,
    };

    // Configure metrics
    let port = metrics_addr.port();
    config.metrics.enabled = true;
    config.metrics.port = port;

    // Configure web dashboard
    let (web_host, web_port) = (web_addr.ip().to_string(), web_addr.port());
    config.ui.web_dashboard.enabled = true;
    config.ui.web_dashboard.host = web_host;
    config.ui.web_dashboard.port = web_port;

    info!("Configuration built from CLI arguments");
    debug!("Backend type: {:?}", config.backend.backend_type);
    debug!("Gateways: {} configured", config.gateways.len());
    debug!("File enforcement: {}", config.file_access.enabled);
    debug!("Metrics port: {}", config.metrics.port);
    debug!(
        "Web dashboard: {}:{}",
        config.ui.web_dashboard.host, config.ui.web_dashboard.port
    );

    Ok(config)
}

/// Run the enforcer with the given configuration
async fn run_enforcer(
    config: UnifiedConfig,
    config_path: Option<PathBuf>,
    web_addr: SocketAddr,
) -> Result<()> {
    info!("Initializing enforcer components...");

    // Initialize backend registry and register available backends
    let mut registry = BackendRegistry::new();

    // Register platform-specific backends
    #[cfg(all(target_os = "linux", feature = "ebpf-linux"))]
    {
        info!("Registering Linux eBPF backend...");
        if let Err(e) = ebpf_registry::register_backend(&mut registry) {
            warn!("Failed to register eBPF backend: {}", e);
        }
    }

    let registry = Arc::new(registry);
    info!("Backend registry initialized");

    // List available backends
    let available_backends = registry.list_available();
    if available_backends.is_empty() {
        warn!("No backends are currently registered!");
        warn!("This is expected if platform-specific backends haven't been compiled yet.");
    } else {
        info!("Available backends:");
        for backend_info in &available_backends {
            info!(
                "  - {:?} (platform: {:?})",
                backend_info.backend_type, backend_info.platform
            );
        }
    }

    // Initialize lifecycle manager
    let lifecycle_manager = BackendLifecycleManager::new(registry.clone());
    info!("Lifecycle manager initialized");

    // Initialize metrics system
    let metrics_registry =
        Arc::new(MetricsRegistry::new_default().context("Failed to initialize metrics registry")?);
    info!("Metrics system initialized");

    // Initialize event bus
    let event_bus = Arc::new(EventBus::new(1000));
    info!("Event bus initialized");

    // Initialize config manager
    let config_path =
        config_path.unwrap_or_else(|| PathBuf::from("/tmp/agent-gateway-enforcer.yaml"));
    let config_manager = Arc::new(RwLock::new(ConfigManager::new(&config_path)));
    {
        let cm = config_manager.write().await;
        cm.update_current(config.clone()).await?;
    }
    info!("Configuration manager initialized");

    // Create application state
    let app_state = Arc::new(AppState {
        start_time: Instant::now(),
        lifecycle_manager,
        config_manager: config_manager.clone(),
        metrics_registry: metrics_registry.clone(),
        event_bus: event_bus.clone(),
    });

    // Start the backend
    info!("Starting backend: {:?}", config.backend.backend_type);
    match app_state
        .lifecycle_manager
        .auto_start(&convert_to_backend_config(&config))
        .await
    {
        Ok(_) => {
            info!("Backend started successfully");
        }
        Err(e) => {
            warn!("Failed to start backend: {}", e);
            warn!("This is expected if platform-specific backends haven't been implemented yet.");
            warn!("The web server will still start for status/metrics.");
        }
    }

    // Start web server in background
    let web_config = WebConfig {
        host: web_addr.ip().to_string(),
        port: web_addr.port(),
        enable_cors: true,
        static_dir: "agent-gateway-enforcer-core/static".to_string(),
    };

    let web_server = WebServer::new(
        web_config.clone(),
        config_manager.clone(),
        metrics_registry.clone(),
        event_bus.clone(),
    );

    info!(
        "Starting web server on {}:{}",
        web_config.host, web_config.port
    );

    let web_handle = tokio::spawn(async move {
        if let Err(e) = web_server.start().await {
            error!("Web server error: {}", e);
        }
    });

    // Start metrics server
    let metrics_port = config.metrics.port;
    let metrics_registry_clone = metrics_registry.clone();
    let metrics_handle = tokio::spawn(async move {
        if let Err(e) = run_metrics_server(metrics_port, metrics_registry_clone).await {
            error!("Metrics server error: {}", e);
        }
    });

    info!("Agent Gateway Enforcer is running");
    info!(
        "  Web dashboard: http://{}:{}",
        web_config.host, web_config.port
    );
    info!(
        "  Metrics endpoint: http://127.0.0.1:{}/metrics",
        metrics_port
    );
    info!("Press Ctrl+C to shutdown");

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C)");
        }
        _ = web_handle => {
            warn!("Web server terminated unexpectedly");
        }
        _ = metrics_handle => {
            warn!("Metrics server terminated unexpectedly");
        }
    }

    // Graceful shutdown
    info!("Shutting down...");

    // Stop the backend
    if let Err(e) = app_state.lifecycle_manager.stop_current_backend().await {
        error!("Error stopping backend: {}", e);
    } else {
        info!("Backend stopped");
    }

    info!("Shutdown complete");
    Ok(())
}

/// Run the metrics server
async fn run_metrics_server(port: u16, metrics_registry: Arc<MetricsRegistry>) -> Result<()> {
    use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};

    let app = Router::new()
        .route(
            "/metrics",
            get({
                let metrics_registry = metrics_registry.clone();
                move || {
                    let metrics_registry = metrics_registry.clone();
                    async move {
                        match metrics_registry.global_metrics().export_prometheus() {
                            Ok(metrics) => (StatusCode::OK, metrics).into_response(),
                            Err(e) => {
                                error!("Failed to export metrics: {}", e);
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Failed to export metrics",
                                )
                                    .into_response()
                            }
                        }
                    }
                }
            }),
        )
        .route("/health", get(|| async { (StatusCode::OK, "OK") }));

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind metrics server to {}", addr))?;

    info!("Metrics server listening on {}", addr);

    axum::serve(listener, app)
        .await
        .context("Metrics server error")?;

    Ok(())
}

/// Convert UnifiedConfig to backend-specific config
fn convert_to_backend_config(
    config: &UnifiedConfig,
) -> agent_gateway_enforcer_core::backend::UnifiedConfig {
    use agent_gateway_enforcer_core::backend::{
        FileAccessConfig as BackendFileAccessConfig, GatewayConfig as BackendGatewayConfig,
        UnifiedConfig as BackendConfig,
    };

    BackendConfig {
        gateways: config
            .gateways
            .iter()
            .map(|g| {
                // Parse address to get IP and port
                let parts: Vec<&str> = g.address.split(':').collect();
                let (address, port) = if parts.len() == 2 {
                    (parts[0].to_string(), parts[1].parse::<u16>().unwrap_or(443))
                } else {
                    (g.address.clone(), 443)
                };

                BackendGatewayConfig {
                    address,
                    port,
                    enabled: g.enabled,
                    description: g.description.clone(),
                }
            })
            .collect(),
        file_access: BackendFileAccessConfig {
            allowed_paths: config.file_access.allowed_extensions.clone(),
            denied_paths: config.file_access.monitored_processes.clone(),
            default_deny: matches!(config.file_access.default_policy, DefaultPolicy::Deny),
        },
        backend_settings: serde_json::Value::Null,
    }
}

/// List available backends
fn list_backends() {
    println!("Available backends:");

    #[cfg(target_os = "linux")]
    println!("  - ebpf_linux (Linux eBPF)");

    #[cfg(target_os = "macos")]
    println!("  - macos_desktop (macOS Desktop)");

    #[cfg(target_os = "windows")]
    println!("  - windows_desktop (Windows Desktop)");

    println!("\nNote: Backends may not be compiled/available on all platforms.");
    println!("Use --backend auto to auto-detect the appropriate backend.");
}
