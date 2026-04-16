use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use aya::maps::{HashMap, MapData, PerfEventArray};
use aya::programs::{CgroupSkb, CgroupSkbAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use prometheus::{Counter, Encoder, IntCounterVec, Opts, Registry, TextEncoder};
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use agent_gateway_enforcer_common::{
    BlockedEvent, BlockedKey, FileBlockedEvent, GatewayKey, PathKey, PathRule, PathRuleType,
    FILE_PERM_ALL, FILE_PERM_DELETE, FILE_PERM_EXEC, FILE_PERM_READ, FILE_PERM_WRITE,
};

#[derive(Debug, Parser)]
#[command(name = "agent-gateway-enforcer")]
#[command(about = "eBPF-based gateway enforcer for AI agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the gateway enforcer daemon
    Run {
        /// Gateway address(es) to allow (IP:PORT format)
        #[arg(short, long, required = true)]
        gateway: Vec<String>,

        /// Cgroup path to attach to
        #[arg(short, long, default_value = "/sys/fs/cgroup")]
        cgroup: PathBuf,

        /// Port for metrics HTTP server
        #[arg(short, long, default_value = "9090")]
        metrics_port: u16,

        /// Path to eBPF object file (optional, uses embedded by default)
        #[arg(long)]
        ebpf_path: Option<PathBuf>,

        /// Paths to allow access to (can be specified multiple times)
        #[arg(long)]
        allow_path: Vec<String>,

        /// Paths to deny access to (can be specified multiple times)
        #[arg(long)]
        deny_path: Vec<String>,

        /// Enable default-deny mode for file access (only allowed paths are accessible)
        #[arg(long, default_value = "false")]
        default_deny_files: bool,

        /// Enable LSM BPF file access enforcement
        #[arg(long, default_value = "false")]
        enable_file_enforcement: bool,
    },

    /// Add a gateway to the allow list (requires running daemon)
    AddGateway {
        /// Gateway address (IP:PORT format)
        address: String,
    },

    /// Remove a gateway from the allow list (requires running daemon)
    RemoveGateway {
        /// Gateway address (IP:PORT format)
        address: String,
    },

    /// Show current metrics
    Metrics {
        /// Metrics server address
        #[arg(short, long, default_value = "127.0.0.1:9090")]
        address: String,
    },
}

/// Shared state for the metrics server
struct AppState {
    registry: Registry,
    blocked_counter: IntCounterVec,
    allowed_counter: Counter,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            gateway,
            cgroup,
            metrics_port,
            ebpf_path,
            allow_path,
            deny_path,
            default_deny_files,
            enable_file_enforcement,
        } => {
            run_daemon(
                gateway,
                cgroup,
                metrics_port,
                ebpf_path,
                allow_path,
                deny_path,
                default_deny_files,
                enable_file_enforcement,
            )
            .await
        }
        Commands::AddGateway { address } => {
            // For now, this would need IPC or a management socket
            // In a production version, you'd implement a Unix socket or REST API
            eprintln!("Dynamic gateway management not yet implemented.");
            eprintln!("Restart the daemon with additional --gateway flags.");
            Ok(())
        }
        Commands::RemoveGateway { address } => {
            eprintln!("Dynamic gateway management not yet implemented.");
            eprintln!("Restart the daemon with updated --gateway flags.");
            Ok(())
        }
        Commands::Metrics { address } => {
            // Fetch metrics from the running daemon
            let url = format!("http://{}/metrics", address);
            eprintln!("Fetching metrics from {}", url);
            eprintln!("Use curl or a browser to access the metrics endpoint.");
            Ok(())
        }
    }
}

async fn run_daemon(
    gateways: Vec<String>,
    cgroup_path: PathBuf,
    metrics_port: u16,
    _ebpf_path: Option<PathBuf>,
    allow_paths: Vec<String>,
    deny_paths: Vec<String>,
    default_deny_files: bool,
    enable_file_enforcement: bool,
) -> Result<()> {
    info!("Starting agent-gateway-enforcer daemon");

    // Parse gateway addresses
    let parsed_gateways: Vec<(Ipv4Addr, u16)> = gateways
        .iter()
        .map(|g| parse_gateway_address(g))
        .collect::<Result<Vec<_>>>()
        .context("Failed to parse gateway addresses")?;

    info!("Allowed gateways:");
    for (ip, port) in &parsed_gateways {
        info!("  - {}:{}", ip, port);
    }

    if enable_file_enforcement {
        info!("File access enforcement: ENABLED");
        info!(
            "Default policy: {}",
            if default_deny_files {
                "DENY (allowlist mode)"
            } else {
                "ALLOW (blocklist mode)"
            }
        );
        if !allow_paths.is_empty() {
            info!("Allowed paths:");
            for path in &allow_paths {
                info!("  + {}", path);
            }
        }
        if !deny_paths.is_empty() {
            info!("Denied paths:");
            for path in &deny_paths {
                info!("  - {}", path);
            }
        }
    } else {
        info!("File access enforcement: DISABLED");
    }

    // Load the eBPF program
    // In development, use a placeholder that will be replaced at build time
    #[cfg(debug_assertions)]
    let mut bpf = {
        // Try to load from file first (for development)
        let ebpf_path = std::env::current_dir()?
            .join("target")
            .join("bpf")
            .join("agent-gateway-enforcer.bpf.o");

        if ebpf_path.exists() {
            info!("Loading eBPF from: {}", ebpf_path.display());
            Ebpf::load_file(&ebpf_path).context("Failed to load eBPF program from file")?
        } else {
            bail!(
                "eBPF program not found at {}. Run 'cargo xtask build-ebpf' first.",
                ebpf_path.display()
            );
        }
    };

    #[cfg(not(debug_assertions))]
    let mut bpf = {
        // In release mode, embed the eBPF bytecode
        // This requires the eBPF to be built first
        let ebpf_path = std::env::current_dir()?
            .join("target")
            .join("bpf")
            .join("agent-gateway-enforcer.bpf.o");

        Ebpf::load_file(&ebpf_path).context("Failed to load eBPF program")?
    };

    // Initialize eBPF logging
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Get the program and attach to cgroup
    let program: &mut CgroupSkb = bpf
        .program_mut("agent_gateway_egress")
        .context("Failed to find eBPF program")?
        .try_into()
        .context("Failed to convert to CgroupSkb")?;

    program.load().context("Failed to load eBPF program")?;

    // Open the cgroup
    let cgroup_file = std::fs::File::open(&cgroup_path)
        .with_context(|| format!("Failed to open cgroup: {}", cgroup_path.display()))?;

    program
        .attach(cgroup_file, CgroupSkbAttachType::Egress)
        .context("Failed to attach eBPF program to cgroup")?;

    info!("eBPF program attached to cgroup: {}", cgroup_path.display());

    // Populate the allowed gateways map
    let mut allowed_gateways: HashMap<_, GatewayKey, u8> = HashMap::try_from(
        bpf.map_mut("ALLOWED_GATEWAYS")
            .context("Failed to get map")?,
    )?;

    for (ip, port) in &parsed_gateways {
        let key = GatewayKey::new(u32::from(*ip).to_be(), *port);
        allowed_gateways
            .insert(key, 1, 0)
            .context("Failed to insert gateway")?;
        info!("Added gateway: {}:{}", ip, port);
    }

    // Set up file access enforcement if enabled
    if enable_file_enforcement {
        // Load and attach LSM programs
        use aya::programs::Lsm;

        // Set default policy
        let mut default_deny_map: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("DEFAULT_DENY")
                .context("Failed to get DEFAULT_DENY map")?,
        )?;
        default_deny_map
            .insert(0u32, if default_deny_files { 1u8 } else { 0u8 }, 0)
            .context("Failed to set default policy")?;

        // Populate path rules
        let mut path_rules: HashMap<_, PathKey, PathRule> = HashMap::try_from(
            bpf.map_mut("PATH_RULES")
                .context("Failed to get PATH_RULES map")?,
        )?;

        // Add allowed paths
        for path in &allow_paths {
            let key = PathKey::new(path);
            let rule = PathRule::allow(FILE_PERM_ALL, true); // prefix match, all permissions
            path_rules
                .insert(key, rule, 0)
                .context("Failed to insert allow path rule")?;
            info!("Added allow rule for: {}", path);
        }

        // Add denied paths
        for path in &deny_paths {
            let key = PathKey::new(path);
            let rule = PathRule::deny(FILE_PERM_ALL, true); // prefix match, all permissions
            path_rules
                .insert(key, rule, 0)
                .context("Failed to insert deny path rule")?;
            info!("Added deny rule for: {}", path);
        }

        // Load and attach LSM programs
        let lsm_programs = [
            "file_open_check",
            "file_permission_check",
            "path_unlink_check",
            "path_mkdir_check",
            "path_rmdir_check",
            "bprm_check",
        ];

        for prog_name in lsm_programs {
            if let Ok(prog) = bpf.program_mut(prog_name) {
                if let Ok(lsm) = TryInto::<&mut Lsm>::try_into(prog) {
                    // Get BTF from /sys/kernel/btf/vmlinux
                    let btf = aya::Btf::from_sys_fs().context("Failed to load BTF")?;
                    lsm.load(prog_name, &btf)
                        .context(format!("Failed to load LSM program {}", prog_name))?;
                    lsm.attach()
                        .context(format!("Failed to attach LSM program {}", prog_name))?;
                    info!("Attached LSM program: {}", prog_name);
                }
            }
        }

        info!("File access enforcement configured successfully");
    }

    // Set up Prometheus metrics
    let registry = Registry::new();

    let blocked_counter = IntCounterVec::new(
        Opts::new(
            "agent_gateway_blocked_total",
            "Total number of blocked connection attempts",
        ),
        &["dst_ip", "dst_port", "protocol"],
    )?;

    let allowed_counter = Counter::new(
        "agent_gateway_allowed_total",
        "Total number of allowed connections",
    )?;

    registry.register(Box::new(blocked_counter.clone()))?;
    registry.register(Box::new(allowed_counter.clone()))?;

    let state = Arc::new(AppState {
        registry,
        blocked_counter,
        allowed_counter,
    });

    // Start the metrics HTTP server
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], metrics_port));
    info!("Metrics server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Spawn the metrics server
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            error!("Metrics server error: {}", e);
        }
    });

    // Set up perf event handling for blocked events
    let mut perf_array = PerfEventArray::try_from(
        bpf.map_mut("BLOCKED_EVENTS")
            .context("Failed to get perf array")?,
    )?;

    let cpus = online_cpus().context("Failed to get online CPUs")?;
    let mut perf_buffers = Vec::new();

    for cpu_id in cpus {
        let buf = perf_array
            .open(cpu_id, None)
            .context("Failed to open perf buffer")?;
        perf_buffers.push(buf);
    }

    info!("Daemon running. Press Ctrl+C to stop.");

    // Main event loop
    let mut buffers = (0..perf_buffers.len())
        .map(|_| BytesMut::with_capacity(1024))
        .collect::<Vec<_>>();

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                break;
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                // Poll perf buffers
                for (i, buf) in perf_buffers.iter_mut().enumerate() {
                    if let Ok(events) = buf.read_events(&mut buffers[i]) {
                        for _ in 0..events.read {
                            // Process blocked event
                            if buffers[i].len() >= std::mem::size_of::<BlockedEvent>() {
                                let event: BlockedEvent = unsafe {
                                    std::ptr::read(buffers[i].as_ptr() as *const BlockedEvent)
                                };

                                let dst_ip = Ipv4Addr::from(u32::from_be(event.dst_addr));
                                let protocol = match event.protocol {
                                    6 => "tcp",
                                    17 => "udp",
                                    _ => "other",
                                };

                                state.blocked_counter
                                    .with_label_values(&[
                                        &dst_ip.to_string(),
                                        &event.dst_port.to_string(),
                                        protocol,
                                    ])
                                    .inc();

                                info!(
                                    "Blocked: {} -> {}:{} ({})",
                                    Ipv4Addr::from(u32::from_be(event.src_addr)),
                                    dst_ip,
                                    event.dst_port,
                                    protocol
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    info!("Daemon stopped.");
    Ok(())
}

async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<String, StatusCode> {
    let encoder = TextEncoder::new();
    let metric_families = state.registry.gather();
    let mut buffer = Vec::new();

    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    String::from_utf8(buffer).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn health_handler() -> &'static str {
    "OK"
}

fn parse_gateway_address(addr: &str) -> Result<(Ipv4Addr, u16)> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        bail!("Invalid gateway format '{}'. Expected IP:PORT", addr);
    }

    let ip: Ipv4Addr = parts[0]
        .parse()
        .with_context(|| format!("Invalid IP address: {}", parts[0]))?;

    let port: u16 = parts[1]
        .parse()
        .with_context(|| format!("Invalid port: {}", parts[1]))?;

    Ok((ip, port))
}
