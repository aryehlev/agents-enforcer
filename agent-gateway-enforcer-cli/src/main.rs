//! Agent Gateway Enforcer - Unified CLI
//!
//! This is the main CLI application that provides a consistent interface across all platforms.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;

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
        #[arg(long, default_value = "0.0.0.0:9090")]
        metrics_port: SocketAddr,
        
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
        config: Option<String>,
    },
    
    /// Show enforcer status
    Status,
    
    /// List available backends
    Backends,
    
    /// Stop the enforcer
    Stop,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Run {
            gateway,
            metrics_port,
            enable_file_enforcement,
            allow_path,
            deny_path,
            default_deny_files,
            config: _,
        } => {
            tracing::info!("Starting agent gateway enforcer");
            tracing::info!("Gateways: {:?}", gateway);
            tracing::info!("Metrics endpoint: {}", metrics_port);
            
            if enable_file_enforcement {
                tracing::info!("File enforcement enabled");
                if default_deny_files {
                    tracing::info!("File policy: allowlist mode");
                    tracing::info!("Allowed paths: {:?}", allow_path);
                } else {
                    tracing::info!("File policy: blocklist mode");
                    tracing::info!("Denied paths: {:?}", deny_path);
                }
            }
            
            // TODO: Initialize backend registry and start enforcement
            tracing::warn!("Backend initialization not yet implemented");
            
            // Keep running
            tokio::signal::ctrl_c().await?;
            tracing::info!("Shutting down");
        }
        
        Commands::Status => {
            println!("Status command not yet implemented");
        }
        
        Commands::Backends => {
            println!("Available backends:");
            #[cfg(target_os = "linux")]
            println!("  - ebpf-linux (Linux eBPF)");
            #[cfg(target_os = "macos")]
            println!("  - macos-desktop (macOS Desktop)");
            #[cfg(target_os = "windows")]
            println!("  - windows-desktop (Windows Desktop)");
        }
        
        Commands::Stop => {
            println!("Stop command not yet implemented");
        }
    }
    
    Ok(())
}
