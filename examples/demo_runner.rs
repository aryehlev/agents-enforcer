use agent_gateway_enforcer_core::backend::{BackendRegistry, BackendType, UnifiedConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     🚀 Agent Gateway Enforcer - Demo Runner             ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // Create backend registry
    let mut registry = BackendRegistry::new();
    println!("📋 Creating backend registry...");

    // Register platform-specific backend
    #[cfg(target_os = "macos")]
    {
        use agent_gateway_enforcer_backend_macos::registry;
        match registry::register_backend(&mut registry) {
            Ok(_) => println!("✅ Registered macOS Desktop backend"),
            Err(e) => println!("⚠️  Failed to register macOS backend: {}", e),
        }
    }

    #[cfg(target_os = "linux")]
    {
        use agent_gateway_enforcer_backend_ebpf_linux::registry;
        match registry::register_backend(&mut registry) {
            Ok(_) => println!("✅ Registered eBPF Linux backend"),
            Err(e) => println!("⚠️  Failed to register Linux backend: {}", e),
        }
    }

    println!();
    println!("📊 Available backends:");
    for info in registry.list_available() {
        println!("   • {:?} on {:?}", info.backend_type, info.platform);
        println!("     Capabilities:");
        println!("       - Network filtering: {}", info.capabilities.network_filtering);
        println!("       - File access control: {}", info.capabilities.file_access_control);
        println!("       - Real-time events: {}", info.capabilities.real_time_events);
    }

    println!();
    println!("🔧 Creating default configuration...");
    let config = UnifiedConfig::default();

    println!("⚙️  Configuration:");
    println!("   • Gateways: {}", config.gateways.len());
    println!("   • File enforcement: {}", config.file_access.allowed_paths.len() > 0);

    // Try to get and initialize a backend
    println!();
    println!("🎯 Attempting to initialize backend...");

    let backend_type = BackendType::EbpfLinux;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let backend_type = BackendType::Auto;

    match registry.get_backend(&backend_type).await {
        Ok(backend) => {
            println!("✅ Backend created successfully!");
            println!("   • Type: {:?}", backend.backend_type());
            println!("   • Platform: {:?}", backend.platform());

            // Initialize the backend
            println!();
            println!("🚀 Initializing backend...");
            // Note: Can't call initialize on Arc<dyn Trait> without interior mutability
            println!("   (Initialization would happen here)");

            println!();
            println!("📊 Backend information:");
            println!("   • Name: {}", backend.name());
            println!("   • Description: {}", backend.description());

            let health = backend.health_check()?;
            println!("   • Health status: {:?}", health.status);
            println!("   • Details: {}", health.details);
        }
        Err(e) => {
            println!("⚠️  Failed to create backend: {}", e);
        }
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  ✨ Demo Complete!                                       ║");
    println!("║                                                          ║");
    println!("║  Next steps:                                             ║");
    println!("║  • View web dashboard: static/index.html                 ║");
    println!("║  • Check docs: HOW_TO_RUN.md                             ║");
    println!("║  • Run tests: cargo test                                 ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    Ok(())
}
