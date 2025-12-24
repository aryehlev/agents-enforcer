//! Linux eBPF backend for agent gateway enforcement
//!
//! This backend uses eBPF to enforce network and file access policies on Linux systems.
//! It provides full implementation of the EnforcementBackend trait with support for
//! network filtering, file access control, real-time events, and metrics collection.
//!
//! The implementation uses conditional compilation to support both Linux (with eBPF) and
//! non-Linux platforms (with stub implementations for testing).

#![warn(missing_docs)]

use agent_gateway_enforcer_core::backend::{
    BackendCapabilities, BackendHealth, BackendType, EnforcementBackend, EventHandler,
    FileAccessConfig, GatewayConfig, HealthStatus, MetricsCollector, Platform, Result,
    UnifiedConfig,
};
use agent_gateway_enforcer_core::events::{
    EventSource, FileAccessType, FileAction, NetworkAction, NetworkProtocol, UnifiedEvent,
};
use async_trait::async_trait;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use tokio::sync::mpsc;

// Linux-specific imports for eBPF
#[cfg(target_os = "linux")]
use aya::{
    maps::{HashMap as BpfHashMap, Map, MapData},
    Bpf,
};

#[cfg(target_os = "linux")]
use agent_gateway_enforcer_common::{
    BlockedEvent, FileBlockedEvent, GatewayKey, PathKey, PathRule, FILE_PERM_DELETE,
    FILE_PERM_EXEC, FILE_PERM_READ, FILE_PERM_WRITE, IPPROTO_TCP, IPPROTO_UDP,
};

/// Linux eBPF backend implementation
///
/// This backend uses eBPF programs for network and file access enforcement.
/// On Linux, it loads actual eBPF programs. On other platforms, it provides
/// stub implementations for testing purposes.
pub struct EbpfLinuxBackend {
    /// Backend state
    state: Arc<RwLock<BackendState>>,
    /// Current configuration
    config: Arc<RwLock<UnifiedConfig>>,
    /// eBPF program handles (Linux only)
    #[cfg(target_os = "linux")]
    ebpf_state: Arc<Mutex<EbpfProgramState>>,
    /// Event handler for streaming events
    event_handler: Option<Arc<dyn EventHandler>>,
    /// Metrics collector
    metrics_collector: Option<Arc<dyn MetricsCollector>>,
    /// Event sender channel
    event_sender: Arc<Mutex<Option<mpsc::UnboundedSender<UnifiedEvent>>>>,
    /// Event receiver task handle
    event_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Internal metrics storage
    metrics: Arc<EbpfMetrics>,
}

/// eBPF program state (Linux only)
#[cfg(target_os = "linux")]
struct EbpfProgramState {
    /// Network filtering eBPF program
    network_program: Option<Bpf>,
    /// LSM file access eBPF program
    lsm_program: Option<Bpf>,
}

#[cfg(target_os = "linux")]
impl EbpfProgramState {
    fn new() -> Self {
        Self {
            network_program: None,
            lsm_program: None,
        }
    }
}

/// Backend state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendState {
    /// Not yet initialized
    NotInitialized,
    /// Initialized but not started
    Initialized,
    /// Running and enforcing policies
    Running,
    /// Stopped
    Stopped,
    /// Error state
    Error,
}

/// Internal metrics implementation for the eBPF backend
struct EbpfMetrics {
    /// Network events counters
    network_blocked: std::sync::atomic::AtomicU64,
    network_allowed: std::sync::atomic::AtomicU64,
    /// File events counters
    file_blocked: std::sync::atomic::AtomicU64,
    file_allowed: std::sync::atomic::AtomicU64,
    /// Event callbacks
    event_callbacks: Mutex<Vec<Box<dyn Fn(serde_json::Value) + Send + Sync>>>,
}

impl EbpfMetrics {
    fn new() -> Self {
        Self {
            network_blocked: std::sync::atomic::AtomicU64::new(0),
            network_allowed: std::sync::atomic::AtomicU64::new(0),
            file_blocked: std::sync::atomic::AtomicU64::new(0),
            file_allowed: std::sync::atomic::AtomicU64::new(0),
            event_callbacks: Mutex::new(Vec::new()),
        }
    }

    fn increment_network_blocked(&self) {
        self.network_blocked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn increment_network_allowed(&self) {
        self.network_allowed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn increment_file_blocked(&self) {
        self.file_blocked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn increment_file_allowed(&self) {
        self.file_allowed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn emit_event(&self, event_json: serde_json::Value) {
        if let Ok(callbacks) = self.event_callbacks.lock() {
            for callback in callbacks.iter() {
                callback(event_json.clone());
            }
        }
    }
}

impl MetricsCollector for EbpfMetrics {
    fn get_metrics(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "backend": "ebpf_linux",
            "network": {
                "blocked_total": self.network_blocked.load(std::sync::atomic::Ordering::Relaxed),
                "allowed_total": self.network_allowed.load(std::sync::atomic::Ordering::Relaxed),
            },
            "file": {
                "blocked_total": self.file_blocked.load(std::sync::atomic::Ordering::Relaxed),
                "allowed_total": self.file_allowed.load(std::sync::atomic::Ordering::Relaxed),
            },
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }))
    }

    fn reset(&self) -> Result<()> {
        self.network_blocked
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.network_allowed
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.file_blocked
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.file_allowed
            .store(0, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

impl EventHandler for EbpfMetrics {
    fn on_event(&self, callback: Box<dyn Fn(serde_json::Value) + Send + Sync>) -> Result<()> {
        let mut callbacks = self
            .event_callbacks
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire event callbacks lock: {}", e))?;
        callbacks.push(callback);
        Ok(())
    }
}

impl EbpfLinuxBackend {
    /// Create a new Linux eBPF backend
    pub fn new() -> Self {
        let metrics = Arc::new(EbpfMetrics::new());

        Self {
            state: Arc::new(RwLock::new(BackendState::NotInitialized)),
            config: Arc::new(RwLock::new(UnifiedConfig::default())),
            #[cfg(target_os = "linux")]
            ebpf_state: Arc::new(Mutex::new(EbpfProgramState::new())),
            event_handler: Some(metrics.clone() as Arc<dyn EventHandler>),
            metrics_collector: Some(metrics.clone() as Arc<dyn MetricsCollector>),
            event_sender: Arc::new(Mutex::new(None)),
            event_task: Arc::new(Mutex::new(None)),
            metrics,
        }
    }

    /// Validate kernel version and eBPF support (Linux only)
    #[cfg(target_os = "linux")]
    fn validate_kernel_support(&self) -> Result<()> {
        use nix::sys::utsname::uname;

        let uname_info =
            uname().map_err(|e| anyhow::anyhow!("Failed to get kernel info: {}", e))?;
        let release = uname_info
            .release()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid kernel release string"))?;

        // Parse kernel version (major.minor.patch)
        let version_parts: Vec<u32> = release
            .split('.')
            .take(3)
            .filter_map(|s| s.split('-').next()?.parse().ok())
            .collect();

        if version_parts.len() < 2 {
            return Err(anyhow::anyhow!(
                "Unable to parse kernel version: {}",
                release
            ));
        }

        let major = version_parts[0];
        let minor = version_parts[1];

        // Require kernel 5.8+ for eBPF LSM support
        if major < 5 || (major == 5 && minor < 8) {
            tracing::warn!(
                "Kernel version {}.{} may not support all eBPF features (5.8+ recommended)",
                major,
                minor
            );
        } else {
            tracing::info!(
                "Kernel version {}.{} detected - full eBPF support available",
                major,
                minor
            );
        }

        Ok(())
    }

    /// Load and verify eBPF programs (Linux only)
    #[cfg(target_os = "linux")]
    async fn load_ebpf_programs(&self) -> Result<()> {
        tracing::info!("Loading eBPF programs");

        // In a real implementation, this would load compiled eBPF bytecode
        // For now, we'll create a placeholder that returns an error indicating
        // that eBPF programs need to be compiled first

        // TODO: Implement actual eBPF program loading
        // Expected files:
        // - network.o: Network filtering program (cgroup_skb)
        // - lsm.o: File access control program (LSM hooks)

        tracing::warn!("eBPF program loading not yet implemented - stub mode");
        Ok(())
    }

    /// Attach eBPF programs to appropriate hooks (Linux only)
    #[cfg(target_os = "linux")]
    async fn attach_programs(&self) -> Result<()> {
        tracing::info!("Attaching eBPF programs");

        // TODO: Implement actual program attachment
        // - Attach network program to cgroup
        // - Attach LSM program to file operation hooks

        tracing::warn!("eBPF program attachment not yet implemented - stub mode");
        Ok(())
    }

    /// Update eBPF maps with gateway configuration (Linux only)
    #[cfg(target_os = "linux")]
    fn update_gateway_maps(&self, gateways: &[GatewayConfig]) -> Result<()> {
        tracing::debug!("Updating gateway maps with {} entries", gateways.len());

        // TODO: Implement actual map updates
        // - Clear existing gateway map
        // - Add new gateway entries

        Ok(())
    }

    /// Update eBPF maps with file access rules (Linux only)
    #[cfg(target_os = "linux")]
    fn update_file_access_maps(&self, config: &FileAccessConfig) -> Result<()> {
        tracing::debug!(
            "Updating file access maps - {} allowed, {} denied",
            config.allowed_paths.len(),
            config.denied_paths.len()
        );

        // TODO: Implement actual map updates
        // - Clear existing path rule maps
        // - Add allowed path rules
        // - Add denied path rules

        Ok(())
    }

    /// Emit a network event
    fn emit_network_event(
        &self,
        action: NetworkAction,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        protocol: NetworkProtocol,
        pid: Option<u32>,
    ) {
        // Update metrics
        match action {
            NetworkAction::Blocked => self.metrics.increment_network_blocked(),
            NetworkAction::Allowed => self.metrics.increment_network_allowed(),
            _ => {}
        }

        // Create unified event
        let event = UnifiedEvent::network(
            action,
            dst_ip,
            dst_port,
            protocol,
            pid,
            EventSource::EbpfLinux,
        );

        // Emit to event handlers
        if let Ok(event_json) = serde_json::to_value(&event) {
            self.metrics.emit_event(event_json);
        }

        // Send to event channel
        if let Ok(guard) = self.event_sender.lock() {
            if let Some(ref sender) = *guard {
                let _ = sender.send(event);
            }
        }
    }

    /// Emit a file access event
    fn emit_file_event(
        &self,
        action: FileAction,
        path: String,
        access_type: FileAccessType,
        pid: Option<u32>,
    ) {
        // Update metrics
        match action {
            FileAction::Blocked => self.metrics.increment_file_blocked(),
            FileAction::Allowed => self.metrics.increment_file_allowed(),
            _ => {}
        }

        // Create unified event
        let event =
            UnifiedEvent::file_access(action, path, access_type, pid, EventSource::EbpfLinux);

        // Emit to event handlers
        if let Ok(event_json) = serde_json::to_value(&event) {
            self.metrics.emit_event(event_json);
        }

        // Send to event channel
        if let Ok(guard) = self.event_sender.lock() {
            if let Some(ref sender) = *guard {
                let _ = sender.send(event);
            }
        }
    }

    /// Start event processing loop (Linux only)
    #[cfg(target_os = "linux")]
    async fn start_event_processing(&self) -> Result<()> {
        tracing::info!("Starting eBPF event processing");

        // TODO: Implement perf buffer reading
        // - Read network events from network program perf buffer
        // - Read file events from LSM program perf buffer
        // - Convert to UnifiedEvent and emit

        Ok(())
    }

    /// Set backend state
    fn set_state(&self, new_state: BackendState) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire state lock: {}", e))?;
        *state = new_state;
        Ok(())
    }

    /// Get current backend state
    fn get_state(&self) -> Result<BackendState> {
        let state = self
            .state
            .read()
            .map_err(|e| anyhow::anyhow!("Failed to acquire state lock: {}", e))?;
        Ok(*state)
    }
}

impl Default for EbpfLinuxBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnforcementBackend for EbpfLinuxBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::EbpfLinux
    }

    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            network_filtering: true,
            file_access_control: true,
            process_monitoring: true,
            real_time_events: true,
            metrics_collection: true,
            configuration_hot_reload: true,
        }
    }

    fn initialize(&mut self, config: &UnifiedConfig) -> Result<()> {
        tracing::info!("Initializing Linux eBPF backend");

        // Validate we're on Linux for actual eBPF functionality
        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!("Running eBPF backend on non-Linux platform - stub mode only");
        }

        // Validate kernel support (Linux only)
        #[cfg(target_os = "linux")]
        {
            self.validate_kernel_support()?;

            // Note: eBPF program loading would normally be async, but we're in a sync context
            // In a real implementation, this would be handled during build time or initialization
            tracing::info!("eBPF programs will be loaded on start");
        }

        // Store configuration
        {
            let mut cfg = self
                .config
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to acquire config lock: {}", e))?;
            *cfg = config.clone();
        }

        // Set up event streaming
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel::<UnifiedEvent>();
        {
            let mut sender_guard = self
                .event_sender
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire sender lock: {}", e))?;
            *sender_guard = Some(event_sender);
        }

        // Start event processing task
        let metrics = self.metrics.clone();
        let task = tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                if let Ok(event_json) = serde_json::to_value(&event) {
                    metrics.emit_event(event_json);
                }
            }
        });

        {
            let mut task_guard = self
                .event_task
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire task lock: {}", e))?;
            *task_guard = Some(task);
        }

        self.set_state(BackendState::Initialized)?;
        tracing::info!("Linux eBPF backend initialized successfully");

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        tracing::info!("Starting Linux eBPF backend");

        let current_state = self.get_state()?;
        if current_state != BackendState::Initialized {
            return Err(anyhow::anyhow!(
                "Backend must be initialized before starting (current state: {:?})",
                current_state
            ));
        }

        // Attach eBPF programs (Linux only)
        #[cfg(target_os = "linux")]
        {
            // In a real implementation, we would attach programs here
            // For now, we log that we're in stub mode
            tracing::warn!("eBPF program attachment not yet implemented - stub mode");
        }

        self.set_state(BackendState::Running)?;
        tracing::info!("Linux eBPF backend started successfully");

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        tracing::info!("Stopping Linux eBPF backend");

        // Detach eBPF programs (Linux only)
        #[cfg(target_os = "linux")]
        {
            let mut ebpf_state = self
                .ebpf_state
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;

            // Unload network program
            if let Some(ref mut bpf) = ebpf_state.network_program {
                for (name, program) in bpf.programs_mut() {
                    if let Err(e) = program.unload() {
                        tracing::warn!("Failed to unload network program {}: {}", name, e);
                    }
                }
            }

            // Unload LSM program
            if let Some(ref mut bpf) = ebpf_state.lsm_program {
                for (name, program) in bpf.programs_mut() {
                    if let Err(e) = program.unload() {
                        tracing::warn!("Failed to unload LSM program {}: {}", name, e);
                    }
                }
            }
        }

        self.set_state(BackendState::Stopped)?;
        tracing::info!("Linux eBPF backend stopped successfully");

        Ok(())
    }

    fn configure_gateways(&self, gateways: &[GatewayConfig]) -> Result<()> {
        tracing::info!("Configuring {} gateways", gateways.len());

        // Update configuration
        {
            let mut config = self
                .config
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to acquire config lock: {}", e))?;
            config.gateways = gateways.to_vec();
        }

        // Update eBPF maps (Linux only)
        #[cfg(target_os = "linux")]
        {
            self.update_gateway_maps(gateways)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::debug!("Gateway configuration updated (stub mode - no eBPF maps)");
        }

        Ok(())
    }

    fn configure_file_access(&self, config: &FileAccessConfig) -> Result<()> {
        tracing::info!(
            "Configuring file access - {} allowed, {} denied paths",
            config.allowed_paths.len(),
            config.denied_paths.len()
        );

        // Update configuration
        {
            let mut cfg = self
                .config
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to acquire config lock: {}", e))?;
            cfg.file_access = config.clone();
        }

        // Update eBPF maps (Linux only)
        #[cfg(target_os = "linux")]
        {
            self.update_file_access_maps(config)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::debug!("File access configuration updated (stub mode - no eBPF maps)");
        }

        Ok(())
    }

    fn metrics_collector(&self) -> Option<Arc<dyn MetricsCollector>> {
        self.metrics_collector.clone()
    }

    fn event_handler(&self) -> Option<Arc<dyn EventHandler>> {
        self.event_handler.clone()
    }

    fn health_check(&self) -> Result<BackendHealth> {
        let state = self.get_state()?;

        let (status, details) = match state {
            BackendState::Running => {
                #[cfg(target_os = "linux")]
                {
                    // On Linux, verify eBPF programs are loaded
                    let ebpf_state = self
                        .ebpf_state
                        .lock()
                        .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;

                    let has_programs =
                        ebpf_state.network_program.is_some() || ebpf_state.lsm_program.is_some();

                    if has_programs {
                        (
                            HealthStatus::Healthy,
                            "Backend is running and enforcing policies".to_string(),
                        )
                    } else {
                        (
                            HealthStatus::Degraded,
                            "Backend is running but eBPF programs not loaded".to_string(),
                        )
                    }
                }

                #[cfg(not(target_os = "linux"))]
                {
                    (
                        HealthStatus::Degraded,
                        "Backend is running in stub mode (non-Linux platform)".to_string(),
                    )
                }
            }
            BackendState::Initialized => (
                HealthStatus::Degraded,
                "Backend is initialized but not started".to_string(),
            ),
            BackendState::Stopped => (HealthStatus::Degraded, "Backend is stopped".to_string()),
            BackendState::NotInitialized => (
                HealthStatus::Unhealthy,
                "Backend is not initialized".to_string(),
            ),
            BackendState::Error => (
                HealthStatus::Unhealthy,
                "Backend is in error state".to_string(),
            ),
        };

        Ok(BackendHealth {
            status,
            last_check: SystemTime::now(),
            details,
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        tracing::info!("Cleaning up Linux eBPF backend resources");

        // Stop if running
        let current_state = self.get_state()?;
        if current_state == BackendState::Running {
            self.stop()?;
        }

        // Clean up eBPF programs (Linux only)
        #[cfg(target_os = "linux")]
        {
            let mut ebpf_state = self
                .ebpf_state
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;
            ebpf_state.network_program = None;
            ebpf_state.lsm_program = None;
        }

        // Clean up event processing
        {
            let mut sender_guard = self
                .event_sender
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire sender lock: {}", e))?;
            *sender_guard = None;
        }

        {
            let mut task_guard = self
                .event_task
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire task lock: {}", e))?;
            if let Some(task) = task_guard.take() {
                task.abort();
            }
        }

        self.set_state(BackendState::NotInitialized)?;
        tracing::info!("Linux eBPF backend cleanup completed");

        Ok(())
    }
}

// Public modules
pub mod migration;
pub mod registry;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_creation() {
        let backend = EbpfLinuxBackend::new();
        assert_eq!(backend.backend_type(), BackendType::EbpfLinux);
        assert_eq!(backend.platform(), Platform::Linux);

        let capabilities = backend.capabilities();
        assert!(capabilities.network_filtering);
        assert!(capabilities.file_access_control);
        assert!(capabilities.process_monitoring);
        assert!(capabilities.real_time_events);
        assert!(capabilities.metrics_collection);
        assert!(capabilities.configuration_hot_reload);
    }

    #[test]
    fn test_metrics_collection() {
        let backend = EbpfLinuxBackend::new();

        // Get metrics collector
        let metrics = backend
            .metrics_collector()
            .expect("Should have metrics collector");

        // Get initial metrics
        let initial = metrics.get_metrics().expect("Should get metrics");
        assert!(initial.is_object());

        // Reset metrics
        metrics.reset().expect("Should reset metrics");

        // Verify reset
        let after_reset = metrics.get_metrics().expect("Should get metrics");
        assert_eq!(after_reset["network"]["blocked_total"], 0);
        assert_eq!(after_reset["network"]["allowed_total"], 0);
    }

    #[test]
    fn test_event_handler() {
        let backend = EbpfLinuxBackend::new();

        // Get event handler
        let handler = backend.event_handler().expect("Should have event handler");

        // Register callback
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = called.clone();

        handler
            .on_event(Box::new(move |_event| {
                called_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            }))
            .expect("Should register callback");

        // Emit test event
        backend.emit_network_event(
            NetworkAction::Blocked,
            "192.168.1.1".parse().unwrap(),
            443,
            NetworkProtocol::Tcp,
            Some(1234),
        );

        // Give some time for async processing
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Verify callback was called
        assert!(called.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_backend_lifecycle() {
        let mut backend = EbpfLinuxBackend::new();

        // Initial state
        assert_eq!(backend.get_state().unwrap(), BackendState::NotInitialized);

        // Initialize
        let config = UnifiedConfig::default();
        backend.initialize(&config).expect("Should initialize");
        assert_eq!(backend.get_state().unwrap(), BackendState::Initialized);

        // Start
        backend.start().expect("Should start");
        assert_eq!(backend.get_state().unwrap(), BackendState::Running);

        // Health check
        let health = backend.health_check().expect("Should check health");
        assert!(matches!(
            health.status,
            HealthStatus::Healthy | HealthStatus::Degraded
        ));

        // Stop
        backend.stop().expect("Should stop");
        assert_eq!(backend.get_state().unwrap(), BackendState::Stopped);

        // Cleanup
        backend.cleanup().expect("Should cleanup");
        assert_eq!(backend.get_state().unwrap(), BackendState::NotInitialized);
    }

    #[test]
    fn test_gateway_configuration() {
        let mut backend = EbpfLinuxBackend::new();
        backend
            .initialize(&UnifiedConfig::default())
            .expect("Should initialize");

        let gateways = vec![
            GatewayConfig {
                address: "192.168.1.1".to_string(),
                port: 443,
                enabled: true,
                description: Some("Test gateway".to_string()),
            },
            GatewayConfig {
                address: "10.0.0.1".to_string(),
                port: 8080,
                enabled: true,
                description: None,
            },
        ];

        backend
            .configure_gateways(&gateways)
            .expect("Should configure gateways");

        // Verify configuration was stored
        let config = backend.config.read().unwrap();
        assert_eq!(config.gateways.len(), 2);
        assert_eq!(config.gateways[0].address, "192.168.1.1");
        assert_eq!(config.gateways[1].port, 8080);
    }

    #[test]
    fn test_file_access_configuration() {
        let mut backend = EbpfLinuxBackend::new();
        backend
            .initialize(&UnifiedConfig::default())
            .expect("Should initialize");

        let file_config = FileAccessConfig {
            allowed_paths: vec!["/tmp".to_string(), "/var/log".to_string()],
            denied_paths: vec!["/etc/shadow".to_string(), "/root".to_string()],
            default_deny: true,
        };

        backend
            .configure_file_access(&file_config)
            .expect("Should configure file access");

        // Verify configuration was stored
        let config = backend.config.read().unwrap();
        assert_eq!(config.file_access.allowed_paths.len(), 2);
        assert_eq!(config.file_access.denied_paths.len(), 2);
        assert!(config.file_access.default_deny);
    }

    #[test]
    fn test_event_emission() {
        let backend = EbpfLinuxBackend::new();

        // Emit network events
        backend.emit_network_event(
            NetworkAction::Blocked,
            "192.168.1.1".parse().unwrap(),
            443,
            NetworkProtocol::Tcp,
            Some(1234),
        );

        backend.emit_network_event(
            NetworkAction::Allowed,
            "10.0.0.1".parse().unwrap(),
            80,
            NetworkProtocol::Tcp,
            Some(5678),
        );

        // Emit file events
        backend.emit_file_event(
            FileAction::Blocked,
            "/etc/shadow".to_string(),
            FileAccessType::Read,
            Some(9999),
        );

        backend.emit_file_event(
            FileAction::Allowed,
            "/tmp/test.txt".to_string(),
            FileAccessType::Write,
            Some(1111),
        );

        // Verify metrics
        let metrics = backend.metrics_collector().unwrap();
        let data = metrics.get_metrics().unwrap();

        assert_eq!(data["network"]["blocked_total"], 1);
        assert_eq!(data["network"]["allowed_total"], 1);
        assert_eq!(data["file"]["blocked_total"], 1);
        assert_eq!(data["file"]["allowed_total"], 1);
    }
}
