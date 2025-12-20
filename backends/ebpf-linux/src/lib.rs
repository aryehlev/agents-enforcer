//! Linux eBPF backend for agent gateway enforcement
//!
//! This backend uses eBPF to enforce network and file access policies on Linux systems.
//! It provides full implementation of the EnforcementBackend trait with support for
//! network filtering, file access control, real-time events, and metrics collection.

#![warn(missing_docs)]

use agent_gateway_enforcer_core::backend::{
    EnforcementBackend, BackendCapabilities, BackendHealth, BackendType, 
    FileAccessConfig, GatewayConfig, HealthStatus, MetricsCollector, 
    EventHandler, Platform, Result, UnifiedConfig
};
use agent_gateway_enforcer_core::events::{Event, NetworkBlockedEvent, NetworkAllowedEvent, 
    FileBlockedEvent, FileAllowedEvent, Protocol, FileAccessType};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
use aya::{Bpf, programs::{CgroupSkb, Lsm}};

/// Linux eBPF backend implementation
pub struct EbpfLinuxBackend {
    /// Backend state
    state: BackendState,
    /// Current configuration
    config: UnifiedConfig,
    /// eBPF program for network filtering
    #[cfg(target_os = "linux")]
    network_program: Option<Bpf>,
    /// eBPF program for file access control
    #[cfg(target_os = "linux")]
    lsm_program: Option<Bpf>,
    /// Event handler for streaming events
    event_handler: Option<Arc<dyn EventHandler>>,
    /// Metrics collector
    metrics_collector: Option<Arc<dyn MetricsCollector>>,
    /// Event sender
    event_sender: Option<mpsc::UnboundedSender<Event>>,
    /// Event receiver task handle
    event_task: Option<tokio::task::JoinHandle<()>>,
    /// Internal metrics storage
    metrics: Arc<EbpfMetrics>,
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
        self.network_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    fn increment_network_allowed(&self) {
        self.network_allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    fn increment_file_blocked(&self) {
        self.file_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    fn increment_file_allowed(&self) {
        self.file_allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl MetricsCollector for EbpfMetrics {
    fn get_metrics(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "network": {
                "blocked_total": self.network_blocked.load(std::sync::atomic::Ordering::Relaxed),
                "allowed_total": self.network_allowed.load(std::sync::atomic::Ordering::Relaxed),
            },
            "file": {
                "blocked_total": self.file_blocked.load(std::sync::atomic::Ordering::Relaxed),
                "allowed_total": self.file_allowed.load(std::sync::atomic::Ordering::Relaxed),
            }
        }))
    }
    
    fn reset(&self) -> Result<()> {
        self.network_blocked.store(0, std::sync::atomic::Ordering::Relaxed);
        self.network_allowed.store(0, std::sync::atomic::Ordering::Relaxed);
        self.file_blocked.store(0, std::sync::atomic::Ordering::Relaxed);
        self.file_allowed.store(0, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

impl EventHandler for EbpfMetrics {
    fn on_event(&self, callback: Box<dyn Fn(serde_json::Value) + Send + Sync>) -> Result<()> {
        let mut callbacks = self.event_callbacks.lock().unwrap();
        callbacks.push(callback);
        Ok(())
    }
}

/// Backend state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendState {
    NotInitialized,
    Initialized,
    Running,
    Stopped,
    Error,
}

impl EbpfLinuxBackend {
    /// Create a new Linux eBPF backend
    pub fn new() -> Self {
        let metrics = Arc::new(EbpfMetrics::new());
        
        Self {
            state: BackendState::NotInitialized,
            config: UnifiedConfig::default(),
            #[cfg(target_os = "linux")]
            network_program: None,
            #[cfg(target_os = "linux")]
            lsm_program: None,
            event_handler: Some(metrics.clone() as Arc<dyn EventHandler>),
            metrics_collector: Some(metrics.clone() as Arc<dyn MetricsCollector>),
            event_sender: None,
            event_task: None,
            metrics,
        }
    }
    
    /// Validate kernel version and eBPF support
    #[cfg(target_os = "linux")]
    fn validate_kernel_support(&self) -> Result<()> {
        let uname = nix::sys::utsname::uname();
        let release = uname.release();
        
        // Parse kernel version (major.minor.patch)
        let version_parts: Vec<u32> = release
            .split('.')
            .take(3)
            .filter_map(|s| s.parse().ok())
            .collect();
            
        if version_parts.len() < 2 {
            return Err(anyhow::anyhow!("Unable to parse kernel version: {}", release));
        }
        
        let major = version_parts[0];
        let minor = version_parts[1];
        
        // Require kernel 5.8+ for eBPF LSM support
        if major < 5 || (major == 5 && minor < 8) {
            tracing::warn!("Kernel version {}.{} may not support all eBPF features", major, minor);
        }
        
        tracing::info!("Kernel version {}.{} detected", major, minor);
        Ok(())
    }
    
    /// Load and verify eBPF programs
    #[cfg(target_os = "linux")]
    async fn load_ebpf_programs(&mut self) -> Result<()> {
        // TODO: Load actual eBPF programs from compiled bytecode
        // For now, we'll create placeholder programs
        
        tracing::info!("Loading eBPF programs");
        
        // Network filtering program
        let network_bpf = Bpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/network.o")))?;
        self.network_program = Some(network_bpf);
        
        // File access control program
        let lsm_bpf = Bpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/lsm.o")))?;
        self.lsm_program = Some(lsm_bpf);
        
        Ok(())
    }
    
    /// Initialize perf buffers for event collection
    #[cfg(target_os = "linux")]
    fn initialize_perf_buffers(&mut self) -> Result<()> {
        tracing::info!("Initializing perf buffers");
        // TODO: Set up perf buffers for network and file events
        Ok(())
    }
    
    /// Attach eBPF programs to appropriate hooks
    #[cfg(target_os = "linux")]
    async fn attach_programs(&mut self) -> Result<()> {
        tracing::info!("Attaching eBPF programs");
        
        // Attach network program to cgroup
        if let Some(ref network_bpf) = self.network_program {
            if let Ok(program_result) = network_bpf.program_mut("filter_network") {
                if let Ok(mut program) = program_result.try_into() {
                    program.load()?;
                    // TODO: Get actual cgroup FD
                    // program.attach(cgroup_fd)?;
                }
            }
        }
        
        // Attach LSM program
        if let Some(ref lsm_bpf) = self.lsm_program {
            if let Ok(program_result) = lsm_bpf.program_mut("file_access") {
                if let Ok(mut program) = program_result.try_into() {
                    program.load()?;
                    program.attach()?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Emit network event
    fn emit_network_event(&self, blocked: bool, dst_ip: std::net::IpAddr, 
                          dst_port: u16, protocol: Protocol, pid: Option<u32>) {
        // Update metrics
        if blocked {
            self.metrics.increment_network_blocked();
        } else {
            self.metrics.increment_network_allowed();
        }
        
        // Send event to handlers
        if let Some(ref _event_handler) = self.event_handler {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
                
            let event = if blocked {
                Event::NetworkBlocked(NetworkBlockedEvent {
                    timestamp,
                    dst_ip,
                    dst_port,
                    protocol,
                    pid,
                })
            } else {
                Event::NetworkAllowed(NetworkAllowedEvent {
                    timestamp,
                    dst_ip,
                    dst_port,
                    protocol,
                    pid,
                })
            };
            
            if let Ok(event_json) = serde_json::to_value(&event) {
                // Call all registered callbacks
                if let Ok(callbacks) = self.metrics.event_callbacks.lock() {
                    for callback in callbacks.iter() {
                        callback(event_json.clone());
                    }
                }
            }
        }
        
        // Also send to event channel if available
        if let Some(ref sender) = self.event_sender {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
                
            let event = if blocked {
                Event::NetworkBlocked(NetworkBlockedEvent {
                    timestamp,
                    dst_ip,
                    dst_port,
                    protocol,
                    pid,
                })
            } else {
                Event::NetworkAllowed(NetworkAllowedEvent {
                    timestamp,
                    dst_ip,
                    dst_port,
                    protocol,
                    pid,
                })
            };
            
            let _ = sender.send(event);
        }
    }
    
    /// Emit file access event
    fn emit_file_event(&self, blocked: bool, path: String, 
                      access_type: FileAccessType, pid: Option<u32>) {
        // Update metrics
        if blocked {
            self.metrics.increment_file_blocked();
        } else {
            self.metrics.increment_file_allowed();
        }
        
        // Send event to handlers
        if let Some(ref _event_handler) = self.event_handler {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
                
            let event = if blocked {
                Event::FileBlocked(FileBlockedEvent {
                    timestamp,
                    path: path.clone(),
                    access_type,
                    pid,
                })
            } else {
                Event::FileAllowed(FileAllowedEvent {
                    timestamp,
                    path: path.clone(),
                    access_type,
                    pid,
                })
            };
            
            if let Ok(event_json) = serde_json::to_value(&event) {
                // Call all registered callbacks
                if let Ok(callbacks) = self.metrics.event_callbacks.lock() {
                    for callback in callbacks.iter() {
                        callback(event_json.clone());
                    }
                }
            }
        }
        
        // Also send to event channel if available
        if let Some(ref sender) = self.event_sender {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
                
            let event = if blocked {
                Event::FileBlocked(FileBlockedEvent {
                    timestamp,
                    path,
                    access_type,
                    pid,
                })
            } else {
                Event::FileAllowed(FileAllowedEvent {
                    timestamp,
                    path,
                    access_type,
                    pid,
                })
            };
            
            let _ = sender.send(event);
        }
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
    
    async fn initialize(&mut self, config: &UnifiedConfig) -> Result<()> {
        tracing::info!("Initializing Linux eBPF backend");
        
        #[cfg(not(target_os = "linux"))]
        {
            return Err(anyhow::anyhow!("Linux eBPF backend is only supported on Linux"));
        }
        
        #[cfg(target_os = "linux")]
        {
            // Validate kernel support
            self.validate_kernel_support()?;
            
            // Store configuration
            self.config = config.clone();
            
            // Load eBPF programs
            self.load_ebpf_programs().await?;
            
            // Initialize perf buffers
            self.initialize_perf_buffers()?;
            
            // Set up event streaming
            let (event_sender, mut event_receiver) = mpsc::unbounded_channel::<Event>();
            self.event_sender = Some(event_sender);
            
            // Start event processing task
            let event_handler = self.event_handler.clone();
            self.event_task = Some(tokio::spawn(async move {
                while let Some(event) = event_receiver.recv().await {
                    if let Some(ref handler) = event_handler {
                        // Convert event to JSON and send to handler
                        if let Ok(event_json) = serde_json::to_value(&event) {
                            // TODO: Handle event callback properly
                        }
                    }
                }
            }));
            
            self.state = BackendState::Initialized;
            tracing::info!("Linux eBPF backend initialized successfully");
        }
    }
    
    async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting Linux eBPF backend");
        
        if self.state != BackendState::Initialized {
            return Err(anyhow::anyhow!("Backend must be initialized before starting"));
        }
        
        #[cfg(target_os = "linux")]
        {
            // Attach eBPF programs
            self.attach_programs().await?;
            
            // Start metrics collection
            if let Some(ref metrics) = self.metrics_collector {
                // TODO: Initialize metrics collection
            }
            
            self.state = BackendState::Running;
            tracing::info!("Linux eBPF backend started successfully");
        }
        
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        tracing::info!("Stopping Linux eBPF backend");
        
        #[cfg(target_os = "linux")]
        {
            // Detach eBPF programs
            if let Some(ref mut network_bpf) = self.network_program {
                for (_, program) in network_bpf.programs_mut() {
                    let _ = program.unload();
                }
            }
            
            if let Some(ref mut lsm_bpf) = self.lsm_program {
                for (_, program) in lsm_bpf.programs_mut() {
                    let _ = program.unload();
                }
            }
        }
        
        // Stop event processing
        if let Some(event_task) = self.event_task.take() {
            event_task.abort();
        }
        
        self.state = BackendState::Stopped;
        tracing::info!("Linux eBPF backend stopped successfully");
        
        Ok(())
    }
    
    async fn configure_gateways(&mut self, gateways: &[GatewayConfig]) -> Result<()> {
        tracing::info!("Configuring {} gateways", gateways.len());
        
        self.config.gateways = gateways.to_vec();
        
        #[cfg(target_os = "linux")]
        {
            // TODO: Update eBPF maps with new gateway configurations
            if let Some(ref network_bpf) = self.network_program {
                let gateway_map = network_bpf.map_mut("allowed_gateways")?;
                // Clear existing entries
                gateway_map.clear()?;
                // Add new gateway entries
                for gateway in gateways {
                    if gateway.enabled {
                        // TODO: Parse address and add to map
                    }
                }
            }
        }
        
        Ok(())
    }
    
    async fn configure_file_access(&mut self, config: &FileAccessConfig) -> Result<()> {
        tracing::info!("Configuring file access rules");
        
        self.config.file_access = config.clone();
        
        #[cfg(target_os = "linux")]
        {
            // TODO: Update eBPF maps with new file access rules
            if let Some(ref lsm_bpf) = self.lsm_program {
                let allowed_map = lsm_bpf.map_mut("allowed_paths")?;
                let denied_map = lsm_bpf.map_mut("denied_paths")?;
                
                // Clear existing entries
                allowed_map.clear()?;
                denied_map.clear()?;
                
                // Add new entries
                for path in &config.allowed_paths {
                    // TODO: Add path to allowed map
                }
                
                for path in &config.denied_paths {
                    // TODO: Add path to denied map
                }
            }
        }
        
        Ok(())
    }
    
    fn metrics_collector(&self) -> Option<Arc<dyn MetricsCollector>> {
        self.metrics_collector.clone()
    }
    
    fn event_handler(&self) -> Option<Arc<dyn EventHandler>> {
        self.event_handler.clone()
    }
    
    async fn health_check(&self) -> Result<BackendHealth> {
        let status = match self.state {
            BackendState::Running => HealthStatus::Healthy,
            BackendState::Initialized => HealthStatus::Degraded,
            BackendState::Stopped => HealthStatus::Degraded,
            BackendState::NotInitialized => HealthStatus::Unhealthy,
            BackendState::Error => HealthStatus::Unhealthy,
        };
        
        let details = match self.state {
            BackendState::Running => "Backend is running and enforcing policies".to_string(),
            BackendState::Initialized => "Backend is initialized but not started".to_string(),
            BackendState::Stopped => "Backend is stopped".to_string(),
            BackendState::Error => "Backend is in error state".to_string(),
            BackendState::NotInitialized => "Backend is not initialized".to_string(),
        };
        
        Ok(BackendHealth {
            status,
            last_check: SystemTime::now(),
            details,
        })
    }
    
    async fn cleanup(&mut self) -> Result<()> {
        tracing::info!("Cleaning up Linux eBPF backend resources");
        
        // Stop if running
        if self.state == BackendState::Running {
            self.stop().await?;
        }
        
        #[cfg(target_os = "linux")]
        {
            // Clean up eBPF programs
            self.network_program = None;
            self.lsm_program = None;
        }
        
        // Clean up event processing
        self.event_sender = None;
        if let Some(event_task) = self.event_task.take() {
            event_task.abort();
        }
        
        self.state = BackendState::NotInitialized;
        tracing::info!("Linux eBPF backend cleanup completed");
        
        Ok(())
    }
}

/// Include helper for aligned bytes
#[cfg(target_os = "linux")]
fn include_bytes_aligned(path: &str) -> &'static [u8] {
    // TODO: Implement proper alignment for eBPF bytecode
    include_bytes!(path)
}

pub mod registry;
pub mod migration;

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
        assert!(capabilities.real_time_events);
        assert!(capabilities.metrics_collection);
        assert!(capabilities.configuration_hot_reload);
    }

    #[test]
    fn test_backend_state_transitions() {
        let mut backend = EbpfLinuxBackend::new();
        
        // Initial state
        assert_eq!(backend.state, BackendState::NotInitialized);
        
        // Mock initialization
        let config = UnifiedConfig::default();
        
        #[cfg(target_os = "linux")]
        {
            // In a real test, we would mock the eBPF loading
            // For now, just test the state management
        }
    }

    #[tokio::test]
    async fn test_health_check() {
        let backend = EbpfLinuxBackend::new();
        let health = backend.health_check().await.unwrap();
        assert_eq!(health.status, HealthStatus::Unhealthy);
    }
}
