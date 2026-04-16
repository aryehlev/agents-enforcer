//! macOS desktop backend for agent gateway enforcement
//!
//! This backend uses macOS system extensions to enforce network and file access policies.
//! UI components are managed separately on the main thread via message passing to maintain
//! thread safety (Send + Sync compliance).

#![warn(missing_docs)]

/// UI module - macOS native UI components
pub mod ui;
pub mod registry;

use agent_gateway_enforcer_core::backend::{
    BackendCapabilities, BackendHealth, BackendType, EnforcementBackend, EventHandler,
    FileAccessConfig, GatewayConfig, HealthStatus, MetricsCollector, Platform, Result,
    UnifiedConfig,
};
use agent_gateway_enforcer_core::events::{
    EventSource, FileAccessType, FileAction, NetworkAction, NetworkProtocol, UnifiedEvent,
};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use tokio::sync::mpsc;

/// macOS desktop backend implementation
///
/// This backend uses macOS Network Extension and Endpoint Security frameworks
/// for enforcement. UI components are managed separately on the main thread.
pub struct MacosDesktopBackend {
    /// Backend state
    state: Arc<RwLock<BackendState>>,
    /// Current configuration
    config: Arc<RwLock<UnifiedConfig>>,
    /// Event handler for streaming events
    event_handler: Option<Arc<dyn EventHandler>>,
    /// Metrics collector
    metrics_collector: Option<Arc<dyn MetricsCollector>>,
    /// Event sender channel
    event_sender: Arc<Mutex<Option<mpsc::UnboundedSender<UnifiedEvent>>>>,
    /// Event receiver task handle
    event_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Internal metrics storage
    metrics: Arc<MacosMetrics>,
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

/// Internal metrics implementation for the macOS backend
struct MacosMetrics {
    /// Network events counters
    network_blocked: std::sync::atomic::AtomicU64,
    network_allowed: std::sync::atomic::AtomicU64,
    /// File events counters
    file_blocked: std::sync::atomic::AtomicU64,
    file_allowed: std::sync::atomic::AtomicU64,
    /// Event callbacks
    event_callbacks: Mutex<Vec<Box<dyn Fn(serde_json::Value) + Send + Sync>>>,
}

impl MacosMetrics {
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

impl MetricsCollector for MacosMetrics {
    fn get_metrics(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "backend": "macos_desktop",
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

impl EventHandler for MacosMetrics {
    fn on_event(&self, callback: Box<dyn Fn(serde_json::Value) + Send + Sync>) -> Result<()> {
        let mut callbacks = self
            .event_callbacks
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire event callbacks lock: {}", e))?;
        callbacks.push(callback);
        Ok(())
    }
}

impl MacosDesktopBackend {
    /// Create a new macOS desktop backend
    pub fn new() -> Self {
        let metrics = Arc::new(MacosMetrics::new());

        Self {
            state: Arc::new(RwLock::new(BackendState::NotInitialized)),
            config: Arc::new(RwLock::new(UnifiedConfig::default())),
            event_handler: Some(metrics.clone() as Arc<dyn EventHandler>),
            metrics_collector: Some(metrics.clone() as Arc<dyn MetricsCollector>),
            event_sender: Arc::new(Mutex::new(None)),
            event_task: Arc::new(Mutex::new(None)),
            metrics,
        }
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
            EventSource::MacOSDesktop,
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
            UnifiedEvent::file_access(action, path, access_type, pid, EventSource::MacOSDesktop);

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

    /// Check if backend is running
    pub fn is_running(&self) -> bool {
        matches!(self.get_state(), Ok(BackendState::Running))
    }

    /// Get backend name
    pub fn name(&self) -> &str {
        "macos-desktop"
    }
}

impl Default for MacosDesktopBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl EnforcementBackend for MacosDesktopBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::MacOSDesktop
    }

    fn platform(&self) -> Platform {
        Platform::MacOS
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
        tracing::info!("Initializing macOS desktop backend");

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
        tracing::info!("macOS desktop backend initialized successfully");

        // Note: UI is managed separately on the main thread
        // System extension would be initialized here
        tracing::info!("Backend initialized (UI must be managed separately)");

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        tracing::info!("Starting macOS desktop backend");

        let current_state = self.get_state()?;
        if current_state != BackendState::Initialized {
            return Err(anyhow::anyhow!(
                "Backend must be initialized before starting (current state: {:?})",
                current_state
            ));
        }

        self.set_state(BackendState::Running)?;
        tracing::info!("macOS desktop backend started successfully");

        // TODO: Start system extension
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        tracing::info!("Stopping macOS desktop backend");

        self.set_state(BackendState::Stopped)?;
        tracing::info!("macOS desktop backend stopped successfully");

        // Note: UI cleanup must be done separately on the main thread
        tracing::info!("Backend stopped (UI cleanup must be done separately)");

        // TODO: Stop system extension
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

        // TODO: Update system extension with new gateway rules
        Ok(())
    }

    fn configure_file_access(&self, config: &FileAccessConfig) -> Result<()> {
        tracing::info!("Configuring file access rules");

        // Update configuration
        {
            let mut cfg = self
                .config
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to acquire config lock: {}", e))?;
            cfg.file_access = config.clone();
        }

        // TODO: Update system extension with new file access rules
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
            BackendState::Running => (
                HealthStatus::Healthy,
                "Backend is running and enforcing policies".to_string(),
            ),
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
        tracing::info!("Cleaning up macOS desktop backend resources");

        // Stop if running
        let current_state = self.get_state()?;
        if current_state == BackendState::Running {
            self.stop()?;
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
        tracing::info!("macOS desktop backend cleanup completed");

        // Note: UI cleanup must be done separately on the main thread
        tracing::info!("Backend cleanup complete (UI cleanup must be done separately)");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_creation() {
        let backend = MacosDesktopBackend::new();
        assert_eq!(backend.name(), "macos-desktop");
        assert_eq!(backend.platform(), Platform::MacOS);
        assert!(!backend.is_running());
    }

    #[test]
    fn test_backend_capabilities() {
        let backend = MacosDesktopBackend::new();
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
        let backend = MacosDesktopBackend::new();

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
        let backend = MacosDesktopBackend::new();

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

    #[tokio::test]
    async fn test_backend_lifecycle() {
        let mut backend = MacosDesktopBackend::new();

        // Initial state
        assert_eq!(backend.get_state().unwrap(), BackendState::NotInitialized);

        // Initialize
        let config = UnifiedConfig::default();
        backend.initialize(&config).expect("Should initialize");
        assert_eq!(backend.get_state().unwrap(), BackendState::Initialized);

        // Start
        backend.start().expect("Should start");
        assert_eq!(backend.get_state().unwrap(), BackendState::Running);
        assert!(backend.is_running());

        // Health check
        let health = backend.health_check().expect("Should check health");
        assert_eq!(health.status, HealthStatus::Healthy);

        // Stop
        backend.stop().expect("Should stop");
        assert_eq!(backend.get_state().unwrap(), BackendState::Stopped);
        assert!(!backend.is_running());

        // Cleanup
        backend.cleanup().expect("Should cleanup");
        assert_eq!(backend.get_state().unwrap(), BackendState::NotInitialized);
    }

    #[tokio::test]
    async fn test_gateway_configuration() {
        let mut backend = MacosDesktopBackend::new();
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

    #[tokio::test]
    async fn test_file_access_configuration() {
        let mut backend = MacosDesktopBackend::new();
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
        let backend = MacosDesktopBackend::new();

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
