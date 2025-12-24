//! Common test utilities and mock backends for integration tests

use agent_gateway_enforcer_core::backend::{
    BackendCapabilities, BackendHealth, BackendType, EnforcementBackend, FileAccessConfig,
    GatewayConfig, HealthStatus, Platform, UnifiedConfig,
};
use agent_gateway_enforcer_core::backend::{EventHandler, MetricsCollector};
use anyhow::Result;
use std::sync::Arc;
use std::sync::RwLock;

/// Mock backend for testing
pub struct MockBackend {
    backend_type: BackendType,
    platform: Platform,
    initialized: RwLock<bool>,
    started: RwLock<bool>,
    config: RwLock<Option<UnifiedConfig>>,
    gateways: RwLock<Vec<GatewayConfig>>,
    file_access: RwLock<Option<FileAccessConfig>>,
    health_status: RwLock<HealthStatus>,
    operation_log: Arc<RwLock<Vec<String>>>,
}

impl MockBackend {
    /// Create a new mock backend
    pub fn new(backend_type: BackendType, platform: Platform) -> Self {
        Self {
            backend_type,
            platform,
            initialized: RwLock::new(false),
            started: RwLock::new(false),
            config: RwLock::new(None),
            gateways: RwLock::new(Vec::new()),
            file_access: RwLock::new(None),
            health_status: RwLock::new(HealthStatus::Unknown),
            operation_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a healthy mock backend
    pub fn healthy(backend_type: BackendType, platform: Platform) -> Self {
        let backend = Self::new(backend_type, platform);
        *backend.health_status.write().unwrap() = HealthStatus::Healthy;
        backend
    }

    /// Create a mock backend that fails health checks
    pub fn unhealthy(backend_type: BackendType, platform: Platform) -> Self {
        let backend = Self::new(backend_type, platform);
        *backend.health_status.write().unwrap() = HealthStatus::Unhealthy;
        backend
    }

    /// Check if backend was initialized
    pub fn was_initialized(&self) -> bool {
        *self.initialized.read().unwrap()
    }

    /// Check if backend was started
    pub fn was_started(&self) -> bool {
        *self.started.read().unwrap()
    }

    /// Get operation log
    pub fn get_operations(&self) -> Vec<String> {
        self.operation_log.read().unwrap().clone()
    }

    /// Clear operation log
    pub fn clear_operations(&self) {
        self.operation_log.write().unwrap().clear();
    }

    fn log_operation(&self, operation: String) {
        self.operation_log.write().unwrap().push(operation);
    }
}

impl EnforcementBackend for MockBackend {
    fn backend_type(&self) -> BackendType {
        self.backend_type.clone()
    }

    fn platform(&self) -> Platform {
        self.platform
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
        self.log_operation("initialize".to_string());
        *self.initialized.write().unwrap() = true;
        *self.config.write().unwrap() = Some(config.clone());
        *self.health_status.write().unwrap() = HealthStatus::Healthy;
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.log_operation("start".to_string());
        if !*self.initialized.read().unwrap() {
            return Err(anyhow::anyhow!("Backend not initialized"));
        }
        *self.started.write().unwrap() = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.log_operation("stop".to_string());
        *self.started.write().unwrap() = false;
        Ok(())
    }

    fn configure_gateways(&self, gateways: &[GatewayConfig]) -> Result<()> {
        self.log_operation(format!("configure_gateways({})", gateways.len()));
        *self.gateways.write().unwrap() = gateways.to_vec();
        Ok(())
    }

    fn configure_file_access(&self, config: &FileAccessConfig) -> Result<()> {
        self.log_operation("configure_file_access".to_string());
        *self.file_access.write().unwrap() = Some(config.clone());
        Ok(())
    }

    fn metrics_collector(&self) -> Option<Arc<dyn MetricsCollector>> {
        None
    }

    fn event_handler(&self) -> Option<Arc<dyn EventHandler>> {
        None
    }

    fn health_check(&self) -> Result<BackendHealth> {
        self.log_operation("health_check".to_string());
        Ok(BackendHealth {
            status: self.health_status.read().unwrap().clone(),
            last_check: std::time::SystemTime::now(),
            details: format!(
                "Mock backend status: {:?}",
                *self.health_status.read().unwrap()
            ),
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        self.log_operation("cleanup".to_string());
        *self.initialized.write().unwrap() = false;
        *self.started.write().unwrap() = false;
        *self.config.write().unwrap() = None;
        *self.gateways.write().unwrap() = Vec::new();
        *self.file_access.write().unwrap() = None;
        *self.health_status.write().unwrap() = HealthStatus::Unknown;
        Ok(())
    }
}

/// Create a test configuration
pub fn create_test_config() -> UnifiedConfig {
    use agent_gateway_enforcer_common::config::*;

    UnifiedConfig {
        version: "1.0".to_string(),
        backend: BackendConfig {
            backend_type: BackendType::Auto,
            auto_detect: true,
            platform_specific: std::collections::HashMap::new(),
        },
        gateways: vec![GatewayConfig {
            address: "10.0.0.1".to_string(),
            description: Some("Test Gateway".to_string()),
            protocols: vec![NetworkProtocol::Tcp],
            enabled: true,
            priority: 1,
            tags: vec!["test".to_string()],
        }],
        file_access: FileAccessConfig {
            enabled: true,
            default_policy: DefaultPolicy::Allow,
            rules: vec![],
            protected_paths: vec![],
            allowed_extensions: vec![],
            monitored_processes: vec![],
        },
        metrics: MetricsConfig {
            enabled: true,
            port: 9090,
            path: "/metrics".to_string(),
            interval_seconds: 60,
            retention_hours: 24,
            exporters: vec![],
        },
        logging: LoggingConfig {
            level: LogLevel::Info,
            format: LogFormat::Json,
            output: LogOutput::Stdout,
            file_path: None,
            rotate_size_mb: 100,
            max_files: 10,
        },
        ui: UIConfig {
            web_dashboard: WebDashboardConfig {
                enabled: true,
                port: 8080,
                host: "127.0.0.1".to_string(),
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
            },
            native_ui: NativeUIConfig {
                enabled: false,
                show_on_startup: false,
                minimize_to_tray: true,
                theme: UITheme::System,
            },
        },
        agents: vec![],
    }
}

/// Create a minimal test configuration
pub fn create_minimal_config() -> UnifiedConfig {
    UnifiedConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_backend_creation() {
        let backend = MockBackend::new(BackendType::EbpfLinux, Platform::Linux);
        assert_eq!(backend.backend_type(), BackendType::EbpfLinux);
        assert_eq!(backend.platform(), Platform::Linux);
        assert!(!backend.was_initialized());
        assert!(!backend.was_started());
    }

    #[test]
    fn test_mock_backend_initialization() {
        let mut backend = MockBackend::new(BackendType::EbpfLinux, Platform::Linux);
        let config = create_test_config();

        backend.initialize(&config).unwrap();
        assert!(backend.was_initialized());
        assert!(backend.get_operations().contains(&"initialize".to_string()));
    }

    #[test]
    fn test_create_test_config() {
        let config = create_test_config();
        assert_eq!(config.version, "1.0");
        assert!(config.metrics.enabled);
        assert_eq!(config.gateways.len(), 1);
    }
}
