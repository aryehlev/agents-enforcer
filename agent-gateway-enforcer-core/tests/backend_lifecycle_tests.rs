//! Integration tests for backend lifecycle management
//!
//! These tests verify the initialization, start, stop, and cleanup
//! operations of enforcement backends.

mod common;

use agent_gateway_enforcer_core::backend::{
    BackendFactory, BackendLifecycleManager, BackendRegistry, BackendType, EnforcementBackend,
    HealthStatus, Platform, UnifiedConfig,
};
use common::{create_test_config, MockBackend};
use std::sync::Arc;

/// Mock factory for testing
struct MockFactory {
    backend_type: BackendType,
    platform: Platform,
}

impl MockFactory {
    fn new(backend_type: BackendType, platform: Platform) -> Self {
        Self {
            backend_type,
            platform,
        }
    }
}

impl BackendFactory for MockFactory {
    fn create(&self) -> agent_gateway_enforcer_core::Result<Arc<dyn EnforcementBackend>> {
        Ok(Arc::new(MockBackend::healthy(
            self.backend_type.clone(),
            self.platform,
        )))
    }

    fn backend_type(&self) -> BackendType {
        self.backend_type.clone()
    }

    fn platform(&self) -> Platform {
        self.platform
    }

    fn capabilities(&self) -> agent_gateway_enforcer_core::backend::BackendCapabilities {
        agent_gateway_enforcer_core::backend::BackendCapabilities {
            network_filtering: true,
            file_access_control: true,
            process_monitoring: true,
            real_time_events: true,
            metrics_collection: true,
            configuration_hot_reload: true,
        }
    }
}

#[tokio::test]
async fn test_lifecycle_manager_creation() {
    let registry = Arc::new(BackendRegistry::new());
    let lifecycle = BackendLifecycleManager::new(registry);

    assert!(!lifecycle.is_running());
}

#[tokio::test]
async fn test_lifecycle_manager_start_backend() {
    let mut registry = BackendRegistry::new();
    let current_platform = Platform::current();

    // Register a mock factory for the current platform
    let backend_type = match current_platform {
        Platform::Linux => BackendType::EbpfLinux,
        Platform::MacOS => BackendType::MacOSDesktop,
        Platform::Windows => BackendType::WindowsDesktop,
        Platform::Unknown => return, // Skip test on unknown platforms
    };

    let factory = Box::new(MockFactory::new(backend_type.clone(), current_platform));
    registry.register_factory(backend_type.clone(), factory);

    let lifecycle = BackendLifecycleManager::new(Arc::new(registry));
    let config = create_test_config();

    // Start the backend
    lifecycle.start_backend(&backend_type, &config).await.unwrap();

    // Verify backend is running
    assert!(lifecycle.is_running());
}

#[tokio::test]
async fn test_lifecycle_manager_auto_start() {
    let mut registry = BackendRegistry::new();
    let current_platform = Platform::current();

    if current_platform == Platform::Unknown {
        return; // Skip test on unknown platforms
    }

    let backend_type = match current_platform {
        Platform::Linux => BackendType::EbpfLinux,
        Platform::MacOS => BackendType::MacOSDesktop,
        Platform::Windows => BackendType::WindowsDesktop,
        Platform::Unknown => return,
    };

    let factory = Box::new(MockFactory::new(backend_type, current_platform));
    registry.register_factory(backend_type, factory);

    let lifecycle = BackendLifecycleManager::new(Arc::new(registry));
    let config = create_test_config();

    // Auto-start should detect the current platform
    lifecycle.auto_start(&config).await.unwrap();

    assert!(lifecycle.is_running());
}

#[tokio::test]
async fn test_lifecycle_manager_stop() {
    let mut registry = BackendRegistry::new();
    let current_platform = Platform::current();

    if current_platform == Platform::Unknown {
        return;
    }

    let backend_type = match current_platform {
        Platform::Linux => BackendType::EbpfLinux,
        Platform::MacOS => BackendType::MacOSDesktop,
        Platform::Windows => BackendType::WindowsDesktop,
        Platform::Unknown => return,
    };

    let factory = Box::new(MockFactory::new(backend_type.clone(), current_platform));
    registry.register_factory(backend_type.clone(), factory);

    let lifecycle = BackendLifecycleManager::new(Arc::new(registry));
    let config = create_test_config();

    // Start and then stop
    lifecycle.start_backend(&backend_type, &config).await.unwrap();
    assert!(lifecycle.is_running());

    lifecycle.stop_current_backend().unwrap();
    assert!(!lifecycle.is_running());
}

#[tokio::test]
async fn test_lifecycle_manager_health_check() {
    let mut registry = BackendRegistry::new();
    let current_platform = Platform::current();

    if current_platform == Platform::Unknown {
        return;
    }

    let backend_type = match current_platform {
        Platform::Linux => BackendType::EbpfLinux,
        Platform::MacOS => BackendType::MacOSDesktop,
        Platform::Windows => BackendType::WindowsDesktop,
        Platform::Unknown => return,
    };

    let factory = Box::new(MockFactory::new(backend_type.clone(), current_platform));
    registry.register_factory(backend_type.clone(), factory);

    let lifecycle = BackendLifecycleManager::new(Arc::new(registry));
    let config = create_test_config();

    // Health check with no backend running
    let health = lifecycle.health_check().await.unwrap();
    assert_eq!(health.status, HealthStatus::Unknown);
    assert_eq!(health.details, "No backend running");

    // Start backend and check health
    lifecycle.start_backend(&backend_type, &config).await.unwrap();
    let health = lifecycle.health_check().await.unwrap();
    assert_eq!(health.status, HealthStatus::Healthy);
}

#[tokio::test]
async fn test_lifecycle_manager_reconfigure() {
    let mut registry = BackendRegistry::new();
    let current_platform = Platform::current();

    if current_platform == Platform::Unknown {
        return;
    }

    let backend_type = match current_platform {
        Platform::Linux => BackendType::EbpfLinux,
        Platform::MacOS => BackendType::MacOSDesktop,
        Platform::Windows => BackendType::WindowsDesktop,
        Platform::Unknown => return,
    };

    let factory = Box::new(MockFactory::new(backend_type.clone(), current_platform));
    registry.register_factory(backend_type.clone(), factory);

    let lifecycle = BackendLifecycleManager::new(Arc::new(registry));
    let mut config = create_test_config();

    // Start backend
    lifecycle.start_backend(&backend_type, &config).await.unwrap();

    // Reconfigure with new settings
    config.gateways.push(agent_gateway_enforcer_common::config::GatewayConfig {
        address: "10.0.0.2".to_string(),
        description: Some("Second Gateway".to_string()),
        protocols: vec![agent_gateway_enforcer_common::config::NetworkProtocol::Udp],
        enabled: true,
        priority: 2,
        tags: vec![],
    });

    lifecycle.reconfigure(&config).unwrap();
    // Reconfigure should succeed without errors
}

#[tokio::test]
async fn test_lifecycle_manager_reconfigure_no_backend() {
    let registry = Arc::new(BackendRegistry::new());
    let lifecycle = BackendLifecycleManager::new(registry);
    let config = create_test_config();

    // Reconfiguring without a running backend should fail
    let result = lifecycle.reconfigure(&config);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_lifecycle_manager_switch_backends() {
    let mut registry = BackendRegistry::new();

    // Register multiple backends (if on supported platform)
    let current_platform = Platform::current();
    if current_platform == Platform::Unknown {
        return;
    }

    let backend_type1 = BackendType::EbpfLinux;
    let backend_type2 = BackendType::MacOSDesktop;

    registry.register_factory(
        backend_type1.clone(),
        Box::new(MockFactory::new(backend_type1.clone(), Platform::Linux)),
    );
    registry.register_factory(
        backend_type2.clone(),
        Box::new(MockFactory::new(backend_type2.clone(), Platform::MacOS)),
    );

    let lifecycle = BackendLifecycleManager::new(Arc::new(registry));
    let config = create_test_config();

    // Start first backend
    lifecycle.start_backend(&backend_type1, &config).await.unwrap();
    assert!(lifecycle.is_running());

    // Switch to second backend (should stop first and start second)
    lifecycle.start_backend(&backend_type2, &config).await.unwrap();
    assert!(lifecycle.is_running());

    // Verify we can get the current backend
    let current = lifecycle.current_backend();
    assert!(current.is_some());
}

#[tokio::test]
async fn test_lifecycle_manager_current_backend() {
    let mut registry = BackendRegistry::new();
    let current_platform = Platform::current();

    if current_platform == Platform::Unknown {
        return;
    }

    let backend_type = match current_platform {
        Platform::Linux => BackendType::EbpfLinux,
        Platform::MacOS => BackendType::MacOSDesktop,
        Platform::Windows => BackendType::WindowsDesktop,
        Platform::Unknown => return,
    };

    let factory = Box::new(MockFactory::new(backend_type.clone(), current_platform));
    registry.register_factory(backend_type.clone(), factory);

    let lifecycle = BackendLifecycleManager::new(Arc::new(registry));
    let config = create_test_config();

    // No backend initially
    assert!(lifecycle.current_backend().is_none());

    // Start backend
    lifecycle.start_backend(&backend_type, &config).await.unwrap();

    // Should have a current backend
    let current = lifecycle.current_backend();
    assert!(current.is_some());
    assert_eq!(current.unwrap().backend_type(), backend_type);
}

#[tokio::test]
async fn test_lifecycle_manager_registry_access() {
    let registry = Arc::new(BackendRegistry::new());
    let lifecycle = BackendLifecycleManager::new(Arc::clone(&registry));

    let lifecycle_registry = lifecycle.registry();
    assert!(Arc::ptr_eq(&registry, &lifecycle_registry));
}
