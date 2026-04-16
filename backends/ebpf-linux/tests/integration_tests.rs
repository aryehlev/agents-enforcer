//! Integration tests for the Linux eBPF backend

use agent_gateway_enforcer_backend_ebpf_linux::{registry, EbpfLinuxBackend};
use agent_gateway_enforcer_core::backend::{
    BackendRegistry, BackendType, EnforcementBackend, GatewayConfig, UnifiedConfig,
};

#[tokio::test]
async fn test_backend_lifecycle() {
    let mut backend = EbpfLinuxBackend::new();

    // Test initial state
    assert_eq!(backend.backend_type(), BackendType::EbpfLinux);
    let health = backend.health_check().await.unwrap();
    assert_eq!(
        health.status,
        agent_gateway_enforcer_core::backend::HealthStatus::Unhealthy
    );

    // Test capabilities
    let capabilities = backend.capabilities();
    assert!(capabilities.network_filtering);
    assert!(capabilities.file_access_control);
    assert!(capabilities.real_time_events);
    assert!(capabilities.metrics_collection);
    assert!(capabilities.configuration_hot_reload);

    // Test configuration
    let config = UnifiedConfig::default();

    #[cfg(target_os = "linux")]
    {
        // On Linux, we should be able to initialize
        let result = backend.initialize(&config).await;
        if result.is_ok() {
            // Test health after initialization
            let health = backend.health_check().await.unwrap();
            assert_eq!(
                health.status,
                agent_gateway_enforcer_core::backend::HealthStatus::Degraded
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux systems, initialization should fail
        assert!(backend.initialize(&config).await.is_err());
    }
}

#[tokio::test]
async fn test_backend_factory() {
    let mut registry = BackendRegistry::new();

    // Register the backend
    registry::register_backend(&mut registry).unwrap();

    // Test that it's registered
    assert!(registry.has_backend(&BackendType::EbpfLinux));

    // Get list of available backends
    let available = registry.list_available();
    let our_backend = available
        .iter()
        .find(|info| info.backend_type == BackendType::EbpfLinux);
    assert!(our_backend.is_some());

    let info = our_backend.unwrap();
    assert_eq!(info.backend_type, BackendType::EbpfLinux);
    assert_eq!(
        info.platform,
        agent_gateway_enforcer_core::backend::Platform::Linux
    );
    assert!(info.capabilities.network_filtering);
    assert!(info.capabilities.file_access_control);
}

#[tokio::test]
async fn test_gateway_configuration() {
    let mut backend = EbpfLinuxBackend::new();

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
            enabled: false,
            description: None,
        },
    ];

    // Test configuration (should work even without initialization)
    let result = backend.configure_gateways(&gateways).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_access_configuration() {
    let mut backend = EbpfLinuxBackend::new();

    let file_config = agent_gateway_enforcer_core::backend::FileAccessConfig {
        allowed_paths: vec!["/tmp/allowed/".to_string(), "/var/log/app.log".to_string()],
        denied_paths: vec!["/etc/shadow".to_string(), "/root/".to_string()],
        default_deny: false,
    };

    // Test configuration (should work even without initialization)
    let result = backend.configure_file_access(&file_config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_metrics_collection() {
    let backend = EbpfLinuxBackend::new();

    // Test that metrics collector is available
    let metrics_collector = backend.metrics_collector();
    assert!(metrics_collector.is_some());

    // Get metrics
    let metrics = metrics_collector.unwrap().get_metrics().unwrap();
    assert!(metrics.is_object());

    // Should have network and file sections
    assert!(metrics.get("network").is_some());
    assert!(metrics.get("file").is_some());
}

#[tokio::test]
async fn test_event_handling() {
    let backend = EbpfLinuxBackend::new();

    // Test that event handler is available
    let event_handler = backend.event_handler();
    assert!(event_handler.is_some());

    // Register a callback
    let callback_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback_called_clone = callback_called.clone();

    let callback = Box::new(move |_event: serde_json::Value| {
        callback_called_clone.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    event_handler.unwrap().on_event(callback).unwrap();

    // Note: In a real test, we would trigger events and verify the callback is called
    // For now, we just verify that registration doesn't fail
}

#[test]
fn test_backend_creation() {
    let backend = EbpfLinuxBackend::new();
    assert_eq!(backend.backend_type(), BackendType::EbpfLinux);
    assert_eq!(
        backend.platform(),
        agent_gateway_enforcer_core::backend::Platform::Linux
    );
}
