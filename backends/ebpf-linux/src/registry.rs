//! Linux eBPF backend factory and registration
//!
//! This module provides the factory for creating Linux eBPF backend instances
//! and registers the backend with the registry.

use agent_gateway_enforcer_core::backend::{BackendFactory, BackendInfo, BackendRegistry, BackendType, Platform, BackendCapabilities, Result, EnforcementBackend};
use crate::EbpfLinuxBackend;
use std::sync::Arc;

/// Factory for creating Linux eBPF backend instances
pub struct EbpfLinuxBackendFactory;

impl BackendFactory for EbpfLinuxBackendFactory {
    fn create(&self) -> Result<Arc<dyn EnforcementBackend>> {
        Ok(Arc::new(EbpfLinuxBackend::new()))
    }

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
}

/// Register the Linux eBPF backend with a registry
pub fn register_backend(registry: &mut BackendRegistry) -> Result<()> {
    let factory = EbpfLinuxBackendFactory;
    let info = BackendInfo {
        backend_type: factory.backend_type(),
        platform: factory.platform(),
        capabilities: factory.capabilities(),
    };

    registry.register_factory(info.backend_type.clone(), Box::new(factory));
    tracing::info!("Linux eBPF backend registered successfully");
    Ok(())
}

/// Initialize and register the Linux eBPF backend with the default registry
pub async fn init() -> Result<Arc<dyn EnforcementBackend>> {
    let mut registry = BackendRegistry::new();
    register_backend(&mut registry)?;

    // Create and return a backend instance
    registry.get_backend(&BackendType::EbpfLinux).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_gateway_enforcer_core::backend::BackendRegistry;

    #[test]
    fn test_backend_factory() {
        let factory = EbpfLinuxBackendFactory;
        assert_eq!(factory.backend_type(), BackendType::EbpfLinux);
        assert_eq!(factory.platform(), Platform::Linux);
        
        let capabilities = factory.capabilities();
        assert!(capabilities.network_filtering);
        assert!(capabilities.file_access_control);
        assert!(capabilities.real_time_events);
        assert!(capabilities.metrics_collection);
        assert!(capabilities.configuration_hot_reload);
    }

    #[test]
    fn test_backend_creation() {
        let factory = EbpfLinuxBackendFactory;
        let backend = factory.create().unwrap();
        assert_eq!(backend.backend_type(), BackendType::EbpfLinux);
        assert_eq!(backend.platform(), Platform::Linux);
    }

    #[test]
    fn test_backend_registration() {
        let mut registry = BackendRegistry::new();
        
        // Register the backend
        register_backend(&mut registry).unwrap();
        
        // Verify it was registered
        assert!(registry.has_backend(&BackendType::EbpfLinux));
        
        // Find our backend in available list
        let available = registry.list_available();
        let our_backend = available.iter().find(|info| info.backend_type == BackendType::EbpfLinux);
        assert!(our_backend.is_some());
        assert_eq!(our_backend.unwrap().backend_type, BackendType::EbpfLinux);
    }
}