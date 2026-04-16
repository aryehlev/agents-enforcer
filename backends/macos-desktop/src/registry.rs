//! macOS desktop backend factory and registration
//!
//! This module provides the factory for creating macOS desktop backend instances
//! and registers the backend with the registry.

use crate::MacosDesktopBackend;
use agent_gateway_enforcer_core::backend::{
    BackendCapabilities, BackendFactory, BackendInfo, BackendRegistry, BackendType,
    EnforcementBackend, Platform, Result,
};
use std::sync::Arc;

/// Factory for creating macOS desktop backend instances
pub struct MacosDesktopBackendFactory;

impl BackendFactory for MacosDesktopBackendFactory {
    fn create(&self) -> Result<Arc<dyn EnforcementBackend>> {
        Ok(Arc::new(MacosDesktopBackend::new()))
    }

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
}

/// Register the macOS desktop backend with a registry
pub fn register_backend(registry: &mut BackendRegistry) -> Result<()> {
    let factory = MacosDesktopBackendFactory;
    let info = BackendInfo {
        backend_type: factory.backend_type(),
        platform: factory.platform(),
        capabilities: factory.capabilities(),
    };

    registry.register_factory(info.backend_type.clone(), Box::new(factory));
    tracing::info!("macOS desktop backend registered successfully");
    Ok(())
}

/// Initialize and register the macOS desktop backend with the default registry
pub async fn init() -> Result<Arc<dyn EnforcementBackend>> {
    let mut registry = BackendRegistry::new();
    register_backend(&mut registry)?;

    // Create and return a backend instance
    registry.get_backend(&BackendType::MacOSDesktop).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_gateway_enforcer_core::backend::BackendRegistry;

    #[test]
    fn test_backend_factory() {
        let factory = MacosDesktopBackendFactory;
        assert_eq!(factory.backend_type(), BackendType::MacOSDesktop);
        assert_eq!(factory.platform(), Platform::MacOS);

        let capabilities = factory.capabilities();
        assert!(capabilities.network_filtering);
        assert!(capabilities.file_access_control);
        assert!(capabilities.real_time_events);
        assert!(capabilities.metrics_collection);
        assert!(capabilities.configuration_hot_reload);
    }

    #[test]
    fn test_backend_creation() {
        let factory = MacosDesktopBackendFactory;
        let backend = factory.create().unwrap();
        assert_eq!(backend.backend_type(), BackendType::MacOSDesktop);
        assert_eq!(backend.platform(), Platform::MacOS);
    }

    #[test]
    fn test_backend_registration() {
        let mut registry = BackendRegistry::new();

        // Register the backend
        register_backend(&mut registry).unwrap();

        // Verify it was registered
        assert!(registry.has_backend(&BackendType::MacOSDesktop));

        // Find our backend in available list
        let available = registry.list_available();
        let our_backend = available
            .iter()
            .find(|info| info.backend_type == BackendType::MacOSDesktop);
        assert!(our_backend.is_some());
        assert_eq!(our_backend.unwrap().backend_type, BackendType::MacOSDesktop);
    }
}
