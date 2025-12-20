//! macOS desktop backend for agent gateway enforcement
//!
//! This backend uses macOS system extensions to enforce network and file access policies.

#![warn(missing_docs)]

use agent_gateway_enforcer_core::backend::{Backend, BackendStatus, Platform};
use async_trait::async_trait;

/// macOS desktop backend implementation
pub struct MacosDesktopBackend {
    running: bool,
}

impl MacosDesktopBackend {
    /// Create a new macOS desktop backend
    pub fn new() -> Self {
        Self { running: false }
    }
}

impl Default for MacosDesktopBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Backend for MacosDesktopBackend {
    fn name(&self) -> &str {
        "macos-desktop"
    }
    
    fn platform(&self) -> Platform {
        Platform::MacosDesktop
    }
    
    async fn initialize(&mut self) -> agent_gateway_enforcer_core::Result<()> {
        tracing::info!("Initializing macOS desktop backend");
        // TODO: Initialize system extension
        Ok(())
    }
    
    async fn start(&mut self) -> agent_gateway_enforcer_core::Result<()> {
        tracing::info!("Starting macOS desktop backend");
        self.running = true;
        // TODO: Start system extension
        Ok(())
    }
    
    async fn stop(&mut self) -> agent_gateway_enforcer_core::Result<()> {
        tracing::info!("Stopping macOS desktop backend");
        self.running = false;
        // TODO: Stop system extension
        Ok(())
    }
    
    fn is_running(&self) -> bool {
        self.running
    }
    
    async fn status(&self) -> agent_gateway_enforcer_core::Result<BackendStatus> {
        Ok(BackendStatus {
            running: self.running,
            active_policies: 0,
            metadata: serde_json::json!({
                "platform": "macos",
                "type": "system-extension"
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_creation() {
        let backend = MacosDesktopBackend::new();
        assert_eq!(backend.name(), "macos-desktop");
        assert_eq!(backend.platform(), Platform::MacosDesktop);
        assert!(!backend.is_running());
    }
}
