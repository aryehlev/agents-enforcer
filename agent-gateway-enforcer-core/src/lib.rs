//! Agent Gateway Enforcer - Platform-Agnostic Core
//!
//! This crate provides the core abstractions and interfaces for the agent gateway enforcer.
//! It defines the backend traits, configuration system, and event handling that all
//! platform-specific implementations must support.

#![warn(missing_docs)]

pub mod backend;
pub mod config;
pub mod events;
pub mod metrics;

/// Result type alias for core operations
pub type Result<T> = std::result::Result<T, anyhow::Error>;

#[cfg(test)]
mod tests {
    #[test]
    fn test_core_initialized() {
        // Placeholder test to ensure the crate compiles
        assert!(true);
    }
}
