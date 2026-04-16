use anyhow::Result;
use async_trait::async_trait;

pub mod manager;
pub mod migration;
pub mod validators;

pub use manager::*;
pub use migration::*;
pub use validators::*;

// Re-export common types
pub use agent_gateway_enforcer_common::config::UnifiedConfig;

/// Configuration validator trait
#[async_trait]
pub trait ConfigValidator: Send + Sync {
    /// Validate configuration
    async fn validate(&self, config: &UnifiedConfig) -> Result<()>;

    /// Get validator name
    fn name(&self) -> &'static str;
}
