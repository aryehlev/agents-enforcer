use async_trait::async_trait;
use anyhow::Result;

pub mod manager;
pub mod validators;
pub mod migration;

pub use manager::*;
pub use validators::*;
pub use migration::*;

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