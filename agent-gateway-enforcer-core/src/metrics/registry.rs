//! Metrics registry for unified metrics system

use crate::metrics::{UnifiedMetrics, MetricsSummary};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tracing::{debug, info, warn, error};

/// Metrics registry for managing multiple metrics instances
#[derive(Debug)]
pub struct MetricsRegistry {
    /// Registered metrics instances
    metrics_instances: Arc<RwLock<HashMap<String, RegisteredMetrics>>>,
    /// Global metrics instance
    global_metrics: Arc<UnifiedMetrics>,
    /// Registry configuration
    config: RegistryConfig,
    /// Registry statistics
    stats: Arc<RwLock<RegistryStats>>,
}

/// Registry configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Maximum number of metrics instances
    pub max_instances: usize,
    /// Default retention period for metrics
    pub default_retention: std::time::Duration,
    /// Cleanup interval
    pub cleanup_interval: std::time::Duration,
    /// Enable metrics aggregation
    pub enable_aggregation: bool,
    /// Enable metrics caching
    pub enable_caching: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_instances: 100,
            default_retention: std::time::Duration::from_secs(24 * 60 * 60), // 24 hours
            cleanup_interval: std::time::Duration::from_secs(5 * 60), // 5 minutes
            enable_aggregation: true,
            enable_caching: true,
        }
    }
}

/// Registered metrics information
#[derive(Debug, Clone)]
pub struct RegisteredMetrics {
    /// Metrics instance
    pub metrics: Arc<UnifiedMetrics>,
    /// Instance metadata
    pub metadata: MetricsMetadata,
    /// Registration timestamp
    pub registered_at: chrono::DateTime<chrono::Utc>,
    /// Last access timestamp
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    /// Access count
    pub access_count: u64,
}

/// Metrics metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsMetadata {
    /// Instance name
    pub name: String,
    /// Instance description
    pub description: Option<String>,
    /// Instance tags
    pub tags: HashMap<String, String>,
    /// Instance type
    pub instance_type: MetricsInstanceType,
    /// Component name
    pub component: Option<String>,
    /// Backend name
    pub backend: Option<String>,
}

/// Metrics instance type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricsInstanceType {
    /// Global metrics instance
    Global,
    /// Backend-specific metrics
    Backend,
    /// Component-specific metrics
    Component,
    /// Temporary metrics
    Temporary,
    /// Custom metrics
    Custom,
}

/// Registry statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryStats {
    /// Total registered instances
    pub total_instances: usize,
    /// Active instances
    pub active_instances: usize,
    /// Total registrations
    pub total_registrations: u64,
    /// Total unregistrations
    pub total_unregistrations: u64,
    /// Total lookups
    pub total_lookups: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Last cleanup timestamp
    pub last_cleanup_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

impl MetricsRegistry {
    /// Create a new metrics registry
    pub fn new(config: RegistryConfig) -> crate::Result<Self> {
        let global_metrics = Arc::new(UnifiedMetrics::new()?);

        Ok(Self {
            metrics_instances: Arc::new(RwLock::new(HashMap::new())),
            global_metrics,
            config,
            stats: Arc::new(RwLock::new(RegistryStats::default())),
        })
    }

    /// Create a new metrics registry with default configuration
    pub fn new_default() -> crate::Result<Self> {
        Self::new(RegistryConfig::default())
    }

    /// Register a new metrics instance
    pub async fn register_metrics(
        &self,
        instance_id: String,
        metadata: MetricsMetadata,
    ) -> crate::Result<Arc<UnifiedMetrics>> {
        // Check if we've reached the maximum number of instances
        {
            let instances = self.metrics_instances.read().await;
            if instances.len() >= self.config.max_instances {
                return Err(anyhow::anyhow!(
                    "Maximum number of metrics instances reached"
                ));
            }

            // Check if instance already exists
            if instances.contains_key(&instance_id) {
                return Err(anyhow::anyhow!(
                    "Metrics instance already exists"
                ));
            }
        }

        // Create new metrics instance
        let metrics = Arc::new(UnifiedMetrics::new()?);

        // Register the instance
        let registered_metrics = RegisteredMetrics {
            metrics: metrics.clone(),
            metadata,
            registered_at: chrono::Utc::now(),
            last_accessed: chrono::Utc::now(),
            access_count: 0,
        };

        {
            let mut instances = self.metrics_instances.write().await;
            instances.insert(instance_id.clone(), registered_metrics);
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_instances = self.metrics_instances.read().await.len();
            stats.total_registrations += 1;
        }

        info!("Registered metrics instance '{}'", instance_id);
        Ok(metrics)
    }

    /// Unregister a metrics instance
    pub async fn unregister_metrics(&self, instance_id: &str) -> crate::Result<bool> {
        let removed = {
            let mut instances = self.metrics_instances.write().await;
            instances.remove(instance_id).is_some()
        };

        if removed {
            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.total_instances = self.metrics_instances.read().await.len();
                stats.total_unregistrations += 1;
            }

            info!("Unregistered metrics instance '{}'", instance_id);
        }

        Ok(removed)
    }

    /// Get a metrics instance by ID
    pub async fn get_metrics(&self, instance_id: &str) -> crate::Result<Option<Arc<UnifiedMetrics>>> {
        // Update lookup statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_lookups += 1;
        }

        let mut instances = self.metrics_instances.write().await;
        
        if let Some(registered_metrics) = instances.get_mut(instance_id) {
            // Update access information
            registered_metrics.last_accessed = chrono::Utc::now();
            registered_metrics.access_count += 1;

            // Update cache hit statistics
            {
                let mut stats = self.stats.write().await;
                stats.cache_hits += 1;
            }

            Ok(Some(registered_metrics.metrics.clone()))
        } else {
            // Update cache miss statistics
            {
                let mut stats = self.stats.write().await;
                stats.cache_misses += 1;
            }

            Ok(None)
        }
    }

    /// Get the global metrics instance
    pub fn global_metrics(&self) -> Arc<UnifiedMetrics> {
        self.global_metrics.clone()
    }

    /// List all registered metrics instances
    pub async fn list_instances(&self) -> Vec<String> {
        let instances = self.metrics_instances.read().await;
        instances.keys().cloned().collect()
    }

    /// Get metadata for a metrics instance
    pub async fn get_metadata(&self, instance_id: &str) -> Option<MetricsMetadata> {
        let instances = self.metrics_instances.read().await;
        instances.get(instance_id).map(|rm| rm.metadata.clone())
    }

    /// Get aggregated metrics summary
    pub async fn get_aggregated_summary(&self) -> crate::Result<AggregatedSummary> {
        let instances = self.metrics_instances.read().await;
        
        let mut total_events = 0u64;
        let mut network_blocked = 0u64;
        let mut network_allowed = 0u64;
        let mut file_blocked = 0u64;
        let mut file_allowed = 0u64;
        let mut security_events = 0u64;

        // Aggregate from all instances
        for registered_metrics in instances.values() {
            let summary = registered_metrics.metrics.get_summary();
            total_events += summary.total_events;
            network_blocked += summary.network_blocked;
            network_allowed += summary.network_allowed;
            file_blocked += summary.file_blocked;
            file_allowed += summary.file_allowed;
            security_events += summary.security_events;
        }

        // Include global metrics
        let global_summary = self.global_metrics.get_summary();
        total_events += global_summary.total_events;
        network_blocked += global_summary.network_blocked;
        network_allowed += global_summary.network_allowed;
        file_blocked += global_summary.file_blocked;
        file_allowed += global_summary.file_allowed;
        security_events += global_summary.security_events;

        Ok(AggregatedSummary {
            total_events,
            network_blocked,
            network_allowed,
            file_blocked,
            file_allowed,
            security_events,
            instance_count: instances.len(),
            uptime_seconds: global_summary.uptime_seconds,
        })
    }

    /// Get registry statistics
    pub async fn stats(&self) -> RegistryStats {
        self.stats.read().await.clone()
    }

    /// Cleanup expired metrics instances
    pub async fn cleanup(&self) -> crate::Result<usize> {
        let mut instances_to_remove = Vec::new();
        let now = chrono::Utc::now();

        {
            let instances = self.metrics_instances.read().await;
            
            for (instance_id, registered_metrics) in instances.iter() {
                // Remove temporary instances that haven't been accessed recently
                if registered_metrics.metadata.instance_type == MetricsInstanceType::Temporary {
                    let time_since_last_access = now - registered_metrics.last_accessed;
                    if time_since_last_access > chrono::Duration::from_std(self.config.default_retention).unwrap() {
                        instances_to_remove.push(instance_id.clone());
                    }
                }
            }
        }

        // Remove expired instances
        let mut removed_count = 0;
        for instance_id in instances_to_remove {
            if self.unregister_metrics(&instance_id).await? {
                removed_count += 1;
            }
        }

        // Update cleanup statistics
        if removed_count > 0 {
            let mut stats = self.stats.write().await;
            stats.last_cleanup_timestamp = Some(chrono::Utc::now());
        }

        if removed_count > 0 {
            debug!("Cleaned up {} expired metrics instances", removed_count);
        }

        Ok(removed_count)
    }

    /// Start the cleanup task
    pub async fn start_cleanup_task(&self) -> crate::Result<()> {
        let registry = self.clone();
        let cleanup_interval = self.config.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = registry.cleanup().await {
                    error!("Metrics registry cleanup failed: {}", e);
                }
            }
        });

        info!("Started metrics registry cleanup task");
        Ok(())
    }

    /// Find metrics instances by tags
    pub async fn find_by_tags(&self, tags: &HashMap<String, String>) -> Vec<String> {
        let instances = self.metrics_instances.read().await;
        let mut matching_instances = Vec::new();

        for (instance_id, registered_metrics) in instances.iter() {
            let mut matches_all = true;
            
            for (tag_key, tag_value) in tags.iter() {
                if let Some(instance_value) = registered_metrics.metadata.tags.get(tag_key) {
                    if instance_value != tag_value {
                        matches_all = false;
                        break;
                    }
                } else {
                    matches_all = false;
                    break;
                }
            }
            
            if matches_all {
                matching_instances.push(instance_id.clone());
            }
        }

        matching_instances
    }

    /// Find metrics instances by type
    pub async fn find_by_type(&self, instance_type: MetricsInstanceType) -> Vec<String> {
        let instances = self.metrics_instances.read().await;
        let mut matching_instances = Vec::new();

        for (instance_id, registered_metrics) in instances.iter() {
            if registered_metrics.metadata.instance_type == instance_type {
                matching_instances.push(instance_id.clone());
            }
        }

        matching_instances
    }

    /// Get metrics instance health information
    pub async fn get_health_info(&self) -> Vec<InstanceHealth> {
        let instances = self.metrics_instances.read().await;
        let mut health_info = Vec::new();

        for (instance_id, registered_metrics) in instances.iter() {
            let now = chrono::Utc::now();
            let time_since_last_access = now - registered_metrics.last_accessed;
            
            let health = InstanceHealth {
                instance_id: instance_id.clone(),
                name: registered_metrics.metadata.name.clone(),
                instance_type: registered_metrics.metadata.instance_type,
                status: if time_since_last_access < chrono::Duration::minutes(5) {
                    InstanceStatus::Healthy
                } else if time_since_last_access < chrono::Duration::hours(1) {
                    InstanceStatus::Stale
                } else {
                    InstanceStatus::Unhealthy
                },
                registered_at: registered_metrics.registered_at,
                last_accessed: registered_metrics.last_accessed,
                access_count: registered_metrics.access_count,
            };
            
            health_info.push(health);
        }

        health_info
    }
}

impl Clone for MetricsRegistry {
    fn clone(&self) -> Self {
        Self {
            metrics_instances: self.metrics_instances.clone(),
            global_metrics: self.global_metrics.clone(),
            config: self.config.clone(),
            stats: self.stats.clone(),
        }
    }
}

/// Aggregated metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedSummary {
    /// Total events across all instances
    pub total_events: u64,
    /// Network connections blocked across all instances
    pub network_blocked: u64,
    /// Network connections allowed across all instances
    pub network_allowed: u64,
    /// File accesses blocked across all instances
    pub file_blocked: u64,
    /// File accesses allowed across all instances
    pub file_allowed: u64,
    /// Security events across all instances
    pub security_events: u64,
    /// Number of instances included in aggregation
    pub instance_count: usize,
    /// System uptime seconds
    pub uptime_seconds: f64,
}

/// Instance health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceHealth {
    /// Instance ID
    pub instance_id: String,
    /// Instance name
    pub name: String,
    /// Instance type
    pub instance_type: MetricsInstanceType,
    /// Instance status
    pub status: InstanceStatus,
    /// Registration timestamp
    pub registered_at: chrono::DateTime<chrono::Utc>,
    /// Last access timestamp
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    /// Access count
    pub access_count: u64,
}

/// Instance status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceStatus {
    /// Instance is healthy and actively used
    Healthy,
    /// Instance is stale (not accessed recently)
    Stale,
    /// Instance is unhealthy (error state)
    Unhealthy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_metrics_registry_creation() {
        let registry = MetricsRegistry::new_default().unwrap();
        
        let stats = registry.stats().await;
        assert_eq!(stats.total_instances, 0);
        assert_eq!(stats.total_registrations, 0);
        assert_eq!(stats.total_lookups, 0);
    }

    #[tokio::test]
    async fn test_register_metrics() {
        let registry = MetricsRegistry::new_default().unwrap();
        
        let metadata = MetricsMetadata {
            name: "test_metrics".to_string(),
            description: Some("Test metrics instance".to_string()),
            tags: HashMap::from([("env".to_string(), "test".to_string())]),
            instance_type: MetricsInstanceType::Custom,
            component: Some("test_component".to_string()),
            backend: None,
        };

        let metrics = registry.register_metrics("test".to_string(), metadata).await.unwrap();
        assert!(metrics.get_summary().total_events == 0);

        let stats = registry.stats().await;
        assert_eq!(stats.total_instances, 1);
        assert_eq!(stats.total_registrations, 1);
    }

    #[tokio::test]
    async fn test_get_metrics() {
        let registry = MetricsRegistry::new_default().unwrap();
        
        let metadata = MetricsMetadata {
            name: "test_metrics".to_string(),
            description: None,
            tags: HashMap::new(),
            instance_type: MetricsInstanceType::Custom,
            component: None,
            backend: None,
        };

        registry.register_metrics("test".to_string(), metadata).await.unwrap();
        
        let retrieved_metrics = registry.get_metrics("test").await.unwrap();
        assert!(retrieved_metrics.is_some());

        let stats = registry.stats().await;
        assert_eq!(stats.total_lookups, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 0);
    }

    #[tokio::test]
    async fn test_unregister_metrics() {
        let registry = MetricsRegistry::new_default().unwrap();
        
        let metadata = MetricsMetadata {
            name: "test_metrics".to_string(),
            description: None,
            tags: HashMap::new(),
            instance_type: MetricsInstanceType::Temporary,
            component: None,
            backend: None,
        };

        registry.register_metrics("test".to_string(), metadata).await.unwrap();
        
        let removed = registry.unregister_metrics("test").await.unwrap();
        assert!(removed);

        let stats = registry.stats().await;
        assert_eq!(stats.total_instances, 0);
        assert_eq!(stats.total_unregistrations, 1);
    }

    #[tokio::test]
    async fn test_find_by_tags() {
        let registry = MetricsRegistry::new_default().unwrap();
        
        let metadata1 = MetricsMetadata {
            name: "test1".to_string(),
            description: None,
            tags: HashMap::from([("env".to_string(), "test".to_string())]),
            instance_type: MetricsInstanceType::Custom,
            component: None,
            backend: None,
        };

        let metadata2 = MetricsMetadata {
            name: "test2".to_string(),
            description: None,
            tags: HashMap::from([("env".to_string(), "prod".to_string())]),
            instance_type: MetricsInstanceType::Custom,
            component: None,
            backend: None,
        };

        registry.register_metrics("test1".to_string(), metadata1).await.unwrap();
        registry.register_metrics("test2".to_string(), metadata2).await.unwrap();
        
        let test_instances = registry.find_by_tags(&HashMap::from([("env".to_string(), "test".to_string())])).await;
        assert_eq!(test_instances.len(), 1);
        assert!(test_instances.contains(&"test1".to_string()));
    }

    #[tokio::test]
    async fn test_aggregated_summary() {
        let registry = MetricsRegistry::new_default().unwrap();
        
        let metadata = MetricsMetadata {
            name: "test".to_string(),
            description: None,
            tags: HashMap::new(),
            instance_type: MetricsInstanceType::Custom,
            component: None,
            backend: None,
        };

        registry.register_metrics("test".to_string(), metadata).await.unwrap();
        
        let summary = registry.get_aggregated_summary().await.unwrap();
        assert_eq!(summary.instance_count, 1);
        assert_eq!(summary.total_events, 0);
    }

    #[tokio::test]
    async fn test_global_metrics() {
        let registry = MetricsRegistry::new_default().unwrap();
        
        let global_metrics = registry.global_metrics();
        let summary = global_metrics.get_summary();
        assert_eq!(summary.total_events, 0);
    }
}