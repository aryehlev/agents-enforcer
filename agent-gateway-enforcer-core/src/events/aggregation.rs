//! Event aggregation for filtering, correlation, and analysis

use crate::events::{EventSeverity, EventSource, EventType, UnifiedEvent};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Event aggregator for filtering, correlation, and analysis
#[derive(Debug)]
pub struct EventAggregator {
    /// Aggregation rules
    rules: Arc<RwLock<Vec<AggregationRule>>>,
    /// Event windows for time-based aggregation
    windows: Arc<RwLock<HashMap<String, EventWindow>>>,
    /// Correlation engine
    correlation: Arc<RwLock<CorrelationEngine>>,
    /// Aggregated events storage
    aggregated_events: Arc<RwLock<VecDeque<AggregatedEvent>>>,
    /// Configuration
    config: AggregatorConfig,
}

/// Aggregation rule for processing events
#[derive(Debug, Clone)]
pub struct AggregationRule {
    /// Rule ID
    pub id: Uuid,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Event filter
    pub event_filter: EventFilterSpec,
    /// Aggregation type
    pub aggregation_type: AggregationType,
    /// Time window
    pub time_window: Duration,
    /// Grouping criteria
    pub grouping_criteria: Vec<GroupingCriterion>,
    /// Threshold for triggering aggregation
    pub threshold: Option<u64>,
    /// Rule is enabled
    pub enabled: bool,
}

/// Event filter specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventFilterSpec {
    /// Filter by event type
    EventType(Vec<EventType>),
    /// Filter by event source
    EventSource(Vec<EventSource>),
    /// Filter by event severity
    EventSeverity(Vec<EventSeverity>),
    /// Filter by tag
    Tag(String, String),
    /// Filter by custom field
    CustomField(String, serde_json::Value),
    /// Composite filter (AND)
    And(Vec<EventFilterSpec>),
    /// Composite filter (OR)
    Or(Vec<EventFilterSpec>),
    /// No filter (match all)
    All,
}

/// Aggregation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationType {
    /// Count events
    Count,
    /// Sum numeric values
    Sum,
    /// Average numeric values
    Average,
    /// Minimum value
    Min,
    /// Maximum value
    Max,
    /// First event
    First,
    /// Last event
    Last,
    /// Unique count
    UniqueCount,
}

impl std::fmt::Display for AggregationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Count => write!(f, "count"),
            Self::Sum => write!(f, "sum"),
            Self::Average => write!(f, "average"),
            Self::Min => write!(f, "min"),
            Self::Max => write!(f, "max"),
            Self::First => write!(f, "first"),
            Self::Last => write!(f, "last"),
            Self::UniqueCount => write!(f, "unique_count"),
        }
    }
}

/// Grouping criterion for aggregation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupingCriterion {
    /// Group by event type
    EventType,
    /// Group by event source
    EventSource,
    /// Group by event severity
    EventSeverity,
    /// Group by tag
    Tag(String),
    /// Group by custom field
    CustomField(String),
    /// Group by time window
    TimeWindow(Duration),
}

/// Event window for time-based aggregation
#[derive(Debug)]
pub struct EventWindow {
    /// Window ID
    pub id: String,
    /// Events in the window
    pub events: VecDeque<UnifiedEvent>,
    /// Window start time
    pub start_time: DateTime<Utc>,
    /// Window duration
    pub duration: Duration,
    /// Maximum number of events
    pub max_events: usize,
}

/// Correlation engine for finding related events
#[derive(Debug)]
pub struct CorrelationEngine {
    /// Correlation rules
    pub rules: Vec<CorrelationRule>,
    /// Event index for fast lookup
    pub event_index: HashMap<String, Vec<Uuid>>,
    /// Correlation cache
    pub correlation_cache: HashMap<String, CorrelationResult>,
}

/// Correlation rule
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    /// Rule ID
    pub id: Uuid,
    /// Rule name
    pub name: String,
    /// Time window for correlation
    pub time_window: Duration,
    /// Correlation criteria
    pub criteria: Vec<CorrelationCriterion>,
    /// Minimum correlation score
    pub min_score: f64,
}

/// Correlation criterion
#[derive(Debug, Clone)]
pub enum CorrelationCriterion {
    /// Same process ID
    SameProcessId,
    /// Same user ID
    SameUserId,
    /// Same IP address
    SameIpAddress,
    /// Same file path
    SameFilePath,
    /// Time proximity (within specified duration)
    TimeProximity(Duration),
    /// Sequential events
    Sequential,
    /// Custom correlation function
    Custom(String),
}

/// Correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// Correlation ID
    pub id: Uuid,
    /// Correlated event IDs
    pub event_ids: Vec<Uuid>,
    /// Correlation score
    pub score: f64,
    /// Correlation type
    pub correlation_type: String,
    /// Correlation timestamp
    pub timestamp: DateTime<Utc>,
}

/// Aggregated event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedEvent {
    /// Aggregated event ID
    pub id: Uuid,
    /// Original event IDs
    pub original_event_ids: Vec<Uuid>,
    /// Aggregation type
    pub aggregation_type: AggregationType,
    /// Aggregated value
    pub value: AggregatedValue,
    /// Grouping key
    pub grouping_key: String,
    /// Time window
    pub time_window: (DateTime<Utc>, DateTime<Utc>),
    /// Event count
    pub event_count: u64,
    /// Aggregation timestamp
    pub timestamp: DateTime<Utc>,
}

/// Aggregated value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregatedValue {
    /// Numeric value
    Number(f64),
    /// Count value
    Count(u64),
    /// String value
    String(String),
    /// Boolean value
    Boolean(bool),
    /// Array of values
    Array(Vec<AggregatedValue>),
    /// Object of key-value pairs
    Object(HashMap<String, AggregatedValue>),
}

/// Aggregator configuration
#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    /// Maximum number of aggregated events to keep
    pub max_aggregated_events: usize,
    /// Default time window for aggregation
    pub default_time_window: Duration,
    /// Maximum number of events per window
    pub max_events_per_window: usize,
    /// Correlation cache size
    pub correlation_cache_size: usize,
    /// Cleanup interval
    pub cleanup_interval: Duration,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            max_aggregated_events: 10000,
            default_time_window: Duration::minutes(5),
            max_events_per_window: 1000,
            correlation_cache_size: 1000,
            cleanup_interval: Duration::minutes(1),
        }
    }
}

impl EventAggregator {
    /// Create a new event aggregator
    pub fn new(config: AggregatorConfig) -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            windows: Arc::new(RwLock::new(HashMap::new())),
            correlation: Arc::new(RwLock::new(CorrelationEngine {
                rules: Vec::new(),
                event_index: HashMap::new(),
                correlation_cache: HashMap::new(),
            })),
            aggregated_events: Arc::new(RwLock::new(VecDeque::new())),
            config,
        }
    }

    /// Create a new event aggregator with default configuration
    pub fn default() -> Self {
        Self::new(AggregatorConfig::default())
    }

    /// Add an aggregation rule
    pub async fn add_rule(&self, rule: AggregationRule) -> crate::Result<()> {
        let mut rules = self.rules.write().await;
        rules.push(rule);
        Ok(())
    }

    /// Remove an aggregation rule
    pub async fn remove_rule(&self, rule_id: Uuid) -> bool {
        let mut rules = self.rules.write().await;
        let initial_len = rules.len();
        rules.retain(|rule| rule.id != rule_id);
        rules.len() < initial_len
    }

    /// List aggregation rules
    pub async fn list_rules(&self) -> Vec<AggregationRule> {
        let rules = self.rules.read().await;
        rules.clone()
    }

    /// Process an event
    pub async fn process_event(&self, event: UnifiedEvent) -> crate::Result<Vec<AggregatedEvent>> {
        let mut aggregated_events = Vec::new();

        // Process with all rules
        {
            let rules = self.rules.read().await;
            for rule in rules.iter() {
                if !rule.enabled {
                    continue;
                }

                // Check if event matches rule filter
                if !self.matches_filter(&event, &rule.event_filter) {
                    continue;
                }

                // Process event with rule
                if let Some(aggregated) = self.process_event_with_rule(&event, rule).await? {
                    aggregated_events.push(aggregated);
                }
            }
        }

        // Update event index for correlation
        self.update_event_index(&event).await;

        // Perform correlation analysis
        self.perform_correlation(&event).await?;

        Ok(aggregated_events)
    }

    /// Check if an event matches a filter
    fn matches_filter(&self, event: &UnifiedEvent, filter: &EventFilterSpec) -> bool {
        match filter {
            EventFilterSpec::EventType(types) => types.contains(&event.event_type),
            EventFilterSpec::EventSource(sources) => sources.contains(&event.source),
            EventFilterSpec::EventSeverity(severities) => severities.contains(&event.severity),
            EventFilterSpec::Tag(key, value) => event.metadata.tags.get(key) == Some(value),
            EventFilterSpec::CustomField(key, expected_value) => {
                event.metadata.custom_fields.get(key) == Some(expected_value)
            }
            EventFilterSpec::And(filters) => filters.iter().all(|f| self.matches_filter(event, f)),
            EventFilterSpec::Or(filters) => filters.iter().any(|f| self.matches_filter(event, f)),
            EventFilterSpec::All => true,
        }
    }

    /// Process an event with a specific rule
    async fn process_event_with_rule(
        &self,
        event: &UnifiedEvent,
        rule: &AggregationRule,
    ) -> crate::Result<Option<AggregatedEvent>> {
        // Get or create event window
        let window_id = self.get_window_id(event, rule);
        let mut windows = self.windows.write().await;

        let window = windows
            .entry(window_id.clone())
            .or_insert_with(|| EventWindow {
                id: window_id,
                events: VecDeque::new(),
                start_time: event.timestamp,
                duration: rule.time_window,
                max_events: self.config.max_events_per_window,
            });

        // Add event to window
        window.events.push_back(event.clone());

        // Remove old events outside the time window
        let cutoff_time = event.timestamp - rule.time_window;
        while let Some(front_event) = window.events.front() {
            if front_event.timestamp < cutoff_time {
                window.events.pop_front();
            } else {
                break;
            }
        }

        // Check if we should trigger aggregation
        let should_aggregate = match rule.threshold {
            Some(threshold) => window.events.len() as u64 >= threshold,
            None => true,
        };

        if should_aggregate {
            // Perform aggregation
            let aggregated_value = self.perform_aggregation(&window.events, rule.aggregation_type);

            let aggregated_event = AggregatedEvent {
                id: Uuid::new_v4(),
                original_event_ids: window.events.iter().map(|e| e.id).collect(),
                aggregation_type: rule.aggregation_type,
                value: aggregated_value,
                grouping_key: self.get_grouping_key(event, rule),
                time_window: (window.start_time, event.timestamp),
                event_count: window.events.len() as u64,
                timestamp: Utc::now(),
            };

            // Store aggregated event
            {
                let mut aggregated = self.aggregated_events.write().await;
                aggregated.push_back(aggregated_event.clone());

                // Remove old aggregated events if we exceed the limit
                while aggregated.len() > self.config.max_aggregated_events {
                    aggregated.pop_front();
                }
            }

            return Ok(Some(aggregated_event));
        }

        Ok(None)
    }

    /// Perform aggregation on events
    fn perform_aggregation(
        &self,
        events: &VecDeque<UnifiedEvent>,
        aggregation_type: AggregationType,
    ) -> AggregatedValue {
        if events.is_empty() {
            return AggregatedValue::Count(0);
        }

        match aggregation_type {
            AggregationType::Count => AggregatedValue::Count(events.len() as u64),
            AggregationType::First => {
                // Return the first event as a serialized object
                let first_event = &events[0];
                let mut obj = HashMap::new();
                obj.insert(
                    "id".to_string(),
                    AggregatedValue::String(first_event.id.to_string()),
                );
                obj.insert(
                    "type".to_string(),
                    AggregatedValue::String(format!("{:?}", first_event.event_type)),
                );
                obj.insert(
                    "timestamp".to_string(),
                    AggregatedValue::String(first_event.timestamp.to_rfc3339()),
                );
                AggregatedValue::Object(obj)
            }
            AggregationType::Last => {
                // Return the last event as a serialized object
                let last_event = &events[events.len() - 1];
                let mut obj = HashMap::new();
                obj.insert(
                    "id".to_string(),
                    AggregatedValue::String(last_event.id.to_string()),
                );
                obj.insert(
                    "type".to_string(),
                    AggregatedValue::String(format!("{:?}", last_event.event_type)),
                );
                obj.insert(
                    "timestamp".to_string(),
                    AggregatedValue::String(last_event.timestamp.to_rfc3339()),
                );
                AggregatedValue::Object(obj)
            }
            AggregationType::UniqueCount => {
                let unique_ids: std::collections::HashSet<_> =
                    events.iter().map(|e| e.id).collect();
                AggregatedValue::Count(unique_ids.len() as u64)
            }
            // For numeric aggregations, we'd need to extract numeric values from events
            // This is a simplified implementation
            AggregationType::Sum => AggregatedValue::Number(events.len() as f64),
            AggregationType::Average => AggregatedValue::Number(1.0),
            AggregationType::Min => AggregatedValue::Number(0.0),
            AggregationType::Max => AggregatedValue::Number(events.len() as f64),
        }
    }

    /// Get window ID for an event and rule
    fn get_window_id(&self, event: &UnifiedEvent, rule: &AggregationRule) -> String {
        let mut parts = vec![
            format!("{:?}", rule.aggregation_type),
            format!("{:?}", event.event_type),
        ];

        for criterion in &rule.grouping_criteria {
            match criterion {
                GroupingCriterion::EventType => parts.push(format!("{:?}", event.event_type)),
                GroupingCriterion::EventSource => parts.push(format!("{:?}", event.source)),
                GroupingCriterion::EventSeverity => parts.push(format!("{:?}", event.severity)),
                GroupingCriterion::Tag(key) => {
                    if let Some(value) = event.metadata.tags.get(key) {
                        parts.push(format!("{}:{}", key, value));
                    }
                }
                GroupingCriterion::CustomField(key) => {
                    if let Some(value) = event.metadata.custom_fields.get(key) {
                        parts.push(format!("{}:{}", key, value));
                    }
                }
                GroupingCriterion::TimeWindow(duration) => {
                    let window_start = event.timestamp - *duration;
                    parts.push(format!("window:{}", window_start.timestamp()));
                }
            }
        }

        parts.join("|")
    }

    /// Get grouping key for an event and rule
    fn get_grouping_key(&self, event: &UnifiedEvent, rule: &AggregationRule) -> String {
        let mut parts = Vec::new();

        for criterion in &rule.grouping_criteria {
            match criterion {
                GroupingCriterion::EventType => parts.push(format!("{:?}", event.event_type)),
                GroupingCriterion::EventSource => parts.push(format!("{:?}", event.source)),
                GroupingCriterion::EventSeverity => parts.push(format!("{:?}", event.severity)),
                GroupingCriterion::Tag(key) => {
                    if let Some(value) = event.metadata.tags.get(key) {
                        parts.push(format!("{}:{}", key, value));
                    }
                }
                GroupingCriterion::CustomField(key) => {
                    if let Some(value) = event.metadata.custom_fields.get(key) {
                        parts.push(format!("{}:{}", key, value));
                    }
                }
                GroupingCriterion::TimeWindow(_) => {} // Time windows are handled separately
            }
        }

        if parts.is_empty() {
            "default".to_string()
        } else {
            parts.join("|")
        }
    }

    /// Update event index for correlation
    async fn update_event_index(&self, event: &UnifiedEvent) {
        let mut correlation = self.correlation.write().await;

        // Index by process ID
        if let Some(pid) = self.extract_pid(event) {
            correlation
                .event_index
                .entry(format!("pid:{}", pid))
                .or_insert_with(Vec::new)
                .push(event.id);
        }

        // Index by user ID
        if let Some(user_id) = &event.metadata.user_id {
            correlation
                .event_index
                .entry(format!("user:{}", user_id))
                .or_insert_with(Vec::new)
                .push(event.id);
        }

        // Index by IP address (for network events)
        if let Some(ip) = self.extract_ip(event) {
            correlation
                .event_index
                .entry(format!("ip:{}", ip))
                .or_insert_with(Vec::new)
                .push(event.id);
        }
    }

    /// Extract process ID from event
    fn extract_pid(&self, event: &UnifiedEvent) -> Option<u32> {
        match &event.data {
            crate::events::EventData::Network(net_event) => net_event.pid,
            crate::events::EventData::FileAccess(file_event) => file_event.pid,
            _ => None,
        }
    }

    /// Extract IP address from event
    fn extract_ip(&self, event: &UnifiedEvent) -> Option<String> {
        match &event.data {
            crate::events::EventData::Network(net_event) => Some(net_event.dst_ip.to_string()),
            _ => None,
        }
    }

    /// Perform correlation analysis
    async fn perform_correlation(&self, event: &UnifiedEvent) -> crate::Result<()> {
        let correlation = self.correlation.read().await;

        for rule in &correlation.rules {
            // Find related events based on criteria
            let related_events = self.find_related_events(event, rule).await?;

            if related_events.len() > 1 {
                // Calculate correlation score
                let score = self.calculate_correlation_score(event, &related_events, rule);

                if score >= rule.min_score {
                    // Create correlation result
                    let correlation_result = CorrelationResult {
                        id: Uuid::new_v4(),
                        event_ids: related_events.iter().map(|e| e.id).collect(),
                        score,
                        correlation_type: rule.name.clone(),
                        timestamp: Utc::now(),
                    };

                    // Store correlation result (in a real implementation, this would be stored or emitted)
                    tracing::info!(
                        "Found correlation: {} events with score {}",
                        related_events.len(),
                        score
                    );
                }
            }
        }

        Ok(())
    }

    /// Find related events based on correlation rule
    async fn find_related_events(
        &self,
        event: &UnifiedEvent,
        rule: &CorrelationRule,
    ) -> crate::Result<Vec<UnifiedEvent>> {
        let mut related_events = vec![event.clone()];

        // This is a simplified implementation
        // In a real implementation, we would query the event store or index
        // For now, we'll just return the current event

        Ok(related_events)
    }

    /// Calculate correlation score
    fn calculate_correlation_score(
        &self,
        event: &UnifiedEvent,
        related_events: &[UnifiedEvent],
        rule: &CorrelationRule,
    ) -> f64 {
        // Simplified scoring algorithm
        // In a real implementation, this would be more sophisticated
        let base_score = related_events.len() as f64;
        let time_factor = if related_events.len() > 1 {
            let time_span = related_events
                .iter()
                .map(|e| e.timestamp)
                .max()
                .unwrap_or(event.timestamp)
                - related_events
                    .iter()
                    .map(|e| e.timestamp)
                    .min()
                    .unwrap_or(event.timestamp);

            if time_span < rule.time_window {
                1.0
            } else {
                0.5
            }
        } else {
            1.0
        };

        base_score * time_factor
    }

    /// Get aggregated events
    pub async fn get_aggregated_events(&self, limit: Option<usize>) -> Vec<AggregatedEvent> {
        let aggregated = self.aggregated_events.read().await;
        let events: Vec<_> = aggregated.iter().rev().cloned().collect();

        if let Some(limit) = limit {
            events.into_iter().take(limit).collect()
        } else {
            events
        }
    }

    /// Get aggregator statistics
    pub async fn stats(&self) -> AggregatorStats {
        let rules = self.rules.read().await;
        let windows = self.windows.read().await;
        let aggregated = self.aggregated_events.read().await;
        let correlation = self.correlation.read().await;

        AggregatorStats {
            rules_count: rules.len(),
            active_windows: windows.len(),
            aggregated_events_count: aggregated.len(),
            correlation_rules_count: correlation.rules.len(),
            indexed_events_count: correlation.event_index.values().map(|v| v.len()).sum(),
        }
    }

    /// Start cleanup task
    pub async fn start_cleanup_task(&self) -> crate::Result<()> {
        let windows = self.windows.clone();
        let aggregated_events = self.aggregated_events.clone();
        let cleanup_interval = self.config.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval.to_std().unwrap());

            loop {
                interval.tick().await;

                let now = Utc::now();

                // Clean up old windows
                {
                    let mut windows_mut = windows.write().await;
                    windows_mut.retain(|_, window| now - window.start_time < window.duration * 2);
                }

                // Clean up old aggregated events if needed
                {
                    let mut aggregated_mut = aggregated_events.write().await;
                    // This would be based on some retention policy
                    // For now, we'll just keep the configured maximum
                }
            }
        });

        Ok(())
    }
}

/// Aggregator statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorStats {
    /// Number of aggregation rules
    pub rules_count: usize,
    /// Number of active windows
    pub active_windows: usize,
    /// Number of aggregated events
    pub aggregated_events_count: usize,
    /// Number of correlation rules
    pub correlation_rules_count: usize,
    /// Number of indexed events
    pub indexed_events_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventSource, SystemAction};

    #[tokio::test]
    async fn test_event_aggregator_basic() {
        let aggregator = EventAggregator::default();

        // Create a simple rule
        let rule = AggregationRule {
            id: Uuid::new_v4(),
            name: "test_rule".to_string(),
            description: "Test rule".to_string(),
            event_filter: EventFilterSpec::All,
            aggregation_type: AggregationType::Count,
            time_window: Duration::minutes(5),
            grouping_criteria: vec![GroupingCriterion::EventType],
            threshold: Some(2),
            enabled: true,
        };

        aggregator.add_rule(rule).await.unwrap();

        // Process events
        let event1 = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test event 1".to_string(),
            EventSource::Core,
        );

        let event2 = UnifiedEvent::system(
            SystemAction::Stopped,
            "test".to_string(),
            "Test event 2".to_string(),
            EventSource::Core,
        );

        // Process first event (should not trigger aggregation yet)
        let result1 = aggregator.process_event(event1).await.unwrap();
        assert_eq!(result1.len(), 0);

        // Process second event (should trigger aggregation)
        let result2 = aggregator.process_event(event2).await.unwrap();
        assert_eq!(result2.len(), 1);
        assert_eq!(result2[0].event_count, 2);
    }

    #[tokio::test]
    async fn test_event_filter() {
        let aggregator = EventAggregator::default();

        // Test event type filter
        let filter = EventFilterSpec::EventType(vec![EventType::System]);
        let system_event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test".to_string(),
            EventSource::Core,
        );
        let network_event = UnifiedEvent::network(
            crate::events::NetworkAction::Blocked,
            "192.168.1.1".parse().unwrap(),
            443,
            crate::events::NetworkProtocol::Tcp,
            None,
            EventSource::Core,
        );

        assert!(aggregator.matches_filter(&system_event, &filter));
        assert!(!aggregator.matches_filter(&network_event, &filter));
    }

    #[tokio::test]
    async fn test_aggregator_stats() {
        let aggregator = EventAggregator::default();

        let stats = aggregator.stats().await;
        assert_eq!(stats.rules_count, 0);
        assert_eq!(stats.active_windows, 0);
        assert_eq!(stats.aggregated_events_count, 0);
    }
}
