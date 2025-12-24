//! Event handlers and filters for the unified event system

use crate::events::{EventSeverity, EventSource, EventType, UnifiedEvent};
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;

/// Trait for handling events
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Handle an event
    async fn handle_event(&self, event: UnifiedEvent) -> crate::Result<()>;

    /// Get handler name
    fn name(&self) -> &str;

    /// Check if handler is healthy
    async fn is_healthy(&self) -> bool {
        true
    }
}

/// Trait for filtering events
pub trait EventFilter: std::fmt::Debug + Send + Sync {
    /// Check if an event matches the filter
    fn matches(&self, event: &UnifiedEvent) -> bool;

    /// Get filter description
    fn description(&self) -> &str;
}

/// Filter events by type
#[derive(Debug)]
pub struct EventTypeFilter {
    allowed_types: HashSet<EventType>,
}

impl EventTypeFilter {
    /// Create a new event type filter
    pub fn new(allowed_types: Vec<EventType>) -> Self {
        Self {
            allowed_types: allowed_types.into_iter().collect(),
        }
    }

    /// Create a filter that allows only the specified type
    pub fn single(event_type: EventType) -> Self {
        Self::new(vec![event_type])
    }
}

impl EventFilter for EventTypeFilter {
    fn matches(&self, event: &UnifiedEvent) -> bool {
        self.allowed_types.contains(&event.event_type)
    }

    fn description(&self) -> &str {
        "Event type filter"
    }
}

/// Filter events by source
#[derive(Debug)]
pub struct EventSourceFilter {
    allowed_sources: HashSet<EventSource>,
}

impl EventSourceFilter {
    /// Create a new event source filter
    pub fn new(allowed_sources: Vec<EventSource>) -> Self {
        Self {
            allowed_sources: allowed_sources.into_iter().collect(),
        }
    }

    /// Create a filter that allows only the specified source
    pub fn single(source: EventSource) -> Self {
        Self::new(vec![source])
    }
}

impl EventFilter for EventSourceFilter {
    fn matches(&self, event: &UnifiedEvent) -> bool {
        self.allowed_sources.contains(&event.source)
    }

    fn description(&self) -> &str {
        "Event source filter"
    }
}

/// Filter events by severity
#[derive(Debug)]
pub struct EventSeverityFilter {
    min_severity: EventSeverity,
}

impl EventSeverityFilter {
    /// Create a new event severity filter
    pub fn new(min_severity: EventSeverity) -> Self {
        Self { min_severity }
    }
}

impl EventFilter for EventSeverityFilter {
    fn matches(&self, event: &UnifiedEvent) -> bool {
        event.severity >= self.min_severity
    }

    fn description(&self) -> &str {
        "Event severity filter"
    }
}

/// Filter events by tag
#[derive(Debug)]
pub struct EventTagFilter {
    required_tags: Vec<(String, String)>,
}

impl EventTagFilter {
    /// Create a new event tag filter
    pub fn new(required_tags: Vec<(String, String)>) -> Self {
        Self { required_tags }
    }

    /// Create a filter that requires a single tag
    pub fn single(key: String, value: String) -> Self {
        Self::new(vec![(key, value)])
    }
}

impl EventFilter for EventTagFilter {
    fn matches(&self, event: &UnifiedEvent) -> bool {
        self.required_tags
            .iter()
            .all(|(key, value)| event.metadata.tags.get(key) == Some(value))
    }

    fn description(&self) -> &str {
        "Event tag filter"
    }
}

/// Composite filter that combines multiple filters with AND logic
#[derive(Debug)]
pub struct AndFilter {
    filters: Vec<Arc<dyn EventFilter + Send + Sync>>,
}

impl AndFilter {
    /// Create a new AND filter
    pub fn new(filters: Vec<Arc<dyn EventFilter + Send + Sync>>) -> Self {
        Self { filters }
    }
}

impl EventFilter for AndFilter {
    fn matches(&self, event: &UnifiedEvent) -> bool {
        self.filters.iter().all(|filter| filter.matches(event))
    }

    fn description(&self) -> &str {
        "AND composite filter"
    }
}

/// Composite filter that combines multiple filters with OR logic
#[derive(Debug)]
pub struct OrFilter {
    filters: Vec<Arc<dyn EventFilter + Send + Sync>>,
}

impl OrFilter {
    /// Create a new OR filter
    pub fn new(filters: Vec<Arc<dyn EventFilter + Send + Sync>>) -> Self {
        Self { filters }
    }
}

impl EventFilter for OrFilter {
    fn matches(&self, event: &UnifiedEvent) -> bool {
        self.filters.iter().any(|filter| filter.matches(event))
    }

    fn description(&self) -> &str {
        "OR composite filter"
    }
}

/// Console event handler that prints events to stdout
#[derive(Debug)]
pub struct ConsoleEventHandler {
    name: String,
}

impl ConsoleEventHandler {
    /// Create a new console event handler
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait]
impl EventHandler for ConsoleEventHandler {
    async fn handle_event(&self, event: UnifiedEvent) -> crate::Result<()> {
        println!(
            "[{}] {}: {} - {}",
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            event.severity.as_str().to_uppercase(),
            self.name,
            event
        );
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Logging event handler that logs events using tracing
#[derive(Debug)]
pub struct LoggingEventHandler {
    name: String,
}

impl LoggingEventHandler {
    /// Create a new logging event handler
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait]
impl EventHandler for LoggingEventHandler {
    async fn handle_event(&self, event: UnifiedEvent) -> crate::Result<()> {
        match event.severity {
            EventSeverity::Debug => {
                tracing::debug!(
                    event_id = %event.id,
                    event_type = ?event.event_type,
                    source = ?event.source,
                    "{}: {}",
                    self.name,
                    event
                );
            }
            EventSeverity::Info => {
                tracing::info!(
                    event_id = %event.id,
                    event_type = ?event.event_type,
                    source = ?event.source,
                    "{}: {}",
                    self.name,
                    event
                );
            }
            EventSeverity::Warning => {
                tracing::warn!(
                    event_id = %event.id,
                    event_type = ?event.event_type,
                    source = ?event.source,
                    "{}: {}",
                    self.name,
                    event
                );
            }
            EventSeverity::Error => {
                tracing::error!(
                    event_id = %event.id,
                    event_type = ?event.event_type,
                    source = ?event.source,
                    "{}: {}",
                    self.name,
                    event
                );
            }
            EventSeverity::Critical => {
                tracing::error!(
                    event_id = %event.id,
                    event_type = ?event.event_type,
                    source = ?event.source,
                    "{}: {}",
                    self.name,
                    event
                );
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Buffer event handler that stores events in memory
#[derive(Debug)]
pub struct BufferEventHandler {
    name: String,
    events: Arc<tokio::sync::Mutex<Vec<UnifiedEvent>>>,
    max_size: usize,
}

impl BufferEventHandler {
    /// Create a new buffer event handler
    pub fn new(name: String, max_size: usize) -> Self {
        Self {
            name,
            events: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            max_size,
        }
    }

    /// Get all buffered events
    pub async fn get_events(&self) -> Vec<UnifiedEvent> {
        let events = self.events.lock().await;
        events.clone()
    }

    /// Get the number of buffered events
    pub async fn len(&self) -> usize {
        let events = self.events.lock().await;
        events.len()
    }

    /// Clear all buffered events
    pub async fn clear(&self) {
        let mut events = self.events.lock().await;
        events.clear();
    }

    /// Get events by type
    pub async fn get_events_by_type(&self, event_type: EventType) -> Vec<UnifiedEvent> {
        let events = self.events.lock().await;
        events
            .iter()
            .filter(|event| event.event_type == event_type)
            .cloned()
            .collect()
    }
}

#[async_trait]
impl EventHandler for BufferEventHandler {
    async fn handle_event(&self, event: UnifiedEvent) -> crate::Result<()> {
        let mut events = self.events.lock().await;

        // Add the event
        events.push(event);

        // Remove oldest events if we exceed max size
        let len = events.len();
        if len > self.max_size {
            events.drain(0..len - self.max_size);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Forwarding event handler that forwards events to another event bus
#[derive(Debug)]
pub struct ForwardingEventHandler {
    name: String,
    target_bus: Arc<crate::events::EventBusHandle>,
}

impl ForwardingEventHandler {
    /// Create a new forwarding event handler
    pub fn new(name: String, target_bus: Arc<crate::events::EventBusHandle>) -> Self {
        Self { name, target_bus }
    }
}

#[async_trait]
impl EventHandler for ForwardingEventHandler {
    async fn handle_event(&self, event: UnifiedEvent) -> crate::Result<()> {
        self.target_bus.publish(event).await
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Metrics event handler that updates metrics based on events
#[derive(Debug)]
pub struct MetricsEventHandler {
    name: String,
    metrics: Arc<crate::metrics::UnifiedMetrics>,
}

impl MetricsEventHandler {
    /// Create a new metrics event handler
    pub fn new(name: String, metrics: Arc<crate::metrics::UnifiedMetrics>) -> Self {
        Self { name, metrics }
    }
}

#[async_trait]
impl EventHandler for MetricsEventHandler {
    async fn handle_event(&self, event: UnifiedEvent) -> crate::Result<()> {
        // Update event counters
        self.metrics
            .events
            .events_by_type
            .with_label_values(&[&event.event_type.to_string()])
            .inc();
        self.metrics
            .events
            .events_by_source
            .with_label_values(&[&event.source.to_string()])
            .inc();
        self.metrics
            .events
            .events_by_severity
            .with_label_values(&[event.severity.as_str()])
            .inc();

        // Update specific metrics based on event type
        match &event.data {
            crate::events::EventData::Network(network_event) => match network_event.action {
                crate::events::NetworkAction::Blocked => {
                    self.metrics
                        .network
                        .network_blocked_total
                        .with_label_values(&["", "", ""])
                        .inc();
                }
                crate::events::NetworkAction::Allowed => {
                    self.metrics
                        .network
                        .network_allowed_total
                        .with_label_values(&["", "", ""])
                        .inc();
                }
                crate::events::NetworkAction::RateLimited => {
                    self.metrics.network.network_rate_limited_total.inc();
                }
                crate::events::NetworkAction::Unknown => {}
            },
            crate::events::EventData::FileAccess(file_event) => match file_event.action {
                crate::events::FileAction::Blocked => {
                    self.metrics
                        .files
                        .file_blocked_total
                        .with_label_values(&["", ""])
                        .inc();
                }
                crate::events::FileAction::Allowed => {
                    self.metrics
                        .files
                        .file_allowed_total
                        .with_label_values(&["", ""])
                        .inc();
                }
                crate::events::FileAction::Quarantined => {
                    self.metrics.files.file_quarantined_total.inc();
                }
                crate::events::FileAction::Unknown => {}
            },
            crate::events::EventData::Security(_) => {
                self.metrics
                    .security
                    .security_events_total
                    .with_label_values(&["", ""])
                    .inc();
            }
            _ => {}
        }

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventSource, SystemAction};

    #[test]
    fn test_event_type_filter() {
        let filter = EventTypeFilter::single(EventType::Network);

        let network_event = UnifiedEvent::network(
            crate::events::NetworkAction::Blocked,
            "192.168.1.1".parse().unwrap(),
            443,
            crate::events::NetworkProtocol::Tcp,
            None,
            EventSource::Core,
        );

        let system_event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test".to_string(),
            EventSource::Core,
        );

        assert!(filter.matches(&network_event));
        assert!(!filter.matches(&system_event));
    }

    #[test]
    fn test_event_source_filter() {
        let filter = EventSourceFilter::single(EventSource::Core);

        let core_event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test".to_string(),
            EventSource::Core,
        );

        let cli_event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test".to_string(),
            EventSource::Cli,
        );

        assert!(filter.matches(&core_event));
        assert!(!filter.matches(&cli_event));
    }

    #[test]
    fn test_event_severity_filter() {
        let filter = EventSeverityFilter::new(EventSeverity::Warning);

        let warning_event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test".to_string(),
            EventSource::Core,
        );
        warning_event.severity = EventSeverity::Warning;

        let info_event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test".to_string(),
            EventSource::Core,
        );
        info_event.severity = EventSeverity::Info;

        assert!(filter.matches(&warning_event));
        assert!(!filter.matches(&info_event));
    }

    #[test]
    fn test_and_filter() {
        let type_filter = EventTypeFilter::single(EventType::System);
        let source_filter = EventSourceFilter::single(EventSource::Core);
        let and_filter = AndFilter::new(vec![Arc::new(type_filter), Arc::new(source_filter)]);

        let matching_event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test".to_string(),
            EventSource::Core,
        );

        let non_matching_event = UnifiedEvent::network(
            crate::events::NetworkAction::Blocked,
            "192.168.1.1".parse().unwrap(),
            443,
            crate::events::NetworkProtocol::Tcp,
            None,
            EventSource::Core,
        );

        assert!(and_filter.matches(&matching_event));
        assert!(!and_filter.matches(&non_matching_event));
    }

    #[tokio::test]
    async fn test_buffer_event_handler() {
        let handler = BufferEventHandler::new("test".to_string(), 100);

        let event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test".to_string(),
            EventSource::Core,
        );

        handler.handle_event(event.clone()).await.unwrap();

        let events = handler.get_events().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);

        let system_events = handler.get_events_by_type(EventType::System).await;
        assert_eq!(system_events.len(), 1);
    }
}
