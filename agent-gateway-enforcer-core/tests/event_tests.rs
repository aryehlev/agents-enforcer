//! Integration tests for event system
//!
//! These tests verify event publishing, subscription, filtering,
//! aggregation, and streaming functionality.

use agent_gateway_enforcer_core::events::*;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Test event handler that collects events
struct TestEventHandler {
    events: Arc<Mutex<Vec<UnifiedEvent>>>,
    name: String,
}

impl TestEventHandler {
    fn new(name: impl Into<String>) -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            name: name.into(),
        }
    }

    async fn get_events(&self) -> Vec<UnifiedEvent> {
        self.events.lock().await.clone()
    }

    async fn event_count(&self) -> usize {
        self.events.lock().await.len()
    }

    async fn clear(&self) {
        self.events.lock().await.clear();
    }
}

impl EventHandler for TestEventHandler {
    async fn handle_event(&self, event: UnifiedEvent) -> agent_gateway_enforcer_core::Result<()> {
        self.events.lock().await.push(event);
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Test event filter by type
struct TypeFilter {
    allowed_types: Vec<EventType>,
}

impl EventFilter for TypeFilter {
    fn matches(&self, event: &UnifiedEvent) -> bool {
        self.allowed_types.contains(&event.event_type)
    }

    fn description(&self) -> &str {
        "Type filter"
    }
}

/// Test event filter by severity
struct SeverityFilter {
    min_severity: EventSeverity,
}

impl EventFilter for SeverityFilter {
    fn matches(&self, event: &UnifiedEvent) -> bool {
        event.severity >= self.min_severity
    }

    fn description(&self) -> &str {
        "Severity filter"
    }
}

#[tokio::test]
async fn test_event_bus_creation() {
    let bus = EventBus::new(1000);
    let handle = bus.handle();

    let stats = handle.stats().await;
    assert_eq!(stats.events_sent, 0);
    assert_eq!(stats.handlers_registered, 0);
}

#[tokio::test]
async fn test_event_publishing() {
    let bus = EventBus::new(1000);
    let handle = bus.handle();

    bus.start().await.unwrap();

    // Create and publish an event
    let event = UnifiedEvent::network(
        NetworkAction::Blocked,
        "192.168.1.1".parse().unwrap(),
        443,
        NetworkProtocol::Tcp,
        Some(1234),
        EventSource::EbpfLinux,
    );

    handle.publish(event).await.unwrap();

    // Check stats
    let stats = handle.stats().await;
    assert_eq!(stats.events_sent, 1);
}

#[tokio::test]
async fn test_event_handler_registration() {
    let bus = EventBus::new(1000);
    let handle = bus.handle();

    bus.start().await.unwrap();

    let handler = Arc::new(TestEventHandler::new("test1"));

    // Register handler
    let handler_id = handle
        .register_handler(handler.clone(), None, "test1".to_string())
        .await;

    // Verify registration
    let stats = handle.stats().await;
    assert_eq!(stats.handlers_registered, 1);

    // Unregister
    let removed = handle.unregister_handler(handler_id).await;
    assert!(removed);

    let stats = handle.stats().await;
    assert_eq!(stats.handlers_registered, 0);
}

#[tokio::test]
async fn test_event_delivery() {
    let bus = EventBus::new(1000);
    let handle = bus.handle();

    bus.start().await.unwrap();

    let handler = Arc::new(TestEventHandler::new("test"));

    // Register handler
    handle
        .register_handler(handler.clone(), None, "test".to_string())
        .await;

    // Publish event
    let event = UnifiedEvent::system(
        SystemAction::Started,
        "backend".to_string(),
        "Backend started".to_string(),
        EventSource::Core,
    );

    handle.publish(event).await.unwrap();

    // Wait for event processing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify event was received
    let received = handler.get_events().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].event_type, EventType::System);
}

#[tokio::test]
async fn test_multiple_handlers() {
    let bus = EventBus::new(1000);
    let handle = bus.handle();

    bus.start().await.unwrap();

    let handler1 = Arc::new(TestEventHandler::new("handler1"));
    let handler2 = Arc::new(TestEventHandler::new("handler2"));
    let handler3 = Arc::new(TestEventHandler::new("handler3"));

    // Register all handlers
    handle
        .register_handler(handler1.clone(), None, "handler1".to_string())
        .await;
    handle
        .register_handler(handler2.clone(), None, "handler2".to_string())
        .await;
    handle
        .register_handler(handler3.clone(), None, "handler3".to_string())
        .await;

    // Publish event
    let event = UnifiedEvent::network(
        NetworkAction::Allowed,
        "10.0.0.1".parse().unwrap(),
        80,
        NetworkProtocol::Tcp,
        Some(5678),
        EventSource::Core,
    );

    handle.publish(event).await.unwrap();

    // Wait for processing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // All handlers should receive the event
    assert_eq!(handler1.event_count().await, 1);
    assert_eq!(handler2.event_count().await, 1);
    assert_eq!(handler3.event_count().await, 1);
}

#[tokio::test]
async fn test_event_filtering_by_type() {
    let bus = EventBus::new(1000);
    let handle = bus.handle();

    bus.start().await.unwrap();

    let handler = Arc::new(TestEventHandler::new("filtered"));

    // Register handler with type filter (only network events)
    let filter = Arc::new(TypeFilter {
        allowed_types: vec![EventType::Network],
    });

    handle
        .register_handler(handler.clone(), Some(filter), "filtered".to_string())
        .await;

    // Publish network event (should be received)
    let network_event = UnifiedEvent::network(
        NetworkAction::Blocked,
        "192.168.1.1".parse().unwrap(),
        443,
        NetworkProtocol::Tcp,
        None,
        EventSource::EbpfLinux,
    );

    handle.publish(network_event).await.unwrap();

    // Publish system event (should be filtered out)
    let system_event = UnifiedEvent::system(
        SystemAction::Started,
        "test".to_string(),
        "Test".to_string(),
        EventSource::Core,
    );

    handle.publish(system_event).await.unwrap();

    // Wait for processing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Handler should only receive network event
    let received = handler.get_events().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].event_type, EventType::Network);
}

#[tokio::test]
async fn test_event_filtering_by_severity() {
    let bus = EventBus::new(1000);
    let handle = bus.handle();

    bus.start().await.unwrap();

    let handler = Arc::new(TestEventHandler::new("severity_filtered"));

    // Register handler with severity filter (only warning and above)
    let filter = Arc::new(SeverityFilter {
        min_severity: EventSeverity::Warning,
    });

    handle
        .register_handler(handler.clone(), Some(filter), "severity_filtered".to_string())
        .await;

    // Publish info event (should be filtered out)
    let info_event = UnifiedEvent::system(
        SystemAction::HealthCheck,
        "test".to_string(),
        "Health check".to_string(),
        EventSource::Core,
    );

    handle.publish(info_event).await.unwrap();

    // Publish error event (should be received)
    let error_event = UnifiedEvent::system(
        SystemAction::Error,
        "test".to_string(),
        "Error occurred".to_string(),
        EventSource::Core,
    );

    handle.publish(error_event).await.unwrap();

    // Wait for processing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Handler should only receive error event
    let received = handler.get_events().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].severity, EventSeverity::Error);
}

#[tokio::test]
async fn test_event_bus_stats() {
    let bus = EventBus::new(1000);
    let handle = bus.handle();

    bus.start().await.unwrap();

    let handler = Arc::new(TestEventHandler::new("stats_test"));
    handle
        .register_handler(handler, None, "stats_test".to_string())
        .await;

    // Publish multiple events
    for i in 0..5 {
        let event = UnifiedEvent::network(
            NetworkAction::Allowed,
            "10.0.0.1".parse().unwrap(),
            80 + i,
            NetworkProtocol::Tcp,
            Some(1000 + i as u32),
            EventSource::Core,
        );
        handle.publish(event).await.unwrap();
    }

    // Wait for processing
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let stats = handle.stats().await;
    assert_eq!(stats.events_sent, 5);
    assert_eq!(stats.events_received, 5);
    assert_eq!(stats.events_processed, 5);
    assert_eq!(stats.handlers_registered, 1);
}

#[tokio::test]
async fn test_event_list_handlers() {
    let bus = EventBus::new(1000);
    let handle = bus.handle();

    bus.start().await.unwrap();

    // Register multiple handlers
    let handler1 = Arc::new(TestEventHandler::new("handler1"));
    let handler2 = Arc::new(TestEventHandler::new("handler2"));

    handle
        .register_handler(handler1, None, "handler1".to_string())
        .await;
    handle
        .register_handler(handler2, None, "handler2".to_string())
        .await;

    let handlers = handle.list_handlers().await;
    assert_eq!(handlers.len(), 2);
    assert!(handlers.contains(&"handler1".to_string()));
    assert!(handlers.contains(&"handler2".to_string()));
}

#[tokio::test]
async fn test_event_creation_helpers() {
    // Test network event creation
    let network_event = UnifiedEvent::network(
        NetworkAction::Blocked,
        "192.168.1.100".parse().unwrap(),
        443,
        NetworkProtocol::Tcp,
        Some(1234),
        EventSource::EbpfLinux,
    );

    assert_eq!(network_event.event_type, EventType::Network);
    assert_eq!(network_event.severity, EventSeverity::Warning);

    // Test file access event creation
    let file_event = UnifiedEvent::file_access(
        FileAction::Blocked,
        "/etc/shadow".to_string(),
        FileAccessType::Read,
        Some(5678),
        EventSource::MacOSDesktop,
    );

    assert_eq!(file_event.event_type, EventType::FileAccess);
    assert_eq!(file_event.severity, EventSeverity::Warning);

    // Test system event creation
    let system_event = UnifiedEvent::system(
        SystemAction::Started,
        "backend".to_string(),
        "Backend started successfully".to_string(),
        EventSource::Core,
    );

    assert_eq!(system_event.event_type, EventType::System);
    assert_eq!(system_event.severity, EventSeverity::Info);

    // Test security event creation
    let security_event = UnifiedEvent::security(
        SecurityThreatType::Malware,
        SecuritySeverity::High,
        "Malicious file detected".to_string(),
        EventSource::WindowsDesktop,
    );

    assert_eq!(security_event.event_type, EventType::Security);
    assert_eq!(security_event.severity, EventSeverity::Critical);
}

#[tokio::test]
async fn test_event_metadata() {
    let mut event = UnifiedEvent::system(
        SystemAction::Started,
        "test".to_string(),
        "Test event".to_string(),
        EventSource::Core,
    );

    // Add tags
    event = event.with_tag("environment".to_string(), "production".to_string());
    event = event.with_tag("region".to_string(), "us-west-2".to_string());

    assert_eq!(
        event.metadata.tags.get("environment"),
        Some(&"production".to_string())
    );
    assert_eq!(
        event.metadata.tags.get("region"),
        Some(&"us-west-2".to_string())
    );

    // Add custom fields
    let mut custom_fields = std::collections::HashMap::new();
    custom_fields.insert("version".to_string(), serde_json::json!("1.0.0"));
    custom_fields.insert("build".to_string(), serde_json::json!(12345));

    event = event.with_custom_fields(custom_fields);

    assert_eq!(
        event.metadata.custom_fields.get("version"),
        Some(&serde_json::json!("1.0.0"))
    );
}

#[tokio::test]
async fn test_event_severity_ordering() {
    assert!(EventSeverity::Debug < EventSeverity::Info);
    assert!(EventSeverity::Info < EventSeverity::Warning);
    assert!(EventSeverity::Warning < EventSeverity::Error);
    assert!(EventSeverity::Error < EventSeverity::Critical);
}

#[tokio::test]
async fn test_event_severity_from_str() {
    assert_eq!(
        EventSeverity::from_str("debug"),
        Some(EventSeverity::Debug)
    );
    assert_eq!(EventSeverity::from_str("info"), Some(EventSeverity::Info));
    assert_eq!(
        EventSeverity::from_str("warning"),
        Some(EventSeverity::Warning)
    );
    assert_eq!(
        EventSeverity::from_str("error"),
        Some(EventSeverity::Error)
    );
    assert_eq!(
        EventSeverity::from_str("critical"),
        Some(EventSeverity::Critical)
    );
    assert_eq!(EventSeverity::from_str("invalid"), None);
}

#[tokio::test]
async fn test_event_source_display() {
    assert_eq!(EventSource::EbpfLinux.to_string(), "ebpf_linux");
    assert_eq!(EventSource::MacOSDesktop.to_string(), "macos_desktop");
    assert_eq!(EventSource::WindowsDesktop.to_string(), "windows_desktop");
    assert_eq!(EventSource::Core.to_string(), "core");
}

#[tokio::test]
async fn test_event_type_display() {
    assert_eq!(EventType::Network.to_string(), "network");
    assert_eq!(EventType::FileAccess.to_string(), "file_access");
    assert_eq!(EventType::System.to_string(), "system");
    assert_eq!(EventType::Security.to_string(), "security");
}
