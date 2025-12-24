//! Event bus for unified event distribution

use crate::events::{UnifiedEvent, EventFilter, EventHandler};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

/// Event bus for distributing events to multiple handlers
#[derive(Debug)]
pub struct EventBus {
    /// Event sender
    sender: broadcast::Sender<UnifiedEvent>,
    /// Registered handlers
    handlers: Arc<RwLock<HashMap<Uuid, HandlerInfo>>>,
    /// Event statistics
    stats: Arc<RwLock<EventBusStats>>,
}

/// Information about a registered handler
#[derive(Clone)]
struct HandlerInfo {
    /// Handler ID
    id: Uuid,
    /// Handler implementation
    handler: Arc<dyn EventHandler + Send + Sync>,
    /// Event filter
    filter: Option<Arc<dyn EventFilter + Send + Sync>>,
    /// Handler name
    name: String,
    /// Registration timestamp
    registered_at: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for HandlerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerInfo")
            .field("id", &self.id)
            .field("handler", &"<EventHandler>")
            .field("filter", &self.filter.is_some())
            .field("name", &self.name)
            .field("registered_at", &self.registered_at)
            .finish()
    }
}

/// Event bus statistics
#[derive(Debug, Default, Clone)]
pub struct EventBusStats {
    /// Total events sent
    pub events_sent: u64,
    /// Total events received
    pub events_received: u64,
    /// Total events processed
    pub events_processed: u64,
    /// Total events dropped
    pub events_dropped: u64,
    /// Number of registered handlers
    pub handlers_registered: usize,
    /// Number of active handlers
    pub handlers_active: usize,
}

/// Handle for interacting with the event bus
#[derive(Debug, Clone)]
pub struct EventBusHandle {
    /// Event sender
    sender: broadcast::Sender<UnifiedEvent>,
    /// Handlers reference
    handlers: Arc<RwLock<HashMap<Uuid, HandlerInfo>>>,
    /// Statistics reference
    stats: Arc<RwLock<EventBusStats>>,
}

impl EventBus {
    /// Create a new event bus
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        
        Self {
            sender,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(EventBusStats::default())),
        }
    }

    /// Create a new event bus with default capacity
    pub fn default() -> Self {
        Self::new(10000)
    }

    /// Get a handle to the event bus
    pub fn handle(&self) -> EventBusHandle {
        EventBusHandle {
            sender: self.sender.clone(),
            handlers: self.handlers.clone(),
            stats: self.stats.clone(),
        }
    }

    /// Start the event bus processing loop
    pub async fn start(&self) -> crate::Result<()> {
        let mut receiver = self.sender.subscribe();
        let handlers = self.handlers.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                // Update statistics
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.events_received += 1;
                }

                // Process event with all handlers
                let handlers_guard = handlers.read().await;
                let mut processed_count = 0;

                for handler_info in handlers_guard.values() {
                    // Check if event matches filter
                    if let Some(filter) = &handler_info.filter {
                        if !filter.matches(&event) {
                            continue;
                        }
                    }

                    // Handle the event
                    if let Err(e) = handler_info.handler.handle_event(event.clone()).await {
                        tracing::error!(
                            "Handler '{}' failed to process event {}: {}",
                            handler_info.name,
                            event.id,
                            e
                        );
                    } else {
                        processed_count += 1;
                    }
                }

                // Update statistics
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.events_processed += 1;
                    if processed_count == 0 {
                        stats_guard.events_dropped += 1;
                    }
                }
            }
        });

        tracing::info!("Event bus started");
        Ok(())
    }

    /// Register a new event handler
    pub async fn register_handler(
        &self,
        handler: Arc<dyn EventHandler + Send + Sync>,
        filter: Option<Arc<dyn EventFilter + Send + Sync>>,
        name: String,
    ) -> Uuid {
        let handler_id = Uuid::new_v4();
        let name_clone = name.clone();
        let handler_info = HandlerInfo {
            id: handler_id,
            handler,
            filter,
            name,
            registered_at: chrono::Utc::now(),
        };

        {
            let mut handlers = self.handlers.write().await;
            handlers.insert(handler_id, handler_info);
        }

        {
            let mut stats = self.stats.write().await;
            stats.handlers_registered = self.handlers.read().await.len();
            stats.handlers_active = stats.handlers_registered;
        }

        tracing::info!("Registered event handler '{}' with ID {}", name_clone, handler_id);
        handler_id
    }

    /// Unregister an event handler
    pub async fn unregister_handler(&self, handler_id: Uuid) -> bool {
        let removed = {
            let mut handlers = self.handlers.write().await;
            handlers.remove(&handler_id).is_some()
        };

        if removed {
            {
                let mut stats = self.stats.write().await;
                stats.handlers_registered = self.handlers.read().await.len();
                stats.handlers_active = stats.handlers_registered;
            }

            tracing::info!("Unregistered event handler with ID {}", handler_id);
        }

        removed
    }

    /// Get event bus statistics
    pub async fn stats(&self) -> EventBusStats {
        self.stats.read().await.clone()
    }

    /// Get list of registered handlers
    pub async fn list_handlers(&self) -> Vec<String> {
        let handlers = self.handlers.read().await;
        handlers
            .values()
            .map(|info| info.name.clone())
            .collect()
    }

    /// Get a streamer for this event bus
    pub async fn streamer(&self) -> broadcast::Receiver<UnifiedEvent> {
        self.sender.subscribe()
    }
}

impl EventBusHandle {
    /// Publish an event to the bus
    pub async fn publish(&self, event: UnifiedEvent) -> crate::Result<()> {
        match self.sender.send(event.clone()) {
            Ok(_) => {
                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.events_sent += 1;
                }

                tracing::debug!("Published event {} to event bus", event.id);
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to publish event {} to event bus: {}", event.id, e);
                Err(anyhow::anyhow!("Failed to publish event: {}", e))
            }
        }
    }

    /// Register a new event handler
    pub async fn register_handler(
        &self,
        handler: Arc<dyn EventHandler + Send + Sync>,
        filter: Option<Arc<dyn EventFilter + Send + Sync>>,
        name: String,
    ) -> Uuid {
        let handler_id = Uuid::new_v4();
        let name_clone = name.clone();
        let handler_info = HandlerInfo {
            id: handler_id,
            handler,
            filter,
            name,
            registered_at: chrono::Utc::now(),
        };

        {
            let mut handlers = self.handlers.write().await;
            handlers.insert(handler_id, handler_info);
        }

        {
            let mut stats = self.stats.write().await;
            stats.handlers_registered = self.handlers.read().await.len();
            stats.handlers_active = stats.handlers_registered;
        }

        tracing::info!("Registered event handler '{}' with ID {}", name_clone, handler_id);
        handler_id
    }

    /// Unregister an event handler
    pub async fn unregister_handler(&self, handler_id: Uuid) -> bool {
        let removed = {
            let mut handlers = self.handlers.write().await;
            handlers.remove(&handler_id).is_some()
        };

        if removed {
            {
                let mut stats = self.stats.write().await;
                stats.handlers_registered = self.handlers.read().await.len();
                stats.handlers_active = stats.handlers_registered;
            }

            tracing::info!("Unregistered event handler with ID {}", handler_id);
        }

        removed
    }

    /// Get event bus statistics
    pub async fn stats(&self) -> EventBusStats {
        self.stats.read().await.clone()
    }

    /// Get list of registered handlers
    pub async fn list_handlers(&self) -> Vec<String> {
        let handlers = self.handlers.read().await;
        handlers
            .values()
            .map(|info| info.name.clone())
            .collect()
    }

    /// Subscribe to events directly
    pub fn subscribe(&self) -> broadcast::Receiver<UnifiedEvent> {
        self.sender.subscribe()
    }

    /// Get a streamer for this event bus
    pub async fn streamer(&self) -> broadcast::Receiver<UnifiedEvent> {
        self.subscribe()
    }




}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventFilter, EventHandler};
    use std::sync::Arc;

    struct TestHandler {
        name: String,
        events: Arc<tokio::sync::Mutex<Vec<UnifiedEvent>>>,
    }

    impl EventHandler for TestHandler {
        async fn handle_event(&self, event: UnifiedEvent) -> crate::Result<()> {
            let mut events = self.events.lock().await;
            events.push(event);
            Ok(())
        }
    }

    struct TestFilter {
        allowed_sources: Vec<String>,
    }

    impl EventFilter for TestFilter {
        fn matches(&self, event: &UnifiedEvent) -> bool {
            self.allowed_sources.contains(&event.source.to_string())
        }
    }

    #[tokio::test]
    async fn test_event_bus_basic() {
        let bus = EventBus::default();
        let handle = bus.handle();

        // Start the event bus
        bus.start().await.unwrap();

        // Create a test handler
        let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let handler = Arc::new(TestHandler {
            name: "test".to_string(),
            events: events.clone(),
        });

        // Register the handler
        let handler_id = handle.register_handler(handler.clone(), None, "test".to_string()).await;

        // Publish an event
        let event = UnifiedEvent::system(
            crate::events::SystemAction::Started,
            "test".to_string(),
            "Test event".to_string(),
            crate::events::EventSource::Core,
        );

        handle.publish(event).await.unwrap();

        // Wait for event processing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Check that the event was received
        let received_events = events.lock().await;
        assert_eq!(received_events.len(), 1);

        // Unregister the handler
        assert!(handle.unregister_handler(handler_id).await);
    }

    #[tokio::test]
    async fn test_event_bus_with_filter() {
        let bus = EventBus::default();
        let handle = bus.handle();

        // Start the event bus
        bus.start().await.unwrap();

        // Create a test handler with filter
        let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let handler = Arc::new(TestHandler {
            name: "test".to_string(),
            events: events.clone(),
        });

        let filter = Arc::new(TestFilter {
            allowed_sources: vec!["Core".to_string()],
        });

        // Register the handler with filter
        handle.register_handler(handler.clone(), Some(filter), "test".to_string()).await;

        // Publish events from different sources
        let core_event = UnifiedEvent::system(
            crate::events::SystemAction::Started,
            "test".to_string(),
            "Core event".to_string(),
            crate::events::EventSource::Core,
        );

        let cli_event = UnifiedEvent::system(
            crate::events::SystemAction::Started,
            "test".to_string(),
            "CLI event".to_string(),
            crate::events::EventSource::Cli,
        );

        handle.publish(core_event).await.unwrap();
        handle.publish(cli_event).await.unwrap();

        // Wait for event processing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Check that only the core event was received
        let received_events = events.lock().await;
        assert_eq!(received_events.len(), 1);
        assert_eq!(received_events[0].source, crate::events::EventSource::Core);
    }

    #[tokio::test]
    async fn test_event_bus_stats() {
        let bus = EventBus::default();
        let handle = bus.handle();

        // Start the event bus
        bus.start().await.unwrap();

        // Get initial stats
        let initial_stats = handle.stats().await;
        assert_eq!(initial_stats.events_sent, 0);
        assert_eq!(initial_stats.events_received, 0);

        // Publish an event
        let event = UnifiedEvent::system(
            crate::events::SystemAction::Started,
            "test".to_string(),
            "Test event".to_string(),
            crate::events::EventSource::Core,
        );

        handle.publish(event).await.unwrap();

        // Wait for event processing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Check updated stats
        let updated_stats = handle.stats().await;
        assert_eq!(updated_stats.events_sent, 1);
        assert_eq!(updated_stats.events_received, 1);
        assert_eq!(updated_stats.events_processed, 1);
    }
}