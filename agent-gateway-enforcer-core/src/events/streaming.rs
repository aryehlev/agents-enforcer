//! Event streaming for real-time UI updates

use crate::events::{UnifiedEvent, EventFilter, EventBusHandle};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

/// Event streamer for real-time event distribution
#[derive(Debug)]
pub struct EventStreamer {
    /// Event bus handle
    event_bus: Arc<EventBusHandle>,
    /// Active streams
    streams: Arc<RwLock<HashMap<Uuid, StreamInfo>>>,
    /// Stream configuration
    config: StreamerConfig,
}

/// Information about an active stream
#[derive(Debug, Clone)]
struct StreamInfo {
    /// Stream ID
    id: Uuid,
    /// Stream name
    name: String,
    /// Event filter
    filter: Option<Arc<dyn EventFilter + Send + Sync>>,
    /// Stream sender
    sender: broadcast::Sender<StreamedEvent>,
    /// Creation timestamp
    created_at: chrono::DateTime<chrono::Utc>,
    /// Last activity timestamp
    last_activity: chrono::DateTime<chrono::Utc>,
    /// Events sent count
    events_sent: u64,
}

/// Streamer configuration
#[derive(Debug, Clone)]
pub struct StreamerConfig {
    /// Maximum number of concurrent streams
    pub max_streams: usize,
    /// Default stream buffer size
    pub default_buffer_size: usize,
    /// Stream timeout in seconds
    pub stream_timeout_seconds: u64,
    /// Maximum events per stream
    pub max_events_per_stream: u64,
}

impl Default for StreamerConfig {
    fn default() -> Self {
        Self {
            max_streams: 1000,
            default_buffer_size: 1000,
            stream_timeout_seconds: 300, // 5 minutes
            max_events_per_stream: 10000,
        }
    }
}

/// Handle for an event stream
#[derive(Debug)]
pub struct StreamHandle {
    /// Stream ID
    id: Uuid,
    /// Stream receiver
    receiver: broadcast::Receiver<StreamedEvent>,
    /// Streamer reference
    streamer: Arc<EventStreamer>,
}

impl StreamHandle {
    /// Create a new subscription to this stream
    pub async fn resubscribe(&self) -> Option<Self> {
        self.streamer.subscribe_to_stream(self.id).await.map(|receiver| {
            Self {
                id: self.id,
                receiver,
                streamer: self.streamer.clone(),
            }
        })
    }
}

/// Streamed event with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamedEvent {
    /// The original event
    pub event: UnifiedEvent,
    /// Stream metadata
    pub metadata: StreamMetadata,
}

/// Stream metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMetadata {
    /// Stream ID
    pub stream_id: Uuid,
    /// Sequence number
    pub sequence_number: u64,
    /// Timestamp when streamed
    pub streamed_at: chrono::DateTime<chrono::Utc>,
    /// Total events in stream
    pub total_events: u64,
}

/// Stream statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamStats {
    /// Number of active streams
    pub active_streams: usize,
    /// Total events streamed
    pub total_events_streamed: u64,
    /// Average events per stream
    pub avg_events_per_stream: f64,
    /// Oldest stream age in seconds
    pub oldest_stream_age_seconds: u64,
}

impl EventStreamer {
    /// Create a new event streamer
    pub fn new(event_bus: Arc<EventBusHandle>, config: StreamerConfig) -> Self {
        Self {
            event_bus,
            streams: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a new event streamer with default configuration
    pub fn new_default(event_bus: Arc<EventBusHandle>) -> Self {
        Self::new(event_bus, StreamerConfig::default())
    }

    /// Create a new event stream
    pub async fn create_stream(
        &self,
        name: String,
        filter: Option<Arc<dyn EventFilter + Send + Sync>>,
    ) -> crate::Result<broadcast::Receiver<StreamedEvent>> {
        // Check stream limit
        {
            let streams = self.streams.read().await;
            if streams.len() >= self.config.max_streams {
                return Err(anyhow::anyhow!(
                    "Maximum number of streams reached"
                ));
            }
        }

        let stream_id = Uuid::new_v4();
        let (sender, receiver) = broadcast::channel(self.config.default_buffer_size);

        let stream_info = StreamInfo {
            id: stream_id,
            name: name.clone(),
            filter,
            sender,
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            events_sent: 0,
        };

        {
            let mut streams = self.streams.write().await;
            streams.insert(stream_id, stream_info);
        }

        tracing::info!("Created event stream '{}' with ID {}", name, stream_id);

        Ok(receiver)
    }

    /// Get stream statistics
    pub async fn stats(&self) -> StreamStats {
        let streams = self.streams.read().await;
        let now = chrono::Utc::now();

        let active_streams = streams.len();
        let total_events_streamed: u64 = streams.values().map(|s| s.events_sent).sum();
        let avg_events_per_stream = if active_streams > 0 {
            total_events_streamed as f64 / active_streams as f64
        } else {
            0.0
        };

        let oldest_stream_age_seconds = streams
            .values()
            .map(|s| (now - s.created_at).num_seconds() as u64)
            .max()
            .unwrap_or(0);

        StreamStats {
            active_streams,
            total_events_streamed,
            avg_events_per_stream,
            oldest_stream_age_seconds,
        }
    }

    /// List active streams
    pub async fn list_streams(&self) -> Vec<String> {
        let streams = self.streams.read().await;
        streams.values().map(|s| s.name.clone()).collect()
    }

    /// Subscribe to an existing stream by ID
    pub async fn subscribe_to_stream(&self, stream_id: Uuid) -> Option<broadcast::Receiver<StreamedEvent>> {
        let streams = self.streams.read().await;
        streams.get(&stream_id).map(|info| info.sender.subscribe())
    }

    /// Remove a stream
    pub async fn remove_stream(&self, stream_id: Uuid) -> bool {
        let removed = {
            let mut streams = self.streams.write().await;
            streams.remove(&stream_id).is_some()
        };

        if removed {
            tracing::info!("Removed event stream with ID {}", stream_id);
        }

        removed
    }

    /// Start the event streamer
    pub async fn start(&self) -> crate::Result<()> {
        let event_bus = self.event_bus.clone();
        let streams = self.streams.clone();
        let config = self.config.clone();

        // Subscribe to events from the event bus
        let mut receiver = event_bus.subscribe();

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                let streams_guard = streams.read().await;
                
                // Collect stream IDs that need updates
                let mut successful_streams = Vec::new();
                
                // Send event to all matching streams
                for stream_info in streams_guard.values() {
                    // Check if event matches the stream's filter
                    if let Some(filter) = &stream_info.filter {
                        if !filter.matches(&event) {
                            continue;
                        }
                    }

                    // Create streamed event
                    let streamed_event = StreamedEvent {
                        event: event.clone(),
                        metadata: StreamMetadata {
                            stream_id: stream_info.id,
                            sequence_number: stream_info.events_sent + 1,
                            streamed_at: chrono::Utc::now(),
                            total_events: stream_info.events_sent + 1,
                        },
                    };

                    // Send to stream
                    if let Err(_) = stream_info.sender.send(streamed_event) {
                        tracing::warn!(
                            "Failed to send event to stream '{}'. Stream may be closed.",
                            stream_info.name
                        );
                    } else {
                        successful_streams.push(stream_info.id);
                    }
                }
                
                // Update stream statistics outside the loop
                if !successful_streams.is_empty() {
                    drop(streams_guard);
                    let mut streams_mut = streams.write().await;
                    for stream_id in successful_streams {
                        if let Some(stream_info) = streams_mut.get_mut(&stream_id) {
                            stream_info.events_sent += 1;
                            stream_info.last_activity = chrono::Utc::now();
                        }
                    }
                }
            }
        });

        // Start stream cleanup task
        self.start_cleanup_task()?;

        tracing::info!("Event streamer started");
        Ok(())
    }

    /// Start the stream cleanup task
    fn start_cleanup_task(&self) -> crate::Result<()> {
        let streams = self.streams.clone();
        let timeout_seconds = self.config.stream_timeout_seconds;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(60), // Check every minute
            );

            loop {
                interval.tick().await;

                let now = chrono::Utc::now();
                let mut streams_to_remove = Vec::new();

                {
                    let streams_guard = streams.read().await;
                    for (stream_id, stream_info) in streams_guard.iter() {
                        let age_seconds = (now - stream_info.last_activity).num_seconds() as u64;
                        
                        // Remove stream if it's too old or has too many events
                        if age_seconds > timeout_seconds
                            || stream_info.events_sent > 1000 // Hardcoded limit
                        {
                            streams_to_remove.push(*stream_id);
                        }
                    }
                }

                // Remove old streams
                if !streams_to_remove.is_empty() {
                    let mut streams_mut = streams.write().await;
                    for stream_id in streams_to_remove {
                        if streams_mut.remove(&stream_id).is_some() {
                            tracing::info!("Removed expired stream with ID {}", stream_id);
                        }
                    }
                }
            }
        });

        Ok(())
    }
}

impl Clone for EventStreamer {
    fn clone(&self) -> Self {
        Self {
            event_bus: self.event_bus.clone(),
            streams: self.streams.clone(),
            config: self.config.clone(),
        }
    }
}

impl StreamHandle {
    /// Get the stream ID
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Receive the next event from the stream
    pub async fn recv(&mut self) -> Option<StreamedEvent> {
        self.receiver.recv().await.ok()
    }

    /// Convert to a stream
    pub fn into_stream(self) -> impl futures::Stream<Item = StreamedEvent> {
        BroadcastStream::new(self.receiver)
            .filter_map(|result| result.ok())
    }

    /// Get stream statistics
    pub async fn stats(&self) -> Option<StreamStats> {
        self.streamer.stats().await.into()
    }

    /// Close the stream
    pub async fn close(self) {
        self.streamer.remove_stream(self.id).await;
    }
}

/// WebSocket event streamer for web dashboard
#[derive(Debug)]
pub struct WebSocketStreamer {
    /// Event streamer
    event_streamer: Arc<EventStreamer>,
    /// Active WebSocket connections
    connections: Arc<RwLock<HashMap<Uuid, WebSocketConnection>>>,
}

/// WebSocket connection information
#[derive(Debug)]
struct WebSocketConnection {
    /// Connection ID
    id: Uuid,
    /// Stream handle
    stream_handle: StreamHandle,
    /// Connection metadata
    metadata: ConnectionMetadata,
}

/// Connection metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetadata {
    /// Client ID
    pub client_id: String,
    /// User agent
    pub user_agent: Option<String>,
    /// IP address
    pub ip_address: Option<String>,
    /// Connected at
    pub connected_at: chrono::DateTime<chrono::Utc>,
}

impl WebSocketStreamer {
    /// Create a new WebSocket streamer
    pub fn new(event_streamer: Arc<EventStreamer>) -> Self {
        Self {
            event_streamer,
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new WebSocket connection
    pub async fn create_connection(
        &self,
        client_id: String,
        filter: Option<Arc<dyn EventFilter + Send + Sync>>,
        metadata: ConnectionMetadata,
    ) -> crate::Result<Uuid> {
        let stream_handle = self
            .event_streamer
            .create_stream(format!("ws-{}", client_id), filter)
            .await?;

        let connection_id = Uuid::new_v4();
        let stream_handle = StreamHandle {
            id: connection_id,
            receiver: stream_handle,
            streamer: self.event_streamer.clone()
        };
        let connection = WebSocketConnection {
            id: connection_id,
            stream_handle,
            metadata,
        };

        {
            let mut connections = self.connections.write().await;
            connections.insert(connection_id, connection);
        }

        tracing::info!("Created WebSocket connection for client '{}'", client_id);
        Ok(connection_id)
    }

    /// Get events for a WebSocket connection
    pub async fn get_connection_events(
        &self,
        connection_id: Uuid,
    ) -> Option<impl futures::Stream<Item = StreamedEvent>> {
        let connections = self.connections.read().await;
        let stream_handle = connections.get(&connection_id)?;
        let new_handle = stream_handle.stream_handle.resubscribe().await?;
        Some(new_handle.into_stream())
    }

    /// Close a WebSocket connection
    pub async fn close_connection(&self, connection_id: Uuid) -> bool {
        let removed = {
            let mut connections = self.connections.write().await;
            if let Some(connection) = connections.remove(&connection_id) {
                connection.stream_handle.close().await;
                true
            } else {
                false
            }
        };

        if removed {
            tracing::info!("Closed WebSocket connection with ID {}", connection_id);
        }

        removed
    }

    /// Get connection statistics
    pub async fn stats(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventBus, EventFilter, EventTypeFilter, SystemAction, EventSource};

    #[tokio::test]
    async fn test_event_streamer_basic() {
        let event_bus = EventBus::default();
        let event_bus_handle = event_bus.handle();
        event_bus.start().await.unwrap();

        let streamer = EventStreamer::new_default(Arc::new(event_bus_handle));
        streamer.start().await.unwrap();

        // Create a stream
        let stream = streamer
            .create_stream("test".to_string(), None)
            .await
            .unwrap();

        // Publish an event
        let event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "Test event".to_string(),
            EventSource::Core,
        );

        streamer.event_bus.publish(event).await.unwrap();

        // Receive the event
        let mut stream_handle = stream;
        let streamed_event = stream_handle.recv().await.unwrap();
        assert_eq!(streamed_event.metadata.sequence_number, 1);
    }

    #[tokio::test]
    async fn test_event_streamer_with_filter() {
        let event_bus = EventBus::default();
        let event_bus_handle = event_bus.handle();
        event_bus.start().await.unwrap();

        let streamer = EventStreamer::new_default(Arc::new(event_bus_handle));
        streamer.start().await.unwrap();

        // Create a stream with filter
        let filter = Arc::new(EventTypeFilter::single(EventType::System));
        let stream = streamer
            .create_stream("test".to_string(), Some(filter))
            .await
            .unwrap();

        // Publish events of different types
        let system_event = UnifiedEvent::system(
            SystemAction::Started,
            "test".to_string(),
            "System event".to_string(),
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

        streamer.event_bus.publish(system_event).await.unwrap();
        streamer.event_bus.publish(network_event).await.unwrap();

        // Should only receive the system event
        let mut stream_handle = stream;
        let streamed_event = stream_handle.recv().await.unwrap();
        assert_eq!(streamed_event.event.event_type, EventType::System);

        // No more events
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert!(stream_handle.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_streamer_stats() {
        let event_bus = EventBus::default();
        let event_bus_handle = event_bus.handle();
        event_bus.start().await.unwrap();

        let streamer = EventStreamer::new_default(Arc::new(event_bus_handle));
        streamer.start().await.unwrap();

        // Create streams
        streamer.create_stream("test1".to_string(), None).await.unwrap();
        streamer.create_stream("test2".to_string(), None).await.unwrap();

        // Check stats
        let stats = streamer.stats().await;
        assert_eq!(stats.active_streams, 2);
    }
}