use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use warp::ws::{Message, WebSocket};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::events::bus::EventBus;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WebSocketMessage {
    Event(serde_json::Value),
    Metrics(serde_json::Value),
    Status(serde_json::Value),
    Ping,
    Pong,
    Error(String),
}

pub struct WebSocketConnection {
    id: String,
    tx: mpsc::UnboundedSender<Result<Message, warp::Error>>,
}

impl WebSocketConnection {
    pub fn new(tx: mpsc::UnboundedSender<Result<Message, warp::Error>>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tx,
        }
    }

    pub fn send(&self, msg: WebSocketMessage) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&msg)?;
        let ws_msg = Message::text(json);
        self.tx.send(Ok(ws_msg))
            .map_err(|e| format!("Failed to send message: {}", e).into())
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

pub async fn handle_connection(ws: WebSocket, event_bus: Arc<EventBus>) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel();
    
    let connection = Arc::new(WebSocketConnection::new(tx));
    let connection_id = connection.id().to_string();
    
    info!("WebSocket connection established: {}", connection_id);

    // Spawn task to forward messages from channel to WebSocket
    let forward_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(message) = msg {
                if ws_tx.send(message).await.is_err() {
                    break;
                }
            }
        }
    });

    // Subscribe to event bus
    let event_connection = connection.clone();
    let mut event_subscriber = event_bus.subscribe();
    let event_task = tokio::spawn(async move {
        while let Ok(event) = event_subscriber.recv().await {
            if let Ok(event_json) = serde_json::to_value(&event) {
                let msg = WebSocketMessage::Event(event_json);
                if event_connection.send(msg).is_err() {
                    break;
                }
            }
        }
    });

    // Handle incoming messages
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                if msg.is_text() {
                    if let Ok(text) = msg.to_str() {
                        debug!("Received WebSocket message: {}", text);
                        
                        match serde_json::from_str::<WebSocketMessage>(text) {
                            Ok(WebSocketMessage::Ping) => {
                                let pong = WebSocketMessage::Pong;
                                if connection.send(pong).is_err() {
                                    break;
                                }
                            }
                            Ok(msg) => {
                                debug!("Received message: {:?}", msg);
                            }
                            Err(e) => {
                                warn!("Invalid message format: {}", e);
                                let error_msg = WebSocketMessage::Error(
                                    format!("Invalid message format: {}", e)
                                );
                                let _ = connection.send(error_msg);
                            }
                        }
                    }
                } else if msg.is_close() {
                    info!("WebSocket close message received for {}", connection_id);
                    break;
                }
            }
            Err(e) => {
                error!("WebSocket error for {}: {}", connection_id, e);
                break;
            }
        }
    }

    // Clean up
    info!("WebSocket connection closed: {}", connection_id);
    event_task.abort();
    forward_task.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_message_serialization() {
        let msg = WebSocketMessage::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"type":"Ping"}"#);

        let msg = WebSocketMessage::Error("test error".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("Error"));
        assert!(json.contains("test error"));
    }

    #[test]
    fn test_websocket_message_deserialization() {
        let json = r#"{"type":"Ping"}"#;
        let msg: WebSocketMessage = serde_json::from_str(json).unwrap();
        match msg {
            WebSocketMessage::Ping => {},
            _ => panic!("Expected Ping message"),
        }
    }
}
