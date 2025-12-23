use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use warp::{Filter, Rejection, Reply};
use warp::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

pub mod api;
pub mod websocket;
pub mod static_files;

use crate::config::manager::ConfigManager;
use crate::config::UnifiedConfig;
use crate::metrics::registry::MetricsRegistry;
use crate::events::bus::EventBus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    pub host: String,
    pub port: u16,
    pub enable_cors: bool,
    pub static_dir: String,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            enable_cors: true,
            static_dir: "static".to_string(),
        }
    }
}

pub struct WebServer {
    config: WebConfig,
    config_manager: Arc<RwLock<ConfigManager>>,
    metrics_registry: Arc<MetricsRegistry>,
    event_bus: Arc<EventBus>,
}

impl WebServer {
    pub fn new(
        config: WebConfig,
        config_manager: Arc<RwLock<ConfigManager>>,
        metrics_registry: Arc<MetricsRegistry>,
        event_bus: Arc<EventBus>,
    ) -> Self {
        Self {
            config,
            config_manager,
            metrics_registry,
            event_bus,
        }
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let addr: SocketAddr = format!("{}:{}", self.config.host, self.config.port)
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        info!("Starting web server on {}", addr);

        // Create shared state
        let config_manager = self.config_manager.clone();
        let metrics_registry = self.metrics_registry.clone();
        let event_bus = self.event_bus.clone();
        let static_dir = self.config.static_dir.clone();

        // API routes
        let api_routes = self.api_routes(
            config_manager.clone(),
            metrics_registry.clone(),
            event_bus.clone(),
        );

        // WebSocket routes
        let ws_routes = self.websocket_routes(event_bus.clone());

        // Static file routes
        let static_routes = static_files::static_routes(static_dir);

        // Combine all routes
        let routes = api_routes
            .or(ws_routes)
            .or(static_routes)
            .recover(handle_rejection);

        // Apply CORS if enabled
        let routes = if self.config.enable_cors {
            routes.with(warp::cors()
                .allow_any_origin()
                .allow_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
                .allow_headers(vec!["Content-Type", "Authorization"]))
                .boxed()
        } else {
            routes.boxed()
        };

        info!("Web server listening on http://{}", addr);
        warp::serve(routes).run(addr).await;

        Ok(())
    }

    fn api_routes(
        &self,
        config_manager: Arc<RwLock<ConfigManager>>,
        metrics_registry: Arc<MetricsRegistry>,
        event_bus: Arc<EventBus>,
    ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
        let status_route = warp::path!("api" / "v1" / "status")
            .and(warp::get())
            .and(with_state(config_manager.clone(), metrics_registry.clone(), event_bus.clone()))
            .and_then(handlers::get_status);

        let metrics_route = warp::path!("api" / "v1" / "metrics")
            .and(warp::get())
            .and(warp::query::<MetricsQuery>())
            .and(with_metrics(metrics_registry.clone()))
            .and_then(handlers::get_metrics);

        let events_route = warp::path!("api" / "v1" / "events")
            .and(warp::get())
            .and(warp::query::<EventsQuery>())
            .and(with_event_bus(event_bus.clone()))
            .and_then(handlers::get_events);

        let get_config_route = warp::path!("api" / "v1" / "config")
            .and(warp::get())
            .and(with_config(config_manager.clone()))
            .and_then(handlers::get_config);

        let update_config_route = warp::path!("api" / "v1" / "config")
            .and(warp::put())
            .and(warp::body::json())
            .and(with_config(config_manager.clone()))
            .and_then(handlers::update_config);

        status_route
            .or(metrics_route)
            .or(events_route)
            .or(get_config_route)
            .or(update_config_route)
    }

    fn websocket_routes(
        &self,
        event_bus: Arc<EventBus>,
    ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
        warp::path("ws")
            .and(warp::ws())
            .and(with_event_bus(event_bus))
            .map(|ws: warp::ws::Ws, event_bus: Arc<EventBus>| {
                ws.on_upgrade(move |socket| websocket::handle_connection(socket, event_bus))
            })
    }
}

// Helper functions for dependency injection
fn with_state(
    config: Arc<RwLock<ConfigManager>>,
    metrics: Arc<MetricsRegistry>,
    events: Arc<EventBus>,
) -> impl Filter<Extract = (Arc<RwLock<ConfigManager>>, Arc<MetricsRegistry>, Arc<EventBus>), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || (config.clone(), metrics.clone(), events.clone()))
}

fn with_config(
    config: Arc<RwLock<ConfigManager>>,
) -> impl Filter<Extract = (Arc<RwLock<ConfigManager>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || config.clone())
}

fn with_metrics(
    metrics: Arc<MetricsRegistry>,
) -> impl Filter<Extract = (Arc<MetricsRegistry>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || metrics.clone())
}

fn with_event_bus(
    event_bus: Arc<EventBus>,
) -> impl Filter<Extract = (Arc<EventBus>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || event_bus.clone())
}

// Query parameter structures
#[derive(Debug, Deserialize)]
struct MetricsQuery {
    time_range: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    filter: Option<String>,
    limit: Option<usize>,
}

// API response structures
#[derive(Debug, Serialize)]
struct StatusResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
    backend: String,
    active_connections: usize,
}

#[derive(Debug, Serialize)]
struct MetricsResponse {
    timestamp: String,
    metrics: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct EventsResponse {
    events: Vec<serde_json::Value>,
    total: usize,
}

#[derive(Debug, Serialize)]
struct ConfigResponse {
    config: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

// Request handlers
mod handlers {
    use super::*;
    use warp::http::StatusCode;

    pub async fn get_status(
        config: Arc<RwLock<ConfigManager>>,
        metrics: Arc<MetricsRegistry>,
        events: Arc<EventBus>,
    ) -> Result<impl Reply, Rejection> {
        let config_guard = config.read().await;
        let current_config = config_guard.get_config();
        
        let backend = current_config
            .backend
            .as_ref()
            .and_then(|b| b.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let response = StatusResponse {
            status: "running".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: 0, // TODO: Track actual uptime
            backend,
            active_connections: 0, // TODO: Track actual connections
        };

        Ok(warp::reply::json(&response))
    }

    pub async fn get_metrics(
        query: MetricsQuery,
        metrics: Arc<MetricsRegistry>,
    ) -> Result<impl Reply, Rejection> {
        let metrics_data = metrics.gather_metrics();
        
        let response = MetricsResponse {
            timestamp: chrono::Utc::now().to_rfc3339(),
            metrics: serde_json::to_value(&metrics_data).unwrap_or(serde_json::json!({})),
        };

        Ok(warp::reply::json(&response))
    }

    pub async fn get_events(
        query: EventsQuery,
        event_bus: Arc<EventBus>,
    ) -> Result<impl Reply, Rejection> {
        // TODO: Implement event retrieval from event bus
        let events = vec![];
        
        let response = EventsResponse {
            events,
            total: 0,
        };

        Ok(warp::reply::json(&response))
    }

    pub async fn get_config(
        config: Arc<RwLock<ConfigManager>>,
    ) -> Result<impl Reply, Rejection> {
        let config_guard = config.read().await;
        let current_config = config_guard.get_config();
        
        let response = ConfigResponse {
            config: serde_json::to_value(&current_config).unwrap_or(serde_json::json!({})),
        };

        Ok(warp::reply::json(&response))
    }

    pub async fn update_config(
        new_config: serde_json::Value,
        config: Arc<RwLock<ConfigManager>>,
    ) -> Result<impl Reply, Rejection> {
        let mut config_guard = config.write().await;
        
        // Convert JSON value to UnifiedConfig
        let config_update: UnifiedConfig = 
            serde_json::from_value(new_config)
                .map_err(|e| {
                    warp::reject::custom(ApiError::BadRequest(format!("Invalid config: {}", e)))
                })?;

        // Update config
        {
            let mut current_config = config_guard.write().await;
            *current_config = config_update;
        }

        let response = ConfigResponse {
            config: serde_json::to_value(&config_guard.read().await).unwrap_or(serde_json::json!({})),
        };

        Ok(warp::reply::json(&response))
    }
}

// Custom error types
#[derive(Debug)]
enum ApiError {
    BadRequest(String),
    NotFound(String),
    InternalError(String),
}

impl warp::reject::Reject for ApiError {}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Resource not found";
    } else if let Some(api_err) = err.find::<ApiError>() {
        match api_err {
            ApiError::BadRequest(msg) => {
                code = StatusCode::BAD_REQUEST;
                message = msg.as_str();
            }
            ApiError::NotFound(msg) => {
                code = StatusCode::NOT_FOUND;
                message = msg.as_str();
            }
            ApiError::InternalError(msg) => {
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message = msg.as_str();
            }
        }
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "Method not allowed";
    } else {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal server error";
    }

    let json = warp::reply::json(&ErrorResponse {
        error: code.canonical_reason().unwrap_or("Unknown").to_string(),
        message: message.to_string(),
    });

    Ok(warp::reply::with_status(json, code))
}
