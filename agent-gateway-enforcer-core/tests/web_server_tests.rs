//! Integration tests for web server API endpoints
//!
//! These tests verify the web server's REST API, WebSocket connections,
//! and static file serving.

use agent_gateway_enforcer_common::config::*;
use agent_gateway_enforcer_core::config::ConfigManager;
use agent_gateway_enforcer_core::events::EventBus;
use agent_gateway_enforcer_core::metrics::registry::MetricsRegistry;
use agent_gateway_enforcer_core::web::{WebConfig, WebServer};
use reqwest;
use serde_json::Value;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

/// Helper to create a test web server
async fn create_test_server(
    port: u16,
) -> (
    Arc<RwLock<ConfigManager>>,
    Arc<MetricsRegistry>,
    Arc<EventBus>,
) {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let test_config = UnifiedConfig::default();
    let yaml = serde_yaml::to_string(&test_config).unwrap();
    std::fs::write(&config_path, yaml).unwrap();

    let config_manager = Arc::new(RwLock::new(ConfigManager::new(&config_path)));
    let metrics_registry = Arc::new(MetricsRegistry::new_default().unwrap());
    let event_bus = Arc::new(EventBus::new(1000));

    // Load initial config
    config_manager.write().await.load().await.unwrap();

    (config_manager, metrics_registry, event_bus)
}

/// Helper to wait for server to start
async fn wait_for_server(port: u16) {
    for _ in 0..30 {
        if let Ok(_) = reqwest::get(format!("http://127.0.0.1:{}/api/v1/status", port)).await {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("Server failed to start on port {}", port);
}

#[tokio::test]
async fn test_status_endpoint() {
    let port = 18080;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(web_config, config_manager, metrics_registry, event_bus);

    // Start server in background
    tokio::spawn(async move {
        let _ = server.start().await;
    });

    // Wait for server to start
    wait_for_server(port).await;

    // Test status endpoint
    let response = reqwest::get(format!("http://127.0.0.1:{}/api/v1/status", port))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    assert!(body.get("status").is_some());
    assert!(body.get("version").is_some());
    assert_eq!(body["status"], "running");
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let port = 18081;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(web_config, config_manager, metrics_registry, event_bus);

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    wait_for_server(port).await;

    // Test metrics endpoint
    let response = reqwest::get(format!("http://127.0.0.1:{}/api/v1/metrics", port))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    assert!(body.get("timestamp").is_some());
    assert!(body.get("metrics").is_some());
}

#[tokio::test]
async fn test_get_config_endpoint() {
    let port = 18082;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(web_config, config_manager, metrics_registry, event_bus);

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    wait_for_server(port).await;

    // Test get config endpoint
    let response = reqwest::get(format!("http://127.0.0.1:{}/api/v1/config", port))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    assert!(body.get("config").is_some());

    let config = &body["config"];
    assert!(config.get("version").is_some());
    assert!(config.get("backend").is_some());
    assert!(config.get("metrics").is_some());
}

#[tokio::test]
async fn test_update_config_endpoint() {
    let port = 18083;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(
        web_config,
        config_manager.clone(),
        metrics_registry,
        event_bus,
    );

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    wait_for_server(port).await;

    // Get current config
    let current = config_manager.read().await.get_current().await;
    let mut updated_config = current.clone();
    updated_config.version = "2.0".to_string();

    // Update config via API
    let client = reqwest::Client::new();
    let response = client
        .put(format!("http://127.0.0.1:{}/api/v1/config", port))
        .json(&updated_config)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    assert!(body.get("config").is_some());
    assert_eq!(body["config"]["version"], "2.0");

    // Verify config was actually updated
    let current = config_manager.read().await.get_current().await;
    assert_eq!(current.version, "2.0");
}

#[tokio::test]
async fn test_events_endpoint() {
    let port = 18084;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(web_config, config_manager, metrics_registry, event_bus);

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    wait_for_server(port).await;

    // Test events endpoint
    let response = reqwest::get(format!("http://127.0.0.1:{}/api/v1/events", port))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    assert!(body.get("events").is_some());
    assert!(body.get("total").is_some());
}

#[tokio::test]
async fn test_events_endpoint_with_filter() {
    let port = 18085;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(web_config, config_manager, metrics_registry, event_bus);

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    wait_for_server(port).await;

    // Test events endpoint with query parameters
    let response = reqwest::get(format!(
        "http://127.0.0.1:{}/api/v1/events?filter=network&limit=10",
        port
    ))
    .await
    .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    assert!(body.get("events").is_some());
}

#[tokio::test]
async fn test_cors_headers() {
    let port = 18086;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(web_config, config_manager, metrics_registry, event_bus);

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    wait_for_server(port).await;

    // Test CORS headers
    let client = reqwest::Client::new();
    let response = client
        .request(
            reqwest::Method::OPTIONS,
            format!("http://127.0.0.1:{}/api/v1/status", port),
        )
        .header("Origin", "http://example.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    // CORS headers should be present
    assert!(response
        .headers()
        .contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn test_not_found_endpoint() {
    let port = 18087;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(web_config, config_manager, metrics_registry, event_bus);

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    wait_for_server(port).await;

    // Test non-existent endpoint
    let response = reqwest::get(format!("http://127.0.0.1:{}/api/v1/nonexistent", port))
        .await
        .unwrap();

    assert_eq!(response.status(), 404);

    let body: Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
}

#[tokio::test]
async fn test_invalid_json_body() {
    let port = 18088;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(web_config, config_manager, metrics_registry, event_bus);

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    wait_for_server(port).await;

    // Send invalid JSON
    let client = reqwest::Client::new();
    let response = client
        .put(format!("http://127.0.0.1:{}/api/v1/config", port))
        .header("Content-Type", "application/json")
        .body("invalid json")
        .send()
        .await
        .unwrap();

    assert!(response.status().is_client_error());
}

#[tokio::test]
async fn test_concurrent_requests() {
    let port = 18089;
    let (config_manager, metrics_registry, event_bus) = create_test_server(port).await;

    let web_config = WebConfig {
        host: "127.0.0.1".to_string(),
        port,
        enable_cors: true,
        static_dir: "static".to_string(),
    };

    let server = WebServer::new(web_config, config_manager, metrics_registry, event_bus);

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    wait_for_server(port).await;

    // Send multiple concurrent requests
    let mut handles = vec![];
    for _ in 0..10 {
        let url = format!("http://127.0.0.1:{}/api/v1/status", port);
        let handle = tokio::spawn(async move {
            let response = reqwest::get(&url).await.unwrap();
            assert_eq!(response.status(), 200);
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        handle.await.unwrap();
    }
}
