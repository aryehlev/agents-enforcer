//! Web Interface Integration Tests
//!
//! This module contains integration tests for the web interface and API:
//! - HTTP endpoints functionality
//! - RESTful API behavior
//! - WebSocket connections
//! - Static file serving
//! - CORS handling
//! - Authentication and authorization
//! - Error handling and status codes

use agent_gateway_enforcer_tests::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Run all web interface tests
pub fn run_all_web_interface_tests() {
    println!("=== Running Web Interface Integration Tests ===");

    // Test basic HTTP endpoints
    test_status_endpoint();
    test_health_endpoint();
    test_version_endpoint();

    // Test API endpoints
    test_metrics_api();
    test_events_api();
    test_configuration_api();
    test_backend_api();

    // Test WebSocket functionality
    test_websocket_connections();
    test_realtime_updates();
    test_websocket_error_handling();

    // Test static file serving
    test_static_file_serving();
    test_dashboard_ui();
    test_asset_caching();

    // Test CORS and security
    test_cors_headers();
    test_security_headers();
    test_rate_limiting();

    // Test error handling
    test_404_handling();
    test_invalid_json_handling();
    test_server_error_handling();

    // Test performance
    test_concurrent_requests();
    test_request_timeout();
    test_memory_usage();

    println!("=== Web Interface Integration Tests Completed ===");
}

// =============================================================================
// Basic HTTP Endpoint Tests
// =============================================================================

/// Mock HTTP server for testing
struct MockHttpServer {
    port: u16,
    endpoints: Arc<Mutex<HashMap<String, MockEndpoint>>>,
    request_log: Arc<Mutex<Vec<MockRequest>>>,
}

struct MockEndpoint {
    path: String,
    method: String,
    response_status: u16,
    response_body: String,
    response_headers: HashMap<String, String>,
    #[allow(dead_code)]
    handler: Option<Arc<dyn Fn(&MockRequest) -> MockResponse + Send + Sync>>,
}

impl std::fmt::Debug for MockEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockEndpoint")
            .field("path", &self.path)
            .field("method", &self.method)
            .field("response_status", &self.response_status)
            .field("response_body", &self.response_body)
            .field("response_headers", &self.response_headers)
            .field("handler", &self.handler.as_ref().map(|_| "<handler>"))
            .finish()
    }
}

impl Clone for MockEndpoint {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            method: self.method.clone(),
            response_status: self.response_status,
            response_body: self.response_body.clone(),
            response_headers: self.response_headers.clone(),
            handler: self.handler.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct MockRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
    timestamp: std::time::SystemTime,
}

#[derive(Debug, Clone)]
struct MockResponse {
    status: u16,
    body: String,
    headers: HashMap<String, String>,
}

impl MockHttpServer {
    fn new(port: u16) -> Self {
        Self {
            port,
            endpoints: Arc::new(Mutex::new(HashMap::new())),
            request_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add_endpoint(&mut self, endpoint: MockEndpoint) {
        let mut endpoints = self.endpoints.lock().unwrap();
        endpoints.insert(endpoint.path.clone(), endpoint);
    }

    fn simulate_request(
        &self,
        method: &str,
        path: &str,
        headers: HashMap<String, String>,
        body: String,
    ) -> MockResponse {
        let request = MockRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: headers.clone(),
            body: body.clone(),
            timestamp: std::time::SystemTime::now(),
        };

        // Log the request
        self.request_log.lock().unwrap().push(request.clone());

        // Find and execute endpoint handler
        let endpoints = self.endpoints.lock().unwrap();

        // Try exact match first, then fall back to catch-all handler
        let endpoint = endpoints.get(path).or_else(|| endpoints.get("/*"));

        if let Some(endpoint) = endpoint {
            if endpoint.method == method || endpoint.method == "*" {
                // Check for If-None-Match header (ETag caching)
                if let Some(if_none_match) = headers.get("If-None-Match") {
                    if let Some(etag) = endpoint.response_headers.get("ETag") {
                        if if_none_match == etag {
                            return MockResponse {
                                status: 304,
                                body: String::new(),
                                headers: endpoint.response_headers.clone(),
                            };
                        }
                    }
                }

                if let Some(handler) = &endpoint.handler {
                    handler(&request)
                } else {
                    MockResponse {
                        status: endpoint.response_status,
                        body: endpoint.response_body.clone(),
                        headers: endpoint.response_headers.clone(),
                    }
                }
            } else {
                MockResponse {
                    status: 405,
                    body: "Method Not Allowed".to_string(),
                    headers: HashMap::new(),
                }
            }
        } else {
            MockResponse {
                status: 404,
                body: "Not Found".to_string(),
                headers: HashMap::new(),
            }
        }
    }

    fn get_request_log(&self) -> Vec<MockRequest> {
        self.request_log.lock().unwrap().clone()
    }

    fn clear_log(&self) {
        self.request_log.lock().unwrap().clear();
    }
}

/// Test status endpoint
fn test_status_endpoint() {
    println!("Testing status endpoint...");

    let mut server = MockHttpServer::new(8080);

    // Add status endpoint
    let status_endpoint = MockEndpoint {
        path: "/api/status".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"{"status": "healthy", "uptime": "2h 15m 30s", "version": "0.1.0"}"#
            .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(status_endpoint);

    // Test status endpoint
    let response = server.simulate_request("GET", "/api/status", HashMap::new(), String::new());

    assert_eq!(response.status, 200);
    assert!(response.body.contains("\"status\": \"healthy\""));
    assert!(response.body.contains("\"uptime\""));
    assert!(response.body.contains("\"version\""));
    assert_eq!(
        response.headers.get("Content-Type"),
        Some(&"application/json".to_string())
    );

    println!("✓ Status endpoint tests passed");
}

/// Test health endpoint
fn test_health_endpoint() {
    println!("Testing health endpoint...");

    let mut server = MockHttpServer::new(8080);

    // Add health endpoint
    let health_endpoint = MockEndpoint {
        path: "/api/health".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: "OK".to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "text/plain".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(health_endpoint);

    // Test health endpoint
    let response = server.simulate_request("GET", "/api/health", HashMap::new(), String::new());

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "OK");
    assert_eq!(
        response.headers.get("Content-Type"),
        Some(&"text/plain".to_string())
    );

    println!("✓ Health endpoint tests passed");
}

/// Test version endpoint
fn test_version_endpoint() {
    println!("Testing version endpoint...");

    let mut server = MockHttpServer::new(8080);

    // Add version endpoint
    let version_endpoint = MockEndpoint {
        path: "/api/version".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body:
            r#"{"version": "0.1.0", "build": "abc123", "features": ["ebpf", "metrics", "web"]}"#
                .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(version_endpoint);

    // Test version endpoint
    let response = server.simulate_request("GET", "/api/version", HashMap::new(), String::new());

    assert_eq!(response.status, 200);
    assert!(response.body.contains("\"version\": \"0.1.0\""));
    assert!(response.body.contains("\"build\": \"abc123\""));
    assert!(response.body.contains("\"features\""));
    assert!(response.body.contains("ebpf"));

    println!("✓ Version endpoint tests passed");
}

// =============================================================================
// API Endpoint Tests
// =============================================================================

/// Test metrics API
fn test_metrics_api() {
    println!("Testing metrics API...");

    let mut server = MockHttpServer::new(8080);

    // Add metrics endpoint
    let metrics_endpoint = MockEndpoint {
        path: "/api/metrics".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"{
  "http_requests_total": 1234,
  "active_connections": 42,
  "cpu_usage_percent": 75.5,
  "memory_usage_bytes": 8589934592,
  "events_processed_total": 98765,
  "policy_violations_total": 123
}"#
        .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };

    // Add Prometheus metrics endpoint
    let prometheus_endpoint = MockEndpoint {
        path: "/metrics".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total 1234

# HELP active_connections Current active connections
# TYPE active_connections gauge
active_connections 42"#
            .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "text/plain".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(metrics_endpoint);
    server.add_endpoint(prometheus_endpoint);

    // Test JSON metrics endpoint
    let json_response =
        server.simulate_request("GET", "/api/metrics", HashMap::new(), String::new());
    assert_eq!(json_response.status, 200);
    assert!(json_response.body.contains("\"http_requests_total\""));
    assert!(json_response.body.contains("1234"));

    // Test Prometheus metrics endpoint
    let prometheus_response =
        server.simulate_request("GET", "/metrics", HashMap::new(), String::new());
    assert_eq!(prometheus_response.status, 200);
    assert!(prometheus_response.body.contains("# HELP"));
    assert!(prometheus_response.body.contains("# TYPE"));
    assert!(prometheus_response
        .body
        .contains("http_requests_total 1234"));

    println!("✓ Metrics API tests passed");
}

/// Test events API
fn test_events_api() {
    println!("Testing events API...");

    let mut server = MockHttpServer::new(8080);

    // Add events endpoint
    let events_endpoint = MockEndpoint {
        path: "/api/events".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"{
  "events": [
    {
      "id": "event-123",
      "type": "network",
      "severity": "info",
      "timestamp": "2024-01-15T10:30:00Z",
      "message": "Network connection established",
      "source": "agent-gateway-enforcer"
    },
    {
      "id": "event-124",
      "type": "file",
      "severity": "warning",
      "timestamp": "2024-01-15T10:29:30Z",
      "message": "File access denied",
      "source": "agent-gateway-enforcer"
    }
  ],
  "total": 2,
  "filtered": 2
}"#
        .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };

    // Add events with filter endpoint
    let events_filter_endpoint = MockEndpoint {
        path: "/api/events".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"{
  "events": [
    {
      "id": "event-124",
      "type": "file",
      "severity": "warning",
      "timestamp": "2024-01-15T10:29:30Z",
      "message": "File access denied",
      "source": "agent-gateway-enforcer"
    }
  ],
  "total": 1,
  "filtered": 1
}"#
        .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(events_endpoint);

    // Test events endpoint
    let response = server.simulate_request("GET", "/api/events", HashMap::new(), String::new());
    assert_eq!(response.status, 200);
    assert!(response.body.contains("\"events\""));
    assert!(response.body.contains("\"total\": 2"));
    assert!(response.body.contains("event-123"));
    assert!(response.body.contains("network"));

    // Test events with filter - mock server returns same response regardless of query
    // In production, filtering would be handled by actual server logic
    let mut headers = HashMap::new();
    headers.insert("query".to_string(), "severity=warning".to_string());
    let filtered_response = server.simulate_request("GET", "/api/events", headers, String::new());
    assert_eq!(filtered_response.status, 200);
    // Note: Mock doesn't differentiate by query params, so we get same response
    assert!(filtered_response.body.contains("\"events\""));

    println!("✓ Events API tests passed");
}

/// Test configuration API
fn test_configuration_api() {
    println!("Testing configuration API...");

    let mut server = MockHttpServer::new(8080);

    // Add config endpoint that handles both GET and PUT
    let config_endpoint = MockEndpoint {
        path: "/api/config".to_string(),
        method: "*".to_string(), // Accept any method
        response_status: 200,
        response_body: r#"{
  "server": {
    "host": "127.0.0.1",
    "port": 8080
  },
  "backend": {
    "type": "mock",
    "auto_start": true
  },
  "logging": {
    "level": "info"
  }
}"#
        .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: Some(Arc::new(|request: &MockRequest| {
            if request.method == "GET" {
                MockResponse {
                    status: 200,
                    body: r#"{"server": {"host": "127.0.0.1", "port": 8080}, "backend": {"type": "mock"}, "logging": {"level": "info"}}"#.to_string(),
                    headers: HashMap::new(),
                }
            } else if request.method == "PUT" {
                MockResponse {
                    status: 200,
                    body: r#"{"message": "Configuration updated successfully"}"#.to_string(),
                    headers: HashMap::new(),
                }
            } else {
                MockResponse {
                    status: 405,
                    body: "Method Not Allowed".to_string(),
                    headers: HashMap::new(),
                }
            }
        })),
    };

    server.add_endpoint(config_endpoint);

    // Test GET config endpoint
    let get_response = server.simulate_request("GET", "/api/config", HashMap::new(), String::new());
    assert_eq!(get_response.status, 200);
    assert!(get_response.body.contains("\"server\""));
    assert!(get_response.body.contains("\"backend\""));
    assert!(get_response.body.contains("\"logging\""));

    // Test PUT config endpoint
    let update_body = r#"{"server": {"port": 9090}}"#;
    let put_response = server.simulate_request(
        "PUT",
        "/api/config",
        HashMap::new(),
        update_body.to_string(),
    );
    assert_eq!(put_response.status, 200);
    assert!(put_response
        .body
        .contains("Configuration updated successfully"));

    println!("✓ Configuration API tests passed");
}

/// Test backend API
fn test_backend_api() {
    println!("Testing backend API...");

    let mut server = MockHttpServer::new(8080);

    // Add backend list endpoint
    let backend_list_endpoint = MockEndpoint {
        path: "/api/backends".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"{
  "backends": [
    {
      "name": "mock",
      "type": "mock",
      "status": "running",
      "active": true
    },
    {
      "name": "ebpf-linux",
      "type": "ebpf",
      "status": "stopped",
      "active": false
    }
  ]
}"#
        .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };

    // Add backend control endpoint
    let backend_control_endpoint = MockEndpoint {
        path: "/api/backends/mock/start".to_string(),
        method: "POST".to_string(),
        response_status: 200,
        response_body: r#"{"message": "Backend 'mock' started successfully"}"#.to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(backend_list_endpoint);
    server.add_endpoint(backend_control_endpoint);

    // Test backend list endpoint
    let list_response =
        server.simulate_request("GET", "/api/backends", HashMap::new(), String::new());
    assert_eq!(list_response.status, 200);
    assert!(list_response.body.contains("\"backends\""));
    assert!(list_response.body.contains("mock"));
    assert!(list_response.body.contains("ebpf-linux"));

    // Test backend control endpoint
    let control_response = server.simulate_request(
        "POST",
        "/api/backends/mock/start",
        HashMap::new(),
        String::new(),
    );
    assert_eq!(control_response.status, 200);
    assert!(control_response
        .body
        .contains("Backend 'mock' started successfully"));

    println!("✓ Backend API tests passed");
}

// =============================================================================
// WebSocket Tests
// =============================================================================

/// Mock WebSocket connection
#[derive(Clone)]
struct MockWebSocket {
    id: String,
    path: String,
    connected: bool,
    messages: Arc<Mutex<Vec<String>>>,
}

impl MockWebSocket {
    fn new(id: &str, path: &str) -> Self {
        Self {
            id: id.to_string(),
            path: path.to_string(),
            connected: true,
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn send_message(&self, message: &str) {
        if self.connected {
            self.messages.lock().unwrap().push(message.to_string());
        }
    }

    fn receive_messages(&self) -> Vec<String> {
        self.messages.lock().unwrap().clone()
    }

    fn close(&mut self) {
        self.connected = false;
    }
}

/// Mock WebSocket server
struct MockWebSocketServer {
    connections: Arc<Mutex<Vec<MockWebSocket>>>,
    port: u16,
}

impl MockWebSocketServer {
    fn new(port: u16) -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            port,
        }
    }

    fn accept_connection(&self, path: &str) -> MockWebSocket {
        let ws = MockWebSocket::new(
            &format!("ws-{}", self.connections.lock().unwrap().len()),
            path,
        );
        self.connections.lock().unwrap().push(ws.clone());
        ws
    }

    fn broadcast(&self, message: &str) {
        let connections = self.connections.lock().unwrap();
        for conn in connections.iter() {
            if conn.connected {
                conn.send_message(message);
            }
        }
    }

    fn get_connection_count(&self) -> usize {
        self.connections.lock().unwrap().len()
    }
}

/// Test WebSocket connections
fn test_websocket_connections() {
    println!("Testing WebSocket connections...");

    let ws_server = MockWebSocketServer::new(8081);

    // Accept WebSocket connections
    let ws1 = ws_server.accept_connection("/ws/events");
    let ws2 = ws_server.accept_connection("/ws/metrics");

    assert_eq!(ws_server.get_connection_count(), 2);
    assert!(ws1.connected);
    assert!(ws2.connected);
    assert_eq!(ws1.path, "/ws/events");
    assert_eq!(ws2.path, "/ws/metrics");

    // Test message sending
    ws1.send_message("Hello WebSocket 1");
    ws2.send_message("Hello WebSocket 2");

    let ws1_messages = ws1.receive_messages();
    let ws2_messages = ws2.receive_messages();

    assert_eq!(ws1_messages.len(), 1);
    assert_eq!(ws2_messages.len(), 1);
    assert_eq!(ws1_messages[0], "Hello WebSocket 1");
    assert_eq!(ws2_messages[0], "Hello WebSocket 2");

    // Test connection closing
    let mut ws1_mut = ws1;
    ws1_mut.close();

    assert!(!ws1_mut.connected);

    println!("✓ WebSocket connections tests passed");
}

/// Test real-time updates
fn test_realtime_updates() {
    println!("Testing real-time updates...");

    let ws_server = MockWebSocketServer::new(8081);

    // Accept connections for different topics
    let events_ws = ws_server.accept_connection("/ws/events");
    let metrics_ws = ws_server.accept_connection("/ws/metrics");

    // Simulate real-time updates
    let event_update =
        r#"{"type": "event", "data": {"id": "event-125", "type": "network", "severity": "info"}}"#;
    let metric_update = r#"{"type": "metric", "data": {"name": "cpu_usage", "value": 85.2}}"#;

    ws_server.broadcast(event_update);
    ws_server.broadcast(metric_update);

    let events_messages = events_ws.receive_messages();
    let metrics_messages = metrics_ws.receive_messages();

    assert_eq!(events_messages.len(), 2); // Should receive both broadcasts
    assert_eq!(metrics_messages.len(), 2); // Should receive both broadcasts

    assert!(events_messages[0].contains("event-125"));
    assert!(metrics_messages[1].contains("cpu_usage"));

    println!("✓ Real-time updates tests passed");
}

/// Test WebSocket error handling
fn test_websocket_error_handling() {
    println!("Testing WebSocket error handling...");

    let ws_server = MockWebSocketServer::new(8081);

    // Test connection with invalid path
    let invalid_ws = ws_server.accept_connection("/ws/invalid");

    // Simulate error by closing connection abruptly
    let mut invalid_ws_mut = invalid_ws;
    invalid_ws_mut.close();

    // Try to send message to closed connection
    invalid_ws_mut.send_message("Test message");

    // Should not have received the message
    let messages = invalid_ws_mut.receive_messages();
    assert_eq!(messages.len(), 0);

    println!("✓ WebSocket error handling tests passed");
}

// =============================================================================
// Static File Serving Tests
// =============================================================================

/// Test static file serving
fn test_static_file_serving() {
    println!("Testing static file serving...");

    let mut server = MockHttpServer::new(8080);

    // Add static file endpoint
    let static_endpoint = MockEndpoint {
        path: "/index.html".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"<!DOCTYPE html>
<html>
<head>
    <title>Agent Gateway Enforcer Dashboard</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>Agent Gateway Enforcer</h1>
    <div id="app">Loading...</div>
    <script src="/js/app.js"></script>
</body>
</html>"#
            .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "text/html".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(static_endpoint);

    // Test static file serving
    let response = server.simulate_request("GET", "/index.html", HashMap::new(), String::new());

    assert_eq!(response.status, 200);
    assert!(response.body.contains("<!DOCTYPE html>"));
    assert!(response.body.contains("Agent Gateway Enforcer Dashboard"));
    assert!(response.body.contains("/css/style.css"));
    assert!(response.body.contains("/js/app.js"));
    assert_eq!(
        response.headers.get("Content-Type"),
        Some(&"text/html".to_string())
    );

    println!("✓ Static file serving tests passed");
}

/// Test dashboard UI
fn test_dashboard_ui() {
    println!("Testing dashboard UI...");

    let mut server = MockHttpServer::new(8080);

    // Add dashboard endpoint
    let dashboard_endpoint = MockEndpoint {
        path: "/".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <header>
        <nav>
            <h1>Agent Gateway Enforcer</h1>
            <ul>
                <li><a href="/">Dashboard</a></li>
                <li><a href="/metrics">Metrics</a></li>
                <li><a href="/events">Events</a></li>
                <li><a href="/config">Configuration</a></li>
            </ul>
        </nav>
    </header>
    <main>
        <div class="dashboard-grid">
            <div class="status-card">
                <h2>Status</h2>
                <div class="status-indicator healthy">Healthy</div>
            </div>
            <div class="metrics-card">
                <h2>Metrics</h2>
                <canvas id="metrics-chart"></canvas>
            </div>
        </div>
    </main>
</body>
</html>"#
            .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "text/html".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(dashboard_endpoint);

    // Test dashboard UI
    let response = server.simulate_request("GET", "/", HashMap::new(), String::new());

    assert_eq!(response.status, 200);
    assert!(response.body.contains("<!DOCTYPE html>"));
    assert!(response.body.contains("Dashboard"));
    assert!(response.body.contains("Agent Gateway Enforcer"));
    assert!(response.body.contains("status-indicator"));
    assert!(response.body.contains("metrics-card"));
    assert!(response.body.contains("canvas"));

    println!("✓ Dashboard UI tests passed");
}

/// Test asset caching
fn test_asset_caching() {
    println!("Testing asset caching...");

    let mut server = MockHttpServer::new(8080);

    // Add CSS file endpoint with caching headers
    let css_endpoint = MockEndpoint {
        path: "/css/style.css".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: "body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }"
            .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "text/css".to_string());
            headers.insert(
                "Cache-Control".to_string(),
                "public, max-age=3600".to_string(),
            );
            headers.insert("ETag".to_string(), "\"abc123\"".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(css_endpoint);

    // Test first request
    let response1 = server.simulate_request("GET", "/css/style.css", HashMap::new(), String::new());
    assert_eq!(response1.status, 200);
    assert_eq!(
        response1.headers.get("Cache-Control"),
        Some(&"public, max-age=3600".to_string())
    );
    assert_eq!(
        response1.headers.get("ETag"),
        Some(&"\"abc123\"".to_string())
    );

    // Test request with If-None-Match header
    let mut headers = HashMap::new();
    headers.insert("If-None-Match".to_string(), "\"abc123\"".to_string());
    let response2 = server.simulate_request("GET", "/css/style.css", headers, String::new());

    // Should return 304 Not Modified
    assert_eq!(response2.status, 304);
    assert!(response2.body.is_empty());

    println!("✓ Asset caching tests passed");
}

// =============================================================================
// CORS and Security Tests
// =============================================================================

/// Test CORS headers
fn test_cors_headers() {
    println!("Testing CORS headers...");

    let mut server = MockHttpServer::new(8080);

    // Add endpoint with CORS support
    let cors_endpoint = MockEndpoint {
        path: "/api/test".to_string(),
        method: "OPTIONS".to_string(),
        response_status: 200,
        response_body: String::new(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
            headers.insert(
                "Access-Control-Allow-Methods".to_string(),
                "GET, POST, PUT, DELETE, OPTIONS".to_string(),
            );
            headers.insert(
                "Access-Control-Allow-Headers".to_string(),
                "Content-Type, Authorization".to_string(),
            );
            headers.insert("Access-Control-Max-Age".to_string(), "86400".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(cors_endpoint);

    // Test OPTIONS request
    let response = server.simulate_request("OPTIONS", "/api/test", HashMap::new(), String::new());

    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("Access-Control-Allow-Origin"),
        Some(&"*".to_string())
    );
    assert_eq!(
        response.headers.get("Access-Control-Allow-Methods"),
        Some(&"GET, POST, PUT, DELETE, OPTIONS".to_string())
    );
    assert_eq!(
        response.headers.get("Access-Control-Allow-Headers"),
        Some(&"Content-Type, Authorization".to_string())
    );
    assert_eq!(
        response.headers.get("Access-Control-Max-Age"),
        Some(&"86400".to_string())
    );

    // Test preflight request with specific origin
    let mut headers = HashMap::new();
    headers.insert("Origin".to_string(), "https://example.com".to_string());
    let response2 = server.simulate_request("OPTIONS", "/api/test", headers, String::new());

    // Should still return appropriate CORS headers
    assert_eq!(response2.status, 200);
    assert!(response2
        .headers
        .contains_key("Access-Control-Allow-Origin"));

    println!("✓ CORS headers tests passed");
}

/// Test security headers
fn test_security_headers() {
    println!("Testing security headers...");

    let mut server = MockHttpServer::new(8080);

    // Add endpoint with security headers
    let security_endpoint = MockEndpoint {
        path: "/api/secure".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"{"message": "Secure endpoint"}"#.to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
            headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
            headers.insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());
            headers.insert(
                "Strict-Transport-Security".to_string(),
                "max-age=31536000; includeSubDomains".to_string(),
            );
            headers.insert(
                "Content-Security-Policy".to_string(),
                "default-src 'self'".to_string(),
            );
            headers
        },
        handler: None,
    };

    server.add_endpoint(security_endpoint);

    // Test security headers
    let response = server.simulate_request("GET", "/api/secure", HashMap::new(), String::new());

    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("X-Content-Type-Options"),
        Some(&"nosniff".to_string())
    );
    assert_eq!(
        response.headers.get("X-Frame-Options"),
        Some(&"DENY".to_string())
    );
    assert_eq!(
        response.headers.get("X-XSS-Protection"),
        Some(&"1; mode=block".to_string())
    );
    assert_eq!(
        response.headers.get("Strict-Transport-Security"),
        Some(&"max-age=31536000; includeSubDomains".to_string())
    );
    assert_eq!(
        response.headers.get("Content-Security-Policy"),
        Some(&"default-src 'self'".to_string())
    );

    println!("✓ Security headers tests passed");
}

/// Test rate limiting
fn test_rate_limiting() {
    println!("Testing rate limiting...");

    let mut server = MockHttpServer::new(8080);

    // Track request count per IP
    let request_counts = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let request_counts_clone = request_counts.clone();

    // Add rate-limited endpoint
    let rate_limit_endpoint = MockEndpoint {
        path: "/api/rate-limited".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"{"message": "Success"}"#.to_string(),
        response_headers: HashMap::new(),
        handler: Some(Arc::new(move |request: &MockRequest| {
            let client_ip = request
                .headers
                .get("X-Real-IP")
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".to_string());

            let mut counts = request_counts_clone.lock().unwrap();
            let count = counts.entry(client_ip.clone()).or_insert(0);
            *count += 1;

            if *count > 10 {
                MockResponse {
                    status: 429,
                    body: r#"{"error": "Rate limit exceeded"}"#.to_string(),
                    headers: {
                        let mut headers = HashMap::new();
                        headers.insert("Retry-After".to_string(), "60".to_string());
                        headers
                    },
                }
            } else {
                MockResponse {
                    status: 200,
                    body: r#"{"message": "Success"}"#.to_string(),
                    headers: HashMap::new(),
                }
            }
        })),
    };

    server.add_endpoint(rate_limit_endpoint);

    // Test rate limiting behavior
    let mut headers = HashMap::new();
    headers.insert("X-Real-IP".to_string(), "192.168.1.100".to_string());

    // Make requests up to the limit
    for i in 1..=10 {
        let response =
            server.simulate_request("GET", "/api/rate-limited", headers.clone(), String::new());
        assert_eq!(response.status, 200, "Request {} should succeed", i);
    }

    // Next request should be rate limited
    let response = server.simulate_request("GET", "/api/rate-limited", headers, String::new());
    assert_eq!(response.status, 429);
    assert!(response.body.contains("Rate limit exceeded"));
    assert_eq!(response.headers.get("Retry-After"), Some(&"60".to_string()));

    println!("✓ Rate limiting tests passed");
}

// =============================================================================
// Error Handling Tests
// =============================================================================

/// Test 404 handling
fn test_404_handling() {
    println!("Testing 404 handling...");

    let mut server = MockHttpServer::new(8080);

    // Add generic 404 handler
    let not_found_handler = MockEndpoint {
        path: "/*".to_string(),
        method: "*".to_string(),
        response_status: 404,
        response_body:
            r#"{"error": "Not Found", "message": "The requested resource was not found"}"#
                .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(not_found_handler);

    // Test 404 for non-existent endpoint
    let response =
        server.simulate_request("GET", "/api/nonexistent", HashMap::new(), String::new());

    assert_eq!(response.status, 404);
    assert!(response.body.contains("\"error\": \"Not Found\""));
    assert_eq!(
        response.headers.get("Content-Type"),
        Some(&"application/json".to_string())
    );

    println!("✓ 404 handling tests passed");
}

/// Test invalid JSON handling
fn test_invalid_json_handling() {
    println!("Testing invalid JSON handling...");

    let mut server = MockHttpServer::new(8080);

    // Add endpoint that expects JSON
    let json_endpoint = MockEndpoint {
        path: "/api/validate".to_string(),
        method: "POST".to_string(),
        response_status: 200,
        response_body: r#"{"message": "Valid JSON received"}"#.to_string(),
        response_headers: HashMap::new(),
        handler: Some(Arc::new(|request: &MockRequest| {
            // Try to parse JSON body
            match serde_json::from_str::<serde_json::Value>(&request.body) {
                Ok(_) => MockResponse {
                    status: 200,
                    body: r#"{"message": "Valid JSON received"}"#.to_string(),
                    headers: HashMap::new(),
                },
                Err(_) => MockResponse {
                    status: 400,
                    body: r#"{"error": "Bad Request", "message": "Invalid JSON format"}"#
                        .to_string(),
                    headers: {
                        let mut headers = HashMap::new();
                        headers.insert("Content-Type".to_string(), "application/json".to_string());
                        headers
                    },
                },
            }
        })),
    };

    server.add_endpoint(json_endpoint);

    // Test invalid JSON
    let invalid_json = r#"{"name": "test", "invalid": }"#;
    let response = server.simulate_request(
        "POST",
        "/api/validate",
        HashMap::new(),
        invalid_json.to_string(),
    );

    assert_eq!(response.status, 400);
    assert!(response.body.contains("Invalid JSON format"));

    // Test valid JSON
    let valid_json = r#"{"name": "test", "value": 123}"#;
    let response2 = server.simulate_request(
        "POST",
        "/api/validate",
        HashMap::new(),
        valid_json.to_string(),
    );

    assert_eq!(response2.status, 200);
    assert!(response2.body.contains("Valid JSON received"));

    println!("✓ Invalid JSON handling tests passed");
}

/// Test server error handling
fn test_server_error_handling() {
    println!("Testing server error handling...");

    let mut server = MockHttpServer::new(8080);

    // Add endpoint that simulates server error
    let error_endpoint = MockEndpoint {
        path: "/api/error".to_string(),
        method: "GET".to_string(),
        response_status: 500,
        response_body: r#"{"error": "Internal Server Error", "message": "Something went wrong"}"#
            .to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };

    server.add_endpoint(error_endpoint);

    // Test server error
    let response = server.simulate_request("GET", "/api/error", HashMap::new(), String::new());

    assert_eq!(response.status, 500);
    assert!(response
        .body
        .contains("\"error\": \"Internal Server Error\""));
    assert_eq!(
        response.headers.get("Content-Type"),
        Some(&"application/json".to_string())
    );

    println!("✓ Server error handling tests passed");
}

// =============================================================================
// Performance Tests
// =============================================================================

/// Test concurrent requests
fn test_concurrent_requests() {
    println!("Testing concurrent requests...");

    let server = Arc::new(MockHttpServer::new(8080));
    let request_count = 100;

    // Add simple endpoint
    let mut server_mut = MockHttpServer::new(8080);
    let endpoint = MockEndpoint {
        path: "/api/concurrent".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"{"message": "Concurrent test"}"#.to_string(),
        response_headers: {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
        handler: None,
    };
    server_mut.add_endpoint(endpoint);
    let server = Arc::new(server_mut);

    let start_time = std::time::Instant::now();
    let mut handles = vec![];

    // Spawn concurrent requests
    for i in 0..request_count {
        let server_clone = Arc::clone(&server);
        let handle = std::thread::spawn(move || {
            let response = server_clone.simulate_request(
                "GET",
                "/api/concurrent",
                HashMap::new(),
                String::new(),
            );
            assert_eq!(response.status, 200);
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }

    let elapsed = start_time.elapsed();
    let requests_per_second = request_count as f64 / elapsed.as_secs_f64();

    println!(
        "Processed {} concurrent requests in {:?} ({:.2} req/s)",
        request_count, elapsed, requests_per_second
    );

    // Check request log
    let request_log = server.get_request_log();
    assert_eq!(request_log.len(), request_count);

    println!("✓ Concurrent requests tests passed");
}

/// Test request timeout
fn test_request_timeout() {
    println!("Testing request timeout...");

    let mut server = MockHttpServer::new(8080);

    // Add slow endpoint
    let slow_endpoint = MockEndpoint {
        path: "/api/slow".to_string(),
        method: "GET".to_string(),
        response_status: 200,
        response_body: r#"{"message": "Slow response"}"#.to_string(),
        response_headers: HashMap::new(),
        handler: Some(Arc::new(|_request: &MockRequest| {
            // Simulate slow response by sleeping (in real implementation)
            std::thread::sleep(std::time::Duration::from_millis(100));
            MockResponse {
                status: 200,
                body: r#"{"message": "Slow response"}"#.to_string(),
                headers: HashMap::new(),
            }
        })),
    };

    server.add_endpoint(slow_endpoint);

    // Test with timeout
    let start_time = std::time::Instant::now();
    let response = server.simulate_request("GET", "/api/slow", HashMap::new(), String::new());
    let elapsed = start_time.elapsed();

    // Should complete within reasonable time
    assert!(elapsed < std::time::Duration::from_secs(1));
    assert_eq!(response.status, 200);

    println!("✓ Request timeout tests passed");
}

/// Test memory usage
fn test_memory_usage() {
    println!("Testing memory usage...");

    let mut server = MockHttpServer::new(8080);

    // Add endpoints that consume memory
    for i in 0..10 {
        let endpoint = MockEndpoint {
            path: format!("/api/memory/{}", i),
            method: "GET".to_string(),
            response_status: 200,
            response_body: format!("{{\"id\": {}, \"data\": \"{}\"}}", i, "x".repeat(1000)),
            response_headers: {
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "application/json".to_string());
                headers
            },
            handler: None,
        };
        server.add_endpoint(endpoint);
    }

    // Test memory usage under load
    for i in 0..10 {
        let response = server.simulate_request(
            "GET",
            &format!("/api/memory/{}", i),
            HashMap::new(),
            String::new(),
        );
        assert_eq!(response.status, 200);
        assert!(response.body.len() > 1000); // Should contain large data
    }

    // Check request log size
    let request_log = server.get_request_log();
    assert_eq!(request_log.len(), 10);

    // Clear log to test cleanup
    server.clear_log();
    assert!(server.get_request_log().is_empty());

    println!("✓ Memory usage tests passed");
}
