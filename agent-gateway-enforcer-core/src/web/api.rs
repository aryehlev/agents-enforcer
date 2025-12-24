use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error};

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("JSON parsing failed: {0}")]
    JsonError(String),

    #[error("Server error: {status} - {message}")]
    ServerError { status: u16, message: String },

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Clone)]
pub struct ApiClient {
    base_url: String,
    client: Client,
    retry_count: u32,
}

impl ApiClient {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url,
            client,
            retry_count: 3,
        }
    }

    pub fn with_retry_count(mut self, count: u32) -> Self {
        self.retry_count = count;
        self
    }

    async fn get_with_retry(&self, url: &str) -> ApiResult<Response> {
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < self.retry_count {
            match self.client.get(url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(response);
                    } else {
                        let status = response.status().as_u16();
                        let text = response.text().await.unwrap_or_default();

                        if status == 404 {
                            return Err(ApiError::NotFound(text));
                        }

                        return Err(ApiError::ServerError {
                            status,
                            message: text,
                        });
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;

                    if attempts < self.retry_count {
                        debug!(
                            "Request failed, retrying ({}/{})",
                            attempts, self.retry_count
                        );
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                    }
                }
            }
        }

        Err(ApiError::RequestFailed(last_error.unwrap()))
    }

    pub async fn get_status(&self) -> ApiResult<StatusResponse> {
        let url = format!("{}/api/v1/status", self.base_url);
        debug!("GET {}", url);

        let response = self.get_with_retry(&url).await?;
        let status = response
            .json::<StatusResponse>()
            .await
            .map_err(|e| ApiError::JsonError(e.to_string()))?;

        Ok(status)
    }

    pub async fn get_metrics(&self, time_range: Option<String>) -> ApiResult<MetricsResponse> {
        let mut url = format!("{}/api/v1/metrics", self.base_url);

        if let Some(range) = time_range {
            url.push_str(&format!("?time_range={}", range));
        }

        debug!("GET {}", url);

        let response = self.get_with_retry(&url).await?;
        let metrics = response
            .json::<MetricsResponse>()
            .await
            .map_err(|e| ApiError::JsonError(e.to_string()))?;

        Ok(metrics)
    }

    pub async fn get_events(
        &self,
        filter: Option<String>,
        limit: Option<usize>,
    ) -> ApiResult<EventsResponse> {
        let mut url = format!("{}/api/v1/events", self.base_url);
        let mut params = vec![];

        if let Some(f) = filter {
            params.push(format!("filter={}", f));
        }

        if let Some(l) = limit {
            params.push(format!("limit={}", l));
        }

        if !params.is_empty() {
            url.push_str("?");
            url.push_str(&params.join("&"));
        }

        debug!("GET {}", url);

        let response = self.get_with_retry(&url).await?;
        let events = response
            .json::<EventsResponse>()
            .await
            .map_err(|e| ApiError::JsonError(e.to_string()))?;

        Ok(events)
    }

    pub async fn get_config(&self) -> ApiResult<ConfigResponse> {
        let url = format!("{}/api/v1/config", self.base_url);
        debug!("GET {}", url);

        let response = self.get_with_retry(&url).await?;
        let config = response
            .json::<ConfigResponse>()
            .await
            .map_err(|e| ApiError::JsonError(e.to_string()))?;

        Ok(config)
    }

    pub async fn update_config(&self, config: serde_json::Value) -> ApiResult<ConfigResponse> {
        let url = format!("{}/api/v1/config", self.base_url);
        debug!("PUT {}", url);

        let response = self.client.put(&url).json(&config).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let text = response.text().await.unwrap_or_default();

            if status == 400 {
                return Err(ApiError::InvalidConfig(text));
            }

            return Err(ApiError::ServerError {
                status,
                message: text,
            });
        }

        let updated_config = response
            .json::<ConfigResponse>()
            .await
            .map_err(|e| ApiError::JsonError(e.to_string()))?;

        Ok(updated_config)
    }
}

// Response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub backend: String,
    pub active_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub timestamp: String,
    pub metrics: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsResponse {
    pub events: Vec<serde_json::Value>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub config: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_client_creation() {
        let client = ApiClient::new("http://localhost:8080".to_string());
        assert_eq!(client.base_url, "http://localhost:8080");
        assert_eq!(client.retry_count, 3);
    }

    #[test]
    fn test_api_client_with_retry() {
        let client = ApiClient::new("http://localhost:8080".to_string()).with_retry_count(5);
        assert_eq!(client.retry_count, 5);
    }
}
