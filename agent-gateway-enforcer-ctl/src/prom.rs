//! Thin Prometheus HTTP query client. Used by `capabilities budget`
//! + `status` to pull `enforcer_llm_spend_usd_total` and `up` gauges
//! without pulling in the full Prometheus Rust SDK.
//!
//! Works against anything that speaks the Prometheus HTTP API —
//! Prometheus, VictoriaMetrics' `vmsingle` / `vmselect`, Mimir,
//! Thanos' `query-frontend`, Cortex.

use anyhow::Context;
use serde::Deserialize;

/// Client pointed at a Prometheus-compatible endpoint.
pub struct PromClient {
    base_url: String,
    http: reqwest::Client,
}

impl PromClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("reqwest build"),
        }
    }

    /// Instant query. Returns one sample per returned time series;
    /// the caller maps labels to their own shape.
    pub async fn query(&self, promql: &str) -> anyhow::Result<Vec<Sample>> {
        let url = format!("{}/api/v1/query", self.base_url.trim_end_matches('/'));
        let resp = self
            .http
            .get(&url)
            .query(&[("query", promql)])
            .send()
            .await
            .with_context(|| format!("GET {}", url))?;
        if !resp.status().is_success() {
            anyhow::bail!("prometheus query {} -> {}", promql, resp.status());
        }
        let parsed: PromResponse = resp.json().await.context("parse prom json")?;
        if parsed.status != "success" {
            anyhow::bail!("prometheus error: {:?}", parsed.error);
        }
        Ok(parsed
            .data
            .result
            .into_iter()
            .map(|r| Sample {
                labels: r.metric,
                value: r.value.1.parse::<f64>().unwrap_or(0.0),
            })
            .collect())
    }
}

/// A single instant-query sample. `labels` is the metric's label set;
/// `value` is the scalar the query resolved to.
#[derive(Debug, Clone)]
pub struct Sample {
    pub labels: std::collections::BTreeMap<String, String>,
    pub value: f64,
}

#[derive(Debug, Deserialize)]
struct PromResponse {
    status: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    data: PromData,
}

#[derive(Debug, Deserialize, Default)]
struct PromData {
    #[serde(default)]
    result: Vec<PromResult>,
}

#[derive(Debug, Deserialize)]
struct PromResult {
    #[serde(default)]
    metric: std::collections::BTreeMap<String, String>,
    // [ unix_timestamp, "value_as_string" ] — Prometheus insists on
    // the string form even for integers.
    value: (f64, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_json_shape_parses() {
        let json = r#"{
          "status":"success",
          "data":{"resultType":"vector","result":[
            {"metric":{"__name__":"enforcer_llm_spend_usd_total","agent":"prod/a"},
             "value":[1713456789.0,"1.234"]}
          ]}
        }"#;
        let parsed: PromResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.status, "success");
        assert_eq!(parsed.data.result.len(), 1);
        assert_eq!(parsed.data.result[0].value.1, "1.234");
    }

    #[test]
    fn error_response_parses_even_without_data() {
        let json = r#"{"status":"error","error":"bad expression"}"#;
        let parsed: PromResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.status, "error");
        assert_eq!(parsed.error.as_deref(), Some("bad expression"));
    }
}
