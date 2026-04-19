//! Provider adapters. A "provider" is a specific LLM API dialect
//! (OpenAI, Anthropic, …). Each adapter extracts the two things the
//! proxy cares about — request facts to enforce on, and token usage
//! from the response — and tells the forwarder which upstream path
//! to POST to.
//!
//! The provider is pure: it never touches HTTP or state. Handler code
//! does the I/O and calls into the adapter for the parts that vary
//! between providers. That keeps `handler.rs` short and lets us
//! snapshot-test wire-shape parsing without spinning up a server.

use serde_json::Value;

/// What the proxy needs to know about an inbound request. Owning
/// `String`s because the borrowed `Value` path gets tangled inside
/// the axum handler's async lifetimes; the cost is two short clones
/// per request.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderFacts {
    pub model: String,
    pub tool_names: Vec<String>,
    pub estimated_input_tokens: u64,
    pub requested_max_output: Option<u32>,
}

/// Token counts the proxy pulls off a successful upstream response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// A provider dialect. See submodule docs for the shapes covered.
pub trait Provider: Send + Sync {
    /// Stable name used in logs + routing logs; not surfaced to
    /// users.
    fn name(&self) -> &'static str;

    /// Path suffix (everything after the base URL) for this
    /// provider's chat-completion-equivalent endpoint.
    fn upstream_path(&self) -> &'static str;

    /// Parse an inbound request body. A `Err(msg)` bubbles into a
    /// 400 without the upstream ever being called.
    fn extract_facts(&self, body: &Value) -> Result<ProviderFacts, String>;

    /// Parse usage off the upstream **non-streaming** response body.
    /// Returns `None` when the response is well-formed JSON but
    /// carries no usage object — the proxy treats that as "forward
    /// but don't account".
    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage>;

    /// Inspect one SSE event from a streamed response and return the
    /// *cumulative* usage visible so far, or `None` when this event
    /// doesn't carry usage info.
    ///
    /// `event_name` is the `event: …` header (empty string when the
    /// stream uses OpenAI-style unnamed events). `data` is the raw
    /// `data: …` payload, minus the prefix, as UTF-8 bytes.
    ///
    /// Implementations must be robust to malformed events: the proxy
    /// passes every chunk through to the client regardless, and a
    /// parse failure here just means "skip this event for
    /// accounting". Never panic.
    fn extract_usage_from_sse(
        &self,
        event_name: &str,
        data: &[u8],
    ) -> Option<ProviderUsage> {
        // Default: no usage extraction. Providers without streaming
        // support (or streams that don't carry usage) inherit this.
        let _ = (event_name, data);
        None
    }
}

fn estimate_input_tokens(body: &Value) -> u64 {
    // Conservative: byte-count / 4. Real tokenization would need
    // tiktoken / SentencePiece; for budget math a consistent lower
    // bound is what matters, and this overcounts relative to
    // reality ~2x which errs on the side of rejecting rather than
    // overspending.
    let bytes = serde_json::to_vec(body).map(|v| v.len()).unwrap_or(0);
    (bytes / 4) as u64
}

// -------------------------------------------------------------------
// OpenAI
// -------------------------------------------------------------------

/// OpenAI chat completions. Matches the shape used by
/// `/v1/chat/completions` on api.openai.com, Azure OpenAI deployment
/// endpoints, LiteLLM (default router), Portkey (OpenAI-compat),
/// and vLLM's OpenAI-compatible server.
pub struct OpenAi;

impl Provider for OpenAi {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn upstream_path(&self) -> &'static str {
        "/v1/chat/completions"
    }

    fn extract_facts(&self, body: &Value) -> Result<ProviderFacts, String> {
        let model = body
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| "field 'model' is required".to_string())?
            .to_string();
        let tool_names = body
            .get("tools")
            .and_then(Value::as_array)
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|t| {
                        // OpenAI: { "type": "function", "function": { "name": "..." } }
                        t.get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(Value::as_str)
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        let requested_max_output = body
            .get("max_tokens")
            .or_else(|| body.get("max_completion_tokens"))
            .and_then(Value::as_u64)
            .and_then(|u| u32::try_from(u).ok());
        Ok(ProviderFacts {
            model,
            tool_names,
            estimated_input_tokens: estimate_input_tokens(body),
            requested_max_output,
        })
    }

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage> {
        // OpenAI: { "usage": { "prompt_tokens": N, "completion_tokens": N, ... } }
        let v: Value = serde_json::from_slice(body).ok()?;
        let usage = v.get("usage")?;
        Some(ProviderUsage {
            input_tokens: usage
                .get("prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: usage
                .get("completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }

    fn extract_usage_from_sse(&self, _event: &str, data: &[u8]) -> Option<ProviderUsage> {
        // OpenAI SSE: plain `data: { … }` lines, unnamed events. The
        // usage object is present in the *final* chunk only when the
        // caller set `stream_options: { include_usage: true }`; we
        // parse every chunk anyway because it's cheap and older
        // servers sometimes interleave usage earlier.
        if data == b"[DONE]" {
            return None;
        }
        let v: Value = serde_json::from_slice(data).ok()?;
        let usage = v.get("usage")?;
        // A null `usage` field (sentinel emitted on non-final chunks
        // when `include_usage` is off) must not reset counters.
        if usage.is_null() {
            return None;
        }
        Some(ProviderUsage {
            input_tokens: usage
                .get("prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: usage
                .get("completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }
}

// -------------------------------------------------------------------
// Anthropic
// -------------------------------------------------------------------

/// Anthropic Messages API. Different shape:
/// - tools live at top-level `tools[].name`, not inside `function`.
/// - response usage is `{ "usage": { "input_tokens", "output_tokens" } }`.
/// - input-token limit is `max_tokens` (required, unlike OpenAI).
pub struct Anthropic;

impl Provider for Anthropic {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn upstream_path(&self) -> &'static str {
        "/v1/messages"
    }

    fn extract_facts(&self, body: &Value) -> Result<ProviderFacts, String> {
        let model = body
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| "field 'model' is required".to_string())?
            .to_string();
        let tool_names = body
            .get("tools")
            .and_then(Value::as_array)
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|t| t.get("name").and_then(Value::as_str).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let requested_max_output = body
            .get("max_tokens")
            .and_then(Value::as_u64)
            .and_then(|u| u32::try_from(u).ok());
        Ok(ProviderFacts {
            model,
            tool_names,
            estimated_input_tokens: estimate_input_tokens(body),
            requested_max_output,
        })
    }

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage> {
        let v: Value = serde_json::from_slice(body).ok()?;
        let usage = v.get("usage")?;
        Some(ProviderUsage {
            input_tokens: usage
                .get("input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: usage
                .get("output_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }

    fn extract_usage_from_sse(&self, event: &str, data: &[u8]) -> Option<ProviderUsage> {
        // Anthropic emits usage in two events:
        //   event: message_start
        //   data: { "message": { "usage": { "input_tokens": ... , "output_tokens": 0 } } }
        //
        //   event: message_delta
        //   data: { "usage": { "output_tokens": N } }
        //
        // The message_delta only carries an updated output_tokens —
        // input_tokens is fixed in the opening message_start event.
        // We merge by returning the latest view we can construct; the
        // handler keeps running totals across events and picks the
        // max to avoid regressions from out-of-order chunks.
        let v: Value = serde_json::from_slice(data).ok()?;
        match event {
            "message_start" => {
                let usage = v.get("message")?.get("usage")?;
                Some(ProviderUsage {
                    input_tokens: usage.get("input_tokens").and_then(Value::as_u64).unwrap_or(0),
                    output_tokens: usage
                        .get("output_tokens")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                })
            }
            "message_delta" => {
                let usage = v.get("usage")?;
                // Only output_tokens moves in message_delta; keep
                // input_tokens at 0 here and let the handler's max()
                // preserve whatever message_start set.
                Some(ProviderUsage {
                    input_tokens: 0,
                    output_tokens: usage
                        .get("output_tokens")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn openai_extracts_model_and_tools() {
        let body = json!({
            "model": "gpt-4o",
            "tools": [
                { "type": "function", "function": { "name": "search" } },
                { "type": "function", "function": { "name": "read_file" } }
            ],
            "max_tokens": 128
        });
        let f = OpenAi.extract_facts(&body).unwrap();
        assert_eq!(f.model, "gpt-4o");
        assert_eq!(f.tool_names, vec!["search", "read_file"]);
        assert_eq!(f.requested_max_output, Some(128));
    }

    #[test]
    fn openai_missing_model_errors() {
        assert!(OpenAi.extract_facts(&json!({})).is_err());
    }

    #[test]
    fn openai_usage_parses() {
        let body = br#"{"usage":{"prompt_tokens":100,"completion_tokens":50}}"#;
        let u = OpenAi.extract_usage(body).unwrap();
        assert_eq!(
            u,
            ProviderUsage {
                input_tokens: 100,
                output_tokens: 50,
            }
        );
    }

    #[test]
    fn openai_usage_absent_returns_none() {
        assert!(OpenAi.extract_usage(br#"{"choices":[]}"#).is_none());
    }

    #[test]
    fn anthropic_extracts_top_level_tools() {
        // Anthropic tools don't nest under `function`.
        let body = json!({
            "model": "claude-sonnet-4.6",
            "tools": [{ "name": "search" }, { "name": "read_file" }],
            "max_tokens": 256
        });
        let f = Anthropic.extract_facts(&body).unwrap();
        assert_eq!(f.model, "claude-sonnet-4.6");
        assert_eq!(f.tool_names, vec!["search", "read_file"]);
        assert_eq!(f.requested_max_output, Some(256));
    }

    #[test]
    fn anthropic_usage_parses_separate_field_names() {
        let body = br#"{"usage":{"input_tokens":10,"output_tokens":20}}"#;
        let u = Anthropic.extract_usage(body).unwrap();
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 20);
    }

    #[test]
    fn anthropic_uses_messages_path() {
        assert_eq!(Anthropic.upstream_path(), "/v1/messages");
        assert_eq!(OpenAi.upstream_path(), "/v1/chat/completions");
    }

    #[test]
    fn provider_names_are_stable_strings() {
        assert_eq!(OpenAi.name(), "openai");
        assert_eq!(Anthropic.name(), "anthropic");
    }

    #[test]
    fn openai_sse_done_is_ignored() {
        assert!(OpenAi.extract_usage_from_sse("", b"[DONE]").is_none());
    }

    #[test]
    fn openai_sse_chunk_with_null_usage_is_ignored() {
        // Non-final delta chunks emit `"usage":null` when
        // `include_usage` is on. Must not reset running totals.
        let data = br#"{"choices":[{"delta":{"content":"hi"}}],"usage":null}"#;
        assert!(OpenAi.extract_usage_from_sse("", data).is_none());
    }

    #[test]
    fn openai_sse_final_chunk_carries_usage() {
        let data = br#"{"choices":[],"usage":{"prompt_tokens":42,"completion_tokens":7}}"#;
        let u = OpenAi.extract_usage_from_sse("", data).unwrap();
        assert_eq!(u.input_tokens, 42);
        assert_eq!(u.output_tokens, 7);
    }

    #[test]
    fn anthropic_message_start_carries_input_tokens() {
        let data = br#"{"type":"message_start","message":{"id":"m","usage":{"input_tokens":100,"output_tokens":0}}}"#;
        let u = Anthropic
            .extract_usage_from_sse("message_start", data)
            .unwrap();
        assert_eq!(u.input_tokens, 100);
        assert_eq!(u.output_tokens, 0);
    }

    #[test]
    fn anthropic_message_delta_updates_only_output() {
        let data = br#"{"delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":55}}"#;
        let u = Anthropic
            .extract_usage_from_sse("message_delta", data)
            .unwrap();
        // input_tokens intentionally 0 here; handler merges via max
        // against message_start's value.
        assert_eq!(u.input_tokens, 0);
        assert_eq!(u.output_tokens, 55);
    }

    #[test]
    fn anthropic_unrelated_events_do_not_emit_usage() {
        let data = br#"{"type":"content_block_delta","delta":{"text":"hi"}}"#;
        assert!(Anthropic.extract_usage_from_sse("content_block_delta", data).is_none());
        assert!(Anthropic.extract_usage_from_sse("message_stop", b"{}").is_none());
    }

    #[test]
    fn malformed_sse_payload_does_not_panic() {
        // Truncated JSON from a flaky upstream mustn't crash the
        // proxy — we fall back to "no usage this chunk".
        assert!(OpenAi.extract_usage_from_sse("", b"{not json").is_none());
        assert!(Anthropic
            .extract_usage_from_sse("message_delta", b"{not json")
            .is_none());
    }
}
