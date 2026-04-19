//! Pure HTTP+JSON decoder for plaintext captured by the TLS uprobe.
//!
//! Scope: just enough of HTTP/1.1 to recognize `POST` to one of the
//! known LLM endpoints and pull the JSON body out. HTTP/2 lands in
//! a follow-on (h2 framing + HPACK is its own project; OpenAI's
//! Python SDK falls back to HTTP/1.1 with a header, which covers
//! the most common deployment).
//!
//! The decoder is lossy on purpose: any malformed framing returns
//! `ParseStatus::NotLlm` and we let the request through. Pre-flight
//! enforcement happens at the cgroup egress layer (the agent can
//! only reach allowlisted hosts in the first place); this layer is
//! defense-in-depth + audit, so being permissive on parse failure
//! is the right default.

use serde::Deserialize;

/// Endpoints we recognize. Match `Provider::upstream_path()` in the
/// LLM proxy so policy semantics stay aligned across enforcement
/// modes (proxy vs. eBPF-only).
const OPENAI_PATH: &str = "/v1/chat/completions";
const ANTHROPIC_PATH: &str = "/v1/messages";

/// What the decoder distilled from a captured HTTP request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmRequestFacts {
    /// `model` field from the JSON body (lowercased for matching).
    pub model: String,
    /// `tools[].function.name` (OpenAI) or `tools[].name` (Anthropic).
    pub tool_names: Vec<String>,
    /// `max_tokens` (Anthropic) / `max_completion_tokens` /
    /// `max_tokens` (OpenAI). `None` when the field is absent.
    pub requested_max_output: Option<u32>,
    /// Which dialect we matched on, for labeling.
    pub provider: ProviderHint,
}

/// Provider dialect hint, mirrored from the LLM proxy's
/// `providers` module. Kept here as its own enum (instead of pulling
/// the proxy crate in) because the eBPF backend should be standalone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHint {
    OpenAi,
    Anthropic,
}

/// Outcome of feeding a plaintext blob to the decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseStatus {
    /// Successfully decoded one full LLM request.
    Ok(LlmRequestFacts),
    /// Plaintext is recognizably HTTP but doesn't target an LLM
    /// path we care about. Caller skips, no alarm.
    NotLlm,
    /// Plaintext is HTTP for an LLM path but the body is incomplete
    /// (only the headers + part of `Content-Length` arrived). Caller
    /// keeps buffering more events for this `conn_id`.
    NeedMore,
    /// Plaintext is malformed enough that we can't safely parse it.
    /// Treated as non-LLM by the consumer (i.e. allow).
    Garbage,
}

/// Parse one chunk of plaintext (typically the first SSL_write of a
/// request). On `NeedMore`, the caller concatenates additional
/// chunks for the same `conn_id` and re-calls.
///
/// Implementation: a tiny, byte-level HTTP/1.1 parser. We don't pull
/// in a full HTTP crate because the body is what we want — header
/// parsing only needs to find `Content-Length`, the request line
/// path, and the end-of-headers marker. ~80 lines beats a 30k LoC
/// dep that already exists in the proxy.
pub fn parse(chunk: &[u8]) -> ParseStatus {
    // The first \r\n terminates the request line. If we don't even
    // have that yet, the caller hasn't pushed enough bytes — keep
    // buffering rather than declaring garbage.
    let Some((request_line, rest)) = split_once(chunk, b"\r\n") else {
        return ParseStatus::NeedMore;
    };

    let parts: Vec<&[u8]> = request_line.split(|b| *b == b' ').collect();
    if parts.len() < 3 {
        return ParseStatus::Garbage;
    }
    if parts[0] != b"POST" {
        return ParseStatus::NotLlm;
    }

    let path = std::str::from_utf8(parts[1]).unwrap_or("");
    let provider = if path.starts_with(OPENAI_PATH) {
        ProviderHint::OpenAi
    } else if path.starts_with(ANTHROPIC_PATH) {
        ProviderHint::Anthropic
    } else {
        return ParseStatus::NotLlm;
    };

    // End-of-headers is the `\r\n\r\n` marker. If absent, we
    // haven't seen all the headers yet — keep buffering.
    let Some(end_of_headers) = find(rest, b"\r\n\r\n") else {
        return ParseStatus::NeedMore;
    };
    let header_block = &rest[..end_of_headers];
    let cursor = &rest[end_of_headers + 4..]; // past `\r\n\r\n`

    let mut content_length: Option<usize> = None;
    for line in header_block.split(|b| *b == b'\n') {
        // header_block is split on `\n`; trim the trailing `\r` per
        // line. Empty lines can't appear because we sliced before
        // the `\r\n\r\n` terminator.
        let line = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if let Some(value) = header_value_ci(line, b"content-length") {
            content_length = std::str::from_utf8(value)
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok());
        }
    }

    // No Content-Length on a POST is rare and not worth supporting;
    // chunked-transfer encoding for an LLM request is rarer still.
    let Some(want) = content_length else {
        return ParseStatus::Garbage;
    };
    if cursor.len() < want {
        return ParseStatus::NeedMore;
    }
    let body = &cursor[..want];

    match provider {
        ProviderHint::OpenAi => parse_openai_body(body),
        ProviderHint::Anthropic => parse_anthropic_body(body),
    }
}

/// Parse the OpenAI `chat/completions` JSON body.
fn parse_openai_body(body: &[u8]) -> ParseStatus {
    #[derive(Deserialize)]
    struct OpenAiTool {
        function: Option<OpenAiToolFn>,
    }
    #[derive(Deserialize)]
    struct OpenAiToolFn {
        name: Option<String>,
    }
    #[derive(Deserialize)]
    struct OpenAiBody {
        model: Option<String>,
        tools: Option<Vec<OpenAiTool>>,
        max_tokens: Option<u32>,
        max_completion_tokens: Option<u32>,
    }

    let Ok(b): Result<OpenAiBody, _> = serde_json::from_slice(body) else {
        return ParseStatus::Garbage;
    };
    let Some(model) = b.model else {
        return ParseStatus::Garbage;
    };
    let tool_names = b
        .tools
        .into_iter()
        .flatten()
        .filter_map(|t| t.function.and_then(|f| f.name))
        .collect();
    ParseStatus::Ok(LlmRequestFacts {
        model: model.to_ascii_lowercase(),
        tool_names,
        // OpenAI deprecated `max_tokens` in favor of
        // `max_completion_tokens`; clients often still send the old
        // field. Honor the new one when both are present.
        requested_max_output: b.max_completion_tokens.or(b.max_tokens),
        provider: ProviderHint::OpenAi,
    })
}

/// Parse the Anthropic `messages` JSON body.
fn parse_anthropic_body(body: &[u8]) -> ParseStatus {
    #[derive(Deserialize)]
    struct AnthropicTool {
        name: Option<String>,
    }
    #[derive(Deserialize)]
    struct AnthropicBody {
        model: Option<String>,
        tools: Option<Vec<AnthropicTool>>,
        max_tokens: Option<u32>,
    }

    let Ok(b): Result<AnthropicBody, _> = serde_json::from_slice(body) else {
        return ParseStatus::Garbage;
    };
    let Some(model) = b.model else {
        return ParseStatus::Garbage;
    };
    let tool_names = b
        .tools
        .into_iter()
        .flatten()
        .filter_map(|t| t.name)
        .collect();
    ParseStatus::Ok(LlmRequestFacts {
        model: model.to_ascii_lowercase(),
        tool_names,
        requested_max_output: b.max_tokens,
        provider: ProviderHint::Anthropic,
    })
}

fn split_once<'a>(buf: &'a [u8], sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let pos = find(buf, sep)?;
    Some((&buf[..pos], &buf[pos + sep.len()..]))
}

fn find(buf: &[u8], sep: &[u8]) -> Option<usize> {
    if sep.is_empty() || buf.len() < sep.len() {
        return None;
    }
    buf.windows(sep.len()).position(|w| w == sep)
}

/// Case-insensitive header lookup. `line` is the full header line
/// (without CRLF); returns the value bytes (trimmed left whitespace
/// only — RFC 7230 says the value may keep trailing whitespace).
fn header_value_ci<'a>(line: &'a [u8], name_lower: &[u8]) -> Option<&'a [u8]> {
    let colon = line.iter().position(|b| *b == b':')?;
    let (n, v) = line.split_at(colon);
    if n.len() != name_lower.len() {
        return None;
    }
    for (a, b) in n.iter().zip(name_lower.iter()) {
        if a.to_ascii_lowercase() != *b {
            return None;
        }
    }
    let mut value = &v[1..]; // skip ':'
    while value.first() == Some(&b' ') {
        value = &value[1..];
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(method_line: &str, body: &str) -> Vec<u8> {
        format!(
            "{}\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            method_line,
            body.len(),
            body,
        )
        .into_bytes()
    }

    #[test]
    fn openai_minimal_request_extracts_model() {
        let req = body(
            "POST /v1/chat/completions HTTP/1.1",
            r#"{"model":"gpt-4o","messages":[]}"#,
        );
        let r = parse(&req);
        let ParseStatus::Ok(facts) = r else {
            panic!("got {:?}", r)
        };
        assert_eq!(facts.model, "gpt-4o");
        assert_eq!(facts.provider, ProviderHint::OpenAi);
        assert!(facts.tool_names.is_empty());
        assert_eq!(facts.requested_max_output, None);
    }

    #[test]
    fn openai_tools_collected_by_function_name() {
        let req = body(
            "POST /v1/chat/completions HTTP/1.1",
            r#"{"model":"gpt-4o","messages":[],"tools":[
                {"type":"function","function":{"name":"web.search"}},
                {"type":"function","function":{"name":"db.query"}}
            ]}"#,
        );
        let ParseStatus::Ok(facts) = parse(&req) else {
            panic!("expected Ok")
        };
        assert_eq!(facts.tool_names, vec!["web.search", "db.query"]);
    }

    #[test]
    fn openai_max_completion_tokens_wins_over_max_tokens() {
        // Real-world: clients often send both fields during the
        // OpenAI deprecation window. Newer field is the source of truth.
        let req = body(
            "POST /v1/chat/completions HTTP/1.1",
            r#"{"model":"gpt-4o","messages":[],"max_tokens":256,"max_completion_tokens":128}"#,
        );
        let ParseStatus::Ok(f) = parse(&req) else {
            panic!()
        };
        assert_eq!(f.requested_max_output, Some(128));
    }

    #[test]
    fn anthropic_minimal_request_extracts_model_and_tools() {
        let req = body(
            "POST /v1/messages HTTP/1.1",
            r#"{"model":"claude-sonnet-4.6","max_tokens":256,
                "tools":[{"name":"weather"}], "messages":[]}"#,
        );
        let ParseStatus::Ok(f) = parse(&req) else {
            panic!()
        };
        assert_eq!(f.provider, ProviderHint::Anthropic);
        assert_eq!(f.model, "claude-sonnet-4.6");
        assert_eq!(f.tool_names, vec!["weather"]);
        assert_eq!(f.requested_max_output, Some(256));
    }

    #[test]
    fn non_llm_path_is_silently_ignored() {
        let req = body("POST /v1/embeddings HTTP/1.1", r#"{"model":"x"}"#);
        assert_eq!(parse(&req), ParseStatus::NotLlm);
    }

    #[test]
    fn get_request_is_not_an_llm_request() {
        // Health-check pings to the same hostname don't carry a body
        // and aren't subject to capability enforcement.
        let req = b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        assert_eq!(parse(req), ParseStatus::NotLlm);
    }

    #[test]
    fn partial_body_signals_need_more() {
        // Headers say Content-Length: 100 but only 30 bytes after \r\n\r\n.
        let req = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{\"model\":\"gpt-4o\",\"messages\":[]}";
        assert_eq!(parse(req), ParseStatus::NeedMore);
    }

    #[test]
    fn missing_content_length_on_post_is_garbage() {
        // Chunked-encoded LLM requests are vanishingly rare; treat
        // as garbage so the consumer doesn't enter an unbounded
        // reassembly state.
        let req = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n\r\n{}";
        assert_eq!(parse(req), ParseStatus::Garbage);
    }

    #[test]
    fn json_without_model_is_garbage() {
        let req = body("POST /v1/chat/completions HTTP/1.1", r#"{"messages":[]}"#);
        assert_eq!(parse(&req), ParseStatus::Garbage);
    }

    #[test]
    fn case_insensitive_header_lookup() {
        // Some clients send `content-length:`, some send
        // `Content-Length:`. Both must work.
        let body_str = r#"{"model":"gpt-4o","x":"yz"}"#;
        let req = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\ncontent-length: {}\r\n\r\n{}",
            body_str.len(),
            body_str,
        );
        assert!(matches!(parse(req.as_bytes()), ParseStatus::Ok(_)));
    }

    #[test]
    fn model_is_lowercased_for_matching() {
        // Capability bundles store model names lowercased; the
        // decoder normalizes here so the decision layer stays simple.
        let req = body(
            "POST /v1/chat/completions HTTP/1.1",
            r#"{"model":"GPT-4O","messages":[]}"#,
        );
        let ParseStatus::Ok(f) = parse(&req) else {
            panic!()
        };
        assert_eq!(f.model, "gpt-4o");
    }
}
