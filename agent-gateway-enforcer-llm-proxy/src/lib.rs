//! OpenAI-compatible LLM gateway that enforces `AgentCapability`
//! bundles: model allowlist, tool allowlist, and a daily USD cap.
//!
//! Layers:
//! - [`pricing`]: per-model USD-per-million-tokens table.
//! - [`budget`]: process-local daily spend counter per agent.
//! - [`capabilities`]: bundle store + YAML loader.
//! - [`enforce`]: pure rule engine (table-tested).
//! - [`handler`]: axum router speaking the OpenAI wire format.
//! - [`metrics`] / [`metrics_server`]: `/metrics` endpoint.
//!
//! The binary lives under `src/bin/llm_proxy.rs`; the crate lib is
//! usable standalone by integrators who want a different transport
//! (e.g. a sidecar wired through a UNIX socket).

#![warn(missing_docs)]

pub mod budget;
pub mod capabilities;
pub mod enforce;
pub mod handler;
pub mod metrics;
pub mod metrics_server;
pub mod pricing;
pub mod providers;
pub mod reporter;
pub mod sse;
