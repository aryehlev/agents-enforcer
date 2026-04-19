//! eBPF-only LLM enforcement.
//!
//! Composition:
//! - [`decoder`] turns plaintext bytes into [`decoder::LlmRequestFacts`].
//! - [`reassembler`] buffers across multiple `SSL_write` chunks for one connection.
//! - [`capability`] is the per-pod policy bundle (operator-supplied YAML).
//! - [`decision`] is the pure allow/deny function.
//!
//! The eBPF backend's TLS ringbuf consumer (Linux-only) wires these
//! together: ringbuf event → reassembler → on `Complete`, look up
//! the pod's capability via `cgroup_id`, run [`decision::decide`],
//! and emit a `DecisionEventWire` so the existing reporter ships
//! it to the controller's `/events/batch`.
//!
//! Why this lives in the eBPF crate
//! --------------------------------
//! The eBPF-only enforcement story ("agentless, no proxy") is the
//! product wedge — keeping all of it inside one crate means a
//! customer-facing `llm-enforcer` can be built without dragging in
//! the proxy/controller crates. The proxy keeps its own
//! `enforce::check` for the in-process path.

pub mod capability;
pub mod decision;
pub mod decoder;
pub mod reassembler;

pub use capability::{load_from_dir, LlmCapability, LlmCapabilityStore};
pub use decision::{decide, DenyReason, LlmVerdict};
pub use decoder::{parse, LlmRequestFacts, ParseStatus, ProviderHint};
pub use reassembler::{ChunkOutcome, Reassembler};
