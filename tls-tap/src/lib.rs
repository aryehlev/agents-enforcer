//! eBPF TLS plaintext sensor.
//!
//! See [`README.md`](https://github.com/aryehlev/tls-tap) for the
//! full positioning. The crate is intentionally small:
//!
//! - [`event::TlsEvent`] is the one struct the rest of the world
//!   consumes.
//! - [`uprobes`] picks the right symbols in the right binaries
//!   per runtime (recipes for OpenSSL, Node.js today).
//! - [`reassembler::Reassembler`] stitches multi-chunk SSL_write
//!   calls into one logical message per `(conn_id, direction)`.
//! - [`Tap`] is the convenience wrapper around the eBPF object —
//!   load, attach, subscribe.
//!
//! The library knows nothing about Kubernetes, AgentPolicy,
//! capability bundles, or LLM dialects. Building any of that on
//! top is the consumer's call.

#![warn(missing_docs)]

pub mod event;
pub mod reassembler;
pub mod uprobes;

#[cfg(target_os = "linux")]
mod tap_linux;
#[cfg(target_os = "linux")]
pub use tap_linux::Tap;

pub use event::{TlsDirection, TlsEvent, TlsEventHdr};
pub use reassembler::{ReassembledMessage, Reassembler};
pub use uprobes::{discover_targets, plan_all, recipes, ProbePlan, ProbeRecipe, ProbeTarget};
