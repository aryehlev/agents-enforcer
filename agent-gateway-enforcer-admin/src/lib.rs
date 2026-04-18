//! Read-only admin HTTP API for agents-enforcer.
//!
//! Two audiences:
//! - Ops teams who want a single dashboard for policies, capabilities,
//!   violations, and cluster health without plumbing one of each
//!   `kubectl get` + `promql`.
//! - Automation (CI checks, Backstage plugins, chatops bots) that
//!   wants a stable JSON shape instead of driving `kubectl` through
//!   shell.
//!
//! Explicitly read-only: writes go through `kubectl apply` so they
//! hit the existing admission webhook and keep one validation path.
//! When somebody asks for write endpoints later, they'll ride on top
//! of the same kube-rs client here — but until then the surface stays
//! small and easy to reason about.

#![warn(missing_docs)]

pub mod api;
pub mod router;
pub mod views;

pub use router::{router, AppState};
