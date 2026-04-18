//! Validating admission webhook for `agents.enforcer.io` CRs.
//!
//! The CRD's OpenAPI schema catches malformed YAML at apply time;
//! this webhook catches semantic errors the schema can't: unknown
//! gateway references, unresolved hostnames, and duplicate
//! `AgentPolicy` names selecting the same pod set.
//!
//! Keeping validation outside the controller means users see errors
//! synchronously at `kubectl apply` time instead of as a Degraded
//! status condition later.

#![warn(missing_docs)]

pub mod handler;
pub mod validate;

pub use handler::router;
pub use validate::{validate_agent_policy, ValidationError};
