//! Kubernetes controller + CRD types for agent-gateway-enforcer.
//!
//! This crate owns the user-facing Custom Resource Definitions
//! (`AgentPolicy`, `GatewayCatalog`, `EnforcerConfig`) and the logic
//! that turns a reconciled `AgentPolicy` into the flat
//! [`agent_gateway_enforcer_core::backend::PolicyBundle`] node agents
//! consume.
//!
//! Layers:
//! - [`crds`]: CR types, `CustomResource` derives, JSON schema.
//! - [`compiler`]: pure `AgentPolicy` + catalogs → `PolicyBundle`.
//! - [`distributor`]: trait for shipping bundles to node agents, plus
//!   an `InMemoryDistributor` for single-node / tests.
//! - [`reconciler`]: pure reconcile function taking the full input and
//!   emitting distributor calls + a status outcome.
//! - [`matching`]: pod-selector matching + `PodIdentity` construction
//!   from `kube::api::Pod`.
//!
//! The outer kube-rs `Controller` loop — apiserver watches, status
//! patches — is explicitly out of scope for this crate until the
//! follow-up Phase B.3. Every decision this crate makes is reachable
//! from unit tests today.

#![warn(missing_docs)]

pub mod compiler;
pub mod controller;
pub mod crds;
pub mod distributor;
pub mod matching;
pub mod metrics;
pub mod reconciler;
pub mod state;

pub use compiler::{compile_policy, CompileError};
pub use controller::{error_policy, reconcile, run, Context, ControllerConfig, ReconcileLoopError};
pub use crds::{
    AgentPolicy, AgentPolicySpec, AgentPolicyStatus, AgentViolation, AgentViolationSpec,
    EnforcerConfig, EnforcerConfigSpec, GatewayCatalog, GatewayCatalogSpec, LabelSelector,
    ViolationKind,
};
pub use distributor::{
    BundleDistributor, GrpcDistributor, InMemoryDistributor, LoggingDistributor,
    NodeEndpointResolver, StaticNodeEndpointResolver,
};
pub use matching::{pod_identity_from, pod_matches_selector};
pub use reconciler::{reconcile_policy, ReconcileError, ReconcileOutcome, ReconcileRequest};
pub use state::{PolicyKey, PolicyStateStore};
