//! Kubernetes controller + CRD types for agent-gateway-enforcer.
//!
//! This crate owns the user-facing Custom Resource Definitions
//! (`AgentPolicy`, `GatewayCatalog`, `EnforcerConfig`) and the logic that
//! compiles a reconciled `AgentPolicy` into the flat [`PolicyBundle`]
//! that node agents consume. The reconciler loop itself (kube-rs
//! `Controller::run`) lives in [`reconciler`]; the CRD types live in
//! [`crds`] so they can be imported without pulling in the kube client.
//!
//! **Scope note.** Phase B.1 in `docs/k8s-controller-plan.md`: this
//! crate currently ships the CRD surface + bundle compiler. Wiring the
//! gRPC push to node agents and the Status subresource writeback is
//! Phase B.2 and lives in a follow-up branch.

#![warn(missing_docs)]

pub mod compiler;
pub mod crds;

pub use compiler::{compile_policy, CompileError};
pub use crds::{AgentPolicy, AgentPolicySpec, EnforcerConfig, EnforcerConfigSpec, GatewayCatalog, GatewayCatalogSpec};
