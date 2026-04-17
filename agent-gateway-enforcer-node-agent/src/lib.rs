//! gRPC node agent — protocol types, server (behind the `server`
//! feature), and conversion helpers between the wire types and the
//! `agent-gateway-enforcer-core::backend` types.
//!
//! Split so the controller can take a lightweight client-only
//! dependency on this crate without pulling in aya / libbpf. Turn on
//! the `server` feature to get the `server` module + the
//! `enforcer-node-agent` binary.

#![warn(missing_docs)]

/// Raw tonic-generated bindings. External callers should prefer the
/// re-exports in this crate root; `proto` is kept public so tests and
/// advanced users can reach into request/response types directly.
pub mod proto {
    // The generated code lives in OUT_DIR so stale checked-in copies
    // can never drift from the .proto. `package` in the .proto maps
    // to the inner module name here.
    tonic::include_proto!("agents.enforcer.v1alpha1");
}

mod conversions;

pub mod metrics;
pub mod metrics_server;

pub use conversions::{bundle_from_proto, bundle_to_proto, pod_from_proto, pod_to_proto};
pub use proto::{
    node_agent_client::NodeAgentClient, node_agent_server::NodeAgentServer, AttachPodRequest,
    AttachPodResponse, DetachPodRequest, DetachPodResponse, FileAccessConfig as ProtoFileAccess,
    GatewayConfig as ProtoGateway, HealthRequest, HealthResponse, PodIdentity as ProtoPod,
    PolicyBundle as ProtoBundle, UpdatePolicyRequest, UpdatePolicyResponse,
};

#[cfg(feature = "server")]
pub mod server;
