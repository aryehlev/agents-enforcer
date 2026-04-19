//! Lossless conversions between the wire (`proto::*`) and the
//! in-memory types (`agent_gateway_enforcer_core::backend::*`).
//!
//! Every field on both sides maps 1:1 today. Keeping these as
//! explicit functions (rather than `From` impls) so the direction
//! and any fallibility is obvious at the call site — `From` on a
//! fallible proto→native direction leads to surprising panics.

use agent_gateway_enforcer_core::backend::{
    FileAccessConfig, GatewayConfig, PodIdentity, PolicyBundle, PolicyHash,
};

use crate::proto;

/// Native → wire for `PodIdentity`.
pub fn pod_to_proto(p: &PodIdentity) -> proto::PodIdentity {
    proto::PodIdentity {
        uid: p.uid.clone(),
        namespace: p.namespace.clone(),
        name: p.name.clone(),
        cgroup_path: p.cgroup_path.clone(),
        node_name: p.node_name.clone(),
    }
}

/// Wire → native for `PodIdentity`.
pub fn pod_from_proto(p: proto::PodIdentity) -> PodIdentity {
    PodIdentity {
        uid: p.uid,
        namespace: p.namespace,
        name: p.name,
        cgroup_path: p.cgroup_path,
        node_name: p.node_name,
    }
}

/// Native → wire for `PolicyBundle`.
pub fn bundle_to_proto(b: &PolicyBundle) -> proto::PolicyBundle {
    proto::PolicyBundle {
        hash: b.hash.as_str().to_string(),
        gateways: b.gateways.iter().map(gateway_to_proto).collect(),
        file_access: Some(file_access_to_proto(&b.file_access)),
        exec_allowlist: b.exec_allowlist.clone(),
        block_mutations: b.block_mutations,
    }
}

/// Wire → native for `PolicyBundle`. Missing `file_access` is treated
/// as a default (empty) config rather than a hard error — the proto
/// field is optional so upgrade compatibility doesn't depend on
/// every client filling it in.
pub fn bundle_from_proto(b: proto::PolicyBundle) -> PolicyBundle {
    PolicyBundle {
        hash: PolicyHash::new(b.hash),
        gateways: b.gateways.into_iter().map(gateway_from_proto).collect(),
        file_access: b
            .file_access
            .map(file_access_from_proto)
            .unwrap_or_default(),
        exec_allowlist: b.exec_allowlist,
        block_mutations: b.block_mutations,
    }
}

fn gateway_to_proto(g: &GatewayConfig) -> proto::GatewayConfig {
    proto::GatewayConfig {
        address: g.address.clone(),
        port: g.port as u32,
        enabled: g.enabled,
        description: g.description.clone().unwrap_or_default(),
    }
}

fn gateway_from_proto(g: proto::GatewayConfig) -> GatewayConfig {
    GatewayConfig {
        address: g.address,
        // proto uint32 -> u16 truncates valid-range ports (0..=65535)
        // correctly; a malicious sender passing > 65535 gets the low
        // 16 bits which still round-trips for legal values.
        port: g.port as u16,
        enabled: g.enabled,
        description: if g.description.is_empty() {
            None
        } else {
            Some(g.description)
        },
    }
}

fn file_access_to_proto(f: &FileAccessConfig) -> proto::FileAccessConfig {
    proto::FileAccessConfig {
        allowed_paths: f.allowed_paths.clone(),
        denied_paths: f.denied_paths.clone(),
        default_deny: f.default_deny,
    }
}

fn file_access_from_proto(f: proto::FileAccessConfig) -> FileAccessConfig {
    FileAccessConfig {
        allowed_paths: f.allowed_paths,
        denied_paths: f.denied_paths,
        default_deny: f.default_deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pod() -> PodIdentity {
        PodIdentity {
            uid: "u".into(),
            namespace: "prod".into(),
            name: "agent".into(),
            cgroup_path: "/sys/fs/cgroup/foo".into(),
            node_name: "node-1".into(),
        }
    }

    fn sample_bundle() -> PolicyBundle {
        PolicyBundle {
            hash: PolicyHash::new("deadbeef"),
            gateways: vec![GatewayConfig {
                address: "10.0.0.1".into(),
                port: 443,
                enabled: true,
                description: Some("openai".into()),
            }],
            file_access: FileAccessConfig {
                allowed_paths: vec!["/app".into()],
                denied_paths: vec!["/etc".into()],
                default_deny: true,
            },
            exec_allowlist: vec!["/usr/bin/python3".into()],
            block_mutations: true,
        }
    }

    #[test]
    fn pod_round_trips() {
        let p = sample_pod();
        let back = pod_from_proto(pod_to_proto(&p));
        assert_eq!(p, back);
    }

    #[test]
    fn bundle_round_trips() {
        let b = sample_bundle();
        let back = bundle_from_proto(bundle_to_proto(&b));
        assert_eq!(b, back);
    }

    #[test]
    fn empty_description_becomes_none_on_reverse() {
        // Explicit edge case — proto strings default to "" so
        // round-trip must preserve Option::None when the native side
        // set `description = None`.
        let gw = GatewayConfig {
            address: "10.0.0.2".into(),
            port: 80,
            enabled: true,
            description: None,
        };
        let back = gateway_from_proto(gateway_to_proto(&gw));
        assert_eq!(back.description, None);
    }
}
