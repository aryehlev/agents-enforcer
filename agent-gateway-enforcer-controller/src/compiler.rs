//! Compile a reconciled `AgentPolicy` (plus any `GatewayCatalog`
//! references) into the flat [`PolicyBundle`] that node agents consume.
//!
//! This module is deliberately pure: no kube client, no I/O, no async.
//! The reconciler resolves DNS and fetches catalogs, then hands the
//! fully-materialized inputs here. That makes compilation trivially
//! unit-testable and deterministic — critical for bundle hashing,
//! since two controllers compiling the same inputs must produce the
//! same hash.

use std::collections::BTreeMap;

use agent_gateway_enforcer_core::backend::{
    FileAccessConfig, GatewayConfig, PolicyBundle, PolicyHash,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::crds::{
    AgentPolicySpec, CatalogGateway, EgressAction, EgressPolicy, ExecPolicy, FileAccessPolicy,
    GatewayCatalogSpec,
};

/// Compilation failure modes. These surface into
/// `AgentPolicyStatus.message` so operators see them via
/// `kubectl describe agentpolicy`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompileError {
    /// The policy referenced a gateway name that isn't in any supplied
    /// catalog.
    #[error("unknown gateway reference: {0}")]
    UnknownGateway(String),
    /// A catalog entry's `host` couldn't be parsed as IPv4.
    ///
    /// Hostname resolution is the reconciler's job (so the DNS cache
    /// can be shared across policies); by the time a catalog reaches
    /// the compiler, every `host` must already be an IPv4 literal.
    #[error("gateway '{name}' has non-IPv4 host '{host}' — resolver should have pre-resolved it")]
    UnresolvedHost { name: String, host: String },
}

/// Compile an `AgentPolicySpec` plus the set of catalogs it references
/// into a [`PolicyBundle`].
///
/// The returned bundle's `hash` is derived from its canonicalized
/// contents (stable, SHA-256 of JSON with sorted maps), so two
/// identical policies always produce byte-identical bundles.
pub fn compile_policy(
    policy: &AgentPolicySpec,
    catalogs: &BTreeMap<String, GatewayCatalogSpec>,
) -> Result<PolicyBundle, CompileError> {
    let gateways = build_gateways(policy.egress.as_ref(), catalogs)?;
    let file_access = build_file_access(policy.file_access.as_ref());
    let exec_allowlist = policy
        .exec
        .as_ref()
        .map(ExecPolicy::clone)
        .map(|p| p.allowed_binaries)
        .unwrap_or_default();

    let mut bundle = PolicyBundle {
        hash: PolicyHash::new(""),
        gateways,
        file_access,
        exec_allowlist,
        block_mutations: policy.block_mutations,
    };
    bundle.hash = hash_bundle(&bundle);
    Ok(bundle)
}

/// Resolve `GatewayCatalog` refs + inline CIDRs into a flat list of
/// `GatewayConfig`. The order is: catalog refs first (in the order the
/// policy listed them), then CIDRs, so operators can read the compiled
/// output top-to-bottom in the same shape they wrote the policy.
fn build_gateways(
    egress: Option<&EgressPolicy>,
    catalogs: &BTreeMap<String, GatewayCatalogSpec>,
) -> Result<Vec<GatewayConfig>, CompileError> {
    let Some(egress) = egress else { return Ok(Vec::new()) };

    // Audit / Allow defaults never populate the allowlist — the data
    // plane interprets an empty allowlist with default_action != Deny
    // as "don't program anything, let everything through".
    if !matches!(egress.default_action, EgressAction::Deny) && egress.gateway_refs.is_empty() {
        return Ok(Vec::new());
    }

    // Flatten catalog entries into a lookup by name. When the same
    // name appears in multiple catalogs the last-seen wins; the
    // reconciler is responsible for logging that as a conflict.
    let mut by_name: BTreeMap<&str, &CatalogGateway> = BTreeMap::new();
    for catalog in catalogs.values() {
        for gw in &catalog.gateways {
            by_name.insert(gw.name.as_str(), gw);
        }
    }

    let mut out = Vec::new();
    for name in &egress.gateway_refs {
        let gw = by_name
            .get(name.as_str())
            .ok_or_else(|| CompileError::UnknownGateway(name.clone()))?;
        // The compiler only accepts pre-resolved IPv4 literals.
        if gw.host.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(CompileError::UnresolvedHost {
                name: gw.name.clone(),
                host: gw.host.clone(),
            });
        }
        if gw.ports.is_empty() {
            // port=0 → wildcard (see gateway_allowed() in ebpf/network.c).
            out.push(GatewayConfig {
                address: gw.host.clone(),
                port: 0,
                enabled: true,
                description: gw.description.clone(),
            });
        } else {
            for port in &gw.ports {
                out.push(GatewayConfig {
                    address: gw.host.clone(),
                    port: *port,
                    enabled: true,
                    description: gw.description.clone(),
                });
            }
        }
    }

    for cidr in &egress.cidrs {
        // v1alpha1 accepts but doesn't expand CIDRs — only exact /32
        // addresses are enforced by the ebpf-linux backend. Strip any
        // mask so the host bit is what ends up in the allowlist, and
        // let a future LPM-map backend interpret the full prefix.
        let host = cidr.cidr.split('/').next().unwrap_or("").to_string();
        if host.parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        if cidr.ports.is_empty() {
            out.push(GatewayConfig {
                address: host,
                port: 0,
                enabled: true,
                description: None,
            });
        } else {
            for port in &cidr.ports {
                out.push(GatewayConfig {
                    address: host.clone(),
                    port: *port,
                    enabled: true,
                    description: None,
                });
            }
        }
    }

    Ok(out)
}

fn build_file_access(policy: Option<&FileAccessPolicy>) -> FileAccessConfig {
    policy
        .map(|p| FileAccessConfig {
            default_deny: p.default_deny,
            allowed_paths: p.allowed_paths.clone(),
            denied_paths: p.denied_paths.clone(),
        })
        .unwrap_or_default()
}

/// Canonical hash of a bundle. SHA-256 over a deterministic JSON
/// serialization with an empty `hash` field, so the hash is stable
/// regardless of what was previously written into the field.
fn hash_bundle(bundle: &PolicyBundle) -> PolicyHash {
    let mut canonical = bundle.clone();
    canonical.hash = PolicyHash::new("");
    let json = serde_json::to_vec(&canonical)
        .expect("PolicyBundle is always JSON-serializable");
    let digest = Sha256::digest(&json);
    PolicyHash::new(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{CidrRule, ExecPolicy, LabelSelector};

    fn empty_policy() -> AgentPolicySpec {
        AgentPolicySpec {
            pod_selector: LabelSelector::default(),
            egress: None,
            file_access: None,
            exec: None,
            block_mutations: false,
        }
    }

    #[test]
    fn compile_empty_policy_yields_empty_bundle() {
        let bundle = compile_policy(&empty_policy(), &BTreeMap::new()).unwrap();
        assert!(bundle.gateways.is_empty());
        assert!(bundle.exec_allowlist.is_empty());
        assert!(!bundle.block_mutations);
        assert!(!bundle.hash.as_str().is_empty(), "hash is always set");
    }

    #[test]
    fn compile_is_deterministic() {
        let mut p = empty_policy();
        p.block_mutations = true;
        p.exec = Some(ExecPolicy {
            allowed_binaries: vec!["/usr/bin/python3".into()],
        });
        let a = compile_policy(&p, &BTreeMap::new()).unwrap();
        let b = compile_policy(&p, &BTreeMap::new()).unwrap();
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn compile_resolves_gateway_refs() {
        let mut policy = empty_policy();
        policy.egress = Some(EgressPolicy {
            default_action: EgressAction::Deny,
            gateway_refs: vec!["openai".into()],
            cidrs: vec![],
        });
        let mut catalogs = BTreeMap::new();
        catalogs.insert(
            "platform".into(),
            GatewayCatalogSpec {
                gateways: vec![CatalogGateway {
                    name: "openai".into(),
                    host: "1.2.3.4".into(),
                    ports: vec![443],
                    description: None,
                }],
            },
        );
        let bundle = compile_policy(&policy, &catalogs).unwrap();
        assert_eq!(bundle.gateways.len(), 1);
        assert_eq!(bundle.gateways[0].address, "1.2.3.4");
        assert_eq!(bundle.gateways[0].port, 443);
    }

    #[test]
    fn compile_wildcards_port_when_catalog_ports_empty() {
        let mut policy = empty_policy();
        policy.egress = Some(EgressPolicy {
            default_action: EgressAction::Deny,
            gateway_refs: vec!["redis".into()],
            cidrs: vec![],
        });
        let mut catalogs = BTreeMap::new();
        catalogs.insert(
            "platform".into(),
            GatewayCatalogSpec {
                gateways: vec![CatalogGateway {
                    name: "redis".into(),
                    host: "10.0.0.5".into(),
                    ports: vec![],
                    description: None,
                }],
            },
        );
        let bundle = compile_policy(&policy, &catalogs).unwrap();
        assert_eq!(bundle.gateways.len(), 1);
        assert_eq!(bundle.gateways[0].port, 0);
    }

    #[test]
    fn compile_rejects_unknown_gateway_ref() {
        let mut policy = empty_policy();
        policy.egress = Some(EgressPolicy {
            default_action: EgressAction::Deny,
            gateway_refs: vec!["nope".into()],
            cidrs: vec![],
        });
        let err = compile_policy(&policy, &BTreeMap::new()).unwrap_err();
        assert!(matches!(err, CompileError::UnknownGateway(name) if name == "nope"));
    }

    #[test]
    fn compile_rejects_unresolved_hostname() {
        let mut policy = empty_policy();
        policy.egress = Some(EgressPolicy {
            default_action: EgressAction::Deny,
            gateway_refs: vec!["openai".into()],
            cidrs: vec![],
        });
        let mut catalogs = BTreeMap::new();
        catalogs.insert(
            "platform".into(),
            GatewayCatalogSpec {
                gateways: vec![CatalogGateway {
                    name: "openai".into(),
                    host: "api.openai.com".into(), // not IPv4
                    ports: vec![443],
                    description: None,
                }],
            },
        );
        let err = compile_policy(&policy, &catalogs).unwrap_err();
        assert!(matches!(err, CompileError::UnresolvedHost { .. }));
    }

    #[test]
    fn compile_audit_mode_with_no_refs_yields_empty_gateways() {
        let mut policy = empty_policy();
        policy.egress = Some(EgressPolicy {
            default_action: EgressAction::Audit,
            gateway_refs: vec![],
            cidrs: vec![CidrRule {
                cidr: "10.0.0.0/32".into(),
                ports: vec![443],
            }],
        });
        let bundle = compile_policy(&policy, &BTreeMap::new()).unwrap();
        assert!(bundle.gateways.is_empty());
    }

    #[test]
    fn compile_expands_cidrs_in_deny_mode() {
        let mut policy = empty_policy();
        policy.egress = Some(EgressPolicy {
            default_action: EgressAction::Deny,
            gateway_refs: vec![],
            cidrs: vec![CidrRule {
                cidr: "10.0.0.5/32".into(),
                ports: vec![443, 5432],
            }],
        });
        let bundle = compile_policy(&policy, &BTreeMap::new()).unwrap();
        assert_eq!(bundle.gateways.len(), 2);
        assert_eq!(bundle.gateways[0].address, "10.0.0.5");
        assert_eq!(bundle.gateways[0].port, 443);
        assert_eq!(bundle.gateways[1].port, 5432);
    }

    #[test]
    fn compile_carries_file_access_and_block_mutations() {
        let mut policy = empty_policy();
        policy.block_mutations = true;
        policy.file_access = Some(FileAccessPolicy {
            default_deny: true,
            allowed_paths: vec!["/app".into()],
            denied_paths: vec!["/etc".into()],
        });
        let bundle = compile_policy(&policy, &BTreeMap::new()).unwrap();
        assert!(bundle.block_mutations);
        assert!(bundle.file_access.default_deny);
        assert_eq!(bundle.file_access.allowed_paths, vec!["/app".to_string()]);
    }

    #[test]
    fn hash_changes_when_policy_changes() {
        let mut a = empty_policy();
        let mut b = empty_policy();
        b.block_mutations = true;
        let ba = compile_policy(&a, &BTreeMap::new()).unwrap();
        let bb = compile_policy(&b, &BTreeMap::new()).unwrap();
        assert_ne!(ba.hash, bb.hash);

        // And a semantic-no-op change to the hash field itself must
        // not matter (hash_bundle() zeros it before hashing).
        a.block_mutations = true;
        let ba2 = compile_policy(&a, &BTreeMap::new()).unwrap();
        assert_eq!(ba2.hash, bb.hash);
    }
}
