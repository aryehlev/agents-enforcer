//! `enforcerctl gen-crds`. Emits the five CRD YAMLs. Identical to
//! the `xtask gen-crds` dev command, shipped here so operators can
//! regenerate manifests without a source checkout.

use std::path::Path;

use agent_gateway_enforcer_controller::{
    AgentCapability, AgentPolicy, AgentViolation, EnforcerConfig, GatewayCatalog,
};
use anyhow::Context;
use kube::CustomResourceExt;

pub fn run(out_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    for (name, value) in [
        (
            "agentpolicies.agents.enforcer.io.yaml",
            serde_yaml::to_value(AgentPolicy::crd())?,
        ),
        (
            "gatewaycatalogs.agents.enforcer.io.yaml",
            serde_yaml::to_value(GatewayCatalog::crd())?,
        ),
        (
            "enforcerconfigs.agents.enforcer.io.yaml",
            serde_yaml::to_value(EnforcerConfig::crd())?,
        ),
        (
            "agentviolations.agents.enforcer.io.yaml",
            serde_yaml::to_value(AgentViolation::crd())?,
        ),
        (
            "agentcapabilities.agents.enforcer.io.yaml",
            serde_yaml::to_value(AgentCapability::crd())?,
        ),
    ] {
        let path = out_dir.join(name);
        let yaml = serde_yaml::to_string(&value)?;
        std::fs::write(&path, yaml).with_context(|| format!("write {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}
