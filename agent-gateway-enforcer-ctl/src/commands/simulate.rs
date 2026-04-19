//! `enforcerctl simulate`. Compiles a policy YAML + catalogs into the
//! concrete `PolicyBundle` without touching a cluster — runs the
//! same compiler the webhook and controller use, so whatever the
//! simulator accepts the cluster will too.

use std::collections::BTreeMap;
use std::path::PathBuf;

use agent_gateway_enforcer_controller::{compile_policy, AgentPolicy, GatewayCatalog};
use anyhow::Context;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Format {
    Yaml,
    Json,
}

pub fn run(policy_path: &PathBuf, catalog_paths: &[PathBuf], format: Format) -> anyhow::Result<String> {
    let policy_yaml = std::fs::read_to_string(policy_path)
        .with_context(|| format!("read {}", policy_path.display()))?;
    let policy: AgentPolicy = serde_yaml::from_str(&policy_yaml)
        .with_context(|| format!("parse AgentPolicy from {}", policy_path.display()))?;

    let mut catalogs = BTreeMap::new();
    for path in catalog_paths {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let cat: GatewayCatalog = serde_yaml::from_str(&yaml)
            .with_context(|| format!("parse GatewayCatalog from {}", path.display()))?;
        // Name collisions overwrite; matches the controller's
        // "later list wins" behavior on duplicate CRs.
        let name = cat
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "unnamed".into());
        catalogs.insert(name, cat.spec);
    }

    let bundle = compile_policy(&policy.spec, &catalogs)
        .map_err(|e| anyhow::anyhow!("compile failed: {}", e))?;

    Ok(match format {
        Format::Yaml => serde_yaml::to_string(&bundle)?,
        Format::Json => serde_json::to_string_pretty(&bundle)?,
    })
}
