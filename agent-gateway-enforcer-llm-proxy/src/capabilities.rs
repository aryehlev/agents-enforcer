//! Thread-safe store of `CapabilityBundle`s keyed by `agent_id`.
//!
//! In v1alpha1 the proxy receives bundles at startup via a directory
//! of YAML files (so operators can hotload via a ConfigMap) and
//! re-reads on a SIGHUP. A push channel from the controller lands
//! in the same slot — replacing this module with a gRPC consumer
//! is the Phase C.5 work; the interface to the rest of the proxy
//! is intentionally a simple `get(agent_id) -> Option<Bundle>`.

use std::collections::HashMap;
use std::path::Path;

use agent_gateway_enforcer_controller::{
    compile_capability, AgentCapability, CapabilityBundle,
};
use parking_lot::RwLock;

/// Maps `agent_id` header → enforced bundle.
#[derive(Default)]
pub struct CapabilityStore {
    inner: RwLock<HashMap<String, CapabilityBundle>>,
}

impl CapabilityStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the whole store. Atomic from the POV of `get`.
    pub fn replace(&self, new_map: HashMap<String, CapabilityBundle>) {
        *self.inner.write() = new_map;
    }

    /// Fetch the bundle for a caller, if any. Returns an owned clone
    /// so callers don't hold the lock across awaits.
    pub fn get(&self, agent_id: &str) -> Option<CapabilityBundle> {
        self.inner.read().get(agent_id).cloned()
    }

    /// Count of tracked agents — handy for a `/readyz` sanity check.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether there's any agent at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Load every `AgentCapability` YAML file in `dir` into a new map.
/// The agent-id key is `namespace/name` — that's what pods supply
/// in the `X-Agent-Id` header so the namespace is explicit.
pub fn load_from_dir(dir: &Path) -> anyhow::Result<HashMap<String, CapabilityBundle>> {
    let mut out = HashMap::new();
    if !dir.exists() {
        tracing::warn!(path = %dir.display(), "capability dir missing; starting empty");
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml")
            && path.extension().and_then(|s| s.to_str()) != Some("yml")
        {
            continue;
        }
        let yaml = std::fs::read_to_string(&path)?;
        // Support multi-document YAML so operators can stuff all
        // capabilities into a single file.
        for doc in serde_yaml::Deserializer::from_str(&yaml) {
            let cap: AgentCapability = match AgentCapability::deserialize(doc) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        file = %path.display(),
                        err = %e,
                        "skipping malformed AgentCapability document"
                    );
                    continue;
                }
            };
            let namespace = cap
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".into());
            let name = match cap.metadata.name.clone() {
                Some(n) => n,
                None => continue,
            };
            let bundle = match compile_capability(&cap.spec) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        file = %path.display(),
                        cap = %format!("{}/{}", namespace, name),
                        err = %e,
                        "skipping AgentCapability that fails compile"
                    );
                    continue;
                }
            };
            out.insert(format!("{}/{}", namespace, name), bundle);
        }
    }
    Ok(out)
}

// The `Deserialize` impl resolves via kube's CustomResource derive;
// pull the trait in so `AgentCapability::deserialize` compiles.
use serde::Deserialize;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn get_on_missing_returns_none() {
        let s = CapabilityStore::new();
        assert!(s.get("prod/missing").is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn replace_is_atomic() {
        let s = CapabilityStore::new();
        let mut m = HashMap::new();
        m.insert(
            "prod/agent".into(),
            CapabilityBundle {
                hash: "h".into(),
                ..Default::default()
            },
        );
        s.replace(m);
        assert_eq!(s.len(), 1);
        assert!(s.get("prod/agent").is_some());
    }

    #[test]
    fn load_from_dir_reads_every_yaml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("cap.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
apiVersion: agents.enforcer.io/v1alpha1
kind: AgentCapability
metadata:
  name: agent-one
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: ai-agent
  allowedModels: [gpt-4o-mini]
  maxDailySpendUsd: 5.0
---
apiVersion: agents.enforcer.io/v1alpha1
kind: AgentCapability
metadata:
  name: agent-two
  namespace: staging
spec:
  podSelector:
    matchLabels:
      app: ai-agent
  allowedModels: [claude-haiku-4.5]
  maxDailySpendUsd: 1.0
"#
        )
        .unwrap();
        let loaded = load_from_dir(dir.path()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains_key("prod/agent-one"));
        assert!(loaded.contains_key("staging/agent-two"));
    }

    #[test]
    fn load_from_dir_skips_malformed_docs() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("cap.yaml");
        std::fs::write(&path, b"kind: not-an-agent-capability\n").unwrap();
        let loaded = load_from_dir(dir.path()).unwrap();
        assert!(loaded.is_empty());
    }
}
