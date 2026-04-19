//! Pod-scoped LLM capability bundle, the eBPF-only equivalent of the
//! LLM proxy's `CapabilityBundle`. Loaded from the same ConfigMap-
//! mounted YAML files so operators write one policy and both
//! enforcement modes (proxy / eBPF-only) see the same source of
//! truth.
//!
//! The shape duplicates the proxy's bundle on purpose: the eBPF
//! backend is meant to stand alone (no controller/proxy crate
//! dependency) so an `llm-enforcer` build for a customer who's
//! turned the proxy off has the smallest possible surface.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// Effective per-pod LLM capability bundle. Field semantics mirror
/// `agent_gateway_enforcer_controller::CapabilityBundle`.
#[derive(Debug, Clone, PartialEq)]
pub struct LlmCapability {
    /// Lowercased, sorted, deduped allowed model names. Empty list
    /// means "no model is allowed", which the decision layer treats
    /// as a deny-all.
    pub allowed_models: Vec<String>,
    /// Allowed tool names (exact match).
    pub allowed_tools: Vec<String>,
    /// Optional cap on the requested `max_output_tokens`. None =
    /// no cap (the controller still runs cost enforcement; eBPF
    /// mode just doesn't clamp the field).
    pub max_output_tokens: Option<u32>,
}

/// In-memory keyed store. Key is the agent identifier the LLM proxy
/// uses ( `<namespace>/<pod-name>` ); the eBPF backend resolves
/// `cgroup_id → pod` via the existing `Attributor` and hands the
/// pod name to this lookup.
#[derive(Debug, Default)]
pub struct LlmCapabilityStore {
    by_agent: parking_lot::Mutex<HashMap<String, LlmCapability>>,
}

impl LlmCapabilityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn replace(&self, fresh: HashMap<String, LlmCapability>) {
        *self.by_agent.lock() = fresh;
    }

    pub fn get(&self, agent_id: &str) -> Option<LlmCapability> {
        self.by_agent.lock().get(agent_id).cloned()
    }

    pub fn len(&self) -> usize {
        self.by_agent.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_agent.lock().is_empty()
    }
}

/// Wire shape of a single capability YAML file. Identical to the
/// controller's `AgentCapability` CR spec but `agent_id` is the
/// flattened `<namespace>/<pod>` string the runtime keys on, so the
/// loader doesn't need to depend on kube-rs to walk podSelectors.
///
/// Operators have two ways to ship these:
/// - The controller mounts a ConfigMap of these files (current path)
/// - A future pull-based loader queries the controller's HTTP API
///   so the node-agent doesn't need a ConfigMap remount on change.
#[derive(Debug, Deserialize)]
struct CapabilityFile {
    agent_id: String,
    #[serde(default)]
    allowed_models: Vec<String>,
    #[serde(default)]
    allowed_tools: Vec<String>,
    #[serde(default)]
    max_output_tokens: Option<u32>,
}

/// Read every `*.yaml` file under `dir` and build the agent_id →
/// capability map. Files that fail to parse are logged and
/// skipped — one bad capability shouldn't block the whole load.
pub fn load_from_dir(dir: &Path) -> anyhow::Result<HashMap<String, LlmCapability>> {
    let mut out = HashMap::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(file = %path.display(), err = %e, "capability read failed; skipping");
                continue;
            }
        };
        let parsed: CapabilityFile = match serde_yaml::from_str(&text) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(file = %path.display(), err = %e, "capability YAML invalid; skipping");
                continue;
            }
        };
        out.insert(parsed.agent_id.clone(), normalize(parsed));
    }
    Ok(out)
}

fn normalize(c: CapabilityFile) -> LlmCapability {
    let mut models: Vec<String> = c
        .allowed_models
        .into_iter()
        .map(|m| m.to_ascii_lowercase())
        .collect();
    models.sort();
    models.dedup();
    let mut tools = c.allowed_tools;
    tools.sort();
    tools.dedup();
    LlmCapability {
        allowed_models: models,
        allowed_tools: tools,
        max_output_tokens: c.max_output_tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn load_dir_normalizes_and_keys_by_agent_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        write(
            tmp.path(),
            "a.yaml",
            r#"
agent_id: prod/agent-0
allowed_models: [GPT-4o, claude-sonnet-4.6]
allowed_tools: [search, search, db]
max_output_tokens: 1024
"#,
        );
        let m = load_from_dir(tmp.path()).unwrap();
        let cap = m.get("prod/agent-0").unwrap();
        assert_eq!(cap.allowed_models, vec!["claude-sonnet-4.6", "gpt-4o"]);
        assert_eq!(cap.allowed_tools, vec!["db", "search"]);
        assert_eq!(cap.max_output_tokens, Some(1024));
    }

    #[test]
    fn malformed_file_is_skipped_not_fatal() {
        // One bad file shouldn't break the whole load — the goal is
        // graceful degradation when an operator typos one CR.
        let tmp = tempfile::TempDir::new().unwrap();
        write(tmp.path(), "good.yaml", "agent_id: ns/p\nallowed_models: [a]\n");
        write(tmp.path(), "bad.yaml", "this: is: not: valid: yaml: at: all\n");
        let m = load_from_dir(tmp.path()).unwrap();
        assert_eq!(m.len(), 1);
        assert!(m.contains_key("ns/p"));
    }

    #[test]
    fn missing_dir_returns_empty_not_error() {
        let m = load_from_dir(Path::new("/nope/does/not/exist")).unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn store_replace_swaps_atomically() {
        let s = LlmCapabilityStore::new();
        s.replace(HashMap::from([(
            "a".into(),
            LlmCapability {
                allowed_models: vec!["m".into()],
                allowed_tools: vec![],
                max_output_tokens: None,
            },
        )]));
        assert!(s.get("a").is_some());
        s.replace(HashMap::new());
        assert!(s.get("a").is_none());
    }
}
