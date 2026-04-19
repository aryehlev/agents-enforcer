//! Node.js recipe — BoringSSL is statically linked into the
//! `node` binary in every release from nodejs.org.
//!
//! Path: Node ships unstripped by default (the release binaries
//! keep `.symtab`), so we can resolve `SSL_write` / `SSL_read` in
//! the `node` executable directly — same symbol names as OpenSSL
//! because BoringSSL preserves the OpenSSL 1.0 API surface.
//!
//! What this does NOT cover:
//! - Distro-repackaged Node (Debian / Alpine) sometimes strips
//!   `.symtab`; those binaries need pattern scanning. The recipe
//!   returns empty rather than guessing — framework falls through.
//! - Electron / NW.js / Bun embed their own (non-standard) TLS
//!   locations. Separate recipes per product.
//!
//! Selection rule: target's `exe_path` basename is exactly `node`
//! or `node.<digits>` (Debian alternate). We deliberately don't
//! match every binary called "node" by file type — too noisy —
//! but we DO match when the process name matches and
//! `/proc/<pid>/exe` points to an unstripped ELF.

use super::super::elf::resolve_symbols;
use super::super::{ProbePlan, ProbeRecipe, ProbeTarget};

pub struct NodeJs;

impl NodeJs {
    /// Node embeds BoringSSL, which keeps OpenSSL's external
    /// surface — the symbol names are identical. Keeping the list
    /// in this module (not sharing with OpenSSL's) because a
    /// future Node version that drops a symbol should surface
    /// here, not silently stop working.
    pub const SYMBOLS: &'static [&'static str] = &["SSL_write", "SSL_read"];
}

impl ProbeRecipe for NodeJs {
    fn name(&self) -> &'static str {
        "nodejs"
    }

    fn plan(&self, target: &ProbeTarget) -> Vec<ProbePlan> {
        if !is_node_executable(&target.exe_path) {
            return vec![];
        }
        let Ok(symbols) = resolve_symbols(&target.exe_path, Self::SYMBOLS) else {
            return vec![];
        };
        let mut out = Vec::with_capacity(3);
        if let Some(s) = symbols.get("SSL_write") {
            out.push(ProbePlan {
                program: "uprobe_ssl_write",
                binary_path: target.exe_path.clone(),
                offset: s.offset,
                label: "node SSL_write".into(),
                is_ret: false,
            });
        }
        if let Some(s) = symbols.get("SSL_read") {
            out.push(ProbePlan {
                program: "uprobe_ssl_read",
                binary_path: target.exe_path.clone(),
                offset: s.offset,
                label: "node SSL_read entry".into(),
                is_ret: false,
            });
            out.push(ProbePlan {
                program: "uretprobe_ssl_read",
                binary_path: target.exe_path.clone(),
                offset: s.offset,
                label: "node SSL_read ret".into(),
                is_ret: true,
            });
        }
        out
    }
}

/// True when `path`'s basename is `node` or `node.<digits>`
/// (Debian's alternate name for the binary). False for every
/// other executable — deliberately strict to keep the recipe
/// deterministic: if a customer builds their own Node wrapper
/// named something else, they add a recipe.
fn is_node_executable(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name == "node" {
        return true;
    }
    if let Some(rest) = name.strip_prefix("node.") {
        return !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit() || c == '.');
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_node_by_basename() {
        assert!(is_node_executable(Path::new("/usr/bin/node")));
        assert!(is_node_executable(Path::new("/opt/node-v20/bin/node")));
        assert!(is_node_executable(Path::new("/usr/bin/node.18")));
        assert!(is_node_executable(Path::new("/usr/bin/node.20.11")));
    }

    #[test]
    fn rejects_non_node_binaries() {
        // Guardrails: close-but-wrong names must not match,
        // or we'd attach uprobes to every `nodeinfo` /
        // `nodeexporter` binary on a node.
        assert!(!is_node_executable(Path::new("/usr/bin/python3")));
        assert!(!is_node_executable(Path::new("/usr/bin/nodeinfo")));
        assert!(!is_node_executable(Path::new("/usr/bin/prometheus-node-exporter")));
        assert!(!is_node_executable(Path::new("/usr/bin/node.sh")));
    }

    #[test]
    fn non_node_target_returns_no_plans() {
        let t = ProbeTarget {
            pid: 1,
            exe_path: "/usr/bin/python3".into(),
            loaded_libs: vec![],
        };
        assert!(NodeJs.plan(&t).is_empty());
    }
}
