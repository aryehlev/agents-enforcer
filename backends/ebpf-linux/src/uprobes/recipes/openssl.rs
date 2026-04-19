//! OpenSSL / BoringSSL recipe (dynamic linkage).
//!
//! Matches any target whose `loaded_libs` includes a `libssl.so*`
//! path, resolves the four symbols we care about via ELF
//! [`.dynsym`], and returns entry/ret probes for SSL_write and
//! SSL_read.
//!
//! Coverage: OpenSSL 1.0 / 1.1 / 3.x; BoringSSL; LibreSSL (same
//! API surface). Python's `_ssl.cpython-*.so` is NOT matched here
//! on its own because the symbols it re-exports already live in
//! the libssl.so it dynamically links — one attach to libssl
//! covers every Python process on the node at once.
//!
//! Not covered: statically-linked OpenSSL baked into an executable
//! (rare today outside hand-rolled Alpine images). For those we'd
//! read the main binary's `.symtab`/`.dynsym` directly — same code
//! path minus the lib-path filter — and gate it on a binary
//! fingerprint to avoid false positives. Follow-on recipe.

use super::super::elf::{resolve_symbols, SymbolOffset};
use super::super::{ProbePlan, ProbeRecipe, ProbeTarget};

/// OpenSSL-shaped recipe (covers BoringSSL + LibreSSL too).
pub struct OpenSsl;

impl OpenSsl {
    /// Symbol names this recipe tries to resolve. Kept as a public
    /// const so tests can pin the set without reaching into a
    /// private function.
    pub const SYMBOLS: &'static [&'static str] = &["SSL_write", "SSL_read"];
}

impl ProbeRecipe for OpenSsl {
    fn name(&self) -> &'static str {
        "openssl"
    }

    fn plan(&self, target: &ProbeTarget) -> Vec<ProbePlan> {
        let Some(libssl) = pick_libssl(target) else {
            return vec![];
        };
        let Ok(symbols) = resolve_symbols(libssl, Self::SYMBOLS) else {
            // Read/parse failure of a real libssl shouldn't break
            // the attach sweep — a follow-on discovery pass may
            // pick up a replacement mapping after a rolling
            // restart.
            return vec![];
        };
        plans_from_symbols(libssl, &symbols)
    }
}

/// Pick the libssl-looking path out of the target's loaded libs.
/// Prefer a versioned `.so.3` over an unversioned `.so` when both
/// are present (unversioned is often a dev-tree symlink).
fn pick_libssl(t: &ProbeTarget) -> Option<&std::path::Path> {
    let mut best: Option<&std::path::Path> = None;
    for p in &t.loaded_libs {
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("libssl.so") {
            continue;
        }
        match best {
            None => best = Some(p),
            Some(prev) => {
                // Prefer paths with a version suffix.
                let prev_name = prev.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.len() > prev_name.len() {
                    best = Some(p);
                }
            }
        }
    }
    best
}

fn plans_from_symbols(
    libssl: &std::path::Path,
    symbols: &std::collections::HashMap<String, SymbolOffset>,
) -> Vec<ProbePlan> {
    let mut out = Vec::with_capacity(3);
    if let Some(s) = symbols.get("SSL_write") {
        out.push(ProbePlan {
            program: "uprobe_ssl_write",
            binary_path: libssl.to_path_buf(),
            offset: s.offset,
            label: "SSL_write".into(),
            is_ret: false,
        });
    }
    if let Some(s) = symbols.get("SSL_read") {
        // SSL_read is a pair — entry to capture buf + num, ret to
        // emit after the call actually filled the buffer.
        out.push(ProbePlan {
            program: "uprobe_ssl_read",
            binary_path: libssl.to_path_buf(),
            offset: s.offset,
            label: "SSL_read entry".into(),
            is_ret: false,
        });
        out.push(ProbePlan {
            program: "uretprobe_ssl_read",
            binary_path: libssl.to_path_buf(),
            offset: s.offset,
            label: "SSL_read ret".into(),
            is_ret: true,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_with_libs(libs: &[&str]) -> ProbeTarget {
        ProbeTarget {
            pid: 1,
            exe_path: "/proc/1/exe".into(),
            loaded_libs: libs.iter().map(|s| s.into()).collect(),
        }
    }

    #[test]
    fn pick_libssl_prefers_versioned_suffix() {
        // When both `libssl.so` (symlink) and `libssl.so.3` are
        // present, pick the versioned one — it's what the kernel's
        // uprobe resolver actually opens via inode.
        let t = target_with_libs(&["/lib/libssl.so", "/lib/libssl.so.3"]);
        let picked = pick_libssl(&t).unwrap();
        assert_eq!(picked.file_name().unwrap(), "libssl.so.3");
    }

    #[test]
    fn no_libssl_means_no_plans() {
        // A pod running a pure-Rust binary with rustls doesn't
        // load libssl. The OpenSSL recipe must return empty so
        // the framework moves on to the rustls recipe.
        let t = target_with_libs(&["/lib/libfoo.so"]);
        assert!(OpenSsl.plan(&t).is_empty());
    }

    #[test]
    fn plans_from_symbols_builds_expected_probe_triple() {
        // SSL_write = entry-only, SSL_read = entry + ret. That
        // split matters because the userspace consumer keys on
        // direction; getting it wrong would swap request and
        // response streams.
        use std::collections::HashMap;
        let mut sym = HashMap::new();
        sym.insert(
            "SSL_write".into(),
            SymbolOffset {
                offset: 0x100,
                source: crate::uprobes::elf::SymbolSource::DynSym,
            },
        );
        sym.insert(
            "SSL_read".into(),
            SymbolOffset {
                offset: 0x200,
                source: crate::uprobes::elf::SymbolSource::DynSym,
            },
        );
        let plans = plans_from_symbols(std::path::Path::new("/lib/libssl.so.3"), &sym);
        assert_eq!(plans.len(), 3);
        assert!(plans
            .iter()
            .any(|p| p.label == "SSL_write" && !p.is_ret));
        assert!(plans
            .iter()
            .any(|p| p.label == "SSL_read entry" && !p.is_ret));
        assert!(plans
            .iter()
            .any(|p| p.label == "SSL_read ret" && p.is_ret));
    }

    #[test]
    fn missing_ssl_write_still_produces_read_plans() {
        // Recipe is tolerant of partial symbol resolution — if a
        // vendor stripped SSL_write for some reason, we can still
        // capture responses. Better partial visibility than none.
        use std::collections::HashMap;
        let mut sym = HashMap::new();
        sym.insert(
            "SSL_read".into(),
            SymbolOffset {
                offset: 0x200,
                source: crate::uprobes::elf::SymbolSource::DynSym,
            },
        );
        let plans = plans_from_symbols(std::path::Path::new("/lib/libssl.so.3"), &sym);
        assert_eq!(plans.len(), 2);
        assert!(plans.iter().all(|p| p.label.starts_with("SSL_read")));
    }
}
