//! Uprobe attachment framework.
//!
//! Turns "a pod is running process X" into "attach these uprobes to
//! these addresses in these binaries." Structured as a set of
//! per-runtime [`ProbeRecipe`] implementations that the framework
//! iterates in order — the first one that matches a discovered
//! binary wins.
//!
//! Why per-runtime recipes
//! -----------------------
//! OpenSSL's `SSL_write` lives in a shared library with a dynamic
//! symbol table we can just look up. Node.js bundles BoringSSL
//! statically; the symbols still exist in the unstripped release
//! binaries shipped by nodejs.org but we have to resolve them
//! inside `node` itself. Go's `crypto/tls` is stripped and
//! version-dependent — it needs ELF symbol scanning plus a small
//! offset table per Go release. One recipe per pattern keeps each
//! implementation honest about what it supports; the framework
//! handles discovery, dedup, and (on Linux) the actual
//! `UProbe::attach` dance.
//!
//! Scope & testability
//! -------------------
//! Everything up to "build a [`ProbePlan`]" is pure and unit-tested
//! against ELF fixtures. The attach step is Linux-only and
//! deferred to [`attach`]; tests there are gated behind
//! `#[cfg(target_os = "linux")]` and `#[ignore]` so CI on macOS
//! stays green.

pub mod discovery;
pub mod elf;
pub mod recipes;

pub use discovery::{discover_targets, ProbeTarget};
pub use recipes::{nodejs::NodeJs, openssl::OpenSsl};

/// A single uprobe to attach: binary path, offset within the
/// binary, direction (entry / ret), and a logical name so the
/// userspace consumer knows which TLS event kind this one
/// produces.
///
/// Offsets are absolute within the ELF (i.e. function's virtual
/// address); the aya attach helper subtracts the binary's load
/// address at attach time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePlan {
    /// The runtime-scoped eBPF program name the verifier loaded
    /// (e.g. "uprobe_ssl_write"). Must match a SEC("uprobe/…")
    /// in the loaded .o.
    pub program: &'static str,
    /// Absolute file path of the target binary. We pass this to
    /// the uprobe attach so the kernel resolves it via
    /// `/proc/<pid>/maps` at the time it fires.
    pub binary_path: std::path::PathBuf,
    /// Function offset within the binary, in bytes. For ELF, this
    /// is `st_value` of the symbol (already a virtual address in
    /// the file).
    pub offset: u64,
    /// Human-readable probe label for logs and metrics.
    pub label: String,
    /// True = uretprobe (fire on return), false = uprobe (fire on
    /// entry). SSL_read needs the uretprobe variant because
    /// `buf` only holds decrypted bytes after the call.
    pub is_ret: bool,
}

/// Runtime-specific recipe. Implementations inspect a target
/// (binary + metadata) and return zero or more [`ProbePlan`]s.
/// Returning an empty vector means "this recipe doesn't apply to
/// this target" — the framework moves on to the next recipe.
pub trait ProbeRecipe: Send + Sync {
    /// Short stable name for metrics + logs.
    fn name(&self) -> &'static str;

    /// Inspect `target` and return the probes to attach. Pure
    /// function — MUST NOT touch the process, only read the files
    /// the [`ProbeTarget`] references.
    fn plan(&self, target: &ProbeTarget) -> Vec<ProbePlan>;
}

/// Run every recipe against every target and collect the deduped
/// plan set. Same binary matched by two recipes (e.g. "a Go binary
/// that also dynamically links libssl") produces one plan per
/// recipe — that's correct, since both stacks may actually be in
/// use in the same process.
pub fn plan_all(recipes: &[Box<dyn ProbeRecipe>], targets: &[ProbeTarget]) -> Vec<ProbePlan> {
    let mut out = Vec::new();
    for t in targets {
        for r in recipes {
            for plan in r.plan(t) {
                if !out.iter().any(|p: &ProbePlan| {
                    p.binary_path == plan.binary_path
                        && p.offset == plan.offset
                        && p.is_ret == plan.is_ret
                }) {
                    out.push(plan);
                }
            }
        }
    }
    out
}

/// Linux-only uprobe attach driver. On non-Linux (CI/macOS dev),
/// returns an error so callers can detect the no-op path.
#[cfg(target_os = "linux")]
pub mod attach {
    use super::ProbePlan;
    use anyhow::Context;
    use aya::programs::UProbe;
    use aya::Bpf;

    /// Attach every plan against the already-loaded TLS bpf object.
    /// Returns the number of probes that attached successfully;
    /// per-probe failures are logged and skipped so one bad offset
    /// doesn't break the whole batch.
    pub fn attach_all(bpf: &mut Bpf, plans: &[ProbePlan]) -> anyhow::Result<usize> {
        let mut ok = 0;
        for plan in plans {
            let program: &mut UProbe = match bpf.program_mut(plan.program) {
                Some(p) => p
                    .try_into()
                    .with_context(|| format!("program '{}' not a uprobe", plan.program))?,
                None => {
                    tracing::warn!(program = plan.program, "uprobe program missing");
                    continue;
                }
            };
            if let Err(e) = program.load() {
                tracing::warn!(label = %plan.label, err = %e, "uprobe load failed");
                continue;
            }
            match program.attach(None, plan.offset, &plan.binary_path, /* pid */ None) {
                Ok(_) => {
                    ok += 1;
                    tracing::info!(
                        label = %plan.label,
                        binary = %plan.binary_path.display(),
                        offset = plan.offset,
                        "uprobe attached"
                    );
                }
                Err(e) => tracing::warn!(
                    label = %plan.label,
                    binary = %plan.binary_path.display(),
                    err = %e,
                    "uprobe attach failed"
                ),
            }
        }
        Ok(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysMatch;
    impl ProbeRecipe for AlwaysMatch {
        fn name(&self) -> &'static str {
            "always"
        }
        fn plan(&self, _t: &ProbeTarget) -> Vec<ProbePlan> {
            vec![ProbePlan {
                program: "uprobe_ssl_write",
                binary_path: "/usr/lib/libssl.so.3".into(),
                offset: 0x1000,
                label: "SSL_write".into(),
                is_ret: false,
            }]
        }
    }

    struct NeverMatch;
    impl ProbeRecipe for NeverMatch {
        fn name(&self) -> &'static str {
            "never"
        }
        fn plan(&self, _t: &ProbeTarget) -> Vec<ProbePlan> {
            vec![]
        }
    }

    fn fake_target() -> ProbeTarget {
        ProbeTarget {
            pid: 1,
            exe_path: "/proc/1/exe".into(),
            loaded_libs: vec!["/usr/lib/libssl.so.3".into()],
        }
    }

    #[test]
    fn plan_all_dedups_identical_probes_across_recipes() {
        // Two recipes that return the exact same probe. Attaching
        // twice would double-fire the ringbuf. Dedup is the invariant.
        let recipes: Vec<Box<dyn ProbeRecipe>> = vec![Box::new(AlwaysMatch), Box::new(AlwaysMatch)];
        let plans = plan_all(&recipes, &[fake_target()]);
        assert_eq!(plans.len(), 1);
    }

    #[test]
    fn plan_all_keeps_distinct_offsets() {
        struct Entry;
        impl ProbeRecipe for Entry {
            fn name(&self) -> &'static str {
                "e"
            }
            fn plan(&self, _: &ProbeTarget) -> Vec<ProbePlan> {
                vec![ProbePlan {
                    program: "uprobe_ssl_read",
                    binary_path: "/x".into(),
                    offset: 100,
                    label: "SSL_read entry".into(),
                    is_ret: false,
                }]
            }
        }
        struct Ret;
        impl ProbeRecipe for Ret {
            fn name(&self) -> &'static str {
                "r"
            }
            fn plan(&self, _: &ProbeTarget) -> Vec<ProbePlan> {
                vec![ProbePlan {
                    program: "uretprobe_ssl_read",
                    binary_path: "/x".into(),
                    offset: 100,
                    label: "SSL_read ret".into(),
                    is_ret: true,
                }]
            }
        }
        let recipes: Vec<Box<dyn ProbeRecipe>> = vec![Box::new(Entry), Box::new(Ret)];
        let plans = plan_all(&recipes, &[fake_target()]);
        // Entry + uretprobe at the same offset are different
        // probes — must keep both.
        assert_eq!(plans.len(), 2);
    }

    #[test]
    fn plan_all_skips_non_matching_recipes() {
        let recipes: Vec<Box<dyn ProbeRecipe>> = vec![Box::new(NeverMatch), Box::new(AlwaysMatch)];
        let plans = plan_all(&recipes, &[fake_target()]);
        assert_eq!(plans.len(), 1);
    }
}
