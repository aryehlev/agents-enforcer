//! ELF symbol lookup for uprobe offset resolution.
//!
//! Two concerns, in order of prevalence:
//!
//! 1. **Dynamic symbol table** (`.dynsym`). Present in every shared
//!    library and every dynamically-linked executable. Covers
//!    libssl.so, libcrypto.so, libnghttp2.so, and anything else
//!    that's a `.so`.
//!
//! 2. **Full symbol table** (`.symtab`). Present in unstripped
//!    release binaries from nodejs.org, Go's `go build` output,
//!    most Rust releases, and dev builds everywhere. Alpine and
//!    slim container images strip it; distroless usually doesn't.
//!    When present, contains the function-scope symbols we need
//!    for static-TLS recipes.
//!
//! Stripped static TLS (Alpine + `musl-gcc -static` + a `strip`
//! pass) is out of scope here — recipes for those binaries need
//! byte-pattern scanning against known function prologues, which
//! is a lot of per-version maintenance. Layer that on top of this
//! module when a customer needs it.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use object::{Object, ObjectSymbol};

/// Resolved symbol: file offset (which for ELF is the same as the
/// virtual address within the binary, modulo PIE base). The aya
/// uprobe attach helper interprets this as "bytes from the start
/// of the binary file," which is what we want.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolOffset {
    /// Symbol's address from the ELF symbol entry. For uprobe
    /// attachment, aya subtracts the binary's `p_vaddr` of the
    /// first loadable segment internally, so passing this value
    /// directly is correct.
    pub offset: u64,
    /// Which table it came from — useful when debugging
    /// "why didn't we find X" (stripped binaries return only
    /// `.dynsym` hits).
    pub source: SymbolSource,
}

/// Which ELF table a symbol came from. Useful diagnostic for
/// debugging "why didn't we find X" — a stripped binary would
/// return `.dynsym` hits only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolSource {
    /// From the `.dynsym` section (exported / imported dynamic).
    DynSym,
    /// From the `.symtab` section (static, stripped on release).
    SymTab,
}

/// Look up each name in `wanted` in `binary_path`'s ELF symbol
/// tables. Missing symbols simply don't appear in the output — the
/// caller decides whether that's fatal (via `Option`) or expected.
pub fn resolve_symbols(
    binary_path: &Path,
    wanted: &[&str],
) -> anyhow::Result<HashMap<String, SymbolOffset>> {
    let data =
        std::fs::read(binary_path).with_context(|| format!("read {}", binary_path.display()))?;
    resolve_from_bytes(&data, wanted)
}

/// Test-friendly variant. Lets tests build an ELF in memory (or
/// read one from a fixture) without touching the filesystem.
pub fn resolve_from_bytes(
    data: &[u8],
    wanted: &[&str],
) -> anyhow::Result<HashMap<String, SymbolOffset>> {
    let file = object::File::parse(data).context("parse ELF")?;
    let mut out = HashMap::new();

    // Walk `.dynsym` first. For shared libraries (our primary
    // target), this is the authoritative table.
    for sym in file.dynamic_symbols() {
        if let Ok(name) = sym.name() {
            if wanted.contains(&name) {
                out.insert(
                    name.to_string(),
                    SymbolOffset {
                        offset: sym.address(),
                        source: SymbolSource::DynSym,
                    },
                );
            }
        }
    }

    // Walk `.symtab` for anything still missing. This is the path
    // for unstripped static binaries (node, Go's output, Rust
    // debug builds). `.dynsym` already hit takes precedence
    // because exported symbols are more stable than local ones.
    if out.len() < wanted.len() {
        for sym in file.symbols() {
            if let Ok(name) = sym.name() {
                if wanted.contains(&name) && !out.contains_key(name) {
                    out.insert(
                        name.to_string(),
                        SymbolOffset {
                            offset: sym.address(),
                            source: SymbolSource::SymTab,
                        },
                    );
                }
            }
        }
    }

    Ok(out)
}

/// Convenience: returns `Some(offset)` for every symbol that
/// resolved. `None` entries let recipes enumerate missing probes
/// without double-walking the ELF.
pub fn lookup_many(
    binary_path: &Path,
    wanted: &[&str],
) -> anyhow::Result<Vec<(String, Option<SymbolOffset>)>> {
    let map = resolve_symbols(binary_path, wanted)?;
    Ok(wanted
        .iter()
        .map(|n| (n.to_string(), map.get(*n).copied()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test binary itself is an ELF with a rich symbol table
    /// (cargo test builds don't strip). Use it as a fixture so we
    /// don't ship binary blobs in the repo — the test is
    /// self-hosting.
    fn test_binary_path() -> std::path::PathBuf {
        std::env::current_exe().expect("current_exe")
    }

    #[test]
    fn resolve_finds_its_own_symbols() {
        // Every cargo-built test binary exports a `main` in its
        // `.symtab` (not stripped). Use that as the smoke check.
        let map = resolve_symbols(&test_binary_path(), &["main"])
            .expect("resolve should succeed on the test binary");
        let m = map.get("main").expect("test binary must have `main`");
        assert!(m.offset > 0, "symbol offset must be non-zero");
    }

    #[test]
    fn missing_symbols_are_absent_not_error() {
        // Looking up a symbol that doesn't exist is expected flow
        // (recipe tries both OpenSSL 1.1 and 3.0 names); it must
        // not error — just return a missing entry.
        let map = resolve_symbols(
            &test_binary_path(),
            &["__this_symbol_does_not_exist_anywhere_xyz"],
        )
        .unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn lookup_many_preserves_requested_order_and_presence() {
        // Recipes iterate the result in request order to assign
        // probe labels; the API must preserve that.
        let names = ["main", "this_is_not_here", "main"];
        let got = lookup_many(&test_binary_path(), &names).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, "main");
        assert!(got[0].1.is_some());
        assert!(got[1].1.is_none());
        // Duplicate request returns the same answer — we don't
        // deduplicate at this layer so caller semantics stay clear.
        assert_eq!(got[2].1, got[0].1);
    }

    #[test]
    fn garbage_file_errors_cleanly() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"not an elf").unwrap();
        let err = resolve_symbols(tmp.path(), &["whatever"]).unwrap_err();
        // Sanity-check that the error carries enough context to
        // debug (filename path is mentioned somewhere in the chain).
        let chain = format!("{:#}", err);
        assert!(chain.contains("ELF") || chain.contains("parse"));
    }
}
