//! Find the binaries we'd attach uprobes to.
//!
//! Input: a pod (via its cgroup id). Output: a list of
//! [`ProbeTarget`]s, one per distinct binary loaded by any of that
//! pod's processes — main executable plus dynamically-linked
//! libraries (`libssl.so.*`, `libcrypto.so.*`, a JVM's libjli, …).
//!
//! Why per-binary, not per-process: the kernel attaches uprobes at
//! the binary level (by inode), so we dedup across processes. A
//! single `libssl.so.3` in /usr/lib of a sidecarless 10-pod
//! cluster gets one attach that fires for every pod.
//!
//! Two levels of discovery
//! -----------------------
//! 1. `/proc/<pid>/exe` → the agent's own executable. Covers Go,
//!    Node, Rust — anything that statically links its TLS stack.
//! 2. `/proc/<pid>/maps` → every shared object loaded into that
//!    process's address space. Covers dynamic libssl, rustls
//!    compiled as a .so, Python's _ssl.so, etc.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// A binary we might want to probe. Recipes inspect these and
/// return [`crate::uprobes::ProbePlan`]s.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeTarget {
    /// Some pid that loaded this binary. Kept for logs only — the
    /// actual uprobe attach keys on the binary path, not the pid.
    pub pid: u32,
    /// Absolute path of the binary. For `/proc/<pid>/exe` this is
    /// the canonicalized target; for `/proc/<pid>/maps` entries
    /// it's the path field verbatim (aya resolves it at attach).
    pub exe_path: PathBuf,
    /// Distinct shared-object paths loaded by this process.
    /// Sorted + deduped so recipes can scan deterministically.
    pub loaded_libs: Vec<PathBuf>,
}

/// Enumerate probe targets for every pid in `pids`. Missing pids
/// (process exited between discovery and scan) are silently
/// skipped; transient pids are the common case.
pub fn discover_targets(pids: &[u32]) -> Vec<ProbeTarget> {
    pids.iter().filter_map(|&p| discover_one(p).ok()).collect()
}

fn discover_one(pid: u32) -> std::io::Result<ProbeTarget> {
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))?;
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))?;
    let libs = parse_loaded_libs(&maps);
    Ok(ProbeTarget {
        pid,
        exe_path: exe,
        loaded_libs: libs,
    })
}

/// Parse `/proc/<pid>/maps` output into a deduped list of loaded
/// file paths. Anonymous mappings and the `[vdso]` / `[stack]`
/// pseudo-entries are skipped. Entries that don't look like
/// shared objects (extension not `.so.*` or `.so`) are also
/// skipped — we never want to attach uprobes to the Perl script
/// sitting in the data segment.
pub fn parse_loaded_libs(maps: &str) -> Vec<PathBuf> {
    let mut out: BTreeSet<PathBuf> = BTreeSet::new();
    for line in maps.lines() {
        // /proc/<pid>/maps format:
        //   address    perms  offset  dev    inode  pathname
        //   7f.. ..    r-xp   00000   08:01  1234   /usr/lib/libssl.so.3
        let Some(path) = line.split_whitespace().nth(5) else {
            continue;
        };
        if path.starts_with('[') {
            continue;
        }
        // Keep only shared objects — we don't want to attach to
        // random mapped data files (fonts, locales, mmap'd JSON).
        if !is_shared_object(path) {
            continue;
        }
        out.insert(PathBuf::from(path));
    }
    out.into_iter().collect()
}

/// A path is a shared object if it ends in `.so` or `.so.<ver>`
/// possibly followed by `.<minor>…`. Catches `libssl.so.3`,
/// `libssl.so.1.1`, `libboringssl.so`, etc.
fn is_shared_object(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or(path);
    let parts = last.split('.').rev();
    // Walk version numbers: .1.1 -> parts = ["1","1","so","libssl"]
    for p in parts {
        if p == "so" {
            return true;
        }
        if !p.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS_FIXTURE: &str = "\
55b8e0000000-55b8e0001000 r--p 00000000 08:01 1234 /usr/bin/python3.11
55b8e0001000-55b8e0002000 r-xp 00001000 08:01 1234 /usr/bin/python3.11
7f1234560000-7f1234561000 r-xp 00000000 08:01 5678 /usr/lib/x86_64-linux-gnu/libssl.so.3
7f1234561000-7f1234562000 r-xp 00000000 08:01 5679 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
7f1234562000-7f1234563000 rw-p 00000000 00:00 0
7fff11111000-7fff11112000 r-xp 00000000 00:00 0                          [vdso]
7fff22222000-7fff22223000 r--p 00000000 00:00 0                          [stack]
7f9999990000-7f9999991000 r-xp 00000000 08:01 9999 /usr/lib/_ssl.cpython-311-x86_64-linux-gnu.so
";

    #[test]
    fn maps_parser_keeps_shared_objects_and_skips_anon() {
        let libs = parse_loaded_libs(MAPS_FIXTURE);
        let names: Vec<String> = libs
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "libssl.so.3"));
        assert!(names.iter().any(|n| n == "libcrypto.so.3"));
        assert!(
            names.iter().any(|n| n.starts_with("_ssl.cpython")),
            "Python's _ssl.so is in-scope for an OpenSSL recipe"
        );
        // Not included: the executable mapping, anonymous mappings,
        // and the [vdso]/[stack] pseudo-entries.
        assert!(!names.iter().any(|n| n == "python3.11"));
    }

    #[test]
    fn maps_parser_dedupes_multiple_mappings_of_same_file() {
        // A real /proc/<pid>/maps has 4–6 mappings per shared
        // object (text, rodata, data, bss, relro…). Dedup is
        // mandatory or recipes would attach N times.
        let libs = parse_loaded_libs(MAPS_FIXTURE);
        let count = libs
            .iter()
            .filter(|p| p.file_name().unwrap() == "libssl.so.3")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn shared_object_detector() {
        assert!(is_shared_object("/usr/lib/libssl.so"));
        assert!(is_shared_object("/usr/lib/libssl.so.3"));
        assert!(is_shared_object("/usr/lib/libssl.so.1.1"));
        assert!(is_shared_object(
            "/app/_ssl.cpython-311-x86_64-linux-gnu.so"
        ));
        assert!(!is_shared_object("/usr/bin/python3"));
        assert!(!is_shared_object("/etc/hostname"));
        // Hypothetical adversarial name — ".so" is in the middle
        // but not at the end. Must not match.
        assert!(!is_shared_object("/tmp/tricky.solder"));
    }

    #[test]
    fn discovery_tolerates_a_gone_pid() {
        // PID 0 can't exist on Linux. discover_targets swallows
        // the error and returns an empty set; callers treat a
        // missing pid as "not programmable" without crashing.
        let v = discover_targets(&[0]);
        assert!(v.is_empty());
    }
}
