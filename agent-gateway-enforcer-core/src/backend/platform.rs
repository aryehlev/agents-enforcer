//! Platform detection. The project is Kubernetes-native and
//! Linux-only; this module exists so callers can log or short-circuit
//! when run on an unsupported host rather than segfault in eBPF land.

use serde::{Deserialize, Serialize};
use std::env;

/// Supported platforms for enforcement backends. Everything we
/// actually enforce on is Linux; anything else falls through to
/// `Unknown` and the CLI / tests refuse to start the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    /// Linux — the only production target.
    Linux,
    /// Any non-Linux OS. Tests and stubs use this to exercise error
    /// paths without needing another kernel.
    Unknown,
}

impl Platform {
    /// Detect the current platform at runtime.
    pub fn current() -> Self {
        match env::consts::OS {
            "linux" => Platform::Linux,
            _ => Platform::Unknown,
        }
    }

    /// Whether this is a platform we can enforce on.
    pub fn is_supported(&self) -> bool {
        matches!(self, Platform::Linux)
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Platform::Linux => "Linux",
            Platform::Unknown => "Unknown",
        }
    }

    /// Lowercase slug for config files and CLI args.
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Unknown => "unknown",
        }
    }

    /// Parse from a string. Accepts common Linux synonyms; everything
    /// else returns `None`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "linux" => Some(Platform::Linux),
            _ => None,
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_reports_linux_on_linux() {
        #[cfg(target_os = "linux")]
        assert_eq!(Platform::current(), Platform::Linux);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(Platform::current(), Platform::Unknown);
    }

    #[test]
    fn only_linux_is_supported() {
        assert!(Platform::Linux.is_supported());
        assert!(!Platform::Unknown.is_supported());
    }

    #[test]
    fn round_trips_through_as_str() {
        assert_eq!(Platform::from_str("linux"), Some(Platform::Linux));
        assert_eq!(Platform::from_str("Linux"), Some(Platform::Linux));
        assert_eq!(Platform::from_str("macos"), None);
        assert_eq!(Platform::from_str("windows"), None);
    }

    #[test]
    fn display_matches_name() {
        assert_eq!(format!("{}", Platform::Linux), "Linux");
    }

    #[test]
    fn serde_round_trip() {
        let p = Platform::Linux;
        let j = serde_json::to_string(&p).unwrap();
        let back: Platform = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
