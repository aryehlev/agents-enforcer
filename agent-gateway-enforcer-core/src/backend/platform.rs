//! Platform detection and identification

use serde::{Deserialize, Serialize};
use std::env;

/// Supported platforms for enforcement backends
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    /// Linux operating system
    Linux,
    /// macOS operating system
    MacOS,
    /// Windows operating system
    Windows,
    /// Unknown or unsupported platform
    Unknown,
}

impl Platform {
    /// Detect the current platform at runtime
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_gateway_enforcer_core::backend::Platform;
    ///
    /// let platform = Platform::current();
    /// assert!(platform.is_supported() || platform == Platform::Unknown);
    /// ```
    pub fn current() -> Self {
        match env::consts::OS {
            "linux" => Platform::Linux,
            "macos" => Platform::MacOS,
            "windows" => Platform::Windows,
            _ => Platform::Unknown,
        }
    }
    
    /// Check if the platform is supported
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_gateway_enforcer_core::backend::Platform;
    ///
    /// assert!(Platform::Linux.is_supported());
    /// assert!(Platform::MacOS.is_supported());
    /// assert!(Platform::Windows.is_supported());
    /// assert!(!Platform::Unknown.is_supported());
    /// ```
    pub fn is_supported(&self) -> bool {
        matches!(self, Platform::Linux | Platform::MacOS | Platform::Windows)
    }
    
    /// Get the human-readable name of the platform
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_gateway_enforcer_core::backend::Platform;
    ///
    /// assert_eq!(Platform::Linux.name(), "Linux");
    /// assert_eq!(Platform::MacOS.name(), "macOS");
    /// assert_eq!(Platform::Windows.name(), "Windows");
    /// assert_eq!(Platform::Unknown.name(), "Unknown");
    /// ```
    pub fn name(&self) -> &'static str {
        match self {
            Platform::Linux => "Linux",
            Platform::MacOS => "macOS",
            Platform::Windows => "Windows",
            Platform::Unknown => "Unknown",
        }
    }
    
    /// Get the platform as a lowercase string identifier
    ///
    /// Useful for configuration files and CLI arguments.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_gateway_enforcer_core::backend::Platform;
    ///
    /// assert_eq!(Platform::Linux.as_str(), "linux");
    /// assert_eq!(Platform::MacOS.as_str(), "macos");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::MacOS => "macos",
            Platform::Windows => "windows",
            Platform::Unknown => "unknown",
        }
    }
    
    /// Parse a platform from a string
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_gateway_enforcer_core::backend::Platform;
    ///
    /// assert_eq!(Platform::from_str("linux"), Some(Platform::Linux));
    /// assert_eq!(Platform::from_str("macos"), Some(Platform::MacOS));
    /// assert_eq!(Platform::from_str("windows"), Some(Platform::Windows));
    /// assert_eq!(Platform::from_str("invalid"), None);
    /// ```
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "linux" => Some(Platform::Linux),
            "macos" | "darwin" | "osx" => Some(Platform::MacOS),
            "windows" | "win32" | "win64" => Some(Platform::Windows),
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
    fn test_platform_current() {
        let platform = Platform::current();
        
        // Should detect the current platform correctly
        #[cfg(target_os = "linux")]
        assert_eq!(platform, Platform::Linux);
        
        #[cfg(target_os = "macos")]
        assert_eq!(platform, Platform::MacOS);
        
        #[cfg(target_os = "windows")]
        assert_eq!(platform, Platform::Windows);
    }

    #[test]
    fn test_platform_is_supported() {
        assert!(Platform::Linux.is_supported());
        assert!(Platform::MacOS.is_supported());
        assert!(Platform::Windows.is_supported());
        assert!(!Platform::Unknown.is_supported());
    }

    #[test]
    fn test_platform_name() {
        assert_eq!(Platform::Linux.name(), "Linux");
        assert_eq!(Platform::MacOS.name(), "macOS");
        assert_eq!(Platform::Windows.name(), "Windows");
        assert_eq!(Platform::Unknown.name(), "Unknown");
    }

    #[test]
    fn test_platform_as_str() {
        assert_eq!(Platform::Linux.as_str(), "linux");
        assert_eq!(Platform::MacOS.as_str(), "macos");
        assert_eq!(Platform::Windows.as_str(), "windows");
        assert_eq!(Platform::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_platform_from_str() {
        assert_eq!(Platform::from_str("linux"), Some(Platform::Linux));
        assert_eq!(Platform::from_str("Linux"), Some(Platform::Linux));
        assert_eq!(Platform::from_str("LINUX"), Some(Platform::Linux));
        
        assert_eq!(Platform::from_str("macos"), Some(Platform::MacOS));
        assert_eq!(Platform::from_str("darwin"), Some(Platform::MacOS));
        assert_eq!(Platform::from_str("osx"), Some(Platform::MacOS));
        
        assert_eq!(Platform::from_str("windows"), Some(Platform::Windows));
        assert_eq!(Platform::from_str("win32"), Some(Platform::Windows));
        assert_eq!(Platform::from_str("win64"), Some(Platform::Windows));
        
        assert_eq!(Platform::from_str("invalid"), None);
        assert_eq!(Platform::from_str(""), None);
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(format!("{}", Platform::Linux), "Linux");
        assert_eq!(format!("{}", Platform::MacOS), "macOS");
        assert_eq!(format!("{}", Platform::Windows), "Windows");
    }

    #[test]
    fn test_platform_serialization() {
        let platform = Platform::Linux;
        let serialized = serde_json::to_string(&platform).unwrap();
        let deserialized: Platform = serde_json::from_str(&serialized).unwrap();
        assert_eq!(platform, deserialized);
    }

    #[test]
    fn test_platform_equality() {
        assert_eq!(Platform::Linux, Platform::Linux);
        assert_ne!(Platform::Linux, Platform::MacOS);
        assert_ne!(Platform::MacOS, Platform::Windows);
    }
}
