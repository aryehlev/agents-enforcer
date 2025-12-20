//! Error types for backend operations

use super::BackendType;
use thiserror::Error;

/// Backend-specific errors
#[derive(Error, Debug)]
pub enum BackendError {
    /// Backend not found in registry
    #[error("Backend not found: {backend_type:?}")]
    BackendNotFound {
        /// The backend type that was not found
        backend_type: BackendType
    },
    
    /// Backend initialization failed
    #[error("Backend initialization failed: {reason}")]
    InitializationFailed {
        /// Reason for the initialization failure
        reason: String
    },
    
    /// Backend start operation failed
    #[error("Backend start failed: {reason}")]
    StartFailed {
        /// Reason for the start failure
        reason: String
    },
    
    /// Backend stop operation failed
    #[error("Backend stop failed: {reason}")]
    StopFailed {
        /// Reason for the stop failure
        reason: String
    },
    
    /// Configuration error
    #[error("Configuration error: {reason}")]
    ConfigurationError {
        /// Reason for the configuration error
        reason: String
    },
    
    /// Platform not supported
    #[error("Platform not supported: {platform}")]
    UnsupportedPlatform {
        /// The unsupported platform name
        platform: String
    },
    
    /// Backend not available on current platform
    #[error("Backend not available on current platform: {backend_type:?}")]
    NotAvailableOnPlatform {
        /// The backend type that's not available
        backend_type: BackendType
    },
    
    /// Backend factory not found
    #[error("Backend factory not found: {backend_type:?}")]
    FactoryNotFound {
        /// The backend type whose factory wasn't found
        backend_type: BackendType
    },
    
    /// Backend operation failed
    #[error("Backend operation failed: {operation} - {reason}")]
    OperationFailed {
        /// The operation that failed
        operation: String,
        /// Reason for the failure
        reason: String
    },
    
    /// Health check failed
    #[error("Health check failed: {reason}")]
    HealthCheckFailed {
        /// Reason for the health check failure
        reason: String
    },
    
    /// Resource cleanup failed
    #[error("Resource cleanup failed: {reason}")]
    CleanupFailed {
        /// Reason for the cleanup failure
        reason: String
    },
    
    /// No backend registered
    #[error("No backend registered for current platform")]
    NoBackendRegistered,
    
    /// Backend already running
    #[error("Backend is already running")]
    AlreadyRunning,
    
    /// Backend not running
    #[error("Backend is not running")]
    NotRunning,
    
    /// Invalid configuration
    #[error("Invalid configuration: {field} - {reason}")]
    InvalidConfiguration {
        /// The configuration field that's invalid
        field: String,
        /// Reason why it's invalid
        reason: String
    },
}

impl BackendError {
    /// Create an initialization failed error
    pub fn initialization_failed(reason: impl Into<String>) -> Self {
        Self::InitializationFailed {
            reason: reason.into(),
        }
    }
    
    /// Create a start failed error
    pub fn start_failed(reason: impl Into<String>) -> Self {
        Self::StartFailed {
            reason: reason.into(),
        }
    }
    
    /// Create a stop failed error
    pub fn stop_failed(reason: impl Into<String>) -> Self {
        Self::StopFailed {
            reason: reason.into(),
        }
    }
    
    /// Create a configuration error
    pub fn configuration_error(reason: impl Into<String>) -> Self {
        Self::ConfigurationError {
            reason: reason.into(),
        }
    }
    
    /// Create an operation failed error
    pub fn operation_failed(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::OperationFailed {
            operation: operation.into(),
            reason: reason.into(),
        }
    }
    
    /// Create a health check failed error
    pub fn health_check_failed(reason: impl Into<String>) -> Self {
        Self::HealthCheckFailed {
            reason: reason.into(),
        }
    }
    
    /// Create a cleanup failed error
    pub fn cleanup_failed(reason: impl Into<String>) -> Self {
        Self::CleanupFailed {
            reason: reason.into(),
        }
    }
    
    /// Create an invalid configuration error
    pub fn invalid_configuration(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidConfiguration {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_error_display() {
        let err = BackendError::initialization_failed("test error");
        assert_eq!(err.to_string(), "Backend initialization failed: test error");
    }

    #[test]
    fn test_backend_not_found_error() {
        let err = BackendError::BackendNotFound {
            backend_type: BackendType::EbpfLinux,
        };
        assert!(err.to_string().contains("Backend not found"));
    }

    #[test]
    fn test_configuration_error_builder() {
        let err = BackendError::configuration_error("invalid gateway address");
        assert!(err.to_string().contains("Configuration error"));
    }

    #[test]
    fn test_operation_failed_error() {
        let err = BackendError::operation_failed("configure_gateways", "network unavailable");
        assert!(err.to_string().contains("configure_gateways"));
        assert!(err.to_string().contains("network unavailable"));
    }

    #[test]
    fn test_invalid_configuration_error() {
        let err = BackendError::invalid_configuration("gateway.port", "must be between 1-65535");
        assert!(err.to_string().contains("gateway.port"));
        assert!(err.to_string().contains("must be between 1-65535"));
    }
}
