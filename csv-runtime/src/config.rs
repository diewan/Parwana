//! Operational Configuration Module
//!
//! This module separates operational configuration from protocol semantics.
//! Protocol constants are immutable and defined in csv-core, while operational
//! configuration is defined here and can be adjusted at runtime.
//!
//! # Separation of Concerns
//!
//! - **Protocol Semantics**: Immutable constants defined in csv-core (e.g., hash sizes, proof formats)
//! - **Operational Configuration**: Runtime-adjustable settings (e.g., retry counts, timeouts, RPC endpoints)
//!
//! This separation ensures that protocol changes require a version bump, while
//! operational changes can be made without affecting protocol compatibility.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Operational configuration for the CSV runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationalConfig {
    /// RPC configuration
    pub rpc: RpcConfig,
    /// Retry configuration
    pub retry: RetryConfig,
    /// Timeout configuration
    pub timeout: TimeoutConfig,
    /// Lease configuration
    pub lease: LeaseConfig,
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
}

impl Default for OperationalConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl OperationalConfig {
    /// Create a production configuration (strict, no fallbacks)
    pub fn production() -> Self {
        Self {
            rpc: RpcConfig {
                allow_fallback: false,
                max_concurrent_connections: 10,
                connection_timeout: Duration::from_secs(30),
                request_timeout: Duration::from_secs(60),
            },
            retry: RetryConfig {
                max_retries: 3,
                initial_delay: Duration::from_secs(5),
                max_delay: Duration::from_secs(60),
                backoff_multiplier: 2.0,
            },
            timeout: TimeoutConfig {
                lock_timeout: Duration::from_secs(300),
                mint_timeout: Duration::from_secs(300),
                verification_timeout: Duration::from_secs(120),
            },
            lease: LeaseConfig {
                default_duration: Duration::from_secs(3600),
                max_duration: Duration::from_secs(86400),
                renewal_threshold: Duration::from_secs(300),
            },
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 5,
                open_timeout: Duration::from_secs(60),
                success_threshold: 2,
            },
        }
    }

    /// Create a development configuration (lenient, allows fallbacks)
    pub fn development() -> Self {
        Self {
            rpc: RpcConfig {
                allow_fallback: true,
                max_concurrent_connections: 5,
                connection_timeout: Duration::from_secs(10),
                request_timeout: Duration::from_secs(30),
            },
            retry: RetryConfig {
                max_retries: 5,
                initial_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(30),
                backoff_multiplier: 1.5,
            },
            timeout: TimeoutConfig {
                lock_timeout: Duration::from_secs(120),
                mint_timeout: Duration::from_secs(120),
                verification_timeout: Duration::from_secs(60),
            },
            lease: LeaseConfig {
                default_duration: Duration::from_secs(1800),
                max_duration: Duration::from_secs(7200),
                renewal_threshold: Duration::from_secs(300),
            },
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 10,
                open_timeout: Duration::from_secs(30),
                success_threshold: 1,
            },
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.lease.default_duration > self.lease.max_duration {
            return Err(ConfigValidationError::InvalidLeaseDuration(
                "Default lease duration cannot exceed max duration".to_string(),
            ));
        }

        if self.retry.max_retries == 0 {
            return Err(ConfigValidationError::InvalidRetryConfig(
                "Max retries must be at least 1".to_string(),
            ));
        }

        if self.circuit_breaker.failure_threshold == 0 {
            return Err(ConfigValidationError::InvalidCircuitBreakerConfig(
                "Failure threshold must be at least 1".to_string(),
            ));
        }

        Ok(())
    }
}

/// RPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Whether to allow RPC fallback to simulated mode
    pub allow_fallback: bool,
    /// Maximum number of concurrent RPC connections
    pub max_concurrent_connections: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial retry delay
    pub initial_delay: Duration,
    /// Maximum retry delay
    pub max_delay: Duration,
    /// Backoff multiplier for exponential backoff
    pub backoff_multiplier: f64,
}

/// Timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Timeout for lock operations
    pub lock_timeout: Duration,
    /// Timeout for mint operations
    pub mint_timeout: Duration,
    /// Timeout for verification operations
    pub verification_timeout: Duration,
}

/// Lease configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseConfig {
    /// Default lease duration
    pub default_duration: Duration,
    /// Maximum lease duration
    pub max_duration: Duration,
    /// Time before lease expiry to attempt renewal
    pub renewal_threshold: Duration,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening circuit
    pub failure_threshold: u32,
    /// Duration to keep circuit open before attempting recovery
    pub open_timeout: Duration,
    /// Number of successful requests required to close circuit
    pub success_threshold: u32,
}

/// Configuration validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigValidationError {
    /// Invalid lease duration
    InvalidLeaseDuration(String),
    /// Invalid retry configuration
    InvalidRetryConfig(String),
    /// Invalid circuit breaker configuration
    InvalidCircuitBreakerConfig(String),
    /// Invalid timeout configuration
    InvalidTimeoutConfig(String),
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigValidationError::InvalidLeaseDuration(msg) => {
                write!(f, "Invalid lease duration: {}", msg)
            }
            ConfigValidationError::InvalidRetryConfig(msg) => {
                write!(f, "Invalid retry config: {}", msg)
            }
            ConfigValidationError::InvalidCircuitBreakerConfig(msg) => {
                write!(f, "Invalid circuit breaker config: {}", msg)
            }
            ConfigValidationError::InvalidTimeoutConfig(msg) => {
                write!(f, "Invalid timeout config: {}", msg)
            }
        }
    }
}

impl std::error::Error for ConfigValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_config() {
        let config = OperationalConfig::production();
        assert!(!config.rpc.allow_fallback);
        assert_eq!(config.retry.max_retries, 3);
        assert_eq!(config.circuit_breaker.failure_threshold, 5);
    }

    #[test]
    fn test_development_config() {
        let config = OperationalConfig::development();
        assert!(config.rpc.allow_fallback);
        assert_eq!(config.retry.max_retries, 5);
        assert_eq!(config.circuit_breaker.failure_threshold, 10);
    }

    #[test]
    fn test_config_validation_success() {
        let config = OperationalConfig::production();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_invalid_lease_duration() {
        let mut config = OperationalConfig::production();
        config.lease.default_duration = Duration::from_secs(100000);
        config.lease.max_duration = Duration::from_secs(50000);

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigValidationError::InvalidLeaseDuration(_) => (),
            _ => panic!("Expected InvalidLeaseDuration error"),
        }
    }

    #[test]
    fn test_config_validation_invalid_retry_config() {
        let mut config = OperationalConfig::production();
        config.retry.max_retries = 0;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigValidationError::InvalidRetryConfig(_) => (),
            _ => panic!("Expected InvalidRetryConfig error"),
        }
    }

    #[test]
    fn test_config_validation_invalid_circuit_breaker() {
        let mut config = OperationalConfig::production();
        config.circuit_breaker.failure_threshold = 0;

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigValidationError::InvalidCircuitBreakerConfig(_) => (),
            _ => panic!("Expected InvalidCircuitBreakerConfig error"),
        }
    }
}
