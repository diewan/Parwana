//! Failure domains classification for CSV protocol
//!
//! This module defines the failure domain classification system that enables
//! deterministic error handling and recovery strategies.
//!
//! # Failure Domains
//!
//! All errors in the CSV protocol are classified into failure domains:
//! - **Transient**: Temporary failures that may resolve with retry
//! - **Permanent**: Irrecoverable failures requiring manual intervention
//! - **Recoverable**: Failures with deterministic recovery paths
//! - **Catastrophic**: System-level failures requiring full restart
//!
//! # Error Handling Strategy
//!
//! - Transient errors: exponential backoff retry
//! - Recoverable errors: execute recovery procedure
//! - Permanent errors: surface to user with clear guidance
//! - Catastrophic errors: trigger emergency shutdown

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Failure domain classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailureDomain {
    /// Transient failure - may resolve with retry
    Transient,

    /// Permanent failure - requires manual intervention
    Permanent,

    /// Recoverable failure - has deterministic recovery path
    Recoverable,

    /// Catastrophic failure - system-level emergency
    Catastrophic,
}

impl FailureDomain {
    /// Get the recommended retry strategy for this domain.
    pub fn retry_strategy(&self) -> RetryStrategy {
        match self {
            FailureDomain::Transient => RetryStrategy::ExponentialBackoff {
                initial_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(60),
                multiplier: 2.0,
                max_attempts: 5,
            },
            FailureDomain::Recoverable => RetryStrategy::RecoveryProcedure,
            FailureDomain::Permanent => RetryStrategy::NoRetry,
            FailureDomain::Catastrophic => RetryStrategy::EmergencyShutdown,
        }
    }
}

/// Retry strategy for a failure domain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RetryStrategy {
    /// No retry - failure is permanent
    NoRetry,

    /// Exponential backoff retry
    ExponentialBackoff {
        /// Initial delay before first retry
        initial_delay: Duration,
        /// Maximum delay between retries
        max_delay: Duration,
        /// Multiplier for delay after each retry
        multiplier: f64,
        /// Maximum number of retry attempts
        max_attempts: u32,
    },

    /// Execute deterministic recovery procedure
    RecoveryProcedure,

    /// Emergency shutdown required
    EmergencyShutdown,
}

/// Classified error with failure domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedError {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Failure domain
    pub domain: FailureDomain,
    /// Component that generated the error
    pub component: Component,
    /// Timestamp of error occurrence
    pub timestamp: u64,
    /// Additional context
    pub context: ErrorContext,
}

/// Component that generated an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Component {
    /// Chain adapter (Bitcoin, Ethereum, etc.)
    ChainAdapter(String),

    /// Runtime coordinator
    Runtime,

    /// Verifier
    Verifier,

    /// Storage layer
    Storage,

    /// Network layer
    Network,

    /// Cryptographic operations
    Crypto,

    /// Contract interaction
    Contract,

    /// Unknown component
    Unknown,
}

/// Additional error context.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ErrorContext {
    /// Chain ID if applicable
    pub chain_id: Option<String>,

    /// Transaction hash if applicable
    pub tx_hash: Option<String>,

    /// Block number if applicable
    pub block_number: Option<u64>,

    /// Additional key-value context
    pub metadata: Vec<(String, String)>,
}

impl ClassifiedError {
    /// Create a new classified error.
    pub fn new(code: String, message: String, domain: FailureDomain, component: Component) -> Self {
        Self {
            code,
            message,
            domain,
            component,
            timestamp: chrono::Utc::now().timestamp() as u64,
            context: ErrorContext::default(),
        }
    }

    /// Add chain ID to context.
    pub fn with_chain_id(mut self, chain_id: String) -> Self {
        self.context.chain_id = Some(chain_id);
        self
    }

    /// Add transaction hash to context.
    pub fn with_tx_hash(mut self, tx_hash: String) -> Self {
        self.context.tx_hash = Some(tx_hash);
        self
    }

    /// Add block number to context.
    pub fn with_block_number(mut self, block_number: u64) -> Self {
        self.context.block_number = Some(block_number);
        self
    }

    /// Add metadata to context.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.context.metadata.push((key, value));
        self
    }

    /// Get the retry strategy for this error.
    pub fn retry_strategy(&self) -> RetryStrategy {
        self.domain.retry_strategy()
    }

    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.domain,
            FailureDomain::Transient | FailureDomain::Recoverable
        )
    }

    /// Check if this error requires emergency shutdown.
    pub fn requires_emergency_shutdown(&self) -> bool {
        self.domain == FailureDomain::Catastrophic
    }
}

/// Error classifier for categorizing errors into failure domains.
pub trait ErrorClassifier {
    /// Classify an error into a failure domain.
    fn classify(&self, error: &dyn std::error::Error) -> ClassifiedError;
}

/// Default error classifier implementation.
pub struct DefaultErrorClassifier;

impl ErrorClassifier for DefaultErrorClassifier {
    fn classify(&self, error: &dyn std::error::Error) -> ClassifiedError {
        let error_str = error.to_string().to_lowercase();

        let domain = if error_str.contains("timeout") || error_str.contains("network") {
            FailureDomain::Transient
        } else if error_str.contains("insufficient") || error_str.contains("invalid") {
            FailureDomain::Permanent
        } else if error_str.contains("replay") || error_str.contains("double-spend") {
            FailureDomain::Recoverable
        } else if error_str.contains("corruption") || error_str.contains("integrity") {
            FailureDomain::Catastrophic
        } else {
            FailureDomain::Permanent
        };

        ClassifiedError::new(
            error_str.clone(),
            error.to_string(),
            domain,
            Component::Unknown,
        )
    }
}

/// Failure domain registry for tracking error patterns.
#[derive(Debug, Clone, Default)]
pub struct FailureDomainRegistry {
    /// Error statistics by domain
    pub stats: std::collections::HashMap<FailureDomain, ErrorStats>,
}

/// Error statistics for a failure domain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorStats {
    /// Total error count
    pub total_count: u64,
    /// Error count in last hour
    pub recent_count: u64,
    /// Last error timestamp
    pub last_error_timestamp: Option<u64>,
}

impl FailureDomainRegistry {
    /// Create a new failure domain registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an error occurrence.
    pub fn record_error(&mut self, error: &ClassifiedError) {
        let stats = self.stats.entry(error.domain).or_default();
        stats.total_count += 1;
        stats.recent_count += 1;
        stats.last_error_timestamp = Some(error.timestamp);
    }

    /// Get statistics for a failure domain.
    pub fn get_stats(&self, domain: FailureDomain) -> Option<&ErrorStats> {
        self.stats.get(&domain)
    }

    /// Check if a failure domain is experiencing elevated error rates.
    pub fn is_elevated(&self, domain: FailureDomain, threshold: u64) -> bool {
        self.stats
            .get(&domain)
            .map(|s| s.recent_count > threshold)
            .unwrap_or(false)
    }

    /// Reset recent error counts (call periodically).
    pub fn reset_recent(&mut self) {
        for stats in self.stats.values_mut() {
            stats.recent_count = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_domain_retry_strategy() {
        let strategy = FailureDomain::Transient.retry_strategy();
        assert!(matches!(strategy, RetryStrategy::ExponentialBackoff { .. }));

        let strategy = FailureDomain::Permanent.retry_strategy();
        assert_eq!(strategy, RetryStrategy::NoRetry);
    }

    #[test]
    fn test_classified_error() {
        let error = ClassifiedError::new(
            "TEST_ERROR".to_string(),
            "Test error message".to_string(),
            FailureDomain::Transient,
            Component::Runtime,
        );

        assert!(error.is_retryable());
        assert!(!error.requires_emergency_shutdown());
    }

    #[test]
    fn test_failure_domain_registry() {
        let mut registry = FailureDomainRegistry::new();
        let error = ClassifiedError::new(
            "TEST".to_string(),
            "Test".to_string(),
            FailureDomain::Transient,
            Component::Runtime,
        );

        registry.record_error(&error);
        assert!(registry.get_stats(FailureDomain::Transient).is_some());
    }
}
