//! Failure domain classification for runtime errors
//!
//! All runtime failures MUST be classified into a specific failure domain.
//! This enables targeted recovery strategies and prevents implicit reconstruction.

use std::fmt;

/// Failure domain classification
///
/// Every error in the runtime MUST be associated with one of these domains.
/// This enables deterministic recovery strategies and prevents cross-domain contamination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FailureDomain {
    /// RPC communication failure with chain endpoints
    Rpc,
    /// Verification failure (delegated to csv-verifier via chain adapters)
    Verification,
    /// Storage backend failure (replay DB, transfer store, etc.)
    Storage,
    /// Replay registry failure (duplicate detection, nullifier checking)
    Replay,
    /// Finality verification failure (chain-specific finality not met)
    Finality,
    /// Consensus failure (chain reorg, fork detection)
    Consensus,
    /// Serialization/deserialization failure
    Serialization,
}

impl FailureDomain {
    /// Returns true if this failure domain is transient and may be retried
    pub fn is_transient(&self) -> bool {
        matches!(self, FailureDomain::Rpc | FailureDomain::Storage)
    }

    /// Returns true if this failure domain requires operator intervention
    pub fn requires_operator_intervention(&self) -> bool {
        matches!(
            self,
            FailureDomain::Verification | FailureDomain::Replay | FailureDomain::Consensus
        )
    }

    /// Returns true if this failure domain can be recovered via checkpoint rollback
    pub fn is_checkpoint_recoverable(&self) -> bool {
        matches!(
            self,
            FailureDomain::Rpc | FailureDomain::Storage | FailureDomain::Finality
        )
    }
}

impl fmt::Display for FailureDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FailureDomain::Rpc => write!(f, "Rpc"),
            FailureDomain::Verification => write!(f, "Verification"),
            FailureDomain::Storage => write!(f, "Storage"),
            FailureDomain::Replay => write!(f, "Replay"),
            FailureDomain::Finality => write!(f, "Finality"),
            FailureDomain::Consensus => write!(f, "Consensus"),
            FailureDomain::Serialization => write!(f, "Serialization"),
        }
    }
}

/// Classified error with failure domain
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClassifiedError {
    /// The failure domain
    pub domain: FailureDomain,
    /// Error message
    pub message: String,
    /// Optional error code for machine processing
    pub code: Option<String>,
    /// Timestamp of the error
    pub timestamp: std::time::SystemTime,
}

impl ClassifiedError {
    /// Create a new classified error
    pub fn new(domain: FailureDomain, message: impl Into<String>) -> Self {
        Self {
            domain,
            message: message.into(),
            code: None,
            timestamp: std::time::SystemTime::now(),
        }
    }

    /// Create a new classified error with an error code
    pub fn with_code(
        domain: FailureDomain,
        message: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        Self {
            domain,
            message: message.into(),
            code: Some(code.into()),
            timestamp: std::time::SystemTime::now(),
        }
    }
}

impl fmt::Display for ClassifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.domain)?;
        if let Some(code) = &self.code {
            write!(f, "({}): {}", code, self.message)?;
        } else {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for ClassifiedError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_domain_properties() {
        assert!(FailureDomain::Rpc.is_transient());
        assert!(FailureDomain::Storage.is_transient());
        assert!(!FailureDomain::Verification.is_transient());

        assert!(FailureDomain::Verification.requires_operator_intervention());
        assert!(FailureDomain::Replay.requires_operator_intervention());
        assert!(!FailureDomain::Rpc.requires_operator_intervention());

        assert!(FailureDomain::Rpc.is_checkpoint_recoverable());
        assert!(FailureDomain::Finality.is_checkpoint_recoverable());
        assert!(!FailureDomain::Verification.is_checkpoint_recoverable());
    }

    #[test]
    fn test_classified_error() {
        let err = ClassifiedError::new(FailureDomain::Rpc, "Connection timeout");
        assert_eq!(err.domain, FailureDomain::Rpc);
        assert_eq!(err.message, "Connection timeout");
        assert!(err.code.is_none());

        let err_with_code = ClassifiedError::with_code(
            FailureDomain::Storage,
            "Database connection failed",
            "DB_CONN_001",
        );
        assert_eq!(err_with_code.code, Some("DB_CONN_001".to_string()));
    }

    #[test]
    fn test_classified_error_display() {
        let err = ClassifiedError::new(FailureDomain::Rpc, "Connection timeout");
        assert_eq!(format!("{}", err), "[Rpc]: Connection timeout");

        let err_with_code = ClassifiedError::with_code(
            FailureDomain::Storage,
            "Database connection failed",
            "DB_CONN_001",
        );
        assert_eq!(
            format!("{}", err_with_code),
            "[Storage](DB_CONN_001): Database connection failed"
        );
    }
}
