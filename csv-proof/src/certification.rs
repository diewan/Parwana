//! Certification stub module

use serde::{Deserialize, Serialize};

/// Certification status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificationStatus {
    /// Uncertified
    Uncertified,
    /// Pending
    Pending,
    /// Certified
    Certified,
    /// Rejected
    Rejected,
}

/// Proof certification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCertification {
    /// Certification status
    pub status: CertificationStatus,
    /// Certifier ID
    pub certifier_id: String,
    /// Timestamp
    pub timestamp: u64,
}
