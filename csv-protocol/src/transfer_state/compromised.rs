//! Compromised State
//!
//! Transfer compromised due to security incident.

use super::TransferData;

/// Transfer has been compromised
#[derive(Clone, Debug)]
pub struct Compromised {
    /// Shared transfer data
    pub data: TransferData,
    /// Compromise timestamp
    pub compromised_at: u64,
    /// Type of compromise
    pub compromise_type: CompromiseType,
    /// Additional details
    pub details: String,
}

/// Type of security compromise
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompromiseType {
    /// Replay attack detected
    ReplayAttack,
    /// Double-spend detected
    DoubleSpend,
    /// Proof validation failed
    InvalidProof,
    /// RPC provider disagreement
    RpcDisagreement,
    /// Other security incident
    Other,
}

impl Compromised {
    /// Create a new compromised state
    pub fn new(data: TransferData, compromise_type: CompromiseType, details: String) -> Self {
        Self {
            data,
            compromised_at: 0, // Will be set when compromise is detected
            compromise_type,
            details,
        }
    }

    /// Get the transfer data
    pub fn data(&self) -> &TransferData {
        &self.data
    }

    /// Get the compromise type
    pub fn compromise_type(&self) -> &CompromiseType {
        &self.compromise_type
    }

    /// Get the compromise details
    pub fn details(&self) -> &str {
        &self.details
    }
}
