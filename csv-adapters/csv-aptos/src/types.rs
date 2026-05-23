//! Aptos-specific type definitions

use serde::{Deserialize, Serialize};

/// Aptos seal reference (resource with key + delete)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AptosSealPoint {
    /// Account address (32 bytes)
    pub account_address: [u8; 32],
    /// Resource type tag
    pub resource_type: String,
    /// Nonce for replay resistance
    pub nonce: u64,
}

impl AptosSealPoint {
    pub fn new(account_address: [u8; 32], resource_type: String, nonce: u64) -> Self {
        Self {
            account_address,
            resource_type,
            nonce,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 + self.resource_type.len());
        out.extend_from_slice(&self.account_address);
        out.extend_from_slice(&(self.resource_type.len() as u64).to_le_bytes());
        out.extend_from_slice(self.resource_type.as_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }
}

/// Aptos anchor reference (EventHandle containing commitment)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AptosCommitAnchor {
    /// Transaction version
    pub version: u64,
    /// Event handle address
    pub event_handle: [u8; 32],
    /// Event sequence number
    pub sequence_number: u64,
}

impl AptosCommitAnchor {
    pub fn new(version: u64, event_handle: [u8; 32], sequence_number: u64) -> Self {
        Self {
            version,
            event_handle,
            sequence_number,
        }
    }
}

/// Aptos inclusion proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AptosInclusionProof {
    /// Transaction proof bytes
    pub transaction_proof: Vec<u8>,
    /// Event proof bytes
    pub event_proof: Vec<u8>,
    /// Version number
    pub version: u64,
}

impl AptosInclusionProof {
    pub fn new(transaction_proof: Vec<u8>, event_proof: Vec<u8>, version: u64) -> Self {
        Self {
            transaction_proof,
            event_proof,
            version,
        }
    }
}

/// Aptos finality proof (checkpoint)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AptosFinalityProof {
    /// Version number
    pub version: u64,
    /// Whether certified by 2f+1
    pub is_certified: bool,
}

impl AptosFinalityProof {
    pub fn new(version: u64, is_certified: bool) -> Self {
        Self {
            version,
            is_certified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_ref_creation() {
        let seal = AptosSealPoint::new([1u8; 32], "CSV::Seal".to_string(), 42);
        assert_eq!(seal.nonce, 42);
    }
}
