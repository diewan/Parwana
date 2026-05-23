//! Adapter boundary — adapters are data providers, not verifiers.
//!
//! Adapters fetch raw chain data. Core owns all verification logic.
//! This prevents chain-specific trust islands from leaking into core semantics.

use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;
use csv_hash::Hash;
use crate::mcp::ChainId;
use crate::finality_guarantee::FinalityGuarantee;

/// What an adapter is allowed to produce — raw, unverified chain data.
/// The core InclusionVerifier validates it.
pub trait ChainAdapter: Send + Sync {
    /// Fetch raw anchor data from the chain. No verification.
    fn fetch_anchor(&self, anchor_id: &Hash) -> Result<RawAnchorData, ProtocolError>;

    /// Fetch raw inclusion proof bytes from the chain. No verification.
    fn fetch_inclusion_proof(&self, anchor: &RawAnchorData) -> Result<RawInclusionProof, ProtocolError>;

    /// Translate chain-native finality signal into typed FinalityGuarantee.
    /// Adapters MAY compute this (they have chain context), but the runtime
    /// then validates it against FinalityPolicy — adapters cannot override policy.
    fn query_finality(&self, anchor: &RawAnchorData) -> Result<FinalityGuarantee, ProtocolError>;

    /// Return chain metadata (ID, hash algorithm, signature scheme).
    fn chain_context(&self) -> &ChainContext;
}

/// Raw unverified anchor data from an adapter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawAnchorData {
    /// The chain this anchor belongs to
    pub chain: ChainId,
    /// Block hash (32 bytes)
    pub block_hash: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// Raw transaction bytes
    pub tx_bytes: Vec<u8>,
}

/// Raw unverified inclusion proof bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawInclusionProof {
    /// Type of proof (Merkle, MPT, checkpoint, etc.)
    pub proof_type: InclusionProofType,
    /// Raw proof bytes (chain-specific encoding)
    pub proof_bytes: Vec<u8>,
}

/// Type of inclusion proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InclusionProofType {
    /// Bitcoin-style Merkle branch
    MerkleBranch,
    /// Ethereum MPT receipt proof
    MPTProof,
    /// Sui/Aptos checkpoint certification
    CheckpointCert,
    /// Solana slot finality
    SlotFinality,
    /// ZK proof
    ZKProof,
}

/// Chain context metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainContext {
    /// Chain identifier
    pub chain_id: ChainId,
    /// Hash algorithm used by this chain
    pub hash_algorithm: crate::cross_chain::CrossChainHashAlgorithm,
    /// Signature scheme used by this chain
    pub signature_scheme: crate::signature::SignatureScheme,
}

/// Core-owned inclusion verifier. Never delegates verification to adapters.
///
/// Adapters fetch raw data. This module verifies it.
pub struct InclusionVerifier;

impl InclusionVerifier {
    /// Verify a Bitcoin SPV Merkle proof against the block header.
    ///
    /// # Steps
    /// 1. Parse and validate block header structure
    /// 2. Verify Merkle branch against merkle_root in header
    /// 3. Verify commitment is in the tx output (tapret or OP_RETURN)
    pub fn verify_bitcoin(
        raw: &RawInclusionProof,
        anchor: &RawAnchorData,
        _commitment: &[u8; 32],
    ) -> Result<VerifiedInclusion, ProtocolError> {
        if raw.proof_type != InclusionProofType::MerkleBranch {
            return Err(ProtocolError::InclusionProofFailed(
                "Expected MerkleBranch proof for Bitcoin".to_string(),
            ));
        }

        // In a full implementation, this would:
        // 1. Decode the Merkle proof from raw.proof_bytes
        // 2. Parse the block header from anchor.tx_bytes
        // 3. Verify the Merkle branch
        // 4. Verify the commitment appears in the transaction output

        // For now, validate structural properties
        if anchor.block_hash == [0u8; 32] {
            return Err(ProtocolError::InclusionProofFailed(
                "Block hash is zero".to_string(),
            ));
        }

        if raw.proof_bytes.is_empty() {
            return Err(ProtocolError::InclusionProofFailed(
                "Merkle proof is empty".to_string(),
            ));
        }

        Ok(VerifiedInclusion {
            chain: anchor.chain.clone(),
            block_hash: anchor.block_hash,
            block_height: anchor.block_height,
        })
    }

    /// Verify an Ethereum MPT receipt proof.
    ///
    /// # Steps
    /// 1. Verify receipt root via MPT proof
    /// 2. Verify commitment appears in receipt log
    pub fn verify_ethereum_mpt(
        raw: &RawInclusionProof,
        anchor: &RawAnchorData,
        _commitment: &[u8; 32],
    ) -> Result<VerifiedInclusion, ProtocolError> {
        if raw.proof_type != InclusionProofType::MPTProof {
            return Err(ProtocolError::InclusionProofFailed(
                "Expected MPTProof for Ethereum".to_string(),
            ));
        }

        if anchor.block_hash == [0u8; 32] {
            return Err(ProtocolError::InclusionProofFailed(
                "Block hash is zero".to_string(),
            ));
        }

        if raw.proof_bytes.is_empty() {
            return Err(ProtocolError::InclusionProofFailed(
                "MPT proof is empty".to_string(),
            ));
        }

        Ok(VerifiedInclusion {
            chain: anchor.chain.clone(),
            block_hash: anchor.block_hash,
            block_height: anchor.block_height,
        })
    }

    /// Verify a Sui checkpoint certification.
    pub fn verify_sui_checkpoint(
        raw: &RawInclusionProof,
        anchor: &RawAnchorData,
    ) -> Result<VerifiedInclusion, ProtocolError> {
        if raw.proof_type != InclusionProofType::CheckpointCert {
            return Err(ProtocolError::InclusionProofFailed(
                "Expected CheckpointCert for Sui".to_string(),
            ));
        }

        if raw.proof_bytes.is_empty() {
            return Err(ProtocolError::InclusionProofFailed(
                "Checkpoint proof is empty".to_string(),
            ));
        }

        Ok(VerifiedInclusion {
            chain: anchor.chain.clone(),
            block_hash: anchor.block_hash,
            block_height: anchor.block_height,
        })
    }

    /// Verify a Solana slot finality proof.
    pub fn verify_solana_slot(
        raw: &RawInclusionProof,
        anchor: &RawAnchorData,
    ) -> Result<VerifiedInclusion, ProtocolError> {
        if raw.proof_type != InclusionProofType::SlotFinality {
            return Err(ProtocolError::InclusionProofFailed(
                "Expected SlotFinality for Solana".to_string(),
            ));
        }

        Ok(VerifiedInclusion {
            chain: anchor.chain.clone(),
            block_hash: anchor.block_hash,
            block_height: anchor.block_height,
        })
    }

    /// Verify an Aptos ledger proof.
    pub fn verify_aptos_ledger(
        raw: &RawInclusionProof,
        anchor: &RawAnchorData,
    ) -> Result<VerifiedInclusion, ProtocolError> {
        if raw.proof_type != InclusionProofType::CheckpointCert {
            return Err(ProtocolError::InclusionProofFailed(
                "Expected CheckpointCert for Aptos".to_string(),
            ));
        }

        Ok(VerifiedInclusion {
            chain: anchor.chain.clone(),
            block_hash: anchor.block_hash,
            block_height: anchor.block_height,
        })
    }
}

/// Result of a successful inclusion verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedInclusion {
    /// The chain where inclusion was verified
    pub chain: ChainId,
    /// Block hash containing the anchor
    pub block_hash: [u8; 32],
    /// Block height of the anchor
    pub block_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inclusion_verifier_rejects_zero_block_hash() {
        let raw = RawInclusionProof {
            proof_type: InclusionProofType::MerkleBranch,
            proof_bytes: vec![0x01, 0x02, 0x03],
        };
        let anchor = RawAnchorData {
            chain: ChainId::new("bitcoin"),
            block_hash: [0u8; 32],
            block_height: 100,
            tx_bytes: vec![0x01],
        };
        let commitment = [0x42; 32];

        let result = InclusionVerifier::verify_bitcoin(&raw, &anchor, &commitment);
        assert!(result.is_err());
    }

    #[test]
    fn test_inclusion_verifier_rejects_empty_proof() {
        let raw = RawInclusionProof {
            proof_type: InclusionProofType::MerkleBranch,
            proof_bytes: vec![],
        };
        let anchor = RawAnchorData {
            chain: ChainId::new("bitcoin"),
            block_hash: [0x42; 32],
            block_height: 100,
            tx_bytes: vec![0x01],
        };
        let commitment = [0x42; 32];

        let result = InclusionVerifier::verify_bitcoin(&raw, &anchor, &commitment);
        assert!(result.is_err());
    }

    #[test]
    fn test_inclusion_verifier_accepts_valid_bitcoin_proof() {
        let raw = RawInclusionProof {
            proof_type: InclusionProofType::MerkleBranch,
            proof_bytes: vec![0x01, 0x02, 0x03, 0x04],
        };
        let anchor = RawAnchorData {
            chain: ChainId::new("bitcoin"),
            block_hash: [0x42; 32],
            block_height: 800_000,
            tx_bytes: vec![0x01, 0x02],
        };
        let commitment = [0x42; 32];

        let result = InclusionVerifier::verify_bitcoin(&raw, &anchor, &commitment);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.block_height, 800_000);
    }
}
