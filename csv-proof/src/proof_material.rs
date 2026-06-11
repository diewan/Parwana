//! Proof Material Provider trait — adapters become pure data providers.
//!
//! Per the audit: adapters should fetch proofs, headers, state roots, and
//! chain metadata. They should NOT decide final validity, authorize minting,
//! determine assurance thresholds, determine replay status, or decide rollback
//! necessity. Those belong to core/runtime.

use async_trait::async_trait;
use std::string::String;
use std::vec::Vec;

use crate::provenance::ProofProvenance;
use csv_hash::Hash;
use csv_protocol::proof_taxonomy::InclusionProof;

/// A bundle of proof material fetched from a chain.
///
/// Adapters produce this. Core/runtime verifies it.
#[derive(Debug, Clone)]
pub struct ProofMaterialBundle {
    /// The raw inclusion proof data.
    pub inclusion_proof: InclusionProof,
    /// The block hash for the inclusion proof.
    pub block_hash: Hash,
    /// The block height for the inclusion proof.
    pub block_height: u64,
    /// Chain metadata (state roots, headers, etc.).
    pub chain_metadata: Vec<u8>,
    /// Provenance of how this material was fetched.
    pub provenance: ProofProvenance,
}

/// Trait that chain adapters implement to provide proof material.
///
/// Adapters are pure data providers — they fetch from the chain but do NOT
/// make verification or policy decisions. The core proof pipeline decides
/// validity.
#[async_trait]
pub trait ProofMaterialProvider: Send + Sync {
    /// Fetch the proof material (inclusion proof + headers) for a given
    /// transaction at the given block height.
    async fn fetch_proof_material(
        &self,
        tx_hash: &[u8],
        block_height: u64,
    ) -> Result<ProofMaterialBundle, String>;

    /// Fetch the chain's current state root at a given block height.
    async fn fetch_state_root(&self, block_height: u64) -> Result<Hash, String>;

    /// Fetch the chain's current block header at a given height.
    async fn fetch_header(&self, block_height: u64) -> Result<Vec<u8>, String>;

    /// Fetch chain metadata (genesis, network id, chain id).
    async fn fetch_chain_metadata(&self) -> Result<Vec<u8>, String>;
}
