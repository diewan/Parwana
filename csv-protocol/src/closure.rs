//! Chain-neutral source-closure proof and finalized-checkpoint interfaces.
//!
//! These types are the protocol boundary between an isolated verifier and a
//! chain adapter.  They carry proof material and provenance, never a
//! caller-supplied "proof valid" flag.  A chain-specific verifier must consume
//! [`ClosureProof::proof_material`] and return a [`ClosureVerificationResult`].

use csv_hash::{Hash, csv_tagged_hash};
use serde::{Deserialize, Serialize};

use crate::ConsumedStateRef;

/// Domain tag for a closure proof commitment.
pub const CLOSURE_PROOF_TAG: &str = "closure-proof-v2";
/// Domain tag for a finalized checkpoint commitment.
pub const FINALIZED_CHECKPOINT_TAG: &str = "finalized-checkpoint-v2";
/// Maximum chain-native proof material accepted at the protocol boundary.
pub const MAX_CLOSURE_PROOF_BYTES: usize = 4 * 1024 * 1024;

/// Proof family carried in [`ClosureProof`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureProofKind {
    /// A Bitcoin transaction, inclusion branch, and supporting headers.
    BitcoinTransactionInclusion,
    /// A chain-specific proof family identified by a stable protocol name.
    ChainSpecific(String),
}

/// A proof that a named state was closed in favour of one successor.
///
/// `proof_material` is deliberately opaque to `csv-protocol`: its canonical
/// transport encoding belongs to the wire/adapter layer and its interpretation
/// belongs to the adapter named by [`ClosureVerificationResult::verifier_id`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureProof {
    /// State whose unique successor is asserted.
    pub consumed_state: ConsumedStateRef,
    /// Canonical successor transition commitment.
    pub successor_commitment: Hash,
    /// Chain-native proof family.
    pub proof_kind: ClosureProofKind,
    /// Chain-native proof bytes consumed by the adapter verifier.
    pub proof_material: Vec<u8>,
}

impl ClosureProof {
    /// Validate the chain-neutral envelope, leaving native semantics to the adapter.
    pub fn validate(&self) -> Result<(), ClosureInterfaceError> {
        if self.successor_commitment == Hash::new([0; 32]) {
            return Err(ClosureInterfaceError::ZeroSuccessorCommitment);
        }
        if self.proof_material.is_empty() {
            return Err(ClosureInterfaceError::EmptyProofMaterial);
        }
        if self.proof_material.len() > MAX_CLOSURE_PROOF_BYTES {
            return Err(ClosureInterfaceError::ProofMaterialTooLarge);
        }
        if matches!(&self.proof_kind, ClosureProofKind::ChainSpecific(name) if name.is_empty()) {
            return Err(ClosureInterfaceError::EmptyProofKind);
        }
        Ok(())
    }

    /// Domain-separated commitment to the complete proof envelope.
    pub fn commitment(&self) -> Hash {
        Hash::new(csv_tagged_hash(CLOSURE_PROOF_TAG, &self.canonical_bytes()))
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, &self.consumed_state.to_canonical_bytes());
        out.extend_from_slice(self.successor_commitment.as_bytes());
        match &self.proof_kind {
            ClosureProofKind::BitcoinTransactionInclusion => out.push(1),
            ClosureProofKind::ChainSpecific(name) => {
                out.push(2);
                push_bytes(&mut out, name.as_bytes());
            }
        }
        push_bytes(&mut out, &self.proof_material);
        out
    }
}

/// Finality rule satisfied by a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityPolicy {
    /// Nakamoto-style confirmation depth.
    Confirmations(u32),
    /// A chain-native deterministic finality rule.
    Deterministic(String),
}

/// A chain checkpoint against which inclusion and finality were evaluated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedCheckpoint {
    /// Stable chain identifier, such as `bitcoin`.
    pub chain_id: String,
    /// Stable network identifier, such as `signet`.
    pub network_id: String,
    /// Height of the checkpoint block.
    pub block_height: u64,
    /// Native identity/hash of the checkpoint block.
    pub block_id: Vec<u8>,
    /// Exact finality rule this checkpoint satisfied.
    pub finality_policy: FinalityPolicy,
}

impl FinalizedCheckpoint {
    /// Validate fields that are common to every chain.
    pub fn validate(&self) -> Result<(), ClosureInterfaceError> {
        if self.chain_id.is_empty() {
            return Err(ClosureInterfaceError::EmptyChain);
        }
        if self.network_id.is_empty() {
            return Err(ClosureInterfaceError::EmptyNetwork);
        }
        if self.block_id.is_empty() {
            return Err(ClosureInterfaceError::EmptyBlockIdentity);
        }
        match &self.finality_policy {
            FinalityPolicy::Confirmations(0) => Err(ClosureInterfaceError::ZeroConfirmationPolicy),
            FinalityPolicy::Deterministic(name) if name.is_empty() => {
                Err(ClosureInterfaceError::EmptyFinalityPolicy)
            }
            _ => Ok(()),
        }
    }

    /// Domain-separated commitment to this exact checkpoint and policy.
    pub fn commitment(&self) -> Hash {
        Hash::new(csv_tagged_hash(
            FINALIZED_CHECKPOINT_TAG,
            &self.canonical_bytes(),
        ))
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, self.chain_id.as_bytes());
        push_bytes(&mut out, self.network_id.as_bytes());
        out.extend_from_slice(&self.block_height.to_le_bytes());
        push_bytes(&mut out, &self.block_id);
        match &self.finality_policy {
            FinalityPolicy::Confirmations(depth) => {
                out.push(1);
                out.extend_from_slice(&depth.to_le_bytes());
            }
            FinalityPolicy::Deterministic(name) => {
                out.push(2);
                push_bytes(&mut out, name.as_bytes());
            }
        }
        out
    }
}

/// Trust anchor used by the chain-native verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureTrustMode {
    /// Verification against a locally validated full-node chain view.
    FullNode,
    /// Verification from a pinned light-client checkpoint.
    LightClient,
    /// Agreement from a named quorum of independent RPC providers.
    RpcQuorum,
    /// A signature from a named registry; an attestation, not recomputation.
    AttestedRegistry,
}

/// Independently reported closure/finality dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureDimensionStatus {
    /// Cryptographic proof material satisfied this dimension.
    Satisfied,
    /// Proof material was checked and failed.
    Failed,
    /// The named trust mode cannot establish this dimension.
    Indeterminate,
}

/// Typed output of a chain-native closure verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureVerificationResult {
    /// Chain evaluated.
    pub chain_id: String,
    /// Network evaluated.
    pub network_id: String,
    /// Proof family consumed.
    pub proof_kind: ClosureProofKind,
    /// Exact checkpoint used.
    pub checkpoint: FinalizedCheckpoint,
    /// Whether native inclusion was established.
    pub proof_validity: ClosureDimensionStatus,
    /// Whether the checkpoint satisfies its named policy.
    pub checkpoint_finality: ClosureDimensionStatus,
    /// Whether the checkpoint is fresh under the verifier's configured bound.
    pub checkpoint_freshness: ClosureDimensionStatus,
    /// Whether the source is closed in favour of the supplied successor.
    pub source_closure: ClosureDimensionStatus,
    /// Trust anchor used for the conclusions.
    pub trust_mode: ClosureTrustMode,
    /// Stable identifier of the verifier implementation.
    pub verifier_id: String,
    /// Stable identifier of the proof-material provider.
    pub proof_provider_id: String,
    /// Stable machine-readable reason codes.
    pub reason_codes: Vec<String>,
}

impl ClosureVerificationResult {
    /// Validate provenance and prevent cross-chain/checkpoint confusion.
    pub fn validate(&self) -> Result<(), ClosureInterfaceError> {
        self.checkpoint.validate()?;
        if self.chain_id != self.checkpoint.chain_id {
            return Err(ClosureInterfaceError::CheckpointChainMismatch);
        }
        if self.network_id != self.checkpoint.network_id {
            return Err(ClosureInterfaceError::CheckpointNetworkMismatch);
        }
        if self.verifier_id.is_empty() {
            return Err(ClosureInterfaceError::EmptyVerifier);
        }
        if self.proof_provider_id.is_empty() {
            return Err(ClosureInterfaceError::EmptyProofProvider);
        }
        if self.reason_codes.is_empty() {
            return Err(ClosureInterfaceError::MissingReasonCode);
        }
        Ok(())
    }
}

/// Invalid chain-neutral closure boundary data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClosureInterfaceError {
    /// Successor commitments cannot use the zero sentinel.
    #[error("successor commitment is zero")]
    ZeroSuccessorCommitment,
    /// Native proof material is mandatory.
    #[error("closure proof material is empty")]
    EmptyProofMaterial,
    /// Native proof material exceeded the protocol bound.
    #[error("closure proof material exceeds the protocol bound")]
    ProofMaterialTooLarge,
    /// A custom proof family must be named.
    #[error("chain-specific proof kind is empty")]
    EmptyProofKind,
    /// Chain identifier is missing.
    #[error("checkpoint chain identifier is empty")]
    EmptyChain,
    /// Network identifier is missing.
    #[error("checkpoint network identifier is empty")]
    EmptyNetwork,
    /// Block identity is missing.
    #[error("checkpoint block identity is empty")]
    EmptyBlockIdentity,
    /// A confirmation policy must require at least one confirmation.
    #[error("checkpoint confirmation policy is zero")]
    ZeroConfirmationPolicy,
    /// A deterministic finality rule must be named.
    #[error("deterministic finality policy is empty")]
    EmptyFinalityPolicy,
    /// Result and checkpoint name different chains.
    #[error("result chain does not match checkpoint chain")]
    CheckpointChainMismatch,
    /// Result and checkpoint name different networks.
    #[error("result network does not match checkpoint network")]
    CheckpointNetworkMismatch,
    /// Verifier provenance is mandatory.
    #[error("closure verifier identifier is empty")]
    EmptyVerifier,
    /// Proof-provider provenance is mandatory.
    #[error("closure proof provider identifier is empty")]
    EmptyProofProvider,
    /// Every conclusion needs a stable reason.
    #[error("closure verification result has no reason code")]
    MissingReasonCode,
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::StateTypeId;

    fn proof() -> ClosureProof {
        ClosureProof {
            consumed_state: ConsumedStateRef::new(Hash::new([1; 32]), 3, 7),
            successor_commitment: Hash::new([2; 32]),
            proof_kind: ClosureProofKind::BitcoinTransactionInclusion,
            proof_material: vec![3, 4, 5],
        }
    }

    #[test]
    fn random_nonempty_material_is_not_a_verification_result() {
        let proof = proof();
        assert!(proof.validate().is_ok());
        // The envelope can only commit to material; it has no validity/status field.
        assert_ne!(proof.commitment(), Hash::new([0; 32]));
    }

    #[test]
    fn commitments_cover_every_security_relevant_field() {
        let original = proof();
        let mut changed = original.clone();
        changed.successor_commitment = Hash::new([9; 32]);
        assert_ne!(original.commitment(), changed.commitment());
        changed = original.clone();
        changed.proof_material.push(9);
        assert_ne!(original.commitment(), changed.commitment());
    }

    #[test]
    fn checkpoint_commitment_covers_network_and_policy() {
        let original = FinalizedCheckpoint {
            chain_id: "bitcoin".into(),
            network_id: "signet".into(),
            block_height: 100,
            block_id: vec![7; 32],
            finality_policy: FinalityPolicy::Confirmations(6),
        };
        let mut changed = original.clone();
        changed.network_id = "mainnet".into();
        assert_ne!(original.commitment(), changed.commitment());
        changed = original.clone();
        changed.finality_policy = FinalityPolicy::Confirmations(7);
        assert_ne!(original.commitment(), changed.commitment());
    }
}
