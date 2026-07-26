//! Isolated cryptographic verification of Solana source closure.
//!
//! Inclusion is re-derived from bytes: the record is hashed, located in the
//! slot's entry list, and the entry list is hashed and matched against the bank
//! hash's committed digest, whose own digest must equal the checkpoint the
//! caller named.
//!
//! Finality is reported from the caller's trust mode. On Solana this is not a
//! conservative default but the only honest answer available — see
//! [`finality_for_trust_mode`] and the module docs of [`crate::closure`].

use async_trait::async_trait;
use csv_chain_ports::{
    AdapterError, AdapterResult, ChainInclusion, ClosureProofVerifier, CommitmentChain,
    encode_entries, verify_commitment_chain,
};
use csv_protocol::{
    ClosureDimensionStatus, ClosureProof, ClosureProofKind, ClosureTrustMode,
    ClosureVerificationResult, FinalityPolicy, FinalizedCheckpoint, SourceNullifier,
};

use crate::closure::{
    SOLANA_CHAIN_ID, SOLANA_CLOSURE_PROOF_KIND, SOLANA_CLOSURE_VERIFIER_ID,
    SolanaClosureDeployment, SolanaClosureMaterial, solana_digest,
};

/// Everything needed to verify one Solana closure against one checkpoint.
pub struct SolanaClosureVerificationInput<'a> {
    /// The closure proof under evaluation.
    pub proof: &'a ClosureProof,
    /// Deployment the proof must belong to.
    pub deployment: &'a SolanaClosureDeployment,
    /// Exact checkpoint and finality policy being evaluated.
    pub checkpoint: &'a FinalizedCheckpoint,
    /// Highest slot the provider reports as rooted.
    pub observed_rooted_slot: u64,
    /// Optional maximum checkpoint age, in slots.
    pub max_checkpoint_age: Option<u64>,
    /// Stable proof-material provider identifier.
    pub proof_provider_id: &'a str,
    /// Trust anchor used to obtain the bank hash.
    pub trust_mode: ClosureTrustMode,
}

/// What a given trust mode can establish about Solana slot finality.
///
/// Solana publishes no compact, signed artifact a recipient can verify offline:
/// there is no committee signature over a header to recompute and no Merkle path
/// from an account to consensus. A `finalized` commitment level returned by an
/// RPC endpoint is that endpoint's assertion.
///
/// Only `FullNode` — a caller replaying the ledger itself — can establish
/// finality. `LightClient` is deliberately **not** accepted here, because unlike
/// Sui and Aptos, Solana has no light-client construction to hold a verified
/// checkpoint with; accepting it would name a capability that does not exist.
/// Every other mode yields `Indeterminate`.
pub fn finality_for_trust_mode(
    trust_mode: ClosureTrustMode,
    rooted: bool,
) -> ClosureDimensionStatus {
    match trust_mode {
        ClosureTrustMode::FullNode => {
            if rooted {
                ClosureDimensionStatus::Satisfied
            } else {
                ClosureDimensionStatus::Failed
            }
        }
        ClosureTrustMode::LightClient
        | ClosureTrustMode::RpcQuorum
        | ClosureTrustMode::AttestedRegistry => ClosureDimensionStatus::Indeterminate,
    }
}

/// Verify account registration, successor binding, inclusion, and finality.
pub fn verify_solana_closure(
    input: SolanaClosureVerificationInput<'_>,
) -> Result<ClosureVerificationResult, SolanaClosureVerificationError> {
    let SolanaClosureVerificationInput {
        proof,
        deployment,
        checkpoint,
        observed_rooted_slot,
        max_checkpoint_age,
        proof_provider_id,
        trust_mode,
    } = input;

    proof
        .validate()
        .map_err(|_| SolanaClosureVerificationError::MalformedProofEnvelope)?;

    match &proof.proof_kind {
        ClosureProofKind::ChainSpecific(name) if name == SOLANA_CLOSURE_PROOF_KIND => {}
        _ => return Err(SolanaClosureVerificationError::WrongProofKind),
    }

    if checkpoint.chain_id != SOLANA_CHAIN_ID || checkpoint.network_id != deployment.network_id {
        return Err(SolanaClosureVerificationError::WrongNetwork);
    }

    let material = SolanaClosureMaterial::decode(&proof.proof_material)
        .map_err(|_| SolanaClosureVerificationError::MalformedProofMaterial)?;

    if material.record.program_id != deployment.program_id {
        return Err(SolanaClosureVerificationError::WrongDeployment);
    }

    let bank_digest = material.bank_hash.digest();
    if checkpoint.block_id.as_slice() != bank_digest.as_slice() {
        return Err(SolanaClosureVerificationError::WrongCheckpointDigest);
    }
    if checkpoint.block_height != material.bank_hash.slot {
        return Err(SolanaClosureVerificationError::WrongCheckpoint);
    }
    // The record must belong to the slot the bank hash commits, not a
    // neighbouring one.
    if material.record.slot != material.bank_hash.slot {
        return Err(SolanaClosureVerificationError::WrongSlot);
    }

    let nullifier = SourceNullifier::derive(&proof.consumed_state);
    let binding = deployment.expected_binding(&proof.consumed_state, &proof.successor_commitment);
    let record_matches = material.record.nullifier == *nullifier.as_bytes()
        && material.record.binding == *binding.as_bytes();

    let entries_bytes = encode_entries(&material.slot_entries);
    let bank_bytes = material.bank_hash.canonical_bytes();
    let record_bytes = material.record.canonical_bytes();
    let inclusion = verify_commitment_chain(
        &CommitmentChain {
            record_bytes: &record_bytes,
            batch_bytes: &entries_bytes,
            batch_entries: &material.slot_entries,
            checkpoint_batch_digest: material.bank_hash.entries_digest,
            checkpoint_digest: bank_digest,
            checkpoint_summary_bytes: &bank_bytes,
        },
        solana_digest,
    );

    let proof_validity = match (record_matches, inclusion) {
        (true, ChainInclusion::Included { .. }) => ClosureDimensionStatus::Satisfied,
        _ => ClosureDimensionStatus::Failed,
    };

    let rooted = match &checkpoint.finality_policy {
        FinalityPolicy::Deterministic(name) if name == "rooted-slot" => {
            checkpoint.block_height <= observed_rooted_slot
        }
        FinalityPolicy::Confirmations(required) if *required > 0 => {
            let depth = observed_rooted_slot
                .checked_sub(checkpoint.block_height)
                .map(|d| d + 1)
                .unwrap_or(0);
            depth >= u64::from(*required)
        }
        _ => return Err(SolanaClosureVerificationError::UnsupportedFinalityPolicy),
    };
    let checkpoint_finality = finality_for_trust_mode(trust_mode, rooted);

    let checkpoint_freshness = match max_checkpoint_age {
        Some(max_age) => {
            let age = observed_rooted_slot.saturating_sub(checkpoint.block_height);
            if age <= max_age {
                ClosureDimensionStatus::Satisfied
            } else {
                ClosureDimensionStatus::Failed
            }
        }
        None => ClosureDimensionStatus::Indeterminate,
    };

    let source_closure = match (proof_validity, checkpoint_finality) {
        (ClosureDimensionStatus::Satisfied, ClosureDimensionStatus::Satisfied) => {
            ClosureDimensionStatus::Satisfied
        }
        (ClosureDimensionStatus::Failed, _) => ClosureDimensionStatus::Failed,
        _ => ClosureDimensionStatus::Indeterminate,
    };

    let reason = match (proof_validity, checkpoint_finality) {
        (ClosureDimensionStatus::Satisfied, ClosureDimensionStatus::Satisfied) => {
            "SOLANA.CLOSURE.VERIFIED"
        }
        (ClosureDimensionStatus::Failed, _) => "SOLANA.CLOSURE.RECORD_NOT_COMMITTED",
        (_, ClosureDimensionStatus::Indeterminate) => "SOLANA.FINALITY.TRUST_MODE_CANNOT_ESTABLISH",
        _ => "SOLANA.FINALITY.NOT_ROOTED",
    };

    Ok(ClosureVerificationResult {
        chain_id: SOLANA_CHAIN_ID.to_string(),
        network_id: deployment.network_id.clone(),
        proof_kind: ClosureProofKind::ChainSpecific(SOLANA_CLOSURE_PROOF_KIND.to_string()),
        checkpoint: checkpoint.clone(),
        proof_validity,
        checkpoint_finality,
        checkpoint_freshness,
        source_closure,
        trust_mode,
        verifier_id: SOLANA_CLOSURE_VERIFIER_ID.to_string(),
        proof_provider_id: proof_provider_id.to_string(),
        reason_codes: vec![reason.to_string()],
    })
}

/// Adapter binding: verifies against one configured Solana deployment.
pub struct SolanaClosureProofVerifier {
    deployment: SolanaClosureDeployment,
    observed_rooted_slot: u64,
    max_checkpoint_age: Option<u64>,
    proof_provider_id: String,
    trust_mode: ClosureTrustMode,
}

impl SolanaClosureProofVerifier {
    /// Bind a verifier to one deployment, provider, and trust anchor.
    pub fn new(
        deployment: SolanaClosureDeployment,
        observed_rooted_slot: u64,
        max_checkpoint_age: Option<u64>,
        proof_provider_id: impl Into<String>,
        trust_mode: ClosureTrustMode,
    ) -> Self {
        Self {
            deployment,
            observed_rooted_slot,
            max_checkpoint_age,
            proof_provider_id: proof_provider_id.into(),
            trust_mode,
        }
    }
}

#[async_trait]
impl ClosureProofVerifier for SolanaClosureProofVerifier {
    async fn verify_closure(
        &self,
        proof: &ClosureProof,
        checkpoint: &FinalizedCheckpoint,
    ) -> AdapterResult<ClosureVerificationResult> {
        verify_solana_closure(SolanaClosureVerificationInput {
            proof,
            deployment: &self.deployment,
            checkpoint,
            observed_rooted_slot: self.observed_rooted_slot,
            max_checkpoint_age: self.max_checkpoint_age,
            proof_provider_id: &self.proof_provider_id,
            trust_mode: self.trust_mode,
        })
        .map_err(|error| AdapterError::ProofVerificationFailed(error.to_string()))
    }
}

/// Why a Solana closure could not be evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SolanaClosureVerificationError {
    /// The chain-neutral envelope is invalid.
    #[error("Solana closure proof envelope is malformed")]
    MalformedProofEnvelope,
    /// The proof belongs to another proof family.
    #[error("closure proof is not a Solana account/nullifier proof")]
    WrongProofKind,
    /// Proof material could not be decoded.
    #[error("Solana closure proof material is malformed")]
    MalformedProofMaterial,
    /// The record belongs to another program deployment.
    #[error("Solana closure record belongs to a different deployment")]
    WrongDeployment,
    /// Checkpoint names another chain or cluster.
    #[error("Solana closure checkpoint is for a different chain or cluster")]
    WrongNetwork,
    /// The bank hash does not hash to the checkpoint identity.
    #[error("Solana closure bank hash does not match the checkpoint digest")]
    WrongCheckpointDigest,
    /// The bank hash slot does not match the checkpoint height.
    #[error("Solana closure checkpoint slot does not match the bank hash")]
    WrongCheckpoint,
    /// The record was written in a different slot than the one committed.
    #[error("Solana closure record slot does not match the committed slot")]
    WrongSlot,
    /// The checkpoint names a finality policy this adapter does not implement.
    #[error("Solana closure finality policy is unsupported")]
    UnsupportedFinalityPolicy,
}
