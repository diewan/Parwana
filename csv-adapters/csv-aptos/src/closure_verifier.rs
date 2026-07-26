//! Isolated cryptographic verification of Aptos source closure.
//!
//! Inclusion is re-derived from bytes: the record is hashed, located in the
//! transaction accumulator, and the accumulator is hashed and matched against
//! the ledger info's committed root, whose own digest must equal the checkpoint
//! the caller named.
//!
//! Finality is reported from the caller's trust mode rather than inferred from
//! inclusion — see [`finality_for_trust_mode`].

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
    APTOS_CHAIN_ID, APTOS_CLOSURE_PROOF_KIND, APTOS_CLOSURE_VERIFIER_ID, AptosClosureDeployment,
    AptosClosureMaterial, aptos_digest,
};

/// Everything needed to verify one Aptos closure against one checkpoint.
pub struct AptosClosureVerificationInput<'a> {
    /// The closure proof under evaluation.
    pub proof: &'a ClosureProof,
    /// Deployment the proof must belong to.
    pub deployment: &'a AptosClosureDeployment,
    /// Exact checkpoint and finality policy being evaluated.
    pub checkpoint: &'a FinalizedCheckpoint,
    /// Highest ledger version the provider reports as committed.
    pub observed_committed_version: u64,
    /// Optional maximum checkpoint age, in ledger versions.
    pub max_checkpoint_age: Option<u64>,
    /// Stable proof-material provider identifier.
    pub proof_provider_id: &'a str,
    /// Trust anchor used to obtain the ledger info.
    pub trust_mode: ClosureTrustMode,
}

/// What a given trust mode can establish about Aptos ledger finality.
///
/// An Aptos ledger info is final because a validator set signed it with a BLS
/// aggregate over 2f+1 stake. Recomputing that needs the epoch's validator set,
/// which a REST response does not supply. A node's own `committed` claim is a
/// claim, not a proof.
///
/// `FullNode` and `LightClient` can therefore establish finality; `RpcQuorum`
/// and `AttestedRegistry` return `Indeterminate` and never `Satisfied`.
pub fn finality_for_trust_mode(
    trust_mode: ClosureTrustMode,
    committed: bool,
) -> ClosureDimensionStatus {
    match trust_mode {
        ClosureTrustMode::FullNode | ClosureTrustMode::LightClient => {
            if committed {
                ClosureDimensionStatus::Satisfied
            } else {
                ClosureDimensionStatus::Failed
            }
        }
        ClosureTrustMode::RpcQuorum | ClosureTrustMode::AttestedRegistry => {
            ClosureDimensionStatus::Indeterminate
        }
    }
}

/// Verify resource registration, successor binding, inclusion, and finality.
pub fn verify_aptos_closure(
    input: AptosClosureVerificationInput<'_>,
) -> Result<ClosureVerificationResult, AptosClosureVerificationError> {
    let AptosClosureVerificationInput {
        proof,
        deployment,
        checkpoint,
        observed_committed_version,
        max_checkpoint_age,
        proof_provider_id,
        trust_mode,
    } = input;

    proof
        .validate()
        .map_err(|_| AptosClosureVerificationError::MalformedProofEnvelope)?;

    match &proof.proof_kind {
        ClosureProofKind::ChainSpecific(name) if name == APTOS_CLOSURE_PROOF_KIND => {}
        _ => return Err(AptosClosureVerificationError::WrongProofKind),
    }

    if checkpoint.chain_id != APTOS_CHAIN_ID || checkpoint.network_id != deployment.network_id {
        return Err(AptosClosureVerificationError::WrongNetwork);
    }

    let material = AptosClosureMaterial::decode(&proof.proof_material)
        .map_err(|_| AptosClosureVerificationError::MalformedProofMaterial)?;

    if material.record.module_address != deployment.module_address {
        return Err(AptosClosureVerificationError::WrongDeployment);
    }

    let ledger_digest = material.ledger_info.digest();
    if checkpoint.block_id.as_slice() != ledger_digest.as_slice() {
        return Err(AptosClosureVerificationError::WrongCheckpointDigest);
    }
    if checkpoint.block_height != material.ledger_info.version {
        return Err(AptosClosureVerificationError::WrongCheckpoint);
    }

    let nullifier = SourceNullifier::derive(&proof.consumed_state);
    let binding = deployment.expected_binding(&proof.consumed_state, &proof.successor_commitment);
    let record_matches = material.record.nullifier == *nullifier.as_bytes()
        && material.record.binding == *binding.as_bytes();

    let accumulator_bytes = encode_entries(&material.accumulator_entries);
    let ledger_bytes = material.ledger_info.canonical_bytes();
    let record_bytes = material.record.canonical_bytes();
    let inclusion = verify_commitment_chain(
        &CommitmentChain {
            record_bytes: &record_bytes,
            batch_bytes: &accumulator_bytes,
            batch_entries: &material.accumulator_entries,
            checkpoint_batch_digest: material.ledger_info.accumulator_root,
            checkpoint_digest: ledger_digest,
            checkpoint_summary_bytes: &ledger_bytes,
        },
        aptos_digest,
    );

    let proof_validity = match (record_matches, inclusion) {
        (true, ChainInclusion::Included { .. }) => ClosureDimensionStatus::Satisfied,
        _ => ClosureDimensionStatus::Failed,
    };

    let committed = match &checkpoint.finality_policy {
        FinalityPolicy::Deterministic(name) if name == "validator-committed" => {
            checkpoint.block_height <= observed_committed_version
        }
        FinalityPolicy::Confirmations(required) if *required > 0 => {
            let depth = observed_committed_version
                .checked_sub(checkpoint.block_height)
                .map(|d| d + 1)
                .unwrap_or(0);
            depth >= u64::from(*required)
        }
        _ => return Err(AptosClosureVerificationError::UnsupportedFinalityPolicy),
    };
    let checkpoint_finality = finality_for_trust_mode(trust_mode, committed);

    let checkpoint_freshness = match max_checkpoint_age {
        Some(max_age) => {
            let age = observed_committed_version.saturating_sub(checkpoint.block_height);
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
            "APTOS.CLOSURE.VERIFIED"
        }
        (ClosureDimensionStatus::Failed, _) => "APTOS.CLOSURE.RECORD_NOT_COMMITTED",
        (_, ClosureDimensionStatus::Indeterminate) => "APTOS.FINALITY.TRUST_MODE_CANNOT_ESTABLISH",
        _ => "APTOS.FINALITY.NOT_COMMITTED",
    };

    Ok(ClosureVerificationResult {
        chain_id: APTOS_CHAIN_ID.to_string(),
        network_id: deployment.network_id.clone(),
        proof_kind: ClosureProofKind::ChainSpecific(APTOS_CLOSURE_PROOF_KIND.to_string()),
        checkpoint: checkpoint.clone(),
        proof_validity,
        checkpoint_finality,
        checkpoint_freshness,
        source_closure,
        trust_mode,
        verifier_id: APTOS_CLOSURE_VERIFIER_ID.to_string(),
        proof_provider_id: proof_provider_id.to_string(),
        reason_codes: vec![reason.to_string()],
    })
}

/// Adapter binding: verifies against one configured Aptos deployment.
pub struct AptosClosureProofVerifier {
    deployment: AptosClosureDeployment,
    observed_committed_version: u64,
    max_checkpoint_age: Option<u64>,
    proof_provider_id: String,
    trust_mode: ClosureTrustMode,
}

impl AptosClosureProofVerifier {
    /// Bind a verifier to one deployment, provider, and trust anchor.
    pub fn new(
        deployment: AptosClosureDeployment,
        observed_committed_version: u64,
        max_checkpoint_age: Option<u64>,
        proof_provider_id: impl Into<String>,
        trust_mode: ClosureTrustMode,
    ) -> Self {
        Self {
            deployment,
            observed_committed_version,
            max_checkpoint_age,
            proof_provider_id: proof_provider_id.into(),
            trust_mode,
        }
    }
}

#[async_trait]
impl ClosureProofVerifier for AptosClosureProofVerifier {
    async fn verify_closure(
        &self,
        proof: &ClosureProof,
        checkpoint: &FinalizedCheckpoint,
    ) -> AdapterResult<ClosureVerificationResult> {
        verify_aptos_closure(AptosClosureVerificationInput {
            proof,
            deployment: &self.deployment,
            checkpoint,
            observed_committed_version: self.observed_committed_version,
            max_checkpoint_age: self.max_checkpoint_age,
            proof_provider_id: &self.proof_provider_id,
            trust_mode: self.trust_mode,
        })
        .map_err(|error| AdapterError::ProofVerificationFailed(error.to_string()))
    }
}

/// Why an Aptos closure could not be evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AptosClosureVerificationError {
    /// The chain-neutral envelope is invalid.
    #[error("Aptos closure proof envelope is malformed")]
    MalformedProofEnvelope,
    /// The proof belongs to another proof family.
    #[error("closure proof is not an Aptos resource/nullifier proof")]
    WrongProofKind,
    /// Proof material could not be decoded.
    #[error("Aptos closure proof material is malformed")]
    MalformedProofMaterial,
    /// The record was written by another module deployment.
    #[error("Aptos closure record belongs to a different deployment")]
    WrongDeployment,
    /// Checkpoint names another chain or network.
    #[error("Aptos closure checkpoint is for a different chain or network")]
    WrongNetwork,
    /// The ledger info does not hash to the checkpoint identity.
    #[error("Aptos closure ledger info does not match the checkpoint digest")]
    WrongCheckpointDigest,
    /// The ledger version does not match the checkpoint height.
    #[error("Aptos closure checkpoint version does not match the ledger info")]
    WrongCheckpoint,
    /// The checkpoint names a finality policy this adapter does not implement.
    #[error("Aptos closure finality policy is unsupported")]
    UnsupportedFinalityPolicy,
}
