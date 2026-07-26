//! Isolated cryptographic verification of Sui source closure.
//!
//! Inclusion is re-derived from bytes: the closure record is hashed, located in
//! the checkpoint contents, and the contents are hashed and matched against the
//! summary's content digest, whose own digest must equal the checkpoint the
//! caller named. Nothing is accepted on an RPC's word.
//!
//! Finality is deliberately **not** derived from inclusion. See
//! [`finality_for_trust_mode`] for why an `RpcQuorum` verdict cannot be
//! `Satisfied` here.

use async_trait::async_trait;
use csv_chain_ports::{
    AdapterError, AdapterResult, ChainInclusion, ClosureProofVerifier, CommitmentChain,
    checkpoint_chain::encode_entries, verify_commitment_chain,
};
use csv_protocol::{
    ClosureDimensionStatus, ClosureProof, ClosureProofKind, ClosureTrustMode,
    ClosureVerificationResult, FinalityPolicy, FinalizedCheckpoint, SourceNullifier,
};

use crate::closure::{
    SUI_CHAIN_ID, SUI_CLOSURE_PROOF_KIND, SUI_CLOSURE_VERIFIER_ID, SuiClosureDeployment,
    SuiClosureMaterial, sui_digest,
};

/// Everything needed to verify one Sui closure against one checkpoint.
pub struct SuiClosureVerificationInput<'a> {
    /// The closure proof under evaluation.
    pub proof: &'a ClosureProof,
    /// Deployment the proof must belong to.
    pub deployment: &'a SuiClosureDeployment,
    /// Exact checkpoint and finality policy being evaluated.
    pub checkpoint: &'a FinalizedCheckpoint,
    /// Highest checkpoint sequence the provider reports as certified.
    pub observed_certified_sequence: u64,
    /// Optional maximum checkpoint age, in sequence numbers.
    pub max_checkpoint_age: Option<u64>,
    /// Stable proof-material provider identifier.
    pub proof_provider_id: &'a str,
    /// Trust anchor used to obtain the checkpoint.
    pub trust_mode: ClosureTrustMode,
}

/// What a given trust mode can establish about Sui checkpoint finality.
///
/// Sui checkpoints are certified by a BLS aggregate signature over 2f+1 stake.
/// Recomputing that requires the epoch's validator committee, which a bare RPC
/// response does not provide — an RPC saying "certified" is a claim, not a
/// proof, and a malicious or compromised endpoint can make it freely.
///
/// So:
/// - `FullNode` / `LightClient` — the caller validated consensus itself or holds
///   a verified committee checkpoint: finality can be `Satisfied`.
/// - `RpcQuorum` / `AttestedRegistry` — agreement or attestation, not
///   recomputation: `Indeterminate`, never `Satisfied`.
///
/// Returning `Indeterminate` is the honest answer, and it propagates into
/// `source_closure`, so a recipient behind an RPC quorum is told the closure is
/// unproven rather than shown a fabricated success.
pub fn finality_for_trust_mode(
    trust_mode: ClosureTrustMode,
    certified: bool,
) -> ClosureDimensionStatus {
    match trust_mode {
        ClosureTrustMode::FullNode | ClosureTrustMode::LightClient => {
            if certified {
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

/// Verify object consumption, successor binding, inclusion, and finality.
pub fn verify_sui_closure(
    input: SuiClosureVerificationInput<'_>,
) -> Result<ClosureVerificationResult, SuiClosureVerificationError> {
    let SuiClosureVerificationInput {
        proof,
        deployment,
        checkpoint,
        observed_certified_sequence,
        max_checkpoint_age,
        proof_provider_id,
        trust_mode,
    } = input;

    proof
        .validate()
        .map_err(|_| SuiClosureVerificationError::MalformedProofEnvelope)?;

    match &proof.proof_kind {
        ClosureProofKind::ChainSpecific(name) if name == SUI_CLOSURE_PROOF_KIND => {}
        _ => return Err(SuiClosureVerificationError::WrongProofKind),
    }

    if checkpoint.chain_id != SUI_CHAIN_ID || checkpoint.network_id != deployment.network_id {
        return Err(SuiClosureVerificationError::WrongNetwork);
    }

    let material = SuiClosureMaterial::decode(&proof.proof_material)
        .map_err(|_| SuiClosureVerificationError::MalformedProofMaterial)?;

    if material.record.package_id != deployment.package_id {
        return Err(SuiClosureVerificationError::WrongDeployment);
    }

    // The checkpoint the caller named must be the one the summary describes.
    let summary_digest = material.summary.digest();
    if checkpoint.block_id.as_slice() != summary_digest.as_slice() {
        return Err(SuiClosureVerificationError::WrongCheckpointDigest);
    }
    if checkpoint.block_height != material.summary.sequence_number {
        return Err(SuiClosureVerificationError::WrongCheckpoint);
    }

    // The record must carry the identity and binding this proof claims.
    let nullifier = SourceNullifier::derive(&proof.consumed_state);
    let binding = deployment.expected_binding(&proof.consumed_state, &proof.successor_commitment);
    let record_matches = material.record.nullifier == *nullifier.as_bytes()
        && material.record.binding == *binding.as_bytes();

    let contents_bytes = encode_entries(&material.checkpoint_contents);
    let summary_bytes = material.summary.canonical_bytes();
    let record_bytes = material.record.canonical_bytes();
    let inclusion = verify_commitment_chain(
        &CommitmentChain {
            record_bytes: &record_bytes,
            batch_bytes: &contents_bytes,
            batch_entries: &material.checkpoint_contents,
            checkpoint_batch_digest: material.summary.content_digest,
            checkpoint_digest: summary_digest,
            checkpoint_summary_bytes: &summary_bytes,
        },
        sui_digest,
    );

    // A record that is included but names another source or successor does not
    // prove *this* closure, so both conditions are required.
    let proof_validity = match (record_matches, inclusion) {
        (true, ChainInclusion::Included { .. }) => ClosureDimensionStatus::Satisfied,
        _ => ClosureDimensionStatus::Failed,
    };

    let certified = match &checkpoint.finality_policy {
        FinalityPolicy::Deterministic(name) if name == "validator-certified" => {
            checkpoint.block_height <= observed_certified_sequence
        }
        FinalityPolicy::Confirmations(required) if *required > 0 => {
            let depth = observed_certified_sequence
                .checked_sub(checkpoint.block_height)
                .map(|d| d + 1)
                .unwrap_or(0);
            depth >= u64::from(*required)
        }
        _ => return Err(SuiClosureVerificationError::UnsupportedFinalityPolicy),
    };
    let checkpoint_finality = finality_for_trust_mode(trust_mode, certified);

    let checkpoint_freshness = match max_checkpoint_age {
        Some(max_age) => {
            let age = observed_certified_sequence.saturating_sub(checkpoint.block_height);
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
            "SUI.CLOSURE.VERIFIED"
        }
        (ClosureDimensionStatus::Failed, _) => "SUI.CLOSURE.RECORD_NOT_COMMITTED",
        (_, ClosureDimensionStatus::Indeterminate) => "SUI.FINALITY.TRUST_MODE_CANNOT_ESTABLISH",
        _ => "SUI.FINALITY.NOT_CERTIFIED",
    };

    Ok(ClosureVerificationResult {
        chain_id: SUI_CHAIN_ID.to_string(),
        network_id: deployment.network_id.clone(),
        proof_kind: ClosureProofKind::ChainSpecific(SUI_CLOSURE_PROOF_KIND.to_string()),
        checkpoint: checkpoint.clone(),
        proof_validity,
        checkpoint_finality,
        checkpoint_freshness,
        source_closure,
        trust_mode,
        verifier_id: SUI_CLOSURE_VERIFIER_ID.to_string(),
        proof_provider_id: proof_provider_id.to_string(),
        reason_codes: vec![reason.to_string()],
    })
}

/// Adapter binding: verifies against one configured Sui deployment.
pub struct SuiClosureProofVerifier {
    deployment: SuiClosureDeployment,
    observed_certified_sequence: u64,
    max_checkpoint_age: Option<u64>,
    proof_provider_id: String,
    trust_mode: ClosureTrustMode,
}

impl SuiClosureProofVerifier {
    /// Bind a verifier to one deployment, provider, and trust anchor.
    pub fn new(
        deployment: SuiClosureDeployment,
        observed_certified_sequence: u64,
        max_checkpoint_age: Option<u64>,
        proof_provider_id: impl Into<String>,
        trust_mode: ClosureTrustMode,
    ) -> Self {
        Self {
            deployment,
            observed_certified_sequence,
            max_checkpoint_age,
            proof_provider_id: proof_provider_id.into(),
            trust_mode,
        }
    }
}

#[async_trait]
impl ClosureProofVerifier for SuiClosureProofVerifier {
    async fn verify_closure(
        &self,
        proof: &ClosureProof,
        checkpoint: &FinalizedCheckpoint,
    ) -> AdapterResult<ClosureVerificationResult> {
        verify_sui_closure(SuiClosureVerificationInput {
            proof,
            deployment: &self.deployment,
            checkpoint,
            observed_certified_sequence: self.observed_certified_sequence,
            max_checkpoint_age: self.max_checkpoint_age,
            proof_provider_id: &self.proof_provider_id,
            trust_mode: self.trust_mode,
        })
        .map_err(|error| AdapterError::ProofVerificationFailed(error.to_string()))
    }
}

/// Why a Sui closure could not be evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SuiClosureVerificationError {
    /// The chain-neutral envelope is invalid.
    #[error("Sui closure proof envelope is malformed")]
    MalformedProofEnvelope,
    /// The proof belongs to another proof family.
    #[error("closure proof is not a Sui object-consumption proof")]
    WrongProofKind,
    /// Proof material could not be decoded.
    #[error("Sui closure proof material is malformed")]
    MalformedProofMaterial,
    /// The record was produced by another package.
    #[error("Sui closure record belongs to a different deployment")]
    WrongDeployment,
    /// Checkpoint names another chain or network.
    #[error("Sui closure checkpoint is for a different chain or network")]
    WrongNetwork,
    /// The summary does not hash to the checkpoint identity.
    #[error("Sui closure summary does not match the checkpoint digest")]
    WrongCheckpointDigest,
    /// The summary sequence does not match the checkpoint height.
    #[error("Sui closure checkpoint sequence does not match the summary")]
    WrongCheckpoint,
    /// The checkpoint names a finality policy this adapter does not implement.
    #[error("Sui closure finality policy is unsupported")]
    UnsupportedFinalityPolicy,
}
