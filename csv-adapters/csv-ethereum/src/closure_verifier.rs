//! Isolated cryptographic verification of Ethereum source closure.
//!
//! Everything this module concludes is re-derived from the supplied bytes:
//! the block hash and state root come from the header, the storage value comes
//! from a Merkle-Patricia proof under that state root, and the expected value
//! comes from the consumed state and the configured deployment. No caller
//! assertion is trusted, and there is no boolean input that means "valid".
//!
//! The four dimensions of [`ClosureVerificationResult`] are reported
//! independently, because they fail independently:
//!
//! - `proof_validity` — the storage proof reconstructs to the header's state
//!   root and the slot holds the expected binding.
//! - `checkpoint_finality` — the checkpoint satisfies its own named policy.
//! - `checkpoint_freshness` — the checkpoint is recent enough for the caller's
//!   configured bound; `Indeterminate` when no bound was configured.
//! - `source_closure` — the source is closed in favour of this successor, which
//!   requires *both* a valid proof and a final checkpoint.
//!
//! A structurally valid proof under an unfinalized checkpoint is therefore
//! reported as a valid proof with indeterminate closure, never as success.

use alloy_primitives::{B256, Bytes};
use alloy_trie::{Nibbles, proof::verify_proof};
use async_trait::async_trait;
use csv_chain_ports::{AdapterError, AdapterResult, ClosureProofVerifier};
use csv_hash::Hash;
use csv_protocol::{
    ClosureDimensionStatus, ClosureProof, ClosureProofKind, ClosureTrustMode,
    ClosureVerificationResult, FinalityPolicy, FinalizedCheckpoint, SourceNullifier,
};

use crate::closure::{
    ETHEREUM_CHAIN_ID, ETHEREUM_CLOSURE_PROOF_KIND, ETHEREUM_CLOSURE_VERIFIER_ID,
    EthereumClosureMaterial, EthereumClosureRegistry, expected_binding, header_identity,
    storage_value_rlp,
};

/// What a given trust mode can establish about Ethereum checkpoint finality.
///
/// A Merkle-Patricia proof establishes "under state root `R`, slot `S` holds
/// `V`". It does **not** establish that `R` is the state root of a canonical,
/// finalized Ethereum block — and this verifier takes the header from the same
/// proof material, so an endpoint that fabricates a header, a state root, and a
/// matching trie produces something internally consistent.
///
/// Deciding that a header is canonical needs either a locally validated chain
/// (`FullNode`) or a beacon sync-committee light client (`LightClient`). An
/// `RpcQuorum` is agreement among endpoints, and an `AttestedRegistry` is a
/// signature over someone's claim; neither recomputes consensus, so both return
/// `Indeterminate`.
///
/// This mirrors the Sui, Aptos, and Solana adapters deliberately: inclusion is
/// cryptographic on all four, and canonicity is a trust-mode question on all
/// four. Ethereum having state proofs makes its *inclusion* evidence stronger,
/// not its *finality* evidence.
pub fn finality_for_trust_mode(
    trust_mode: ClosureTrustMode,
    final_by_policy: bool,
) -> ClosureDimensionStatus {
    match trust_mode {
        ClosureTrustMode::FullNode | ClosureTrustMode::LightClient => {
            if final_by_policy {
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

/// Everything needed to verify one Ethereum closure against one checkpoint.
pub struct EthereumClosureVerificationInput<'a> {
    /// The closure proof under evaluation.
    pub proof: &'a ClosureProof,
    /// Registry deployment the proof must belong to.
    pub registry: &'a EthereumClosureRegistry,
    /// Exact checkpoint and finality policy being evaluated.
    pub checkpoint: &'a FinalizedCheckpoint,
    /// Highest block the provider reports as finalized by consensus.
    pub observed_finalized_height: u64,
    /// Optional maximum checkpoint age, in blocks.
    pub max_checkpoint_age: Option<u64>,
    /// Stable proof-material provider identifier.
    pub proof_provider_id: &'a str,
    /// Trust anchor used to obtain the header and finalized height.
    pub trust_mode: ClosureTrustMode,
}

/// Verify nullifier registration, successor binding, inclusion, and finality.
pub fn verify_ethereum_closure(
    input: EthereumClosureVerificationInput<'_>,
) -> Result<ClosureVerificationResult, EthereumClosureVerificationError> {
    let EthereumClosureVerificationInput {
        proof,
        registry,
        checkpoint,
        observed_finalized_height,
        max_checkpoint_age,
        proof_provider_id,
        trust_mode,
    } = input;

    proof
        .validate()
        .map_err(|_| EthereumClosureVerificationError::MalformedProofEnvelope)?;

    // The proof family must be this one. A Bitcoin inclusion proof or another
    // chain's nullifier proof must not be read by this verifier at all.
    match &proof.proof_kind {
        ClosureProofKind::ChainSpecific(name) if name == ETHEREUM_CLOSURE_PROOF_KIND => {}
        _ => return Err(EthereumClosureVerificationError::WrongProofKind),
    }

    if checkpoint.chain_id != ETHEREUM_CHAIN_ID || checkpoint.network_id != registry.network_id {
        return Err(EthereumClosureVerificationError::WrongNetwork);
    }

    let material = EthereumClosureMaterial::decode(&proof.proof_material)
        .map_err(|_| EthereumClosureVerificationError::MalformedProofMaterial)?;

    // The proof must address the configured deployment. Without this, a proof
    // against an attacker-chosen contract would verify against its own state.
    if material.contract_address != registry.contract_address
        || material.mapping_slot != registry.mapping_slot
    {
        return Err(EthereumClosureVerificationError::WrongRegistry);
    }

    // Re-derive block identity from the header rather than trusting the
    // checkpoint's own claims about itself.
    let identity = header_identity(&material.block_header_rlp)
        .ok_or(EthereumClosureVerificationError::MalformedBlockHeader)?;
    if checkpoint.block_id.as_slice() != identity.block_hash.as_slice() {
        return Err(EthereumClosureVerificationError::WrongBlockHeader);
    }
    if checkpoint.block_height != identity.block_height {
        return Err(EthereumClosureVerificationError::WrongCheckpoint);
    }

    let nullifier = SourceNullifier::derive(&proof.consumed_state);
    let binding = expected_binding(registry, &proof.consumed_state, &proof.successor_commitment);
    let storage_key = registry.storage_key(&nullifier);

    let proof_validity = verify_binding_in_state(
        identity.state_root,
        &registry.contract_address,
        &material.account_proof,
        &storage_key,
        &material.storage_proof,
        &binding,
    );

    // Finality and freshness are checkpoint properties, evaluated separately
    // from whether the proof itself reconstructs.
    let final_by_policy = match &checkpoint.finality_policy {
        FinalityPolicy::Confirmations(required) if *required > 0 => {
            let confirmations = observed_finalized_height
                .checked_sub(checkpoint.block_height)
                .map(|depth| depth + 1)
                .unwrap_or(0);
            confirmations >= u64::from(*required)
        }
        // Post-merge Ethereum has a consensus notion of finalized: the
        // checkpoint must be at or below the reported finalized head.
        FinalityPolicy::Deterministic(name) if name == "beacon-finalized" => {
            checkpoint.block_height <= observed_finalized_height
        }
        _ => return Err(EthereumClosureVerificationError::UnsupportedFinalityPolicy),
    };
    let checkpoint_finality = finality_for_trust_mode(trust_mode, final_by_policy);

    let checkpoint_freshness = match max_checkpoint_age {
        Some(max_age) => {
            let age = observed_finalized_height.saturating_sub(checkpoint.block_height);
            if age <= max_age {
                ClosureDimensionStatus::Satisfied
            } else {
                ClosureDimensionStatus::Failed
            }
        }
        None => ClosureDimensionStatus::Indeterminate,
    };

    // Closure is the conjunction: a valid proof under a non-final checkpoint is
    // not closure, and a final checkpoint with an invalid proof is not closure.
    let source_closure = match (proof_validity, checkpoint_finality) {
        (ClosureDimensionStatus::Satisfied, ClosureDimensionStatus::Satisfied) => {
            ClosureDimensionStatus::Satisfied
        }
        (ClosureDimensionStatus::Failed, _) => ClosureDimensionStatus::Failed,
        _ => ClosureDimensionStatus::Indeterminate,
    };

    let reason = match (proof_validity, checkpoint_finality) {
        (ClosureDimensionStatus::Satisfied, ClosureDimensionStatus::Satisfied) => {
            "ETHEREUM.CLOSURE.VERIFIED"
        }
        (ClosureDimensionStatus::Failed, _) => "ETHEREUM.CLOSURE.BINDING_NOT_PROVEN",
        (_, ClosureDimensionStatus::Indeterminate) => {
            "ETHEREUM.FINALITY.TRUST_MODE_CANNOT_ESTABLISH"
        }
        _ => "ETHEREUM.FINALITY.INSUFFICIENT",
    };

    Ok(ClosureVerificationResult {
        chain_id: ETHEREUM_CHAIN_ID.to_string(),
        network_id: registry.network_id.clone(),
        proof_kind: ClosureProofKind::ChainSpecific(ETHEREUM_CLOSURE_PROOF_KIND.to_string()),
        checkpoint: checkpoint.clone(),
        proof_validity,
        checkpoint_finality,
        checkpoint_freshness,
        source_closure,
        trust_mode,
        verifier_id: ETHEREUM_CLOSURE_VERIFIER_ID.to_string(),
        proof_provider_id: proof_provider_id.to_string(),
        reason_codes: vec![reason.to_string()],
    })
}

/// Prove `storage[key] == binding` for `address` under `state_root`.
///
/// Two chained Merkle-Patricia proofs: state root → account (yielding the
/// account's storage root), then storage root → slot. The storage root is taken
/// from the *proven* account node, never from the caller.
fn verify_binding_in_state(
    state_root: B256,
    address: &[u8; 20],
    account_proof: &[Vec<u8>],
    storage_key: &[u8; 32],
    storage_proof: &[Vec<u8>],
    binding: &Hash,
) -> ClosureDimensionStatus {
    if account_proof.is_empty() || storage_proof.is_empty() {
        return ClosureDimensionStatus::Failed;
    }

    let account_nodes: Vec<Bytes> = account_proof
        .iter()
        .map(|node| Bytes::copy_from_slice(node))
        .collect();
    let storage_nodes: Vec<Bytes> = storage_proof
        .iter()
        .map(|node| Bytes::copy_from_slice(node))
        .collect();

    let account_key = alloy_primitives::keccak256(address);
    let account_rlp = match resolve_proven_value(state_root, account_key.as_slice(), &account_nodes)
    {
        Some(value) => value,
        None => return ClosureDimensionStatus::Failed,
    };

    let storage_root = match decode_account_storage_root(&account_rlp) {
        Some(root) => root,
        None => return ClosureDimensionStatus::Failed,
    };

    let slot_key = alloy_primitives::keccak256(storage_key);
    let expected = storage_value_rlp(binding);
    match verify_proof(
        storage_root,
        Nibbles::unpack(slot_key.as_slice()),
        Some(expected),
        &storage_nodes,
    ) {
        Ok(()) => ClosureDimensionStatus::Satisfied,
        Err(_) => ClosureDimensionStatus::Failed,
    }
}

/// Return the value proven at `key` under `root`, if the proof reconstructs.
///
/// The value is read out of the proof's terminal leaf and then re-verified
/// against the root, so a proof that reconstructs to a *different* value is
/// rejected rather than accepted for whatever it happens to contain.
fn resolve_proven_value(root: B256, key: &[u8], nodes: &[Bytes]) -> Option<Vec<u8>> {
    use alloy_rlp::Decodable;
    use alloy_trie::nodes::TrieNode;

    let nibbles = Nibbles::unpack(key);
    let terminal = nodes.last()?;
    let value = match TrieNode::decode(&mut &terminal[..]).ok()? {
        TrieNode::Leaf(leaf) => leaf.value,
        // A branch may carry the value in place when the key terminates there.
        TrieNode::Branch(_) | TrieNode::Extension(_) | TrieNode::EmptyRoot => return None,
    };
    verify_proof(root, nibbles, Some(value.clone()), nodes).ok()?;
    Some(value)
}

/// Extract `storage_root` from an RLP account: `[nonce, balance, root, code]`.
fn decode_account_storage_root(account_rlp: &[u8]) -> Option<B256> {
    use alloy_rlp::Decodable;
    let mut buf = account_rlp;
    let header = alloy_rlp::Header::decode(&mut buf).ok()?;
    if !header.list {
        return None;
    }
    let _nonce = u64::decode(&mut buf).ok()?;
    let _balance = alloy_primitives::U256::decode(&mut buf).ok()?;
    let storage_root = B256::decode(&mut buf).ok()?;
    Some(storage_root)
}

/// Adapter binding: verifies against one configured registry deployment.
pub struct EthereumClosureProofVerifier {
    registry: EthereumClosureRegistry,
    observed_finalized_height: u64,
    max_checkpoint_age: Option<u64>,
    proof_provider_id: String,
    trust_mode: ClosureTrustMode,
}

impl EthereumClosureProofVerifier {
    /// Bind a verifier to one registry, provider, and trust anchor.
    pub fn new(
        registry: EthereumClosureRegistry,
        observed_finalized_height: u64,
        max_checkpoint_age: Option<u64>,
        proof_provider_id: impl Into<String>,
        trust_mode: ClosureTrustMode,
    ) -> Self {
        Self {
            registry,
            observed_finalized_height,
            max_checkpoint_age,
            proof_provider_id: proof_provider_id.into(),
            trust_mode,
        }
    }
}

#[async_trait]
impl ClosureProofVerifier for EthereumClosureProofVerifier {
    async fn verify_closure(
        &self,
        proof: &ClosureProof,
        checkpoint: &FinalizedCheckpoint,
    ) -> AdapterResult<ClosureVerificationResult> {
        verify_ethereum_closure(EthereumClosureVerificationInput {
            proof,
            registry: &self.registry,
            checkpoint,
            observed_finalized_height: self.observed_finalized_height,
            max_checkpoint_age: self.max_checkpoint_age,
            proof_provider_id: &self.proof_provider_id,
            trust_mode: self.trust_mode,
        })
        .map_err(|error| AdapterError::ProofVerificationFailed(error.to_string()))
    }
}

/// Why an Ethereum closure could not be evaluated.
///
/// These are *evaluation* failures: the material could not be read as a proof
/// about this deployment and checkpoint at all. A proof that is well-formed but
/// wrong produces a [`ClosureVerificationResult`] with a failed dimension
/// instead, so "unreadable" and "disproven" are never conflated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EthereumClosureVerificationError {
    /// The chain-neutral envelope is invalid.
    #[error("Ethereum closure proof envelope is malformed")]
    MalformedProofEnvelope,
    /// The proof belongs to another proof family.
    #[error("closure proof is not an Ethereum nullifier storage proof")]
    WrongProofKind,
    /// Proof material could not be decoded.
    #[error("Ethereum closure proof material is malformed")]
    MalformedProofMaterial,
    /// The proof addresses another registry deployment.
    #[error("Ethereum closure proof addresses a different registry")]
    WrongRegistry,
    /// Checkpoint names another chain or network.
    #[error("Ethereum closure checkpoint is for a different chain or network")]
    WrongNetwork,
    /// The header did not decode.
    #[error("Ethereum closure block header is malformed")]
    MalformedBlockHeader,
    /// The header does not hash to the checkpoint block identity.
    #[error("Ethereum closure block header does not match the checkpoint")]
    WrongBlockHeader,
    /// The header height does not match the checkpoint height.
    #[error("Ethereum closure checkpoint height does not match the header")]
    WrongCheckpoint,
    /// The checkpoint names a finality policy this adapter does not implement.
    #[error("Ethereum closure finality policy is unsupported")]
    UnsupportedFinalityPolicy,
}
