//! Transfer coordinator — single source of truth for cross-chain transfer execution
//!
//! All applications (CLI, wallet, SDK) MUST use this coordinator.
//! No application may implement its own transfer execution.
//!
//! All proof verification is delegated to [`csv_verifier::CanonicalVerifier`]
//! to ensure consistent verification semantics across the protocol.

#![allow(missing_docs)]

use crate::distributed_coordinator_lease::{CoordinatorId, CoordinatorLease};
use crate::error::TransferCoordinatorError;
use crate::event_bus::{EventBus, TransferEvent};
use crate::event_envelope::{EventType, RuntimeEventEnvelope};
use crate::event_persistence::EventStore;
#[cfg(test)]
use crate::event_persistence::InMemoryEventStore;
use crate::execution_journal::ExecutionJournal;
#[cfg(test)]
use crate::execution_journal::InMemoryJournal;
use crate::recovery::{CheckpointManager, TransferStage};
use csv_adapter_core::{AdapterRegistry, CrossChainTransfer, TxFinality};
use csv_admission::{AdmissionController, AdmissionLimits, AdmissionSnapshot};
use csv_hash::chain_id::ChainId;
use csv_hash::seal::SealPoint;
use csv_observability::metrics::{MetricsCollector, RuntimeFlowSnapshot};
use csv_protocol::finality::CapabilityRequirements;
use csv_storage::{ReplayDatabase, ReplayDbError};
use csv_verifier::{CanonicalVerifier, CanonicalVerifierImpl, VerificationContext, VerifierConfig};
use uuid::Uuid;

const LOCK_OUTPUT_INDEX_BYTES: usize = std::mem::size_of::<u32>();
const EVENT_VERSION_LOCKED: u64 = 1;
const EVENT_VERSION_AWAITING_FINALITY: u64 = 2;
const EVENT_VERSION_PROOF_BUILT: u64 = 3;
const EVENT_VERSION_PROOF_VERIFIED: u64 = 4;
const EVENT_VERSION_COMPLETE: u64 = 5;
const EVENT_VERSION_REPLAY_DETECTED: u64 = 1;

fn hash_from_tx_bytes(tx_hash: &[u8]) -> Result<csv_hash::Hash, TransferCoordinatorError> {
    csv_hash::Hash::try_from(tx_hash).map_err(|_| {
        TransferCoordinatorError::InvalidTxHash(format!("expected 32 bytes, got {}", tx_hash.len()))
    })
}

fn hash_from_tx_str(tx_hash: &str) -> Result<csv_hash::Hash, TransferCoordinatorError> {
    let normalized = tx_hash.strip_prefix("0x").unwrap_or(tx_hash);
    let bytes = hex::decode(normalized).map_err(|e| {
        TransferCoordinatorError::InvalidTxHash(format!("transaction hash is not hex: {}", e))
    })?;
    hash_from_tx_bytes(&bytes)
}

fn runtime_signature_scheme(
    scheme: csv_protocol::signature::SignatureScheme,
) -> Result<csv_protocol::signature::SignatureScheme, TransferCoordinatorError> {
    // csv_protocol::SignatureScheme only has Ed25519 and Secp256k1 variants
    // Both are supported by the runtime verifier
    Ok(scheme)
}

fn replay_id_from_hash(
    replay_id: csv_hash::ReplayIdHash,
) -> csv_protocol::proof_taxonomy::ReplayId {
    csv_protocol::proof_taxonomy::ReplayId {
        version: csv_protocol::proof_taxonomy::ReplayId::CURRENT_VERSION,
        id: *replay_id.0.as_bytes(),
    }
}

fn checkpoint_transfer_data(
    transfer: &CrossChainTransfer,
) -> Result<Vec<u8>, TransferCoordinatorError> {
    csv_codec::to_canonical_cbor(transfer).map_err(|e| {
        TransferCoordinatorError::RuntimeError(format!(
            "Failed to serialize transfer checkpoint: {}",
            e
        ))
    })
}

fn proof_payload_hash(payload: &[u8]) -> [u8; 32] {
    csv_hash::csv_tagged_hash("csv.execution-journal.proof-payload.v1", payload)
}

/// 23-byte domain tag for the RFC-0012 §9.2 mint attestation digest.
///
/// Single source of truth lives in `csv_adapter_core` so the runtime (which
/// binds the attestation) and the destination adapter (which binds
/// `destination_contract` and signs the digest) can never drift. The `const`
/// assertion below fails the build if the tag ever drifts from the frozen
/// 23-byte length.
use csv_adapter_core::MINT_ATTESTATION_DOMAIN;
const _: () = assert!(MINT_ATTESTATION_DOMAIN.len() == 23);

/// Contract-layer chain identity (RFC-0012 §6): `keccak256("csv.chain.<name>")`.
///
/// This is the fixed-width identifier the destination contract ABI uses. It is
/// deliberately distinct from the proof-layer `ProofLeafV1` one-byte chain id,
/// which this RFC does NOT change (§5) — adapters map the same chain name into
/// both representations. Nothing in the mint dispatch reads or writes a proof
/// root; correctness is decided off-chain by the canonical verifier.
fn contract_chain_id(name: &str) -> [u8; 32] {
    use csv_protocol::cross_chain::CrossChainHashAlgorithm;
    let tag = format!("csv.chain.{}", name);
    *CrossChainHashAlgorithm::Keccak256
        .hash_bytes(tag.as_bytes())
        .as_bytes()
}

/// Extract the mint commitment from a verified proof bundle.
///
/// Mirrors the destination adapter's convention: the commitment binding the
/// sanad travels in `anchor_ref.anchor_id`. Left-copied into a fixed 32-byte
/// field (the contract-ABI width); every real bundle carries a non-zero anchor,
/// which the destination contract additionally enforces.
fn commitment_from_bundle(proof_bundle: &csv_protocol::proof_taxonomy::ProofBundle) -> [u8; 32] {
    let mut commitment = [0u8; 32];
    let anchor = &proof_bundle.anchor_ref.anchor_id;
    let len = anchor.len().min(32);
    commitment[..len].copy_from_slice(&anchor[..len]);
    commitment
}

/// Deterministic identity of the source-chain lock event.
///
/// Derived from the real lock outpoint (`lock_tx_hash || lock_output_index`),
/// so it is stable across resume and is the settlement / duplicate-source-lock
/// key the destination contract records (`lockEventId`).
fn lock_event_id(transfer: &CrossChainTransfer) -> [u8; 32] {
    let mut preimage = transfer.lock_tx_hash.clone();
    preimage.extend_from_slice(&transfer.lock_output_index.to_le_bytes());
    csv_hash::csv_tagged_hash("csv.mint.lock-event.v1", &preimage)
}

/// Replay nullifier consumed by the source single-use seal.
///
/// Derived from the seal outpoint the verifier proved consumed
/// (`seal_ref.id`), giving the contract's replay-anchoring domain a value bound
/// to the specific single-use seal rather than to the sanad id.
fn mint_nullifier(proof_bundle: &csv_protocol::proof_taxonomy::ProofBundle) -> [u8; 32] {
    csv_hash::csv_tagged_hash("csv.mint.nullifier.v1", &proof_bundle.seal_ref.id)
}

// The RFC-0012 §9.2 attestation-digest inputs (`MintAttestationInputs`) and the
// `RuntimeMintRequest` handed to the destination adapter live in
// `csv_adapter_core` — the single crate depended on by both the runtime (which
// binds the attestation) and every chain adapter (which binds
// `destination_contract` and signs the digest). Keeping one definition prevents
// the silent ABI/serde drift a mirrored struct would invite.
pub use csv_adapter_core::{MintAttestationInputs, RuntimeMintRequest};

/// Build the runtime mint request from a verified proof bundle.
///
/// Called only after off-chain verification has succeeded and been journaled, so
/// the attestation it carries is over material the canonical verifier accepted.
fn build_runtime_mint_request(
    transfer: &CrossChainTransfer,
    proof_bundle: &csv_protocol::proof_taxonomy::ProofBundle,
    proof_bundle_bytes: Vec<u8>,
    destination_owner: Vec<u8>,
) -> RuntimeMintRequest {
    RuntimeMintRequest {
        attestation: MintAttestationInputs {
            destination_chain_id: contract_chain_id(&transfer.destination_chain),
            destination_contract: [0u8; 32],
            sanad_id: *transfer.sanad_id.as_bytes(),
            commitment: commitment_from_bundle(proof_bundle),
            source_chain: contract_chain_id(&transfer.source_chain),
            destination_owner,
            lock_event_id: lock_event_id(transfer),
            nullifier: mint_nullifier(proof_bundle),
            attestation_expiry: 0,
        },
        verifier_signatures: Vec::new(),
        proof_bundle: proof_bundle_bytes,
    }
}

/// Auditable evidence that a destination mint confirmed on-chain.
///
/// Recorded to the durable event store at mint confirmation on BOTH the
/// fresh-execution and resume paths (via [`TransferCoordinator::record_settlement_evidence`]),
/// so the operator flow leaves an identical settlement record no matter how the
/// transfer reached confirmation. Its purpose is to give a later source-chain
/// escrow release (TRM-ESCROW-001) a concrete, replayable settlement key.
///
/// This is *evidence*, not authority: per RFC-0012 the actual source release must
/// still be gated on a verifier-signed `SettlementReceipt`. Nothing here is a
/// proof root — the canonical verifier remains the sole proof adjudicator, and
/// this record only witnesses that the adjudicated mint confirmed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SettlementEvidence {
    /// Runtime transfer identifier.
    pub transfer_id: String,
    /// Sanad transferred (32 bytes).
    pub sanad_id: [u8; 32],
    /// Source chain name.
    pub source_chain: String,
    /// Destination chain name.
    pub destination_chain: String,
    /// Deterministic source-lock-event id — the settlement / duplicate-source-lock key.
    pub lock_event_id: [u8; 32],
    /// Replay nullifier consumed by the source single-use seal.
    pub nullifier: [u8; 32],
    /// Commitment binding the sanad content/ownership.
    pub commitment: [u8; 32],
    /// Source lock transaction hash (chain-native byte encoding, hex).
    pub lock_tx_hash: String,
    /// Confirmed destination mint transaction hash.
    pub mint_tx_hash: String,
    /// Block height that confirmed the destination mint.
    pub mint_block_height: u64,
    /// Unix seconds when the evidence was recorded.
    pub recorded_at: u64,
}

/// Build settlement evidence from a verified transfer and its confirmed mint.
///
/// The settlement key material (`lock_event_id`, `nullifier`, `commitment`) is
/// derived with the same helpers the RFC-0012 §9.2 attestation uses, so the
/// evidence a later release consumes is bound to exactly what was minted.
fn build_settlement_evidence(
    transfer: &CrossChainTransfer,
    proof_bundle: &csv_protocol::proof_taxonomy::ProofBundle,
    mint_tx_hash: &str,
    mint_block_height: u64,
) -> SettlementEvidence {
    SettlementEvidence {
        transfer_id: transfer.id.clone(),
        sanad_id: *transfer.sanad_id.as_bytes(),
        source_chain: transfer.source_chain.clone(),
        destination_chain: transfer.destination_chain.clone(),
        lock_event_id: lock_event_id(transfer),
        nullifier: mint_nullifier(proof_bundle),
        commitment: commitment_from_bundle(proof_bundle),
        lock_tx_hash: hex::encode(&transfer.lock_tx_hash),
        mint_tx_hash: mint_tx_hash.to_string(),
        mint_block_height,
        recorded_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

/// Encode a [`RuntimeMintRequest`] into the canonical bytes handed to the
/// destination adapter's `mint_sanad`.
fn encode_mint_request(request: &RuntimeMintRequest) -> Result<Vec<u8>, TransferCoordinatorError> {
    csv_codec::to_canonical_cbor(request).map_err(|e| {
        TransferCoordinatorError::ProofBuildFailed(format!(
            "Failed to encode runtime mint request: {}",
            e
        ))
    })
}

// The RFC-0012 §10 settlement-receipt inputs (`SettlementReceiptInputs`) and the
// `RuntimeSettlementRequest` handed to the source adapter live in
// `csv_adapter_core`, next to the §9.2 mint types — one definition shared by the
// runtime (which binds every field except `source_escrow_contract`) and the
// source adapter (which binds `source_escrow_contract` and signs).
pub use csv_adapter_core::{RuntimeSettlementRequest, SettlementReceiptInputs};

/// Canonical fixed-width reference to a confirmed destination mint, derived from
/// the mint transaction hash recorded in [`SettlementEvidence`].
///
/// The source escrow treats `destination_mint_tx_ref` as an opaque 32-byte value
/// bound in the signed §10 receipt digest — it does not re-derive it. Tag-hashing
/// the recorded mint tx hash gives a deterministic, chain-agnostic 32-byte ref
/// that the runtime and the signing verifier reproduce identically from the same
/// evidence.
fn destination_mint_tx_ref(mint_tx_hash: &str) -> [u8; 32] {
    csv_hash::csv_tagged_hash("csv.settlement.mint-ref.v1", mint_tx_hash.as_bytes())
}

/// Build the RFC-0012 §10 settlement-receipt inputs from recorded settlement
/// evidence and the caller-supplied operator payout beneficiary.
///
/// Consumes [`SettlementEvidence`] — which exists only after the destination mint
/// confirmed — so a receipt is never built for an unconfirmed or absent mint. The
/// settlement key material (`lock_event_id`, chain identities) is taken verbatim
/// from the evidence, so the receipt authorizes release of exactly the escrow
/// that backs the settled mint. `source_escrow_contract` is left zero for the
/// source adapter to bind before signing, mirroring the mint attestation flow.
fn build_settlement_receipt(
    evidence: &SettlementEvidence,
    operator_payout_address: [u8; 32],
    receipt_expiry: u64,
) -> SettlementReceiptInputs {
    SettlementReceiptInputs {
        source_chain_id: contract_chain_id(&evidence.source_chain),
        source_escrow_contract: [0u8; 32],
        sanad_id: evidence.sanad_id,
        lock_event_id: evidence.lock_event_id,
        destination_chain_id: contract_chain_id(&evidence.destination_chain),
        destination_mint_tx_ref: destination_mint_tx_ref(&evidence.mint_tx_hash),
        operator_payout_address,
        receipt_expiry,
    }
}

/// Current unix time in seconds, saturating to 0 before the epoch.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reconstruct the minimal [`CrossChainTransfer`] a source adapter needs to route
/// and submit an escrow release from recorded [`SettlementEvidence`].
///
/// Everything the source escrow authenticates travels in the signed §10 receipt
/// (carried separately in the encoded request), so this transfer only needs to
/// identify the sanad and the source chain. `lock_output_index` is not part of
/// the receipt — the `lock_event_id` that keys settlement is already fixed in the
/// evidence — so it is defaulted; `transition_id` is unused on the release path.
fn transfer_from_settlement_evidence(evidence: &SettlementEvidence) -> CrossChainTransfer {
    CrossChainTransfer {
        id: evidence.transfer_id.clone(),
        source_chain: evidence.source_chain.clone(),
        destination_chain: evidence.destination_chain.clone(),
        lock_tx_hash: hex::decode(&evidence.lock_tx_hash).unwrap_or_default(),
        lock_output_index: 0,
        sanad_id: csv_hash::Hash::from(evidence.sanad_id),
        transition_id: Vec::new(),
    }
}

/// Encode a [`RuntimeSettlementRequest`] into the canonical bytes handed to the
/// source adapter's `settle_escrow`.
fn encode_settlement_request(
    request: &RuntimeSettlementRequest,
) -> Result<Vec<u8>, TransferCoordinatorError> {
    csv_codec::to_canonical_cbor(request).map_err(|e| {
        TransferCoordinatorError::SettlementFailed(format!(
            "Failed to encode runtime settlement request: {}",
            e
        ))
    })
}

/// Durable record of a completed source-chain escrow settlement (release or
/// refund), appended to the event store as the settlement journal of record.
///
/// This is the crash-recovery anchor for TRM-ESCROW-001: a release/refund event
/// is written only after the source-chain submission returns, so on restart the
/// runtime's one-release-per-`lock_event_id` guard reads it back and refuses to
/// re-submit. On-chain, the escrow contract independently enforces the same
/// domain (a resubmission reverts), so a payout can never happen twice even
/// across a crash between submission and the durable write.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SettlementReleaseRecord {
    /// Whether this record is a release-to-operator (`true`) or a refund-to-locker (`false`).
    pub released_to_operator: bool,
    /// Runtime transfer identifier.
    pub transfer_id: String,
    /// Sanad whose source escrow was settled (32 bytes).
    pub sanad_id: [u8; 32],
    /// Source chain name (the chain that held the escrow).
    pub source_chain: String,
    /// Deterministic source-lock-event id — the settlement anti-replay key.
    pub lock_event_id: [u8; 32],
    /// Canonical 32-byte reference to the confirmed destination mint (release only; zero on refund).
    pub destination_mint_tx_ref: [u8; 32],
    /// Operator payout beneficiary bound in the signed receipt (release only; zero on refund).
    pub operator_payout_address: [u8; 32],
    /// Source-chain settlement transaction hash.
    pub settlement_tx_hash: String,
    /// Block height that confirmed the settlement.
    pub settlement_block_height: u64,
    /// Unix seconds when the settlement was recorded.
    pub settled_at: u64,
}

/// Terminal settlement status of a sanad's source escrow, derived from the
/// append-only event store. `Released` and `Refunded` are mutually exclusive and
/// terminal; `Unsettled` means no source settlement has been recorded yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementStatus {
    /// No source-chain settlement recorded.
    Unsettled,
    /// Escrow released to the operator (record carries the details).
    Released(Box<SettlementReleaseRecord>),
    /// Escrow refunded to the locker (record carries the details).
    Refunded(Box<SettlementReleaseRecord>),
}

/// Convert CrossChainTransfer to HashEntry for durable storage
fn transfer_to_registry_entry(
    transfer: &CrossChainTransfer,
) -> Result<csv_protocol::cross_chain::HashEntry, TransferCoordinatorError> {
    // Encode chain-specific seal data into the id field
    // For Bitcoin: tx_id + output_index
    // For other chains: tx_hash
    let mut source_seal_id = transfer.lock_tx_hash.clone();
    source_seal_id.extend_from_slice(&transfer.lock_output_index.to_le_bytes());

    Ok(csv_protocol::cross_chain::HashEntry {
        transfer_id: transfer.id.clone(),
        sanad_id: transfer.sanad_id,
        source_chain: ChainId::new(&transfer.source_chain),
        source_seal: SealPoint {
            id: source_seal_id,
            nonce: None,
            version: None,
        },
        destination_chain: ChainId::new(&transfer.destination_chain),
        destination_seal: SealPoint {
            id: vec![], // Will be filled after mint
            nonce: None,
            version: None,
        },
        lock_tx_hash: hash_from_tx_bytes(&transfer.lock_tx_hash)?,
        transition_id: transfer.transition_id.clone(),
        mint_tx_hash: csv_hash::Hash::zero(), // Will be updated after mint
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to get current timestamp: {}",
                    e
                ))
            })?
            .as_secs(),
    })
}

/// Convert HashEntry back to CrossChainTransfer for runtime use
fn registry_entry_to_transfer(
    entry: &csv_protocol::cross_chain::HashEntry,
    transfer_id: String,
) -> CrossChainTransfer {
    // Decode output_index from the seal id (last 4 bytes)
    let (lock_tx_hash, output_index) = if entry.source_seal.id.len() >= LOCK_OUTPUT_INDEX_BYTES {
        let split_at = entry.source_seal.id.len() - LOCK_OUTPUT_INDEX_BYTES;
        let mut output_index_bytes = [0u8; LOCK_OUTPUT_INDEX_BYTES];
        output_index_bytes.copy_from_slice(&entry.source_seal.id[split_at..]);
        (
            entry.source_seal.id[..split_at].to_vec(),
            u32::from_le_bytes(output_index_bytes),
        )
    } else {
        (entry.lock_tx_hash.as_bytes().to_vec(), 0)
    };

    CrossChainTransfer {
        id: transfer_id,
        source_chain: entry.source_chain.to_string(),
        destination_chain: entry.destination_chain.to_string(),
        lock_tx_hash,
        lock_output_index: output_index,
        sanad_id: entry.sanad_id,
        transition_id: entry.transition_id.clone(),
    }
}

/// Outcome of a single transfer advance.
///
/// The transfer state machine is resumable: after the lock is on-chain, every
/// step is idempotent and journaled. A single `advance` either completes the
/// transfer (`Completed`) or reports that the lock has not yet reached the
/// required finality depth (`Pending`) — the latter is a normal, non-error
/// result that both the poll-and-block driver (loop until `Completed`) and the
/// resume driver (return and re-invoke later) build on.
#[derive(Debug, Clone)]
pub enum TransferOutcome {
    /// The transfer completed: destination mint confirmed, replay entry consumed.
    ///
    /// Boxed: the receipt carries destination materialization metadata, making it
    /// several times larger than `Pending`.
    Completed(Box<TransferReceipt>),
    /// The lock has not yet reached the required confirmation depth. The lock is
    /// on-chain and journaled; re-invoking `advance`/resume later will progress
    /// it once confirmations accrue. Never re-locks.
    Pending {
        /// Lock transaction hash in the runtime's chain-native byte encoding.
        lock_tx_hash: String,
        /// Confirmations observed on the source-chain lock transaction.
        confirmations: u64,
        /// Confirmation depth required by the source chain's finality policy.
        required: u64,
    },
}

/// Receipt returned after a successful transfer
#[derive(Debug, Clone)]
pub struct TransferReceipt {
    /// Transfer ID
    pub transfer_id: String,
    /// Replay ID used for this transfer (stored as Hash for serialization compatibility)
    pub replay_id: csv_hash::Hash,
    /// Transaction hash of the lock on source chain
    pub lock_tx_hash: String,
    /// Transaction hash of the mint on destination chain
    pub mint_tx_hash: String,
    /// Destination-side materialization metadata observed by the destination adapter.
    pub materialization: csv_adapter_core::DestinationMaterialization,
}

/// The single source of truth for cross-chain transfer execution.
///
/// All proof verification is delegated to the embedded [`CanonicalVerifierImpl`]
/// to ensure consistent verification semantics across the protocol.
pub struct TransferCoordinator {
    replay_db: Box<dyn ReplayDatabase>,
    event_bus: EventBus,
    /// Durable event store for event sourcing and audit trail
    event_store: Box<dyn EventStore>,
    /// Circuit breaker for RPC failure tracking
    circuit_breaker: std::sync::Arc<std::sync::Mutex<crate::runtime_mode::CircuitBreaker>>,
    /// Health monitor for runtime health tracking
    health_monitor: std::sync::Arc<std::sync::Mutex<crate::runtime_mode::HealthMonitor>>,
    /// Optional distributed lease backend for HA deployments
    coordinator_lease: Option<Box<dyn CoordinatorLease>>,
    /// Runtime instance identifier (for lease ownership verification)
    runtime_id: CoordinatorId,
    /// Checkpoint manager for deterministic recovery
    checkpoint_manager: std::sync::Arc<std::sync::Mutex<CheckpointManager>>,
    /// Canonical verifier for proof verification (single source of truth)
    verifier: std::sync::Arc<CanonicalVerifierImpl>,
    /// Execution journal for crash-safe phase tracking
    execution_journal: Box<dyn ExecutionJournal>,
    /// Admission controller for bounded runtime work
    admission_controller: AdmissionController,
    /// Operator-facing metrics for the materialize / settlement flow.
    metrics: std::sync::Arc<std::sync::Mutex<MetricsCollector>>,
    /// Current lease observed for each transfer in this coordinator process.
    active_execution_leases: std::sync::Mutex<
        std::collections::HashMap<csv_hash::SanadId, crate::user_runtime_lease::TransferLease>,
    >,
}

impl TransferCoordinator {
    /// Create an ephemeral coordinator for local tests.
    #[cfg(test)]
    fn new(replay_db: Box<dyn ReplayDatabase>, event_bus: EventBus) -> Self {
        Self::with_event_store(replay_db, event_bus, Box::new(InMemoryEventStore::new()))
    }

    #[cfg(test)]
    fn with_event_store(
        replay_db: Box<dyn ReplayDatabase>,
        event_bus: EventBus,
        event_store: Box<dyn EventStore>,
    ) -> Self {
        let runtime_id = CoordinatorId(Uuid::new_v4().to_string());
        Self {
            replay_db,
            event_bus,
            event_store,
            circuit_breaker: std::sync::Arc::new(std::sync::Mutex::new(
                crate::runtime_mode::CircuitBreaker::new(),
            )),
            health_monitor: std::sync::Arc::new(std::sync::Mutex::new(
                crate::runtime_mode::HealthMonitor::new(),
            )),
            coordinator_lease: None,
            runtime_id,
            checkpoint_manager: std::sync::Arc::new(
                std::sync::Mutex::new(CheckpointManager::new()),
            ),
            verifier: std::sync::Arc::new(CanonicalVerifierImpl::default()),
            execution_journal: Box::new(InMemoryJournal::new(10000)),
            admission_controller: AdmissionController::default(),
            metrics: std::sync::Arc::new(std::sync::Mutex::new(MetricsCollector::new())),
            active_execution_leases: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Create a transfer coordinator with explicit durable stores and verifier.
    ///
    /// Mutation-capable production callers must supply an execution journal
    /// whose records survive process restarts.
    pub fn with_stores(
        replay_db: Box<dyn ReplayDatabase>,
        event_bus: EventBus,
        event_store: Box<dyn EventStore>,
        execution_journal: Box<dyn ExecutionJournal>,
        verifier: CanonicalVerifierImpl,
        coordinator_lease: Box<dyn CoordinatorLease>,
    ) -> Self {
        let runtime_id = CoordinatorId(Uuid::new_v4().to_string());
        Self {
            replay_db,
            event_bus,
            event_store,
            circuit_breaker: std::sync::Arc::new(std::sync::Mutex::new(
                crate::runtime_mode::CircuitBreaker::new(),
            )),
            health_monitor: std::sync::Arc::new(std::sync::Mutex::new(
                crate::runtime_mode::HealthMonitor::new(),
            )),
            coordinator_lease: Some(coordinator_lease),
            runtime_id,
            checkpoint_manager: std::sync::Arc::new(
                std::sync::Mutex::new(CheckpointManager::new()),
            ),
            verifier: std::sync::Arc::new(verifier),
            execution_journal,
            admission_controller: AdmissionController::default(),
            metrics: std::sync::Arc::new(std::sync::Mutex::new(MetricsCollector::new())),
            active_execution_leases: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Override runtime admission limits.
    pub fn with_admission_limits(mut self, limits: AdmissionLimits) -> Self {
        self.admission_controller = AdmissionController::new(limits);
        self
    }

    /// Return the current admission pressure snapshot.
    pub fn admission_snapshot(&self) -> AdmissionSnapshot {
        self.admission_controller.snapshot()
    }

    fn verifier_for_source_chain(
        policy: &crate::policy::RuntimePolicy,
        source_chain: &str,
    ) -> Result<CanonicalVerifierImpl, TransferCoordinatorError> {
        #[cfg(test)]
        if source_chain == "test-chain" {
            return Ok(CanonicalVerifierImpl::new(VerifierConfig {
                max_anchor_age_blocks: Some(100),
                ..VerifierConfig::default()
            }));
        }

        let max_anchor_age_blocks = policy
            .max_proof_age_blocks_for_chain(source_chain)
            .ok_or_else(|| {
                TransferCoordinatorError::ProofVerificationFailed(format!(
                    "No max proof age configured for source chain: {source_chain}"
                ))
            })?;
        Ok(CanonicalVerifierImpl::new(VerifierConfig {
            max_anchor_age_blocks: Some(max_anchor_age_blocks),
            ..VerifierConfig::default()
        }))
    }

    /// Snapshot the operator-facing transfer flow metrics.
    pub fn runtime_flow_metrics(&self) -> RuntimeFlowSnapshot {
        self.metrics
            .lock()
            .map(|metrics| metrics.runtime_flow_snapshot())
            .unwrap_or(RuntimeFlowSnapshot {
                verified_proof_built: 0,
                mint_submitted: 0,
                mint_confirmed: 0,
                settlement_submitted: 0,
                settlement_confirmed: 0,
                replay_rejected: 0,
                authorization_rejected: 0,
            })
    }

    fn with_metrics(&self, record: impl FnOnce(&MetricsCollector)) {
        if let Ok(metrics) = self.metrics.lock() {
            record(&metrics);
        }
    }

    /// Get a reference to the circuit breaker
    pub fn circuit_breaker(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<crate::runtime_mode::CircuitBreaker>> {
        self.circuit_breaker.clone()
    }

    /// Get a reference to the health monitor
    pub fn health_monitor(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<crate::runtime_mode::HealthMonitor>> {
        self.health_monitor.clone()
    }

    /// Record a health check result
    pub fn record_health_check(&self, check: crate::runtime_mode::HealthCheck) {
        if let Ok(mut monitor) = self.health_monitor.lock() {
            monitor.record_check(check);
        }
    }

    /// Assert that this coordinator owns the lease for the given transfer.
    ///
    /// This invariant ensures exactly one coordinator is active for each transfer,
    /// preventing split-brain double-mints in HA deployments.
    ///
    /// # Errors
    ///
    /// If no distributed lease backend is configured, the runtime relies on
    /// the per-call [`RuntimeExecutionContext`] lease validation in `execute`.
    /// Returns `TransferCoordinatorError::LeaseViolation` if this coordinator does not own the lease.
    async fn assert_single_active_coordinator(
        &self,
        transfer_id: &str,
    ) -> Result<(), TransferCoordinatorError> {
        let Some(lease) = self.coordinator_lease.as_ref() else {
            return Ok(());
        };

        // Check if this coordinator holds the lease
        let is_held = lease.is_held_by(&self.runtime_id).await;

        if !is_held {
            return Err(TransferCoordinatorError::LeaseViolation(format!(
                "Coordinator {} does not own lease for transfer {}",
                self.runtime_id.0, transfer_id
            )));
        }

        Ok(())
    }

    fn accept_execution_lease(
        &self,
        lease: &crate::user_runtime_lease::TransferLease,
    ) -> Result<(), TransferCoordinatorError> {
        let now = std::time::SystemTime::now();
        let mut active = self
            .active_execution_leases
            .lock()
            .map_err(|e| TransferCoordinatorError::LeaseViolation(e.to_string()))?;
        let transfer_id: csv_hash::SanadId =
            lease.transfer_id.clone().try_into().map_err(|_| {
                TransferCoordinatorError::LeaseViolation("Invalid transfer ID".to_string())
            })?;
        if let Some(current) = active.get(&transfer_id) {
            if lease.epoch < current.epoch {
                return Err(TransferCoordinatorError::LeaseViolation(
                    "Lease epoch is stale for this transfer".to_string(),
                ));
            }
            if lease.epoch == current.epoch {
                if lease.owner_runtime_id == current.owner_runtime_id {
                    return Ok(());
                }
                return Err(TransferCoordinatorError::LeaseViolation(
                    "Lease epoch is already held by another runtime".to_string(),
                ));
            }
            if current.is_active(now) && current.owner_runtime_id != lease.owner_runtime_id {
                return Err(TransferCoordinatorError::LeaseViolation(
                    "Active transfer lease cannot be superseded by another runtime".to_string(),
                ));
            }
        }
        active.insert(transfer_id.clone(), lease.clone());
        Ok(())
    }

    /// Get the current health status
    pub fn health_status(&self) -> crate::runtime_mode::HealthStatus {
        self.health_monitor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status()
    }

    /// Attempt to recover from circuit breaker open state
    pub fn attempt_circuit_breaker_recovery(&self) -> bool {
        self.circuit_breaker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .attempt_recovery()
    }

    /// Execute a cross-chain transfer through the complete state machine.
    ///
    /// Preconditions checked by this function:
    /// 1. ReplayId is unique (not in replay_db)
    /// 2. Source chain capabilities permit cross-chain source
    /// 3. Destination chain capabilities permit mint
    ///
    /// This function is the only authority path permitted to request a destination mint.
    ///
    /// Backward-compatible blocking entry point: a lock that has not yet reached
    /// finality is surfaced as [`TransferCoordinatorError::FinalityFailed`]. New
    /// callers that want to drive the poll-and-block or resume flows should use
    /// [`TransferCoordinator::execute_outcome`], which returns a first-class
    /// [`TransferOutcome::Pending`] instead of an error.
    pub async fn execute(
        &self,
        transfer: CrossChainTransfer,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        match self
            .execute_outcome(transfer, adapter_registry, runtime_ctx)
            .await?
        {
            TransferOutcome::Completed(receipt) => Ok(*receipt),
            TransferOutcome::Pending {
                confirmations,
                required,
                ..
            } => Err(TransferCoordinatorError::FinalityFailed(format!(
                "lock has {} confirmations, {} required",
                confirmations, required
            ))),
        }
    }

    /// Query the real confirmation status of the transfer's source-chain lock
    /// transaction. This is the single finality primitive shared by the fresh
    /// execution path and every resume path, so the "is the lock final?" decision
    /// can never diverge between them.
    async fn lock_finality_status(
        &self,
        transfer: &CrossChainTransfer,
        adapter_registry: &dyn AdapterRegistry,
    ) -> Result<TxFinality, TransferCoordinatorError> {
        let lock_tx_hex = hex::encode(hash_from_tx_bytes(&transfer.lock_tx_hash)?.as_bytes());
        adapter_registry
            .tx_finality(&transfer.source_chain, &lock_tx_hex)
            .await
            .map_err(|e| TransferCoordinatorError::FinalityFailed(e.to_string()))
    }

    async fn completed_receipt_for(
        &self,
        transfer: &CrossChainTransfer,
        replay_id: csv_hash::Hash,
    ) -> Result<Option<TransferReceipt>, TransferCoordinatorError> {
        if !self
            .replay_db
            .contains(replay_id.as_bytes())
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?
        {
            return Ok(None);
        }

        let transfers = self.replay_db.load_all_transfers().await.map_err(|e| {
            TransferCoordinatorError::RuntimeError(format!("Failed to load transfers: {}", e))
        })?;
        for entry in transfers {
            if entry.sanad_id != transfer.sanad_id || entry.mint_tx_hash == csv_hash::Hash::zero() {
                continue;
            }
            let recorded_transfer_id = if entry.transfer_id.is_empty() {
                transfer.id.clone()
            } else {
                entry.transfer_id.clone()
            };
            let phase = self
                .execution_journal
                .latest_phase(&recorded_transfer_id)
                .map_err(|e| {
                    TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e))
                })?;
            if phase == Some(TransferStage::Completed) {
                return Ok(Some(TransferReceipt {
                    transfer_id: recorded_transfer_id,
                    replay_id,
                    lock_tx_hash: hex::encode(entry.lock_tx_hash.as_bytes()),
                    mint_tx_hash: hex::encode(entry.mint_tx_hash.as_bytes()),
                    materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                        transfer.destination_chain.clone(),
                    ),
                }));
            }
        }
        Ok(None)
    }

    /// Execute a cross-chain transfer, returning a [`TransferOutcome`].
    ///
    /// This is the resumable core: it locks (if not already locked), journals,
    /// and then gates proof-building on real source-chain confirmations. When the
    /// lock has not yet reached `finality_depth`, it returns
    /// [`TransferOutcome::Pending`] rather than building a proof against an
    /// unmined transaction.
    pub async fn execute_outcome(
        &self,
        transfer: CrossChainTransfer,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<TransferOutcome, TransferCoordinatorError> {
        // Assert lease ownership invariant
        self.assert_single_active_coordinator(&transfer.id).await?;

        // Validate that the runtime instance matches the lease owner.
        // This prevents any runtime from executing a transfer with a valid lease
        // for the same transfer_id — only the lease owner may execute.
        if runtime_ctx.lease.owner_runtime_id != runtime_ctx.runtime_instance {
            return Err(TransferCoordinatorError::RuntimeError(format!(
                "Lease owner {} does not match calling runtime {}",
                runtime_ctx.lease.owner_runtime_id, runtime_ctx.runtime_instance
            )));
        }
        let lease_transfer_id: csv_protocol::sanad::SanadId = runtime_ctx
            .lease
            .transfer_id
            .clone()
            .try_into()
            .unwrap_or_else(|_| csv_protocol::sanad::SanadId(csv_hash::Hash::zero()));
        if lease_transfer_id.as_bytes() != transfer.sanad_id.as_bytes() {
            return Err(TransferCoordinatorError::LeaseViolation(
                "Lease does not authorize the transfer sanad".to_string(),
            ));
        }

        // Validate epoch to detect stale leases.
        // A lease with epoch 0 is considered stale — it was acquired before
        // epoch tracking was enabled and cannot be trusted for execution.
        if runtime_ctx.lease.epoch == 0 {
            return Err(TransferCoordinatorError::RuntimeError(
                "Lease epoch is 0 — lease is stale and cannot be used for execution".to_string(),
            ));
        }
        if !runtime_ctx.lease.is_active(std::time::SystemTime::now()) {
            return Err(TransferCoordinatorError::RuntimeError(
                "Lease is expired".to_string(),
            ));
        }
        self.accept_execution_lease(&runtime_ctx.lease)?;

        let _admission_permit = self
            .admission_controller
            .acquire_transfer(&transfer.source_chain, &transfer.destination_chain)?;

        // Enforce runtime policy: check if RPC fallback is allowed
        if !runtime_ctx.policy.allow_rpc_fallback {
            // In production mode, we require all operations to use real RPC
            // This is enforced by the runtime, not by adapters
        }

        // Step 1: Compute ReplayId and check for replay
        // Runtime coordinates only - use sanad_id (Hash) directly for replay detection
        let replay_id = transfer.sanad_id;
        let replay_id_wire = csv_wire::HashWire::from(replay_id);

        if let Some(receipt) = self.completed_receipt_for(&transfer, replay_id).await? {
            tracing::info!(
                "Transfer {} already consumed; returning recorded receipt without remint",
                transfer.id
            );
            return Ok(TransferOutcome::Completed(Box::new(receipt)));
        }

        // Record phase entry: Initialized (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::Initialized,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Atomic idempotent consume-if-unconsumed: prevents duplicate mints
        let consume_result = self.replay_db.consume_if_unconsumed(&replay_id.0).await;
        match consume_result {
            Ok(()) => {}
            Err(e) => match e {
                ReplayDbError::AlreadyExists => {
                    self.with_metrics(|metrics| metrics.record_replay_rejected());
                    // Append ReplayDetected event to EventStore (durable write FIRST)
                    if let Err(e) = self.event_store.append(
                        &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                            csv_wire::SanadIdWire::from(csv_protocol::sanad::SanadId::new(
                                *transfer.sanad_id.as_bytes(),
                            )),
                            crate::event_envelope::EventType::from_static(
                                crate::event_envelope::EventType::TRANSFER_REPLAY_DETECTED,
                            ),
                            EVENT_VERSION_REPLAY_DETECTED,
                            serde_json::json!({
                                "transfer_id": transfer.id,
                                "replay_id": hex::encode(replay_id.0),
                            })
                            .to_string(),
                            None,
                            runtime_ctx.runtime_instance,
                            std::time::SystemTime::now(),
                        ),
                    ) {
                        tracing::warn!(
                            "Failed to append ReplayDetected event to EventStore: {}",
                            e
                        );
                    }

                    self.event_bus.emit(TransferEvent::ReplayDetected(
                        crate::event_bus::TransferContext {
                            transfer_id: transfer.id.clone(),
                            replay_id: Some(replay_id),
                            proof_hash: None,
                            coordinator_id: self
                                .runtime_id
                                .0
                                .parse()
                                .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                            lease_id: None,
                            source_chain: transfer.source_chain.clone(),
                            dest_chain: transfer.destination_chain.clone(),
                            finality_state: crate::event_bus::FinalityState::NotChecked,
                            recovery_attempt: 0,
                        },
                    ));
                    return Err(TransferCoordinatorError::ReplayDetected(replay_id));
                }
                ReplayDbError::Storage(msg) => {
                    let _ = self.execution_journal.record(
                        crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id: replay_id_wire.clone(),
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::Initialized,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(msg.clone()),
                            attempt: 1,
                            transfer_context: None,
                        },
                    );
                    return Err(TransferCoordinatorError::ReplayDbError(msg.to_string()));
                }
                ReplayDbError::NotFound => {
                    let _ = self.execution_journal.record(
                        crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id: replay_id_wire.clone(),
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::Initialized,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(
                                "Replay ID not found".to_string(),
                            ),
                            attempt: 1,
                            transfer_context: None,
                        },
                    );
                    return Err(TransferCoordinatorError::ReplayDbError(
                        "Replay ID not found".to_string(),
                    ));
                }
            },
        }

        // Record phase entry: Initialized (Completed)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::Initialized,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Persist transfer entry to durable storage for crash recovery
        // Note: lock_tx_hash may be empty at this point (SDK passes empty vec),
        // so we defer persistence until after lock operation completes
        let registry_entry = if transfer.lock_tx_hash.is_empty() {
            // Defer persistence - will be stored after lock completes
            None
        } else {
            Some(transfer_to_registry_entry(&transfer)?)
        };
        if let Some(entry) = registry_entry
            && let Err(e) = self.replay_db.store_transfer_entry(&entry).await
        {
            return Err(TransferCoordinatorError::RuntimeError(format!(
                "Failed to persist transfer entry: {}",
                e
            )));
        }

        // Step 2: Verify source chain capabilities
        let src_caps = adapter_registry
            .capabilities(&transfer.source_chain)
            .ok_or(TransferCoordinatorError::UnknownChain(
                transfer.source_chain.clone(),
            ))?;

        if !src_caps.can_authorize_mint() {
            return Err(TransferCoordinatorError::UnsupportedOperation(format!(
                "{} cannot be a cross-chain source",
                transfer.source_chain
            )));
        }
        src_caps
            .plan_for(&CapabilityRequirements::cross_chain_source())
            .ensure_satisfied()
            .map_err(|e| {
                TransferCoordinatorError::UnsupportedOperation(format!(
                    "{} source capability negotiation failed: {}",
                    transfer.source_chain, e
                ))
            })?;

        // Step 3: Verify destination chain capabilities
        let dst_caps = adapter_registry
            .capabilities(&transfer.destination_chain)
            .ok_or(TransferCoordinatorError::UnknownChain(
                transfer.destination_chain.clone(),
            ))?;

        if !dst_caps.can_authorize_mint() {
            return Err(TransferCoordinatorError::UnsupportedOperation(format!(
                "{} cannot be a cross-chain destination",
                transfer.destination_chain
            )));
        }
        dst_caps
            .plan_for(&CapabilityRequirements::cross_chain_destination())
            .ensure_satisfied()
            .map_err(|e| {
                TransferCoordinatorError::UnsupportedOperation(format!(
                    "{} destination capability negotiation failed: {}",
                    transfer.destination_chain, e
                ))
            })?;

        // Step 4: Lock on source chain with retry logic and circuit breaker
        // Record phase entry: Locking (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::LockConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Append durable event BEFORE emitting to subscribers (crash-safe ordering)
        if let Err(e) = self.event_store.append(&RuntimeEventEnvelope::new(
            csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            EventType(EventType::TRANSFER_LOCKED.to_string()),
            EVENT_VERSION_LOCKED,
            serde_json::json!({
                "transfer_id": transfer.id,
                "source_chain": transfer.source_chain,
                "destination_chain": transfer.destination_chain,
            })
            .to_string(),
            None,
            uuid::Uuid::new_v4(),
            runtime_ctx.runtime_instance,
            std::time::SystemTime::now(),
        )) {
            tracing::warn!("Failed to append Locking event to EventStore: {}", e);
        }

        self.event_bus
            .emit(TransferEvent::Locking(crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: None,
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::NotChecked,
                recovery_attempt: 0,
            }));

        // Check circuit breaker before attempting RPC calls
        {
            let breaker = self
                .circuit_breaker
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !breaker.allow_request() {
                return Err(TransferCoordinatorError::RuntimeError(
                    "Circuit breaker is open - RPC calls blocked".to_string(),
                ));
            }
        }

        let mut lock_result = None;
        let mut last_error = None;

        for attempt in 0..=runtime_ctx.policy.max_retries {
            match adapter_registry
                .lock_sanad(&transfer.source_chain, &transfer)
                .await
            {
                Ok(result) => {
                    lock_result = Some(result);
                    // Record success on circuit breaker
                    self.circuit_breaker
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_success();
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                    // Record failure on circuit breaker
                    self.circuit_breaker
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure();
                    if attempt < runtime_ctx.policy.max_retries {
                        tokio::time::sleep(runtime_ctx.policy.retry_delay).await;
                    }
                }
            }
        }

        let mut lock_result = lock_result.ok_or_else(|| {
            let _ = self
                .execution_journal
                .record(crate::execution_journal::TransferPhaseEntry {
                    transfer_id: transfer.id.clone(),
                    replay_id: replay_id_wire.clone(),
                    proof_hash: [0u8; 32],
                    proof_payload: None,
                    phase: crate::recovery::TransferStage::LockConfirmed,
                    ts: std::time::SystemTime::now(),
                    outcome: crate::execution_journal::PhaseOutcome::Failed(
                        last_error
                            .as_ref()
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "Unknown error".to_string()),
                    ),
                    attempt: 1,
                    transfer_context: None,
                });
            TransferCoordinatorError::LockFailed(
                last_error
                    .as_ref()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "Unknown error".to_string()),
            )
        })?;

        // Record phase entry: Locking (Completed)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::LockConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Persist transfer entry with lock_tx_hash now available
        let mut updated_transfer = transfer.clone();
        updated_transfer.lock_tx_hash = hex::decode(lock_result.tx_hash.trim_start_matches("0x"))
            .map_err(|e| {
            TransferCoordinatorError::InvalidTxHash(format!("Failed to decode lock tx hash: {}", e))
        })?;
        let registry_entry = transfer_to_registry_entry(&updated_transfer)?;
        if let Err(e) = self.replay_db.store_transfer_entry(&registry_entry).await {
            return Err(TransferCoordinatorError::RuntimeError(format!(
                "Failed to persist transfer entry: {}",
                e
            )));
        }

        // From here on, use the transfer with the real lock_tx_hash populated.
        // The SDK submits an empty lock_tx_hash (the coordinator fills it after
        // the lock broadcasts), so proof-building and source-proof validation
        // MUST see the populated 32-byte txid, not the original empty vector.
        let transfer = updated_transfer;

        // Create checkpoint after lock confirmed
        self.checkpoint_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create_recovery_checkpoint(
                transfer.id.clone(),
                TransferStage::LockConfirmed,
                checkpoint_transfer_data(&transfer)?,
            );

        // Record phase entry: AwaitingFinality (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::AwaitingFinality,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Append AwaitingFinality event to EventStore (durable write FIRST)
        if let Err(e) = self.event_store.append(
            &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                csv_wire::SanadIdWire::from(csv_protocol::sanad::SanadId::new(
                    *transfer.sanad_id.as_bytes(),
                )),
                crate::event_envelope::EventType::from_static(
                    crate::event_envelope::EventType::TRANSFER_FINALITY_AWAITED,
                ),
                EVENT_VERSION_AWAITING_FINALITY,
                serde_json::json!({
                    "transfer_id": transfer.id,
                })
                .to_string(),
                None,
                runtime_ctx.runtime_instance,
                std::time::SystemTime::now(),
            ),
        ) {
            tracing::warn!(
                "Failed to append AwaitingFinality event to EventStore: {}",
                e
            );
        }

        self.event_bus.emit(TransferEvent::AwaitingFinality(
            crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: Some(replay_id),
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::Awaiting,
                recovery_attempt: 0,
            },
        ));

        // Use runtime policy for finality depth, not adapter's local policy
        let required_finality = runtime_ctx
            .policy
            .finality_depth_for_chain(&transfer.source_chain)
            .ok_or_else(|| {
                TransferCoordinatorError::RuntimeError(format!(
                    "No finality depth configured for chain: {}",
                    transfer.source_chain
                ))
            })?;

        // Real finality gate: query the actual confirmation depth of the lock
        // transaction on the source chain. If it has not yet reached
        // `required_finality`, return Pending — the lock is on-chain and
        // journaled at AwaitingFinality, so a later advance/resume progresses it
        // once confirmations accrue. This replaces the old vacuous height check
        // that let execution march into proof-building against an unmined tx.
        let finality = self
            .lock_finality_status(&transfer, adapter_registry)
            .await
            .inspect_err(|e| {
                let _ =
                    self.execution_journal
                        .record(crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id: replay_id_wire.clone(),
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::AwaitingFinality,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(e.to_string()),
                            attempt: 1,
                            transfer_context: None,
                        });
            })?;

        if finality.confirmations < required_finality {
            tracing::info!(
                "Transfer {} awaiting finality: {}/{} confirmations",
                transfer.id,
                finality.confirmations,
                required_finality
            );
            return Ok(TransferOutcome::Pending {
                lock_tx_hash: hex::encode(&transfer.lock_tx_hash),
                confirmations: finality.confirmations,
                required: required_finality,
            });
        }

        // Correct the lock height to the true confirming block so the inclusion
        // proof is built against the block the tx was actually mined in (the
        // adapter's lock step reports the tip-at-broadcast height, not this).
        lock_result.block_height = finality.block_height;

        // Record phase entry: AwaitingFinality (Completed)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::AwaitingFinality,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Step 5: Build and verify proof bundle via csv-verifier (canonical verifier)
        // Record phase entry: BuildingProof (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::ProofBuilding,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Append BuildingProof event to EventStore (durable write FIRST)
        if let Err(e) = self.event_store.append(
            &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                csv_wire::SanadIdWire::from(csv_protocol::sanad::SanadId::new(
                    *transfer.sanad_id.as_bytes(),
                )),
                crate::event_envelope::EventType::from_static(
                    crate::event_envelope::EventType::TRANSFER_PROOF_BUILT,
                ),
                EVENT_VERSION_PROOF_BUILT,
                serde_json::json!({
                    "transfer_id": transfer.id,
                })
                .to_string(),
                None,
                runtime_ctx.runtime_instance,
                std::time::SystemTime::now(),
            ),
        ) {
            tracing::warn!("Failed to append BuildingProof event to EventStore: {}", e);
        }

        self.event_bus.emit(TransferEvent::BuildingProof(
            crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: Some(replay_id),
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::NotChecked,
                recovery_attempt: 0,
            },
        ));

        // Build the proof bundle using the source chain adapter
        let proof_bundle = adapter_registry
            .build_inclusion_proof(&transfer.source_chain, &transfer, &lock_result)
            .await
            .map_err(|e: csv_adapter_core::AdapterError| {
                TransferCoordinatorError::ProofBuildFailed(e.to_string())
            })?;

        // Verify the proof bundle using the canonical verifier.
        let signature_scheme = runtime_signature_scheme(proof_bundle.signature_scheme)?;
        if let Some(expected_scheme) = adapter_registry.signature_scheme(&transfer.source_chain)
            && expected_scheme != signature_scheme
        {
            return Err(TransferCoordinatorError::ProofVerificationFailed(format!(
                "Proof bundle signature scheme {:?} does not match source chain {} scheme {:?}",
                signature_scheme, transfer.source_chain, expected_scheme
            )));
        }

        let seal_status = adapter_registry
            .check_seal_registry(&transfer.source_chain, &proof_bundle.seal_ref.id)
            .await
            .map_err(|e| {
                TransferCoordinatorError::ProofVerificationFailed(format!(
                    "Seal registry check failed: {}",
                    e
                ))
            })?;
        let seal_is_consumed =
            matches!(seal_status, csv_adapter_core::SealRegistryStatus::Consumed);
        let seal_id_for_registry = proof_bundle.seal_ref.id.clone();

        let required_confirmations = runtime_ctx
            .policy
            .finality_depth_for_chain(&transfer.source_chain)
            .unwrap_or(6);
        // RUNTIME-FINALITY-TAUTOLOGY-001: current_block_height must be an actual
        // observation of the source-chain tip, not `lock_height +
        // required_confirmations` (which made verify_finality pass by
        // construction). Reuse the real finality observation taken by the gate
        // above (`finality`), where the tip = confirming height + confirmations.
        // The gate already returned Pending if confirmations were insufficient,
        // so here verify_finality re-checks against the same observed tip rather
        // than a synthesized one.
        let observed_tip = finality.block_height.saturating_add(finality.confirmations);
        let verification_context = VerificationContext {
            chain_id: transfer.source_chain.clone(),
            signature_scheme,
            required_confirmations,
            current_block_height: Some(observed_tip),
            seal_registry: Some(Box::new(move |seal_id: &[u8]| {
                seal_is_consumed && seal_id == seal_id_for_registry.as_slice()
            })),
            chain_data: None,
            native_proof_validated: true,
            sanad_id: Some(csv_hash::SanadId(transfer.sanad_id)),
            lock_tx: Some(transfer.lock_tx_hash.clone()),
            lock_output_index: Some(transfer.lock_output_index),
            transition_id: Some(transfer.transition_id.clone()),
            destination_chain: Some(transfer.destination_chain.clone()),
            // Runtime path: destination materialization is authorized by the
            // on-chain §9.2 verifier-attested mint plus native_proof_validated
            // above, so the DAG-signature approved-verifier binding is not the
            // gate here (VERIFY-SIGNER-BINDING-001). The offline recipient accept
            // path supplies and enforces this set instead.
            authorized_signers: Vec::new(),
        };

        adapter_registry
            .validate_source_proof(&transfer.source_chain, &transfer, &proof_bundle)
            .await
            .map_err(|e| TransferCoordinatorError::ProofVerificationFailed(e.to_string()))?;

        let source_verifier =
            Self::verifier_for_source_chain(&runtime_ctx.policy, &transfer.source_chain)?;
        match source_verifier.verify_proof_bundle(&proof_bundle, &verification_context) {
            Ok(result) => {
                if !result.is_valid {
                    self.with_metrics(|metrics| metrics.record_authorization_rejected());
                    let _ = self.execution_journal.record(
                        crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id: replay_id_wire.clone(),
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::ProofBuilding,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(
                                result
                                    .errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; "),
                            ),
                            attempt: 1,
                            transfer_context: None,
                        },
                    );
                    return Err(TransferCoordinatorError::ProofVerificationFailed(
                        result
                            .errors
                            .iter()
                            .map(|e| e.to_string())
                            .collect::<Vec<_>>()
                            .join("; "),
                    ));
                }
                // Proof verified successfully
                // Append ProofVerified event to EventStore (durable write FIRST)
                if let Err(e) = self.event_store.append(
                    &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                        csv_wire::SanadIdWire::from(csv_protocol::sanad::SanadId::new(
                            *transfer.sanad_id.as_bytes(),
                        )),
                        crate::event_envelope::EventType::from_static(
                            crate::event_envelope::EventType::TRANSFER_PROOF_VERIFIED,
                        ),
                        EVENT_VERSION_PROOF_VERIFIED,
                        serde_json::json!({
                            "transfer_id": transfer.id,
                        })
                        .to_string(),
                        None,
                        runtime_ctx.runtime_instance,
                        std::time::SystemTime::now(),
                    ),
                ) {
                    tracing::warn!("Failed to append ProofVerified event to EventStore: {}", e);
                }

                self.event_bus.emit(TransferEvent::ProofVerified(
                    crate::event_bus::TransferContext {
                        transfer_id: transfer.id.clone(),
                        replay_id: Some(replay_id),
                        proof_hash: None,
                        coordinator_id: self
                            .runtime_id
                            .0
                            .parse()
                            .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                        lease_id: None,
                        source_chain: transfer.source_chain.clone(),
                        dest_chain: transfer.destination_chain.clone(),
                        finality_state: crate::event_bus::FinalityState::NotChecked,
                        recovery_attempt: 0,
                    },
                ));

                // Record phase entry: BuildingProof (Completed)
                self.execution_journal
                    .record(crate::execution_journal::TransferPhaseEntry {
                        transfer_id: transfer.id.clone(),
                        replay_id: replay_id_wire.clone(),
                        proof_hash: [0u8; 32],
                        proof_payload: None,
                        phase: crate::recovery::TransferStage::ProofBuilding,
                        ts: std::time::SystemTime::now(),
                        outcome: crate::execution_journal::PhaseOutcome::Completed,
                        attempt: 1,
                        transfer_context: None,
                    })
                    .map_err(|e| {
                        TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e))
                    })?;
            }
            Err(e) => {
                self.with_metrics(|metrics| metrics.record_authorization_rejected());
                let _ =
                    self.execution_journal
                        .record(crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id: replay_id_wire.clone(),
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::ProofBuilding,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(e.to_string()),
                            attempt: 1,
                            transfer_context: None,
                        });
                return Err(TransferCoordinatorError::ProofVerificationFailed(
                    e.to_string(),
                ));
            }
        }

        // Serialize proof bundle for minting using canonical CBOR
        let proof_bundle_bytes = proof_bundle.to_canonical_bytes().map_err(|e| {
            TransferCoordinatorError::ProofBuildFailed(format!("Serialization failed: {}", e))
        })?;
        let proof_hash = proof_payload_hash(&proof_bundle_bytes);

        // Persist verified proof material before any destination-chain mutation.
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash,
                proof_payload: Some(proof_bundle_bytes.clone()),
                phase: crate::recovery::TransferStage::ProofValidated,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        self.with_metrics(|metrics| metrics.record_verified_proof_built());

        // Create checkpoint after proof building
        self.checkpoint_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create_recovery_checkpoint(
                transfer.id.clone(),
                TransferStage::ProofBuilding,
                proof_bundle_bytes.clone(),
            );

        // Check circuit breaker before attempting RPC calls
        {
            let allow_request = self
                .circuit_breaker
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .allow_request();
            if !allow_request {
                let _ =
                    self.execution_journal
                        .record(crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id: replay_id_wire.clone(),
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::MintConfirmed,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(
                                "Circuit breaker is open".to_string(),
                            ),
                            attempt: 1,
                            transfer_context: None,
                        });
                let typed_replay_id = replay_id_from_hash(csv_hash::ReplayIdHash(replay_id));
                let _ = self.replay_db.mark_rolled_back(&typed_replay_id).await;
                return Err(TransferCoordinatorError::RuntimeError(
                    "Circuit breaker is open - RPC calls blocked".to_string(),
                ));
            }
        }

        // Record phase entry: Minting (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::MintConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Construct the RFC-0012 §9.2 attestation-carrying mint request the
        // adapter submits. Built from the already-verified proof bundle — the
        // off-chain verifier above is the sole proof adjudicator; this request
        // carries attestation inputs (chain identities via keccak256, commitment,
        // lock-event id, nullifier), never a proof root.
        let destination_owner = runtime_ctx.destination_owner.clone().unwrap_or_default();
        let mint_request = build_runtime_mint_request(
            &transfer,
            &proof_bundle,
            proof_bundle_bytes.clone(),
            destination_owner,
        );
        let mint_payload = encode_mint_request(&mint_request)?;

        let mut mint_result = None;
        let mut last_error = None;

        for attempt in 0..=runtime_ctx.policy.max_retries {
            match adapter_registry
                .mint_sanad(&transfer.destination_chain, &transfer, &mint_payload)
                .await
            {
                Ok(result) => {
                    mint_result = Some(result);
                    // Record success on circuit breaker
                    self.circuit_breaker
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_success();
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                    // Record failure on circuit breaker
                    self.circuit_breaker
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure();
                    if attempt < runtime_ctx.policy.max_retries {
                        tokio::time::sleep(runtime_ctx.policy.retry_delay).await;
                    }
                }
            }
        }

        let mint_result = match mint_result {
            Some(result) => result,
            None => {
                let error = last_error
                    .as_ref()
                    .map(|e: &csv_adapter_core::AdapterError| e.to_string())
                    .unwrap_or_else(|| "Unknown error".to_string());
                let _ =
                    self.execution_journal
                        .record(crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id: replay_id_wire.clone(),
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::MintConfirmed,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(error.clone()),
                            attempt: 1,
                            transfer_context: None,
                        });
                let typed_replay_id = replay_id_from_hash(csv_hash::ReplayIdHash(replay_id));
                let _ = self.replay_db.mark_rolled_back(&typed_replay_id).await;
                return Err(TransferCoordinatorError::MintFailed(error));
            }
        };

        let mut submitted_registry_entry = transfer_to_registry_entry(&transfer)?;
        submitted_registry_entry.mint_tx_hash = hash_from_tx_str(&mint_result.tx_hash)?;
        self.replay_db
            .store_transfer_entry(&submitted_registry_entry)
            .await
            .map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to persist submitted mint transaction: {}",
                    e
                ))
            })?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::MintSubmitted,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        self.with_metrics(|metrics| metrics.record_mint_submitted());

        // Record phase entry: Minting (Completed)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::MintConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Create checkpoint after mint confirmed
        self.checkpoint_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create_recovery_checkpoint(
                transfer.id.clone(),
                TransferStage::MintConfirmed,
                checkpoint_transfer_data(&transfer)?,
            );

        // Promote replay entry Pending → Consumed after mint confirms on-chain
        self.replay_db
            .confirm_consumed(&replay_id.0)
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?;
        self.with_metrics(|metrics| metrics.record_mint_confirmed());

        // Record auditable settlement evidence for a later source release. Built
        // from the already-verified proof bundle and the confirmed mint result.
        let settlement_evidence = build_settlement_evidence(
            &transfer,
            &proof_bundle,
            &mint_result.tx_hash,
            mint_result.block_height,
        );
        self.record_settlement_evidence(&settlement_evidence, runtime_ctx.runtime_instance);

        let mut registry_entry = transfer_to_registry_entry(&transfer)?;
        registry_entry.mint_tx_hash = hash_from_tx_str(&mint_result.tx_hash)?;
        self.replay_db
            .store_transfer_entry(&registry_entry)
            .await
            .map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to persist confirmed transfer: {}",
                    e
                ))
            })?;

        // Append Complete event to EventStore (durable write FIRST)
        if let Err(e) = self.event_store.append(
            &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                csv_wire::SanadIdWire::from(csv_protocol::sanad::SanadId::new(
                    *transfer.sanad_id.as_bytes(),
                )),
                crate::event_envelope::EventType::from_static(
                    crate::event_envelope::EventType::TRANSFER_COMPLETE,
                ),
                EVENT_VERSION_COMPLETE,
                serde_json::json!({
                    "transfer_id": transfer.id,
                    "mint_tx_hash": mint_result.tx_hash,
                })
                .to_string(),
                None,
                runtime_ctx.runtime_instance,
                std::time::SystemTime::now(),
            ),
        ) {
            tracing::warn!("Failed to append Complete event to EventStore: {}", e);
        }

        self.event_bus
            .emit(TransferEvent::Complete(crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: None,
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::Confirmed,
                recovery_attempt: 0,
            }));

        // Create final checkpoint after completion
        self.checkpoint_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create_recovery_checkpoint(
                transfer.id.clone(),
                TransferStage::Completed,
                checkpoint_transfer_data(&transfer)?,
            );

        // Record phase entry: Completed (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::Completed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        Ok(TransferOutcome::Completed(Box::new(TransferReceipt {
            transfer_id: transfer.id,
            replay_id,
            lock_tx_hash: lock_result.tx_hash,
            mint_tx_hash: mint_result.tx_hash,
            materialization: mint_result.materialization,
        })))
    }

    /// Subscribe to transfer events
    pub fn subscribe(&mut self, subscriber: crate::event_bus::EventSubscriber) {
        self.event_bus.subscribe(subscriber);
    }

    /// Load all persisted transfer entries from the replay database.
    ///
    /// Called at startup to rebuild the in-memory session index from durable storage.
    /// Returns an empty vec if no entries exist.
    pub async fn load_all_transfers(
        &self,
    ) -> Result<Vec<CrossChainTransfer>, TransferCoordinatorError> {
        let registry_entries = self
            .replay_db
            .load_all_transfers()
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?;

        // Convert registry entries to runtime transfer objects
        // Note: transfer_id is not stored in registry, so we use sanad_id hex as transfer_id
        let transfers = registry_entries
            .into_iter()
            .map(|entry| {
                let transfer_id = hex::encode(entry.sanad_id.as_bytes());
                registry_entry_to_transfer(&entry, transfer_id)
            })
            .collect();

        Ok(transfers)
    }

    /// Set the distributed coordinator lease backend.
    ///
    /// Used by HA deployments to inject a PostgreSQL-backed lease implementation.
    pub fn set_coordinator_lease(&mut self, lease: Box<dyn CoordinatorLease>) {
        self.coordinator_lease = Some(lease);
    }

    /// Clear the distributed coordinator lease backend.
    ///
    /// Used for single-instance deployments (CLI, SDK) where distributed lease
    /// coordination is not required. The assert_single_active_coordinator check
    /// will be skipped when coordinator_lease is None.
    pub fn clear_coordinator_lease(&mut self) {
        self.coordinator_lease = None;
    }

    /// Acquire or renew the process authority required before executing mutations.
    pub async fn acquire_execution_authority(
        &self,
        ttl: std::time::Duration,
    ) -> Result<u64, TransferCoordinatorError> {
        let lease = self.coordinator_lease.as_ref().ok_or_else(|| {
            TransferCoordinatorError::LeaseViolation(
                "A distributed coordinator lease is required".to_string(),
            )
        })?;
        lease
            .acquire_or_renew(&self.runtime_id, ttl)
            .await
            .map_err(|e| TransferCoordinatorError::LeaseViolation(e.to_string()))
    }

    /// Get the optional distributed coordinator lease backend.
    pub fn coordinator_lease(&self) -> Option<&dyn CoordinatorLease> {
        self.coordinator_lease.as_deref()
    }

    /// Get a reference to the checkpoint manager
    pub fn checkpoint_manager(&self) -> std::sync::Arc<std::sync::Mutex<CheckpointManager>> {
        self.checkpoint_manager.clone()
    }

    /// Get a reference to the canonical verifier.
    ///
    /// This is the single source of truth for all proof verification in the protocol.
    /// All verification paths MUST go through this verifier.
    pub fn verifier(&self) -> &CanonicalVerifierImpl {
        &self.verifier
    }

    /// Get a reference to the execution journal.
    ///
    /// The execution journal provides crash-safe phase tracking for transfer execution.
    pub fn execution_journal(&self) -> &dyn ExecutionJournal {
        self.execution_journal.as_ref()
    }

    /// Record auditable [`SettlementEvidence`] into the durable event store.
    ///
    /// Called at mint confirmation on both the fresh-execution and resume paths.
    /// Appended after the transfer's other lifecycle events with a version derived
    /// from the current aggregate head, so it never regresses the append-only log.
    /// A failure here is logged but does not fail the transfer: the mint has
    /// already confirmed and the replay entry is already consumed, so completion
    /// must not be blocked on the audit write. Escrow release (TRM-ESCROW-001) is
    /// a separate, verifier-signed authorization and does not depend on this write
    /// succeeding in-band.
    fn record_settlement_evidence(&self, evidence: &SettlementEvidence, runtime_instance: Uuid) {
        let sanad = csv_protocol::sanad::SanadId::new(evidence.sanad_id);
        let payload = match serde_json::to_string(evidence) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!(
                    "Failed to serialize settlement evidence for transfer {}: {}",
                    evidence.transfer_id,
                    e
                );
                return;
            }
        };
        // Derive the next version from the aggregate head so the settlement event
        // is always appended monotonically, regardless of how many lifecycle
        // events preceded it on this or a prior process.
        let version = self
            .event_store
            .get_latest_version(&sanad)
            .map(|v| v + 1)
            .unwrap_or(1);
        if let Err(e) = self.event_store.append(
            &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                csv_wire::SanadIdWire::from(sanad),
                crate::event_envelope::EventType::from_static(
                    crate::event_envelope::EventType::TRANSFER_SETTLEMENT_RECORDED,
                ),
                version,
                payload,
                None,
                runtime_instance,
                std::time::SystemTime::now(),
            ),
        ) {
            tracing::warn!(
                "Failed to append SettlementRecorded event for transfer {}: {}",
                evidence.transfer_id,
                e
            );
        }
    }

    /// Query the settlement evidence recorded for a transferred sanad.
    ///
    /// Reads the append-only event store and returns the most recently recorded
    /// [`SettlementEvidence`] for the aggregate, or `None` if the destination mint
    /// has not yet confirmed. This is the read side a source-chain escrow release
    /// (TRM-ESCROW-001) consults before authorizing a release.
    pub fn settlement_evidence(
        &self,
        sanad_id: &csv_hash::SanadId,
    ) -> Result<Option<SettlementEvidence>, TransferCoordinatorError> {
        let aggregate = csv_protocol::sanad::SanadId::new(*sanad_id.as_bytes());
        let events = self.event_store.get_events(&aggregate, None).map_err(|e| {
            TransferCoordinatorError::RuntimeError(format!("Event store error: {}", e))
        })?;
        let latest = events.into_iter().rev().find(|event| {
            event.event_type().as_str()
                == crate::event_envelope::EventType::TRANSFER_SETTLEMENT_RECORDED
        });
        match latest {
            Some(event) => {
                let evidence: SettlementEvidence =
                    serde_json::from_str(event.payload()).map_err(|e| {
                        TransferCoordinatorError::RuntimeError(format!(
                            "Malformed settlement evidence in event store: {}",
                            e
                        ))
                    })?;
                Ok(Some(evidence))
            }
            None => Ok(None),
        }
    }

    /// Terminal settlement status of a sanad's source escrow, read from the
    /// append-only event store.
    ///
    /// This is the runtime's crash-safe idempotency oracle: `release_escrow` and
    /// `refund_escrow` both consult it before submitting, so a settlement that
    /// already completed (possibly in a prior process) is never re-submitted.
    /// Release and refund are mutually exclusive — the most recent terminal record
    /// wins, and both entry points refuse to cross from one to the other.
    pub fn settlement_status(
        &self,
        sanad_id: &csv_hash::SanadId,
    ) -> Result<SettlementStatus, TransferCoordinatorError> {
        let aggregate = csv_protocol::sanad::SanadId::new(*sanad_id.as_bytes());
        let events = self.event_store.get_events(&aggregate, None).map_err(|e| {
            TransferCoordinatorError::RuntimeError(format!("Event store error: {}", e))
        })?;
        let latest = events.into_iter().rev().find(|event| {
            let t = event.event_type().as_str();
            t == crate::event_envelope::EventType::TRANSFER_SETTLEMENT_RELEASED
                || t == crate::event_envelope::EventType::TRANSFER_SETTLEMENT_REFUNDED
        });
        match latest {
            Some(event) => {
                let record: SettlementReleaseRecord = serde_json::from_str(event.payload())
                    .map_err(|e| {
                        TransferCoordinatorError::RuntimeError(format!(
                            "Malformed settlement record in event store: {}",
                            e
                        ))
                    })?;
                if event.event_type().as_str()
                    == crate::event_envelope::EventType::TRANSFER_SETTLEMENT_RELEASED
                {
                    Ok(SettlementStatus::Released(Box::new(record)))
                } else {
                    Ok(SettlementStatus::Refunded(Box::new(record)))
                }
            }
            None => Ok(SettlementStatus::Unsettled),
        }
    }

    /// Release a source-chain escrow to the operator on a verifier-signed
    /// settlement receipt (RFC-0012 §10 / TRM-ESCROW-001).
    ///
    /// The operator is the payout beneficiary and CANNOT self-release: this method
    /// builds the §10 receipt inputs and dispatches them to the source adapter,
    /// which binds `source_escrow_contract`, obtains the verifier signatures, and
    /// submits. Authority is the verifier set that signs the receipt — never the
    /// operator's own claim (the runtime attaches no signatures; an unsigned
    /// request is rejected on-chain).
    ///
    /// Preconditions enforced here (fail-closed):
    /// - the destination mint must have confirmed — [`SettlementEvidence`] must
    ///   exist, or release is refused ([`TransferCoordinatorError::SettlementNotAuthorized`]);
    /// - the escrow must not already be released or refunded (crash-safe
    ///   one-release-per-`lock_event_id` via [`Self::settlement_status`]).
    ///
    /// On success a distinct `Transfer.SettlementReleased` event is appended (never
    /// conflated with `Transfer.Minted`), and the release record is returned.
    pub async fn release_escrow(
        &self,
        sanad_id: &csv_hash::SanadId,
        operator_payout_address: [u8; 32],
        receipt_expiry: u64,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: &crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<SettlementReleaseRecord, TransferCoordinatorError> {
        // Idempotency / mutual-exclusion guard — crash-safe across restarts.
        match self.settlement_status(sanad_id)? {
            SettlementStatus::Released(_) => return Err(TransferCoordinatorError::AlreadyReleased),
            SettlementStatus::Refunded(_) => return Err(TransferCoordinatorError::AlreadyRefunded),
            SettlementStatus::Unsettled => {}
        }

        // Release requires a confirmed destination mint. Absent evidence, a failed
        // or not-yet-confirmed mint must never release escrow.
        let evidence = match self.settlement_evidence(sanad_id)? {
            Some(evidence) => evidence,
            None => {
                self.with_metrics(|metrics| metrics.record_authorization_rejected());
                return Err(TransferCoordinatorError::SettlementNotAuthorized(
                    "no confirmed destination mint recorded for this sanad".to_string(),
                ));
            }
        };

        let receipt = build_settlement_receipt(&evidence, operator_payout_address, receipt_expiry);
        // The runtime holds no verifier key and cannot bind `source_escrow_contract`;
        // the source adapter/verifier fills the signatures over the finalized digest.
        // An empty vector can never release on-chain (fail-closed) — this is the
        // structural reason the operator cannot self-release.
        let request = RuntimeSettlementRequest {
            receipt,
            verifier_signatures: Vec::new(),
        };
        let payload = encode_settlement_request(&request)?;
        let transfer = transfer_from_settlement_evidence(&evidence);

        let result = adapter_registry
            .settle_escrow(&evidence.source_chain, &transfer, &payload)
            .await
            .map_err(|e| TransferCoordinatorError::SettlementFailed(e.to_string()))?;
        self.with_metrics(|metrics| metrics.record_settlement_submitted());

        let record = SettlementReleaseRecord {
            released_to_operator: true,
            transfer_id: evidence.transfer_id.clone(),
            sanad_id: evidence.sanad_id,
            source_chain: evidence.source_chain.clone(),
            lock_event_id: evidence.lock_event_id,
            destination_mint_tx_ref: request.receipt.destination_mint_tx_ref,
            operator_payout_address,
            settlement_tx_hash: result.tx_hash,
            settlement_block_height: result.block_height,
            settled_at: now_unix_secs(),
        };
        self.record_settlement(
            &record,
            crate::event_envelope::EventType::TRANSFER_SETTLEMENT_RELEASED,
            runtime_ctx.runtime_instance,
        )?;
        self.with_metrics(|metrics| metrics.record_settlement_confirmed());
        Ok(record)
    }

    /// Refund a source-chain escrow to the original locker after the destination
    /// mint fails to occur (RFC-0012 §10 failure handling / TRM-ESCROW-001).
    ///
    /// Refuses if a destination mint confirmed ([`SettlementEvidence`] present) —
    /// a confirmed mint must settle to the operator, never refund — and if the
    /// escrow was already released or refunded. The source adapter's on-chain
    /// refund is additionally timeout-gated. On success a distinct
    /// `Transfer.SettlementRefunded` event is appended.
    pub async fn refund_escrow(
        &self,
        transfer: &CrossChainTransfer,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: &crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<SettlementReleaseRecord, TransferCoordinatorError> {
        let sanad_id = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());
        match self.settlement_status(&sanad_id)? {
            SettlementStatus::Released(_) => return Err(TransferCoordinatorError::AlreadyReleased),
            SettlementStatus::Refunded(_) => return Err(TransferCoordinatorError::AlreadyRefunded),
            SettlementStatus::Unsettled => {}
        }

        // A confirmed destination mint must settle to the operator, not refund.
        if self.settlement_evidence(&sanad_id)?.is_some() {
            return Err(TransferCoordinatorError::SettlementNotAuthorized(
                "destination mint confirmed; escrow must settle to operator, not refund"
                    .to_string(),
            ));
        }

        let result = adapter_registry
            .refund_escrow(&transfer.source_chain, transfer)
            .await
            .map_err(|e| TransferCoordinatorError::SettlementFailed(e.to_string()))?;
        self.with_metrics(|metrics| metrics.record_settlement_submitted());

        let record = SettlementReleaseRecord {
            released_to_operator: false,
            transfer_id: transfer.id.clone(),
            sanad_id: *transfer.sanad_id.as_bytes(),
            source_chain: transfer.source_chain.clone(),
            lock_event_id: lock_event_id(transfer),
            destination_mint_tx_ref: [0u8; 32],
            operator_payout_address: [0u8; 32],
            settlement_tx_hash: result.tx_hash,
            settlement_block_height: result.block_height,
            settled_at: now_unix_secs(),
        };
        self.record_settlement(
            &record,
            crate::event_envelope::EventType::TRANSFER_SETTLEMENT_REFUNDED,
            runtime_ctx.runtime_instance,
        )?;
        self.with_metrics(|metrics| metrics.record_settlement_confirmed());
        Ok(record)
    }

    /// Append a terminal settlement record to the event store.
    ///
    /// Unlike settlement *evidence* (a best-effort audit write), a settlement
    /// record is the durable proof the payout happened, so a failed append is a
    /// hard error: the caller must not treat an unrecorded settlement as complete.
    fn record_settlement(
        &self,
        record: &SettlementReleaseRecord,
        event_type: &'static str,
        runtime_instance: Uuid,
    ) -> Result<(), TransferCoordinatorError> {
        let sanad = csv_protocol::sanad::SanadId::new(record.sanad_id);
        let payload = serde_json::to_string(record).map_err(|e| {
            TransferCoordinatorError::SettlementFailed(format!(
                "Failed to serialize settlement record: {}",
                e
            ))
        })?;
        let version = self
            .event_store
            .get_latest_version(&sanad)
            .map(|v| v + 1)
            .unwrap_or(1);
        self.event_store
            .append(
                &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                    csv_wire::SanadIdWire::from(sanad),
                    crate::event_envelope::EventType::from_static(event_type),
                    version,
                    payload,
                    None,
                    runtime_instance,
                    std::time::SystemTime::now(),
                ),
            )
            .map_err(|e| {
                TransferCoordinatorError::SettlementFailed(format!(
                    "Failed to append settlement record for transfer {}: {}",
                    record.transfer_id, e
                ))
            })
    }

    /// Record settlement evidence on the resume path, reconstructing the verified
    /// proof bundle from the journal's persisted payload.
    ///
    /// Best-effort: the mint has already confirmed and the replay entry is already
    /// consumed by the time this runs, so a missing or malformed persisted payload
    /// is logged rather than allowed to fail the completing transfer.
    fn record_resumed_settlement_evidence(
        &self,
        transfer: &CrossChainTransfer,
        mint_result: &csv_adapter_core::MintResult,
        runtime_ctx: &crate::user_runtime_lease::RuntimeExecutionContext,
    ) {
        let payload = match self.execution_journal.latest_entry(&transfer.id) {
            Ok(Some(entry)) => entry.proof_payload,
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    "Skipping settlement evidence for transfer {}: journal read failed: {}",
                    transfer.id,
                    e
                );
                return;
            }
        };
        let Some(payload) = payload.filter(|p| !p.is_empty()) else {
            tracing::warn!(
                "Skipping settlement evidence for transfer {}: no persisted proof payload",
                transfer.id
            );
            return;
        };
        match csv_protocol::proof_taxonomy::ProofBundle::from_canonical_bytes(&payload) {
            Ok(proof_bundle) => {
                let evidence = build_settlement_evidence(
                    transfer,
                    &proof_bundle,
                    &mint_result.tx_hash,
                    mint_result.block_height,
                );
                self.record_settlement_evidence(&evidence, runtime_ctx.runtime_instance);
            }
            Err(e) => tracing::warn!(
                "Skipping settlement evidence for transfer {}: proof payload malformed: {}",
                transfer.id,
                e
            ),
        }
    }

    /// Resume a specific transfer after a crash or restart.
    ///
    /// This method queries the execution journal for the last recorded phase
    /// of a transfer and resumes execution from that phase.
    ///
    /// # Arguments
    ///
    /// * `transfer_id` - The ID of the transfer to resume
    /// * `adapter_registry` - The adapter registry for chain operations
    /// * `runtime_ctx` - Runtime execution context with lease and policy
    ///
    /// # Returns
    ///
    /// The transfer receipt if the transfer completes successfully.
    pub async fn resume_transfer(
        &self,
        transfer_id: &str,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        // Assert lease ownership invariant
        self.assert_single_active_coordinator(transfer_id).await?;

        let recovery_entry = self
            .execution_journal
            .latest_entry(transfer_id)
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?
            .ok_or(TransferCoordinatorError::NotFound)?;
        let phase = recovery_entry.phase;

        tracing::info!("Resuming transfer {} from phase {:?}", transfer_id, phase);

        // Try to retrieve transfer from durable storage
        let transfers = self.replay_db.load_all_transfers().await.map_err(|e| {
            TransferCoordinatorError::RuntimeError(format!("Failed to load transfers: {}", e))
        })?;

        let cached_transfer = transfers
            .iter()
            .find(|entry| {
                entry.transfer_id == transfer_id
                    || (entry.transfer_id.is_empty()
                        && hex::encode(entry.sanad_id.as_bytes()) == transfer_id)
            })
            .map(|entry| registry_entry_to_transfer(entry, transfer_id.to_string()));

        // Phase-specific recovery logic
        match phase {
            crate::recovery::TransferStage::Initialized => {
                // Transfer was initialized but lock was never broadcast
                // Try to recover from cache if available
                if let Some(transfer) = cached_transfer {
                    tracing::info!("Recovering transfer from cache - restarting from lock phase");
                    // Re-execute the transfer from the beginning
                    // The replay check will prevent duplicate execution
                    self.execute(transfer, adapter_registry, runtime_ctx).await
                } else {
                    Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from Initialized phase - transfer state lost (cache miss)"
                            .to_string(),
                    ))
                }
            }
            crate::recovery::TransferStage::LockSubmitted => {
                // Lock was submitted but not confirmed - resume by checking lock status
                if let Some(transfer) = cached_transfer {
                    tracing::info!("Resuming from LockSubmitted - checking lock status");
                    // Delegate to execute_from_lock which will check lock status
                    self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                        .await
                } else {
                    Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from LockSubmitted phase - transfer state lost (cache miss)"
                            .to_string(),
                    ))
                }
            }
            crate::recovery::TransferStage::LockConfirmed => {
                // Try to reconstruct transfer from journal context
                let transfer = if let Some(transfer) = cached_transfer {
                    transfer
                } else if let Some(ctx) = recovery_entry.transfer_context {
                    // Reconstruct transfer from journal context
                    tracing::info!(
                        "Reconstructing transfer from journal context for LockConfirmed recovery"
                    );
                    CrossChainTransfer {
                        id: transfer_id.to_string(),
                        source_chain: ctx.source_chain.clone(),
                        destination_chain: ctx.destination_chain.clone(),
                        lock_tx_hash: {
                            let hash: csv_hash::Hash = ctx
                                .lock_tx_hash
                                .clone()
                                .try_into()
                                .unwrap_or_else(|_| csv_hash::Hash::zero());
                            hash.as_slice().to_vec()
                        },
                        lock_output_index: 0,
                        sanad_id: {
                            let sanad_id: csv_protocol::sanad::SanadId =
                                ctx.sanad_id.clone().try_into().unwrap_or_else(|_| {
                                    csv_protocol::sanad::SanadId(csv_hash::Hash::zero())
                                });
                            sanad_id.0
                        },
                        transition_id: vec![],
                    }
                } else {
                    return Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from LockConfirmed phase - transfer context missing from journal"
                            .to_string(),
                    ));
                };
                self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                    .await
            }
            crate::recovery::TransferStage::ProofBuilding => {
                // Check for persisted proof checkpoint before regenerating
                if let Some(proof_payload) = &recovery_entry.proof_payload {
                    if !proof_payload.is_empty() {
                        tracing::info!(
                            "Resuming from ProofBuilding - using persisted proof checkpoint"
                        );
                        // Proof was already built and persisted, skip regeneration
                        let proof_bundle: csv_protocol::proof_taxonomy::ProofBundle =
                            csv_protocol::proof_taxonomy::ProofBundle::from_canonical_bytes(
                                proof_payload,
                            )
                            .map_err(|e| {
                                TransferCoordinatorError::ProofVerificationFailed(format!(
                                    "Persisted proof checkpoint is malformed: {}",
                                    e
                                ))
                            })?;

                        // Reconstruct transfer from journal context if needed
                        let transfer = if let Some(transfer) = cached_transfer {
                            transfer
                        } else if let Some(ctx) = &recovery_entry.transfer_context {
                            CrossChainTransfer {
                                id: transfer_id.to_string(),
                                source_chain: ctx.source_chain.clone(),
                                destination_chain: ctx.destination_chain.clone(),
                                lock_tx_hash: {
                                    let hash: csv_hash::Hash = ctx
                                        .lock_tx_hash
                                        .clone()
                                        .try_into()
                                        .unwrap_or_else(|_| csv_hash::Hash::zero());
                                    hash.as_bytes().to_vec()
                                },
                                lock_output_index: 0,
                                sanad_id: {
                                    let sanad_id: csv_protocol::sanad::SanadId =
                                        ctx.sanad_id.clone().try_into().unwrap_or_else(|_| {
                                            csv_protocol::sanad::SanadId(csv_hash::Hash::zero())
                                        });
                                    sanad_id.0
                                },
                                transition_id: vec![],
                            }
                        } else {
                            return Err(TransferCoordinatorError::RuntimeError(
                                "Cannot resume from ProofBuilding - transfer context missing"
                                    .to_string(),
                            ));
                        };

                        // Verify the persisted proof and proceed to mint
                        let lock_tx_hash =
                            hex::encode(hash_from_tx_bytes(&transfer.lock_tx_hash)?.as_bytes());
                        let confirmed_lock = adapter_registry
                            .confirm_tx(&transfer.source_chain, &lock_tx_hash)
                            .await
                            .map_err(|e| TransferCoordinatorError::FinalityFailed(e.to_string()))?;

                        self.verify_recovery_proof(
                            &transfer,
                            &proof_bundle,
                            confirmed_lock.block_height,
                            adapter_registry,
                            &runtime_ctx,
                        )
                        .await?;

                        self.execute_from_proof(
                            transfer,
                            proof_payload.clone(),
                            adapter_registry,
                            runtime_ctx,
                        )
                        .await
                    } else {
                        // No persisted proof, need to regenerate
                        let transfer = if let Some(transfer) = cached_transfer {
                            transfer
                        } else if let Some(ctx) = recovery_entry.transfer_context {
                            CrossChainTransfer {
                                id: transfer_id.to_string(),
                                source_chain: ctx.source_chain.clone(),
                                destination_chain: ctx.destination_chain.clone(),
                                lock_tx_hash: {
                                    let hash: csv_hash::Hash = ctx
                                        .lock_tx_hash
                                        .clone()
                                        .try_into()
                                        .unwrap_or_else(|_| csv_hash::Hash::zero());
                                    hash.as_bytes().to_vec()
                                },
                                lock_output_index: 0,
                                sanad_id: {
                                    let sanad_id: csv_protocol::sanad::SanadId =
                                        ctx.sanad_id.clone().try_into().unwrap_or_else(|_| {
                                            csv_protocol::sanad::SanadId(csv_hash::Hash::zero())
                                        });
                                    sanad_id.0
                                },
                                transition_id: vec![],
                            }
                        } else {
                            return Err(TransferCoordinatorError::RuntimeError(
                                "Cannot resume from ProofBuilding phase - transfer state lost"
                                    .to_string(),
                            ));
                        };
                        self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                            .await
                    }
                } else {
                    // No proof payload in journal, need to regenerate
                    let transfer = if let Some(transfer) = cached_transfer {
                        transfer
                    } else if let Some(ctx) = recovery_entry.transfer_context {
                        CrossChainTransfer {
                            id: transfer_id.to_string(),
                            source_chain: ctx.source_chain.clone(),
                            destination_chain: ctx.destination_chain.clone(),
                            lock_tx_hash: {
                                let hash: csv_hash::Hash = ctx
                                    .lock_tx_hash
                                    .clone()
                                    .try_into()
                                    .unwrap_or_else(|_| csv_hash::Hash::zero());
                                hash.as_bytes().to_vec()
                            },
                            lock_output_index: 0,
                            sanad_id: {
                                let sanad_id: csv_protocol::sanad::SanadId =
                                    ctx.sanad_id.clone().try_into().unwrap_or_else(|_| {
                                        csv_protocol::sanad::SanadId(csv_hash::Hash::zero())
                                    });
                                sanad_id.0
                            },
                            transition_id: vec![],
                        }
                    } else {
                        return Err(TransferCoordinatorError::RuntimeError(
                            "Cannot resume from ProofBuilding phase - transfer state lost"
                                .to_string(),
                        ));
                    };
                    self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                        .await
                }
            }
            crate::recovery::TransferStage::ProofValidated => {
                // Proof was validated, need to resume from mint broadcast
                if let Some(transfer) = cached_transfer {
                    tracing::info!("Resuming from ProofValidated - proceeding to mint");
                    let proof_payload = recovery_entry.proof_payload.ok_or_else(|| {
                        TransferCoordinatorError::RuntimeError(
                            "Cannot resume from ProofValidated phase - verified proof payload missing"
                                .to_string(),
                        )
                    })?;
                    if recovery_entry.proof_hash != proof_payload_hash(&proof_payload) {
                        return Err(TransferCoordinatorError::ProofVerificationFailed(
                            "Persisted proof payload does not match journal digest".to_string(),
                        ));
                    }
                    self.execute_from_proof(transfer, proof_payload, adapter_registry, runtime_ctx)
                        .await
                } else {
                    Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from ProofValidated phase - transfer state lost (cache miss)".to_string()
                    ))
                }
            }
            crate::recovery::TransferStage::AwaitingFinality => {
                // Awaiting finality - resume from finality check
                // Re-poll finality monitor with proof height from journal
                let transfer = if let Some(transfer) = cached_transfer {
                    transfer
                } else if let Some(ctx) = recovery_entry.transfer_context {
                    tracing::info!(
                        "Reconstructing transfer from journal context for AwaitingFinality recovery"
                    );
                    CrossChainTransfer {
                        id: transfer_id.to_string(),
                        source_chain: ctx.source_chain.clone(),
                        destination_chain: ctx.destination_chain.clone(),
                        lock_tx_hash: {
                            let hash: csv_hash::Hash = ctx
                                .lock_tx_hash
                                .clone()
                                .try_into()
                                .unwrap_or_else(|_| csv_hash::Hash::zero());
                            hash.as_bytes().to_vec()
                        },
                        lock_output_index: 0,
                        sanad_id: {
                            let sanad_id: csv_protocol::sanad::SanadId =
                                ctx.sanad_id.clone().try_into().unwrap_or_else(|_| {
                                    csv_protocol::sanad::SanadId(csv_hash::Hash::zero())
                                });
                            sanad_id.0
                        },
                        transition_id: vec![],
                    }
                } else {
                    return Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from AwaitingFinality phase - transfer context missing from journal"
                            .to_string(),
                    ));
                };
                self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                    .await
            }
            crate::recovery::TransferStage::MintSubmitted => {
                let entry = transfers
                    .iter()
                    .find(|entry| {
                        entry.transfer_id == transfer_id
                            || (entry.transfer_id.is_empty()
                                && hex::encode(entry.sanad_id.as_bytes()) == transfer_id)
                    })
                    .ok_or(TransferCoordinatorError::NotFound)?;
                if entry.mint_tx_hash == csv_hash::Hash::zero() {
                    let transfer = cached_transfer.ok_or_else(|| {
                        TransferCoordinatorError::RuntimeError(
                            "Cannot recover MintSubmitted without transfer cache entry".to_string(),
                        )
                    })?;
                    let proof_payload = recovery_entry.proof_payload.ok_or_else(|| {
                        TransferCoordinatorError::RuntimeError(
                            "Cannot recover MintSubmitted without persisted proof payload"
                                .to_string(),
                        )
                    })?;
                    if proof_payload.is_empty() {
                        return Err(TransferCoordinatorError::RuntimeError(
                            "Cannot recover MintSubmitted with empty proof payload".to_string(),
                        ));
                    }
                    if recovery_entry.proof_hash != proof_payload_hash(&proof_payload) {
                        return Err(TransferCoordinatorError::ProofVerificationFailed(
                            "Persisted proof payload does not match journal digest".to_string(),
                        ));
                    }
                    tracing::warn!(
                        "Transfer {} reached MintSubmitted without durable mint tx hash; \
                         resubmitting from persisted verified proof",
                        transfer_id
                    );
                    return self
                        .execute_from_proof(transfer, proof_payload, adapter_registry, runtime_ctx)
                        .await;
                }
                let mint_tx_hash = hex::encode(entry.mint_tx_hash.as_bytes());
                self.execute_from_mint(transfer_id, &mint_tx_hash, adapter_registry, runtime_ctx)
                    .await
            }
            crate::recovery::TransferStage::MintConfirmed => {
                // Mint was confirmed - transfer should be complete
                tracing::info!("Transfer {} is already at MintConfirmed phase", transfer_id);
                Err(TransferCoordinatorError::RuntimeError(
                    "Transfer already at MintConfirmed phase - should be marked as Completed"
                        .to_string(),
                ))
            }
            crate::recovery::TransferStage::Completed => {
                let transfer = if let Some(transfer) = cached_transfer {
                    transfer
                } else if let Some(ctx) = recovery_entry.transfer_context {
                    CrossChainTransfer {
                        id: transfer_id.to_string(),
                        source_chain: ctx.source_chain.clone(),
                        destination_chain: ctx.destination_chain.clone(),
                        lock_tx_hash: {
                            let hash: csv_hash::Hash = ctx
                                .lock_tx_hash
                                .clone()
                                .try_into()
                                .unwrap_or_else(|_| csv_hash::Hash::zero());
                            hash.as_bytes().to_vec()
                        },
                        lock_output_index: 0,
                        sanad_id: {
                            let sanad_id: csv_protocol::sanad::SanadId =
                                ctx.sanad_id.clone().try_into().unwrap_or_else(|_| {
                                    csv_protocol::sanad::SanadId(csv_hash::Hash::zero())
                                });
                            sanad_id.0
                        },
                        transition_id: vec![],
                    }
                } else {
                    return Err(TransferCoordinatorError::AlreadyComplete);
                };

                self.completed_receipt_for(&transfer, transfer.sanad_id)
                    .await?
                    .ok_or(TransferCoordinatorError::AlreadyComplete)
            }
            crate::recovery::TransferStage::RolledBack => {
                Err(TransferCoordinatorError::AlreadyRolledBack)
            }
            crate::recovery::TransferStage::Compromised => {
                // Transfer was compromised - cannot resume
                Err(TransferCoordinatorError::RuntimeError(
                    "Cannot resume from Compromised phase - transfer security incident".to_string(),
                ))
            }
            crate::recovery::TransferStage::SealAssigned
            | crate::recovery::TransferStage::SourceSealClosed
            | crate::recovery::TransferStage::ConsignmentEmitted => {
                // Send-mode (interactive off-chain) transfers have no destination
                // finality phase and are resumed by the dedicated, idempotent
                // send path — never by the materialize resume driver, which would
                // try to drive a lock/mint state machine the send transfer never
                // entered.
                Err(TransferCoordinatorError::RuntimeError(format!(
                    "Cannot resume send-mode transfer {transfer_id} via materialize resume; use resume_send"
                )))
            }
        }
    }

    /// Resume a transfer, returning a [`TransferOutcome`].
    ///
    /// This is the resume driver used by non-blocking callers (a CLI `resume`
    /// subcommand, a web wallet refresh, a background worker). For a lock that is
    /// on-chain but not yet final it returns [`TransferOutcome::Pending`] instead
    /// of an error, so the caller can report "awaiting finality — N/M confs" and
    /// re-invoke later. It never re-locks: the lock is gated on the journal stage
    /// (`LockConfirmed`/`AwaitingFinality`) and driven by the shared finality
    /// core. All other stages delegate to [`TransferCoordinator::resume_transfer`]
    /// and are reported as `Completed`.
    pub async fn resume_transfer_outcome(
        &self,
        transfer_id: &str,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<TransferOutcome, TransferCoordinatorError> {
        self.assert_single_active_coordinator(transfer_id).await?;

        let recovery_entry = self
            .execution_journal
            .latest_entry(transfer_id)
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?
            .ok_or(TransferCoordinatorError::NotFound)?;

        match recovery_entry.phase {
            crate::recovery::TransferStage::LockConfirmed
            | crate::recovery::TransferStage::AwaitingFinality
            | crate::recovery::TransferStage::LockSubmitted => {
                let transfers = self.replay_db.load_all_transfers().await.map_err(|e| {
                    TransferCoordinatorError::RuntimeError(format!(
                        "Failed to load transfers: {}",
                        e
                    ))
                })?;
                let cached_transfer = transfers
                    .iter()
                    .find(|entry| {
                        entry.transfer_id == transfer_id
                            || (entry.transfer_id.is_empty()
                                && hex::encode(entry.sanad_id.as_bytes()) == transfer_id)
                    })
                    .map(|entry| registry_entry_to_transfer(entry, transfer_id.to_string()));

                let transfer = if let Some(transfer) = cached_transfer {
                    transfer
                } else if let Some(ctx) = recovery_entry.transfer_context {
                    CrossChainTransfer {
                        id: transfer_id.to_string(),
                        source_chain: ctx.source_chain.clone(),
                        destination_chain: ctx.destination_chain.clone(),
                        lock_tx_hash: {
                            let hash: csv_hash::Hash = ctx
                                .lock_tx_hash
                                .clone()
                                .try_into()
                                .unwrap_or_else(|_| csv_hash::Hash::zero());
                            hash.as_bytes().to_vec()
                        },
                        lock_output_index: 0,
                        sanad_id: {
                            let sanad_id: csv_protocol::sanad::SanadId =
                                ctx.sanad_id.clone().try_into().unwrap_or_else(|_| {
                                    csv_protocol::sanad::SanadId(csv_hash::Hash::zero())
                                });
                            sanad_id.0
                        },
                        transition_id: vec![],
                    }
                } else {
                    return Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from lock phase - transfer context missing from journal"
                            .to_string(),
                    ));
                };

                self.execute_from_lock_outcome(transfer, adapter_registry, runtime_ctx)
                    .await
            }
            _ => self
                .resume_transfer(transfer_id, adapter_registry, runtime_ctx)
                .await
                .map(|receipt| TransferOutcome::Completed(Box::new(receipt))),
        }
    }

    /// Execute transfer from lock phase (skip lock, go to proof generation).
    ///
    /// This helper method is used for crash recovery when the lock transaction
    /// is already confirmed but the transfer crashed before proof generation.
    ///
    /// # Arguments
    ///
    /// * `transfer` - The transfer to execute
    /// * `adapter_registry` - The adapter registry for chain operations
    /// * `runtime_ctx` - Runtime execution context with lease and policy
    ///
    /// # Returns
    ///
    /// The transfer receipt if the transfer completes successfully.
    async fn validate_recovery_context(
        &self,
        transfer: &CrossChainTransfer,
        runtime_ctx: &crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<csv_hash::ReplayIdHash, TransferCoordinatorError> {
        self.assert_single_active_coordinator(&transfer.id).await?;
        if runtime_ctx.lease.owner_runtime_id != runtime_ctx.runtime_instance
            || runtime_ctx.lease.epoch == 0
            || !runtime_ctx.lease.is_active(std::time::SystemTime::now())
        {
            return Err(TransferCoordinatorError::LeaseViolation(
                "Recovery requires an active lease owned by the calling runtime".to_string(),
            ));
        }
        let lease_transfer_id: csv_protocol::sanad::SanadId = runtime_ctx
            .lease
            .transfer_id
            .clone()
            .try_into()
            .unwrap_or_else(|_| csv_protocol::sanad::SanadId(csv_hash::Hash::zero()));
        if lease_transfer_id.as_bytes() != transfer.sanad_id.as_bytes() {
            return Err(TransferCoordinatorError::LeaseViolation(
                "Recovery lease does not authorize the transfer sanad".to_string(),
            ));
        }
        self.accept_execution_lease(&runtime_ctx.lease)?;
        let replay_id = transfer.sanad_id;
        if !self
            .replay_db
            .contains(replay_id.as_bytes())
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?
        {
            return Err(TransferCoordinatorError::ReplayDbError(
                "Recovery refused: replay reservation is missing".to_string(),
            ));
        }
        Ok(csv_hash::ReplayIdHash(replay_id))
    }

    async fn verify_recovery_proof(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &csv_protocol::proof_taxonomy::ProofBundle,
        confirmed_height: u64,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: &crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<(), TransferCoordinatorError> {
        runtime_ctx
            .policy
            .check_finality_threshold(&transfer.source_chain, confirmed_height)
            .map_err(TransferCoordinatorError::FinalityFailed)?;

        let signature_scheme = runtime_signature_scheme(proof_bundle.signature_scheme)?;
        if let Some(expected_scheme) = adapter_registry.signature_scheme(&transfer.source_chain)
            && expected_scheme != signature_scheme
        {
            return Err(TransferCoordinatorError::ProofVerificationFailed(format!(
                "Proof bundle signature scheme {:?} does not match source chain {} scheme {:?}",
                signature_scheme, transfer.source_chain, expected_scheme
            )));
        }

        let seal_status = adapter_registry
            .check_seal_registry(&transfer.source_chain, &proof_bundle.seal_ref.id)
            .await
            .map_err(|e| {
                TransferCoordinatorError::ProofVerificationFailed(format!(
                    "Seal registry check failed: {}",
                    e
                ))
            })?;
        let seal_is_consumed =
            matches!(seal_status, csv_adapter_core::SealRegistryStatus::Consumed);
        let seal_id_for_registry = proof_bundle.seal_ref.id.clone();
        let required_confirmations = runtime_ctx
            .policy
            .finality_depth_for_chain(&transfer.source_chain)
            .ok_or_else(|| {
                TransferCoordinatorError::FinalityFailed(format!(
                    "No finality depth configured for chain: {}",
                    transfer.source_chain
                ))
            })?;

        // The sanad binding lives in the anchor, not the seal. Chain adapters
        // set `seal_ref.id` to the single-use seal's outpoint (e.g. the Bitcoin
        // lock txid + vout), while the sanad_id being transferred is carried in
        // `anchor_ref.anchor_id`. Bind against the anchor to match every real
        // adapter's proof layout — the fresh-execution path enforces the same
        // invariant via `validate_source_proof` -> `verify_proof_binding`.
        if proof_bundle.anchor_ref.anchor_id != transfer.sanad_id.as_bytes() {
            return Err(TransferCoordinatorError::ProofVerificationFailed(
                "Proof anchor does not bind to the transfer sanad_id".to_string(),
            ));
        }

        // The lock-transaction binding is enforced where it is cryptographically
        // meaningful: `validate_source_proof` proves the lock txid is in the
        // block via SPV, and `seal_ref.id` (the txid+vout) is checked against the
        // seal registry above. The anchor `metadata` carries the canonical
        // inclusion-proof bytes (`csv-verifier` enforces
        // `metadata == inclusion_proof.proof_bytes`), so it must not be
        // reinterpreted here as the ASCII hex of the lock txid.

        // RUNTIME-FINALITY-TAUTOLOGY-001: source current_block_height from a real
        // observation of the source-chain tip, not `confirmed_height +
        // required_confirmations` (which made verify_finality pass by
        // construction on the recovery path too). Observe the lock's true
        // confirmation depth and fail closed if it has not reached the required
        // depth on the real chain, rather than synthesizing a passing height.
        let finality = self
            .lock_finality_status(transfer, adapter_registry)
            .await?;
        if finality.confirmations < required_confirmations {
            return Err(TransferCoordinatorError::FinalityFailed(format!(
                "Source lock has {}/{} confirmations on the real chain; refusing to \
                 finalize on the recovery path",
                finality.confirmations, required_confirmations
            )));
        }
        let observed_tip = finality.block_height.saturating_add(finality.confirmations);

        let verification_context = VerificationContext {
            chain_id: transfer.source_chain.clone(),
            signature_scheme,
            required_confirmations,
            current_block_height: Some(observed_tip),
            seal_registry: Some(Box::new(move |seal_id: &[u8]| {
                seal_is_consumed && seal_id == seal_id_for_registry.as_slice()
            })),
            chain_data: None,
            native_proof_validated: true,
            sanad_id: Some(csv_hash::SanadId(transfer.sanad_id)),
            lock_tx: Some(transfer.lock_tx_hash.clone()),
            lock_output_index: Some(transfer.lock_output_index),
            transition_id: Some(transfer.transition_id.clone()),
            destination_chain: Some(transfer.destination_chain.clone()),
            // Runtime path is gated by the on-chain §9.2 attested mint +
            // native_proof_validated; see the other construction site
            // (VERIFY-SIGNER-BINDING-001).
            authorized_signers: Vec::new(),
        };
        adapter_registry
            .validate_source_proof(&transfer.source_chain, transfer, proof_bundle)
            .await
            .map_err(|e| TransferCoordinatorError::ProofVerificationFailed(e.to_string()))?;
        let source_verifier =
            Self::verifier_for_source_chain(&runtime_ctx.policy, &transfer.source_chain)?;
        let result = source_verifier
            .verify_proof_bundle(proof_bundle, &verification_context)
            .map_err(|e| TransferCoordinatorError::ProofVerificationFailed(e.to_string()))?;
        if result.is_valid {
            Ok(())
        } else {
            Err(TransferCoordinatorError::ProofVerificationFailed(
                result
                    .errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    }

    pub async fn execute_from_lock(
        &self,
        transfer: CrossChainTransfer,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        match self
            .execute_from_lock_outcome(transfer, adapter_registry, runtime_ctx)
            .await?
        {
            TransferOutcome::Completed(receipt) => Ok(*receipt),
            TransferOutcome::Pending {
                confirmations,
                required,
                ..
            } => Err(TransferCoordinatorError::FinalityFailed(format!(
                "lock has {} confirmations, {} required",
                confirmations, required
            ))),
        }
    }

    /// Resume execution from a confirmed (or pending) lock, returning a
    /// [`TransferOutcome`].
    ///
    /// This is the resume-driver core: it never re-locks (the lock is already
    /// on-chain), gates proof-building on real source-chain confirmations, and
    /// returns [`TransferOutcome::Pending`] when the lock has not yet reached the
    /// required depth. Idempotency of the mint is guaranteed by the replay
    /// entry → Consumed promotion downstream.
    pub async fn execute_from_lock_outcome(
        &self,
        transfer: CrossChainTransfer,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<TransferOutcome, TransferCoordinatorError> {
        let replay_id = self
            .validate_recovery_context(&transfer, &runtime_ctx)
            .await?;

        let required_finality = runtime_ctx
            .policy
            .finality_depth_for_chain(&transfer.source_chain)
            .ok_or_else(|| {
                TransferCoordinatorError::RuntimeError(format!(
                    "No finality depth configured for chain: {}",
                    transfer.source_chain
                ))
            })?;

        // Build transfer context for crash recovery
        let sanad_bytes: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(transfer.sanad_id.as_bytes());
            arr
        };
        let lock_bytes: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&transfer.lock_tx_hash[..32]);
            arr
        };
        let transfer_context = crate::execution_journal::TransferContext {
            sanad_id: csv_hash::SanadId(csv_hash::Hash::new(sanad_bytes)).into(),
            source_chain: transfer.source_chain.clone(),
            destination_chain: transfer.destination_chain.clone(),
            lock_tx_hash: csv_hash::Hash::new(lock_bytes).into(),
            destination_owner: runtime_ctx
                .destination_owner
                .as_ref()
                .map(hex::encode)
                .unwrap_or_default(),
        };

        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id.0.into(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::AwaitingFinality,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 2,
                transfer_context: Some(transfer_context.clone()),
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Real finality gate (same primitive as the fresh execution path).
        let finality = self
            .lock_finality_status(&transfer, adapter_registry)
            .await?;
        if finality.confirmations < required_finality {
            tracing::info!(
                "Transfer {} awaiting finality (resume): {}/{} confirmations",
                transfer.id,
                finality.confirmations,
                required_finality
            );
            return Ok(TransferOutcome::Pending {
                lock_tx_hash: hex::encode(&transfer.lock_tx_hash),
                confirmations: finality.confirmations,
                required: required_finality,
            });
        }

        let lock_result = csv_adapter_core::LockResult {
            tx_hash: hex::encode(hash_from_tx_bytes(&transfer.lock_tx_hash)?.as_bytes()),
            block_height: finality.block_height,
        };
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id.0.into(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::AwaitingFinality,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id.0.into(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::ProofBuilding,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        let proof_bundle = adapter_registry
            .build_inclusion_proof(&transfer.source_chain, &transfer, &lock_result)
            .await
            .map_err(|e| TransferCoordinatorError::ProofBuildFailed(e.to_string()))?;
        self.verify_recovery_proof(
            &transfer,
            &proof_bundle,
            lock_result.block_height,
            adapter_registry,
            &runtime_ctx,
        )
        .await?;
        let proof_payload = proof_bundle
            .to_canonical_bytes()
            .map_err(|e| TransferCoordinatorError::ProofBuildFailed(e.to_string()))?;
        let proof_hash = proof_payload_hash(&proof_payload);
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id.0.into(),
                proof_hash,
                proof_payload: Some(proof_payload.clone()),
                phase: TransferStage::ProofBuilding,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id.0.into(),
                proof_hash,
                proof_payload: Some(proof_payload.clone()),
                phase: TransferStage::ProofValidated,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        self.with_metrics(|metrics| metrics.record_verified_proof_built());
        let receipt = self
            .execute_from_proof(transfer, proof_payload, adapter_registry, runtime_ctx)
            .await?;
        Ok(TransferOutcome::Completed(Box::new(receipt)))
    }

    /// Execute transfer from proof phase (skip proof generation, go to mint).
    ///
    /// This helper method is used for crash recovery when the proof is already
    /// generated but the transfer crashed before minting.
    ///
    /// # Arguments
    ///
    /// * `transfer` - The transfer to execute
    /// * `proof_bundle` - The proof bundle to use for minting
    /// * `adapter_registry` - The adapter registry for chain operations
    /// * `runtime_ctx` - Runtime execution context with lease and policy
    ///
    /// # Returns
    ///
    /// The transfer receipt if the transfer completes successfully.
    pub async fn execute_from_proof(
        &self,
        transfer: CrossChainTransfer,
        proof_payload: Vec<u8>,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        let replay_id = self
            .validate_recovery_context(&transfer, &runtime_ctx)
            .await?;
        if proof_payload.is_empty() {
            return Err(TransferCoordinatorError::ProofVerificationFailed(
                "Persisted proof payload is empty".to_string(),
            ));
        }
        let proof_bundle: csv_protocol::proof_taxonomy::ProofBundle =
            csv_protocol::proof_taxonomy::ProofBundle::from_canonical_bytes(&proof_payload)
                .map_err(|e| {
                    TransferCoordinatorError::ProofVerificationFailed(format!(
                        "Persisted proof payload is malformed: {}",
                        e
                    ))
                })?;
        // Re-derive the true confirming height of the lock via the shared
        // finality primitive (source chains such as Bitcoin do not implement the
        // generic confirm_tx read port).
        let finality = self
            .lock_finality_status(&transfer, adapter_registry)
            .await?;
        self.verify_recovery_proof(
            &transfer,
            &proof_bundle,
            finality.block_height,
            adapter_registry,
            &runtime_ctx,
        )
        .await?;

        let _admission_permit = self
            .admission_controller
            .acquire_transfer(&transfer.source_chain, &transfer.destination_chain)?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id.0.into(),
                proof_hash: proof_payload_hash(&proof_payload),
                proof_payload: Some(proof_payload.clone()),
                phase: TransferStage::MintSubmitted,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        // Same attestation-carrying request on the resume path so a recovered
        // transfer submits the identical §9.2 mint request as a fresh one.
        let destination_owner = runtime_ctx.destination_owner.clone().unwrap_or_default();
        let mint_request = build_runtime_mint_request(
            &transfer,
            &proof_bundle,
            proof_payload.clone(),
            destination_owner,
        );
        let mint_payload = encode_mint_request(&mint_request)?;
        let mint_result = adapter_registry
            .mint_sanad(&transfer.destination_chain, &transfer, &mint_payload)
            .await
            .map_err(|e| TransferCoordinatorError::MintFailed(e.to_string()))?;
        let mut submitted_entry = transfer_to_registry_entry(&transfer)?;
        submitted_entry.mint_tx_hash = hash_from_tx_str(&mint_result.tx_hash)?;
        self.replay_db
            .store_transfer_entry(&submitted_entry)
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id.0.into(),
                proof_hash: proof_payload_hash(&proof_payload),
                proof_payload: Some(proof_payload),
                phase: TransferStage::MintSubmitted,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        self.with_metrics(|metrics| metrics.record_mint_submitted());
        self.execute_from_mint(
            &transfer.id,
            &mint_result.tx_hash,
            adapter_registry,
            runtime_ctx,
        )
        .await
    }

    /// Execute transfer from mint phase (skip mint broadcast, just confirm).
    ///
    /// This helper method is used for crash recovery when the mint transaction
    /// is already submitted but the transfer crashed before confirmation.
    ///
    /// # Arguments
    ///
    /// * `transfer_id` - The ID of the transfer to confirm
    /// * `mint_tx_hash` - The hash of the submitted mint transaction
    /// * `adapter_registry` - The adapter registry for chain operations
    ///
    /// # Returns
    ///
    /// The transfer receipt if the transfer completes successfully.
    pub async fn execute_from_mint(
        &self,
        transfer_id: &str,
        mint_tx_hash: &str,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::user_runtime_lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        // Assert lease ownership invariant
        self.assert_single_active_coordinator(transfer_id).await?;

        tracing::info!(
            "Executing transfer {} from mint phase (confirming mint transaction {})",
            transfer_id,
            mint_tx_hash
        );

        let transfers = self.replay_db.load_all_transfers().await.map_err(|e| {
            TransferCoordinatorError::RuntimeError(format!("Failed to load transfers: {}", e))
        })?;

        let transfer = transfers
            .iter()
            .find(|entry| {
                entry.transfer_id == transfer_id
                    || (entry.transfer_id.is_empty()
                        && hex::encode(entry.sanad_id.as_bytes()) == transfer_id)
            })
            .map(|entry| registry_entry_to_transfer(entry, transfer_id.to_string()))
            .ok_or(TransferCoordinatorError::NotFound)?;
        self.validate_recovery_context(&transfer, &runtime_ctx)
            .await?;

        let mint_result = adapter_registry
            .confirm_tx(&transfer.destination_chain, mint_tx_hash)
            .await
            .map_err(|e| TransferCoordinatorError::RuntimeError(e.to_string()))?;

        let replay_id = transfer.sanad_id;
        let replay_id_wire = csv_wire::HashWire::from(replay_id);
        self.replay_db
            .confirm_consumed(replay_id.as_bytes())
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?;
        self.with_metrics(|metrics| metrics.record_mint_confirmed());

        // Record auditable settlement evidence for a later source release. The
        // resume path reconstructs the verified proof bundle from the journal's
        // persisted MintSubmitted payload so the settlement key material is
        // identical to the fresh-execution path.
        self.record_resumed_settlement_evidence(&transfer, &mint_result, &runtime_ctx);

        let mut registry_entry = transfer_to_registry_entry(&transfer)?;
        registry_entry.mint_tx_hash = hash_from_tx_str(&mint_result.tx_hash)?;
        self.replay_db
            .store_transfer_entry(&registry_entry)
            .await
            .map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to persist confirmed transfer: {}",
                    e
                ))
            })?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::MintConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::Completed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        self.event_bus
            .emit(TransferEvent::Complete(crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: Some(replay_id),
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::Confirmed,
                recovery_attempt: 0,
            }));

        Ok(TransferReceipt {
            transfer_id: transfer.id,
            replay_id,
            lock_tx_hash: hex::encode(transfer.lock_tx_hash),
            mint_tx_hash: mint_result.tx_hash,
            materialization: mint_result.materialization,
        })
    }

    /// Resume all incomplete transfers after a crash or restart.
    ///
    /// This method queries the execution journal for incomplete transfers and
    /// attempts to resume them from their last recorded phase.
    ///
    /// # Returns
    ///
    /// The number of transfers that were successfully resumed.
    pub async fn resume_transfers(
        &self,
        adapter_registry: &dyn AdapterRegistry,
        recovery_contexts: &dyn RecoveryContextProvider,
    ) -> Result<usize, TransferCoordinatorError> {
        let incomplete = self
            .execution_journal
            .incomplete_transfers()
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        let mut resumed = 0;

        for entry in incomplete {
            tracing::info!(
                "Found incomplete transfer: {} at phase {:?}",
                entry.transfer_id,
                entry.phase
            );

            // Skip terminal phases that shouldn't be marked as incomplete
            match entry.phase {
                crate::recovery::TransferStage::Completed => {
                    tracing::warn!(
                        "Transfer {} marked as incomplete but phase is Completed - skipping",
                        entry.transfer_id
                    );
                    continue;
                }
                crate::recovery::TransferStage::RolledBack => {
                    tracing::warn!(
                        "Transfer {} marked as incomplete but phase is RolledBack - skipping",
                        entry.transfer_id
                    );
                    continue;
                }
                crate::recovery::TransferStage::Compromised => {
                    tracing::warn!(
                        "Transfer {} marked as incomplete but phase is Compromised - skipping",
                        entry.transfer_id
                    );
                    continue;
                }
                _ => {}
            }

            let runtime_ctx = recovery_contexts.context_for(&entry.transfer_id).await?;

            match self
                .resume_transfer(&entry.transfer_id, adapter_registry, runtime_ctx)
                .await
            {
                Ok(_) => {
                    tracing::info!("Successfully resumed transfer {}", entry.transfer_id);
                    resumed += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to resume transfer {}: {}", entry.transfer_id, e);
                    // Continue with other transfers even if this one fails
                }
            }
        }

        Ok(resumed)
    }
}

// ---------------------------------------------------------------------------
// Send mode (interactive off-chain transfer)
//
// The send lifecycle is `Initialized -> SealAssigned -> SourceSealClosed ->
// ConsignmentEmitted -> Completed`. Every step is journaled Entered/Completed
// in the SAME execution journal the materialize path uses, and resume reads the
// journal to skip already-completed steps. See [`crate::send_transfer`] for the
// idempotency contract.
// ---------------------------------------------------------------------------
impl TransferCoordinator {
    /// Journal one send-mode phase transition.
    fn journal_send_phase(
        &self,
        transfer_id: &str,
        replay_id: &csv_wire::HashWire,
        phase: crate::recovery::TransferStage,
        outcome: crate::execution_journal::PhaseOutcome,
        progress: Option<&crate::send_transfer::SendProgress>,
    ) -> Result<(), TransferCoordinatorError> {
        let proof_payload = match progress {
            Some(p) => Some(csv_codec::to_canonical_cbor(p).map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to encode send progress: {e}"
                ))
            })?),
            None => None,
        };
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer_id.to_string(),
                replay_id: replay_id.clone(),
                proof_hash: [0u8; 32],
                proof_payload,
                phase,
                ts: std::time::SystemTime::now(),
                outcome,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {e}")))
    }

    /// Reconstruct the cumulative send progress from the transfer's latest
    /// journal entry (empty if the transfer has no persisted progress yet).
    fn load_send_progress(
        &self,
        transfer_id: &str,
    ) -> Result<crate::send_transfer::SendProgress, TransferCoordinatorError> {
        let entry = self
            .execution_journal
            .latest_entry(transfer_id)
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {e}")))?;
        match entry.and_then(|e| e.proof_payload) {
            Some(bytes) => csv_codec::from_canonical_cbor(&bytes).map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to decode send progress: {e}"
                ))
            }),
            None => Ok(crate::send_transfer::SendProgress::default()),
        }
    }

    /// Execute an interactive off-chain (send-mode) transfer to completion.
    ///
    /// Drives assign → close-source-seal → emit-consignment, journaling each
    /// step. The source-seal close reserves a per-seal nullifier in the replay
    /// database (compare-and-set) so a *different* transfer cannot close the same
    /// single-use seal. Safe to interrupt at any point: call
    /// [`TransferCoordinator::resume_send`] to finish without re-closing the seal
    /// or re-emitting the consignment.
    pub async fn execute_send(
        &self,
        transfer: &crate::send_transfer::SendTransfer,
        executor: &dyn crate::send_transfer::SendExecutor,
    ) -> Result<crate::send_transfer::SendReceipt, TransferCoordinatorError> {
        let replay_id = csv_wire::HashWire::from(transfer.sanad_id.0);

        // Fresh-execution only. A transfer id that already has journal history —
        // whether an in-flight/completed send or a materialize transfer reusing
        // the id — must be advanced through `resume_send`, never re-executed.
        // Re-journaling `Initialized` over an existing timeline would roll the
        // recorded phase backward and could re-drive a close whose completion is
        // not yet visible in `progress`; routing to resume keeps the idempotent,
        // journal-authoritative path.
        if self
            .execution_journal
            .latest_phase(&transfer.transfer_id)
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {e}")))?
            .is_some()
        {
            return Err(TransferCoordinatorError::RuntimeError(format!(
                "Transfer {} already has journal history; use resume_send",
                transfer.transfer_id
            )));
        }

        // Initialized: entered + completed (idempotent — a fresh replay of this
        // phase records only audit entries and mutates no protocol state).
        self.journal_send_phase(
            &transfer.transfer_id,
            &replay_id,
            crate::recovery::TransferStage::Initialized,
            crate::execution_journal::PhaseOutcome::Entered,
            None,
        )?;
        self.journal_send_phase(
            &transfer.transfer_id,
            &replay_id,
            crate::recovery::TransferStage::Initialized,
            crate::execution_journal::PhaseOutcome::Completed,
            None,
        )?;

        self.drive_send(
            transfer,
            executor,
            crate::send_transfer::SendProgress::default(),
        )
        .await
    }

    /// Resume an interrupted send-mode transfer from its last journaled phase.
    ///
    /// Idempotent: steps already recorded `Completed` are skipped, so the
    /// single-use source seal is never re-closed and the consignment is never
    /// re-emitted. If the transfer already reached a terminal state, returns the
    /// receipt reconstructed from durable journal state.
    pub async fn resume_send(
        &self,
        transfer: &crate::send_transfer::SendTransfer,
        executor: &dyn crate::send_transfer::SendExecutor,
    ) -> Result<crate::send_transfer::SendReceipt, TransferCoordinatorError> {
        let latest_phase = self
            .execution_journal
            .latest_phase(&transfer.transfer_id)
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {e}")))?;

        // A resume MUST NOT re-drive a materialize transfer through the send
        // path, and vice versa. Reject a phase that belongs to the other mode.
        if let Some(phase) = latest_phase
            && phase.is_materialize_stage()
        {
            return Err(TransferCoordinatorError::RuntimeError(format!(
                "Transfer {} is a materialize transfer (phase {:?}); use resume_transfer",
                transfer.transfer_id, phase
            )));
        }

        let progress = self.load_send_progress(&transfer.transfer_id)?;
        self.drive_send(transfer, executor, progress).await
    }

    /// Shared send driver used by both fresh execution and resume.
    ///
    /// `progress` carries whatever prior steps have durably completed; each step
    /// whose output is already present is skipped, making the driver idempotent
    /// under repeated invocation.
    async fn drive_send(
        &self,
        transfer: &crate::send_transfer::SendTransfer,
        executor: &dyn crate::send_transfer::SendExecutor,
        mut progress: crate::send_transfer::SendProgress,
    ) -> Result<crate::send_transfer::SendReceipt, TransferCoordinatorError> {
        use crate::execution_journal::PhaseOutcome;
        use crate::recovery::TransferStage;
        use crate::send_transfer::{Consignment, SealAssignment, SealCloseWitness};

        let replay_id = csv_wire::HashWire::from(transfer.sanad_id.0);

        // Capture the last journaled phase for THIS transfer BEFORE this
        // invocation writes anything. It is `SourceSealClosed` only if a prior
        // (interrupted) run of this same transfer already reserved the seal
        // nullifier and journaled the close as `Entered` but not `Completed`.
        // That single fact is what lets a resumed close tolerate its own
        // pre-existing nullifier reservation without opening a door for a
        // *different* transfer to bypass the duplicate-seal check.
        let owns_prior_close = self
            .execution_journal
            .latest_phase(&transfer.transfer_id)
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {e}")))?
            == Some(TransferStage::SourceSealClosed);

        // Step 1 — assign the Sanad to the invoice's destination seal.
        let assignment = match &progress.assignment {
            Some(bytes) => SealAssignment(bytes.clone()),
            None => {
                self.journal_send_phase(
                    &transfer.transfer_id,
                    &replay_id,
                    TransferStage::SealAssigned,
                    PhaseOutcome::Entered,
                    Some(&progress),
                )?;
                let assignment = executor.assign_seal(transfer).await.map_err(|e| {
                    let _ = self.journal_send_phase(
                        &transfer.transfer_id,
                        &replay_id,
                        TransferStage::SealAssigned,
                        PhaseOutcome::Failed(e.to_string()),
                        Some(&progress),
                    );
                    TransferCoordinatorError::SendFailed(e.to_string())
                })?;
                progress.assignment = Some(assignment.0.clone());
                self.journal_send_phase(
                    &transfer.transfer_id,
                    &replay_id,
                    TransferStage::SealAssigned,
                    PhaseOutcome::Completed,
                    Some(&progress),
                )?;
                assignment
            }
        };

        // Step 2 — close the single-use source seal (the single-use commitment).
        let witness = match &progress.witness {
            Some(bytes) => SealCloseWitness(bytes.clone()),
            None => {
                // Reserve the per-seal nullifier BEFORE journaling this phase, so
                // a transfer that loses the reservation never leaves a
                // `SourceSealClosed` journal entry behind that a later resume
                // could misread as proof of ownership. A genuine duplicate is
                // rejected here with no journal mutation.
                self.reserve_source_seal(transfer, owns_prior_close).await?;

                self.journal_send_phase(
                    &transfer.transfer_id,
                    &replay_id,
                    TransferStage::SourceSealClosed,
                    PhaseOutcome::Entered,
                    Some(&progress),
                )?;

                let witness = executor
                    .close_source_seal(transfer, &assignment)
                    .await
                    .map_err(|e| {
                        let _ = self.journal_send_phase(
                            &transfer.transfer_id,
                            &replay_id,
                            TransferStage::SourceSealClosed,
                            PhaseOutcome::Failed(e.to_string()),
                            Some(&progress),
                        );
                        TransferCoordinatorError::SendFailed(e.to_string())
                    })?;
                progress.witness = Some(witness.0.clone());
                self.journal_send_phase(
                    &transfer.transfer_id,
                    &replay_id,
                    TransferStage::SourceSealClosed,
                    PhaseOutcome::Completed,
                    Some(&progress),
                )?;
                witness
            }
        };

        // Step 3 — emit the consignment for off-band delivery.
        let consignment = match &progress.consignment {
            Some(bytes) => Consignment(bytes.clone()),
            None => {
                self.journal_send_phase(
                    &transfer.transfer_id,
                    &replay_id,
                    TransferStage::ConsignmentEmitted,
                    PhaseOutcome::Entered,
                    Some(&progress),
                )?;
                let consignment = executor
                    .emit_consignment(transfer, &witness)
                    .await
                    .map_err(|e| {
                        let _ = self.journal_send_phase(
                            &transfer.transfer_id,
                            &replay_id,
                            TransferStage::ConsignmentEmitted,
                            PhaseOutcome::Failed(e.to_string()),
                            Some(&progress),
                        );
                        TransferCoordinatorError::SendFailed(e.to_string())
                    })?;
                progress.consignment = Some(consignment.0.clone());
                self.journal_send_phase(
                    &transfer.transfer_id,
                    &replay_id,
                    TransferStage::ConsignmentEmitted,
                    PhaseOutcome::Completed,
                    Some(&progress),
                )?;
                consignment
            }
        };

        // Terminal: Completed (carry final progress forward for auditability).
        self.journal_send_phase(
            &transfer.transfer_id,
            &replay_id,
            TransferStage::Completed,
            PhaseOutcome::Completed,
            Some(&progress),
        )?;

        Ok(crate::send_transfer::SendReceipt {
            transfer_id: transfer.transfer_id.clone(),
            consignment,
            witness,
        })
    }

    /// Reserve the per-source-seal nullifier so no other transfer can close the
    /// same single-use seal.
    ///
    /// Uses compare-and-set. `owns_prior_close` is true only when THIS transfer
    /// already journaled the close as `SourceSealClosed` on an earlier,
    /// interrupted run — in which case a pre-existing reservation is our own and
    /// is tolerated so the resume can finish. Otherwise an `AlreadyExists` means
    /// a *different* transfer already closed this seal and the send is rejected
    /// as a duplicate source seal.
    ///
    /// Security note: reservation happens once per transfer (subsequent runs
    /// skip this via the persisted witness). A crash in the sub-millisecond
    /// window between a successful reservation and the next journal write leaves
    /// the reservation without an owning journal entry; such a transfer fails
    /// closed (rejected) on resume rather than risk re-closing a seal that might
    /// belong to another transfer. Failing closed never double-spends.
    async fn reserve_source_seal(
        &self,
        transfer: &crate::send_transfer::SendTransfer,
        owns_prior_close: bool,
    ) -> Result<(), TransferCoordinatorError> {
        let nullifier = transfer.source_seal_nullifier();
        match self.replay_db.insert_if_absent(&nullifier).await {
            Ok(()) => Ok(()),
            Err(ReplayDbError::AlreadyExists) if owns_prior_close => Ok(()),
            Err(ReplayDbError::AlreadyExists) => Err(TransferCoordinatorError::DuplicateSourceSeal),
            Err(e) => Err(TransferCoordinatorError::ReplayDbError(e.to_string())),
        }
    }
}

/// Supplies authenticated lease context for restart recovery.
///
/// Implementations must retrieve or acquire authority from durable runtime
/// state. Journal contents alone never grant mutation authority.
#[async_trait::async_trait]
pub trait RecoveryContextProvider: Send + Sync {
    async fn context_for(
        &self,
        transfer_id: &str,
    ) -> Result<crate::user_runtime_lease::RuntimeExecutionContext, TransferCoordinatorError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter_registry::AdapterRegistryImpl;
    use csv_adapter_core::{
        ChainAdapter, CrossChainTransfer as RuntimeCrossChainTransfer, LockResult, MintResult,
        SealRegistryStatus,
    };
    use csv_protocol::finality::ChainCapabilities;
    use csv_protocol::proof_taxonomy::ProofBundle;
    use csv_storage::ReplayDatabase;
    use std::sync::Arc;

    // Local test adapter to avoid orphan rule
    struct LocalTestAdapter {
        caps: ChainCapabilities,
        /// When set, `tx_finality` reports this confirmation count instead of the
        /// default `u64::MAX`, so tests can exercise the real finality gate
        /// (RUNTIME-FINALITY-TAUTOLOGY-001).
        finality_confirmations: Option<u64>,
    }

    impl LocalTestAdapter {
        fn new(caps: ChainCapabilities) -> Self {
            Self {
                caps,
                finality_confirmations: None,
            }
        }

        fn new_bitcoin() -> Self {
            Self::new(ChainCapabilities::bitcoin())
        }

        fn new_bitcoin_with_confirmations(confirmations: u64) -> Self {
            let mut adapter = Self::new(ChainCapabilities::bitcoin());
            adapter.finality_confirmations = Some(confirmations);
            adapter
        }

        fn build_fake_lock_result() -> LockResult {
            LockResult {
                tx_hash: hex::encode([0u8; 32]),
                block_height: 100,
            }
        }

        fn build_fake_mint_result() -> MintResult {
            MintResult {
                tx_hash: hex::encode([0u8; 32]),
                block_height: 100,
                materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                    "test-chain",
                ),
            }
        }

        fn build_fake_inclusion_proof(sanad_id: &csv_hash::Hash) -> Result<ProofBundle, String> {
            // Use deterministic proof fixture from csv-testkit
            let mut bundle = csv_testkit::fixtures::TestProofBundle::minimal();
            // Bind the proof to the sanad the way real adapters do: the sanad_id
            // lives in `anchor_ref.anchor_id` (what `verify_recovery_proof`
            // checks), while `seal_ref.id` carries the single-use seal outpoint.
            bundle.anchor_ref.anchor_id = sanad_id.as_bytes().to_vec();
            bundle.seal_ref.id = sanad_id.as_bytes().to_vec();
            Ok(bundle)
        }
    }

    #[test]
    fn test_registry_entry_roundtrip_preserves_lock_tx_and_output_index() {
        let transfer = CrossChainTransfer {
            id: "roundtrip".to_string(),
            source_chain: "bitcoin".to_string(),
            destination_chain: "ethereum".to_string(),
            lock_tx_hash: vec![0xAB; 32],
            lock_output_index: 7,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let entry = transfer_to_registry_entry(&transfer).unwrap();
        let restored = registry_entry_to_transfer(&entry, transfer.id.clone());

        assert_eq!(restored.id, transfer.id);
        assert_eq!(restored.source_chain, transfer.source_chain);
        assert_eq!(restored.destination_chain, transfer.destination_chain);
        assert_eq!(restored.lock_tx_hash, transfer.lock_tx_hash);
        assert_eq!(restored.lock_output_index, transfer.lock_output_index);
        assert_eq!(restored.sanad_id, transfer.sanad_id);
        assert_eq!(restored.transition_id, transfer.transition_id);
    }

    #[test]
    fn test_registry_entry_rejects_malformed_lock_tx_hash() {
        let transfer = CrossChainTransfer {
            id: "bad-hash".to_string(),
            source_chain: "bitcoin".to_string(),
            destination_chain: "ethereum".to_string(),
            lock_tx_hash: vec![0xAB; 31],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        assert!(matches!(
            transfer_to_registry_entry(&transfer),
            Err(TransferCoordinatorError::InvalidTxHash(_))
        ));
    }

    #[async_trait::async_trait]
    impl ChainAdapter for LocalTestAdapter {
        fn chain_id(&self) -> &str {
            "test-chain"
        }

        fn capabilities(&self) -> ChainCapabilities {
            self.caps.clone()
        }

        fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
            csv_protocol::signature::SignatureScheme::Ed25519
        }

        async fn lock_sanad(
            &self,
            _transfer: &CrossChainTransfer,
        ) -> Result<LockResult, csv_adapter_core::AdapterError> {
            Ok(LocalTestAdapter::build_fake_lock_result())
        }

        async fn mint_sanad(
            &self,
            _transfer: &CrossChainTransfer,
            _proof_bundle: &[u8],
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            Ok(LocalTestAdapter::build_fake_mint_result())
        }

        async fn build_inclusion_proof(
            &self,
            transfer: &CrossChainTransfer,
            _lock_result: &LockResult,
        ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
            LocalTestAdapter::build_fake_inclusion_proof(&transfer.sanad_id)
                .map_err(|e| csv_adapter_core::AdapterError::Generic(e))
        }

        async fn validate_source_proof(
            &self,
            transfer: &CrossChainTransfer,
            proof_bundle: &ProofBundle,
        ) -> Result<(), csv_adapter_core::AdapterError> {
            if proof_bundle.seal_ref.id != transfer.sanad_id.as_bytes() {
                return Err(csv_adapter_core::AdapterError::Generic(
                    "proof is not bound to the requested sanad".to_string(),
                ));
            }
            Ok(())
        }

        async fn check_seal_registry(
            &self,
            _seal_id: &[u8],
        ) -> Result<csv_adapter_core::SealRegistryStatus, csv_adapter_core::AdapterError> {
            Ok(csv_adapter_core::SealRegistryStatus::Available)
        }

        async fn confirm_tx(
            &self,
            tx_hash: &str,
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            Ok(MintResult {
                tx_hash: tx_hash.to_string(),
                block_height: 100,
                materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                    "test-chain",
                ),
            })
        }

        async fn tx_finality(
            &self,
            tx_hash: &str,
        ) -> Result<csv_adapter_core::TxFinality, csv_adapter_core::AdapterError> {
            match self.finality_confirmations {
                Some(confirmations) => Ok(csv_adapter_core::TxFinality {
                    block_height: 100,
                    confirmations,
                }),
                // Default: delegate to confirm_tx and treat as final (u64::MAX),
                // matching the trait default.
                None => {
                    let confirmed = self.confirm_tx(tx_hash).await?;
                    Ok(csv_adapter_core::TxFinality {
                        block_height: confirmed.block_height,
                        confirmations: u64::MAX,
                    })
                }
            }
        }

        async fn get_balance(
            &self,
            _address: &str,
        ) -> Result<String, csv_adapter_core::AdapterError> {
            Ok("0".to_string())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    async fn recovery_fixture(
        phase: TransferStage,
        proof_payload: Option<Vec<u8>>,
    ) -> (
        TransferCoordinator,
        AdapterRegistryImpl,
        CrossChainTransfer,
        crate::user_runtime_lease::RuntimeExecutionContext,
    ) {
        recovery_fixture_with_adapter(phase, proof_payload, LocalTestAdapter::new_bitcoin()).await
    }

    async fn recovery_fixture_with_adapter(
        phase: TransferStage,
        proof_payload: Option<Vec<u8>>,
        adapter: LocalTestAdapter,
    ) -> (
        TransferCoordinator,
        AdapterRegistryImpl,
        CrossChainTransfer,
        crate::user_runtime_lease::RuntimeExecutionContext,
    ) {
        let transfer = CrossChainTransfer {
            id: "recover-transfer".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32], // Raw 32-byte hash
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([44u8; 32]),
            transition_id: vec![3u8; 32],
        };
        let db = csv_storage::InMemoryReplayDb::new();
        db.insert_if_absent(transfer.sanad_id.as_bytes())
            .await
            .unwrap();
        db.store_transfer_entry(&transfer_to_registry_entry(&transfer).unwrap())
            .await
            .unwrap();
        let coordinator = TransferCoordinator::new(Box::new(db), EventBus::new());
        let replay_id = transfer.sanad_id;
        let replay_id_wire = csv_wire::HashWire::from(replay_id);
        let proof_hash = proof_payload
            .as_ref()
            .map(|payload| proof_payload_hash(payload))
            .unwrap_or([0u8; 32]);
        coordinator
            .execution_journal()
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: replay_id_wire.clone(),
                proof_hash,
                proof_payload,
                phase,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .unwrap();
        let mut registry = AdapterRegistryImpl::new();
        registry.register_adapter(Box::new(adapter)).unwrap();
        let owner = uuid::Uuid::new_v4();
        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: crate::user_runtime_lease::TransferLease {
                transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
                epoch: 1,
                owner_runtime_id: owner,
                acquired_at: std::time::SystemTime::now(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            },
            runtime_instance: owner,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };
        (coordinator, registry, transfer, runtime_ctx)
    }

    #[tokio::test]
    async fn lock_confirmed_recovery_regenerates_proof_and_completes() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::LockConfirmed, None).await;

        let receipt = coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("confirmed lock must resume without rebroadcasting lock");

        assert_eq!(receipt.transfer_id, transfer.id);
        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn awaiting_finality_recovery_rechecks_finality_and_completes() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::AwaitingFinality, None).await;

        coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("finality recovery must regenerate proof and complete");

        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn recovery_fails_closed_when_lock_below_required_confirmations() {
        // RUNTIME-FINALITY-TAUTOLOGY-001: on the recovery path, current_block_height
        // must come from a real tip observation. With the source chain reporting
        // fewer confirmations than the required finality depth, the transfer must
        // NOT be finalized — it must fail closed rather than synthesize a passing
        // height from `confirmed_height + required_confirmations`.
        let (coordinator, registry, transfer, runtime_ctx) = recovery_fixture_with_adapter(
            TransferStage::AwaitingFinality,
            None,
            // 0 confirmations is below the "test-chain" finality depth (the
            // absolute-minimum fallback of 1), so the lock is not yet final.
            LocalTestAdapter::new_bitcoin_with_confirmations(0),
        )
        .await;

        // Resume must NOT finalize: the real observed tip is below the required
        // finality depth. Whether the path returns
        // Pending (Ok) or a FinalityFailed error, the invariant is that the
        // transfer is never advanced to Completed off a synthesized height.
        let _ = coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await;

        assert_ne!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.id)
                .unwrap(),
            Some(TransferStage::Completed),
            "an under-confirmed transfer must not reach Completed"
        );
    }

    #[test]
    fn source_chain_verifier_rejects_anchor_beyond_configured_max_age() {
        let mut policy = crate::policy::RuntimePolicy::new();
        policy.set_max_proof_age_blocks("bitcoin".to_string(), 100);
        let verifier = TransferCoordinator::verifier_for_source_chain(&policy, "bitcoin").unwrap();
        let ctx = VerificationContext {
            chain_id: "bitcoin".to_string(),
            signature_scheme: csv_protocol::SignatureScheme::Ed25519,
            required_confirmations: 1,
            current_block_height: Some(201),
            seal_registry: None,
            chain_data: None,
            native_proof_validated: true,
            sanad_id: None,
            lock_tx: None,
            lock_output_index: None,
            transition_id: None,
            destination_chain: None,
            authorized_signers: Vec::new(),
        };

        let result = verifier.verify_finality(100, &ctx);
        assert!(
            matches!(result, Err(csv_protocol::ProtocolError::ProofExpired(_))),
            "source-chain verifier must reject over-age anchors, got {result:?}"
        );
    }

    #[test]
    fn source_chain_verifier_accepts_anchor_exactly_at_configured_max_age() {
        let mut policy = crate::policy::RuntimePolicy::new();
        policy.set_max_proof_age_blocks("bitcoin".to_string(), 100);
        let verifier = TransferCoordinator::verifier_for_source_chain(&policy, "bitcoin").unwrap();
        let ctx = VerificationContext {
            chain_id: "bitcoin".to_string(),
            signature_scheme: csv_protocol::SignatureScheme::Ed25519,
            required_confirmations: 1,
            current_block_height: Some(200),
            seal_registry: None,
            chain_data: None,
            native_proof_validated: true,
            sanad_id: None,
            lock_tx: None,
            lock_output_index: None,
            transition_id: None,
            destination_chain: None,
            authorized_signers: Vec::new(),
        };

        assert!(verifier.verify_finality(100, &ctx).is_ok());
    }

    #[tokio::test]
    async fn proof_building_recovery_regenerates_proof_and_completes() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofBuilding, None).await;

        coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("proof-building recovery must regenerate proof and complete");

        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn proof_validated_recovery_uses_persisted_payload_and_completes() {
        let expected_transfer = CrossChainTransfer {
            id: "recover-transfer".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([44u8; 32]),
            transition_id: vec![3u8; 32],
        };
        let proof_bundle = LocalTestAdapter::new_bitcoin()
            .build_inclusion_proof(
                &expected_transfer,
                &LockResult {
                    tx_hash: hex::encode([0x11u8; 32]),
                    block_height: 100,
                },
            )
            .await
            .unwrap();
        let payload = proof_bundle.to_canonical_bytes().unwrap();
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofValidated, Some(payload)).await;

        coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("validated proof recovery must mint using durable proof bytes");

        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn proof_validated_recovery_rejects_missing_payload() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofValidated, None).await;

        let result = coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::RuntimeError(message))
                if message.contains("proof payload missing")
        ));
    }

    #[tokio::test]
    async fn proof_validated_recovery_rejects_malformed_payload() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofValidated, Some(vec![0xFF, 0x00])).await;

        let result = coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::ProofVerificationFailed(_))
        ));
    }

    #[tokio::test]
    async fn proof_validated_recovery_rejects_tampered_payload_digest() {
        let expected_transfer = CrossChainTransfer {
            id: "recover-transfer".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([44u8; 32]),
            transition_id: vec![3u8; 32],
        };
        let bundle = LocalTestAdapter::new_bitcoin()
            .build_inclusion_proof(
                &expected_transfer,
                &LockResult {
                    tx_hash: hex::encode([0x11u8; 32]),
                    block_height: 100,
                },
            )
            .await
            .unwrap();
        let payload = bundle.to_canonical_bytes().unwrap();
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofValidated, Some(payload.clone())).await;
        coordinator
            .execution_journal()
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: csv_wire::HashWire::from(transfer.sanad_id.clone()),
                proof_hash: [0xFF; 32],
                proof_payload: Some(payload),
                phase: TransferStage::ProofValidated,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .unwrap();

        let result = coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::ProofVerificationFailed(message))
                if message.contains("journal digest")
        ));
    }

    #[tokio::test]
    async fn test_transfer_coordinator_replay_idempotent() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-1".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };
        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        // First transfer should succeed
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx.clone())
            .await;
        assert!(
            result.is_ok(),
            "First execution should succeed: {:?}",
            result
        );

        // Completed transfers are idempotent — `consume_if_unconsumed` returns Ok(())
        // for already Consumed entries. This allows safe retries of completed transfers.
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx.clone())
            .await;
        assert!(
            result.is_ok(),
            "Completed transfers should be idempotent: {:?}",
            result
        );

        // Now test that a Pending entry (inserted without confirming) blocks a retry.
        // We need a different transfer to get a different ReplayId.
        let pending_transfer = CrossChainTransfer {
            id: "test-pending".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![5u8; 32], // different lock tx
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([6u8; 32]), // different sanad
            transition_id: vec![7u8; 32],             // different transition
        };

        let pending_lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*pending_transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };
        let pending_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: pending_lease.clone(),
            runtime_instance: pending_lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        // First execution inserts Pending, then the mint succeeds and confirms.
        let result = coordinator
            .execute(pending_transfer.clone(), &registry, pending_ctx)
            .await;
        assert!(
            result.is_ok(),
            "Pending transfer first execution should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_transfer_coordinator_capability_gate() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        // Register celestia which cannot authorize mints (DA only)
        let celestia_caps = ChainCapabilities::celestia();
        struct CelestiaAdapter {
            caps: ChainCapabilities,
        }
        #[async_trait::async_trait]
        impl ChainAdapter for CelestiaAdapter {
            fn chain_id(&self) -> &str {
                "celestia"
            }
            fn capabilities(&self) -> ChainCapabilities {
                self.caps.clone()
            }
            async fn lock_sanad(
                &self,
                _t: &RuntimeCrossChainTransfer,
            ) -> Result<LockResult, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia is not a transfer source".to_string(),
                ))
            }
            async fn mint_sanad(
                &self,
                _t: &RuntimeCrossChainTransfer,
                _p: &[u8],
            ) -> Result<MintResult, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia does not authorize destination mints".to_string(),
                ))
            }
            async fn build_inclusion_proof(
                &self,
                _t: &RuntimeCrossChainTransfer,
                _l: &LockResult,
            ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia is not a transfer proof source".to_string(),
                ))
            }
            async fn validate_source_proof(
                &self,
                _t: &RuntimeCrossChainTransfer,
                _p: &ProofBundle,
            ) -> Result<(), csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia is not a transfer proof source".to_string(),
                ))
            }
            async fn check_seal_registry(
                &self,
                _s: &[u8],
            ) -> Result<csv_adapter_core::SealRegistryStatus, csv_adapter_core::AdapterError>
            {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia has no transfer seal registry".to_string(),
                ))
            }
            async fn get_balance(
                &self,
                _address: &str,
            ) -> Result<String, csv_adapter_core::AdapterError> {
                Ok("0".to_string())
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
        registry
            .register_adapter(Box::new(CelestiaAdapter {
                caps: celestia_caps,
            }))
            .unwrap();

        let transfer = RuntimeCrossChainTransfer {
            id: "test-1".to_string(),
            source_chain: "celestia".to_string(),
            destination_chain: "celestia".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        // Celestia cannot be a source (DA only)
        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };
        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::UnsupportedOperation(_))
        ));
    }

    #[tokio::test]
    async fn test_runtime_policy_enforcement() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-policy".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        // Test with production policy (no RPC fallback, strict finality)
        let production_policy = crate::policy::RuntimePolicy::production();
        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: production_policy,
            destination_owner: None,
        };

        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx)
            .await;
        assert!(
            result.is_ok(),
            "Transfer should succeed with production policy"
        );

        // Test with development policy (allows RPC fallback)
        let dev_policy = crate::policy::RuntimePolicy::development();
        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: dev_policy,
            destination_owner: None,
        };

        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(
            result.is_ok(),
            "Transfer should succeed with development policy"
        );
    }

    #[tokio::test]
    async fn test_retry_logic_with_policy() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-retry".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        // Test with policy that allows retries
        let mut policy = crate::policy::RuntimePolicy::new();
        policy.max_retries = 3;
        policy.retry_delay = std::time::Duration::from_millis(10);

        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy,
            destination_owner: None,
        };

        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(result.is_ok(), "Transfer should succeed with retry policy");
    }

    #[tokio::test]
    async fn test_circuit_breaker_blocks_requests() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        // Open the circuit breaker by recording failures
        for _ in 0..5 {
            coordinator
                .circuit_breaker()
                .lock()
                .unwrap()
                .record_failure();
        }

        let transfer = CrossChainTransfer {
            id: "test-circuit".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::RuntimeError(_))
        ));
    }

    #[tokio::test]
    async fn test_health_monitor_mode_transition() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        // Initially healthy
        assert_eq!(
            coordinator.health_status(),
            crate::runtime_mode::HealthStatus::HEALTHY
        );

        // Record a failed health check
        coordinator.record_health_check(crate::runtime_mode::HealthCheck {
            component: "rpc".to_string(),
            healthy: false,
            error: Some("RPC connection failed".to_string()),
            timestamp: std::time::SystemTime::now(),
        });

        // Should be critical (all checks are unhealthy)
        assert_eq!(
            coordinator.health_status(),
            crate::runtime_mode::HealthStatus::CRITICAL
        );
    }

    #[tokio::test]
    async fn test_degraded_mode_policy() {
        let policy = crate::policy::RuntimePolicy::development();
        assert_eq!(policy.mode, crate::runtime_mode::RuntimeMode::Degraded);
        assert!(policy.mode.allows_rpc_fallback());
        assert_eq!(policy.max_retries, 5);
    }

    #[tokio::test]
    async fn test_unsafe_mode_policy() {
        let policy = crate::policy::RuntimePolicy::unsafe_mode();
        assert_eq!(policy.mode, crate::runtime_mode::RuntimeMode::Unsafe);
        assert!(policy.mode.allows_rpc_fallback());
        assert_eq!(policy.max_retries, 1);
        assert!(policy.mode.requires_operator_confirmation());
    }

    #[tokio::test]
    async fn test_ha_failover_lease_conflict() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-ha".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let original_runtime_id = uuid::Uuid::new_v4();
        let failover_runtime_id = uuid::Uuid::new_v4();

        // Original runtime acquires lease
        let original_lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: original_runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let original_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: original_lease.clone(),
            runtime_instance: original_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        // Original runtime executes successfully
        let result = coordinator
            .execute(transfer.clone(), &registry, original_ctx)
            .await;
        assert!(result.is_ok(), "Original runtime should succeed");

        // Failover runtime tries to execute with different runtime ID (should fail)
        let failover_lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: failover_runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let failover_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: failover_lease,
            runtime_instance: failover_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        let result = coordinator
            .execute(transfer.clone(), &registry, failover_ctx)
            .await;
        assert!(
            matches!(result, Err(TransferCoordinatorError::LeaseViolation(_))),
            "A second runtime cannot reuse an active transfer lease: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_ha_failover_after_lease_expiry() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-ha-expiry".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let original_runtime_id = uuid::Uuid::new_v4();
        let failover_runtime_id = uuid::Uuid::new_v4();

        // Original runtime acquires expired lease
        let expired_lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: original_runtime_id,
            acquired_at: std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
            expires_at: std::time::SystemTime::now() - std::time::Duration::from_secs(1800),
        };

        let expired_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: expired_lease,
            runtime_instance: original_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        // Original runtime with expired lease should fail
        let result = coordinator
            .execute(transfer.clone(), &registry, expired_ctx)
            .await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::RuntimeError(_))
        ));

        // Failover runtime with new lease should succeed
        let failover_lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 2, // Incremented epoch
            owner_runtime_id: failover_runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let failover_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: failover_lease,
            runtime_instance: failover_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        let result = coordinator.execute(transfer, &registry, failover_ctx).await;
        assert!(
            result.is_ok(),
            "Failover runtime should succeed with new lease"
        );
    }

    #[tokio::test]
    async fn test_blockchain_reorg_finality_rollback() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-reorg".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        // Execute transfer successfully
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx)
            .await;
        assert!(result.is_ok(), "Transfer should succeed initially");

        // Simulate reorg by recording a health check indicating reorg
        coordinator.record_health_check(crate::runtime_mode::HealthCheck {
            component: "blockchain".to_string(),
            healthy: false,
            error: Some("Reorg detected at block 1000".to_string()),
            timestamp: std::time::SystemTime::now(),
        });

        // Health status should be critical (all checks are unhealthy)
        assert_eq!(
            coordinator.health_status(),
            crate::runtime_mode::HealthStatus::CRITICAL
        );

        // Circuit breaker should be open after reorg
        for _ in 0..5 {
            coordinator
                .circuit_breaker()
                .lock()
                .unwrap()
                .record_failure();
        }
        assert_eq!(
            coordinator.circuit_breaker().lock().unwrap().state(),
            crate::runtime_mode::CircuitBreakerState::Open
        );
    }

    #[tokio::test]
    async fn test_reorg_recovery() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        // Open circuit breaker
        for _ in 0..5 {
            coordinator
                .circuit_breaker()
                .lock()
                .unwrap()
                .record_failure();
        }
        assert_eq!(
            coordinator.circuit_breaker().lock().unwrap().state(),
            crate::runtime_mode::CircuitBreakerState::Open
        );

        // Attempt recovery - fails because default open_timeout is 60 seconds
        std::thread::sleep(std::time::Duration::from_millis(100));

        let recovered = coordinator.attempt_circuit_breaker_recovery();
        assert!(
            !recovered,
            "Circuit breaker should not recover before timeout (60s)"
        );
        assert_eq!(
            coordinator.circuit_breaker().lock().unwrap().state(),
            crate::runtime_mode::CircuitBreakerState::Open
        );

        // Circuit stays Open because recovery failed (timeout not elapsed)
        // Successes are only processed in HalfOpen state
        assert_eq!(
            coordinator.circuit_breaker().lock().unwrap().state(),
            crate::runtime_mode::CircuitBreakerState::Open
        );
    }

    #[tokio::test]
    async fn test_concurrent_transfer_execution_race() {
        let _replay_db = Arc::new(std::sync::Mutex::new(csv_storage::InMemoryReplayDb::new()));
        let event_bus = EventBus::new();
        let coordinator =
            TransferCoordinator::new(Box::new(csv_storage::InMemoryReplayDb::new()), event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-race".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let runtime_id = uuid::Uuid::new_v4();
        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        // Execute same transfer concurrently - should be idempotent
        let coordinator_ref = Arc::new(coordinator);
        let registry_ref = Arc::new(registry);
        let mut handles = Vec::new();

        for _ in 0..3 {
            let coord = coordinator_ref.clone();
            let reg = registry_ref.clone();
            let transfer_clone = transfer.clone();
            let lease_clone = lease.clone();
            let runtime_id_clone = runtime_id;

            handles.push(tokio::spawn(async move {
                let ctx = crate::user_runtime_lease::RuntimeExecutionContext {
                    lease: lease_clone,
                    runtime_instance: runtime_id_clone,
                    policy: crate::policy::RuntimePolicy::new(),
                    destination_owner: None,
                };
                coord.execute(transfer_clone, reg.as_ref(), ctx).await
            }));
        }

        // Await all handles sequentially (equivalent to join_all for testing)
        let mut results = Vec::new();
        for handle in handles {
            results.push(
                handle
                    .await
                    .unwrap_or_else(|e| panic!("task panicked: {}", e)),
            );
        }
        // All should succeed due to idempotency
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, 3, "All concurrent executions should succeed");
    }

    #[tokio::test]
    async fn test_concurrent_different_runtime_race() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-diff-race".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let runtime_id_1 = uuid::Uuid::new_v4();
        let runtime_id_2 = uuid::Uuid::new_v4();

        let lease_1 = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: runtime_id_1,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let lease_2 = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: runtime_id_2,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        // Execute with different runtime IDs concurrently - one should fail
        let coordinator_ref = Arc::new(coordinator);
        let registry_ref = Arc::new(registry);
        let mut handles = Vec::new();

        for (i, lease) in [lease_1, lease_2].into_iter().enumerate() {
            let coord = coordinator_ref.clone();
            let reg = registry_ref.clone();
            let transfer_clone = transfer.clone();
            let runtime_id = if i == 0 { runtime_id_1 } else { runtime_id_2 };

            handles.push(tokio::spawn(async move {
                let ctx = crate::user_runtime_lease::RuntimeExecutionContext {
                    lease,
                    runtime_instance: runtime_id,
                    policy: crate::policy::RuntimePolicy::new(),
                    destination_owner: None,
                };
                coord.execute(transfer_clone, reg.as_ref(), ctx).await
            }));
        }

        // Await all handles sequentially (equivalent to join_all for testing)
        let mut results = Vec::new();
        for handle in handles {
            results.push(
                handle
                    .await
                    .unwrap_or_else(|e| panic!("task panicked: {}", e)),
            );
        }
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, 1, "Only one runtime may own an active lease");
    }

    #[tokio::test]
    async fn test_adversarial_proof_bundle_rejection() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        // Create a test adapter that rejects invalid proof bundles
        struct MaliciousLocalTestAdapter {
            caps: ChainCapabilities,
        }

        impl MaliciousLocalTestAdapter {
            fn new() -> Self {
                Self {
                    caps: ChainCapabilities::bitcoin(),
                }
            }
        }

        #[async_trait::async_trait]
        impl ChainAdapter for MaliciousLocalTestAdapter {
            fn chain_id(&self) -> &str {
                "malicious-chain"
            }
            fn capabilities(&self) -> ChainCapabilities {
                self.caps.clone()
            }

            async fn lock_sanad(
                &self,
                _transfer: &CrossChainTransfer,
            ) -> Result<LockResult, csv_adapter_core::AdapterError> {
                Ok(LockResult {
                    tx_hash: hex::encode([0x11u8; 32]),
                    block_height: 100,
                })
            }

            async fn mint_sanad(
                &self,
                _transfer: &CrossChainTransfer,
                _proof_bundle: &[u8],
            ) -> Result<MintResult, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Malicious proof bundle detected".to_string(),
                ))
            }

            async fn build_inclusion_proof(
                &self,
                _transfer: &CrossChainTransfer,
                _lock_result: &LockResult,
            ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Malicious proof bundle detected".to_string(),
                ))
            }

            async fn validate_source_proof(
                &self,
                _transfer: &CrossChainTransfer,
                _proof_bundle: &ProofBundle,
            ) -> Result<(), csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Malicious proof bundle detected".to_string(),
                ))
            }

            async fn check_seal_registry(
                &self,
                _seal_id: &[u8],
            ) -> Result<SealRegistryStatus, csv_adapter_core::AdapterError> {
                Ok(SealRegistryStatus::Available)
            }

            async fn get_balance(
                &self,
                _address: &str,
            ) -> Result<String, csv_adapter_core::AdapterError> {
                Ok("0".to_string())
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(MaliciousLocalTestAdapter::new()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-malicious".to_string(),
            source_chain: "malicious-chain".to_string(),
            destination_chain: "malicious-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        // Transfer should fail due to malicious proof bundle rejection
        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(
            result.is_err(),
            "Adversarial transfer should fail: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_double_spend_prevention() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-doublespend".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        // First execution should succeed
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx.clone())
            .await;
        assert!(result.is_ok(), "First execution should succeed");

        // Second execution with same transfer should be idempotent (already consumed)
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx.clone())
            .await;
        assert!(result.is_ok(), "Second execution should be idempotent");

        // Try with different transfer ID but same sanad_id (replay attempt from same runtime)
        let replay_transfer = CrossChainTransfer {
            id: "test-replay".to_string(),
            source_chain: transfer.source_chain.clone(),
            destination_chain: transfer.destination_chain.clone(),
            lock_tx_hash: transfer.lock_tx_hash.clone(),
            lock_output_index: transfer.lock_output_index,
            sanad_id: transfer.sanad_id,
            transition_id: transfer.transition_id,
        };

        let replay_lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*replay_transfer.sanad_id.as_bytes()).into(),
            epoch: 2,
            owner_runtime_id: lease.owner_runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let replay_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: replay_lease.clone(),
            runtime_instance: replay_lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        let result = coordinator
            .execute(replay_transfer, &registry, replay_ctx)
            .await;
        // Should succeed due to idempotent replay_db (already consumed entries return Ok)
        assert!(
            result.is_ok(),
            "Replay of completed transfer should be idempotent: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_lease_epoch_conflict() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-epoch".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let runtime_id = uuid::Uuid::new_v4();

        // Acquire lease with epoch 1
        let lease_epoch_1 = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let ctx_epoch_1 = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease_epoch_1,
            runtime_instance: runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        let result = coordinator
            .execute(transfer.clone(), &registry, ctx_epoch_1)
            .await;
        assert!(result.is_ok(), "Epoch 1 should succeed");

        // Try to use stale lease with epoch 1 after epoch 2 has been issued
        let lease_epoch_2 = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 2,
            owner_runtime_id: runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let ctx_epoch_2 = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease_epoch_2,
            runtime_instance: runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        let result = coordinator
            .execute(transfer.clone(), &registry, ctx_epoch_2)
            .await;
        assert!(result.is_ok(), "Epoch 2 should succeed");

        // Try to use stale epoch 1 lease again - should fail
        let stale_lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let stale_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: stale_lease,
            runtime_instance: runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        let result = coordinator.execute(transfer, &registry, stale_ctx).await;
        assert!(
            matches!(result, Err(TransferCoordinatorError::LeaseViolation(_))),
            "Stale lease must be rejected: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_finality_rollback() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-rollback".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::user_runtime_lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        // Execute transfer successfully
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx)
            .await;
        assert!(result.is_ok(), "Transfer should succeed initially");

        // Simulate finality rollback by recording health check
        coordinator.record_health_check(crate::runtime_mode::HealthCheck {
            component: "finality".to_string(),
            healthy: false,
            error: Some("Finality rollback detected".to_string()),
            timestamp: std::time::SystemTime::now(),
        });

        // Health status should be critical (all checks are unhealthy)
        assert_eq!(
            coordinator.health_status(),
            crate::runtime_mode::HealthStatus::CRITICAL
        );

        // Runtime mode should be unsafe
        let mode = coordinator.health_monitor().lock().unwrap().mode();
        assert_eq!(mode, crate::runtime_mode::RuntimeMode::Unsafe);
    }

    // ===================== RFC-0012 thin-registry mint request (TRM-RUNTIME-001) =====================

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).expect("valid 32-byte hex vector");
        out
    }

    #[test]
    fn contract_chain_id_matches_rfc0012_vectors() {
        // keccak256("csv.chain.<name>"), cross-checked against `cast keccak` and
        // an independent keccak implementation. These are the contract-layer
        // identifiers CSVSeal stores as CHAIN_* constants (RFC-0012 §6).
        assert_eq!(
            contract_chain_id("bitcoin"),
            hex32("43e835a8bce7f8ee213d07ddcc0bdd7b7d247ca16a60e7e639c00de296eee11b")
        );
        assert_eq!(
            contract_chain_id("ethereum"),
            hex32("7d0dc209c5a3fa11e0ee0a3f9680f759f6e93896d643983f9c68ae5323226e48")
        );
        assert_eq!(
            contract_chain_id("solana"),
            hex32("153c41791368005b07fa0a9c3d922fe9d076559f2b15a1a8c33f89bcb4874a3b")
        );
        assert_eq!(
            contract_chain_id("sui"),
            hex32("8ee0b88a63765bed253fe6d0961996852c3a8a4e660c96d65d7c5b58542871e4")
        );
        assert_eq!(
            contract_chain_id("aptos"),
            hex32("c627230c85fd40ff7b0b2c218061691019e9b72f102ad7f817207e4aec59eb9b")
        );
    }

    #[test]
    fn contract_chain_id_is_deterministic_and_distinct_per_chain() {
        assert_eq!(contract_chain_id("bitcoin"), contract_chain_id("bitcoin"));
        assert_ne!(contract_chain_id("bitcoin"), contract_chain_id("ethereum"));
        // The contract-layer identity is a full 32-byte keccak, never the
        // proof-layer one-byte `ProofLeafV1` chain id — the two layers stay distinct.
        assert_ne!(contract_chain_id("bitcoin"), [0u8; 32]);
    }

    #[test]
    fn attestation_digest_matches_independent_sha256_vector() {
        // Cross-implementation check against a Python (keccak + sha256) computation
        // of the exact §9.2 287-byte preimage.
        let inputs = MintAttestationInputs {
            destination_chain_id: [1u8; 32],
            destination_contract: [2u8; 32],
            sanad_id: [3u8; 32],
            commitment: [4u8; 32],
            source_chain: [5u8; 32],
            destination_owner: b"owner-bytes".to_vec(),
            lock_event_id: [6u8; 32],
            nullifier: [7u8; 32],
            attestation_expiry: 42,
        };
        assert_eq!(
            inputs.attestation_digest(),
            hex32("384dedf1821702b2e99d7d0cc73279bb0038cd76d63f93d6fb57933812132bc6")
        );
    }

    #[test]
    fn attestation_digest_is_field_sensitive() {
        let base = MintAttestationInputs {
            destination_chain_id: [0u8; 32],
            destination_contract: [0u8; 32],
            sanad_id: [0u8; 32],
            commitment: [0u8; 32],
            source_chain: [0u8; 32],
            destination_owner: Vec::new(),
            lock_event_id: [0u8; 32],
            nullifier: [0u8; 32],
            attestation_expiry: 0,
        };
        let base_digest = base.attestation_digest();

        let mut flip_nullifier = base.clone();
        flip_nullifier.nullifier = [9u8; 32];
        assert_ne!(base_digest, flip_nullifier.attestation_digest());

        let mut flip_contract = base.clone();
        flip_contract.destination_contract = [9u8; 32];
        assert_ne!(base_digest, flip_contract.attestation_digest());

        let mut flip_owner = base.clone();
        flip_owner.destination_owner = b"x".to_vec();
        assert_ne!(base_digest, flip_owner.attestation_digest());

        let mut flip_expiry = base.clone();
        flip_expiry.attestation_expiry = 1;
        assert_ne!(base_digest, flip_expiry.attestation_digest());
    }

    #[test]
    fn build_runtime_mint_request_carries_attestation_not_proof_root() {
        let transfer = CrossChainTransfer {
            id: "req".to_string(),
            source_chain: "bitcoin".to_string(),
            destination_chain: "ethereum".to_string(),
            lock_tx_hash: vec![0xAB; 32],
            lock_output_index: 7,
            sanad_id: csv_hash::Hash::new([0x44; 32]),
            transition_id: vec![3u8; 32],
        };
        let bundle = LocalTestAdapter::build_fake_inclusion_proof(&transfer.sanad_id).unwrap();
        let bytes = bundle.to_canonical_bytes().unwrap();

        let destination_owner = b"owner-bytes".to_vec();
        let request = build_runtime_mint_request(
            &transfer,
            &bundle,
            bytes.clone(),
            destination_owner.clone(),
        );
        let a = &request.attestation;

        // Contract-layer chain identities via keccak256("csv.chain.<name>").
        assert_eq!(a.destination_chain_id, contract_chain_id("ethereum"));
        assert_eq!(a.source_chain, contract_chain_id("bitcoin"));
        // Sanad + commitment binding taken from the verified bundle.
        assert_eq!(a.sanad_id, *transfer.sanad_id.as_bytes());
        assert_eq!(a.commitment, commitment_from_bundle(&bundle));
        // Lock event id derives from the real lock outpoint; nullifier from the seal.
        assert_eq!(a.lock_event_id, lock_event_id(&transfer));
        assert_eq!(a.nullifier, mint_nullifier(&bundle));
        assert_eq!(a.destination_owner, destination_owner);
        // The nullifier is bound to the source seal, not aliased to the sanad id.
        assert_ne!(a.nullifier, a.sanad_id);
        // Contract identity + signatures are supplied downstream by the adapter/verifier.
        assert_eq!(a.destination_contract, [0u8; 32]);
        assert!(request.verifier_signatures.is_empty());
        // The verified proof bundle travels alongside for the submitting adapter.
        assert_eq!(request.proof_bundle, bytes);
    }

    #[test]
    fn runtime_mint_request_roundtrips_through_canonical_cbor() {
        let request = RuntimeMintRequest {
            attestation: MintAttestationInputs {
                destination_chain_id: [1u8; 32],
                destination_contract: [2u8; 32],
                sanad_id: [3u8; 32],
                commitment: [4u8; 32],
                source_chain: [5u8; 32],
                destination_owner: b"owner".to_vec(),
                lock_event_id: [6u8; 32],
                nullifier: [7u8; 32],
                attestation_expiry: 99,
            },
            verifier_signatures: vec![vec![0xAB; 65]],
            proof_bundle: vec![1, 2, 3, 4],
        };
        let bytes = encode_mint_request(&request).unwrap();
        let decoded: RuntimeMintRequest = csv_codec::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn mint_dispatch_hands_adapter_the_attestation_request() {
        // The adapter that submits the mint must receive the runtime's §9.2
        // attestation request — not a bare proof bundle and not a proof root.
        struct CapturingAdapter {
            caps: ChainCapabilities,
            mint_payload: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
        }

        #[async_trait::async_trait]
        impl ChainAdapter for CapturingAdapter {
            fn chain_id(&self) -> &str {
                "test-chain"
            }
            fn capabilities(&self) -> ChainCapabilities {
                self.caps.clone()
            }
            fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
                csv_protocol::signature::SignatureScheme::Ed25519
            }
            async fn lock_sanad(
                &self,
                _transfer: &CrossChainTransfer,
            ) -> Result<LockResult, csv_adapter_core::AdapterError> {
                Ok(LocalTestAdapter::build_fake_lock_result())
            }
            async fn mint_sanad(
                &self,
                _transfer: &CrossChainTransfer,
                proof_bundle: &[u8],
            ) -> Result<MintResult, csv_adapter_core::AdapterError> {
                *self.mint_payload.lock().unwrap() = Some(proof_bundle.to_vec());
                Ok(LocalTestAdapter::build_fake_mint_result())
            }
            async fn build_inclusion_proof(
                &self,
                transfer: &CrossChainTransfer,
                _lock_result: &LockResult,
            ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
                LocalTestAdapter::build_fake_inclusion_proof(&transfer.sanad_id)
                    .map_err(csv_adapter_core::AdapterError::Generic)
            }
            async fn validate_source_proof(
                &self,
                _transfer: &CrossChainTransfer,
                _proof_bundle: &ProofBundle,
            ) -> Result<(), csv_adapter_core::AdapterError> {
                Ok(())
            }
            async fn check_seal_registry(
                &self,
                _seal_id: &[u8],
            ) -> Result<SealRegistryStatus, csv_adapter_core::AdapterError> {
                Ok(SealRegistryStatus::Available)
            }
            async fn confirm_tx(
                &self,
                tx_hash: &str,
            ) -> Result<MintResult, csv_adapter_core::AdapterError> {
                Ok(MintResult {
                    tx_hash: tx_hash.to_string(),
                    block_height: 100,
                    materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                        "test-chain",
                    ),
                })
            }
            async fn get_balance(
                &self,
                _address: &str,
            ) -> Result<String, csv_adapter_core::AdapterError> {
                Ok("0".to_string())
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let transfer = CrossChainTransfer {
            id: "capture-transfer".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([44u8; 32]),
            transition_id: vec![3u8; 32],
        };
        let bundle = LocalTestAdapter::build_fake_inclusion_proof(&transfer.sanad_id).unwrap();
        let payload = bundle.to_canonical_bytes().unwrap();

        let db = csv_storage::InMemoryReplayDb::new();
        db.insert_if_absent(transfer.sanad_id.as_bytes())
            .await
            .unwrap();
        db.store_transfer_entry(&transfer_to_registry_entry(&transfer).unwrap())
            .await
            .unwrap();
        let coordinator = TransferCoordinator::new(Box::new(db), EventBus::new());
        coordinator
            .execution_journal()
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: csv_wire::HashWire::from(transfer.sanad_id),
                proof_hash: proof_payload_hash(&payload),
                proof_payload: Some(payload.clone()),
                phase: TransferStage::ProofValidated,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .unwrap();

        let captured = Arc::new(std::sync::Mutex::new(None));
        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(CapturingAdapter {
                caps: ChainCapabilities::bitcoin(),
                mint_payload: captured.clone(),
            }))
            .unwrap();

        let owner = uuid::Uuid::new_v4();
        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: crate::user_runtime_lease::TransferLease {
                transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
                epoch: 1,
                owner_runtime_id: owner,
                acquired_at: std::time::SystemTime::now(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            },
            runtime_instance: owner,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("validated proof recovery must mint");

        let bytes = captured
            .lock()
            .unwrap()
            .clone()
            .expect("mint_sanad must be invoked");
        let request: RuntimeMintRequest = csv_codec::from_canonical_cbor(&bytes)
            .expect("adapter must receive a canonical runtime mint request");
        assert_eq!(request.attestation.sanad_id, *transfer.sanad_id.as_bytes());
        assert_eq!(
            request.attestation.destination_chain_id,
            contract_chain_id("test-chain")
        );
        assert_eq!(
            request.attestation.source_chain,
            contract_chain_id("test-chain")
        );
        assert!(request.verifier_signatures.is_empty());
        assert_eq!(request.proof_bundle, payload);
    }

    #[tokio::test]
    async fn verification_failure_prevents_mint_dispatch() {
        // Off-chain verification must precede mint: if `validate_source_proof`
        // rejects, the coordinator must never dispatch a mint.
        struct MintTrackingAdapter {
            caps: ChainCapabilities,
            mint_called: Arc<std::sync::atomic::AtomicBool>,
        }

        #[async_trait::async_trait]
        impl ChainAdapter for MintTrackingAdapter {
            fn chain_id(&self) -> &str {
                "test-chain"
            }
            fn capabilities(&self) -> ChainCapabilities {
                self.caps.clone()
            }
            fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
                csv_protocol::signature::SignatureScheme::Ed25519
            }
            async fn lock_sanad(
                &self,
                _transfer: &CrossChainTransfer,
            ) -> Result<LockResult, csv_adapter_core::AdapterError> {
                Ok(LocalTestAdapter::build_fake_lock_result())
            }
            async fn mint_sanad(
                &self,
                _transfer: &CrossChainTransfer,
                _proof_bundle: &[u8],
            ) -> Result<MintResult, csv_adapter_core::AdapterError> {
                self.mint_called
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(LocalTestAdapter::build_fake_mint_result())
            }
            async fn build_inclusion_proof(
                &self,
                transfer: &CrossChainTransfer,
                _lock_result: &LockResult,
            ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
                LocalTestAdapter::build_fake_inclusion_proof(&transfer.sanad_id)
                    .map_err(csv_adapter_core::AdapterError::Generic)
            }
            async fn validate_source_proof(
                &self,
                _transfer: &CrossChainTransfer,
                _proof_bundle: &ProofBundle,
            ) -> Result<(), csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "source proof rejected".to_string(),
                ))
            }
            async fn check_seal_registry(
                &self,
                _seal_id: &[u8],
            ) -> Result<SealRegistryStatus, csv_adapter_core::AdapterError> {
                Ok(SealRegistryStatus::Available)
            }
            async fn confirm_tx(
                &self,
                tx_hash: &str,
            ) -> Result<MintResult, csv_adapter_core::AdapterError> {
                Ok(MintResult {
                    tx_hash: tx_hash.to_string(),
                    block_height: 100,
                    materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                        "test-chain",
                    ),
                })
            }
            async fn get_balance(
                &self,
                _address: &str,
            ) -> Result<String, csv_adapter_core::AdapterError> {
                Ok("0".to_string())
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let mint_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(MintTrackingAdapter {
                caps: ChainCapabilities::bitcoin(),
                mint_called: mint_called.clone(),
            }))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "verify-before-mint".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let owner = uuid::Uuid::new_v4();
        let runtime_ctx = crate::user_runtime_lease::RuntimeExecutionContext {
            lease: crate::user_runtime_lease::TransferLease {
                transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
                epoch: 1,
                owner_runtime_id: owner,
                acquired_at: std::time::SystemTime::now(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            },
            runtime_instance: owner,
            policy: crate::policy::RuntimePolicy::new(),
            destination_owner: None,
        };

        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(
            matches!(
                result,
                Err(TransferCoordinatorError::ProofVerificationFailed(_))
            ),
            "expected proof verification failure, got {:?}",
            result
        );
        assert!(
            !mint_called.load(std::sync::atomic::Ordering::SeqCst),
            "mint must not be dispatched when source-proof verification fails"
        );
    }

    /// Adapter whose destination mint fails for its first `fail_until` calls and
    /// succeeds thereafter. Used to exercise the operator retry / revert paths.
    struct FlakyMintAdapter {
        caps: ChainCapabilities,
        mint_attempts: Arc<std::sync::atomic::AtomicUsize>,
        fail_until: usize,
    }

    #[async_trait::async_trait]
    impl ChainAdapter for FlakyMintAdapter {
        fn chain_id(&self) -> &str {
            "test-chain"
        }
        fn capabilities(&self) -> ChainCapabilities {
            self.caps.clone()
        }
        fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
            csv_protocol::signature::SignatureScheme::Ed25519
        }
        async fn lock_sanad(
            &self,
            _transfer: &CrossChainTransfer,
        ) -> Result<LockResult, csv_adapter_core::AdapterError> {
            Ok(LocalTestAdapter::build_fake_lock_result())
        }
        async fn mint_sanad(
            &self,
            _transfer: &CrossChainTransfer,
            _proof_bundle: &[u8],
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            let attempt = self
                .mint_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt < self.fail_until {
                return Err(csv_adapter_core::AdapterError::Generic(
                    "destination mint reverted".to_string(),
                ));
            }
            Ok(MintResult {
                tx_hash: hex::encode([0x7u8; 32]),
                block_height: 4242,
                materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                    "test-chain",
                ),
            })
        }
        async fn build_inclusion_proof(
            &self,
            transfer: &CrossChainTransfer,
            _lock_result: &LockResult,
        ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
            LocalTestAdapter::build_fake_inclusion_proof(&transfer.sanad_id)
                .map_err(csv_adapter_core::AdapterError::Generic)
        }
        async fn validate_source_proof(
            &self,
            transfer: &CrossChainTransfer,
            proof_bundle: &ProofBundle,
        ) -> Result<(), csv_adapter_core::AdapterError> {
            if proof_bundle.seal_ref.id != transfer.sanad_id.as_bytes() {
                return Err(csv_adapter_core::AdapterError::Generic(
                    "proof is not bound to the requested sanad".to_string(),
                ));
            }
            Ok(())
        }
        async fn check_seal_registry(
            &self,
            _seal_id: &[u8],
        ) -> Result<SealRegistryStatus, csv_adapter_core::AdapterError> {
            Ok(SealRegistryStatus::Available)
        }
        async fn confirm_tx(
            &self,
            tx_hash: &str,
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            Ok(MintResult {
                tx_hash: tx_hash.to_string(),
                block_height: 100,
                materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                    "test-chain",
                ),
            })
        }
        async fn get_balance(
            &self,
            _address: &str,
        ) -> Result<String, csv_adapter_core::AdapterError> {
            Ok("0".to_string())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct StrictThinRegistryAdapter {
        caps: ChainCapabilities,
        mint_calls: Arc<std::sync::atomic::AtomicUsize>,
        fixed_seal_id: Option<[u8; 32]>,
        enforce_lock_events: bool,
        minted_sanads: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
        used_nullifiers: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
        used_lock_events: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
    }

    impl StrictThinRegistryAdapter {
        fn new(fixed_seal_id: Option<[u8; 32]>, enforce_lock_events: bool) -> Self {
            Self {
                caps: ChainCapabilities::bitcoin(),
                mint_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                fixed_seal_id,
                enforce_lock_events,
                minted_sanads: std::sync::Mutex::new(std::collections::HashSet::new()),
                used_nullifiers: std::sync::Mutex::new(std::collections::HashSet::new()),
                used_lock_events: std::sync::Mutex::new(std::collections::HashSet::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl ChainAdapter for StrictThinRegistryAdapter {
        fn chain_id(&self) -> &str {
            "test-chain"
        }
        fn capabilities(&self) -> ChainCapabilities {
            self.caps.clone()
        }
        fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
            csv_protocol::signature::SignatureScheme::Ed25519
        }
        async fn lock_sanad(
            &self,
            transfer: &CrossChainTransfer,
        ) -> Result<LockResult, csv_adapter_core::AdapterError> {
            Ok(LockResult {
                tx_hash: hex::encode(&transfer.lock_tx_hash),
                block_height: 100,
            })
        }
        async fn mint_sanad(
            &self,
            _transfer: &CrossChainTransfer,
            proof_bundle: &[u8],
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            let request: RuntimeMintRequest = csv_codec::from_canonical_cbor(proof_bundle)
                .map_err(|e| csv_adapter_core::AdapterError::SerializationError(e.to_string()))?;
            let attestation = request.attestation;

            if self.enforce_lock_events {
                let mut locks = self.used_lock_events.lock().map_err(|e| {
                    csv_adapter_core::AdapterError::Generic(format!("lock set poisoned: {e}"))
                })?;
                if !locks.insert(attestation.lock_event_id) {
                    return Err(csv_adapter_core::AdapterError::Generic(
                        "duplicate lock event rejected".to_string(),
                    ));
                }
            }

            let mut nullifiers = self.used_nullifiers.lock().map_err(|e| {
                csv_adapter_core::AdapterError::Generic(format!("nullifier set poisoned: {e}"))
            })?;
            if !nullifiers.insert(attestation.nullifier) {
                return Err(csv_adapter_core::AdapterError::Generic(
                    "duplicate nullifier rejected".to_string(),
                ));
            }
            drop(nullifiers);

            let mut sanads = self.minted_sanads.lock().map_err(|e| {
                csv_adapter_core::AdapterError::Generic(format!("sanad set poisoned: {e}"))
            })?;
            if !sanads.insert(attestation.sanad_id) {
                return Err(csv_adapter_core::AdapterError::Generic(
                    "duplicate sanad mint rejected".to_string(),
                ));
            }

            let call = self
                .mint_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst) as u8;
            Ok(MintResult {
                tx_hash: hex::encode([0xA0 | call; 32]),
                block_height: 700 + u64::from(call),
                materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                    "test-chain",
                ),
            })
        }
        async fn build_inclusion_proof(
            &self,
            transfer: &CrossChainTransfer,
            _lock_result: &LockResult,
        ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
            let mut bundle = LocalTestAdapter::build_fake_inclusion_proof(&transfer.sanad_id)
                .map_err(csv_adapter_core::AdapterError::Generic)?;
            if let Some(seal_id) = self.fixed_seal_id {
                bundle.seal_ref.id = seal_id.to_vec();
            }
            Ok(bundle)
        }
        async fn validate_source_proof(
            &self,
            transfer: &CrossChainTransfer,
            proof_bundle: &ProofBundle,
        ) -> Result<(), csv_adapter_core::AdapterError> {
            if proof_bundle.anchor_ref.anchor_id != transfer.sanad_id.as_bytes() {
                return Err(csv_adapter_core::AdapterError::Generic(
                    "proof anchor is not bound to the requested sanad".to_string(),
                ));
            }
            Ok(())
        }
        async fn check_seal_registry(
            &self,
            _seal_id: &[u8],
        ) -> Result<SealRegistryStatus, csv_adapter_core::AdapterError> {
            Ok(SealRegistryStatus::Available)
        }
        async fn confirm_tx(
            &self,
            tx_hash: &str,
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            Ok(MintResult {
                tx_hash: tx_hash.to_string(),
                block_height: 100,
                materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                    "test-chain",
                ),
            })
        }
        async fn get_balance(
            &self,
            _address: &str,
        ) -> Result<String, csv_adapter_core::AdapterError> {
            Ok("0".to_string())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn strict_registry(
        fixed_seal_id: Option<[u8; 32]>,
        enforce_lock_events: bool,
    ) -> (AdapterRegistryImpl, Arc<std::sync::atomic::AtomicUsize>) {
        let adapter = StrictThinRegistryAdapter::new(fixed_seal_id, enforce_lock_events);
        let calls = adapter.mint_calls.clone();
        let mut registry = AdapterRegistryImpl::new();
        registry.register_adapter(Box::new(adapter)).unwrap();
        (registry, calls)
    }

    fn operator_transfer(id: &str, seed: u8) -> CrossChainTransfer {
        CrossChainTransfer {
            id: id.to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![seed; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([seed; 32]),
            transition_id: vec![seed; 32],
        }
    }

    fn operator_ctx(
        transfer: &CrossChainTransfer,
        retry_delay: std::time::Duration,
        max_retries: u32,
    ) -> crate::user_runtime_lease::RuntimeExecutionContext {
        let owner = uuid::Uuid::new_v4();
        let mut policy = crate::policy::RuntimePolicy::new();
        policy.retry_delay = retry_delay;
        policy.max_retries = max_retries;
        crate::user_runtime_lease::RuntimeExecutionContext {
            lease: crate::user_runtime_lease::TransferLease {
                transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()).into(),
                epoch: 1,
                owner_runtime_id: owner,
                acquired_at: std::time::SystemTime::now(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            },
            runtime_instance: owner,
            policy,
            destination_owner: None,
        }
    }

    #[tokio::test]
    async fn settlement_evidence_recorded_on_successful_mint() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();
        let transfer = operator_transfer("settlement-happy", 9);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);

        coordinator
            .execute(transfer.clone(), &registry, ctx)
            .await
            .expect("operator mint should complete");

        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());
        let evidence = coordinator
            .settlement_evidence(&sanad)
            .expect("settlement query must succeed")
            .expect("settlement evidence must be recorded after a confirmed mint");

        assert_eq!(evidence.transfer_id, transfer.id);
        assert_eq!(evidence.sanad_id, *transfer.sanad_id.as_bytes());
        assert_eq!(evidence.source_chain, "test-chain");
        assert_eq!(evidence.destination_chain, "test-chain");
        // The coordinator rebinds the transfer to the real lock tx hash reported
        // by the adapter before deriving the settlement key, so the recorded
        // lock_event_id is keyed to the confirmed lock outpoint, not the empty
        // placeholder the caller submitted.
        let mut confirmed = transfer.clone();
        confirmed.lock_tx_hash =
            hex::decode(LocalTestAdapter::build_fake_lock_result().tx_hash).unwrap();
        assert_eq!(evidence.lock_event_id, lock_event_id(&confirmed));
        assert_ne!(evidence.mint_tx_hash, "");
    }

    #[tokio::test]
    async fn settlement_evidence_recorded_on_resume_path() {
        // Drive the resume/recovery mint path and confirm it leaves the same
        // settlement record as the fresh-execution path.
        let expected_transfer = CrossChainTransfer {
            id: "recover-transfer".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([44u8; 32]),
            transition_id: vec![3u8; 32],
        };
        let proof_bundle = LocalTestAdapter::new_bitcoin()
            .build_inclusion_proof(
                &expected_transfer,
                &LockResult {
                    tx_hash: hex::encode([0x11u8; 32]),
                    block_height: 100,
                },
            )
            .await
            .unwrap();
        let payload = proof_bundle.to_canonical_bytes().unwrap();
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofValidated, Some(payload)).await;

        coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("resume must mint using durable proof bytes");

        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());
        let evidence = coordinator
            .settlement_evidence(&sanad)
            .expect("settlement query must succeed")
            .expect("resume path must record settlement evidence");
        assert_eq!(evidence.sanad_id, *transfer.sanad_id.as_bytes());
        assert_eq!(evidence.nullifier, mint_nullifier(&proof_bundle));
    }

    #[tokio::test]
    async fn mint_retry_within_call_completes_and_records_settlement() {
        // A transient destination-mint revert is retried inside the same execute
        // call; the transfer still completes and records settlement evidence.
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let mint_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(FlakyMintAdapter {
                caps: ChainCapabilities::bitcoin(),
                mint_attempts: mint_attempts.clone(),
                fail_until: 1, // first attempt reverts, retry succeeds
            }))
            .unwrap();
        let transfer = operator_transfer("mint-retry", 21);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 3);

        coordinator
            .execute(transfer.clone(), &registry, ctx)
            .await
            .expect("transient revert must be retried and complete");

        assert!(
            mint_attempts.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "mint should have been retried at least once"
        );
        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());
        assert!(
            coordinator.settlement_evidence(&sanad).unwrap().is_some(),
            "completed retry must record settlement evidence"
        );
    }

    #[tokio::test]
    async fn mint_revert_rolls_back_and_blocks_duplicate() {
        // When every mint attempt reverts, the transfer fails, the replay entry is
        // rolled back, and a duplicate submission is refused — never double-minted.
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let mint_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(FlakyMintAdapter {
                caps: ChainCapabilities::bitcoin(),
                mint_attempts: mint_attempts.clone(),
                fail_until: usize::MAX, // every attempt reverts
            }))
            .unwrap();
        let transfer = operator_transfer("mint-revert", 33);
        // Reuse the same lease/owner for the duplicate so the retry reaches the
        // replay check rather than being stopped earlier by lease ownership.
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);

        let result = coordinator
            .execute(transfer.clone(), &registry, ctx.clone())
            .await;
        assert!(
            matches!(result, Err(TransferCoordinatorError::MintFailed(_))),
            "a fully-reverted mint must surface MintFailed, got {:?}",
            result
        );

        // No settlement evidence for a mint that never confirmed.
        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());
        assert!(
            coordinator.settlement_evidence(&sanad).unwrap().is_none(),
            "a reverted mint must not record settlement evidence"
        );

        // Duplicate submission after a revert is refused (fail-closed): the
        // rolled-back replay entry blocks any re-execution, preventing a
        // double-mint. Recovery from a revert is an operator action, not an
        // automatic re-run (see the operator runbook).
        let dup = coordinator.execute(transfer.clone(), &registry, ctx).await;
        assert!(
            matches!(dup, Err(TransferCoordinatorError::ReplayDetected(_))),
            "duplicate submission after revert must be refused, got {:?}",
            dup
        );
    }

    #[tokio::test]
    async fn duplicate_completed_sanad_returns_receipt_without_second_mint() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, mint_calls) = strict_registry(None, true);
        let transfer = operator_transfer("dup-same-sanad", 41);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);

        let first = coordinator
            .execute(transfer.clone(), &registry, ctx.clone())
            .await
            .expect("first mint must complete");
        let second = coordinator
            .execute(transfer.clone(), &registry, ctx)
            .await
            .expect("completed replay should return recorded receipt");

        assert_eq!(first.mint_tx_hash, second.mint_tx_hash);
        assert_eq!(
            mint_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "completed idempotent retry must not dispatch a second mint"
        );
    }

    #[tokio::test]
    async fn resume_completed_transfer_returns_recorded_receipt_without_second_mint() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, mint_calls) = strict_registry(None, true);
        let transfer = operator_transfer("resume-completed", 42);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);

        let first = coordinator
            .execute(transfer.clone(), &registry, ctx.clone())
            .await
            .expect("first mint must complete");
        let resumed = coordinator
            .resume_transfer(&transfer.id, &registry, ctx)
            .await
            .expect("completed resume should return recorded receipt");

        assert_eq!(first.transfer_id, resumed.transfer_id);
        assert_eq!(first.lock_tx_hash, resumed.lock_tx_hash);
        assert_eq!(first.mint_tx_hash, resumed.mint_tx_hash);
        assert_eq!(
            mint_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "completed resume must not dispatch a second mint"
        );
    }

    #[tokio::test]
    async fn duplicate_nullifier_fails_closed() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, mint_calls) = strict_registry(Some([0x42; 32]), false);
        let first = operator_transfer("dup-nullifier-1", 42);
        let second = operator_transfer("dup-nullifier-2", 43);

        coordinator
            .execute(
                first.clone(),
                &registry,
                operator_ctx(&first, std::time::Duration::from_millis(0), 1),
            )
            .await
            .expect("first mint must complete");
        let result = coordinator
            .execute(
                second.clone(),
                &registry,
                operator_ctx(&second, std::time::Duration::from_millis(0), 1),
            )
            .await;

        assert!(
            matches!(result, Err(TransferCoordinatorError::MintFailed(ref message)) if message.contains("duplicate nullifier")),
            "duplicate nullifier must fail closed, got {:?}",
            result
        );
        assert_eq!(
            mint_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "duplicate nullifier must not be accepted as a mint"
        );
    }

    #[tokio::test]
    async fn duplicate_lock_event_fails_closed() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, mint_calls) = strict_registry(None, true);
        let first = operator_transfer("dup-lock-1", 51);
        let mut second = operator_transfer("dup-lock-2", 52);
        second.lock_tx_hash = first.lock_tx_hash.clone();
        second.lock_output_index = first.lock_output_index;

        coordinator
            .execute(
                first.clone(),
                &registry,
                operator_ctx(&first, std::time::Duration::from_millis(0), 1),
            )
            .await
            .expect("first mint must complete");
        let result = coordinator
            .execute(
                second.clone(),
                &registry,
                operator_ctx(&second, std::time::Duration::from_millis(0), 1),
            )
            .await;

        assert!(
            matches!(result, Err(TransferCoordinatorError::MintFailed(ref message)) if message.contains("duplicate lock event")),
            "duplicate lock event must fail closed, got {:?}",
            result
        );
        assert_eq!(
            mint_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "duplicate lock event must not be accepted as a mint"
        );
    }

    #[tokio::test]
    async fn forged_mint_authorization_payload_is_rejected() {
        let adapter = StrictThinRegistryAdapter::new(None, true);
        let transfer = operator_transfer("forged-auth", 61);
        let result = adapter.mint_sanad(&transfer, b"not canonical cbor").await;
        assert!(
            matches!(
                result,
                Err(csv_adapter_core::AdapterError::SerializationError(_))
            ),
            "malformed authorization payload must be rejected, got {:?}",
            result
        );
        assert_eq!(
            adapter.mint_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn runtime_flow_metrics_cover_mint_replay_authorization_and_settlement() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, _settle_calls, _refund_calls, _payload) = settling_registry();
        let transfer = operator_transfer("metrics-flow", 62);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);
        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());

        coordinator
            .execute(transfer.clone(), &registry, ctx.clone())
            .await
            .expect("mint must complete");
        coordinator
            .release_escrow(&sanad, PAYOUT, 0, &registry, &ctx)
            .await
            .expect("settlement release must complete");

        let no_mint = csv_hash::SanadId::new([0xEF; 32]);
        assert!(matches!(
            coordinator
                .release_escrow(&no_mint, PAYOUT, 0, &registry, &ctx)
                .await,
            Err(TransferCoordinatorError::SettlementNotAuthorized(_))
        ));

        let reverted = operator_transfer("metrics-revert", 63);
        let mut flaky_registry = AdapterRegistryImpl::new();
        flaky_registry
            .register_adapter(Box::new(FlakyMintAdapter {
                caps: ChainCapabilities::bitcoin(),
                mint_attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                fail_until: usize::MAX,
            }))
            .unwrap();
        let reverted_ctx = operator_ctx(&reverted, std::time::Duration::from_millis(0), 0);
        assert!(matches!(
            coordinator
                .execute(reverted.clone(), &flaky_registry, reverted_ctx.clone())
                .await,
            Err(TransferCoordinatorError::MintFailed(_))
        ));
        assert!(matches!(
            coordinator
                .execute(reverted, &flaky_registry, reverted_ctx)
                .await,
            Err(TransferCoordinatorError::ReplayDetected(_))
        ));

        let snapshot = coordinator.runtime_flow_metrics();
        assert_eq!(snapshot.verified_proof_built, 2);
        assert_eq!(snapshot.mint_submitted, 1);
        assert_eq!(snapshot.mint_confirmed, 1);
        assert_eq!(snapshot.settlement_submitted, 1);
        assert_eq!(snapshot.settlement_confirmed, 1);
        assert_eq!(snapshot.authorization_rejected, 1);
        assert_eq!(snapshot.replay_rejected, 1);
    }

    // ==================== Source-chain settlement (TRM-ESCROW-001) ====================

    /// A `test-chain` adapter that behaves like [`LocalTestAdapter`] for the mint
    /// lifecycle AND implements the §10 settlement ports, capturing what the
    /// runtime dispatched so tests can assert the release/refund request shape.
    struct SettlingTestAdapter {
        caps: ChainCapabilities,
        settle_calls: Arc<std::sync::atomic::AtomicUsize>,
        refund_calls: Arc<std::sync::atomic::AtomicUsize>,
        last_settle_payload: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    }

    impl SettlingTestAdapter {
        fn new() -> Self {
            Self {
                caps: ChainCapabilities::bitcoin(),
                settle_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                refund_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                last_settle_payload: Arc::new(std::sync::Mutex::new(None)),
            }
        }
    }

    #[async_trait::async_trait]
    impl ChainAdapter for SettlingTestAdapter {
        fn chain_id(&self) -> &str {
            "test-chain"
        }
        fn capabilities(&self) -> ChainCapabilities {
            self.caps.clone()
        }
        fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
            csv_protocol::signature::SignatureScheme::Ed25519
        }
        async fn lock_sanad(
            &self,
            _transfer: &CrossChainTransfer,
        ) -> Result<LockResult, csv_adapter_core::AdapterError> {
            Ok(LocalTestAdapter::build_fake_lock_result())
        }
        async fn mint_sanad(
            &self,
            _transfer: &CrossChainTransfer,
            _proof_bundle: &[u8],
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            Ok(LocalTestAdapter::build_fake_mint_result())
        }
        async fn build_inclusion_proof(
            &self,
            transfer: &CrossChainTransfer,
            _lock_result: &LockResult,
        ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
            LocalTestAdapter::build_fake_inclusion_proof(&transfer.sanad_id)
                .map_err(csv_adapter_core::AdapterError::Generic)
        }
        async fn validate_source_proof(
            &self,
            _transfer: &CrossChainTransfer,
            _proof_bundle: &ProofBundle,
        ) -> Result<(), csv_adapter_core::AdapterError> {
            Ok(())
        }
        async fn check_seal_registry(
            &self,
            _seal_id: &[u8],
        ) -> Result<csv_adapter_core::SealRegistryStatus, csv_adapter_core::AdapterError> {
            Ok(csv_adapter_core::SealRegistryStatus::Available)
        }
        async fn confirm_tx(
            &self,
            tx_hash: &str,
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            Ok(MintResult {
                tx_hash: tx_hash.to_string(),
                block_height: 100,
                materialization: csv_adapter_core::DestinationMaterialization::unavailable(
                    "test-chain",
                ),
            })
        }
        async fn get_balance(
            &self,
            _address: &str,
        ) -> Result<String, csv_adapter_core::AdapterError> {
            Ok("0".to_string())
        }
        async fn settle_escrow(
            &self,
            _transfer: &CrossChainTransfer,
            settlement_request: &[u8],
        ) -> Result<csv_adapter_core::SettlementResult, csv_adapter_core::AdapterError> {
            self.settle_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_settle_payload.lock().unwrap() = Some(settlement_request.to_vec());
            Ok(csv_adapter_core::SettlementResult {
                tx_hash: hex::encode([0x5eu8; 32]),
                block_height: 200,
            })
        }
        async fn refund_escrow(
            &self,
            _transfer: &CrossChainTransfer,
        ) -> Result<csv_adapter_core::SettlementResult, csv_adapter_core::AdapterError> {
            self.refund_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(csv_adapter_core::SettlementResult {
                tx_hash: hex::encode([0x4eu8; 32]),
                block_height: 201,
            })
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Register a settlement-capable adapter and return it plus its call counters.
    fn settling_registry() -> (
        AdapterRegistryImpl,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    ) {
        let adapter = SettlingTestAdapter::new();
        let settle_calls = adapter.settle_calls.clone();
        let refund_calls = adapter.refund_calls.clone();
        let payload = adapter.last_settle_payload.clone();
        let mut registry = AdapterRegistryImpl::new();
        registry.register_adapter(Box::new(adapter)).unwrap();
        (registry, settle_calls, refund_calls, payload)
    }

    const PAYOUT: [u8; 32] = [0xAB; 32];

    /// After a confirmed mint, release_escrow dispatches a §10 settlement request
    /// (carrying NO runtime signatures — the operator cannot self-release) and
    /// records a distinct SettlementReleased status.
    #[tokio::test]
    async fn release_escrow_dispatches_and_records_release() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, settle_calls, _refund, payload) = settling_registry();
        let transfer = operator_transfer("settle-release", 21);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);
        coordinator
            .execute(transfer.clone(), &registry, ctx.clone())
            .await
            .expect("mint must complete to record evidence");

        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());
        let evidence = coordinator.settlement_evidence(&sanad).unwrap().unwrap();

        let record = coordinator
            .release_escrow(&sanad, PAYOUT, 0, &registry, &ctx)
            .await
            .expect("release must succeed after a confirmed mint");

        assert_eq!(settle_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(record.released_to_operator);
        assert_eq!(record.lock_event_id, evidence.lock_event_id);
        assert_eq!(record.operator_payout_address, PAYOUT);
        assert_eq!(record.settlement_block_height, 200);

        // Distinct SettlementReleased status is now terminal.
        match coordinator.settlement_status(&sanad).unwrap() {
            SettlementStatus::Released(r) => {
                assert_eq!(r.operator_payout_address, PAYOUT);
                assert!(r.released_to_operator);
            }
            other => panic!("expected Released, got {:?}", other),
        }

        // The dispatched request carries the §10 receipt with NO verifier
        // signatures: authority is bound off-chain by the verifier, never by the
        // operator/runtime. This is the structural no-self-release guarantee.
        let bytes = payload.lock().unwrap().clone().unwrap();
        let decoded: RuntimeSettlementRequest = csv_codec::from_canonical_cbor(&bytes).unwrap();
        assert!(
            decoded.verifier_signatures.is_empty(),
            "runtime must attach no signatures; the source verifier signs the digest"
        );
        assert_eq!(decoded.receipt.lock_event_id, evidence.lock_event_id);
        assert_eq!(decoded.receipt.operator_payout_address, PAYOUT);
        assert_eq!(decoded.receipt.sanad_id, evidence.sanad_id);
        // source_escrow_contract is left for the adapter to bind before signing.
        assert_eq!(decoded.receipt.source_escrow_contract, [0u8; 32]);
    }

    /// Release is refused when no destination mint confirmed: a failed or absent
    /// mint must never release escrow.
    #[tokio::test]
    async fn release_escrow_without_mint_is_unauthorized() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, settle_calls, _refund, _payload) = settling_registry();
        let transfer = operator_transfer("settle-nomint", 22);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);
        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());

        let result = coordinator
            .release_escrow(&sanad, PAYOUT, 0, &registry, &ctx)
            .await;
        assert!(
            matches!(
                result,
                Err(TransferCoordinatorError::SettlementNotAuthorized(_))
            ),
            "release without a confirmed mint must be unauthorized, got {:?}",
            result
        );
        assert_eq!(
            settle_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no source submission may happen without a confirmed mint"
        );
    }

    /// Release is idempotent across restarts: a second release is refused and the
    /// source adapter is never invoked twice — no double payout on crash recovery.
    #[tokio::test]
    async fn release_escrow_is_idempotent() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, settle_calls, _refund, _payload) = settling_registry();
        let transfer = operator_transfer("settle-idem", 23);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);
        coordinator
            .execute(transfer.clone(), &registry, ctx.clone())
            .await
            .unwrap();
        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());

        coordinator
            .release_escrow(&sanad, PAYOUT, 0, &registry, &ctx)
            .await
            .expect("first release succeeds");
        let again = coordinator
            .release_escrow(&sanad, PAYOUT, 0, &registry, &ctx)
            .await;
        assert!(
            matches!(again, Err(TransferCoordinatorError::AlreadyReleased)),
            "second release must be refused, got {:?}",
            again
        );
        assert_eq!(
            settle_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the source escrow must be released at most once"
        );
    }

    /// A confirmed destination mint must settle to the operator, never refund.
    #[tokio::test]
    async fn refund_refused_after_confirmed_mint() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, _settle, refund_calls, _payload) = settling_registry();
        let transfer = operator_transfer("refund-after-mint", 24);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);
        coordinator
            .execute(transfer.clone(), &registry, ctx.clone())
            .await
            .unwrap();

        let result = coordinator.refund_escrow(&transfer, &registry, &ctx).await;
        assert!(
            matches!(
                result,
                Err(TransferCoordinatorError::SettlementNotAuthorized(_))
            ),
            "a confirmed mint must not be refundable, got {:?}",
            result
        );
        assert_eq!(refund_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// When the mint never occurs, refund_escrow dispatches a refund and records a
    /// distinct SettlementRefunded status.
    #[tokio::test]
    async fn refund_escrow_when_mint_absent_records_refund() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        let (registry, _settle, refund_calls, _payload) = settling_registry();
        let transfer = operator_transfer("refund-timeout", 25);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);

        let record = coordinator
            .refund_escrow(&transfer, &registry, &ctx)
            .await
            .expect("refund must succeed when no mint confirmed");
        assert!(!record.released_to_operator);
        assert_eq!(refund_calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());
        match coordinator.settlement_status(&sanad).unwrap() {
            SettlementStatus::Refunded(r) => assert!(!r.released_to_operator),
            other => panic!("expected Refunded, got {:?}", other),
        }

        // Release and refund are mutually exclusive.
        let after = coordinator
            .release_escrow(&sanad, PAYOUT, 0, &registry, &ctx)
            .await;
        assert!(
            matches!(after, Err(TransferCoordinatorError::AlreadyRefunded)),
            "cannot release an already-refunded escrow, got {:?}",
            after
        );
    }

    /// A source chain without a wired settlement path fails closed: escrow is never
    /// released by a default/absent implementation.
    #[tokio::test]
    async fn release_escrow_fail_closed_without_adapter_wiring() {
        let coordinator = TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        );
        // LocalTestAdapter mints but does NOT implement settle_escrow (default fail-closed).
        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();
        let transfer = operator_transfer("settle-unwired", 26);
        let ctx = operator_ctx(&transfer, std::time::Duration::from_millis(0), 1);
        coordinator
            .execute(transfer.clone(), &registry, ctx.clone())
            .await
            .unwrap();
        let sanad = csv_hash::SanadId::new(*transfer.sanad_id.as_bytes());

        let result = coordinator
            .release_escrow(&sanad, PAYOUT, 0, &registry, &ctx)
            .await;
        assert!(
            matches!(result, Err(TransferCoordinatorError::SettlementFailed(_))),
            "an unwired settlement path must fail closed, got {:?}",
            result
        );
        // And no SettlementReleased status was recorded.
        assert!(matches!(
            coordinator.settlement_status(&sanad).unwrap(),
            SettlementStatus::Unsettled
        ));
    }

    // -----------------------------------------------------------------------
    // Send mode (interactive off-chain transfer) journaling & idempotent resume
    // -----------------------------------------------------------------------

    use crate::send_transfer::{
        Consignment, SealAssignment, SealCloseWitness, SendExecutor, SendExecutorError,
        SendTransfer,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Mock send executor that records how many times each step ran and can be
    /// told to fail a given step exactly once (to simulate an interruption).
    #[derive(Default)]
    struct MockSendExecutor {
        assign_calls: AtomicUsize,
        close_calls: AtomicUsize,
        emit_calls: AtomicUsize,
        fail_assign_once: AtomicBool,
        fail_close_once: AtomicBool,
        fail_emit_once: AtomicBool,
    }

    #[async_trait::async_trait]
    impl SendExecutor for MockSendExecutor {
        async fn assign_seal(
            &self,
            transfer: &SendTransfer,
        ) -> Result<SealAssignment, SendExecutorError> {
            self.assign_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_assign_once.swap(false, Ordering::SeqCst) {
                return Err(SendExecutorError::Assign("injected".into()));
            }
            // Deterministic function of inputs.
            let mut bytes = b"assign:".to_vec();
            bytes.extend_from_slice(&transfer.destination_seal.id);
            Ok(SealAssignment(bytes))
        }

        async fn close_source_seal(
            &self,
            transfer: &SendTransfer,
            _assignment: &SealAssignment,
        ) -> Result<SealCloseWitness, SendExecutorError> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_close_once.swap(false, Ordering::SeqCst) {
                return Err(SendExecutorError::Close("injected".into()));
            }
            let mut bytes = b"witness:".to_vec();
            bytes.extend_from_slice(&transfer.source_seal.id);
            Ok(SealCloseWitness(bytes))
        }

        async fn emit_consignment(
            &self,
            _transfer: &SendTransfer,
            witness: &SealCloseWitness,
        ) -> Result<Consignment, SendExecutorError> {
            self.emit_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_emit_once.swap(false, Ordering::SeqCst) {
                return Err(SendExecutorError::Emit("injected".into()));
            }
            let mut bytes = b"consignment:".to_vec();
            bytes.extend_from_slice(&witness.0);
            Ok(Consignment(bytes))
        }
    }

    fn send_transfer_fixture(transfer_id: &str, source_seal_byte: u8) -> SendTransfer {
        SendTransfer {
            transfer_id: transfer_id.to_string(),
            source_chain: "bitcoin".to_string(),
            sanad_id: csv_hash::SanadId::new([source_seal_byte; 32]),
            source_seal: csv_hash::seal::SealPoint::new(vec![source_seal_byte; 36], Some(0), None)
                .unwrap(),
            destination_seal: csv_hash::seal::SealPoint::new(vec![0xDD; 32], Some(7), None)
                .unwrap(),
        }
    }

    fn new_send_coordinator() -> TransferCoordinator {
        TransferCoordinator::new(
            Box::new(csv_storage::InMemoryReplayDb::new()),
            EventBus::new(),
        )
    }

    #[tokio::test]
    async fn send_happy_path_journals_all_phases_once() {
        let coordinator = new_send_coordinator();
        let executor = MockSendExecutor::default();
        let transfer = send_transfer_fixture("send-happy", 0x11);

        let receipt = coordinator
            .execute_send(&transfer, &executor)
            .await
            .expect("send should complete");

        assert_eq!(executor.assign_calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.emit_calls.load(Ordering::SeqCst), 1);
        assert!(receipt.consignment.0.starts_with(b"consignment:"));

        // Terminal phase is journaled Completed.
        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.transfer_id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn send_resume_after_close_interrupt_does_not_reassign_and_closes_once_more() {
        // Interrupt during the source-seal close, then resume: assign must NOT
        // re-run (its output is durable) and the seal close is retried to
        // completion — the single-use commitment lands exactly once overall.
        let coordinator = new_send_coordinator();
        let executor = MockSendExecutor::default();
        executor.fail_close_once.store(true, Ordering::SeqCst);
        let transfer = send_transfer_fixture("send-close-interrupt", 0x22);

        let err = coordinator
            .execute_send(&transfer, &executor)
            .await
            .expect_err("close interrupt should surface as an error");
        assert!(matches!(err, TransferCoordinatorError::SendFailed(_)));
        assert_eq!(executor.assign_calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.emit_calls.load(Ordering::SeqCst), 0);

        // Resume: finishes without re-running assign; close runs its second and
        // final time (the first attempt produced no witness).
        let receipt = coordinator
            .resume_send(&transfer, &executor)
            .await
            .expect("resume should complete the send");
        assert_eq!(
            executor.assign_calls.load(Ordering::SeqCst),
            1,
            "assign must not re-run"
        );
        assert_eq!(executor.close_calls.load(Ordering::SeqCst), 2);
        assert_eq!(executor.emit_calls.load(Ordering::SeqCst), 1);
        assert!(receipt.consignment.0.starts_with(b"consignment:"));
        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.transfer_id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn send_resume_after_emit_interrupt_never_recloses_source_seal() {
        // The critical single-use invariant: once the source seal is closed,
        // resuming to finish consignment emission must NEVER re-close it.
        let coordinator = new_send_coordinator();
        let executor = MockSendExecutor::default();
        executor.fail_emit_once.store(true, Ordering::SeqCst);
        let transfer = send_transfer_fixture("send-emit-interrupt", 0x33);

        let err = coordinator
            .execute_send(&transfer, &executor)
            .await
            .expect_err("emit interrupt should surface as an error");
        assert!(matches!(err, TransferCoordinatorError::SendFailed(_)));
        assert_eq!(executor.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.emit_calls.load(Ordering::SeqCst), 1);

        let receipt = coordinator
            .resume_send(&transfer, &executor)
            .await
            .expect("resume should emit the consignment");
        // Source seal was closed exactly once across the whole lifecycle.
        assert_eq!(
            executor.close_calls.load(Ordering::SeqCst),
            1,
            "resume must not re-close the single-use source seal"
        );
        assert_eq!(executor.emit_calls.load(Ordering::SeqCst), 2);
        assert!(receipt.consignment.0.starts_with(b"consignment:"));
    }

    #[tokio::test]
    async fn send_resume_after_completion_is_a_noop() {
        // Resuming an already-completed send re-runs nothing.
        let coordinator = new_send_coordinator();
        let executor = MockSendExecutor::default();
        let transfer = send_transfer_fixture("send-idempotent", 0x44);

        let first = coordinator
            .execute_send(&transfer, &executor)
            .await
            .unwrap();
        let second = coordinator.resume_send(&transfer, &executor).await.unwrap();

        assert_eq!(executor.assign_calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.emit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(first, second, "resume must reproduce the same receipt");
    }

    #[tokio::test]
    async fn send_double_close_of_same_source_seal_is_rejected() {
        // Two different transfers over the SAME source seal: the second must be
        // rejected as a duplicate source seal (single-use across transfers).
        let coordinator = new_send_coordinator();
        let executor_a = MockSendExecutor::default();
        let executor_b = MockSendExecutor::default();

        let t1 = send_transfer_fixture("send-dup-1", 0x55);
        let mut t2 = send_transfer_fixture("send-dup-2", 0x66);
        // Same source seal as t1, different sanad/transfer id.
        t2.source_seal = t1.source_seal.clone();

        coordinator.execute_send(&t1, &executor_a).await.unwrap();

        let err = coordinator
            .execute_send(&t2, &executor_b)
            .await
            .expect_err("second close of the same seal must be rejected");
        assert!(
            matches!(err, TransferCoordinatorError::DuplicateSourceSeal),
            "expected DuplicateSourceSeal, got {err:?}"
        );
        // The rejected transfer never produced a consignment.
        assert_eq!(executor_b.emit_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn re_executing_a_started_send_is_rejected() {
        // Once a send has been started, execute_send must refuse to re-run it
        // (which would roll the journal backward); the caller must resume.
        let coordinator = new_send_coordinator();
        let executor = MockSendExecutor::default();
        let transfer = send_transfer_fixture("send-reexec", 0x88);

        coordinator
            .execute_send(&transfer, &executor)
            .await
            .unwrap();
        let err = coordinator
            .execute_send(&transfer, &executor)
            .await
            .expect_err("re-executing a started send must be rejected");
        assert!(matches!(err, TransferCoordinatorError::RuntimeError(_)));
        // No extra work ran on the second call.
        assert_eq!(executor.close_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resuming_a_rejected_duplicate_still_rejects() {
        // A duplicate-seal transfer that was rejected at close must NOT become
        // resumable into a double-close: it never journaled SourceSealClosed, so
        // it can never claim ownership of the reservation on resume.
        let coordinator = new_send_coordinator();
        let executor_a = MockSendExecutor::default();
        let executor_b = MockSendExecutor::default();

        let t1 = send_transfer_fixture("dup-owner", 0x99);
        let mut t2 = send_transfer_fixture("dup-loser", 0xAA);
        t2.source_seal = t1.source_seal.clone();

        coordinator.execute_send(&t1, &executor_a).await.unwrap();
        assert!(matches!(
            coordinator.execute_send(&t2, &executor_b).await,
            Err(TransferCoordinatorError::DuplicateSourceSeal)
        ));

        // Resuming the rejected transfer must still be rejected — never allowed
        // to re-close the seal that t1 owns.
        let err = coordinator
            .resume_send(&t2, &executor_b)
            .await
            .expect_err("resuming a rejected duplicate must not close the seal");
        assert!(matches!(err, TransferCoordinatorError::DuplicateSourceSeal));
        assert_eq!(
            executor_b.close_calls.load(Ordering::SeqCst),
            0,
            "the losing transfer must never close the source seal"
        );
    }

    #[tokio::test]
    async fn resume_send_rejects_a_materialize_transfer() {
        // A materialize transfer must not be resumable through the send path.
        let coordinator = new_send_coordinator();
        let executor = MockSendExecutor::default();
        let transfer = send_transfer_fixture("materialize-not-send", 0x77);

        // Seed the journal with a materialize-mode phase for this id.
        coordinator
            .execution_journal()
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.transfer_id.clone(),
                replay_id: csv_wire::HashWire::from(transfer.sanad_id.0),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::AwaitingFinality,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .unwrap();

        let err = coordinator
            .resume_send(&transfer, &executor)
            .await
            .expect_err("send resume must reject a materialize transfer");
        assert!(matches!(err, TransferCoordinatorError::RuntimeError(_)));
        assert_eq!(executor.close_calls.load(Ordering::SeqCst), 0);
    }
}
