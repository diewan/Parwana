//! Interactive off-chain (send-mode) transfer journaling and idempotent resume.
//!
//! The two transfer modes have different lifecycles (see
//! [`csv_protocol::transfer_state::TransferMode`]):
//!
//! - **materialize** locks on the source chain and mints on the destination
//!   chain, with an asynchronous destination-finality phase to resume (driven by
//!   [`crate::transfer_coordinator::TransferCoordinator::execute_outcome`] /
//!   `resume_transfer`);
//! - **send** is the pure off-chain RGB-style transfer: assign the Sanad to the
//!   recipient-controlled destination seal named by the invoice, close the
//!   single-use source seal, and emit a consignment for off-band delivery. There
//!   is no destination transaction.
//!
//! This module owns the send-mode phase model and the port
//! ([`SendExecutor`]) through which the coordinator drives the actual off-chain
//! mechanics, while keeping the crash-safe journaling and replay/idempotency
//! guarantees in the runtime — the same [`crate::execution_journal`] the
//! materialize path uses, never a forked one.
//!
//! # Idempotency contract (why resume is safe)
//!
//! Closing the source seal is the single-use commitment. Two guarantees, layered:
//!
//! - **Intra-transfer (resume):** the journal is the source of truth for what
//!   *this* transfer already did. `resume_send` reads the last journaled phase
//!   and skips every step already `Completed`, so a crash-and-resume never
//!   re-closes the seal or re-emits the consignment. The witness and consignment
//!   bytes are persisted in the journal so a resumed close/emit is unnecessary.
//! - **Cross-transfer (double-send):** the coordinator derives a per-seal
//!   nullifier and reserves it in the replay database with compare-and-set
//!   ([`csv_storage::ReplayDatabase::insert_if_absent`]) at the moment of close.
//!   A *different* transfer trying to close the same source seal observes the
//!   reservation and is rejected with
//!   [`crate::error::TransferCoordinatorError::DuplicateSourceSeal`].

use async_trait::async_trait;
use csv_chain_ports::ClosureProofVerifier;
use csv_hash::seal::SealPoint;
use csv_hash::{Hash, SanadId};
use csv_protocol::closure::ClosureProof;
use csv_protocol::resolution::ResolvedTransition;
use csv_wire::{
    ConsignmentAuthorization, ConsignmentProofRequirements, ConsignmentV2, ConsignmentV2Error,
    ConsignmentV2Payload, Invoice,
};
use std::collections::HashMap;
use std::sync::Mutex;

/// Domain tag for the per-source-seal nullifier that guards against a second
/// transfer closing the same single-use seal.
const SEND_SOURCE_SEAL_NULLIFIER_TAG: &str = "csv.send.source-seal.v1";

/// A request to perform an interactive off-chain (send-mode) transfer.
///
/// This carries only the identity a send needs; the actual off-chain
/// state-transition mechanics live behind [`SendExecutor`].
#[derive(Clone, Debug)]
pub struct SendTransfer {
    /// Runtime-assigned transfer id — the journal and resume key.
    pub transfer_id: String,
    /// Source-chain identifier (e.g. `"bitcoin"`).
    pub source_chain: String,
    /// The Sanad being sent.
    pub sanad_id: SanadId,
    /// The single-use source seal that will be closed. Closing it is the
    /// single-use commitment; it must be closed at most once across the system.
    pub source_seal: SealPoint,
    /// The recipient-controlled destination seal bound by the invoice.
    pub destination_seal: SealPoint,
}

impl SendTransfer {
    /// The per-source-seal nullifier used to reject a second transfer that tries
    /// to close the same seal (cross-transfer double-send protection).
    ///
    /// Bound to the source seal identity only — deliberately independent of
    /// `transfer_id`, so two *different* transfers over the same seal collide
    /// on the same nullifier and the second is rejected.
    pub fn source_seal_nullifier(&self) -> [u8; 32] {
        csv_hash::csv_tagged_hash(SEND_SOURCE_SEAL_NULLIFIER_TAG, &self.source_seal.id)
    }
}

/// Opaque, canonical byte blob binding the Sanad to the invoice's destination
/// seal (produced by [`SendExecutor::assign_seal`]).
///
/// The encoding is owned by the send executor / wire layer; the runtime treats
/// it as durable bytes so a resumed close can be driven without re-assigning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealAssignment(pub Vec<u8>);

/// Opaque, canonical witness proving the single-use source seal was closed
/// (produced by [`SendExecutor::close_source_seal`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealCloseWitness(pub Vec<u8>);

/// Opaque, canonical consignment carrying the transition history for the
/// recipient to client-side validate (produced by
/// [`SendExecutor::emit_consignment`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consignment(pub Vec<u8>);

/// Error raised by a [`SendExecutor`] implementation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendExecutorError {
    /// The assign step failed.
    #[error("assign failed: {0}")]
    Assign(String),
    /// The source-seal close step failed.
    #[error("close failed: {0}")]
    Close(String),
    /// The consignment emission step failed.
    #[error("emit failed: {0}")]
    Emit(String),
}

/// Port through which the coordinator drives the off-chain send mechanics.
///
/// Implementations (wallet/SDK/CLI) provide the chain- and encoding-specific
/// behavior; the coordinator supplies the journaling, replay protection, and
/// resume idempotency around it.
///
/// **Determinism requirement:** every method MUST be a deterministic,
/// side-effect-idempotent function of its inputs. In particular
/// [`SendExecutor::close_source_seal`] must NOT itself perform an
/// irreversible/double-spendable action on repeat — the single-use guarantee is
/// enforced by the coordinator's nullifier reservation, and a crash between the
/// nullifier reservation and the journal `Completed` write means the close may
/// be re-driven on resume with the same inputs.
#[async_trait]
pub trait SendExecutor: Send + Sync {
    /// Assign the Sanad to the recipient-controlled destination seal named by
    /// the invoice. Pure client-side binding; no chain mutation.
    async fn assign_seal(
        &self,
        transfer: &SendTransfer,
    ) -> Result<SealAssignment, SendExecutorError>;

    /// Close the single-use source seal, producing the commitment witness.
    async fn close_source_seal(
        &self,
        transfer: &SendTransfer,
        assignment: &SealAssignment,
    ) -> Result<SealCloseWitness, SendExecutorError>;

    /// Emit the consignment for off-band delivery to the recipient.
    async fn emit_consignment(
        &self,
        transfer: &SendTransfer,
        witness: &SealCloseWitness,
    ) -> Result<Consignment, SendExecutorError>;
}

/// Cumulative durable progress for a send-mode transfer, persisted as the
/// journal payload on every send phase so a resume can reconstruct earlier
/// step outputs from the single most-recent journal entry.
///
/// The execution journal exposes only the *latest* entry per transfer, so each
/// completed step carries forward all prior outputs rather than relying on a
/// per-phase scan.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SendProgress {
    /// Bytes from [`SendExecutor::assign_seal`], once completed.
    pub assignment: Option<Vec<u8>>,
    /// Bytes from [`SendExecutor::close_source_seal`], once completed.
    pub witness: Option<Vec<u8>>,
    /// Bytes from [`SendExecutor::emit_consignment`], once completed.
    pub consignment: Option<Vec<u8>>,
}

/// How a send-mode transfer reached completion.
///
/// A resumed send and a fresh one produce the same consignment and the same
/// witness, so the receipt alone cannot tell them apart. Recording which path
/// ran is what makes "the interrupted run recovered without re-closing the
/// single-use source seal" an observable outcome rather than an inference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendCompletion {
    /// No prior durable progress existed; every step ran in this invocation.
    Executed,
    /// Durable progress from an earlier interrupted run was reused, so at
    /// least one step was skipped rather than repeated.
    Recovered,
}

impl SendCompletion {
    /// Stable registry identifier for this completion path.
    ///
    /// `RUNTIME.SEND.RECOVERED` is the code the portable conformance package's
    /// `crash-recovery` case tells a consumer to expect.
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::Executed => "RUNTIME.SEND.EXECUTED",
            Self::Recovered => "RUNTIME.SEND.RECOVERED",
        }
    }

    /// Every code this family defines, in stable published order.
    pub const ALL: &'static [Self] = &[Self::Executed, Self::Recovered];
}

/// Outcome of driving a send-mode transfer to (or resuming it toward)
/// completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendReceipt {
    /// The transfer id this receipt is for.
    pub transfer_id: String,
    /// The emitted consignment for the recipient.
    pub consignment: Consignment,
    /// The single-use source-seal close witness.
    pub witness: SealCloseWitness,
    /// Whether this receipt came from a fresh run or a resumed one.
    pub completion: SendCompletion,
}

/// All non-closure inputs needed to emit one portable V2 consignment.
///
/// The closure is deliberately not optional and is deliberately not a field
/// callers can replace with a validation boolean: [`emit_consignment_v2`]
/// requires the chain-native [`ClosureProof`] as a separate argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsignmentV2EmissionRequest {
    /// Stable recovery key. Reusing it with different inputs is a conflict.
    pub journal_id: String,
    /// State consumed by the successor transition.
    pub source: csv_protocol::reference::ConsumedStateRef,
    /// Fully resolved successor transition.
    pub successor: ResolvedTransition,
    /// Recipient-issued destination invoice.
    pub destination: Invoice,
    /// Explicit checkpoint and trust inputs required by the recipient.
    pub proof_requirements: ConsignmentProofRequirements,
}

/// Produces authorization evidence over exactly one consignment commitment.
pub trait ConsignmentV2Authorizer: Send + Sync {
    /// Sign `commitment`; the returned evidence must name the same commitment.
    fn authorize(
        &self,
        commitment: Hash,
    ) -> Result<ConsignmentAuthorization, ConsignmentEmissionError>;
}

/// Durable state of one V2 emission.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsignmentEmissionRecord {
    /// Commitment to the complete V2 payload, including source closure.
    pub payload_commitment: Hash,
    /// Canonical closure bytes persisted before authorization or emission.
    pub closure: Vec<u8>,
    /// Canonical chain-native verification result persisted with the closure.
    pub closure_verification: Vec<u8>,
    /// Final canonical V2 artifact, once successfully emitted.
    pub artifact: Option<Vec<u8>>,
}

/// Atomic persistence boundary for V2 emission and recovery.
pub trait ConsignmentEmissionJournal: Send + Sync {
    /// Reserve an emission key or return its existing durable record.
    fn reserve(
        &self,
        journal_id: &str,
        record: ConsignmentEmissionRecord,
    ) -> Result<ConsignmentEmissionRecord, ConsignmentEmissionError>;

    /// Store the completed artifact with compare-and-set semantics.
    fn complete(
        &self,
        journal_id: &str,
        payload_commitment: Hash,
        artifact: Vec<u8>,
    ) -> Result<Vec<u8>, ConsignmentEmissionError>;
}

/// Stable V2 construction and recovery failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsignmentEmissionError {
    /// The closure or another V2 field failed structural validation.
    #[error("invalid consignment: {0}")]
    InvalidConsignment(String),
    /// Authorization could not be produced.
    #[error("authorization failed: {0}")]
    Authorization(String),
    /// Chain-native closure verification did not establish every required dimension.
    #[error("closure verification failed: {0}")]
    ClosureVerification(String),
    /// A recovery key was reused for different immutable inputs.
    #[error("emission conflict for journal entry {0}")]
    Conflict(String),
    /// Durable journal access failed.
    #[error("emission journal failed: {0}")]
    Journal(String),
}

impl From<ConsignmentV2Error> for ConsignmentEmissionError {
    fn from(value: ConsignmentV2Error) -> Self {
        Self::InvalidConsignment(value.to_string())
    }
}

/// In-memory atomic emission journal for tests and ephemeral runtimes.
#[derive(Default)]
pub struct InMemoryConsignmentEmissionJournal {
    records: Mutex<HashMap<String, ConsignmentEmissionRecord>>,
}

impl ConsignmentEmissionJournal for InMemoryConsignmentEmissionJournal {
    fn reserve(
        &self,
        journal_id: &str,
        record: ConsignmentEmissionRecord,
    ) -> Result<ConsignmentEmissionRecord, ConsignmentEmissionError> {
        let mut records = self
            .records
            .lock()
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        match records.get(journal_id) {
            Some(existing)
                if existing.payload_commitment != record.payload_commitment
                    || existing.closure != record.closure
                    || existing.closure_verification != record.closure_verification =>
            {
                Err(ConsignmentEmissionError::Conflict(journal_id.to_owned()))
            }
            Some(existing) => Ok(existing.clone()),
            None => {
                records.insert(journal_id.to_owned(), record.clone());
                Ok(record)
            }
        }
    }

    fn complete(
        &self,
        journal_id: &str,
        payload_commitment: Hash,
        artifact: Vec<u8>,
    ) -> Result<Vec<u8>, ConsignmentEmissionError> {
        let mut records = self
            .records
            .lock()
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        let record = records
            .get_mut(journal_id)
            .ok_or_else(|| ConsignmentEmissionError::Journal("entry was not reserved".into()))?;
        if record.payload_commitment != payload_commitment {
            return Err(ConsignmentEmissionError::Conflict(journal_id.to_owned()));
        }
        match &record.artifact {
            Some(existing) if existing != &artifact => {
                Err(ConsignmentEmissionError::Conflict(journal_id.to_owned()))
            }
            Some(existing) => Ok(existing.clone()),
            None => {
                record.artifact = Some(artifact.clone());
                Ok(artifact)
            }
        }
    }
}

/// Construct, authorize, and durably emit one canonical V2 consignment.
///
/// Recovery is deterministic: the closure and payload commitment are reserved
/// before signing. A retry with the same inputs returns the stored artifact;
/// changed closure, recipient, transition, or proof context fails with
/// [`ConsignmentEmissionError::Conflict`]. A signing/emission failure never
/// removes the reserved closure.
pub async fn emit_consignment_v2(
    request: &ConsignmentV2EmissionRequest,
    source_closure: ClosureProof,
    closure_verifier: &dyn ClosureProofVerifier,
    authorizer: &dyn ConsignmentV2Authorizer,
    journal: &dyn ConsignmentEmissionJournal,
) -> Result<Consignment, ConsignmentEmissionError> {
    let payload = ConsignmentV2Payload::new(
        request.source,
        request.successor.clone(),
        source_closure.clone(),
        request.destination.clone(),
        request.proof_requirements.clone(),
    );
    let unsigned = ConsignmentV2::new(payload)?;
    unsigned.payload.validate_structure()?;
    let verification = closure_verifier
        .verify_closure(&source_closure, &request.proof_requirements.checkpoint)
        .await
        .map_err(|error| ConsignmentEmissionError::ClosureVerification(error.to_string()))?;
    verification
        .validate()
        .map_err(|error| ConsignmentEmissionError::ClosureVerification(error.to_string()))?;
    use csv_protocol::closure::ClosureDimensionStatus::Satisfied;
    if verification.checkpoint != request.proof_requirements.checkpoint
        || verification.proof_kind != source_closure.proof_kind
        || verification.trust_mode != request.proof_requirements.trust_mode
        || verification.proof_provider_id != request.proof_requirements.proof_provider_id
        || verification.proof_validity != Satisfied
        || verification.checkpoint_finality != Satisfied
        || verification.checkpoint_freshness != Satisfied
        || verification.source_closure != Satisfied
    {
        return Err(ConsignmentEmissionError::ClosureVerification(
            "closure, inclusion, finality, freshness, or provenance was not satisfied".into(),
        ));
    }

    let closure = csv_codec::to_canonical_cbor(&source_closure)
        .map_err(|error| ConsignmentEmissionError::InvalidConsignment(error.to_string()))?;
    let closure_verification = csv_codec::to_canonical_cbor(&verification)
        .map_err(|error| ConsignmentEmissionError::ClosureVerification(error.to_string()))?;
    let reserved = journal.reserve(
        &request.journal_id,
        ConsignmentEmissionRecord {
            payload_commitment: unsigned.commitment,
            closure,
            closure_verification,
            artifact: None,
        },
    )?;
    if let Some(artifact) = reserved.artifact {
        ConsignmentV2::decode_v2(&artifact)?;
        return Ok(Consignment(artifact));
    }

    let authorization = authorizer.authorize(unsigned.commitment)?;
    let artifact = unsigned
        .with_authorizations(vec![authorization])?
        .canonical_cbor()?;
    let artifact = journal.complete(&request.journal_id, reserved.payload_commitment, artifact)?;
    Ok(Consignment(artifact))
}

#[cfg(feature = "persistent")]
const CONSIGNMENT_EMISSION_TABLE: redb::TableDefinition<'static, &'static str, &'static [u8]> =
    redb::TableDefinition::new("consignment_v2_emissions");

/// Durable redb implementation of the atomic V2 emission journal.
#[cfg(feature = "persistent")]
pub struct RedbConsignmentEmissionJournal {
    db: redb::Database,
}

#[cfg(feature = "persistent")]
impl RedbConsignmentEmissionJournal {
    /// Open or create a durable journal file.
    pub fn open(path: &str) -> Result<Self, ConsignmentEmissionError> {
        let db = redb::Database::create(path)
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        let write = db
            .begin_write()
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        write
            .open_table(CONSIGNMENT_EMISSION_TABLE)
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        write
            .commit()
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        Ok(Self { db })
    }
}

#[cfg(feature = "persistent")]
impl ConsignmentEmissionJournal for RedbConsignmentEmissionJournal {
    fn reserve(
        &self,
        journal_id: &str,
        record: ConsignmentEmissionRecord,
    ) -> Result<ConsignmentEmissionRecord, ConsignmentEmissionError> {
        use redb::ReadableTable;
        let write = self
            .db
            .begin_write()
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        let result = {
            let mut table = write
                .open_table(CONSIGNMENT_EMISSION_TABLE)
                .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
            if let Some(existing) = table
                .get(journal_id)
                .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?
            {
                let existing: ConsignmentEmissionRecord =
                    csv_codec::from_canonical_cbor(existing.value())
                        .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
                if existing.payload_commitment != record.payload_commitment
                    || existing.closure != record.closure
                    || existing.closure_verification != record.closure_verification
                {
                    return Err(ConsignmentEmissionError::Conflict(journal_id.to_owned()));
                }
                existing
            } else {
                let bytes = csv_codec::to_canonical_cbor(&record)
                    .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
                table
                    .insert(journal_id, bytes.as_slice())
                    .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
                record
            }
        };
        write
            .commit()
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        Ok(result)
    }

    fn complete(
        &self,
        journal_id: &str,
        payload_commitment: Hash,
        artifact: Vec<u8>,
    ) -> Result<Vec<u8>, ConsignmentEmissionError> {
        use redb::ReadableTable;
        let write = self
            .db
            .begin_write()
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        let result = {
            let mut table = write
                .open_table(CONSIGNMENT_EMISSION_TABLE)
                .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
            let existing = table
                .get(journal_id)
                .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?
                .ok_or_else(|| {
                    ConsignmentEmissionError::Journal("entry was not reserved".into())
                })?;
            let mut record: ConsignmentEmissionRecord =
                csv_codec::from_canonical_cbor(existing.value())
                    .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
            drop(existing);
            if record.payload_commitment != payload_commitment {
                return Err(ConsignmentEmissionError::Conflict(journal_id.to_owned()));
            }
            if let Some(existing) = record.artifact {
                if existing != artifact {
                    return Err(ConsignmentEmissionError::Conflict(journal_id.to_owned()));
                }
                existing
            } else {
                record.artifact = Some(artifact.clone());
                let bytes = csv_codec::to_canonical_cbor(&record)
                    .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
                table
                    .insert(journal_id, bytes.as_slice())
                    .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
                artifact
            }
        };
        write
            .commit()
            .map_err(|error| ConsignmentEmissionError::Journal(error.to_string()))?;
        Ok(result)
    }
}

#[cfg(test)]
mod v2_emission_tests {
    use super::*;
    use csv_hash::seal::SealPoint;
    use csv_protocol::SignatureScheme;
    use csv_protocol::closure::{
        ClosureDimensionStatus, ClosureProofKind, ClosureTrustMode, ClosureVerificationResult,
        FinalityPolicy, FinalizedCheckpoint,
    };
    use csv_protocol::exclusivity::{ConsumptionMode, ExclusivityClass, StateUseSchema};
    use csv_protocol::resolution::{ParentOutput, ResolvedInput};
    use csv_protocol::state::StateAssignment;
    use csv_wire::SealDefinition;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct TestAuthorizer {
        calls: AtomicUsize,
        fail_once: AtomicBool,
        signature_byte: u8,
    }

    impl TestAuthorizer {
        fn deterministic() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail_once: AtomicBool::new(false),
                signature_byte: 0xBB,
            }
        }
    }

    impl ConsignmentV2Authorizer for TestAuthorizer {
        fn authorize(
            &self,
            commitment: Hash,
        ) -> Result<ConsignmentAuthorization, ConsignmentEmissionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_once.swap(false, Ordering::SeqCst) {
                return Err(ConsignmentEmissionError::Authorization("injected".into()));
            }
            Ok(ConsignmentAuthorization {
                scheme: SignatureScheme::Ed25519,
                public_key: vec![0xAA; 32],
                signature: vec![self.signature_byte; 64],
                signed_commitment: commitment,
            })
        }
    }

    struct TestClosureVerifier;

    #[async_trait]
    impl ClosureProofVerifier for TestClosureVerifier {
        async fn verify_closure(
            &self,
            proof: &ClosureProof,
            checkpoint: &FinalizedCheckpoint,
        ) -> csv_chain_ports::AdapterResult<ClosureVerificationResult> {
            Ok(ClosureVerificationResult {
                chain_id: checkpoint.chain_id.clone(),
                network_id: checkpoint.network_id.clone(),
                proof_kind: proof.proof_kind.clone(),
                checkpoint: checkpoint.clone(),
                proof_validity: ClosureDimensionStatus::Satisfied,
                checkpoint_finality: ClosureDimensionStatus::Satisfied,
                checkpoint_freshness: ClosureDimensionStatus::Satisfied,
                source_closure: ClosureDimensionStatus::Satisfied,
                trust_mode: ClosureTrustMode::LightClient,
                verifier_id: "test-bitcoin-verifier".into(),
                proof_provider_id: "bitcoin-spv-v1".into(),
                reason_codes: vec!["TEST.CLOSURE.SATISFIED".into()],
            })
        }
    }

    fn fixture(journal_id: &str) -> (ConsignmentV2EmissionRequest, ClosureProof) {
        let invoice = Invoice::new(
            SealDefinition::sui(vec![0xCD; 32], 7).unwrap(),
            vec![0xAA; 32],
            0xBEEF,
        )
        .unwrap();
        let destination = invoice.bound_seal_point().unwrap();
        let source = csv_protocol::reference::ConsumedStateRef::new(Hash::new([0x11; 32]), 0, 7);
        let mut schema = StateUseSchema::new();
        schema.bind(7, ExclusivityClass::Exclusive).unwrap();
        let parent = ParentOutput::sealed(
            source.transition_id,
            source.output_index,
            schema.bind_output(7).unwrap(),
            SealPoint::new(vec![0x22; 36], None, None).unwrap(),
            vec![0x33],
            vec![vec![0x44; 32]],
        );
        let successor = ResolvedTransition {
            transition_id: 9,
            inputs: vec![ResolvedInput {
                reference: source,
                parent,
                mode: ConsumptionMode::Exclusive,
            }],
            outputs: vec![StateAssignment::new(7, destination, vec![0x55])],
            validation_script: vec![0x66],
        };
        let closure = ClosureProof {
            consumed_state: source,
            successor_commitment: successor.commitment(),
            proof_kind: ClosureProofKind::BitcoinTransactionInclusion,
            proof_material: vec![0x77; 64],
        };
        let request = ConsignmentV2EmissionRequest {
            journal_id: journal_id.into(),
            source,
            successor,
            destination: invoice,
            proof_requirements: ConsignmentProofRequirements {
                checkpoint: FinalizedCheckpoint {
                    chain_id: "bitcoin".into(),
                    network_id: "signet".into(),
                    block_height: 100,
                    block_id: vec![0x88; 32],
                    finality_policy: FinalityPolicy::Confirmations(6),
                },
                trust_mode: ClosureTrustMode::LightClient,
                proof_provider_id: "bitcoin-spv-v1".into(),
                verification_context: Hash::new([0x99; 32]),
                maximum_checkpoint_age: 12,
            },
        };
        (request, closure)
    }

    #[tokio::test]
    async fn emits_canonical_v2_with_the_exact_closure() {
        let (request, closure) = fixture("canonical");
        let journal = InMemoryConsignmentEmissionJournal::default();
        let authorizer = TestAuthorizer::deterministic();
        let artifact = emit_consignment_v2(
            &request,
            closure.clone(),
            &TestClosureVerifier,
            &authorizer,
            &journal,
        )
        .await
        .unwrap();
        let decoded = ConsignmentV2::decode_v2(&artifact.0).unwrap();

        assert_eq!(decoded.payload.source_closure, closure);
        assert_eq!(decoded.payload.successor, request.successor);
        assert_eq!(decoded.payload.destination, request.destination);
        assert_eq!(decoded.canonical_cbor().unwrap(), artifact.0);
    }

    #[tokio::test]
    async fn signing_failure_keeps_closure_and_retry_is_identical() {
        let (request, closure) = fixture("signing-crash");
        let journal = InMemoryConsignmentEmissionJournal::default();
        let authorizer = TestAuthorizer {
            fail_once: AtomicBool::new(true),
            ..TestAuthorizer::deterministic()
        };

        assert!(matches!(
            emit_consignment_v2(
                &request,
                closure.clone(),
                &TestClosureVerifier,
                &authorizer,
                &journal
            )
            .await,
            Err(ConsignmentEmissionError::Authorization(_))
        ));
        let first = emit_consignment_v2(
            &request,
            closure.clone(),
            &TestClosureVerifier,
            &authorizer,
            &journal,
        )
        .await
        .unwrap();
        let recovered = emit_consignment_v2(
            &request,
            closure,
            &TestClosureVerifier,
            &authorizer,
            &journal,
        )
        .await
        .unwrap();
        assert_eq!(first, recovered);
        assert_eq!(authorizer.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn changed_closure_or_recipient_is_a_stable_conflict() {
        let (request, closure) = fixture("conflict");
        let journal = InMemoryConsignmentEmissionJournal::default();
        let authorizer = TestAuthorizer::deterministic();
        emit_consignment_v2(
            &request,
            closure.clone(),
            &TestClosureVerifier,
            &authorizer,
            &journal,
        )
        .await
        .unwrap();

        let mut forged = closure.clone();
        forged.proof_material[0] ^= 1;
        assert_eq!(
            emit_consignment_v2(
                &request,
                forged,
                &TestClosureVerifier,
                &authorizer,
                &journal
            )
            .await
            .unwrap_err(),
            ConsignmentEmissionError::Conflict("conflict".into())
        );

        let (mut changed, _) = fixture("conflict");
        changed.destination.nonce ^= 1;
        assert!(matches!(
            emit_consignment_v2(
                &changed,
                closure,
                &TestClosureVerifier,
                &authorizer,
                &journal
            )
            .await,
            Err(ConsignmentEmissionError::InvalidConsignment(_))
                | Err(ConsignmentEmissionError::Conflict(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_retries_return_one_byte_identical_artifact() {
        let (request, closure) = fixture("concurrent");
        let journal = Arc::new(InMemoryConsignmentEmissionJournal::default());
        let authorizer = Arc::new(TestAuthorizer::deterministic());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let request = request.clone();
                let closure = closure.clone();
                let journal = Arc::clone(&journal);
                let authorizer = Arc::clone(&authorizer);
                tokio::spawn(async move {
                    emit_consignment_v2(
                        &request,
                        closure,
                        &TestClosureVerifier,
                        authorizer.as_ref(),
                        journal.as_ref(),
                    )
                    .await
                    .unwrap()
                })
            })
            .collect();
        let mut artifacts = Vec::new();
        for handle in handles {
            artifacts.push(handle.await.unwrap());
        }
        assert!(artifacts.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[cfg(feature = "persistent")]
    #[tokio::test]
    async fn durable_recovery_reopens_the_same_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("emissions.redb");
        let (request, closure) = fixture("durable");
        let authorizer = TestAuthorizer::deterministic();
        let first = {
            let journal = RedbConsignmentEmissionJournal::open(path.to_str().unwrap()).unwrap();
            emit_consignment_v2(
                &request,
                closure.clone(),
                &TestClosureVerifier,
                &authorizer,
                &journal,
            )
            .await
            .unwrap()
        };
        let reopened = RedbConsignmentEmissionJournal::open(path.to_str().unwrap()).unwrap();
        let recovered = emit_consignment_v2(
            &request,
            closure,
            &TestClosureVerifier,
            &authorizer,
            &reopened,
        )
        .await
        .unwrap();
        assert_eq!(first, recovered);
        assert_eq!(authorizer.calls.load(Ordering::SeqCst), 1);
    }
}
