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
use csv_hash::SanadId;
use csv_hash::seal::SealPoint;

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
}
