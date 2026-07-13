//! Transfer receipts, discriminated by transfer mode.
//!
//! A receipt records what the runtime did. Its fields are copied from runtime
//! artifacts — never computed by the presentation layer, and never inferred from
//! a transaction hash or an explorer response.

use serde::{Deserialize, Serialize};

use super::event::{FinalityEvidence, VerificationAssuranceWire};
use super::{ArtifactKind, ContractArtifact, ContractError, ContractHeader, require_nonempty};
use crate::primitives::{HashWire, SanadIdWire};
use crate::seal::SealPointWire;

/// The transfer mode a receipt or event belongs to.
///
/// The mode is not a formatting detail: each mode has a different authority
/// story, a different set of on-chain effects, and a different set of permitted
/// next actions. Collapsing them would let an application offer an action the
/// runtime cannot honor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferMode {
    /// Interactive off-chain send: assign the sanad to the invoice's
    /// recipient-controlled seal, close the source seal, emit a consignment for
    /// off-band delivery. No destination-chain submission and no attestor, hence
    /// no destination phase to resume or retry.
    Send,
    /// Recipient-issued invoice binding a single-use destination seal they control.
    /// The entry point of the interactive mode; nothing is on-chain yet.
    Invoice,
    /// Recipient-side client-side validation of a consignment, recording ownership.
    /// The completion point of the interactive mode; no chain transaction.
    Accept,
    /// On-chain materialization via the thin-registry mint. Has an asynchronous
    /// destination-finality phase, so this is the mode where resume and retry apply.
    Materialize,
}

/// An action a transfer permits next.
///
/// Permitted actions are a property of the mode and the runtime's journaled
/// state, not of the UI. An application offers exactly what is listed — offering
/// more would invite the user into a call the runtime will reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    /// Hand the invoice blob to the sender (off-band).
    DeliverInvoice,
    /// Hand the consignment to the recipient (off-band).
    DeliverConsignment,
    /// Recipient: client-side validate the consignment and accept it.
    Accept,
    /// Advance a locked transfer that is awaiting finality. Never re-locks.
    Resume,
    /// Retry a failed transfer from its journaled phase.
    Retry,
    /// Query the runtime for the transfer's current status.
    Status,
    /// Query the runtime's recorded source-escrow settlement status and evidence.
    SettlementStatus,
}

impl NextAction {
    /// The actions a given mode can ever permit.
    ///
    /// `Send` deliberately excludes `Resume` and `Retry`: an off-chain send has no
    /// destination phase, so there is nothing to advance or re-drive. Only
    /// `Materialize` has an asynchronous destination-finality phase.
    pub fn permitted_for_mode(mode: TransferMode) -> &'static [NextAction] {
        match mode {
            TransferMode::Send => &[NextAction::DeliverConsignment, NextAction::Status],
            TransferMode::Invoice => &[NextAction::DeliverInvoice],
            TransferMode::Accept => &[NextAction::Status],
            TransferMode::Materialize => &[
                NextAction::Resume,
                NextAction::Retry,
                NextAction::Status,
                NextAction::SettlementStatus,
            ],
        }
    }

    /// Reject an action the mode cannot honor.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidField`] if the action is not in
    /// [`NextAction::permitted_for_mode`] — an application must never be told it
    /// may resume a transfer that has no destination phase.
    pub fn validate_for_mode(&self, mode: TransferMode) -> Result<(), ContractError> {
        if Self::permitted_for_mode(mode).contains(self) {
            return Ok(());
        }
        Err(ContractError::InvalidField {
            artifact: "next action",
            reason: format!("{self:?} is not permitted for transfer mode {mode:?}"),
        })
    }
}

/// The mode-specific body of a receipt.
///
/// Each variant carries exactly the fields its mode produces. There is no shared
/// optional-field bag: a field that a mode cannot produce is absent from its type,
/// so an application cannot read a plausible-looking zero where nothing happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ReceiptBody {
    /// Result of an interactive off-chain send.
    Send(SendBody),
    /// Result of issuing an invoice.
    Invoice(InvoiceBody),
    /// Result of accepting a consignment.
    Accept(AcceptBody),
    /// Result of an on-chain materialization.
    Materialize(Box<MaterializeBody>),
}

impl ReceiptBody {
    /// The mode this body belongs to.
    pub fn mode(&self) -> TransferMode {
        match self {
            Self::Send(_) => TransferMode::Send,
            Self::Invoice(_) => TransferMode::Invoice,
            Self::Accept(_) => TransferMode::Accept,
            Self::Materialize(_) => TransferMode::Materialize,
        }
    }
}

/// Off-chain send: the source seal was closed and a consignment emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendBody {
    /// Runtime-assigned transfer identifier.
    pub transfer_id: String,
    /// The sanad that was sent.
    pub sanad_id: SanadIdWire,
    /// Chain the source seal lived on.
    pub source_chain: String,
    /// The single-use source seal that was closed.
    pub source_seal: SealPointWire,
    /// The recipient-controlled destination seal the sanad was assigned to.
    pub destination_seal: SealPointWire,
    /// Canonical id of the invoice this send satisfies.
    #[serde(with = "crate::hexbytes")]
    pub invoice_id: Vec<u8>,
    /// Canonical hash of the emitted consignment (the artifact itself is delivered
    /// off-band; this binds the receipt to the exact bytes handed over).
    #[serde(with = "crate::hexbytes")]
    pub consignment_digest: Vec<u8>,
}

/// Invoice issuance: a destination seal the recipient proved they control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceBody {
    /// Canonical id of the issued invoice.
    #[serde(with = "crate::hexbytes")]
    pub invoice_id: Vec<u8>,
    /// Destination chain the seal lives on.
    pub destination_chain: String,
    /// The seal, with the invoice's anti-replay nonce folded in.
    pub bound_seal: SealPointWire,
    /// Sanad schema the recipient accepts.
    pub schema: String,
    /// The invoice's anti-replay nonce.
    pub nonce: u64,
}

/// Consignment acceptance: client-side validation passed and ownership was recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptBody {
    /// The sanad that was accepted.
    pub sanad_id: SanadIdWire,
    /// Destination chain the accepted seal lives on.
    pub destination_chain: String,
    /// The destination seal the consignment assigned the sanad to.
    pub destination_seal: SealPointWire,
    /// What the client-side verifier actually established. Recorded so a structural
    /// check can never be shown to the recipient as cryptographic success.
    pub assurance: VerificationAssuranceWire,
    /// Finality of the source anchor the consignment's proof was validated against.
    pub finality: FinalityEvidence,
}

/// On-chain materialization: the sanad was locked on the source chain and minted
/// on the destination chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializeBody {
    /// Runtime-assigned transfer identifier.
    pub transfer_id: String,
    /// Replay ID the runtime guarded this transfer with. The runtime is the only
    /// authority for this value.
    pub replay_id: HashWire,
    /// The sanad that was transferred.
    pub sanad_id: SanadIdWire,
    /// Source chain the sanad was locked on.
    pub source_chain: String,
    /// Destination chain the sanad was minted on.
    pub destination_chain: String,
    /// Lock transaction hash on the source chain, as reported by the runtime.
    pub lock_tx_hash: String,
    /// Mint transaction hash on the destination chain, as reported by the runtime.
    /// Empty while the transfer has not yet been minted.
    pub mint_tx_hash: String,
    /// The finality observation the runtime made on the source lock.
    pub finality: FinalityEvidence,
    /// What the canonical verifier established about the source proof, and when.
    pub verification: VerificationRecord,
    /// Destination-side materialization metadata observed by the destination adapter.
    pub materialization: Option<MaterializationWire>,
}

/// Where a receipt's verification claim comes from.
///
/// A receipt must never leave the reader guessing whether the proof was verified
/// *now*, verified *earlier*, or not verified at all. Each possibility is a named
/// variant, so "not established here" can never be read as success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provenance", rename_all = "snake_case")]
pub enum VerificationRecord {
    /// The canonical verifier ran during this execution and reached `assurance`.
    Verified {
        /// What the verifier established.
        assurance: VerificationAssuranceWire,
    },
    /// The proof was verified in an earlier execution and the runtime journal
    /// records it. Nothing was re-verified on this path — the runtime's journal,
    /// not this receipt, is the authority for that earlier result.
    JournalRecorded,
    /// The transfer has not reached proof verification yet.
    NotYetVerified,
}

impl VerificationRecord {
    /// Whether this record may accompany a destination mint.
    ///
    /// A mint is only ever submitted after the canonical verifier accepted the
    /// source proof, so a receipt showing a mint must show either that
    /// verification (cryptographic, never structural-only) or the journal's record
    /// of it. `NotYetVerified` alongside a mint is a contradiction.
    fn may_accompany_mint(&self) -> bool {
        match self {
            Self::Verified { assurance } => assurance.is_cryptographic(),
            Self::JournalRecorded => true,
            Self::NotYetVerified => false,
        }
    }
}

/// Destination-side materialization metadata, as observed by the destination adapter.
///
/// Every field is optional because the adapter reports only what it actually
/// observed. `None` means "not observed", never "zero".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializationWire {
    /// Destination chain that produced the metadata.
    pub chain_id: String,
    /// Destination object/account/resource id, when observed.
    pub object_id: Option<String>,
    /// Destination seal reference, when observed.
    pub seal_ref: Option<String>,
    /// Destination registry reference, when observed.
    pub registry_ref: Option<String>,
    /// Commitment recorded by the destination chain, when observed.
    pub commitment: Option<String>,
    /// Destination owner recorded by the destination chain, when observed.
    pub owner: Option<String>,
}

/// A receipt for one transfer, in one mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferReceipt {
    /// Versioned contract header.
    pub header: ContractHeader,
    /// The mode-specific body.
    pub body: ReceiptBody,
    /// The actions this transfer permits now. Empty means: nothing to do.
    pub next_actions: Vec<NextAction>,
    /// Unix seconds when the receipt was produced.
    pub emitted_at: u64,
}

impl TransferReceipt {
    /// Build a receipt at the current contract version.
    pub fn new(body: ReceiptBody, next_actions: Vec<NextAction>, emitted_at: u64) -> Self {
        Self {
            header: ContractHeader::current(ArtifactKind::TransferReceipt),
            body,
            next_actions,
            emitted_at,
        }
    }

    /// The mode this receipt belongs to.
    pub fn mode(&self) -> TransferMode {
        self.body.mode()
    }

    /// The runtime transfer id, for the modes the runtime assigns one to.
    ///
    /// `Invoice` and `Accept` have none: nothing was submitted to the runtime's
    /// transfer coordinator, so there is no transfer to identify.
    pub fn transfer_id(&self) -> Option<&str> {
        match &self.body {
            ReceiptBody::Send(b) => Some(&b.transfer_id),
            ReceiptBody::Materialize(b) => Some(&b.transfer_id),
            ReceiptBody::Invoice(_) | ReceiptBody::Accept(_) => None,
        }
    }

    /// The runtime replay id, for the modes the runtime guards with one.
    pub fn replay_id(&self) -> Option<&HashWire> {
        match &self.body {
            ReceiptBody::Materialize(b) => Some(&b.replay_id),
            ReceiptBody::Send(_) | ReceiptBody::Invoice(_) | ReceiptBody::Accept(_) => None,
        }
    }
}

impl ContractArtifact for TransferReceipt {
    const KIND: ArtifactKind = ArtifactKind::TransferReceipt;

    fn header(&self) -> &ContractHeader {
        &self.header
    }

    fn validate(&self) -> Result<(), ContractError> {
        const ARTIFACT: &str = "transfer receipt";
        match &self.body {
            ReceiptBody::Send(b) => {
                require_nonempty(ARTIFACT, "transfer_id", &b.transfer_id)?;
                require_nonempty(ARTIFACT, "source_chain", &b.source_chain)?;
                require_nonempty(ARTIFACT, "sanad_id", &b.sanad_id.bytes)?;
                require_digest(ARTIFACT, "invoice_id", &b.invoice_id)?;
                require_digest(ARTIFACT, "consignment_digest", &b.consignment_digest)?;
            }
            ReceiptBody::Invoice(b) => {
                require_digest(ARTIFACT, "invoice_id", &b.invoice_id)?;
                require_nonempty(ARTIFACT, "destination_chain", &b.destination_chain)?;
                require_nonempty(ARTIFACT, "schema", &b.schema)?;
                require_nonempty(ARTIFACT, "bound_seal.id", &b.bound_seal.id)?;
            }
            ReceiptBody::Accept(b) => {
                require_nonempty(ARTIFACT, "sanad_id", &b.sanad_id.bytes)?;
                require_nonempty(ARTIFACT, "destination_chain", &b.destination_chain)?;
                require_nonempty(ARTIFACT, "destination_seal.id", &b.destination_seal.id)?;
                b.finality.validate()?;
                if !b.assurance.is_cryptographic() {
                    return Err(ContractError::InvalidField {
                        artifact: ARTIFACT,
                        reason: "accept receipt reports structural-only assurance: a consignment \
                                 accepted without cryptographic verification must not be receipted"
                            .to_string(),
                    });
                }
            }
            ReceiptBody::Materialize(b) => {
                require_nonempty(ARTIFACT, "transfer_id", &b.transfer_id)?;
                require_nonempty(ARTIFACT, "replay_id", &b.replay_id.bytes)?;
                require_nonempty(ARTIFACT, "sanad_id", &b.sanad_id.bytes)?;
                require_nonempty(ARTIFACT, "source_chain", &b.source_chain)?;
                require_nonempty(ARTIFACT, "destination_chain", &b.destination_chain)?;
                require_nonempty(ARTIFACT, "lock_tx_hash", &b.lock_tx_hash)?;
                b.finality.validate()?;

                // A minted transfer must show what verified it, and must not show a
                // live observation that contradicts the mint. Neither is inferable
                // from the presence of a mint transaction hash.
                if !b.mint_tx_hash.is_empty() {
                    if !b.verification.may_accompany_mint() {
                        return Err(ContractError::InvalidField {
                            artifact: ARTIFACT,
                            reason: format!(
                                "materialize receipt reports a mint with verification record \
                                 {:?}: a mint is only ever submitted after the canonical verifier \
                                 accepted the source proof",
                                b.verification
                            ),
                        });
                    }
                    // `JournalRecovered` evidence is an explicit "not re-observed on
                    // this path" and is allowed to accompany a mint the runtime
                    // journal already recorded. What is never allowed is a *live*
                    // observation that shows the lock short of the required depth
                    // sitting next to a mint that could only follow finality.
                    let observed_live = !matches!(b.finality, FinalityEvidence::JournalRecovered);
                    if observed_live && !b.finality.is_final() {
                        return Err(ContractError::InvalidField {
                            artifact: ARTIFACT,
                            reason: "materialize receipt reports a mint while its own finality \
                                     observation shows the source lock short of the required depth"
                                .to_string(),
                        });
                    }
                }
            }
        }

        for action in &self.next_actions {
            action.validate_for_mode(self.mode())?;
        }
        Ok(())
    }
}

/// Reject a digest field that is absent or not 32 bytes.
fn require_digest(
    artifact: &'static str,
    field: &'static str,
    bytes: &[u8],
) -> Result<(), ContractError> {
    if bytes.len() != 32 {
        return Err(ContractError::InvalidField {
            artifact,
            reason: format!(
                "{field} must be a 32-byte digest, got {} bytes",
                bytes.len()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{decode, encode};

    fn seal(tag: u8) -> SealPointWire {
        SealPointWire {
            id: hex::encode([tag; 32]),
            nonce: Some(7),
            version: Some(1),
        }
    }

    fn final_evidence() -> FinalityEvidence {
        FinalityEvidence::ObservedTip {
            confirming_block_height: 100,
            observed_tip_height: 106,
            confirmations: 6,
            required_confirmations: 6,
        }
    }

    fn materialize_body() -> MaterializeBody {
        MaterializeBody {
            transfer_id: "transfer-1".to_string(),
            replay_id: HashWire {
                bytes: hex::encode([0x22u8; 32]),
            },
            sanad_id: SanadIdWire {
                bytes: hex::encode([0x11u8; 32]),
            },
            source_chain: "bitcoin".to_string(),
            destination_chain: "sui".to_string(),
            lock_tx_hash: "aa".repeat(32),
            mint_tx_hash: "bb".repeat(32),
            finality: final_evidence(),
            verification: VerificationRecord::Verified {
                assurance: VerificationAssuranceWire::ConsensusVerified,
            },
            materialization: None,
        }
    }

    fn materialize_receipt() -> TransferReceipt {
        TransferReceipt::new(
            ReceiptBody::Materialize(Box::new(materialize_body())),
            vec![NextAction::Status, NextAction::SettlementStatus],
            1_700_000_000,
        )
    }

    #[test]
    fn materialize_receipt_carries_runtime_ids_and_next_actions() {
        let receipt = materialize_receipt();
        let bytes = encode(&receipt).expect("valid receipt encodes");
        let back: TransferReceipt = decode(&bytes).expect("decodes");

        assert_eq!(back.mode(), TransferMode::Materialize);
        assert_eq!(back.transfer_id(), Some("transfer-1"));
        assert_eq!(
            back.replay_id().map(|r| r.bytes.as_str()),
            Some(hex::encode([0x22u8; 32]).as_str())
        );
        assert!(back.next_actions.contains(&NextAction::Status));
    }

    #[test]
    fn send_mode_may_not_offer_resume_or_retry() {
        // An off-chain send has no destination phase; offering resume would invite
        // the user into a call the runtime cannot honor.
        for action in [NextAction::Resume, NextAction::Retry] {
            assert!(
                action.validate_for_mode(TransferMode::Send).is_err(),
                "{action:?} must not be permitted for send"
            );
            assert!(action.validate_for_mode(TransferMode::Materialize).is_ok());
        }
    }

    #[test]
    fn receipt_with_action_its_mode_cannot_honor_is_rejected() {
        let receipt = TransferReceipt::new(
            ReceiptBody::Send(SendBody {
                transfer_id: "t-1".to_string(),
                sanad_id: SanadIdWire {
                    bytes: hex::encode([0x11u8; 32]),
                },
                source_chain: "bitcoin".to_string(),
                source_seal: seal(0xAA),
                destination_seal: seal(0xBB),
                invoice_id: vec![0x33; 32],
                consignment_digest: vec![0x44; 32],
            }),
            vec![NextAction::Resume],
            1_700_000_000,
        );
        assert!(matches!(
            receipt.validate(),
            Err(ContractError::InvalidField { .. })
        ));
        assert!(
            encode(&receipt).is_err(),
            "must not encode an unhonorable action"
        );
    }

    #[test]
    fn mint_with_structural_only_verification_is_rejected() {
        let mut body = materialize_body();
        body.verification = VerificationRecord::Verified {
            assurance: VerificationAssuranceWire::StructuralOnly,
        };
        let receipt = TransferReceipt::new(
            ReceiptBody::Materialize(Box::new(body)),
            vec![],
            1_700_000_000,
        );
        assert!(
            receipt.validate().is_err(),
            "structural-only verification must never be receipted as a completed mint"
        );
    }

    #[test]
    fn mint_with_no_verification_at_all_is_rejected() {
        let mut body = materialize_body();
        body.verification = VerificationRecord::NotYetVerified;
        let receipt = TransferReceipt::new(
            ReceiptBody::Materialize(Box::new(body)),
            vec![],
            1_700_000_000,
        );
        assert!(matches!(
            receipt.validate(),
            Err(ContractError::InvalidField { .. })
        ));
    }

    #[test]
    fn mint_contradicted_by_its_own_finality_observation_is_rejected() {
        let mut body = materialize_body();
        body.finality = FinalityEvidence::ObservedTip {
            confirming_block_height: 100,
            observed_tip_height: 102,
            confirmations: 2,
            required_confirmations: 6,
        };
        let receipt = TransferReceipt::new(
            ReceiptBody::Materialize(Box::new(body)),
            vec![],
            1_700_000_000,
        );
        assert!(
            receipt.validate().is_err(),
            "a mint may not sit next to a live observation showing the lock short of finality"
        );
    }

    #[test]
    fn mint_recovered_from_the_journal_states_its_provenance() {
        // Resuming an already-minted transfer re-reads neither the chain nor the
        // proof. The receipt says so, and is accepted precisely because it does not
        // claim a fresh observation it never made.
        let mut body = materialize_body();
        body.finality = FinalityEvidence::JournalRecovered;
        body.verification = VerificationRecord::JournalRecorded;
        let receipt = TransferReceipt::new(
            ReceiptBody::Materialize(Box::new(body)),
            vec![NextAction::Status],
            1_700_000_000,
        );
        assert!(receipt.validate().is_ok());
        assert!(
            !FinalityEvidence::JournalRecovered.is_final(),
            "a journal-recovered record must never be reported as final"
        );
    }

    #[test]
    fn pending_materialize_without_mint_needs_no_verification() {
        // Locked, awaiting finality: no mint yet, so no verification has happened.
        let mut body = materialize_body();
        body.mint_tx_hash = String::new();
        body.verification = VerificationRecord::NotYetVerified;
        body.finality = FinalityEvidence::ObservedTip {
            confirming_block_height: 100,
            observed_tip_height: 102,
            confirmations: 2,
            required_confirmations: 6,
        };
        let receipt = TransferReceipt::new(
            ReceiptBody::Materialize(Box::new(body)),
            vec![NextAction::Resume],
            1_700_000_000,
        );
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn accept_with_structural_only_assurance_is_rejected() {
        let receipt = TransferReceipt::new(
            ReceiptBody::Accept(AcceptBody {
                sanad_id: SanadIdWire {
                    bytes: hex::encode([0x11u8; 32]),
                },
                destination_chain: "sui".to_string(),
                destination_seal: seal(0xBB),
                assurance: VerificationAssuranceWire::StructuralOnly,
                finality: final_evidence(),
            }),
            vec![],
            1_700_000_000,
        );
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn short_invoice_digest_is_rejected() {
        let receipt = TransferReceipt::new(
            ReceiptBody::Invoice(InvoiceBody {
                invoice_id: vec![0x33; 16],
                destination_chain: "sui".to_string(),
                bound_seal: seal(0xBB),
                schema: "payment".to_string(),
                nonce: 1,
            }),
            vec![NextAction::DeliverInvoice],
            1_700_000_000,
        );
        assert!(matches!(
            receipt.validate(),
            Err(ContractError::InvalidField { .. })
        ));
    }
}
