//! Transfer lifecycle events.
//!
//! One event per phase the runtime actually reached. Applications render the
//! lifecycle from these; they never infer a phase from a transaction hash, an
//! explorer response, or the absence of an error.

use serde::{Deserialize, Serialize};

use super::receipt::{NextAction, TransferMode};
use super::{ArtifactKind, ContractArtifact, ContractError, ContractHeader, require_nonempty};
use crate::primitives::{HashWire, SanadIdWire};

/// Evidence that a source-chain lock reached (or has not yet reached) finality.
///
/// A confirmation count alone is not evidence: `confirmations >= required` can be
/// made true by arithmetic on the required depth (RUNTIME-FINALITY-TAUTOLOGY-001).
/// Each variant therefore names *where the depth came from*, and the variant that
/// carries a real chain-tip observation says so explicitly. There is no variant
/// that means "assume final".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum FinalityEvidence {
    /// Depth measured against a source-chain tip the adapter actually read.
    ///
    /// This is the only variant that carries an observed tip, and the only one a
    /// probabilistic-finality chain may produce.
    ObservedTip {
        /// Height of the block that includes the lock transaction.
        confirming_block_height: u64,
        /// Source-chain tip height observed when the depth was measured.
        observed_tip_height: u64,
        /// Confirmations observed on the lock (`observed_tip - confirming_height`).
        confirmations: u64,
        /// Depth the source chain's finality policy requires.
        required_confirmations: u64,
    },

    /// The chain itself reported the transaction as final; no tip height was read.
    ///
    /// Only legitimate for a deterministic-finality chain, where depth-below-tip is
    /// not the finality criterion. Kept distinct from [`FinalityEvidence::ObservedTip`]
    /// so a consumer can never mistake "the chain says final" for "I watched the tip".
    ChainReported {
        /// Height/slot/checkpoint that includes the lock transaction.
        confirming_block_height: u64,
        /// Confirmations the chain reported, if it reports a count at all.
        confirmations: u64,
        /// Depth the source chain's finality policy requires.
        required_confirmations: u64,
    },

    /// The record was recovered from the runtime journal without a fresh chain read.
    ///
    /// Carries no depth, because none was observed on this path. A consumer must
    /// render this as "not re-observed", never as "final".
    JournalRecovered,
}

impl FinalityEvidence {
    /// Whether the evidence shows the required depth was met.
    ///
    /// [`FinalityEvidence::JournalRecovered`] is never final: nothing was observed,
    /// so nothing can be concluded.
    pub fn is_final(&self) -> bool {
        match self {
            Self::ObservedTip {
                confirmations,
                required_confirmations,
                ..
            }
            | Self::ChainReported {
                confirmations,
                required_confirmations,
                ..
            } => confirmations >= required_confirmations,
            Self::JournalRecovered => false,
        }
    }

    /// Reject evidence that cannot describe a real observation.
    ///
    /// # Errors
    ///
    /// - A zero required depth: a policy of "zero confirmations" makes the finality
    ///   gate pass by construction, which is the tautology this contract exists to
    ///   prevent.
    /// - An observed tip below the confirming block: no chain can report a
    ///   transaction mined above its own tip.
    /// - An observed depth that disagrees with `tip - confirming_height`: the count
    ///   and the tip must corroborate each other, or one of them is fabricated.
    pub fn validate(&self) -> Result<(), ContractError> {
        const ARTIFACT: &str = "finality evidence";
        let invalid = |reason: String| ContractError::InvalidField {
            artifact: ARTIFACT,
            reason,
        };

        match self {
            Self::ObservedTip {
                confirming_block_height,
                observed_tip_height,
                confirmations,
                required_confirmations,
            } => {
                if *required_confirmations == 0 {
                    return Err(invalid(
                        "required_confirmations is 0: a zero-depth policy passes the finality gate by construction".to_string(),
                    ));
                }
                if observed_tip_height < confirming_block_height {
                    return Err(invalid(format!(
                        "observed tip {observed_tip_height} is below the confirming block {confirming_block_height}"
                    )));
                }
                let implied = observed_tip_height.saturating_sub(*confirming_block_height);
                if implied != *confirmations {
                    return Err(invalid(format!(
                        "confirmations {confirmations} disagree with the observed tip: \
                         tip {observed_tip_height} - confirming block {confirming_block_height} = {implied}"
                    )));
                }
                Ok(())
            }
            Self::ChainReported {
                required_confirmations,
                ..
            } => {
                if *required_confirmations == 0 {
                    return Err(invalid(
                        "required_confirmations is 0: a zero-depth policy passes the finality gate by construction".to_string(),
                    ));
                }
                Ok(())
            }
            Self::JournalRecovered => Ok(()),
        }
    }
}

/// Coarse assurance reached by the canonical verifier.
///
/// Mirrors `csv_protocol::verification_levels::VerificationLevel` on the wire.
/// Not an authorization signal: the runtime authorizes a mint against per-chain
/// thresholds, not against this label. It exists so an application can *show* what
/// was actually verified — in particular, so a structural-only check can never be
/// presented as cryptographic success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationAssuranceWire {
    /// Structure parsed. No cryptographic check was performed.
    StructuralOnly,
    /// Merkle inclusion verified. Finality not yet confirmed.
    MerkleVerified,
    /// Full cryptographic verification complete.
    FullyVerified,
    /// Cryptographically verified and confirmed to the chain's finality threshold.
    ConsensusVerified,
}

impl VerificationAssuranceWire {
    /// Whether this assurance reflects a real cryptographic verification.
    ///
    /// `StructuralOnly` does not: presenting it as verification success is a
    /// production prohibition, and applications use this to keep them apart.
    pub fn is_cryptographic(&self) -> bool {
        !matches!(self, Self::StructuralOnly)
    }
}

/// A phase of the transfer lifecycle, with the evidence that phase produced.
///
/// The variants follow the runtime's own state machine. An application renders
/// exactly the phases the runtime reports; it does not synthesize intermediate
/// phases to make a progress bar look continuous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum TransferPhase {
    /// Admission control accepted the transfer into the runtime.
    Admitted,
    /// The recipient-controlled destination seal was verified as theirs.
    SealOwnershipVerified {
        /// The seal, as the recipient nominated it.
        seal_id: String,
    },
    /// The source seal was consumed by an on-chain lock.
    Locked {
        /// Lock transaction hash, in the chain's native encoding.
        lock_tx_hash: String,
    },
    /// The lock is on-chain but has not yet reached the required depth.
    AwaitingFinality {
        /// Depth observed so far, and where the observation came from.
        evidence: FinalityEvidence,
    },
    /// The lock reached the depth the source chain's finality policy requires.
    FinalityReached {
        /// The observation that established finality.
        evidence: FinalityEvidence,
    },
    /// An inclusion + finality proof bundle was built against the confirming block.
    ProofBuilt {
        /// Canonical hash of the proof bundle.
        #[serde(with = "crate::hexbytes")]
        proof_hash: Vec<u8>,
    },
    /// The canonical verifier accepted the proof bundle.
    ProofVerified {
        /// What the verifier actually established.
        assurance: VerificationAssuranceWire,
    },
    /// The proof was submitted to the destination chain.
    SubmittedToDestination {
        /// Destination chain the proof was submitted to.
        destination_chain: String,
    },
    /// The destination chain confirmed the materialization.
    Settled {
        /// Destination mint transaction hash.
        mint_tx_hash: String,
    },
    /// The transfer stopped in a state the runtime journal can resume or retry.
    RecoveryRequired {
        /// Why the runtime stopped.
        reason: String,
    },
    /// The transfer failed terminally.
    Failed {
        /// Machine-readable runtime error code.
        code: String,
        /// Human-readable failure message.
        message: String,
    },
}

impl TransferPhase {
    /// Validate the evidence this phase carries.
    fn validate(&self) -> Result<(), ContractError> {
        const ARTIFACT: &str = "transfer event";
        match self {
            Self::AwaitingFinality { evidence } => evidence.validate(),
            Self::FinalityReached { evidence } => {
                evidence.validate()?;
                if !evidence.is_final() {
                    return Err(ContractError::InvalidField {
                        artifact: ARTIFACT,
                        reason: format!(
                            "finality_reached carries evidence that does not show the required depth: {evidence:?}"
                        ),
                    });
                }
                Ok(())
            }
            Self::SealOwnershipVerified { seal_id } => {
                require_nonempty(ARTIFACT, "seal_id", seal_id)
            }
            Self::Locked { lock_tx_hash } => {
                require_nonempty(ARTIFACT, "lock_tx_hash", lock_tx_hash)
            }
            Self::ProofBuilt { proof_hash } => {
                if proof_hash.len() != 32 {
                    return Err(ContractError::InvalidField {
                        artifact: ARTIFACT,
                        reason: format!("proof_hash must be 32 bytes, got {}", proof_hash.len()),
                    });
                }
                Ok(())
            }
            Self::SubmittedToDestination { destination_chain } => {
                require_nonempty(ARTIFACT, "destination_chain", destination_chain)
            }
            Self::Settled { mint_tx_hash } => {
                require_nonempty(ARTIFACT, "mint_tx_hash", mint_tx_hash)
            }
            Self::RecoveryRequired { reason } => require_nonempty(ARTIFACT, "reason", reason),
            Self::Failed { code, message } => {
                require_nonempty(ARTIFACT, "code", code)?;
                require_nonempty(ARTIFACT, "message", message)
            }
            Self::Admitted | Self::ProofVerified { .. } => Ok(()),
        }
    }
}

/// A lifecycle event for one transfer, as reported by the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEvent {
    /// Versioned contract header.
    pub header: ContractHeader,
    /// Which transfer mode this event belongs to.
    pub mode: TransferMode,
    /// Runtime-assigned transfer identifier.
    pub transfer_id: String,
    /// Replay ID the runtime is guarding this transfer with, once assigned.
    pub replay_id: Option<HashWire>,
    /// The sanad being transferred.
    pub sanad_id: SanadIdWire,
    /// Source chain.
    pub source_chain: String,
    /// The phase reached, with its evidence.
    pub phase: TransferPhase,
    /// Actions this transfer permits now. Empty means: wait, do not act.
    pub next_actions: Vec<NextAction>,
    /// Unix seconds when the runtime reported the phase.
    pub observed_at: u64,
}

impl TransferEvent {
    /// Build an event at the current contract version.
    ///
    /// Every parameter is a field the event cannot be meaningful without; grouping
    /// them into a sub-struct would only move the same list one level down.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: TransferMode,
        transfer_id: String,
        replay_id: Option<HashWire>,
        sanad_id: SanadIdWire,
        source_chain: String,
        phase: TransferPhase,
        next_actions: Vec<NextAction>,
        observed_at: u64,
    ) -> Self {
        Self {
            header: ContractHeader::current(ArtifactKind::TransferEvent),
            mode,
            transfer_id,
            replay_id,
            sanad_id,
            source_chain,
            phase,
            next_actions,
            observed_at,
        }
    }
}

impl ContractArtifact for TransferEvent {
    const KIND: ArtifactKind = ArtifactKind::TransferEvent;

    fn header(&self) -> &ContractHeader {
        &self.header
    }

    fn validate(&self) -> Result<(), ContractError> {
        const ARTIFACT: &str = "transfer event";
        require_nonempty(ARTIFACT, "transfer_id", &self.transfer_id)?;
        require_nonempty(ARTIFACT, "source_chain", &self.source_chain)?;
        require_nonempty(ARTIFACT, "sanad_id", &self.sanad_id.bytes)?;
        self.phase.validate()?;
        for action in &self.next_actions {
            action.validate_for_mode(self.mode)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{decode, encode};

    fn observed(confirmations: u64, required: u64) -> FinalityEvidence {
        FinalityEvidence::ObservedTip {
            confirming_block_height: 100,
            observed_tip_height: 100 + confirmations,
            confirmations,
            required_confirmations: required,
        }
    }

    fn event(phase: TransferPhase) -> TransferEvent {
        TransferEvent::new(
            TransferMode::Materialize,
            "transfer-1".to_string(),
            None,
            SanadIdWire {
                bytes: hex::encode([0x11u8; 32]),
            },
            "bitcoin".to_string(),
            phase,
            vec![],
            1_700_000_000,
        )
    }

    #[test]
    fn finality_event_carries_the_observed_tip() {
        let e = event(TransferPhase::FinalityReached {
            evidence: observed(6, 6),
        });
        let bytes = encode(&e).expect("valid finality event encodes");
        let back: TransferEvent = decode(&bytes).expect("decodes");

        match back.phase {
            TransferPhase::FinalityReached {
                evidence:
                    FinalityEvidence::ObservedTip {
                        observed_tip_height,
                        confirming_block_height,
                        ..
                    },
            } => {
                assert_eq!(observed_tip_height, 106);
                assert_eq!(confirming_block_height, 100);
            }
            other => panic!("expected observed-tip finality evidence, got {other:?}"),
        }
    }

    #[test]
    fn zero_required_depth_is_rejected() {
        // A zero-depth policy would make the finality gate pass by construction.
        let e = event(TransferPhase::AwaitingFinality {
            evidence: observed(0, 0),
        });
        assert!(matches!(
            e.validate(),
            Err(ContractError::InvalidField { .. })
        ));
    }

    #[test]
    fn tip_below_confirming_block_is_rejected() {
        let e = event(TransferPhase::AwaitingFinality {
            evidence: FinalityEvidence::ObservedTip {
                confirming_block_height: 100,
                observed_tip_height: 99,
                confirmations: 0,
                required_confirmations: 6,
            },
        });
        assert!(matches!(
            e.validate(),
            Err(ContractError::InvalidField { .. })
        ));
    }

    #[test]
    fn confirmations_must_corroborate_the_observed_tip() {
        // Claiming 6 confirmations while the observed tip implies 1 is a fabrication.
        let e = event(TransferPhase::AwaitingFinality {
            evidence: FinalityEvidence::ObservedTip {
                confirming_block_height: 100,
                observed_tip_height: 101,
                confirmations: 6,
                required_confirmations: 6,
            },
        });
        assert!(matches!(
            e.validate(),
            Err(ContractError::InvalidField { .. })
        ));
    }

    #[test]
    fn finality_reached_below_required_depth_is_rejected() {
        let e = event(TransferPhase::FinalityReached {
            evidence: observed(2, 6),
        });
        assert!(matches!(
            e.validate(),
            Err(ContractError::InvalidField { .. })
        ));
    }

    #[test]
    fn journal_recovered_evidence_is_never_final() {
        assert!(!FinalityEvidence::JournalRecovered.is_final());

        let e = event(TransferPhase::FinalityReached {
            evidence: FinalityEvidence::JournalRecovered,
        });
        assert!(
            e.validate().is_err(),
            "a finality-reached event must not be backed by an unobserved journal record"
        );
    }

    #[test]
    fn structural_only_assurance_is_not_cryptographic() {
        assert!(!VerificationAssuranceWire::StructuralOnly.is_cryptographic());
        assert!(VerificationAssuranceWire::MerkleVerified.is_cryptographic());
        assert!(VerificationAssuranceWire::ConsensusVerified.is_cryptographic());
    }

    #[test]
    fn empty_transfer_id_is_rejected() {
        let mut e = event(TransferPhase::Admitted);
        e.transfer_id = String::new();
        assert!(matches!(
            e.validate(),
            Err(ContractError::MissingField { .. })
        ));
    }

    #[test]
    fn short_proof_hash_is_rejected() {
        let e = event(TransferPhase::ProofBuilt {
            proof_hash: vec![0u8; 16],
        });
        assert!(matches!(
            e.validate(),
            Err(ContractError::InvalidField { .. })
        ));
    }
}
