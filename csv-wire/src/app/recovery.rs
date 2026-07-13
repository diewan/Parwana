//! Recovery: what a stalled transfer permits, according to the runtime journal.
//!
//! The journal is the authority for what a transfer may do next. An application
//! renders this plan; it never decides on its own that a transfer is resumable,
//! and it never mutates transfer state to make one appear so.

use serde::{Deserialize, Serialize};

use super::receipt::{NextAction, TransferMode};
use super::{ArtifactKind, ContractArtifact, ContractError, ContractHeader, require_nonempty};

/// Why a transfer needs an explicit recovery action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RecoveryReason {
    /// The lock is on-chain and journaled, but has not reached the required depth.
    /// Resuming later advances it; it is never re-locked.
    AwaitingFinality {
        /// Confirmations observed on the source lock so far.
        confirmations: u64,
        /// Depth the source chain's finality policy requires.
        required_confirmations: u64,
    },
    /// The runtime stopped in a journaled phase after a failure that may be retried.
    FailedAtPhase {
        /// The journaled phase the transfer stopped in.
        phase: String,
        /// The failure the runtime recorded.
        error: String,
    },
    /// The process died mid-transfer; the journal has a phase but no outcome.
    Interrupted {
        /// The last phase the journal recorded an entry for.
        phase: String,
    },
}

/// The recovery actions a transfer permits, per the runtime journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPlan {
    /// Versioned contract header.
    pub header: ContractHeader,
    /// Runtime-assigned transfer identifier.
    pub transfer_id: String,
    /// The mode of the transfer being recovered.
    pub mode: TransferMode,
    /// Why recovery is needed.
    pub reason: RecoveryReason,
    /// The actions the runtime will honor for this transfer, right now.
    ///
    /// Empty means the transfer is not recoverable by any action the application
    /// can take — the correct response is to wait or to report, never to invent one.
    pub permitted_actions: Vec<NextAction>,
    /// Unix seconds when the plan was read from the journal.
    pub observed_at: u64,
}

impl RecoveryPlan {
    /// Build a recovery plan at the current contract version.
    pub fn new(
        transfer_id: String,
        mode: TransferMode,
        reason: RecoveryReason,
        permitted_actions: Vec<NextAction>,
        observed_at: u64,
    ) -> Self {
        Self {
            header: ContractHeader::current(ArtifactKind::RecoveryPlan),
            transfer_id,
            mode,
            reason,
            permitted_actions,
            observed_at,
        }
    }
}

impl ContractArtifact for RecoveryPlan {
    const KIND: ArtifactKind = ArtifactKind::RecoveryPlan;

    fn header(&self) -> &ContractHeader {
        &self.header
    }

    fn validate(&self) -> Result<(), ContractError> {
        const ARTIFACT: &str = "recovery plan";
        require_nonempty(ARTIFACT, "transfer_id", &self.transfer_id)?;

        match &self.reason {
            RecoveryReason::AwaitingFinality {
                required_confirmations,
                ..
            } => {
                if *required_confirmations == 0 {
                    return Err(ContractError::InvalidField {
                        artifact: ARTIFACT,
                        reason: "required_confirmations is 0: a zero-depth policy passes the \
                                 finality gate by construction"
                            .to_string(),
                    });
                }
            }
            RecoveryReason::FailedAtPhase { phase, error } => {
                require_nonempty(ARTIFACT, "phase", phase)?;
                require_nonempty(ARTIFACT, "error", error)?;
            }
            RecoveryReason::Interrupted { phase } => require_nonempty(ARTIFACT, "phase", phase)?,
        }

        for action in &self.permitted_actions {
            action.validate_for_mode(self.mode)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{decode, encode};

    #[test]
    fn awaiting_finality_plan_round_trips() {
        let plan = RecoveryPlan::new(
            "transfer-1".to_string(),
            TransferMode::Materialize,
            RecoveryReason::AwaitingFinality {
                confirmations: 2,
                required_confirmations: 6,
            },
            vec![NextAction::Resume, NextAction::Status],
            1_700_000_000,
        );
        let bytes = encode(&plan).expect("valid plan encodes");
        assert_eq!(decode::<RecoveryPlan>(&bytes).expect("decodes"), plan);
    }

    #[test]
    fn send_mode_cannot_be_offered_resume() {
        // The charter is explicit: an off-chain send has no destination phase, so
        // resume does not apply to it. The contract refuses to say otherwise.
        let plan = RecoveryPlan::new(
            "transfer-1".to_string(),
            TransferMode::Send,
            RecoveryReason::Interrupted {
                phase: "close_source_seal".to_string(),
            },
            vec![NextAction::Resume],
            1_700_000_000,
        );
        assert!(matches!(
            plan.validate(),
            Err(ContractError::InvalidField { .. })
        ));
    }

    #[test]
    fn zero_required_depth_is_rejected() {
        let plan = RecoveryPlan::new(
            "transfer-1".to_string(),
            TransferMode::Materialize,
            RecoveryReason::AwaitingFinality {
                confirmations: 0,
                required_confirmations: 0,
            },
            vec![NextAction::Resume],
            1_700_000_000,
        );
        assert!(plan.validate().is_err());
    }

    #[test]
    fn empty_failure_detail_is_rejected() {
        let plan = RecoveryPlan::new(
            "transfer-1".to_string(),
            TransferMode::Materialize,
            RecoveryReason::FailedAtPhase {
                phase: "proof_building".to_string(),
                error: String::new(),
            },
            vec![NextAction::Retry],
            1_700_000_000,
        );
        assert!(matches!(
            plan.validate(),
            Err(ContractError::MissingField { .. })
        ));
    }
}
