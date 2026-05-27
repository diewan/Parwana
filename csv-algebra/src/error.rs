use alloc::string::{String, ToString};

/// Algebra-level errors.
///
/// These are pure domain errors with no std::error::Error implementation
/// (since this crate is no_std). They represent invalid state transitions,
/// malformed data, or protocol violations at the algebraic level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgebraError {
    InvalidTransition {
        from: String,
        to: String,
        reason: String,
    },
    InvalidProof {
        reason: String,
    },
    InvalidFinality {
        reason: String,
    },
    InvalidReplayId {
        reason: String,
    },
    InvalidTransferId {
        reason: String,
    },
}

impl AlgebraError {
    pub fn invalid_transition(from: &str, to: &str, reason: &str) -> Self {
        Self::InvalidTransition {
            from: from.to_string(),
            to: to.to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn invalid_proof(reason: &str) -> Self {
        Self::InvalidProof {
            reason: reason.to_string(),
        }
    }

    pub fn invalid_finality(reason: &str) -> Self {
        Self::InvalidFinality {
            reason: reason.to_string(),
        }
    }

    pub fn invalid_replay_id(reason: &str) -> Self {
        Self::InvalidReplayId {
            reason: reason.to_string(),
        }
    }

    pub fn invalid_transfer_id(reason: &str) -> Self {
        Self::InvalidTransferId {
            reason: reason.to_string(),
        }
    }
}
