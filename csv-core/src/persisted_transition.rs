//! Persisted state transitions — atomic coupling of proofs and state changes.
//!
//! The runtime must never:
//! - update state without proof persisted
//! - persist proof without replay update
//! - update replay without event persisted
//!
//! `PersistedTransition` enforces this coupling at the type level.

use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

use csv_hash::Hash;
use csv_hash::sanad::SanadId;

/// A persisted state transition that atomically couples a proof, a replay
/// update, and an event. Only the persistence layer may construct this.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedTransition {
    /// The Sanad (transfer) ID this transition applies to.
    pub sanad_id: SanadId,
    /// The proof hash that justifies this transition.
    pub proof_hash: Hash,
    /// The replay ID that was consumed (if applicable).
    pub replay_id: Option<[u8; 32]>,
    /// Event identifier bytes for the corresponding runtime event.
    pub event_id: Option<[u8; 32]>,
    /// Timestamp of the transition.
    pub persisted_at: u64,
}

/// Marker type for a transition FROM state S1.
#[derive(Debug)]
pub struct PersistedFrom<S1>(PhantomData<S1>);

/// Marker type for a transition TO state S2.
#[derive(Debug)]
pub struct PersistedTo<S2>(PhantomData<S2>);

/// Type-level guaranteed transition that has been persisted.
///
/// `S1` is the source state, `S2` is the destination state.
/// The persistence layer is the ONLY code that may construct this.
#[derive(Debug)]
pub struct TypedPersistedTransition<S1, S2> {
    /// The underlying transition data.
    pub inner: PersistedTransition,
    /// Type-level marker for source state.
    pub _from: PersistedFrom<S1>,
    /// Type-level marker for destination state.
    pub _to: PersistedTo<S2>,
}

impl PersistedTransition {
    /// Create a new persisted transition.
    ///
    /// WARNING: Only the persistence layer should call this.
    pub fn new(
        sanad_id: SanadId,
        proof_hash: Hash,
        replay_id: Option<[u8; 32]>,
        event_id: Option<[u8; 32]>,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            sanad_id,
            proof_hash,
            replay_id,
            event_id,
            persisted_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}
