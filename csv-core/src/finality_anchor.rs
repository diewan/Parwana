//! Restart-safe finality anchoring — canonical chain snapshot persistence.
//!
//! On runtime restart, the latest anchor is loaded and compared against the
//! chain's current state. If ancestor continuity is broken (silent historical
//! reorg), a force rollback is triggered before any new transfer proceeds.
//!
//! # Design
//!
//! After each finality progression, the runtime persists:
//! - The finalized block hash and height
//! - Cumulative chain work (for Bitcoin-style chains)
//! - A bounded window of finalized ancestor hashes
//!
//! On restart:
//! 1. Load the latest anchor from persistent storage
//! 2. Re-query the chain state at the anchored height
//! 3. Verify ancestor hash continuity from anchor to current tip
//! 4. If any mismatch is detected, force rollback and alert
//!
//! This prevents the "cold restart invalidation" problem where a runtime
//! assumes no reorg occurred simply because it did not observe one.

use core::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;

/// A persisted snapshot of a chain's finalized state.
///
/// This anchor is the starting point for restart-safety checks. The runtime
/// persists one anchor per chain after each finality progression, and on
/// restart loads the latest anchor and verifies ancestor continuity against
/// the current chain tip.
///
/// # Invariants
///
/// - `finalized_hash` must never be all-zeros (use `Hash::zero()` to detect corruption)
/// - `finalized_height` must be monotonically increasing across anchors on the same chain
/// - `cumulative_work` must be `None` for proof-of-stake chains
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalityAnchor {
    /// Chain this anchor applies to.
    pub chain: ChainId,
    /// The finalized block/checkpoint height.
    pub finalized_height: u64,
    /// The finalized block/checkpoint hash.
    pub finalized_hash: Hash,
    /// Cumulative work (Bitcoin/Proof-of-work chains). `None` for DPoS/BFT.
    pub cumulative_work: Option<u128>,
    /// When this anchor was persisted.
    pub finalized_at: DateTime<Utc>,
}

impl FinalityAnchor {
    /// Create a new finality anchor.
    ///
    /// The `finalized_at` timestamp is set to the current UTC time.
    pub fn new(
        chain: ChainId,
        finalized_height: u64,
        finalized_hash: Hash,
        cumulative_work: Option<u128>,
    ) -> Self {
        Self {
            chain,
            finalized_height,
            finalized_hash,
            cumulative_work,
            finalized_at: Utc::now(),
        }
    }

    /// Verify that a new anchor is a valid successor (same chain, higher height).
    ///
    /// Returns `true` only if:
    /// - Both anchors apply to the same chain
    /// - The new anchor has a strictly greater height
    /// - The new anchor's hash is not all-zeros (corruption check)
    pub fn is_valid_successor(&self, new: &FinalityAnchor) -> bool {
        self.chain == new.chain
            && new.finalized_height > self.finalized_height
            && new.finalized_hash != Hash::zero()
    }

    /// Check if this anchor is older than the given duration.
    ///
    /// Used to detect stale anchors that may need refreshing.
    pub fn is_stale(&self, max_age: Duration) -> bool {
        Utc::now()
            .signed_duration_since(self.finalized_at)
            .to_std()
            .map(|d| d > max_age)
            .unwrap_or(false)
    }

    /// Check if this anchor's hash is valid (non-zero).
    pub fn is_valid(&self) -> bool {
        self.finalized_hash != Hash::zero()
    }
}

/// Every finalized ancestor hash for at least `max_safe_reorg_depth * 4` blocks.
///
/// This provides the historical chain continuity proof needed to detect
/// long-range reorgs that occurred while the runtime was offline.
///
/// # Invariants
///
/// - `ancestor_hashes` must be in descending height order (tip → older)
/// - Heights must be contiguous (no gaps)
/// - The anchor's `finalized_height` must match the first entry's height
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AncestorContinuityProof {
    /// Chain this proof applies to.
    pub chain: ChainId,
    /// The anchor at the time this proof was generated.
    pub anchor: FinalityAnchor,
    /// Ancestor hashes in descending height order (tip → genesis).
    pub ancestor_hashes: Vec<(u64, Hash)>,
    /// Minimum depth of ancestor hashes stored.
    pub min_depth: u64,
}

impl AncestorContinuityProof {
    /// Create a new ancestor continuity proof.
    ///
    /// # Panics
    ///
    /// Panics if `ancestor_hashes` is empty or if the first entry's height
    /// does not match `anchor.finalized_height`.
    pub fn new(
        chain: ChainId,
        anchor: FinalityAnchor,
        ancestor_hashes: Vec<(u64, Hash)>,
        min_depth: u64,
    ) -> Self {
        assert!(
            !ancestor_hashes.is_empty(),
            "ancestor_hashes must not be empty"
        );
        assert_eq!(
            ancestor_hashes[0].0, anchor.finalized_height,
            "first ancestor height must match anchor height"
        );
        Self {
            chain,
            anchor,
            ancestor_hashes,
            min_depth,
        }
    }

    /// The first ancestor hash at or below the reorg safety threshold.
    ///
    /// The safety threshold is `anchor.finalized_height - max_safe_reorg_depth`.
    /// This hash serves as a checkpoint that must exist on-chain for the
    /// anchor to be considered valid after restart.
    pub fn safety_hash(&self, max_safe_reorg_depth: u64) -> Option<(u64, Hash)> {
        let threshold = self
            .anchor
            .finalized_height
            .saturating_sub(max_safe_reorg_depth);
        self.ancestor_hashes
            .iter()
            .find(|(h, _)| *h <= threshold)
            .copied()
    }

    /// Look up the ancestor hash at a specific height.
    ///
    /// Returns `None` if the height is outside the stored range.
    pub fn get_at_height(&self, height: u64) -> Option<&Hash> {
        self.ancestor_hashes
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, hash)| hash)
    }

    /// Verify that ancestor hashes are contiguous (no gaps in height).
    ///
    /// Returns `Ok(())` if all adjacent pairs differ by exactly 1 in height,
    /// `Err` if a gap or ordering violation is detected.
    pub fn verify_contiguous(&self) -> Result<(), ContinuityError> {
        if self.ancestor_hashes.len() < 2 {
            return Ok(());
        }

        for window in self.ancestor_hashes.windows(2) {
            let (higher, _) = window[0];
            let (lower, _) = window[1];
            if higher.saturating_sub(lower) != 1 {
                return Err(ContinuityError::Gap {
                    higher,
                    lower,
                    expected_gap: 1,
                    actual_gap: higher.saturating_sub(lower),
                });
            }
        }

        Ok(())
    }

    /// Verify that all stored ancestors are within the safe reorg depth
    /// from the anchor height.
    ///
    /// Returns `Ok(())` if all ancestors are within `max_safe_reorg_depth`
    /// of the anchor, `Err` if any ancestor is too far back.
    pub fn verify_within_safety_depth(&self, max_safe_reorg_depth: u64) -> Result<(), ContinuityError> {
        let anchor_height = self.anchor.finalized_height;
        for (height, _) in &self.ancestor_hashes {
            let depth = anchor_height.saturating_sub(*height);
            if depth > max_safe_reorg_depth {
                return Err(ContinuityError::BeyondSafetyDepth {
                    height: *height,
                    depth,
                    max_depth: max_safe_reorg_depth,
                });
            }
        }
        Ok(())
    }

    /// Check if a given hash exists in this continuity proof.
    pub fn contains(&self, hash: &Hash) -> bool {
        self.ancestor_hashes.iter().any(|(_, h)| h == hash)
    }

    /// The number of ancestor hashes stored.
    pub fn len(&self) -> usize {
        self.ancestor_hashes.len()
    }

    /// Whether no ancestor hashes are stored.
    pub fn is_empty(&self) -> bool {
        self.ancestor_hashes.is_empty()
    }
}

/// Error detected during ancestor chain continuity verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContinuityError {
    /// A gap was detected in the ancestor chain (non-contiguous heights).
    Gap {
        /// The higher height in the gap.
        higher: u64,
        /// The lower height after the gap.
        lower: u64,
        /// The expected gap between adjacent blocks.
        expected_gap: u64,
        /// The actual gap detected.
        actual_gap: u64,
    },
    /// An ancestor hash is beyond the configured safety depth.
    BeyondSafetyDepth {
        /// The height of the ancestor that is too far back.
        height: u64,
        /// The depth from the anchor.
        depth: u64,
        /// The maximum allowed safety depth.
        max_depth: u64,
    },
    /// Hash mismatch: the stored hash does not match the on-chain hash.
    HashMismatch {
        /// The height where the mismatch occurred.
        height: u64,
        /// The hash expected from the stored continuity proof.
        expected: Hash,
        /// The hash found on-chain.
        found: Hash,
    },
}

impl core::fmt::Display for ContinuityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Gap {
                higher,
                lower: _,
                expected_gap,
                actual_gap,
            } => write!(
                f,
                "Ancestor gap at height {}: expected contiguous (gap {}), found gap {}",
                higher, expected_gap, actual_gap
            ),
            Self::BeyondSafetyDepth {
                height,
                depth,
                max_depth,
            } => write!(
                f,
                "Ancestor at height {} is beyond safety depth: depth {} > max {}",
                height, depth, max_depth
            ),
            Self::HashMismatch {
                height,
                expected,
                found,
            } => write!(
                f,
                "Hash mismatch at height {}: expected {}, found {}",
                height, expected, found
            ),
        }
    }
}

impl std::error::Error for ContinuityError {}

/// Result of a finality anchor restart verification.
///
/// This is returned by the restart safety check after loading the latest
/// anchor and comparing it against the current chain state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestartVerification {
    /// Continuity verified, no reorg detected.
    ///
    /// The anchor's hash chain matches the current chain state.
    Verified {
        /// The anchor that was verified.
        anchor: FinalityAnchor,
    },
    /// Silent reorg detected — rollback required.
    ///
    /// The anchor's hash does not match the current chain state at the
    /// anchored height, indicating a reorg occurred while the runtime
    /// was offline.
    ReorgDetected {
        /// The anchor that was expected.
        expected_anchor: FinalityAnchor,
        /// The actual hash found on-chain at the anchored height.
        actual_hash: Hash,
        /// Actual height found on-chain (may differ from anchor height
        /// if the chain was reorged deeper than the anchor).
        actual_height: u64,
    },
    /// No anchor found — fresh start required.
    ///
    /// This occurs on first startup or after a full rollback.
    NoAnchor,
    /// Anchor is stale — consider creating a new one.
    ///
    /// The anchor exists but has not been updated for longer than
    /// the configured maximum age.
    Stale {
        /// The stale anchor.
        anchor: FinalityAnchor,
    },
}

/// Storage trait for finality anchors and ancestor continuity proofs.
///
/// Implementations may use SQLite, PostgreSQL, or any persistent store.
/// The runtime does not depend on a specific database backend.
///
/// # Invariants
///
/// - Anchors must be stored per-chain with monotonically increasing heights
/// - Ancestor continuity proofs must be stored alongside their anchors
/// - `clear_chain_history` removes all data for a chain (used during full rollback)
pub trait FinalityAnchorStore: Send + Sync {
    /// Save a finality anchor.
    ///
    /// Implementations should ensure that only valid successors are stored
    /// (same chain, higher height).
    fn save_anchor(&self, anchor: &FinalityAnchor) -> Result<(), AnchorStoreError>;

    /// Save an ancestor continuity proof.
    fn save_ancestor_proof(
        &self,
        chain: &ChainId,
        proof: &AncestorContinuityProof,
    ) -> Result<(), AnchorStoreError>;

    /// Load the latest anchor for a chain.
    ///
    /// Returns `Ok(None)` if no anchor exists for the chain.
    fn load_latest_anchor(&self, chain: &ChainId) -> Result<Option<FinalityAnchor>, AnchorStoreError>;

    /// Load the ancestor continuity proof for a chain.
    ///
    /// Returns `Ok(None)` if no proof exists for the chain.
    fn load_ancestor_proof(
        &self,
        chain: &ChainId,
    ) -> Result<Option<AncestorContinuityProof>, AnchorStoreError>;

    /// Delete all anchors and ancestor proofs for a chain (used during full rollback).
    fn clear_chain_history(&self, chain: &ChainId) -> Result<(), AnchorStoreError>;
}

/// Errors that can occur during anchor storage operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorStoreError {
    /// Database I/O error.
    Io(String),
    /// Serialization/deserialization error.
    Serialization(String),
    /// Anchor data is corrupted or incomplete.
    CorruptedData(String),
    /// Attempted to store an invalid anchor (e.g., zero hash, non-increasing height).
    InvalidAnchor(String),
}

impl core::fmt::Display for AnchorStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "Anchor store I/O error: {}", msg),
            Self::Serialization(msg) => write!(f, "Anchor serialization error: {}", msg),
            Self::CorruptedData(msg) => write!(f, "Corrupted anchor data: {}", msg),
            Self::InvalidAnchor(msg) => write!(f, "Invalid anchor: {}", msg),
        }
    }
}

impl std::error::Error for AnchorStoreError {}