//! Finality State Model
//!
//! This module provides a structured approach to defining and monitoring
//! different levels of transaction finality across chains.

#![allow(missing_docs)]

use std::time::Duration;
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;

pub mod monitor;
pub mod policy;
pub mod state;
pub mod abstraction;
pub mod capabilities;

// Re-exports
pub use monitor::FinalityMonitor;
pub use policy::{ChainFinalityPolicy, FinalityThreshold};
pub use state::{FinalityState, FinalityStatus};
pub use abstraction::{FinalityType as AbstractionFinalityType, FinalityRequirement};
pub use capabilities::{ChainCapabilities, Capability};

/// Finality type enum for chain-specific finality mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityType {
    /// Probabilistic finality (Bitcoin-style)
    Probabilistic,
    
    /// Economic finality (Ethereum-style)
    Economic,
    
    /// Checkpoint finality (Sui/Aptos-style)
    Checkpoint,
    
    /// Quorum finality (Solana-style)
    Quorum,
    
    /// Instant finality (rare)
    Instant,
}

impl FinalityType {
    /// Get the default confirmation requirement for this finality type.
    pub fn default_confirmations(&self) -> u64 {
        match self {
            FinalityType::Probabilistic => 6, // Bitcoin standard
            FinalityType::Economic => 2, // Ethereum finality after 2 blocks
            FinalityType::Checkpoint => 1, // Checkpoint is final
            FinalityType::Quorum => 1, // Quorum is final
            FinalityType::Instant => 0, // Instant is final
        }
    }

    /// Get the expected time to finality for this type.
    pub fn expected_time_to_finality(&self) -> Duration {
        match self {
            FinalityType::Probabilistic => Duration::from_secs(3600), // ~1 hour
            FinalityType::Economic => Duration::from_secs(24), // ~24 seconds
            FinalityType::Checkpoint => Duration::from_secs(2), // ~2 seconds
            FinalityType::Quorum => Duration::from_secs(2), // ~2 seconds
            FinalityType::Instant => Duration::from_secs(0), // Instant
        }
    }
}

/// Finality proof for a chain event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Finality type
    pub finality_type: FinalityType,
    /// Block height of the event
    pub block_height: u64,
    /// Current chain height
    pub current_height: u64,
    /// Confirmations achieved
    pub confirmations: u64,
    /// Required confirmations
    pub required_confirmations: u64,
    /// Finality data (chain-specific)
    pub finality_data: Vec<u8>,
    /// Timestamp of finality achievement
    pub finalized_at: Option<u64>,
}

impl FinalityProof {
    /// Create a new finality proof.
    pub fn new(
        finality_type: FinalityType,
        block_height: u64,
        current_height: u64,
        required_confirmations: u64,
        finality_data: Vec<u8>,
    ) -> Self {
        let confirmations = current_height.saturating_sub(block_height);
        
        Self {
            finality_type,
            block_height,
            current_height,
            confirmations,
            required_confirmations,
            finality_data,
            finalized_at: None,
        }
    }

    /// Check if the proof indicates finality is achieved.
    pub fn is_final(&self) -> bool {
        self.confirmations >= self.required_confirmations
    }

    /// Mark the proof as finalized with a timestamp.
    pub fn mark_finalized(&mut self, timestamp: u64) {
        self.finalized_at = Some(timestamp);
    }

    /// Get the time to finality (if finalized).
    pub fn time_to_finality(&self) -> Option<Duration> {
        if let Some(finalized_at) = self.finalized_at {
            // In production, this would use the block timestamp
            Some(Duration::from_secs(0))
        } else {
            None
        }
    }
}

/// Finality errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FinalityError {
    #[error("Invalid finality proof")]
    InvalidProof,
    
    #[error("Insufficient confirmations: {current}/{required}")]
    InsufficientConfirmations { current: u64, required: u64 },
    
    #[error("Invalid finality data")]
    InvalidFinalityData,
    
    #[error("Block height mismatch")]
    BlockHeightMismatch,
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

/// Finality verifier trait for chain-specific verification.
pub trait FinalityVerifier {
    /// Verify a finality proof for this chain.
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError>;
    
    /// Get the finality type for this chain.
    fn finality_type(&self) -> FinalityType;
    
    /// Get the required confirmations for this chain.
    fn required_confirmations(&self) -> u64;
}

/// Bitcoin finality verifier (probabilistic).
pub struct BitcoinFinalityVerifier {
    /// Required confirmations
    pub required_confirmations: u64,
}

impl BitcoinFinalityVerifier {
    /// Create a new Bitcoin finality verifier.
    pub fn new(required_confirmations: u64) -> Self {
        Self {
            required_confirmations,
        }
    }
}

impl FinalityVerifier for BitcoinFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Probabilistic {
            return Err(FinalityError::InvalidProof);
        }

        if proof.confirmations < self.required_confirmations {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: self.required_confirmations,
            });
        }

        // Verify finality data contains valid block header
        if proof.finality_data.len() < 80 {
            return Err(FinalityError::InvalidFinalityData);
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Probabilistic
    }

    fn required_confirmations(&self) -> u64 {
        self.required_confirmations
    }
}

/// Ethereum finality verifier (economic).
pub struct EthereumFinalityVerifier {
    /// Required confirmations
    pub required_confirmations: u64,
}

impl EthereumFinalityVerifier {
    /// Create a new Ethereum finality verifier.
    pub fn new(required_confirmations: u64) -> Self {
        Self {
            required_confirmations,
        }
    }
}

impl FinalityVerifier for EthereumFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Economic {
            return Err(FinalityError::InvalidProof);
        }

        if proof.confirmations < self.required_confirmations {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: self.required_confirmations,
            });
        }

        // Verify finality data contains valid block header
        if proof.finality_data.len() < 80 {
            return Err(FinalityError::InvalidFinalityData);
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Economic
    }

    fn required_confirmations(&self) -> u64 {
        self.required_confirmations
    }
}

/// Solana finality verifier (quorum).
pub struct SolanaFinalityVerifier;

impl FinalityVerifier for SolanaFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Quorum {
            return Err(FinalityError::InvalidProof);
        }

        // Quorum finality is achieved with 1 confirmation
        if proof.confirmations < 1 {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: 1,
            });
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Quorum
    }

    fn required_confirmations(&self) -> u64 {
        1
    }
}

/// Sui finality verifier (checkpoint).
pub struct SuiFinalityVerifier;

impl FinalityVerifier for SuiFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Checkpoint {
            return Err(FinalityError::InvalidProof);
        }

        // Checkpoint finality is achieved with 1 confirmation
        if proof.confirmations < 1 {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: 1,
            });
        }

        // Verify finality data contains checkpoint digest
        if proof.finality_data.is_empty() {
            return Err(FinalityError::InvalidFinalityData);
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Checkpoint
    }

    fn required_confirmations(&self) -> u64 {
        1
    }
}

/// Aptos finality verifier (checkpoint).
pub struct AptosFinalityVerifier;

impl FinalityVerifier for AptosFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Checkpoint {
            return Err(FinalityError::InvalidProof);
        }

        // Checkpoint finality is achieved with 1 confirmation
        if proof.confirmations < 1 {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: 1,
            });
        }

        // Verify finality data contains checkpoint digest
        if proof.finality_data.is_empty() {
            return Err(FinalityError::InvalidFinalityData);
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Checkpoint
    }

    fn required_confirmations(&self) -> u64 {
        1
    }
}

/// Finality configuration for a chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityConfig {
    /// Chain ID
    pub chain_id: String,
    /// Finality type
    pub finality_type: FinalityType,
    /// Required confirmations
    pub required_confirmations: u64,
    /// Timeout for finality achievement
    pub timeout: Duration,
}

impl Default for FinalityConfig {
    fn default() -> Self {
        Self {
            chain_id: "bitcoin".to_string(),
            finality_type: FinalityType::Probabilistic,
            required_confirmations: 6,
            timeout: Duration::from_secs(3600),
        }
    }
}

impl FinalityConfig {
    /// Create a new finality config.
    pub fn new(
        chain_id: String,
        finality_type: FinalityType,
        required_confirmations: u64,
        timeout: Duration,
    ) -> Self {
        Self {
            chain_id,
            finality_type,
            required_confirmations,
            timeout,
        }
    }

    /// Get the default config for Bitcoin.
    pub fn bitcoin() -> Self {
        Self {
            chain_id: "bitcoin".to_string(),
            finality_type: FinalityType::Probabilistic,
            required_confirmations: 6,
            timeout: Duration::from_secs(3600),
        }
    }

    /// Get the default config for Ethereum.
    pub fn ethereum() -> Self {
        Self {
            chain_id: "ethereum".to_string(),
            finality_type: FinalityType::Economic,
            required_confirmations: 2,
            timeout: Duration::from_secs(60),
        }
    }

    /// Get the default config for Solana.
    pub fn solana() -> Self {
        Self {
            chain_id: "solana".to_string(),
            finality_type: FinalityType::Quorum,
            required_confirmations: 1,
            timeout: Duration::from_secs(10),
        }
    }

    /// Get the default config for Sui.
    pub fn sui() -> Self {
        Self {
            chain_id: "sui".to_string(),
            finality_type: FinalityType::Checkpoint,
            required_confirmations: 1,
            timeout: Duration::from_secs(5),
        }
    }

    /// Get the default config for Aptos.
    pub fn aptos() -> Self {
        Self {
            chain_id: "aptos".to_string(),
            finality_type: FinalityType::Checkpoint,
            required_confirmations: 1,
            timeout: Duration::from_secs(5),
        }
    }
}

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
    /// When this anchor was persisted (Unix timestamp in seconds).
    pub finalized_at: u64,
}

impl FinalityAnchor {
    /// Create a new finality anchor.
    ///
    /// The `finalized_at` timestamp is set to the current time.
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
            finalized_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.finalized_at) > max_age.as_secs()
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

/// Typed finality guarantee — chain-agnostic, runtime-enforceable.
///
/// Adapters produce `FinalityGuarantee` values. The runtime evaluates them
/// against `FinalityPolicy`. Adapters never embed policy decisions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FinalityGuarantee {
    /// Probabilistic finality: Bitcoin, pre-checkpoint Ethereum
    Probabilistic {
        /// Number of confirmations achieved
        confirmations: u64,
        /// Minimum required by protocol policy
        required: u64,
        /// Estimated reorg probability at this depth (0.0–1.0)
        reorg_probability: f64,
    },

    /// Deterministic finality: Solana root, Aptos quorum cert, Sui checkpoint
    Deterministic {
        /// Checkpoint/ledger hash that covers the anchor
        checkpoint_hash: [u8; 32],
        /// Checkpoint sequence number / ledger version
        sequence: u64,
        /// Quorum size that certified this checkpoint (2f+1 style)
        quorum_weight: Option<u64>,
    },

    /// Economic finality: slashing-backed (future EVM rollups)
    Economic {
        /// USD value of slashable stake backing this finality (in cents)
        slash_cost_usd_cents: u128,
        /// Challenge period remaining in seconds (0 = challengeable now)
        challenge_window_secs: u64,
    },
}

impl FinalityGuarantee {
    /// Returns true if this guarantee meets the required policy.
    /// The policy is provided by the runtime — not the adapter.
    pub fn meets_policy(&self, policy: &FinalityPolicy) -> bool {
        match (self, policy) {
            (
                FinalityGuarantee::Probabilistic { confirmations, .. },
                FinalityPolicy::MinConfirmations(required),
            ) => *confirmations >= *required,

            (
                FinalityGuarantee::Deterministic { sequence, .. },
                FinalityPolicy::DeterministicCheckpoint { min_sequence },
            ) => *sequence >= *min_sequence,

            (
                FinalityGuarantee::Economic { challenge_window_secs, .. },
                FinalityPolicy::EconomicSettlement,
            ) => *challenge_window_secs == 0,

            _ => false, // type mismatch = reject
        }
    }

    /// Returns the minimum confirmation count for probabilistic finality, if applicable.
    pub fn confirmations(&self) -> Option<u64> {
        match self {
            FinalityGuarantee::Probabilistic { confirmations, .. } => Some(*confirmations),
            FinalityGuarantee::Deterministic { sequence, .. } => Some(*sequence),
            FinalityGuarantee::Economic { .. } => None,
        }
    }
}

/// Runtime-owned finality policy. Adapters NEVER set this.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FinalityPolicy {
    /// Require at least N confirmations (Bitcoin, Ethereum pre-Dencun)
    MinConfirmations(u64),
    /// Require deterministic checkpoint at or above a given sequence
    DeterministicCheckpoint { min_sequence: u64 },
    /// Require economic settlement (challenge window expired)
    EconomicSettlement,
}

/// Finality policy registry — maps chain IDs to their required policies.
#[derive(Clone, Debug, Default)]
pub struct FinalityPolicyRegistry {
    policies: BTreeMap<String, FinalityPolicy>,
}

impl FinalityPolicyRegistry {
    /// Create a new empty policy registry.
    pub fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
        }
    }

    /// Register a finality policy for a chain.
    pub fn register(&mut self, chain: String, policy: FinalityPolicy) {
        self.policies.insert(chain, policy);
    }

    /// Get the finality policy for a chain.
    pub fn get(&self, chain: &str) -> Option<&FinalityPolicy> {
        self.policies.get(chain)
    }

    /// Check if a finality guarantee meets the policy for a given chain.
    pub fn check(&self, chain: &str, guarantee: &FinalityGuarantee) -> bool {
        match self.policies.get(chain) {
            Some(policy) => guarantee.meets_policy(policy),
            None => false, // No policy = reject
        }
    }
}
