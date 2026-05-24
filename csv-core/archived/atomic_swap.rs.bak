//! Atomic Seal Swap — Hash Time Locked Seal Exchange (HTLSE)
//!
//! Implements escrow-free cross-chain atomic swaps between two participants on
//! different chains. The protocol ensures that either both participants complete
//! the swap or both can refund their sealed assets — no third-party escrow.
//!
//! # Protocol Overview
//!
//! ```text
//! Phase 1 — Lock:
//!   Alice locks Seal_A on Chain A with hash-lock H(secret) and timeout T_A
//!   Bob locks Seal_B on Chain B with hash-lock H(secret) and timeout T_B
//!
//! Phase 2 — Reveal (Alice goes first):
//!   Alice reveals secret on-chain → Bob reads event, claims Seal_B
//!   Bob reveals secret on-chain → Alice reads event, claims Seal_A
//!
//! Phase 3 — Refund (if timeout):
//!   After T_A (Alice's timeout), Alice can refund Seal_A if Bob hasn't claimed yet
//!   After T_B (Bob's timeout), Bob can refund Seal_B if Alice hasn't claimed yet
//! ```
//!
//! # Security Properties
//!
//! 1. **Atomicity**: Either both complete or both refund — no partial execution
//! 2. **Trustless**: No escrow contract; each party locks on their own chain
//! 3. **Timelock**: Refund possible after timeout even if counterparty is offline
//! 4. **Hash-lock**: Secret reveal on-chain makes it visible to both parties
//!
//! # Invariants (Never Break)
//!
//! - A seal consumed in a swap must never be re-consumable (single-use)
//! - The same secret cannot be used for two different swaps
//! - Timeout values must satisfy `T_A > 0` and `T_B > 0`
//! - Hash lock `h = SHA-256(secret)` must be derivable from secret

use alloc::vec::Vec;
use core::time::Duration;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::collections::HashMap;
use csv_hash::Hash;
use crate::mcp::ChainId;
use csv_hash::seal::SealPoint;

// ============================================================================
// Types
// ============================================================================

/// Maximum number of active swaps per participant per chain pair.
pub const MAX_ACTIVE_SWAPS: usize = 100;

/// Minimum timeout in blocks to prevent race conditions.
pub const MIN_TIMEOUT_BLOCKS: u64 = 10;

/// A hash-lock derived from a secret using SHA-256.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashLock([u8; 32]);

impl HashLock {
    /// Derive a hash-lock from a secret using SHA-256.
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"CSV-HTLSE-HASHLOCK::");
        hasher.update(secret);
        Self(hasher.finalize().into())
    }

    /// Verify that `secret` produces this hash-lock.
    pub fn verify(&self, secret: &[u8]) -> bool {
        self == &Self::from_secret(secret)
    }

    /// Returns the 32-byte hash lock value.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the hash-lock and returns the inner bytes.
    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Display for HashLock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl core::str::FromStr for HashLock {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!("Hash lock must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Direction of a seal in an atomic swap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapDirection {
    /// Seal being offered by the initiator (Alice)
    Initiator,
    /// Seal being offered by the responder (Bob)
    Responder,
}

/// An atomic swap offer made by a participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicSwapOffer {
    /// Unique swap identifier (SHA-256 of both chain seals + hash_lock)
    pub swap_id: Hash,
    /// Chain where the initiator locks their seal
    pub chain_a: ChainId,
    /// Chain where the responder locks their seal
    pub chain_b: ChainId,
    /// Initiator's seal on chain A
    pub seal_a: SealPoint,
    /// Responder's seal on chain B
    pub seal_b: SealPoint,
    /// Hash-lock: H = SHA-256(secret), derived from shared secret
    pub hash_lock: HashLock,
    /// Timeout for initiator's seal in blocks (chain A)
    /// After this many blocks, initiator can refund if responder hasn't claimed.
    pub timeout_a: u64,
    /// Timeout for responder's seal in blocks (chain B)
    /// After this many blocks, responder can refund if initiator hasn't claimed.
    pub timeout_b: u64,
    /// Who created this offer (the initiator / Alice)
    pub initiator: Vec<u8>,
    /// Timestamp when the offer was created (Unix epoch seconds)
    pub created_at: u64,
}

impl AtomicSwapOffer {
    /// Create a new atomic swap offer.
    ///
    /// # Arguments
    /// * `chain_a` - Chain for initiator's seal (A)
    /// * `seal_a` - Initiator's seal on chain A
    /// * `chain_b` - Chain for responder's seal (B)
    /// * `seal_b` - Responder's seal on chain B
    /// * `secret` - Shared secret used to derive the hash-lock
    /// * `timeout_a` - Timeout for initiator's seal in blocks on chain A
    /// * `timeout_b` - Timeout for responder's seal in blocks on chain B
    /// * `initiator` - Initiator's public key/address bytes
    /// * `created_at` - Unix timestamp of creation
    ///
    /// # Errors
    /// Returns an error if:
    /// - `timeout_a` or `timeout_b` is less than `MIN_TIMEOUT_BLOCKS`
    /// - `initiator` is empty
    /// - `seal_a` or `seal_b` IDs are empty
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_a: ChainId,
        seal_a: SealPoint,
        chain_b: ChainId,
        seal_b: SealPoint,
        secret: &[u8],
        timeout_a: u64,
        timeout_b: u64,
        initiator: Vec<u8>,
        created_at: u64,
    ) -> Result<Self, AtomicSwapError> {
        if chain_a == chain_b {
            return Err(AtomicSwapError::SameChain);
        }
        if timeout_a < MIN_TIMEOUT_BLOCKS {
            return Err(AtomicSwapError::TimeoutTooShort(timeout_a));
        }
        if timeout_b < MIN_TIMEOUT_BLOCKS {
            return Err(AtomicSwapError::TimeoutTooShort(timeout_b));
        }
        if initiator.is_empty() {
            return Err(AtomicSwapError::EmptyInitiator);
        }
        if seal_a.id.is_empty() {
            return Err(AtomicSwapError::EmptySeal("seal_a"));
        }
        if seal_b.id.is_empty() {
            return Err(AtomicSwapError::EmptySeal("seal_b"));
        }

        let hash_lock = HashLock::from_secret(secret);
        let swap_id = Self::compute_swap_id(&chain_a, &seal_a, &chain_b, &seal_b, &hash_lock);

        Ok(Self {
            swap_id,
            chain_a,
            chain_b,
            seal_a,
            seal_b,
            hash_lock,
            timeout_a,
            timeout_b,
            initiator,
            created_at,
        })
    }

    /// Compute a unique swap ID from the swap parameters.
    pub fn compute_swap_id(
        chain_a: &ChainId,
        seal_a: &SealPoint,
        chain_b: &ChainId,
        seal_b: &SealPoint,
        hash_lock: &HashLock,
    ) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(b"CSV-SWAP-ID::");
        hasher.update(chain_a.as_bytes());
        hasher.update(&seal_a.id);
        hasher.update(seal_a.nonce.unwrap_or(0).to_le_bytes());
        hasher.update(chain_b.as_bytes());
        hasher.update(&seal_b.id);
        hasher.update(seal_b.nonce.unwrap_or(0).to_le_bytes());
        hasher.update(hash_lock.as_bytes());
        Hash::new(hasher.finalize().into())
    }

    /// Get the direction of this seal in the swap.
    pub fn direction_for(&self, seal: &SealPoint) -> Option<SwapDirection> {
        if seal.id == self.seal_a.id {
            Some(SwapDirection::Initiator)
        } else if seal.id == self.seal_b.id {
            Some(SwapDirection::Responder)
        } else {
            None
        }
    }
}

/// Current state of an atomic swap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtomicSwapState {
    /// Swap offer created; both parties need to lock their seals.
    Created {
        /// Block height on chain A when the offer was created.
        block_height_a: u64,
        /// Block height on chain B when the offer was created.
        block_height_b: u64,
    },
    /// Both parties have locked their seals; waiting for secret reveal.
    BothLocked {
        /// Block height when initiator locked on chain A.
        lock_height_a: u64,
        /// Block height when responder locked on chain B.
        lock_height_b: u64,
    },
    /// Initiator has revealed the secret and claimed on chain B.
    /// Responder must now claim on chain A before timeout.
    SecretRevealed {
        /// The revealed secret (stored for reference; should be available on-chain too).
        secret: Vec<u8>,
        /// Block height where secret was revealed.
        reveal_height: u64,
        /// Remaining blocks until initiator's refund timeout.
        remaining_timeout_a: u64,
    },
    /// Swap completed — both parties have claimed their seals.
    Complete {
        /// Transaction hash on chain A where responder claimed.
        claim_tx_a: String,
        /// Transaction hash on chain B where initiator claimed.
        claim_tx_b: String,
    },
    /// Initiator refunded seal_a (timeout expired without claim).
    RefundedByInitiator {
        /// Transaction hash of the refund on chain A.
        refund_tx_a: String,
        /// Block height when refund occurred.
        refund_height: u64,
    },
    /// Responder refunded seal_b (timeout expired without claim).
    RefundedByResponder {
        /// Transaction hash of the refund on chain B.
        refund_tx_b: String,
        /// Block height when refund occurred.
        refund_height: u64,
    },
}

impl AtomicSwapState {
    /// Returns true if the swap is still active (not Complete or Refunded).
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            AtomicSwapState::Created { .. }
                | AtomicSwapState::BothLocked { .. }
                | AtomicSwapState::SecretRevealed { .. }
        )
    }

    /// Returns true if the swap has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            AtomicSwapState::Complete { .. }
                | AtomicSwapState::RefundedByInitiator { .. }
                | AtomicSwapState::RefundedByResponder { .. }
        )
    }

    /// Get the current phase description.
    pub fn phase_name(&self) -> &'static str {
        match self {
            AtomicSwapState::Created { .. } => "created",
            AtomicSwapState::BothLocked { .. } => "both_locked",
            AtomicSwapState::SecretRevealed { .. } => "secret_revealed",
            AtomicSwapState::Complete { .. } => "complete",
            AtomicSwapState::RefundedByInitiator { .. } => "refunded_by_initiator",
            AtomicSwapState::RefundedByResponder { .. } => "refunded_by_responder",
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during atomic swap operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AtomicSwapError {
    /// Both chains must be different.
    #[error("Both chains in a swap must be different")]
    SameChain,

    /// Timeout is below the minimum required blocks.
    #[error("Timeout {0} is below minimum of {MIN_TIMEOUT_BLOCKS} blocks")]
    TimeoutTooShort(u64),

    /// Empty initiator address.
    #[error("Initiator address cannot be empty")]
    EmptyInitiator,

    /// Empty seal reference.
    #[error("Seal '{0}' cannot have an empty ID")]
    EmptySeal(&'static str),

    /// Swap not found by ID.
    #[error("Swap not found: {0}")]
    SwapNotFound(Hash),

    /// Invalid state transition.
    #[error("Invalid state transition: expected '{expected}', got '{actual}'")]
    InvalidStateTransition {
        /// The expected phase name.
        expected: &'static str,
        /// The actual phase name.
        actual: &'static str,
    },

    /// Secret does not match the hash-lock.
    #[error("Secret does not match the hash-lock")]
    InvalidSecret,

    /// Swap has already reached a terminal state.
    #[error("Swap is already in terminal state: '{0}'")]
    AlreadyTerminal(&'static str),

    /// Registry is full (max active swaps per participant).
    #[error("Registry full: maximum {MAX_ACTIVE_SWAPS} active swaps exceeded")]
    RegistryFull,

    /// Double-spend: seal already used in another swap.
    #[error("Seal (id_len={}) is already locked in an active swap", .0.id.len())]
    SealAlreadyLocked(SealPoint),

    /// Chain capability not available for swap.
    #[error("Chain '{0}' does not support hash-lock swaps")]
    SwapNotSupported(ChainId),
}

// ============================================================================
// Atomic Swap Registry
// ============================================================================

/// Tracks all active and completed atomic swaps to prevent double-spend.
///
/// This is the in-memory registry that each node maintains. For production,
/// this should be backed by persistent storage (SQLite). See SC-02.
#[derive(Default)]
pub struct AtomicSwapRegistry {
    /// All swaps indexed by swap_id.
    swaps: alloc::collections::BTreeMap<Hash, SwapRecord>,
    /// Maps seal references to their swap_id to prevent double-locking.
    seals_in_use: HashMap<Vec<u8>, Hash>,
    /// Maps initiator address to list of active swap IDs for rate limiting.
    swaps_by_initiator: HashMap<Vec<u8>, Vec<Hash>>,
}

impl AtomicSwapRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            swaps: alloc::collections::BTreeMap::new(),
            seals_in_use: HashMap::new(),
            swaps_by_initiator: HashMap::new(),
        }
    }

    /// Register a new swap offer.
    ///
    /// # Errors
    /// Returns `AtomicSwapError` if:
    /// - Either seal is already locked in another active swap
    /// - Initiator has already reached the max active swap limit
    pub fn register(
        &mut self,
        offer: &AtomicSwapOffer,
        state: AtomicSwapState,
    ) -> Result<(), AtomicSwapError> {
        // Check if either seal is already in use
        if self.seals_in_use.contains_key(&offer.seal_a.id) {
            return Err(AtomicSwapError::SealAlreadyLocked(offer.seal_a.clone()));
        }
        if self.seals_in_use.contains_key(&offer.seal_b.id) {
            return Err(AtomicSwapError::SealAlreadyLocked(offer.seal_b.clone()));
        }

        // Check initiator swap limit
        let initiator_swaps = self
            .swaps_by_initiator
            .entry(offer.initiator.clone())
            .or_default();
        let active_count = initiator_swaps
            .iter()
            .filter(|sid| self.swaps.get(sid).is_some_and(|r| r.state.is_active()))
            .count();
        if active_count >= MAX_ACTIVE_SWAPS {
            return Err(AtomicSwapError::RegistryFull);
        }

        // Register the swap
        let record = SwapRecord {
            offer: offer.clone(),
            state,
        };
        self.swaps.insert(offer.swap_id, record);
        self.seals_in_use
            .insert(offer.seal_a.id.clone(), offer.swap_id);
        self.seals_in_use
            .insert(offer.seal_b.id.clone(), offer.swap_id);
        initiator_swaps.push(offer.swap_id);

        Ok(())
    }

    /// Get a swap by ID.
    pub fn get(&self, swap_id: &Hash) -> Option<&SwapRecord> {
        self.swaps.get(swap_id)
    }

    /// Get the mutable state of a swap.
    pub fn get_state(&self, swap_id: &Hash) -> Option<&AtomicSwapState> {
        self.swaps.get(swap_id).map(|r| &r.state)
    }

    /// Transition a swap to a new state.
    ///
    /// # Errors
    /// Returns `AtomicSwapError::InvalidStateTransition` if the transition is not allowed.
    pub fn transition(
        &mut self,
        swap_id: &Hash,
        from: AtomicSwapState,
        to: AtomicSwapState,
    ) -> Result<(), AtomicSwapError> {
        let record = self
            .swaps
            .get_mut(swap_id)
            .ok_or(AtomicSwapError::SwapNotFound(*swap_id))?;

        if record.state != from {
            return Err(AtomicSwapError::InvalidStateTransition {
                expected: from.phase_name(),
                actual: record.state.phase_name(),
            });
        }

        // Validate transitions
        match (&from, &to) {
            (AtomicSwapState::Created { .. }, AtomicSwapState::BothLocked { .. }) => {}
            (AtomicSwapState::BothLocked { .. }, AtomicSwapState::SecretRevealed { .. }) => {}
            (AtomicSwapState::SecretRevealed { .. }, AtomicSwapState::Complete { .. }) => {}
            (
                AtomicSwapState::BothLocked { .. } | AtomicSwapState::SecretRevealed { .. },
                AtomicSwapState::RefundedByInitiator { .. },
            ) => {}
            (
                AtomicSwapState::BothLocked { .. } | AtomicSwapState::SecretRevealed { .. },
                AtomicSwapState::RefundedByResponder { .. },
            ) => {}
            _ => {
                return Err(AtomicSwapError::InvalidStateTransition {
                    expected: from.phase_name(),
                    actual: to.phase_name(),
                });
            }
        }

        record.state = to;
        Ok(())
    }

    /// Complete a swap — both parties have claimed their seals.
    pub fn complete(
        &mut self,
        swap_id: &Hash,
        claim_tx_a: &str,
        claim_tx_b: &str,
    ) -> Result<(), AtomicSwapError> {
        let record = self
            .swaps
            .get_mut(swap_id)
            .ok_or(AtomicSwapError::SwapNotFound(*swap_id))?;
        let current = core::mem::replace(
            &mut record.state,
            AtomicSwapState::Complete {
                claim_tx_a: claim_tx_a.to_string(),
                claim_tx_b: claim_tx_b.to_string(),
            },
        );

        if !matches!(current, AtomicSwapState::SecretRevealed { .. }) {
            return Err(AtomicSwapError::InvalidStateTransition {
                expected: "secret_revealed",
                actual: current.phase_name(),
            });
        }

        Ok(())
    }

    /// Refund initiator's seal (timeout expired).
    pub fn refund_initiator(
        &mut self,
        swap_id: &Hash,
        refund_tx_a: &str,
        refund_height: u64,
    ) -> Result<(), AtomicSwapError> {
        let record = self
            .swaps
            .get_mut(swap_id)
            .ok_or(AtomicSwapError::SwapNotFound(*swap_id))?;
        let current = core::mem::replace(
            &mut record.state,
            AtomicSwapState::RefundedByInitiator {
                refund_tx_a: refund_tx_a.to_string(),
                refund_height,
            },
        );

        if !current.is_active() {
            return Err(AtomicSwapError::AlreadyTerminal(current.phase_name()));
        }

        Ok(())
    }

    /// Refund responder's seal (timeout expired).
    pub fn refund_responder(
        &mut self,
        swap_id: &Hash,
        refund_tx_b: &str,
        refund_height: u64,
    ) -> Result<(), AtomicSwapError> {
        let record = self
            .swaps
            .get_mut(swap_id)
            .ok_or(AtomicSwapError::SwapNotFound(*swap_id))?;
        let current = core::mem::replace(
            &mut record.state,
            AtomicSwapState::RefundedByResponder {
                refund_tx_b: refund_tx_b.to_string(),
                refund_height,
            },
        );

        if !current.is_active() {
            return Err(AtomicSwapError::AlreadyTerminal(current.phase_name()));
        }

        Ok(())
    }

    /// Check if a seal is already locked in any active swap.
    pub fn is_seal_locked(&self, seal: &SealPoint) -> bool {
        self.seals_in_use.contains_key(&seal.id)
    }

    /// Get all active swaps.
    pub fn active_swaps(&self) -> Vec<&SwapRecord> {
        self.swaps
            .values()
            .filter(|r| r.state.is_active())
            .collect()
    }

    /// Get the number of active swaps.
    pub fn active_count(&self) -> usize {
        self.swaps.values().filter(|r| r.state.is_active()).count()
    }

    /// Get total number of registered swaps (including completed/refunded).
    pub fn total_count(&self) -> usize {
        self.swaps.len()
    }
}

/// A swap record combining the offer with its current state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapRecord {
    /// The original swap offer parameters.
    pub offer: AtomicSwapOffer,
    /// Current state of the swap.
    pub state: AtomicSwapState,
}

// ============================================================================
// Public API helpers
// ============================================================================

/// Derive a hash-lock from a secret.
pub fn derive_hash_lock(secret: &[u8]) -> HashLock {
    HashLock::from_secret(secret)
}

/// Verify that a secret matches a hash-lock.
pub fn verify_hash_lock(secret: &[u8], lock: &HashLock) -> bool {
    lock.verify(secret)
}

/// Compute a swap ID from the given parameters.
pub fn compute_swap_id(
    chain_a: &ChainId,
    seal_a: &SealPoint,
    chain_b: &ChainId,
    seal_b: &SealPoint,
    hash_lock: &HashLock,
) -> Hash {
    AtomicSwapOffer::compute_swap_id(chain_a, seal_a, chain_b, seal_b, hash_lock)
}

/// Check if a timeout is valid (>= MIN_TIMEOUT_BLOCKS).
pub fn is_timeout_valid(timeout: u64) -> bool {
    timeout >= MIN_TIMEOUT_BLOCKS
}

/// Convert block difference to approximate duration.
///
/// Default heuristic: 1 block ≈ 1 minute for Bitcoin, ~12s for Ethereum,
/// ~400ms for Solana. Uses a conservative 60s default.
pub fn blocks_to_duration(blocks: u64) -> Duration {
    Duration::from_secs(blocks * 60)
}

/// Default timeouts for different chain pairs.
pub struct DefaultTimeouts;

impl DefaultTimeouts {
    /// Timeout for Bitcoin → any (504 blocks ≈ 36 hours).
    pub const BITCOIN: u64 = 504;
    /// Timeout for Ethereum → any (21_600 blocks ≈ 36 hours at 12s).
    pub const ETHEREUM: u64 = 21_600;
    /// Timeout for Solana → any (86_400 slots ≈ 36 hours at 400ms).
    pub const SOLANA: u64 = 86_400;
    /// Timeout for Aptos → any (504 blocks ≈ 36 hours at 4min avg).
    pub const APTOS: u64 = 504;
    /// Timeout for Sui → any (504 checkpoints ≈ 36 hours).
    pub const SUI: u64 = 504;

    /// Get default timeout for a chain.
    pub fn for_chain(chain: &ChainId) -> u64 {
        match chain.as_str() {
            "bitcoin" => Self::BITCOIN,
            "ethereum" => Self::ETHEREUM,
            "solana" => Self::SOLANA,
            "aptos" => Self::APTOS,
            "sui" => Self::SUI,
            _ => Self::ETHEREUM, // Default to Ethereum timeout
        }
    }

    /// Get recommended timeout pair for a chain pair.
    ///
    /// The responder's timeout is always longer (gives initiator time to
    /// reveal secret before responder can refund).
    pub fn for_chain_pair(chain_a: &ChainId, chain_b: &ChainId) -> (u64, u64) {
        let t_a = Self::for_chain(chain_a);
        let t_b = Self::for_chain(chain_b) * 2; // Responder gets 2x timeout
        (t_a, t_b)
    }
}

// ============================================================================
// Chain Backend Extension Trait
// ============================================================================

/// Extension trait for chain backends that support atomic swap hash-locks.
///
/// Implement this trait on a chain backend to enable atomic swap functionality.
/// Each chain encodes the hash-lock differently:
/// - Bitcoin: Tapscript leaf with `OP_SHA256 <hash> OP_EQUALVERIFY`
/// - Ethereum: CSVLock.sol hash-lock modifier
/// - Solana: PDA lock account with hash_lock field + refund timelock
/// - Aptos/Sui: Move entry fun with hash_lock verification
pub trait AtomicSwapBackend {
    /// Encode a hash-lock into the chain's native locking mechanism.
    ///
    /// # Returns
    /// Locking data (e.g., Tapscript bytes, contract calldata) for the swap.
    fn encode_hash_lock(
        &self,
        hash_lock: &HashLock,
        timeout: u64,
        initiator: &[u8],
    ) -> alloc::borrow::Cow<'static, [u8]>;

    /// Verify that a secret satisfies the hash-lock on-chain.
    fn verify_secret_on_chain(&self, secret: &[u8], hash_lock: &HashLock) -> bool;

    /// Build a refund transaction for an expired swap.
    ///
    /// # Arguments
    /// * `swap_id` - The swap to refund
    /// * `current_height` - Current block height (must exceed timeout)
    ///
    /// # Returns
    /// Raw refund transaction bytes, or error if not yet eligible.
    fn build_refund_transaction(
        &self,
        swap_id: &Hash,
        current_height: u64,
    ) -> Result<Vec<u8>, AtomicSwapError>;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain_a() -> ChainId {
        ChainId::new("bitcoin")
    }

    fn test_chain_b() -> ChainId {
        ChainId::new("ethereum")
    }

    fn test_secret() -> Vec<u8> {
        b"test-secret-for-atomic-swap".to_vec()
    }

    fn make_seal(id: u8, nonce: Option<u64>) -> SealPoint {
        SealPoint::new(vec![id], nonce).unwrap()
    }

    #[test]
    fn test_hash_lock_derivation() {
        let secret = b"my-secret";
        let lock = HashLock::from_secret(secret);
        assert_eq!(lock.as_bytes().len(), 32);
    }

    #[test]
    fn test_hash_lock_verification() {
        let secret = b"my-secret";
        let lock = HashLock::from_secret(secret);
        assert!(lock.verify(secret));
        assert!(!lock.verify(b"wrong-secret"));
    }

    #[test]
    fn test_hash_lock_display() {
        let lock = HashLock::from_secret(b"test");
        let display = format!("{}", lock);
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 66); // "0x" + 64 hex chars
    }

    #[test]
    fn test_hash_lock_from_str() {
        let lock = HashLock::from_secret(b"test");
        let hex = format!("{}", lock);
        let parsed: Result<HashLock, _> = hex.parse();
        assert_eq!(parsed.unwrap(), lock);
    }

    #[test]
    fn test_hash_lock_from_str_invalid_hex() {
        let result: Result<HashLock, _> = "not-hex".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_lock_from_str_wrong_length() {
        let result: Result<HashLock, _> = "0xabcdef".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_swap_id_deterministic() {
        let chain_a = test_chain_a();
        let chain_b = test_chain_b();
        let seal_a = make_seal(0x01, None);
        let seal_b = make_seal(0x02, None);
        let lock = HashLock::from_secret(b"secret");

        let id1 = AtomicSwapOffer::compute_swap_id(&chain_a, &seal_a, &chain_b, &seal_b, &lock);
        let id2 = AtomicSwapOffer::compute_swap_id(&chain_a, &seal_a, &chain_b, &seal_b, &lock);
        assert_eq!(id1, id2);

        // Different secret → different swap ID
        let lock2 = HashLock::from_secret(b"other-secret");
        let id3 = AtomicSwapOffer::compute_swap_id(&chain_a, &seal_a, &chain_b, &seal_b, &lock2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_create_offer_success() {
        let secret = test_secret();
        let offer = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            &secret,
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        );
        assert!(offer.is_ok());
        let offer = offer.unwrap();
        assert_eq!(offer.chain_a.as_str(), "bitcoin");
        assert_eq!(offer.chain_b.as_str(), "ethereum");
        assert_eq!(offer.timeout_a, 100);
        assert_eq!(offer.timeout_b, 200);
    }

    #[test]
    fn test_create_offer_same_chain_fails() {
        let result = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_a(), // same chain
            make_seal(0x02, None),
            b"secret",
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        );
        assert!(matches!(result, Err(AtomicSwapError::SameChain)));
    }

    #[test]
    fn test_create_offer_timeout_too_short() {
        let result = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            b"secret",
            5, // below MIN_TIMEOUT_BLOCKS (10)
            200,
            b"alice".to_vec(),
            1_000_000,
        );
        assert!(matches!(result, Err(AtomicSwapError::TimeoutTooShort(5))));

        let result = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            b"secret",
            100,
            3, // below minimum
            b"alice".to_vec(),
            1_000_000,
        );
        assert!(matches!(result, Err(AtomicSwapError::TimeoutTooShort(3))));
    }

    #[test]
    fn test_create_offer_empty_initiator_fails() {
        let result = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            b"secret",
            100,
            200,
            vec![], // empty initiator
            1_000_000,
        );
        assert!(matches!(result, Err(AtomicSwapError::EmptyInitiator)));
    }

    #[test]
    fn test_create_offer_empty_seal_fails() {
        let result = AtomicSwapOffer::new(
            test_chain_a(),
            unsafe { SealPoint::new_unchecked(vec![], None) }, // empty seal ID via new_unchecked
            test_chain_b(),
            make_seal(0x02, None),
            b"secret",
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        );
        assert!(matches!(result, Err(AtomicSwapError::EmptySeal("seal_a"))));

        let result = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            unsafe { SealPoint::new_unchecked(vec![], None) },
            b"secret",
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        );
        assert!(matches!(result, Err(AtomicSwapError::EmptySeal("seal_b"))));
    }

    #[test]
    fn test_offer_direction() {
        let secret = test_secret();
        let offer = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            &secret,
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        )
        .unwrap();

        assert_eq!(
            offer.direction_for(&make_seal(0x01, None)),
            Some(SwapDirection::Initiator)
        );
        assert_eq!(
            offer.direction_for(&make_seal(0x02, None)),
            Some(SwapDirection::Responder)
        );
        assert_eq!(offer.direction_for(&make_seal(0x03, None)), None);
    }

    #[test]
    fn test_swap_state_transitions() {
        let state = AtomicSwapState::Created {
            block_height_a: 100,
            block_height_b: 200,
        };
        assert!(state.is_active());
        assert!(!state.is_terminal());
        assert_eq!(state.phase_name(), "created");

        let locked = AtomicSwapState::BothLocked {
            lock_height_a: 100,
            lock_height_b: 200,
        };
        assert!(locked.is_active());
        assert!(!locked.is_terminal());
        assert_eq!(locked.phase_name(), "both_locked");

        let revealed = AtomicSwapState::SecretRevealed {
            secret: b"secret".to_vec(),
            reveal_height: 300,
            remaining_timeout_a: 50,
        };
        assert!(revealed.is_active());
        assert!(!revealed.is_terminal());
        assert_eq!(revealed.phase_name(), "secret_revealed");

        let complete = AtomicSwapState::Complete {
            claim_tx_a: "tx_a".to_string(),
            claim_tx_b: "tx_b".to_string(),
        };
        assert!(!complete.is_active());
        assert!(complete.is_terminal());
        assert_eq!(complete.phase_name(), "complete");

        let refunded = AtomicSwapState::RefundedByInitiator {
            refund_tx_a: "refund_tx".to_string(),
            refund_height: 400,
        };
        assert!(!refunded.is_active());
        assert!(refunded.is_terminal());
        assert_eq!(refunded.phase_name(), "refunded_by_initiator");
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = AtomicSwapRegistry::new();
        let secret = test_secret();
        let offer = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            &secret,
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        )
        .unwrap();

        let state = AtomicSwapState::Created {
            block_height_a: 100,
            block_height_b: 200,
        };

        assert!(registry.register(&offer, state.clone()).is_ok());
        assert_eq!(registry.total_count(), 1);
        assert_eq!(registry.active_count(), 1);

        let record = registry.get(&offer.swap_id).unwrap();
        assert_eq!(record.offer.swap_id, offer.swap_id);
        assert_eq!(record.state.phase_name(), "created");
    }

    #[test]
    fn test_registry_prevents_double_lock() {
        let mut registry = AtomicSwapRegistry::new();
        let secret1 = b"secret1";
        let offer1 = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            secret1,
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        )
        .unwrap();

        let state1 = AtomicSwapState::Created {
            block_height_a: 100,
            block_height_b: 200,
        };

        registry.register(&offer1, state1).unwrap();

        // Try to register another swap with the same seal
        let secret2 = b"secret2";
        let offer2 = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None), // same seal_a
            ChainId::new("solana"),
            make_seal(0x03, None),
            secret2,
            100,
            200,
            b"bob".to_vec(),
            2_000_000,
        )
        .unwrap();

        let state2 = AtomicSwapState::Created {
            block_height_a: 100,
            block_height_b: 300,
        };

        assert!(matches!(
            registry.register(&offer2, state2),
            Err(AtomicSwapError::SealAlreadyLocked(_))
        ));
    }

    #[test]
    fn test_registry_state_transitions() {
        let mut registry = AtomicSwapRegistry::new();
        let secret = test_secret();
        let offer = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            &secret,
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        )
        .unwrap();

        let created = AtomicSwapState::Created {
            block_height_a: 100,
            block_height_b: 200,
        };

        registry.register(&offer, created).unwrap();

        // Transition to BothLocked
        let both_locked = AtomicSwapState::BothLocked {
            lock_height_a: 100,
            lock_height_b: 200,
        };
        assert!(
            registry
                .transition(
                    &offer.swap_id,
                    AtomicSwapState::Created {
                        block_height_a: 100,
                        block_height_b: 200
                    },
                    both_locked.clone(),
                )
                .is_ok()
        );

        // Transition to SecretRevealed
        let revealed = AtomicSwapState::SecretRevealed {
            secret: b"secret".to_vec(),
            reveal_height: 300,
            remaining_timeout_a: 50,
        };
        assert!(
            registry
                .transition(&offer.swap_id, both_locked.clone(), revealed.clone(),)
                .is_ok()
        );

        // Complete the swap
        assert!(
            registry
                .complete(&offer.swap_id, "claim_tx_a", "claim_tx_b")
                .is_ok()
        );

        let record = registry.get(&offer.swap_id).unwrap();
        assert!(record.state.is_terminal());
    }

    #[test]
    fn test_registry_invalid_transition() {
        let mut registry = AtomicSwapRegistry::new();
        let secret = test_secret();
        let offer = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            &secret,
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        )
        .unwrap();

        let created = AtomicSwapState::Created {
            block_height_a: 100,
            block_height_b: 200,
        };

        registry.register(&offer, created.clone()).unwrap();

        // Try to go from Created → Complete (skip steps)
        let complete = AtomicSwapState::Complete {
            claim_tx_a: "tx_a".to_string(),
            claim_tx_b: "tx_b".to_string(),
        };
        assert!(matches!(
            registry.transition(&offer.swap_id, created, complete),
            Err(AtomicSwapError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn test_registry_refund() {
        let mut registry = AtomicSwapRegistry::new();
        let secret = test_secret();
        let offer = AtomicSwapOffer::new(
            test_chain_a(),
            make_seal(0x01, None),
            test_chain_b(),
            make_seal(0x02, None),
            &secret,
            100,
            200,
            b"alice".to_vec(),
            1_000_000,
        )
        .unwrap();

        let locked = AtomicSwapState::BothLocked {
            lock_height_a: 100,
            lock_height_b: 200,
        };

        registry.register(&offer, locked).unwrap();

        // Refund initiator
        assert!(
            registry
                .refund_initiator(&offer.swap_id, "refund_tx", 300)
                .is_ok()
        );

        let record = registry.get(&offer.swap_id).unwrap();
        assert!(record.state.is_terminal());
        assert_eq!(record.state.phase_name(), "refunded_by_initiator");

        // Cannot refund again (already terminal)
        assert!(matches!(
            registry.refund_initiator(&offer.swap_id, "refund_tx2", 301),
            Err(AtomicSwapError::AlreadyTerminal(_))
        ));
    }

    #[test]
    fn test_registry_active_count() {
        let mut registry = AtomicSwapRegistry::new();

        // Register two swaps
        for i in 0..2 {
            let offer = AtomicSwapOffer::new(
                test_chain_a(),
                make_seal(i as u8, None),
                test_chain_b(),
                make_seal((i + 10) as u8, None),
                format!("secret-{}", i).as_bytes(),
                100,
                200,
                format!("initiator-{}", i).as_bytes().to_vec(),
                1_000_000 + i as u64,
            )
            .unwrap();

            let state = AtomicSwapState::Created {
                block_height_a: 100 + i as u64,
                block_height_b: 200 + i as u64,
            };
            registry.register(&offer, state).unwrap();
        }

        assert_eq!(registry.active_count(), 2);
        assert_eq!(registry.total_count(), 2);

        // Complete one swap
        let swap_id = registry.active_swaps()[0].offer.swap_id;
        let _ = registry.complete(&swap_id, "claim_a", "claim_b");

        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.total_count(), 2);
    }

    #[test]
    fn test_seal_not_locked() {
        let registry = AtomicSwapRegistry::new();
        let seal = make_seal(0x99, None);
        assert!(!registry.is_seal_locked(&seal));
    }

    #[test]
    fn test_default_timeouts() {
        assert_eq!(DefaultTimeouts::for_chain(&ChainId::new("bitcoin")), 504);
        assert_eq!(
            DefaultTimeouts::for_chain(&ChainId::new("ethereum")),
            21_600
        );
        assert_eq!(DefaultTimeouts::for_chain(&ChainId::new("solana")), 86_400);
        assert_eq!(DefaultTimeouts::for_chain(&ChainId::new("unknown")), 21_600); // defaults to ethereum
    }

    #[test]
    fn test_default_timeouts_for_pair() {
        let (ta, tb) =
            DefaultTimeouts::for_chain_pair(&ChainId::new("bitcoin"), &ChainId::new("ethereum"));
        assert_eq!(ta, 504);
        assert_eq!(tb, 43_200); // ethereum * 2
    }

    #[test]
    fn test_blocks_to_duration() {
        let d = blocks_to_duration(60);
        assert_eq!(d, Duration::from_secs(3600)); // 60 blocks * 60s
    }

    #[test]
    fn test_is_timeout_valid() {
        assert!(is_timeout_valid(10));
        assert!(is_timeout_valid(100));
        assert!(!is_timeout_valid(9));
        assert!(!is_timeout_valid(0));
    }
}
