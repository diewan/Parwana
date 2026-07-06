//! State definitions for CSV Seal program (RFC-0012 thin-registry model)
//!
//! The former proof-root / `ProofLeafV1` mint model has been removed. Destination
//! mint is authenticated by verifier-signed attestations over the §9.2 digest, and
//! on-chain replay protection is enforced by uniqueness of the minted-sanad,
//! nullifier, and lock-event PDAs (see `MintRecord`, `NullifierRecord`,
//! `LockEventRecord`).

use anchor_lang::prelude::*;

/// Canonical Sanad lifecycle state — matches Ethereum/Sui/Aptos
/// 0=Uncreated, 1=Created, 2=Active, 3=Locked, 4=Consumed, 5=Minted, 6=Transferred, 7=Refunded, 8=Burned, 9=Invalid
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanadState {
    Uncreated = 0,
    Created = 1,
    Active = 2,
    Locked = 3,
    Consumed = 4,
    Minted = 5,
    Transferred = 6,
    Refunded = 7,
    Burned = 8,
    Invalid = 9,
}

impl SanadState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => SanadState::Uncreated,
            1 => SanadState::Created,
            2 => SanadState::Active,
            3 => SanadState::Locked,
            4 => SanadState::Consumed,
            5 => SanadState::Minted,
            6 => SanadState::Transferred,
            7 => SanadState::Refunded,
            8 => SanadState::Burned,
            9 => SanadState::Invalid,
            _ => SanadState::Invalid,
        }
    }
}

/// Canonical Seal lifecycle state
/// 0=Created, 1=Consumed, 2=Locked, 3=Minted, 4=Refunded
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealState {
    Created = 0,
    Consumed = 1,
    Locked = 2,
    Minted = 3,
    Refunded = 4,
}

impl SealState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => SealState::Created,
            1 => SealState::Consumed,
            2 => SealState::Locked,
            3 => SealState::Minted,
            4 => SealState::Refunded,
            _ => SealState::Created,
        }
    }
}

/// SanadAccount stores the state of a locally-created Sanad on Solana.
/// This is a PDA (Program Derived Address) account.
///
/// NOTE: cross-chain *materialized* sanads are recorded in [`MintRecord`], not here;
/// this account tracks the local create/consume/lock/refund lifecycle.
#[account]
pub struct SanadAccount {
    /// Owner of the sanad
    pub owner: Pubkey,
    /// Unique Sanad identifier (preserved across chains)
    pub sanad_id: [u8; 32],
    /// Commitment hash (preserved across chains)
    pub commitment: [u8; 32],
    /// State root (off-chain state commitment)
    pub state_root: [u8; 32],
    /// Nullifier for this sanad (for L3 chains that use nullifiers)
    pub nullifier: [u8; 32],
    /// Asset class: 0 unspecified, 1 fungible token, 2 NFT, 3 proof sanad
    pub asset_class: u8,
    /// Chain-native token mint, NFT collection/item id, or proof family id
    pub asset_id: [u8; 32],
    /// Hash of canonical metadata for token/NFT/proof payloads
    pub metadata_hash: [u8; 32],
    /// Proof system: 0 unspecified, chain/app-specific values above zero
    pub proof_system: u8,
    /// Canonical lifecycle state (replaces consumed/locked booleans)
    pub state: u8,
    /// Creation timestamp (Unix epoch seconds)
    pub created_at: i64,
    /// Lock timestamp (Unix epoch seconds)
    pub locked_at: i64,
    /// Consumption timestamp (Unix epoch seconds)
    pub consumed_at: i64,
    /// Mint timestamp (Unix epoch seconds)
    pub minted_at: i64,
    /// Refund timestamp (Unix epoch seconds)
    pub refunded_at: i64,
    /// PDA bump seed
    pub bump: u8,
}

impl SanadAccount {
    /// 8 (discriminator) + 32 (owner) + 32 (sanad_id) + 32 (commitment) +
    /// 32 (state_root) + 32 (nullifier) + 1 (asset_class) + 32 (asset_id) +
    /// 32 (metadata_hash) + 1 (proof_system) + 1 (state) + 5*8 (timestamps) + 1 (bump)
    pub const SIZE: usize = 8 + 32 + 32 + 32 + 32 + 32 + 1 + 32 + 32 + 1 + 1 + (5 * 8) + 1;
}

/// LockRecord stores information about a locked sanad for refund/settlement purposes
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct LockRecord {
    /// Sanad identifier
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Original owner
    pub owner: Pubkey,
    /// Destination chain ID (1-byte legacy id retained for the lock event)
    pub destination_chain: u8,
    /// Destination owner (hashed)
    pub destination_owner: [u8; 32],
    /// Asset class for the locked sanad
    pub asset_class: u8,
    /// Chain-native asset id
    pub asset_id: [u8; 32],
    /// Canonical metadata hash
    pub metadata_hash: [u8; 32],
    /// Proof system identifier
    pub proof_system: u8,
    /// Lock timestamp (Unix epoch seconds)
    pub locked_at: i64,
    /// Whether this lock has been refunded (terminal, mutually exclusive with `settled`)
    pub refunded: bool,
    /// Whether this lock's escrow has been settled to the operator via a §10 receipt
    /// (terminal, mutually exclusive with `refunded`).
    pub settled: bool,
}

impl LockRecord {
    /// 32 + 32 + 32 (owner) + 1 + 32 + 1 + 32 + 32 + 1 + 8 + 1 + 1
    pub const SIZE: usize = 32 + 32 + 32 + 1 + 32 + 1 + 32 + 32 + 1 + 8 + 1 + 1;
}

/// LockAccount stores a single lock record as a PDA
#[account]
pub struct LockAccount {
    /// The lock record data
    pub lock: LockRecord,
    /// PDA bump seed
    pub bump: u8,
}

impl LockAccount {
    /// 8 (discriminator) + LockRecord::SIZE + 1 (bump)
    pub const SIZE: usize = 8 + LockRecord::SIZE + 1;
}

/// LockRegistry tracks global lock settings (no longer stores Vec of locks)
/// This is a singleton PDA account
#[account]
pub struct LockRegistry {
    /// Authority that can initialize and manage the registry
    pub authority: Pubkey,
    /// Refund timeout in seconds (default: 24 hours = 86400)
    pub refund_timeout: u32,
    /// Total number of locks (for statistics only)
    pub lock_count: u32,
    /// PDA bump seed
    pub bump: u8,
}

impl LockRegistry {
    /// 8 (discriminator) + 32 (authority) + 4 (refund_timeout) + 4 (lock_count) + 1 (bump)
    pub const SIZE: usize = 8 + 32 + 4 + 4 + 1;
}

/// Maximum number of verifiers the on-chain verifier set can hold.
pub const MAX_VERIFIERS: usize = 16;

/// VerifierRegistry — the authorized verifier set and threshold `M` (RFC-0012 §9.3).
///
/// Verifier identities are stored in the non-EVM canonical form pinned by the ABI
/// constitution: the compressed 33-byte secp256k1 public key. A single verifier
/// keypair serves all chains; mint requires >= `threshold` DISTINCT valid signatures
/// over the §9.2 digest, recovered via `secp256k1_recover`.
///
/// This account and its mutations are OFF the mint hot path — the mint instruction
/// only reads it. Rotation / revocation are authority-gated governance operations.
#[account]
pub struct VerifierRegistry {
    /// Governance authority permitted to rotate the verifier set / threshold.
    pub authority: Pubkey,
    /// Signature threshold `M` (>= 1, <= verifiers.len()).
    pub threshold: u8,
    /// Authorized verifier identities (compressed 33-byte secp256k1 public keys).
    pub verifiers: Vec<[u8; 33]>,
    /// PDA bump seed
    pub bump: u8,
}

impl VerifierRegistry {
    /// 8 (discriminator) + 32 (authority) + 1 (threshold)
    /// + 4 (vec len prefix) + MAX_VERIFIERS * 33 + 1 (bump)
    pub const SIZE: usize = 8 + 32 + 1 + 4 + (MAX_VERIFIERS * 33) + 1;
}

/// MintRecord — the destination-mint registry entry AND the sanadId anti-replay
/// tombstone (PDA seeds: `["minted", sanad_id]`).
///
/// SECURITY: this account is created with `init` and is NEVER closed by any
/// instruction. Its permanent existence is what prevents a `sanad_id` from being
/// minted twice, including via Solana's account close+reopen path.
#[account]
pub struct MintRecord {
    /// Sanad identifier that was minted (primary duplicate-mint key)
    pub sanad_id: [u8; 32],
    /// Commitment binding the sanad content/ownership
    pub commitment: [u8; 32],
    /// Source chain identity (keccak256("csv.chain.<src>"))
    pub source_chain: [u8; 32],
    /// keccak256(destination_owner) — full bytes travel in the event
    pub destination_owner_hash: [u8; 32],
    /// Source-chain lock event id (settlement replay key)
    pub lock_event_id: [u8; 32],
    /// Replay nullifier consumed by the source seal
    pub nullifier: [u8; 32],
    /// When it was minted (Unix epoch seconds)
    pub minted_at: i64,
    /// PDA bump seed
    pub bump: u8,
}

impl MintRecord {
    /// 8 (discriminator) + 6*32 (hash fields) + 8 (minted_at) + 1 (bump)
    pub const SIZE: usize = 8 + (6 * 32) + 8 + 1;
}

/// NullifierRecord — the nullifier anti-replay tombstone (PDA seeds:
/// `["nullifier", nullifier]`).
///
/// SECURITY: created with `init`, NEVER closed. Permanent existence enforces
/// single-use of a replay nullifier against account close+reopen reuse.
#[account]
pub struct NullifierRecord {
    /// The consumed nullifier
    pub nullifier: [u8; 32],
    /// Sanad that consumed it
    pub sanad_id: [u8; 32],
    /// When it was recorded (Unix epoch seconds)
    pub recorded_at: i64,
    /// PDA bump seed
    pub bump: u8,
}

impl NullifierRecord {
    /// 8 (discriminator) + 32 + 32 + 8 + 1
    pub const SIZE: usize = 8 + 32 + 32 + 8 + 1;
}

/// LockEventRecord — the source lock-event anti-replay tombstone (PDA seeds:
/// `["lock_event", lock_event_id]`).
///
/// SECURITY: created with `init`, NEVER closed. Permanent existence enforces that
/// a single source lock event mints at most once.
#[account]
pub struct LockEventRecord {
    /// The source-chain lock event id
    pub lock_event_id: [u8; 32],
    /// Sanad minted from it
    pub sanad_id: [u8; 32],
    /// When it was recorded (Unix epoch seconds)
    pub recorded_at: i64,
    /// PDA bump seed
    pub bump: u8,
}

impl LockEventRecord {
    /// 8 (discriminator) + 32 + 32 + 8 + 1
    pub const SIZE: usize = 8 + 32 + 32 + 8 + 1;
}

/// SettlementRecord — source-chain settlement entry (RFC-0012 §10), keyed by
/// `lock_event_id` (PDA seeds: `["settlement", lock_event_id]`).
///
/// SECURITY: created with `init`, NEVER closed. Its existence is the settlement
/// anti-replay key: exactly one verifier-signed receipt may settle per
/// `lock_event_id`.
#[account]
pub struct SettlementRecord {
    /// Settlement replay key (the source lock event)
    pub lock_event_id: [u8; 32],
    /// Sanad whose source lock was settled
    pub sanad_id: [u8; 32],
    /// Canonical reference to the confirmed destination mint
    pub destination_mint_tx_ref: [u8; 32],
    /// The sole escrow beneficiary bound in the signed receipt
    pub operator_payout: Pubkey,
    /// Terminal release flag
    pub released: bool,
    /// When it was released (Unix epoch seconds)
    pub released_at: i64,
    /// PDA bump seed
    pub bump: u8,
}

impl SettlementRecord {
    /// 8 (discriminator) + 32 + 32 + 32 + 32 (operator) + 1 + 8 + 1
    pub const SIZE: usize = 8 + 32 + 32 + 32 + 32 + 1 + 8 + 1;
}
