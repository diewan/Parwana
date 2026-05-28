//! State definitions for CSV Seal program

use anchor_lang::prelude::*;

/// SanadAccount stores the state of a Sanad on Solana
/// This is a PDA (Program Derived Address) account
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
    /// Root/verification key commitment for advanced proof systems
    pub proof_root: [u8; 32],
    /// Whether this sanad has been consumed
    pub consumed: bool,
    /// Whether this sanad is locked for cross-chain transfer
    pub locked: bool,
    /// Creation timestamp (Unix epoch seconds)
    pub created_at: i64,
    /// PDA bump seed
    pub bump: u8,
}

impl SanadAccount {
    /// Account size for space calculation
    /// 8 (discriminator) + 32 (owner) + 32 (sanad_id) + 32 (commitment) + 
    /// 32 (state_root) + 32 (nullifier) + metadata/proof fields + flags + timestamp + bump
    pub const SIZE: usize = 8 + 32 + 32 + 32 + 32 + 32 + 1 + 32 + 32 + 1 + 32 + 1 + 1 + 8 + 1;
}

/// LockRecord stores information about a locked sanad for refund purposes
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct LockRecord {
    /// Sanad identifier
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Original owner
    pub owner: Pubkey,
    /// Destination chain ID
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
    /// Proof root or verification-key commitment
    pub proof_root: [u8; 32],
    /// Lock timestamp (Unix epoch seconds)
    pub locked_at: i64,
    /// Whether this lock has been refunded
    pub refunded: bool,
}

impl LockRecord {
    /// Size of LockRecord for space calculation
    pub const SIZE: usize = 32 + 32 + 32 + 1 + 32 + 1 + 32 + 32 + 1 + 32 + 8 + 1;
}

/// LockAccount stores a single lock record as a PDA
/// This eliminates the Vec storage and O(n) lookup issues
#[account]
pub struct LockAccount {
    /// The lock record data
    pub lock: LockRecord,
    /// PDA bump seed
    pub bump: u8,
}

impl LockAccount {
    /// Space required for the LockAccount
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
    /// Fixed size - no variable-length data
    /// 8 (discriminator) + 32 (authority) + 4 (refund_timeout) + 4 (lock_count) + 1 (bump)
    pub const SIZE: usize = 8 + 32 + 4 + 4 + 1;
}

/// MintedSanad account for replay protection (PDA: ["minted", sanad_id])
/// This prevents the same sanad_id from being minted multiple times
#[account]
pub struct MintedSanad {
    /// Sanad identifier that was minted
    pub sanad_id: [u8; 32],
    /// When it was minted (Unix epoch seconds)
    pub minted_at: i64,
    /// PDA bump seed
    pub bump: u8,
}

impl MintedSanad {
    /// Space required for MintedSanad
    /// 8 (discriminator) + 32 (sanad_id) + 8 (minted_at) + 1 (bump)
    pub const SIZE: usize = 8 + 32 + 8 + 1;
}
