//! Event definitions for CSV Seal program

use anchor_lang::prelude::*;

/// Emitted when the LockRegistry is initialized
#[event]
pub struct RegistryInitialized {
    /// Authority that initialized the registry
    pub authority: Pubkey,
    /// Refund timeout in seconds
    pub refund_timeout: u32,
}

/// Emitted when a new Sanad is created
#[event]
pub struct SanadCreated {
    /// Unique Sanad identifier
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Owner of the sanad
    pub owner: Pubkey,
    /// Account address (PDA)
    pub account: Pubkey,
    /// Asset class: 0 unspecified, 1 fungible token, 2 NFT, 3 proof sanad
    pub asset_class: u8,
    /// Chain-native token mint, NFT collection/item id, or proof family id
    pub asset_id: [u8; 32],
    /// Hash of canonical metadata
    pub metadata_hash: [u8; 32],
    /// Proof system identifier
    pub proof_system: u8,
    /// Proof root or verification-key commitment
    pub proof_root: [u8; 32],
}

/// Emitted when a Sanad is consumed
#[event]
pub struct SanadConsumed {
    /// Unique Sanad identifier
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Address that consumed the sanad
    pub consumer: Pubkey,
    /// Account address
    pub account: Pubkey,
}

/// Emitted when a Sanad is locked for cross-chain transfer
#[event]
pub struct CrossChainLock {
    /// Unique Sanad identifier
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Owner of the sanad
    pub owner: Pubkey,
    /// Destination chain ID
    pub destination_chain: u8,
    /// Destination owner (hashed)
    pub destination_owner: [u8; 32],
    /// Source transaction hash
    pub source_tx_hash: [u8; 32],
    /// Lock timestamp (Unix epoch seconds)
    pub locked_at: i64,
    /// Asset class
    pub asset_class: u8,
    /// Chain-native asset id
    pub asset_id: [u8; 32],
    /// Canonical metadata hash
    pub metadata_hash: [u8; 32],
    /// Proof system identifier
    pub proof_system: u8,
    /// Proof root or verification-key commitment
    pub proof_root: [u8; 32],
}

/// Emitted when a Sanad is minted from a cross-chain transfer
#[event]
pub struct CrossChainMint {
    /// Unique Sanad identifier (from source chain)
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Owner of the new sanad
    pub owner: Pubkey,
    /// Source chain ID
    pub source_chain: u8,
    /// Source chain seal reference
    pub source_seal_ref: [u8; 32],
    /// Account address of the new sanad
    pub account: Pubkey,
    /// Asset class
    pub asset_class: u8,
    /// Chain-native asset id
    pub asset_id: [u8; 32],
    /// Canonical metadata hash
    pub metadata_hash: [u8; 32],
    /// Proof system identifier
    pub proof_system: u8,
    /// Proof root or verification-key commitment
    pub proof_root: [u8; 32],
}

/// Emitted when a locked Sanad is refunded
#[event]
pub struct CrossChainRefund {
    /// Unique Sanad identifier
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Address that claimed the refund
    pub claimant: Pubkey,
    /// Refund timestamp (Unix epoch seconds)
    pub refunded_at: i64,
}

/// Emitted when a Sanad is transferred to a new owner
#[event]
pub struct SanadTransferred {
    /// Unique Sanad identifier
    pub sanad_id: [u8; 32],
    /// Previous owner
    pub from: Pubkey,
    /// New owner
    pub to: Pubkey,
}

/// Emitted when a nullifier is registered
#[event]
pub struct NullifierRegistered {
    /// The nullifier hash
    pub nullifier: [u8; 32],
    /// The Sanad identifier
    pub sanad_id: [u8; 32],
}

/// Emitted whenever metadata/proof context is recorded for traceability.
#[event]
pub struct SanadMetadataRecorded {
    /// Unique Sanad identifier
    pub sanad_id: [u8; 32],
    /// Asset class
    pub asset_class: u8,
    /// Chain-native asset id
    pub asset_id: [u8; 32],
    /// Canonical metadata hash
    pub metadata_hash: [u8; 32],
    /// Proof system identifier
    pub proof_system: u8,
    /// Proof root or verification-key commitment
    pub proof_root: [u8; 32],
}
