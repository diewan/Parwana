//! Event definitions for CSV Seal program (RFC-0012 canonical event names)

use anchor_lang::prelude::*;

/// Emitted when the LockRegistry is initialized
#[event]
pub struct RegistryInitialized {
    /// Authority that initialized the registry
    pub authority: Pubkey,
    /// Refund timeout in seconds
    pub refund_timeout: u32,
}

/// Emitted when the verifier registry is initialized (RFC-0012 §9.3)
#[event]
pub struct VerifierRegistryInitialized {
    /// Governance authority for the verifier set
    pub authority: Pubkey,
    /// Signature threshold `M`
    pub threshold: u8,
    /// Number of verifiers seeded
    pub verifier_count: u8,
}

/// Emitted when a verifier is added to the set
#[event]
pub struct VerifierAdded {
    /// Compressed 33-byte secp256k1 public key
    pub verifier: [u8; 33],
}

/// Emitted when a verifier is removed from the set
#[event]
pub struct VerifierRemoved {
    /// Compressed 33-byte secp256k1 public key
    pub verifier: [u8; 33],
}

/// Emitted when the signature threshold `M` is updated
#[event]
pub struct ThresholdUpdated {
    /// New threshold `M`
    pub threshold: u8,
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

/// Canonical: Emitted when a Sanad is locked for cross-chain transfer
#[event]
pub struct SanadLocked {
    /// Unique Sanad identifier
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Owner of the sanad
    pub owner: Pubkey,
    /// Destination chain ID (1-byte legacy id)
    pub destination_chain: u8,
    /// Destination owner (hashed)
    pub destination_owner: [u8; 32],
    /// Lock timestamp (Unix epoch seconds)
    pub locked_at: i64,
}

/// Canonical: Emitted when a Sanad is minted on this destination chain
/// (RFC-0012 §3 / ABI §Canonical Event Names). Distinct from settlement.
#[event]
pub struct SanadMinted {
    /// Unique Sanad identifier (from source chain)
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Source chain identity (keccak256("csv.chain.<src>"))
    pub source_chain: [u8; 32],
    /// Full destination-owner identity bytes (only the hash is stored on-chain)
    pub destination_owner: Vec<u8>,
    /// Source-chain lock event id (settlement replay key)
    pub lock_event_id: [u8; 32],
    /// Replay nullifier consumed by the source seal
    pub nullifier: [u8; 32],
    /// Mint timestamp (Unix epoch seconds)
    pub minted_at: i64,
}

/// Canonical: Emitted when a locked Sanad is refunded
#[event]
pub struct SanadRefunded {
    /// Unique Sanad identifier
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// Address that claimed the refund
    pub claimant: Pubkey,
    /// Reason for refund
    pub reason: String,
    /// Refund timestamp (Unix epoch seconds)
    pub refunded_at: i64,
}

/// Canonical: Emitted when a source-chain escrow is settled to the operator on a
/// verifier-signed §10 receipt. DISTINCT from `SanadMinted`.
#[event]
pub struct SettlementReleased {
    /// Sanad whose source lock was settled
    pub sanad_id: [u8; 32],
    /// Settlement replay key (source lock event)
    pub lock_event_id: [u8; 32],
    /// The sole escrow beneficiary bound in the signed receipt
    pub operator_payout: Pubkey,
    /// Canonical reference to the confirmed destination mint
    pub destination_mint_tx_ref: [u8; 32],
    /// Release timestamp (Unix epoch seconds)
    pub released_at: i64,
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
}
