//! Type definitions for Solana adapter

use csv_wire::HashWire;
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, signature::Signature};

/// Solana-specific seal reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaSealPoint {
    /// Account address used as seal
    pub account: Pubkey,
    /// Account owner program
    pub owner: Pubkey,
    /// Lamport amount (0 for closed accounts)
    pub lamports: u64,
    /// Account state seed if applicable
    pub seed: Option<Vec<u8>>,
}

/// Solana-specific anchor reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaCommitAnchor {
    /// Transaction signature
    pub signature: Signature,
    /// Slot number
    pub slot: u64,
    /// Block height
    pub block_height: u64,
    /// Account state changes
    pub account_changes: Vec<AccountChange>,
}

/// Account state change
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChange {
    /// Account address
    pub pubkey: Pubkey,
    /// Previous lamport balance
    pub prev_lamports: u64,
    /// New lamport balance
    pub new_lamports: u64,
    /// Previous data
    pub prev_data: Option<Vec<u8>>,
    /// New data
    pub new_data: Option<Vec<u8>>,
    /// Account was closed
    pub closed: bool,
}

/// Solana inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaInclusionProof {
    /// Transaction signature
    pub signature: Signature,
    /// Slot number
    pub slot: u64,
    /// Block height
    pub block_height: u64,
    /// Confirmation status
    pub confirmation_status: ConfirmationStatus,
    /// Account proofs for each changed account
    pub account_proofs: Vec<AccountProof>,
}

/// Account proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProof {
    /// Account address
    pub pubkey: Pubkey,
    /// Merkle proof
    pub proof: Vec<Vec<u8>>,
    /// Account data hash
    pub data_hash: Option<HashWire>,
}

/// Confirmation status for Solana transactions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfirmationStatus {
    /// Transaction is processed but not confirmed
    Processed,
    /// Transaction is confirmed
    Confirmed,
    /// Transaction is finalized
    Finalized,
}

/// Solana finality proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaFinalityProof {
    /// Final slot number
    pub slot: u64,
    /// Block hash
    pub block_hash: HashWire,
    /// Confirmation depth
    pub confirmation_depth: u64,
    /// Timestamp
    pub timestamp: i64,
}

/// CSV program instruction types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsvInstruction {
    /// Create a new sanad
    CreateSanad {
        sanad_id: HashWire,
        owner: Pubkey,
        commitment: HashWire,
    },
    /// Consume a seal
    ConsumeSeal {
        seal_account: Pubkey,
        sanad_id: HashWire,
        new_owner: Pubkey,
    },
    /// Transfer a sanad
    TransferSanad {
        sanad_id: HashWire,
        from_owner: Pubkey,
        to_owner: Pubkey,
        destination_chain: String,
    },
    /// Publish commitment
    PublishCommitment {
        commitment: HashWire,
        sanad_id: HashWire,
        metadata: Vec<u8>,
    },
}

/// Account state for seals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealAccount {
    /// Account address
    pub pubkey: Pubkey,
    /// Owner of the sanad
    pub owner: Pubkey,
    /// Sanad ID
    pub sanad_id: HashWire,
    /// Commitment hash
    pub commitment: HashWire,
    /// Seal status
    pub status: SealStatus,
    /// Created at slot
    pub created_slot: u64,
    /// Consumed at slot
    pub consumed_slot: Option<u64>,
}

/// Seal status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealStatus {
    /// Seal is active and unspent
    Active,
    /// Seal is consumed
    Consumed,
    /// Seal is pending confirmation
    Pending,
}

/// Solana SanadAccount state (matches contract state.rs)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaSanadAccount {
    /// Owner of the sanad
    pub owner: Pubkey,
    /// Unique Sanad identifier
    pub sanad_id: [u8; 32],
    /// Commitment hash
    pub commitment: [u8; 32],
    /// State root
    pub state_root: [u8; 32],
    /// Nullifier
    pub nullifier: [u8; 32],
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
    /// Canonical lifecycle state (0-9)
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

/// Solana transaction status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolanaTransactionStatus {
    /// Transaction is confirmed
    Confirmed,
    /// Transaction failed
    Failed,
    /// Transaction is pending
    Pending,
}

/// Solana transaction representation
#[derive(Debug, Clone)]
pub struct SolanaTransaction {
    /// Transaction status
    pub status: SolanaTransactionStatus,
    /// Slot number
    pub slot: u64,
    /// Account keys involved in the transaction
    pub account_keys: Vec<Pubkey>,
    /// Transaction fee
    pub fee: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_seal_ref() {
        let seal = SolanaSealPoint {
            account: Pubkey::new_unique(),
            owner: Pubkey::new_unique(),
            lamports: 1000,
            seed: None,
        };
        assert_eq!(seal.lamports, 1000);
    }

    #[test]
    fn test_confirmation_status() {
        assert_eq!(ConfirmationStatus::Processed, ConfirmationStatus::Processed);
        assert_ne!(ConfirmationStatus::Processed, ConfirmationStatus::Confirmed);
    }
}
