//! Type definitions for Solana adapter

use csv_core::Hash;
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
    pub data_hash: Option<Hash>,
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
    pub block_hash: Hash,
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
        sanad_id: Hash,
        owner: Pubkey,
        commitment: Hash,
    },
    /// Consume a seal
    ConsumeSeal {
        seal_account: Pubkey,
        sanad_id: Hash,
        new_owner: Pubkey,
    },
    /// Transfer a sanad
    TransferSanad {
        sanad_id: Hash,
        from_owner: Pubkey,
        to_owner: Pubkey,
        destination_chain: String,
    },
    /// Publish commitment
    PublishCommitment {
        commitment: Hash,
        sanad_id: Hash,
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
    pub sanad_id: Hash,
    /// Commitment hash
    pub commitment: Hash,
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
