//! RPC client for Solana adapter
//!
//! All methods are synchronous, matching the pattern used by other chain adapters.
//! The underlying `solana-rpc-client` provides sync HTTP methods.

use solana_sdk::{
    account::Account, pubkey::Pubkey, signature::Signature, transaction::Transaction,
};
use solana_transaction_status::EncodedConfirmedBlock;

use crate::error::SolanaError;
use crate::error::SolanaResult;
use crate::types::{AccountChange, ConfirmationStatus};

/// Trait for Solana RPC operations (synchronous, matching other chain adapters)
pub trait SolanaRpc: Send + Sync {
    /// Get account info
    fn get_account(&self, pubkey: &Pubkey) -> SolanaResult<Account>;

    /// Get multiple accounts
    fn get_multiple_accounts(&self, pubkeys: &[Pubkey]) -> SolanaResult<Vec<Option<Account>>>;

    /// Get every account owned by a program.
    ///
    /// Callers must still validate account discriminators and canonical fields;
    /// program ownership alone does not identify an account type.
    fn get_program_accounts(&self, program_id: &Pubkey) -> SolanaResult<Vec<(Pubkey, Account)>>;

    /// Get transaction with status
    fn get_transaction(&self, signature: &Signature) -> SolanaResult<String>;

    /// Send transaction
    fn send_transaction(&self, transaction: &Transaction) -> SolanaResult<Signature>;

    /// Get latest slot
    fn get_latest_slot(&self) -> SolanaResult<u64>;

    /// Get slot with commitment
    fn get_slot_with_commitment(&self, commitment: &str) -> SolanaResult<u64>;

    /// Get account changes between slots
    fn get_account_changes(&self, from_slot: u64, to_slot: u64)
    -> SolanaResult<Vec<AccountChange>>;

    /// Wait for transaction confirmation (polls with std::thread::sleep)
    fn wait_for_confirmation(&self, signature: &Signature) -> SolanaResult<ConfirmationStatus>;

    /// Get minimum balance for rent exemption
    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> SolanaResult<u64>;

    /// Get recent blockhash for transaction
    fn get_recent_blockhash(&self) -> SolanaResult<solana_sdk::hash::Hash>;

    /// Get balance for account
    fn get_balance(&self, pubkey: &Pubkey) -> SolanaResult<u64>;

    /// Get block at given slot
    fn get_block(&self, slot: u64) -> SolanaResult<Option<EncodedConfirmedBlock>>;

    /// Get block hash at given slot
    fn get_block_hash(&self, slot: u64) -> SolanaResult<solana_sdk::hash::Hash>;

    /// Clone the RPC client for creating new boxed instances
    fn clone_boxed(&self) -> Box<dyn SolanaRpc>;
}

/// Mock RPC client for testing
pub struct MockSolanaRpc {
    accounts: std::collections::HashMap<Pubkey, Account>,
}

impl Default for MockSolanaRpc {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSolanaRpc {
    /// Create new test RPC
    pub fn new() -> Self {
        Self {
            accounts: std::collections::HashMap::new(),
        }
    }

    /// Add account to test RPC
    pub fn add_account(&mut self, pubkey: Pubkey, account: Account) {
        self.accounts.insert(pubkey, account);
    }
}

impl SolanaRpc for MockSolanaRpc {
    fn get_account(&self, pubkey: &Pubkey) -> SolanaResult<Account> {
        self.accounts
            .get(pubkey)
            .cloned()
            .ok_or_else(|| SolanaError::AccountNotFound(pubkey.to_string()))
    }

    fn get_multiple_accounts(&self, pubkeys: &[Pubkey]) -> SolanaResult<Vec<Option<Account>>> {
        Ok(pubkeys
            .iter()
            .map(|pk| self.accounts.get(pk).cloned())
            .collect())
    }

    fn get_program_accounts(&self, program_id: &Pubkey) -> SolanaResult<Vec<(Pubkey, Account)>> {
        Ok(self
            .accounts
            .iter()
            .filter(|(_, account)| account.owner == *program_id)
            .map(|(pubkey, account)| (*pubkey, account.clone()))
            .collect())
    }

    fn get_transaction(&self, _signature: &Signature) -> SolanaResult<String> {
        Err(SolanaError::Rpc(
            "Mock RPC: get_transaction not implemented".to_string(),
        ))
    }

    fn send_transaction(&self, _transaction: &Transaction) -> SolanaResult<Signature> {
        Ok(Signature::new_unique())
    }

    fn get_latest_slot(&self) -> SolanaResult<u64> {
        Ok(1000)
    }

    fn get_slot_with_commitment(&self, _commitment: &str) -> SolanaResult<u64> {
        Ok(1000)
    }

    fn get_account_changes(
        &self,
        _from_slot: u64,
        _to_slot: u64,
    ) -> SolanaResult<Vec<AccountChange>> {
        Ok(vec![])
    }

    fn wait_for_confirmation(&self, _signature: &Signature) -> SolanaResult<ConfirmationStatus> {
        Ok(ConfirmationStatus::Confirmed)
    }

    fn get_minimum_balance_for_rent_exemption(&self, _data_len: usize) -> SolanaResult<u64> {
        // Test value - rent exemption for typical program size
        Ok(6_900_000_000)
    }

    fn get_recent_blockhash(&self) -> SolanaResult<solana_sdk::hash::Hash> {
        Ok(solana_sdk::hash::Hash::default())
    }

    fn get_balance(&self, pubkey: &Pubkey) -> SolanaResult<u64> {
        // Return test balance from configured accounts or default
        Ok(self
            .accounts
            .get(pubkey)
            .map(|a| a.lamports)
            .unwrap_or(1_000_000_000))
    }

    fn get_block(&self, _slot: u64) -> SolanaResult<Option<EncodedConfirmedBlock>> {
        // Mock implementation - return None for simplicity
        // In a real implementation, this would return actual block data
        Ok(None)
    }

    fn get_block_hash(&self, slot: u64) -> SolanaResult<solana_sdk::hash::Hash> {
        // Mock implementation - return a deterministic hash based on slot
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&slot.to_le_bytes());
        Ok(solana_sdk::hash::Hash::new_from_array(hash_bytes))
    }

    fn clone_boxed(&self) -> Box<dyn SolanaRpc> {
        Box::new(MockSolanaRpc {
            accounts: self.accounts.clone(),
        })
    }
}
