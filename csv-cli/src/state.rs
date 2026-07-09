//! CLI state management — persistent state using unified storage
//!
//! The CLI holds NO protocol authority state. All protocol state
//! (leases, transfers, replay registry) lives exclusively in csv-runtime.
//! The CLI is a stateless client that delegates to the runtime.

use std::io::{self, Write};
use std::path::Path;

#[path = "encrypt.rs"]
mod encrypt;

pub use csv_store::state::{
    Chain, ContractRecord, GasAccount, ProvenanceStrengthSignal, SanadRecord, SanadStatus,
    SealRecord, SealStatus, TransactionRecord, TransactionStatus, TransactionType, TransferRecord,
    TransferStatus, UnifiedStorage, UtxoRecord, WalletAccount,
};

// Unified state manager for CLI

// The unified state manager exposes the full CLI state surface; not every accessor has a command yet.
#[allow(dead_code)]
#[allow(deprecated)]
/// Unified state manager for CLI.
///
/// Protocol authority state (leases, transfer execution, replay registry)
/// lives exclusively in csv-runtime. The CLI only stores display records
/// (sanads, transfers, seals) for user reference.
pub struct UnifiedStateManager {
    pub storage: UnifiedStorage,
    file_path: String,
    passphrase: String,
}

impl UnifiedStateManager {
    /// Default storage path
    pub fn default_path() -> String {
        if let Some(home) = dirs::home_dir() {
            home.join(".csv/unified_storage.json")
                .to_string_lossy()
                .to_string()
        } else {
            std::env::temp_dir()
                .join("csv-unified-storage.json")
                .to_string_lossy()
                .to_string()
        }
    }

    /// Prompt user for a passphrase interactively.
    pub fn prompt_passphrase() -> anyhow::Result<String> {
        print!("Enter CSV state passphrase: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let passphrase = input.trim().to_string();
        if passphrase.is_empty() {
            anyhow::bail!("Passphrase cannot be empty");
        }
        Ok(passphrase)
    }

    /// Load unified state from file with passphrase.
    pub fn load(passphrase: &str) -> anyhow::Result<Self> {
        let path = Self::default_path();
        let storage = if Path::new(&path).exists() {
            let content = std::fs::read_to_string(&path)?;
            if encrypt::is_encrypted(&content) {
                let encrypted: encrypt::EncryptedState = serde_json::from_str(&content)?;
                let plaintext = encrypt::decrypt(&encrypted, passphrase)?;
                let plaintext_str = String::from_utf8(plaintext)?;
                serde_json::from_str::<UnifiedStorage>(&plaintext_str)?
            } else {
                // Plaintext file - load as-is, will be encrypted on next save
                serde_json::from_str(&content)?
            }
        } else {
            UnifiedStorage::new().with_defaults()
        };

        Ok(Self {
            storage,
            file_path: path,
            passphrase: passphrase.to_string(),
        })
    }

    /// Load from a specific path with passphrase.
    ///
    /// Non-default state paths are used by tests and by operators pointing the CLI
    /// at an alternate state file; no in-tree command wires it yet.
    #[allow(dead_code)]
    pub fn load_from(path: &str, passphrase: &str) -> anyhow::Result<Self> {
        let storage = if Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            if encrypt::is_encrypted(&content) {
                let encrypted: encrypt::EncryptedState = serde_json::from_str(&content)?;
                let plaintext = encrypt::decrypt(&encrypted, passphrase)?;
                let plaintext_str = String::from_utf8(plaintext)?;
                serde_json::from_str::<UnifiedStorage>(&plaintext_str)?
            } else {
                serde_json::from_str(&content)?
            }
        } else {
            UnifiedStorage::new().with_defaults()
        };

        Ok(Self {
            storage,
            file_path: path.to_string(),
            passphrase: passphrase.to_string(),
        })
    }

    /// Create new with defaults (requires passphrase for encryption).
    ///
    /// Commands construct state via `load`/`load_from`; this bare constructor is
    /// the seam for a future `csv init`.
    #[allow(dead_code)]
    pub fn new(passphrase: &str) -> Self {
        Self {
            storage: UnifiedStorage::new().with_defaults(),
            file_path: Self::default_path(),
            passphrase: passphrase.to_string(),
        }
    }

    /// Save state to file (encrypted).
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Path::new(&self.file_path);
        let content = serde_json::to_string_pretty(&self.storage)?;
        encrypt::save(path, &content, &self.passphrase)?;
        Ok(())
    }

    /// Passphrase used to decrypt the loaded CLI state.
    ///
    /// Read by callers that re-save state under the same passphrase; none in tree yet.
    #[allow(dead_code)]
    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// Path of the encrypted CLI state file.
    pub fn file_path(&self) -> &str {
        &self.file_path
    }

    // --- Sanads Management ---

    /// Add a Sanad to tracking
    pub fn add_sanad(&mut self, sanad: SanadRecord) {
        self.storage.sanads.push(sanad);
    }

    /// Get a Sanad by ID
    pub fn get_sanad(&self, id: &str) -> Option<&SanadRecord> {
        self.storage.get_sanad(id)
    }

    /// Mark a Sanad as consumed
    pub fn consume_sanad(&mut self, id: &str) -> anyhow::Result<()> {
        if let Some(sanad) = self.storage.sanads.iter_mut().find(|r| r.id == id) {
            sanad.status = SanadStatus::Consumed;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Sanad {} not found", id))
        }
    }

    /// Update a Sanad's status
    pub fn update_sanad_status(&mut self, id: &str, status: SanadStatus) -> anyhow::Result<()> {
        if let Some(sanad) = self.storage.sanads.iter_mut().find(|r| r.id == id) {
            sanad.status = status;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Sanad {} not found", id))
        }
    }

    /// Remove a Sanad from local tracking
    pub fn remove_sanad(&mut self, id: &str) -> anyhow::Result<()> {
        let len_before = self.storage.sanads.len();
        self.storage.sanads.retain(|r| r.id != id);
        if self.storage.sanads.len() < len_before {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Sanad {} not found", id))
        }
    }

    // --- Transfer Management ---

    /// Add or update a transfer in tracking.
    ///
    /// Upserts by transfer `id`: a transfer that is locked, re-checked on each
    /// finality poll, and later resumed would otherwise append a new row every
    /// time, flooding `cross-chain list` with duplicates. Replace the existing
    /// entry in place instead so the cache holds one row per transfer.
    pub fn add_transfer(&mut self, transfer: TransferRecord) {
        if let Some(existing) = self
            .storage
            .transfers
            .iter_mut()
            .find(|t| t.id == transfer.id)
        {
            *existing = transfer;
        } else {
            self.storage.transfers.push(transfer);
        }
    }

    /// Get a transfer by ID
    pub fn get_transfer(&self, id: &str) -> Option<&TransferRecord> {
        self.storage.get_transfer(id)
    }

    /// Update transfer status
    /// Transfer status is written through the runtime journal; no command calls this yet.
    #[allow(dead_code)]
    pub fn update_transfer_status(
        &mut self,
        id: &str,
        status: TransferStatus,
    ) -> anyhow::Result<()> {
        if let Some(transfer) = self.storage.transfers.iter_mut().find(|t| t.id == id) {
            transfer.status = status;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Transfer {} not found", id))
        }
    }

    // --- Seal Management ---

    /// Check if a seal has been consumed
    pub fn is_seal_consumed(&self, seal_ref: &str) -> bool {
        self.storage
            .seals
            .iter()
            .any(|s| s.seal_ref == seal_ref && s.consumed)
    }

    /// Record a seal consumption
    pub fn record_seal_consumption(&mut self, seal_ref: String) {
        if let Some(seal) = self
            .storage
            .seals
            .iter_mut()
            .find(|s| s.seal_ref == seal_ref)
        {
            seal.consumed = true;
        } else {
            // Create new seal record if not exists
            // Note: chain and value would need to be provided by caller
        }
    }

    /// Add or update a seal
    pub fn add_seal(&mut self, seal: SealRecord) {
        if let Some(existing) = self
            .storage
            .seals
            .iter_mut()
            .find(|s| s.seal_ref == seal.seal_ref)
        {
            *existing = seal;
        } else {
            self.storage.seals.push(seal);
        }
    }

    // --- Contract Management ---

    /// Store deployed contract info
    pub fn store_contract(&mut self, contract: ContractRecord) {
        // Remove existing contract at same address
        self.storage
            .contracts
            .retain(|c| c.address != contract.address);
        self.storage.contracts.push(contract);
    }

    /// Get all deployed contracts for a chain
    /// Contract records are read by upcoming deploy/status commands.
    #[allow(dead_code)]
    pub fn get_contracts(&self, chain: &Chain) -> Vec<&ContractRecord> {
        self.storage.get_contracts(chain)
    }

    /// Get the first/primary deployed contract for a chain
    pub fn get_contract(&self, chain: &Chain) -> Option<&ContractRecord> {
        self.storage.contracts.iter().find(|c| &c.chain == chain)
    }

    // --- Address/Account Management ---

    /// Store an address for a chain (creates or updates wallet account)
    pub fn store_address(&mut self, chain: Chain, address: String) {
        self.storage.set_account(WalletAccount {
            id: format!("{}-cli", chain),
            chain: chain.clone(),
            name: format!("{} CLI Account", chain),
            address,
            xpub: None,
            derivation_path: None,
            keystore_ref: None,
        });
    }

    /// Get address for a chain
    pub fn get_address(&self, chain: &Chain) -> Option<&str> {
        self.storage.get_account(chain).map(|a| a.address.as_str())
    }

    /// Store a gas payment account for a chain
    /// Gas-account tracking is populated by upcoming faucet/gas commands.
    #[allow(dead_code)]
    pub fn store_gas_account(&mut self, chain: Chain, address: String) {
        // Remove existing
        self.storage.gas_accounts.retain(|g| g.chain != chain);
        self.storage
            .gas_accounts
            .push(GasAccount { chain, address });
    }

    /// Get gas payment account for a chain
    /// Falls back to regular wallet address if no dedicated gas account exists
    /// Read by upcoming faucet/gas commands; paired with `store_gas_account`.
    #[allow(dead_code)]
    pub fn get_gas_account(&self, chain: &Chain) -> Option<&str> {
        self.storage.get_gas_account(chain)
    }

    // --- Chain Configuration ---

    /// Get chain configuration
    /// Chain config is read from `Config` today; this is the state-backed accessor.
    #[allow(dead_code)]
    pub fn chain_config(&self, chain: &Chain) -> Option<&crate::config::ChainConfig> {
        self.storage.chains.get(chain)
    }

    /// Set chain configuration
    /// Chain config is read from `Config` today; this is the state-backed setter.
    #[allow(dead_code)]
    pub fn set_chain_config(&mut self, chain: Chain, config: crate::config::ChainConfig) {
        self.storage.chains.insert(chain, config);
    }

    // --- Wallet/Account Access ---

    /// Get wallet account for a chain
    /// Wallet accounts are read via `get_address`; this returns the full record.
    #[allow(dead_code)]
    pub fn get_account(&self, chain: &Chain) -> Option<&WalletAccount> {
        self.storage.get_account(chain)
    }

    /// Set wallet account
    pub fn set_account(&mut self, account: WalletAccount) {
        self.storage.set_account(account);
    }

    /// Export for wallet import
    /// State import/export surface for backup tooling; no command wired yet.
    #[allow(dead_code)]
    pub fn export_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(&self.storage)?)
    }

    /// Import from wallet export
    /// State import/export surface for backup tooling; no command wired yet.
    #[allow(dead_code)]
    pub fn import_json(&mut self, json: &str) -> anyhow::Result<()> {
        self.storage = serde_json::from_str(json)?;
        Ok(())
    }

    // --- Transaction Recording ---

    /// Record a transaction from a transfer
    /// Transaction history is journaled by the runtime; this mirrors it into local state.
    #[allow(dead_code)]
    pub fn record_transaction_from_transfer(
        &mut self,
        transfer: &TransferRecord,
        tx_type: TransactionType,
    ) -> TransactionRecord {
        let tx = TransactionRecord {
            id: format!(
                "tx-{}-{:x}",
                transfer.id,
                std::time::UNIX_EPOCH
                    .elapsed()
                    .unwrap_or_default()
                    .as_secs()
            ),
            chain: match tx_type {
                TransactionType::CrossChainLock => transfer.source_chain.clone(),
                TransactionType::CrossChainMint => transfer.dest_chain.clone(),
                _ => transfer.source_chain.clone(),
            },
            tx_hash: match tx_type {
                TransactionType::CrossChainLock | TransactionType::SanadTransfer => {
                    transfer.source_tx_hash.clone().unwrap_or_default()
                }
                TransactionType::CrossChainMint => {
                    transfer.dest_tx_hash.clone().unwrap_or_default()
                }
                _ => transfer.source_tx_hash.clone().unwrap_or_default(),
            },
            tx_type,
            status: match transfer.status {
                TransferStatus::Completed => TransactionStatus::Confirmed,
                TransferStatus::Failed => TransactionStatus::Failed,
                _ => TransactionStatus::Pending,
            },
            from_address: transfer.sender_address.clone().unwrap_or_default(),
            to_address: transfer.destination_address.clone(),
            amount: None,
            fee: match tx_type {
                TransactionType::CrossChainLock => transfer.source_fee,
                TransactionType::CrossChainMint => transfer.dest_fee,
                _ => transfer.source_fee,
            },
            block_number: None,
            confirmations: None,
            created_at: transfer.created_at,
            explorer_url: None,
        };
        self.storage.transactions.push(tx.clone());
        tx
    }

    /// Store an address with derivation path for a chain
    pub fn store_address_with_derivation(
        &mut self,
        chain: Chain,
        address: String,
        derivation_path: Option<String>,
    ) {
        self.storage.set_account(WalletAccount {
            id: format!("{}-cli", chain),
            chain: chain.clone(),
            name: format!("{} CLI Account", chain),
            address,
            xpub: None,
            derivation_path,
            keystore_ref: None,
        });
    }

    // Note: Lease management is handled exclusively by csv-runtime.
    // The CLI delegates lease acquisition and management to the runtime
    // and only stores display records for user reference.
}
