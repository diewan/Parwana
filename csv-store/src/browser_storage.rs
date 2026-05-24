//! Browser localStorage implementation for CSV storage
//!
//! This module provides browser-specific localStorage persistence for the unified
//! storage format.

use csv_protocol::mcp::{FixAction, HasErrorSuggestion, error_codes};
use serde::{Deserialize, Serialize};

use crate::state::{StateStorage, StorageError};

/// Storage error for browser storage operations.
#[derive(Debug, thiserror::Error)]
pub enum BrowserStorageError {
    /// Browser API error
    #[error("Browser API error: {0}")]
    BrowserError(String),
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializeError(String),
    /// Not found
    #[error("Not found: {0}")]
    NotFound(String),
}

impl From<BrowserStorageError> for StorageError {
    fn from(e: BrowserStorageError) -> Self {
        StorageError::SerializeError(e.to_string())
    }
}

impl HasErrorSuggestion for BrowserStorageError {
    fn error_code(&self) -> &'static str {
        error_codes::WALLET_BROWSER_STORAGE
    }

    fn description(&self) -> String {
        self.to_string()
    }

    fn suggested_fix(&self) -> String {
        match self {
            BrowserStorageError::BrowserError(_) => "Browser storage API error. Check: \
                 1) LocalStorage is enabled in your browser, \
                 2) You are not in private/incognito mode, \
                 3) Storage quota has not been exceeded. \
                 Try clearing some storage or using a different browser."
                .to_string(),
            BrowserStorageError::SerializeError(_) => {
                "Failed to serialize data for browser storage. \
                 Ensure all data types are JSON-serializable."
                    .to_string()
            }
            BrowserStorageError::NotFound(key) => {
                format!(
                    "Item '{}' not found in browser storage. \
                     It may have been deleted or never saved.",
                    key
                )
            }
        }
    }

    fn docs_url(&self) -> String {
        error_codes::docs_url(self.error_code())
    }

    fn fix_action(&self) -> Option<FixAction> {
        match self {
            BrowserStorageError::BrowserError(_) => Some(FixAction::CheckState {
                url: "https://docs.csv.dev/wallet/browser-storage".to_string(),
                what: "Verify localStorage is enabled and not full".to_string(),
            }),
            _ => None,
        }
    }
}

/// LocalStorage-based storage manager for browser environments.
#[derive(Clone)]
pub struct LocalStorageManager {
    storage: web_sys::Storage,
    prefix: String,
}

impl LocalStorageManager {
    /// Create new storage manager.
    pub fn new(prefix: &str) -> Result<Self, BrowserStorageError> {
        let window: web_sys::Window = web_sys::window()
            .ok_or_else(|| BrowserStorageError::BrowserError("No window object".to_string()))?;

        let storage = window
            .local_storage()
            .map_err(|e| BrowserStorageError::BrowserError(format!("{:?}", e)))?
            .ok_or_else(|| {
                BrowserStorageError::BrowserError("localStorage not available".to_string())
            })?;

        Ok(Self {
            storage,
            prefix: prefix.to_string(),
        })
    }

    /// Save item.
    pub fn save<T: Serialize>(&self, key: &str, value: &T) -> Result<(), BrowserStorageError> {
        let json = serde_json::to_string(value)
            .map_err(|e| BrowserStorageError::SerializeError(e.to_string()))?;

        let full_key = format!("{}:{}", self.prefix, key);
        self.storage
            .set_item(&full_key, &json)
            .map_err(|e| BrowserStorageError::BrowserError(format!("{:?}", e)))
    }

    /// Load item.
    pub fn load<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<T, BrowserStorageError> {
        let full_key = format!("{}:{}", self.prefix, key);

        let json = self
            .storage
            .get_item(&full_key)
            .map_err(|e| BrowserStorageError::BrowserError(format!("{:?}", e)))?;

        match json {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| BrowserStorageError::SerializeError(e.to_string())),
            None => Err(BrowserStorageError::NotFound(key.to_string())),
        }
    }

    /// Try to load item, returning None on failure.
    pub fn try_load<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        let full_key = format!("{}:{}", self.prefix, key);
        let json = self.storage.get_item(&full_key).ok()??;
        serde_json::from_str(&json).ok()
    }

    /// Delete item.
    pub fn delete(&self, key: &str) -> Result<(), BrowserStorageError> {
        let full_key = format!("{}:{}", self.prefix, key);
        self.storage
            .remove_item(&full_key)
            .map_err(|e| BrowserStorageError::BrowserError(format!("{:?}", e)))
    }

    /// Get item as string.
    pub fn get_raw(&self, key: &str) -> Result<Option<String>, BrowserStorageError> {
        let full_key = format!("{}:{}", self.prefix, key);
        self.storage
            .get_item(&full_key)
            .map_err(|e| BrowserStorageError::BrowserError(format!("{:?}", e)))
    }

    /// Set raw string value.
    pub fn set_raw(&self, key: &str, value: &str) -> Result<(), BrowserStorageError> {
        let full_key = format!("{}:{}", self.prefix, key);
        self.storage
            .set_item(&full_key, value)
            .map_err(|e| BrowserStorageError::BrowserError(format!("{:?}", e)))
    }

    /// Check if key exists.
    pub fn contains(&self, key: &str) -> bool {
        let full_key = format!("{}:{}", self.prefix, key);
        self.storage.get_item(&full_key).ok().flatten().is_some()
    }
}

/// Storage keys
pub const UNIFIED_STORAGE_KEY: &str = "unified_storage";
pub const WALLET_MNEMONIC_KEY: &str = "mnemonic_encrypted";

/// Get wallet storage instance.
pub fn wallet_storage() -> Result<LocalStorageManager, BrowserStorageError> {
    LocalStorageManager::new("csv-cli")
}

/// Get seal storage instance.
pub fn seal_storage() -> Result<LocalStorageManager, BrowserStorageError> {
    LocalStorageManager::new("csv-seals")
}

/// Get asset storage instance.
pub fn asset_storage() -> Result<LocalStorageManager, BrowserStorageError> {
    LocalStorageManager::new("csv-assets")
}

/// State storage manager for browser environments.
///
/// This provides a high-level interface for loading/saving the complete
/// application state to browser localStorage.
pub struct BrowserStateStorage {
    storage: LocalStorageManager,
}

impl BrowserStateStorage {
    /// Create new browser state storage manager.
    pub fn new() -> Result<Self, BrowserStorageError> {
        Ok(Self {
            storage: wallet_storage()?,
        })
    }

    /// Load state from localStorage.
    pub fn load(&self) -> Result<StateStorage, BrowserStorageError> {
        self.storage
            .try_load::<StateStorage>(UNIFIED_STORAGE_KEY)
            .ok_or_else(|| BrowserStorageError::NotFound(UNIFIED_STORAGE_KEY.to_string()))
    }

    /// Load or create default state.
    pub fn load_or_default(&self) -> StateStorage {
        self.storage
            .try_load::<StateStorage>(UNIFIED_STORAGE_KEY)
            .unwrap_or_default()
    }

    /// Save state to localStorage.
    pub fn save(&self, storage: &StateStorage) -> Result<(), BrowserStorageError> {
        self.storage.save(UNIFIED_STORAGE_KEY, storage)
    }

    /// Check if storage exists.
    pub fn exists(&self) -> bool {
        self.storage.contains(UNIFIED_STORAGE_KEY)
    }

    /// Delete storage.
    pub fn delete(&self) -> Result<(), BrowserStorageError> {
        self.storage.delete(UNIFIED_STORAGE_KEY)
    }
}

// Re-export additional state types for convenience
pub use crate::state::{FaucetConfig, GasAccount};

#[cfg(test)]
mod tests {
    use crate::{
        ChainId, Network, SanadStatus, TransactionStatus, TransactionType, TransferStatus,
    };

    // Note: These tests require a browser environment (wasm32-unknown-unknown target)
    // They won't run in standard cargo test without wasm-bindgen-test

    #[test]
    fn test_chain_display() {
        assert_eq!(ChainId::new("bitcoin").to_string(), "bitcoin");
        assert_eq!(ChainId::new("ethereum").to_string(), "ethereum");
        assert_eq!(ChainId::new("solana").to_string(), "solana");
        assert_eq!(ChainId::new("aptos").to_string(), "aptos");
        assert_eq!(ChainId::new("sui").to_string(), "sui");
    }

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Dev.to_string(), "dev");
        assert_eq!(Network::Test.to_string(), "test");
        assert_eq!(Network::Main.to_string(), "main");
    }

    #[test]
    fn test_sanad_status_display() {
        assert_eq!(SanadStatus::Active.to_string(), "active");
        assert_eq!(SanadStatus::Transferred.to_string(), "transferred");
        assert_eq!(SanadStatus::Consumed.to_string(), "consumed");
    }

    #[test]
    fn test_transaction_status_display() {
        assert_eq!(TransactionStatus::Pending.to_string(), "pending");
        assert_eq!(TransactionStatus::Confirmed.to_string(), "confirmed");
        assert_eq!(TransactionStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn test_transaction_type_display() {
        assert_eq!(TransactionType::Transfer.to_string(), "Transfer");
        assert_eq!(TransactionType::SealCreation.to_string(), "Seal Creation");
        assert_eq!(
            TransactionType::SealConsumption.to_string(),
            "Seal Consumption"
        );
    }

    #[test]
    fn test_transfer_status_display() {
        assert_eq!(TransferStatus::Initiated.to_string(), "initiated");
        assert_eq!(TransferStatus::Locked.to_string(), "locked");
        assert_eq!(TransferStatus::Verifying.to_string(), "verifying");
        assert_eq!(TransferStatus::Minting.to_string(), "minting");
        assert_eq!(TransferStatus::Completed.to_string(), "completed");
        assert_eq!(TransferStatus::Failed.to_string(), "failed");
    }
}
