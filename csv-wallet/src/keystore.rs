//! Secure key storage with zeroization
//!
//! This module now uses the canonical SecretHandle from csv-protocol
//! to ensure consistency across the codebase.

use csv_keys::memory::SecretKey;
use csv_protocol::secret::{SecretHandle, SharedSecretHandle};
use std::collections::HashMap;
use std::sync::Arc;

/// Key purpose for derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// Signing key
    Signing,
    /// Encryption key
    Encryption,
    /// Authentication key
    Authentication,
}

/// Key store for managing multiple secret handles
///
/// This uses the canonical SecretHandle from csv-protocol which supports:
/// - Raw secret keys (for testing)
/// - 64-byte BIP-39 seeds (for HD wallet derivation)
/// - Keystore references (for production)
pub struct KeyStore {
    /// Map of key ID to shared secret handle (Arc for thread-safe sharing)
    keys: HashMap<String, SharedSecretHandle>,
}

impl KeyStore {
    /// Create a new key store
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add a key to the store from raw bytes
    ///
    /// # Arguments
    /// * `id` - Key identifier
    /// * `secret` - Secret key bytes (32 bytes for private key, 64 bytes for seed)
    /// * `purpose` - Key purpose (metadata only, not stored in SecretHandle)
    /// * `chain` - Chain identifier (metadata only, not stored in SecretHandle)
    pub fn add_key(&mut self, id: String, secret: Vec<u8>, _purpose: KeyPurpose, _chain: String) {
        // Determine if this is a 64-byte seed or 32-byte key
        let handle = if secret.len() == 64 {
            let mut seed_array = [0u8; 64];
            seed_array.copy_from_slice(&secret);
            SharedSecretHandle::from_seed(seed_array)
        } else {
            let mut key_array = [0u8; 32];
            let len = secret.len().min(32);
            key_array[..len].copy_from_slice(&secret[..len]);
            SharedSecretHandle::from_bytes(key_array)
        };
        self.keys.insert(id, handle);
    }

    /// Add a shared secret handle directly
    ///
    /// # Arguments
    /// * `id` - Key identifier
    /// * `handle` - Shared secret handle
    pub fn add_handle(&mut self, id: String, handle: SharedSecretHandle) {
        self.keys.insert(id, handle);
    }

    /// Get a key from the store
    ///
    /// # Arguments
    /// * `id` - Key identifier
    ///
    /// # Returns
    /// The shared secret handle if found
    pub fn get_key(&self, id: &str) -> Option<&SharedSecretHandle> {
        self.keys.get(id)
    }

    /// Remove a key from the store
    ///
    /// # Arguments
    /// * `id` - Key identifier
    ///
    /// # Returns
    /// The shared secret handle if found
    pub fn remove_key(&mut self, id: &str) -> Option<SharedSecretHandle> {
        self.keys.remove(id)
    }

    /// List all key IDs
    pub fn list_keys(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}
