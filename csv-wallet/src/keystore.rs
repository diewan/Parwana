//! Secure key storage with zeroization

use secrecy::{ExposeSecret, SecretVec, Zeroize};
use std::fmt;

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

/// Handle to a secret key with automatic zeroization
pub struct SecretHandle {
    /// Secret key bytes (zeroized on drop)
    secret: SecretVec<u8>,
    /// Key purpose
    purpose: KeyPurpose,
    /// Chain this key is for
    chain: String,
}

impl SecretHandle {
    /// Create a new secret handle
    ///
    /// # Arguments
    /// * `secret` - Secret key bytes (will be zeroized on drop)
    /// * `purpose` - Key purpose
    /// * `chain` - Chain identifier
    pub fn new(secret: Vec<u8>, purpose: KeyPurpose, chain: String) -> Self {
        Self {
            secret: SecretVec::new(secret),
            purpose,
            chain,
        }
    }

    /// Get the secret bytes (for internal use only)
    ///
    /// # Safety
    /// This exposes the secret bytes. Use with extreme caution.
    pub fn expose_secret(&self) -> &[u8] {
        self.secret.expose_secret()
    }

    /// Get the key purpose
    pub fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// Get the chain
    pub fn chain(&self) -> &str {
        &self.chain
    }
}

impl Zeroize for SecretHandle {
    fn zeroize(&mut self) {
        // SecretVec already handles zeroization
    }
}

impl fmt::Debug for SecretHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretHandle")
            .field("purpose", &self.purpose)
            .field("chain", &self.chain)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Key store for managing multiple secret handles
pub struct KeyStore {
    /// Map of key ID to secret handle
    keys: std::collections::HashMap<String, SecretHandle>,
}

impl KeyStore {
    /// Create a new key store
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
        }
    }

    /// Add a key to the store
    ///
    /// # Arguments
    /// * `id` - Key identifier
    /// * `secret` - Secret key bytes
    /// * `purpose` - Key purpose
    /// * `chain` - Chain identifier
    pub fn add_key(
        &mut self,
        id: String,
        secret: Vec<u8>,
        purpose: KeyPurpose,
        chain: String,
    ) {
        let handle = SecretHandle::new(secret, purpose, chain);
        self.keys.insert(id, handle);
    }

    /// Get a key from the store
    ///
    /// # Arguments
    /// * `id` - Key identifier
    ///
    /// # Returns
    /// The secret handle if found
    pub fn get_key(&self, id: &str) -> Option<&SecretHandle> {
        self.keys.get(id)
    }

    /// Remove a key from the store
    ///
    /// # Arguments
    /// * `id` - Key identifier
    ///
    /// # Returns
    /// The secret handle if found
    pub fn remove_key(&mut self, id: &str) -> Option<SecretHandle> {
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
