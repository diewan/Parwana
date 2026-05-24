//! Browser LocalStorage-based keystore for WASM targets.
//!
//! This module provides secure key storage using the browser's LocalStorage API
//! with AES-256-GCM encryption. Keys are never stored in plaintext.
//!
//! # Security Model
//!
//! - Keys are encrypted with user passphrase before storage
//! - Session-based: keys can be cached in memory during active session
//! - Automatic lock after timeout
//! - No raw private keys in LocalStorage (only encrypted form)

use crate::memory::{Passphrase, SecretKey};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use web_sys::Storage;

/// Error type for browser keystore operations.
#[derive(Debug, Error)]
pub enum BrowserKeystoreError {
    /// Storage not available.
    #[error("Browser storage not available")]
    StorageUnavailable,

    /// Encryption/decryption error.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Key not found.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Session expired.
    #[error("Session expired")]
    SessionExpired,

    /// Invalid passphrase.
    #[error("Invalid passphrase")]
    InvalidPassphrase,
}

/// Browser keystore using LocalStorage.
pub struct BrowserKeystore {
    storage: Storage,
    session: Option<BrowserSession>,
}

/// Active session with cached keys.
#[derive(Debug)]
pub struct BrowserSession {
    /// Session start time.
    start_time: std::time::Instant,
    /// Session timeout duration.
    timeout: std::time::Duration,
    /// Cached keys (only during active session).
    cached_keys: std::collections::HashMap<String, SecretKey>,
}

impl BrowserSession {
    /// Create new session with 15-minute timeout.
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            timeout: std::time::Duration::from_secs(15 * 60), // 15 minutes
            cached_keys: std::collections::HashMap::new(),
        }
    }

    /// Check if session is still valid.
    pub fn is_valid(&self) -> bool {
        self.start_time.elapsed() < self.timeout
    }

    /// Cache a key for session use.
    pub fn cache_key(&mut self, id: String, key: SecretKey) {
        self.cached_keys.insert(id, key);
    }

    /// Get cached key.
    pub fn get_cached(&self, id: &str) -> Option<&SecretKey> {
        if !self.is_valid() {
            return None;
        }
        self.cached_keys.get(id)
    }

    /// Clear all cached keys.
    pub fn clear(&mut self) {
        self.cached_keys.clear();
    }
}

impl Default for BrowserSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Stored key metadata (stored in LocalStorage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBrowserKey {
    /// Key ID (UUID).
    pub id: String,
    /// Chain this key belongs to.
    pub chain: String,
    /// Encrypted key data (base64).
    pub encrypted_data: String,
    /// Nonce for AES-GCM (base64).
    pub nonce: String,
    /// Salt for key derivation (base64).
    pub salt: String,
    /// Creation timestamp.
    pub created_at: u64,
}

impl BrowserKeystore {
    /// Create new browser keystore.
    pub fn new() -> Result<Self, BrowserKeystoreError> {
        let window = web_sys::window().ok_or(BrowserKeystoreError::StorageUnavailable)?;
        let storage = window
            .local_storage()
            .map_err(|_| BrowserKeystoreError::StorageUnavailable)?
            .ok_or(BrowserKeystoreError::StorageUnavailable)?;

        Ok(Self {
            storage,
            session: None,
        })
    }

    /// Storage key prefix.
    const KEY_PREFIX: &'static str = "csv_keystore_";

    /// Generate storage key.
    fn storage_key(id: &str) -> String {
        format!("{}{}", Self::KEY_PREFIX, id)
    }

    /// Store an encrypted key in LocalStorage.
    pub fn store_key(
        &self,
        id: &str,
        chain: &str,
        secret_key: &SecretKey,
        passphrase: &Passphrase,
    ) -> Result<(), BrowserKeystoreError> {
        // Derive encryption key from passphrase
        let salt = Self::generate_salt()?;
        let derived_key = Self::derive_key(passphrase, &salt);

        // Encrypt the secret key
        let nonce_bytes = Self::generate_nonce()?;
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| BrowserKeystoreError::Crypto(e.to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, secret_key.as_bytes().as_ref())
            .map_err(|e| BrowserKeystoreError::Crypto(e.to_string()))?;

        // Store metadata
        let stored = StoredBrowserKey {
            id: id.to_string(),
            chain: chain.to_string(),
            encrypted_data: general_purpose::STANDARD.encode(&ciphertext),
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            salt: general_purpose::STANDARD.encode(salt),
            created_at: js_sys::Date::now() as u64,
        };

        let json = serde_json::to_string(&stored)?;
        self.storage
            .set_item(&Self::storage_key(id), &json)
            .map_err(|_| BrowserKeystoreError::StorageUnavailable)?;

        Ok(())
    }

    /// Retrieve and decrypt a key from LocalStorage.
    pub fn retrieve_key(
        &mut self,
        id: &str,
        passphrase: &Passphrase,
    ) -> Result<SecretKey, BrowserKeystoreError> {
        // Check session cache first
        if let Some(session) = &self.session {
            if let Some(cached) = session.get_cached(id) {
                // Return copy of cached key (SecretKey doesn't impl Clone, so we recreate)
                let bytes = cached.as_bytes();
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(bytes);
                return Ok(SecretKey::new(key_array));
            }
        }

        // Retrieve from LocalStorage
        let json = self
            .storage
            .get_item(&Self::storage_key(id))
            .map_err(|_| BrowserKeystoreError::StorageUnavailable)?
            .ok_or_else(|| BrowserKeystoreError::KeyNotFound(id.to_string()))?;

        let stored: StoredBrowserKey = serde_json::from_str(&json)?;

        // Decrypt
        let salt = general_purpose::STANDARD
            .decode(&stored.salt)
            .map_err(|e| BrowserKeystoreError::Crypto(e.to_string()))?;
        let derived_key = Self::derive_key(passphrase, &salt);

        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| BrowserKeystoreError::Crypto(e.to_string()))?;

        let nonce_bytes = general_purpose::STANDARD
            .decode(&stored.nonce)
            .map_err(|e| BrowserKeystoreError::Crypto(e.to_string()))?;

        let ciphertext = general_purpose::STANDARD
            .decode(&stored.encrypted_data)
            .map_err(|e| BrowserKeystoreError::Crypto(e.to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| BrowserKeystoreError::InvalidPassphrase)?;

        if plaintext.len() != 32 {
            return Err(BrowserKeystoreError::Crypto(
                "Invalid key length".to_string(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&plaintext);
        let secret_key = SecretKey::new(key_array);

        // Cache in session
        if let Some(session) = &mut self.session {
            let mut key_copy = [0u8; 32];
            key_copy.copy_from_slice(secret_key.as_bytes());
            session.cache_key(id.to_string(), SecretKey::new(key_copy));
        }

        Ok(secret_key)
    }

    /// Start a new session (keys will be cached in memory).
    pub fn start_session(&mut self) {
        self.session = Some(BrowserSession::new());
    }

    /// End session and clear cached keys.
    pub fn end_session(&mut self) {
        if let Some(session) = &mut self.session {
            session.clear();
        }
        self.session = None;
    }

    /// Check if session is active.
    pub fn is_session_active(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.is_valid())
    }

    /// Delete a key from LocalStorage.
    pub fn delete_key(&self, id: &str) -> Result<(), BrowserKeystoreError> {
        self.storage
            .remove_item(&Self::storage_key(id))
            .map_err(|_| BrowserKeystoreError::StorageUnavailable)?;
        Ok(())
    }

    /// List all stored key IDs.
    pub fn list_keys(&self) -> Result<Vec<String>, BrowserKeystoreError> {
        let length = self
            .storage
            .length()
            .map_err(|_| BrowserKeystoreError::StorageUnavailable)?;

        let mut keys = Vec::new();
        for i in 0..length {
            if let Ok(Some(key)) = self.storage.key(i) {
                if let Some(stripped) = key.strip_prefix(Self::KEY_PREFIX) {
                    keys.push(stripped.to_string());
                }
            }
        }

        Ok(keys)
    }

    /// Generate random salt.
    fn generate_salt() -> Result<[u8; 32], BrowserKeystoreError> {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|_| BrowserKeystoreError::Crypto("RNG unavailable".to_string()))?;
        Ok(salt)
    }

    /// Generate random nonce.
    fn generate_nonce() -> Result<[u8; 12], BrowserKeystoreError> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| BrowserKeystoreError::Crypto("RNG unavailable".to_string()))?;
        Ok(nonce)
    }

    /// Derive encryption key using PBKDF2.
    fn derive_key(passphrase: &Passphrase, salt: &[u8]) -> [u8; 32] {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;

        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            passphrase.as_bytes(),
            salt,
            600_000, // iterations
            &mut key,
        );
        key
    }
}

impl Default for BrowserKeystore {
    fn default() -> Self {
        Self::new().expect("Browser storage should be available")
    }
}

/// Cookie-style session token for server-side verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    /// User ID or wallet ID.
    pub wallet_id: String,
    /// Session creation timestamp.
    pub created_at: u64,
    /// Session expiration timestamp.
    pub expires_at: u64,
    /// HMAC signature for integrity.
    pub signature: String,
}

impl SessionToken {
    /// Create new session token.
    pub fn new(wallet_id: &str, duration_secs: u64) -> Self {
        let now = js_sys::Date::now() as u64 / 1000;
        Self {
            wallet_id: wallet_id.to_string(),
            created_at: now,
            expires_at: now + duration_secs,
            signature: String::new(), // Would be signed with server secret
        }
    }

    /// Check if token is valid (not expired).
    pub fn is_valid(&self) -> bool {
        let now = js_sys::Date::now() as u64 / 1000;
        now < self.expires_at
    }

    /// Serialize to cookie-safe string.
    pub fn to_cookie(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_string(self)?;
        Ok(general_purpose::STANDARD.encode(json))
    }

    /// Deserialize from cookie string.
    pub fn from_cookie(cookie: &str) -> Result<Self, BrowserKeystoreError> {
        let json = general_purpose::STANDARD
            .decode(cookie)
            .map_err(|e| BrowserKeystoreError::Crypto(e.to_string()))?;
        let token: SessionToken = serde_json::from_slice(&json)?;
        Ok(token)
    }
}
