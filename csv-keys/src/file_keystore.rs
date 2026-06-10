//! Filesystem-based keystore for non-WASM targets (csv-cli).
//!
//! This module provides secure key storage using AES-256-GCM encryption
//! with scrypt KDF. Keys are stored as individual encrypted JSON files
//! in a dedicated keystore directory.
//!
//! # Security Model
//!
//! - Keys are encrypted with user passphrase before storage on disk
//! - Each key is stored as a separate ETH-compatible keystore file
//! - Session-based: keys can be cached in memory during active session
//! - Automatic lock after timeout
//! - No raw private keys on disk (only encrypted form)
//!
//! # Directory Structure
//!
//! ```text
//! ~/.csv/keystore/
//!   ├── meta.json          # Keystore metadata (key IDs, chains, timestamps)
//!   └── keystore-<uuid>.json  # Individual encrypted key files
//! ```

use crate::keystore::{KdfType, KeystoreFile};
use crate::memory::{Passphrase, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Error type for file keystore operations.
#[derive(Debug, Error)]
pub enum FileKeystoreError {
    /// Keystore directory not found.
    #[error("Keystore directory not found: {0}")]
    DirectoryNotFound(String),

    /// Encryption/decryption error.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// File I/O error.
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),

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
    #[error("Invalid passphrase - decryption failed")]
    InvalidPassphrase,

    /// Invalid keystore format.
    #[error("Invalid keystore format: {0}")]
    InvalidFormat(String),

    /// Keystore encryption/decryption error.
    #[error("Keystore error: {0}")]
    Keystore(#[from] crate::keystore::KeystoreError),
}

/// File keystore using encrypted JSON files on disk.
pub struct FileKeystore {
    /// Path to the keystore directory.
    keystore_dir: std::path::PathBuf,
    /// Session with cached keys.
    session: Option<FileSession>,
    /// Keystore metadata (key registry).
    meta: KeystoreMeta,
}

/// Active session with cached keys.
#[derive(Debug)]
pub struct FileSession {
    /// Session start time.
    start_time: std::time::Instant,
    /// Session timeout duration.
    timeout: std::time::Duration,
    /// Cached keys (only during active session).
    cached_keys: std::collections::HashMap<String, SecretKey>,
}

impl FileSession {
    /// Create new session with 15-minute timeout.
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            timeout: std::time::Duration::from_secs(15 * 60),
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

impl Default for FileSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Keystore metadata file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreMeta {
    /// Version of the keystore format.
    pub version: u32,
    /// Registry of stored keys.
    #[serde(default)]
    pub keys: Vec<KeyEntry>,
}

impl Default for KeystoreMeta {
    fn default() -> Self {
        Self {
            version: 1,
            keys: Vec::new(),
        }
    }
}

/// Entry in the keystore metadata registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Unique key ID.
    pub id: String,
    /// Chain this key belongs to.
    pub chain: String,
    /// Human-readable label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// File keystore creation timestamp.
    pub created_at: u64,
    /// UUID of the keystore file.
    pub file_id: String,
}

impl KeystoreMeta {
    /// Add a key entry to the registry.
    pub fn add_key(&mut self, id: String, chain: String, label: Option<String>, file_id: String) {
        self.keys.push(KeyEntry {
            id: id.clone(),
            chain,
            label,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            file_id,
        });
    }

    /// Find a key entry by ID.
    pub fn find(&self, id: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.id == id)
    }

    /// Remove a key entry by ID.
    pub fn remove(&mut self, id: &str) -> bool {
        let len = self.keys.len();
        self.keys.retain(|k| k.id != id);
        self.keys.len() < len
    }
}

impl FileKeystore {
    /// Default keystore directory path.
    pub const DEFAULT_DIR: &'static str = "~/.csv/keystore";

    /// Metadata file name.
    const META_FILE: &'static str = "meta.json";

    /// Create a new file keystore, initializing the directory if needed.
    ///
    /// # Arguments
    /// * `keystore_dir` - Path to the keystore directory (default: ~/.csv/keystore)
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(keystore_dir: Option<&str>) -> Result<Self, FileKeystoreError> {
        let dir = match keystore_dir {
            Some(path) => {
                let mut p = std::path::PathBuf::from(path);
                if p.is_relative() {
                    p = dirs::home_dir()
                        .map(|h| h.join(".."))
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("/"))
                        .join(path.trim_start_matches('~'));
                }
                p
            }
            None => {
                let home = dirs::home_dir().ok_or(FileKeystoreError::DirectoryNotFound(
                    "Home directory not found".to_string(),
                ))?;

                home.join(".csv/keystore")
            }
        };

        // Expand ~ in path
        let dir = expand_tilde(&dir);

        // Create directory if it doesn't exist with restrictive permissions (0o700)
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }

        // Load or create metadata
        let meta_path = dir.join(Self::META_FILE);
        let meta = if meta_path.exists() {
            let json = std::fs::read_to_string(&meta_path)?;
            serde_json::from_str(&json)?
        } else {
            KeystoreMeta::default()
        };

        Ok(Self {
            keystore_dir: dir,
            session: None,
            meta,
        })
    }

    /// Create a new file keystore with a custom directory.
    ///
    /// On wasm32, this uses the provided path directly without home directory resolution.
    #[cfg(target_arch = "wasm32")]
    pub fn new(keystore_dir: Option<&str>) -> Result<Self, FileKeystoreError> {
        let dir = match keystore_dir {
            Some(path) => std::path::PathBuf::from(path),
            None => std::path::PathBuf::from(".csv/keystore"),
        };
        Self::with_dir(dir)
    }

    /// Create a new file keystore with a custom directory.
    pub fn with_dir(dir: impl AsRef<std::path::Path>) -> Result<Self, FileKeystoreError> {
        let dir = expand_tilde(dir.as_ref());
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let meta_path = dir.join(Self::META_FILE);
        let meta = if meta_path.exists() {
            let json = std::fs::read_to_string(&meta_path)?;
            serde_json::from_str(&json)?
        } else {
            KeystoreMeta::default()
        };

        Ok(Self {
            keystore_dir: dir,
            session: None,
            meta,
        })
    }

    /// Store an encrypted key.
    ///
    /// # Arguments
    /// * `id` - Unique key identifier
    /// * `chain` - Chain name (e.g., "bitcoin", "ethereum")
    /// * `label` - Human-readable label (optional)
    /// * `secret_key` - The 32-byte secret key to encrypt
    /// * `passphrase` - The passphrase for encryption
    pub fn store_key(
        &mut self,
        id: &str,
        chain: &str,
        label: Option<&str>,
        secret_key: &SecretKey,
        passphrase: &Passphrase,
    ) -> Result<(), FileKeystoreError> {
        // Encrypt the key using KeystoreFile
        let keystore = KeystoreFile::encrypt(secret_key, passphrase, KdfType::Scrypt)?;

        // Get the file ID from the keystore
        let file_id = keystore.id().to_string();

        // Save to file
        let file_path = self.keystore_dir.join(format!("keystore-{}.json", file_id));
        keystore.save_to(&file_path)?;

        // Update metadata
        self.meta.add_key(
            id.to_string(),
            chain.to_string(),
            label.map(String::from),
            file_id,
        );

        // Save metadata
        let meta_path = self.keystore_dir.join(Self::META_FILE);
        let meta_json = serde_json::to_string_pretty(&self.meta)?;
        std::fs::write(&meta_path, meta_json)?;

        Ok(())
    }

    /// Retrieve and decrypt a key.
    ///
    /// # Arguments
    /// * `id` - Key identifier
    /// * `passphrase` - The passphrase for decryption
    pub fn retrieve_key(
        &mut self,
        id: &str,
        passphrase: &Passphrase,
    ) -> Result<SecretKey, FileKeystoreError> {
        // Check session cache first
        if let Some(session) = &self.session {
            if let Some(cached) = session.get_cached(id) {
                let bytes = cached.expose_secret();
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(bytes);
                return Ok(SecretKey::new(key_array));
            }
        }

        // Find the keystore file from metadata
        let _entry = self
            .meta
            .find(id)
            .ok_or_else(|| FileKeystoreError::KeyNotFound(id.to_string()))?;

        // Try to find the keystore file by matching the entry
        // Since we store by UUID but look up by ID, we need to search
        let keystore_file = self.find_keystore_file_for_id(id)?;

        // Load and decrypt
        let keystore = KeystoreFile::load_from(&keystore_file)?;
        let secret_key = keystore.decrypt(passphrase).map_err(|e| {
            if e.to_string().contains("MAC verification failed") {
                FileKeystoreError::InvalidPassphrase
            } else {
                FileKeystoreError::Crypto(e.to_string())
            }
        })?;

        // Cache in session
        if let Some(session) = &mut self.session {
            let mut key_copy = [0u8; 32];
            key_copy.copy_from_slice(secret_key.expose_secret());
            session.cache_key(id.to_string(), SecretKey::new(key_copy));
        }

        Ok(secret_key)
    }

    /// Find the keystore file path for a given key ID.
    fn find_keystore_file_for_id(&self, id: &str) -> Result<std::path::PathBuf, FileKeystoreError> {
        // Find the entry in metadata
        let entry = self
            .meta
            .find(id)
            .ok_or_else(|| FileKeystoreError::KeyNotFound(id.to_string()))?;

        // Construct the file path from the file_id
        let file_path = self
            .keystore_dir
            .join(format!("keystore-{}.json", entry.file_id));
        Ok(file_path)
    }

    /// Start a new session (keys will be cached in memory).
    pub fn start_session(&mut self) {
        self.session = Some(FileSession::new());
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

    /// Delete a key from the keystore.
    ///
    /// # Arguments
    /// * `id` - Key identifier
    pub fn delete_key(&mut self, id: &str) -> Result<(), FileKeystoreError> {
        // Find and delete the keystore file
        if let Ok(file_path) = self.find_keystore_file_for_id(id) {
            std::fs::remove_file(&file_path)?;
        }

        // Remove from metadata
        self.meta.remove(id);

        // Save metadata
        let meta_path = self.keystore_dir.join(Self::META_FILE);
        let meta_json = serde_json::to_string_pretty(&self.meta)?;
        std::fs::write(&meta_path, meta_json)?;

        Ok(())
    }

    /// List all stored key IDs.
    pub fn list_keys(&self) -> Vec<String> {
        self.meta.keys.iter().map(|k| k.id.clone()).collect()
    }

    /// Get metadata for all keys.
    pub fn list_key_entries(&self) -> &[KeyEntry] {
        &self.meta.keys
    }

    /// Get the keystore directory path.
    pub fn keystore_dir(&self) -> &std::path::Path {
        &self.keystore_dir
    }

    /// Export a key as an encrypted keystore file (for backup/export).
    pub fn export_key(
        &self,
        id: &str,
        _passphrase: &Passphrase,
    ) -> Result<KeystoreFile, FileKeystoreError> {
        let keystore_file = self.find_keystore_file_for_id(id)?;
        KeystoreFile::load_from(&keystore_file).map_err(FileKeystoreError::from)
    }

    /// Import an encrypted keystore file.
    ///
    /// # Arguments
    /// * `keystore` - The keystore file to import
    /// * `chain` - Chain name
    /// * `label` - Human-readable label
    pub fn import_key(
        &mut self,
        keystore: &KeystoreFile,
        chain: &str,
        label: Option<&str>,
    ) -> Result<String, FileKeystoreError> {
        let id = keystore.id().to_string();
        let file_path = self.keystore_dir.join(format!("keystore-{}.json", id));
        keystore.save_to(&file_path)?;

        self.meta.add_key(
            id.clone(),
            chain.to_string(),
            label.map(String::from),
            id.clone(),
        );

        let meta_path = self.keystore_dir.join(Self::META_FILE);
        let meta_json = serde_json::to_string_pretty(&self.meta)?;
        std::fs::write(&meta_path, meta_json)?;

        Ok(id)
    }

    /// Verify a passphrase by attempting to decrypt a key.
    pub fn verify_passphrase(
        &self,
        id: &str,
        passphrase: &Passphrase,
    ) -> Result<(), FileKeystoreError> {
        let keystore_file = self.find_keystore_file_for_id(id)?;
        let keystore = KeystoreFile::load_from(&keystore_file)?;
        keystore.decrypt(passphrase).map_err(|e| {
            if e.to_string().contains("MAC verification failed") {
                FileKeystoreError::InvalidPassphrase
            } else {
                FileKeystoreError::Crypto(e.to_string())
            }
        })?;
        Ok(())
    }
}

/// Expand ~ to home directory in a path.
#[cfg(not(target_arch = "wasm32"))]
fn expand_tilde(path: &std::path::Path) -> std::path::PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with("~/") || s == "~" {
        if let Some(home) = dirs::home_dir() {
            let rest = s.strip_prefix("~").unwrap_or("");
            return home.join(rest.trim_start_matches('/'));
        }
    }
    path.to_path_buf()
}

/// Expand ~ to home directory in a path.
/// On wasm32, this is a no-op since we don't have access to the home directory.
#[cfg(target_arch = "wasm32")]
fn expand_tilde(path: &std::path::Path) -> std::path::PathBuf {
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_keystore_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn test_store_and_retrieve_key() {
        let dir = temp_keystore_dir();
        let mut ks = FileKeystore::with_dir(dir.path()).unwrap();
        let key = SecretKey::random();
        let passphrase = Passphrase::new("test password");

        ks.store_key(
            "test-key",
            "ethereum",
            Some("Test ETH Key"),
            &key,
            &passphrase,
        )
        .unwrap();

        let retrieved = ks.retrieve_key("test-key", &passphrase).unwrap();
        assert_eq!(key.as_bytes(), retrieved.as_bytes());
    }

    #[test]
    fn test_wrong_passphrase() {
        let dir = temp_keystore_dir();
        let mut ks = FileKeystore::with_dir(dir.path()).unwrap();
        let key = SecretKey::random();
        let correct = Passphrase::new("correct");
        let wrong = Passphrase::new("wrong");

        ks.store_key("test-key", "bitcoin", None, &key, &correct)
            .unwrap();

        let result = ks.retrieve_key("test-key", &wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_keys() {
        let dir = temp_keystore_dir();
        let mut ks = FileKeystore::with_dir(dir.path()).unwrap();
        let key = SecretKey::random();
        let passphrase = Passphrase::new("test");

        ks.store_key("key-1", "ethereum", None, &key, &passphrase)
            .unwrap();
        ks.store_key("key-2", "solana", None, &key, &passphrase)
            .unwrap();

        let keys = ks.list_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key-1".to_string()));
        assert!(keys.contains(&"key-2".to_string()));
    }

    #[test]
    fn test_delete_key() {
        let dir = temp_keystore_dir();
        let mut ks = FileKeystore::with_dir(dir.path()).unwrap();
        let key = SecretKey::random();
        let passphrase = Passphrase::new("test");

        ks.store_key("key-1", "ethereum", None, &key, &passphrase)
            .unwrap();
        assert_eq!(ks.list_keys().len(), 1);

        ks.delete_key("key-1").unwrap();
        assert_eq!(ks.list_keys().len(), 0);
    }

    #[test]
    fn test_session_caching() {
        let dir = temp_keystore_dir();
        let mut ks = FileKeystore::with_dir(dir.path()).unwrap();
        let key = SecretKey::random();
        let passphrase = Passphrase::new("test");

        ks.store_key("key-1", "ethereum", None, &key, &passphrase)
            .unwrap();

        ks.start_session();
        let retrieved1 = ks.retrieve_key("key-1", &passphrase).unwrap();
        let retrieved2 = ks.retrieve_key("key-1", &passphrase).unwrap();
        assert_eq!(key.as_bytes(), retrieved1.as_bytes());
        assert_eq!(key.as_bytes(), retrieved2.as_bytes());
    }

    #[test]
    fn test_export_import() {
        let dir1 = temp_keystore_dir();
        let dir2 = temp_keystore_dir();
        let mut ks1 = FileKeystore::with_dir(&dir1).unwrap();
        let mut ks2 = FileKeystore::with_dir(&dir2).unwrap();
        let key = SecretKey::random();
        let passphrase = Passphrase::new("test");

        ks1.store_key("key-1", "ethereum", Some("Export Test"), &key, &passphrase)
            .unwrap();

        let exported = ks1.export_key("key-1", &passphrase).unwrap();
        ks2.import_key(&exported, "ethereum", Some("Imported"))
            .unwrap();

        let retrieved = ks2
            .retrieve_key(&exported.id().to_string(), &passphrase)
            .unwrap();
        assert_eq!(key.as_bytes(), retrieved.as_bytes());
    }
}
