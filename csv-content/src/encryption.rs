//! Encryption envelope for content subtrees
//!
//! Provides the envelope and descriptor **types** for sensitive content in
//! Sanads. This module performs no cryptography: it describes how a subtree was
//! encrypted (`algorithm`, `key_id`, `nonce`, `aad`) and carries the resulting
//! `ciphertext` / `tag`. The AES-256-GCM operations for this path currently live
//! in `csv-cli/src/commands/content.rs`, which takes a raw 32-byte key with no
//! key-derivation function.
//!
//! # Not to be confused with `csv_store::encrypted_storage` (STORE-ENCRYPTION-DEDUP-001)
//!
//! `csv-store`'s encrypted storage is a separate, browser-only (wasm32) at-rest
//! layer for IndexedDB. It derives its key from a user password via
//! PBKDF2-HMAC-SHA256 and adds an HMAC-SHA256 tag on top of the AEAD tag. The
//! two have different key handling and different authentication models; they are
//! not alternatives for one another. Do not route this module's types through
//! that implementation, or vice versa.

use serde::{Deserialize, Serialize};

/// Encryption descriptor
///
/// Describes how content is encrypted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionDescriptor {
    /// Encryption algorithm (e.g., "AES-256-GCM", "XChaCha20-Poly1305")
    pub algorithm: String,
    /// Key identifier (references a key management system)
    pub key_id: String,
    /// Nonce for the encryption
    pub nonce: Vec<u8>,
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
}

impl EncryptionDescriptor {
    /// Create a new encryption descriptor
    pub fn new(algorithm: String, key_id: String, nonce: Vec<u8>) -> Self {
        Self {
            algorithm,
            key_id,
            nonce,
            aad: None,
        }
    }

    /// Set additional authenticated data
    pub fn with_aad(mut self, aad: Vec<u8>) -> Self {
        self.aad = Some(aad);
        self
    }
}

/// Encryption envelope
///
/// Wraps encrypted content with metadata needed for decryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionEnvelope {
    /// Encryption descriptor
    pub descriptor: EncryptionDescriptor,
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Authentication tag (for AEAD modes)
    pub tag: Vec<u8>,
}

impl EncryptionEnvelope {
    /// Create a new encryption envelope
    pub fn new(descriptor: EncryptionDescriptor, ciphertext: Vec<u8>, tag: Vec<u8>) -> Self {
        Self {
            descriptor,
            ciphertext,
            tag,
        }
    }

    /// Get the total size of the encrypted data
    pub fn size(&self) -> usize {
        self.ciphertext.len() + self.tag.len()
    }
}

/// Key access control
///
/// Defines who can access decryption keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAccess {
    /// Public key encryption (anyone with public key can encrypt)
    Public {
        /// Public key identifier
        key_id: String,
    },
    /// Symmetric key (requires pre-shared secret)
    Symmetric {
        /// Key identifier
        key_id: String,
    },
    /// Threshold encryption (requires N of M keys)
    Threshold {
        /// Required threshold
        threshold: u8,
        /// Total key shares
        total_shares: u8,
        /// Key identifiers
        key_ids: Vec<String>,
    },
    /// Time-locked encryption (key available after timestamp)
    TimeLocked {
        /// Unix timestamp when key becomes available
        available_at: u64,
        /// Key identifier
        key_id: String,
    },
}
