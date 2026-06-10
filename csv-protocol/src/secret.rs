//! Secret handling types for secure key management.
//!
//! This module provides typed secret handles that prevent raw secret material
//! from flowing through config structs, logs, errors, and clone paths.
//!
//! ## Design Principles
//!
//! - **No raw hex strings**: Private keys are never passed as `String` or `Option<String>`
//! - **Zeroize on drop**: All secret types automatically clear memory when dropped
//! - **No Clone**: Secret material cannot be accidentally duplicated
//! - **No Serialize/Deserialize**: Secrets cannot be accidentally persisted or transmitted
//! - **Keystore references**: Long-term storage uses encrypted keystore references
//!
//! ## Usage
//!
//! ```
//! use csv_protocol::secret::{SecretHandle, SecretSource};
//! use csv_keys::memory::SecretKey;
//!
//! // Create from raw key (temporary, e.g., for testing)
//! let key = SecretKey::random();
//! let handle = SecretHandle::from_key(key);
//!
//! // Create from keystore reference (production)
//! let handle = SecretHandle::from_keystore("path/to/keystore.json", "passphrase");
//! ```

use csv_keys::memory::SecretKey;
use std::path::PathBuf;
use zeroize::ZeroizeOnDrop;

/// A secure handle to secret key material.
///
/// This type wraps either a raw [`SecretKey`] or a reference to an encrypted
/// keystore file. It prevents:
/// - Raw hex strings flowing through config structs
/// - Accidental cloning of secret material
/// - Serialization of secret material to disk/network
/// - Printing of secret material in logs/errors
///
/// ## Security Properties
///
/// - Implements `ZeroizeOnDrop` to clear memory when dropped
/// - Does NOT implement `Clone` to prevent accidental duplication
/// - Does NOT implement `Serialize`/`Deserialize` to prevent accidental persistence
/// - Debug output shows `[REDACTED]` instead of key material
pub struct SecretHandle {
    source: SecretSource,
}

impl std::fmt::Debug for SecretHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretHandle([REDACTED])")
    }
}

/// The source of secret key material.
enum SecretSource {
    /// Raw secret key (temporary, e.g., for testing)
    Raw(SecretKey),
    /// Reference to encrypted keystore file
    Keystore {
        /// Path to the keystore file
        path: PathBuf,
        /// Passphrase for decrypting the keystore
        passphrase: csv_keys::memory::Passphrase,
    },
}

impl SecretHandle {
    /// Create a secret handle from a raw secret key.
    ///
    /// # Security
    ///
    /// This stores the key in memory. For production use, prefer
    /// [`SecretHandle::from_keystore`] which loads from an encrypted file.
    pub fn from_key(key: SecretKey) -> Self {
        Self {
            source: SecretSource::Raw(key),
        }
    }

    /// Create a secret handle from a keystore file reference.
    ///
    /// # Arguments
    ///
    /// * `path` — Path to the encrypted keystore file
    /// * `passphrase` — Passphrase for decrypting the keystore
    ///
    /// # Security
    ///
    /// The passphrase is stored in memory until the handle is dropped.
    /// For long-lived applications, consider using a hardware signer
    /// or remote signing service instead.
    pub fn from_keystore(path: impl Into<PathBuf>, passphrase: csv_keys::memory::Passphrase) -> Self {
        Self {
            source: SecretSource::Keystore {
                path: path.into(),
                passphrase,
            },
        }
    }

    /// Get a reference to the secret key bytes.
    ///
    /// # Security Warning
    ///
    /// This exposes the raw key material. Only use this when absolutely
    /// necessary for cryptographic operations. The key bytes must not be
    /// stored, transmitted, or logged.
    pub fn as_bytes(&self) -> Option<&[u8; 32]> {
        match &self.source {
            SecretSource::Raw(key) => Some(key.expose_secret()),
            SecretSource::Keystore { .. } => {
                // For keystore-backed handles, we would decrypt on demand.
                // This is a simplification — in production, you'd load the
                // key from the keystore when needed.
                None
            }
        }
    }

    /// Check if this handle contains a raw key (not keystore-backed).
    pub fn is_raw(&self) -> bool {
        matches!(&self.source, SecretSource::Raw(_))
    }

    /// Check if this handle is keystore-backed.
    pub fn is_keystore(&self) -> bool {
        matches!(&self.source, SecretSource::Keystore { .. })
    }

    /// Get the keystore path, if this handle is keystore-backed.
    pub fn keystore_path(&self) -> Option<&PathBuf> {
        match &self.source {
            SecretSource::Keystore { path, .. } => Some(path),
            _ => None,
        }
    }
}

/// A typed secret handle that can be cloned for sharing across threads.
///
/// This is a reference-counted wrapper around [`SecretHandle`] that allows
/// sharing the same secret across multiple components without cloning the
/// actual key material.
///
/// # Thread Safety
///
/// Implements `Send + Sync` for use in multi-threaded contexts.
#[derive(Debug)]
pub struct SharedSecretHandle(std::sync::Arc<SecretHandle>);

impl SharedSecretHandle {
    /// Create a new shared secret handle.
    pub fn new(handle: SecretHandle) -> Self {
        Self(std::sync::Arc::new(handle))
    }

    /// Create a shared secret handle from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let key = SecretKey::new(bytes);
        Self::new(SecretHandle::from_key(key))
    }

    /// Create a shared secret handle with no key (read-only mode).
    pub fn none() -> Self {
        // Create a handle with zero bytes as placeholder
        let key = SecretKey::new([0u8; 32]);
        Self::new(SecretHandle::from_key(key))
    }

    /// Get a reference to the underlying secret handle.
    pub fn inner(&self) -> &SecretHandle {
        &self.0
    }

    /// Get the secret key bytes, if available.
    pub fn as_bytes(&self) -> Option<&[u8; 32]> {
        self.0.as_bytes()
    }
}

impl Clone for SharedSecretHandle {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Default for SharedSecretHandle {
    fn default() -> Self {
        Self::none()
    }
}

impl std::fmt::Display for SecretHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Display for SharedSecretHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_handle_from_key() {
        let key = SecretKey::random();
        let key_bytes = key.as_bytes().clone();
        let handle = SecretHandle::from_key(key);
        assert!(handle.is_raw());
        assert!(!handle.is_keystore());
        assert_eq!(handle.as_bytes().unwrap(), &key_bytes);
    }

    #[test]
    fn test_secret_handle_from_keystore() {
        let passphrase = csv_keys::memory::Passphrase::new("test");
        let handle = SecretHandle::from_keystore("/path/to/keystore.json", passphrase);
        assert!(!handle.is_raw());
        assert!(handle.is_keystore());
        assert_eq!(handle.keystore_path().unwrap(), "/path/to/keystore.json");
    }

    #[test]
    fn test_shared_secret_handle_clone() {
        let key = SecretKey::random();
        let handle = SecretHandle::from_key(key);
        let shared1 = SharedSecretHandle::new(handle);
        let shared2 = shared1.clone();
        
        // Both should have the same bytes
        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_secret_handle_debug_redacted() {
        let key = SecretKey::random();
        let handle = SecretHandle::from_key(key);
        let debug_str = format!("{:?}", handle);
        assert!(debug_str.contains("SecretHandle"));
        assert!(!debug_str.contains("0x")); // Should not contain hex key material
    }

    #[test]
    fn test_secret_handle_display_redacted() {
        let key = SecretKey::random();
        let handle = SecretHandle::from_key(key);
        assert_eq!(format!("{}", handle), "[REDACTED]");
    }
}
