//! CSV Adapter Keystore — Secure key storage with BIP-39/BIP-44 support.
#![allow(clippy::collapsible_if)]
//!
//! This crate provides secure cryptographic key management for the CSV Adapter,
//! implementing industry standards:
//!
//! - **BIP-39**: Mnemonic phrase generation and recovery
//! - **BIP-44**: Hierarchical deterministic (HD) wallet derivation
//! - **ETH Keystore v3**: AES-256-GCM encrypted key storage
//!
//! # Security Features
//!
//! - Memory-safe key types with automatic zeroization on drop
//! - Scrypt/Argon2 KDF for passphrase-to-key derivation
//! - AES-256-GCM authenticated encryption
//! - UUID-based keystore identification
//!
//! # Quick Start
//!
//! ```no_run
//! use csv_keys::{
//!     bip39::{Mnemonic, MnemonicType},
//!     bip44::derive_key,
//!     keystore::{KeystoreFile, create_keystore},
//!     memory::{SecretKey, Passphrase},
//! };
//! use csv_hash::ChainId;
//!
//! // Generate a 24-word mnemonic
//! let mnemonic = Mnemonic::generate(MnemonicType::Words24);
//! println!("Backup phrase: {}", mnemonic.as_str());
//!
//! // Convert to seed
//! let seed = mnemonic.to_seed(None);
//!
//! // Derive Ethereum key
//! let eth_key = derive_key(seed.as_bytes(), &ChainId::new("ethereum"), 0, 0).unwrap();
//!
//! // Encrypt and save
//! let passphrase = Passphrase::new("secure password");
//! let keystore = KeystoreFile::encrypt(&eth_key, &passphrase, csv_keys::keystore::KdfType::Scrypt).unwrap();
//! keystore.save_to("/path/to/keystore.json").unwrap();
//! ```

#![warn(missing_docs)]
#![allow(unexpected_cfgs)]

pub mod bip39;
pub mod bip44;
#[cfg(feature = "wasm")]
pub mod browser_keystore;
pub mod file_keystore;
pub mod keystore;
pub mod memory;

// Re-export commonly used types
pub use bip39::{Mnemonic, MnemonicType};
pub use bip44::{DerivationPath, derivation_path, derive_key};
pub use keystore::{KdfType, KeystoreFile, create_keystore};
pub use memory::{Iv, Nonce, Passphrase, SecretKey, Seed};

/// Version of the csv-adapter-keystore crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use thiserror::Error;

/// Unified error type for keystore operations.
#[derive(Debug, Error)]
pub enum KeystoreError {
    /// BIP-39 mnemonic error.
    #[error("BIP-39 error: {0}")]
    Bip39(#[from] bip39::Bip39Error),

    /// BIP-44 derivation error.
    #[error("BIP-44 error: {0}")]
    Bip44(#[from] bip44::Bip44Error),

    /// Keystore encryption/decryption error.
    #[error("Keystore error: {0}")]
    Keystore(#[from] keystore::KeystoreError),

    /// Memory/security error.
    #[error("Security error: {0}")]
    Security(String),
}

/// Create a complete wallet from a new mnemonic.
///
/// This generates:
/// - A new 24-word mnemonic
/// - Master seed
/// - Keys for all supported chains
/// - Encrypted keystores
///
/// # Arguments
/// * `passphrase` - Passphrase for encrypting the keystores
///
/// # Returns
/// Tuple of (mnemonic phrase, vector of (chain, keystore_file))
pub fn create_full_wallet(
    encryption_passphrase: &Passphrase,
) -> Result<(String, Vec<(csv_hash::chain_id::ChainId, KeystoreFile)>), KeystoreError> {
    use csv_hash::chain_id::ChainId;

    // Generate mnemonic
    let mnemonic = Mnemonic::generate(MnemonicType::Words24);
    let phrase = mnemonic.as_str().to_string();

    // Convert to seed
    let seed = mnemonic.to_seed(None);

    // Generate keys for each chain
    let mut keystores = Vec::new();
    for chain in [
        ChainId::new("bitcoin"),
        ChainId::new("ethereum"),
        ChainId::new("sui"),
        ChainId::new("aptos"),
        ChainId::new("solana"),
    ] {
        let key = derive_key(seed.as_bytes(), &chain, 0, 0).map_err(KeystoreError::Bip44)?;
        let keystore = KeystoreFile::encrypt(&key, encryption_passphrase, KdfType::ScryptTest)
            .map_err(KeystoreError::Keystore)?;
        keystores.push((chain, keystore));
    }

    Ok((phrase, keystores))
}

/// Restore a wallet from a mnemonic phrase.
///
/// # Arguments
/// * `phrase` - The mnemonic phrase (space-separated words)
/// * `passphrase` - Optional BIP-39 passphrase (not the encryption passphrase)
///
/// # Returns
/// The master seed for HD derivation
pub fn restore_from_mnemonic(
    phrase: &str,
    passphrase: Option<&str>,
) -> Result<Seed, KeystoreError> {
    let mnemonic = Mnemonic::from_phrase(phrase).map_err(KeystoreError::Bip39)?;
    Ok(mnemonic.to_seed(passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_full_wallet() {
        let passphrase = Passphrase::new("test wallet password");
        let (phrase, keystores) = create_full_wallet(&passphrase).unwrap();

        assert!(!phrase.is_empty());
        assert_eq!(keystores.len(), 5); // 5 chains

        // Verify we can decrypt each keystore
        for (_chain, keystore) in keystores {
            let decrypted = keystore.decrypt(&passphrase).unwrap();
            assert_eq!(decrypted.as_bytes().len(), 32);
        }
    }

    #[test]
    fn test_restore_from_mnemonic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = restore_from_mnemonic(phrase, None).unwrap();
        assert_eq!(seed.as_bytes().len(), 64);
    }
}
