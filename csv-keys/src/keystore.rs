//! Encrypted keystore file format (ETH-compatible).
//!
//! This module provides secure key storage using AES-256-GCM encryption
//! with scrypt KDF. Compatible with Ethereum keystore format v3.

use crate::memory::{Iv, Passphrase, SecretKey};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Error type for keystore operations.
#[derive(Debug, Error)]
pub enum KeystoreError {
    /// Encryption failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid keystore format.
    #[error("Invalid keystore format: {0}")]
    InvalidFormat(String),

    /// KDF error.
    #[error("KDF error: {0}")]
    KdfError(String),

    /// File I/O error.
    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Keystore file format v3 (ETH-compatible).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreFile {
    /// Version (3 for current format).
    pub version: u8,

    /// Unique identifier for the keystore.
    pub id: Uuid,

    /// Key derivation function parameters.
    pub crypto: CryptoParams,
}

/// Cryptographic parameters for the keystore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoParams {
    /// Cipher type (always "aes-128-ctr" for v3 compatibility, but we use GCM).
    pub cipher: String,

    /// Encrypted ciphertext (hex encoded).
    pub ciphertext: String,

    /// Cipher parameters.
    pub cipherparams: CipherParams,

    /// KDF type ("scrypt" or "pbkdf2").
    pub kdf: String,

    /// KDF parameters.
    pub kdfparams: KdfParams,

    /// MAC (Message Authentication Code) for integrity verification.
    pub mac: String,
}

/// Cipher parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    /// Initialization vector (hex encoded).
    pub iv: String,
}

/// KDF parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Desired key length in bytes (32 for AES-256).
    pub dklen: u32,

    /// Salt (hex encoded).
    pub salt: String,

    /// Scrypt: N (CPU/memory cost parameter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,

    /// Scrypt: r (block size parameter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<u32>,

    /// Scrypt: p (parallelization parameter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<u32>,

    /// PBKDF2: iteration count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c: Option<u32>,

    /// PBKDF2: PRF (always "hmac-sha256" for our implementation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<String>,
}

impl KeystoreFile {
    /// Encrypt a secret key into a keystore file.
    ///
    /// # Arguments
    /// * `secret_key` - The 32-byte secret key to encrypt
    /// * `passphrase` - The passphrase for encryption
    /// * `kdf_type` - Key derivation function type (Scrypt or Pbkdf2)
    ///
    /// # Example
    /// ```
    /// use csv_keys::keystore::{KeystoreFile, KdfType};
    /// use csv_keys::memory::SecretKey;
    /// use csv_keys::memory::Passphrase;
    ///
    /// let key = SecretKey::random();
    /// let passphrase = Passphrase::new("my secure password");
    /// let keystore = KeystoreFile::encrypt(&key, &passphrase, KdfType::Scrypt).unwrap();
    /// ```
    pub fn encrypt(
        secret_key: &SecretKey,
        passphrase: &Passphrase,
        kdf_type: KdfType,
    ) -> Result<Self, KeystoreError> {
        // Generate random salt
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|e| KeystoreError::EncryptionFailed(format!("RNG failed: {}", e)))?;

        // Generate random IV
        let iv = Iv::random();
        let iv_bytes: [u8; 16] = *iv.as_bytes();

        // Derive encryption key using KDF
        let derived_key = derive_key(passphrase, &salt, &kdf_type)?;

        // Encrypt the secret key using AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&derived_key[..32])
            .map_err(|e| KeystoreError::EncryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&iv_bytes[..12]);
        let plaintext = secret_key.expose_secret();

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| KeystoreError::EncryptionFailed(e.to_string()))?;

        // Calculate MAC (SHA3-256 of derived key + ciphertext)
        let mac = calculate_mac(&derived_key, &ciphertext);

        // Build KDF parameters
        let kdfparams = match kdf_type {
            KdfType::Scrypt => KdfParams {
                dklen: 32,
                salt: hex::encode(salt),
                n: Some(262144), // 2^18
                r: Some(8),
                p: Some(1),
                c: None,
                prf: None,
            },
            KdfType::ScryptTest => KdfParams {
                dklen: 32,
                salt: hex::encode(salt),
                n: Some(1024), // 2^10
                r: Some(8),
                p: Some(1),
                c: None,
                prf: None,
            },
            KdfType::Pbkdf2 => KdfParams {
                dklen: 32,
                salt: hex::encode(salt),
                n: None,
                r: None,
                p: None,
                c: Some(100000),
                prf: Some("hmac-sha256".to_string()),
            },
        };

        let crypto = CryptoParams {
            cipher: "aes-256-gcm".to_string(),
            ciphertext: hex::encode(&ciphertext),
            cipherparams: CipherParams {
                iv: hex::encode(iv_bytes),
            },
            kdf: match kdf_type {
                KdfType::Scrypt => "scrypt",
                KdfType::ScryptTest => "scrypt",
                KdfType::Pbkdf2 => "pbkdf2",
            }
            .to_string(),
            kdfparams,
            mac: hex::encode(mac),
        };

        Ok(Self {
            version: 3,
            id: Uuid::new_v4(),
            crypto,
        })
    }

    /// Decrypt the keystore to recover the secret key.
    ///
    /// # Arguments
    /// * `passphrase` - The passphrase used for encryption
    ///
    /// # Returns
    /// The decrypted 32-byte secret key.
    pub fn decrypt(&self, passphrase: &Passphrase) -> Result<SecretKey, KeystoreError> {
        // Reconstruct KDF parameters
        let salt = hex::decode(&self.crypto.kdfparams.salt)
            .map_err(|e| KeystoreError::InvalidFormat(format!("Invalid salt: {}", e)))?;

        let kdf_type = match self.crypto.kdf.as_str() {
            "scrypt" => {
                // Determine cost from stored N parameter
                let n = self.crypto.kdfparams.n.unwrap_or(262144);
                if n <= 4096 {
                    KdfType::ScryptTest
                } else {
                    KdfType::Scrypt
                }
            }
            "pbkdf2" => KdfType::Pbkdf2,
            _ => return Err(KeystoreError::InvalidFormat("Unknown KDF".to_string())),
        };

        // Derive the same key
        let derived_key = derive_key(passphrase, &salt, &kdf_type)?;

        // Verify MAC
        let ciphertext = hex::decode(&self.crypto.ciphertext)
            .map_err(|e| KeystoreError::InvalidFormat(format!("Invalid ciphertext: {}", e)))?;

        let expected_mac = calculate_mac(&derived_key, &ciphertext);
        let actual_mac = hex::decode(&self.crypto.mac)
            .map_err(|e| KeystoreError::InvalidFormat(format!("Invalid MAC: {}", e)))?;

        if expected_mac != actual_mac.as_slice() {
            return Err(KeystoreError::DecryptionFailed(
                "MAC verification failed - wrong passphrase?".to_string(),
            ));
        }

        // Decrypt
        let iv_bytes = hex::decode(&self.crypto.cipherparams.iv)
            .map_err(|e| KeystoreError::InvalidFormat(format!("Invalid IV: {}", e)))?;

        let cipher = Aes256Gcm::new_from_slice(&derived_key[..32])
            .map_err(|e| KeystoreError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&iv_bytes[..12]);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| KeystoreError::DecryptionFailed(e.to_string()))?;

        if plaintext.len() != 32 {
            return Err(KeystoreError::DecryptionFailed(
                "Decrypted key has wrong length".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&plaintext);

        Ok(SecretKey::new(key_bytes))
    }

    /// Save the keystore to a file.
    pub fn save_to(&self, path: impl AsRef<std::path::Path>) -> Result<(), KeystoreError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;

        // Set restrictive permissions (0o600) for keystore files
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Load a keystore from a file.
    pub fn load_from(path: impl AsRef<std::path::Path>) -> Result<Self, KeystoreError> {
        let json = std::fs::read_to_string(path)?;
        let keystore: Self = serde_json::from_str(&json)?;
        Ok(keystore)
    }

    /// Get the keystore UUID.
    pub fn id(&self) -> Uuid {
        self.id
    }
}

/// Key derivation function type.
#[derive(Debug, Clone, Copy, Default)]
pub enum KdfType {
    /// Scrypt KDF (memory-hard, recommended).
    #[default]
    Scrypt,
    /// Low-cost scrypt for tests (N=1024).
    ScryptTest,
    /// PBKDF2 KDF (NIST standard, faster).
    Pbkdf2,
}

/// Derive an encryption key from passphrase and salt using the specified KDF.
fn derive_key(
    passphrase: &Passphrase,
    salt: &[u8],
    kdf_type: &KdfType,
) -> Result<[u8; 32], KeystoreError> {
    let mut key = [0u8; 32];

    match kdf_type {
        KdfType::Scrypt => {
            let params = scrypt::Params::new(
                18, // log2(N) = 18 => N = 262144
                8,  // r
                1,  // p
                32, // key length
            )
            .map_err(|e| KeystoreError::KdfError(e.to_string()))?;

            scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut key)
                .map_err(|e| KeystoreError::KdfError(e.to_string()))?;
        }
        KdfType::ScryptTest => {
            let params = scrypt::Params::new(
                10, // log2(N) = 10 => N = 1024
                8,  // r
                1,  // p
                32, // key length
            )
            .map_err(|e| KeystoreError::KdfError(e.to_string()))?;

            scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut key)
                .map_err(|e| KeystoreError::KdfError(e.to_string()))?;
        }
        KdfType::Pbkdf2 => {
            use pbkdf2::pbkdf2_hmac;
            use sha2::Sha256;

            pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, 100000, &mut key);
        }
    }

    Ok(key)
}

/// Calculate MAC (SHA3-256 of derived_key + ciphertext).
fn calculate_mac(derived_key: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(derived_key);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

/// Create a new keystore with random key.
pub fn create_keystore(
    passphrase: &Passphrase,
) -> Result<(KeystoreFile, SecretKey), KeystoreError> {
    let key = SecretKey::random();
    let keystore = KeystoreFile::encrypt(&key, passphrase, KdfType::default())?;
    Ok((keystore, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_encrypt_decrypt() {
        let key = SecretKey::random();
        let passphrase = Passphrase::new("test password");

        let keystore = KeystoreFile::encrypt(&key, &passphrase, KdfType::Scrypt).unwrap();
        let decrypted = keystore.decrypt(&passphrase).unwrap();

        assert_eq!(key.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let key = SecretKey::random();
        let passphrase = Passphrase::new("correct password");

        let keystore = KeystoreFile::encrypt(&key, &passphrase, KdfType::Scrypt).unwrap();

        let wrong_passphrase = Passphrase::new("wrong password");
        let result = keystore.decrypt(&wrong_passphrase);

        assert!(result.is_err());
    }

    #[test]
    fn test_save_load() {
        let key = SecretKey::random();
        let passphrase = Passphrase::new("save test");

        let keystore = KeystoreFile::encrypt(&key, &passphrase, KdfType::Scrypt).unwrap();

        let temp_file = NamedTempFile::new().unwrap();
        keystore.save_to(temp_file.path()).unwrap();

        let loaded = KeystoreFile::load_from(temp_file.path()).unwrap();
        let decrypted = loaded.decrypt(&passphrase).unwrap();

        assert_eq!(key.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_create_keystore() {
        let passphrase = Passphrase::new("create test");
        let (keystore, key) = create_keystore(&passphrase).unwrap();

        let decrypted = keystore.decrypt(&passphrase).unwrap();
        assert_eq!(key.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_pbkdf2() {
        let key = SecretKey::random();
        let passphrase = Passphrase::new("pbkdf2 test");

        let keystore = KeystoreFile::encrypt(&key, &passphrase, KdfType::Pbkdf2).unwrap();
        let decrypted = keystore.decrypt(&passphrase).unwrap();

        assert_eq!(key.as_bytes(), decrypted.as_bytes());
    }
}
