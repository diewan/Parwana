//! State file encryption using AES-256-GCM + Argon2id key derivation.
//!
//! The state file is encrypted before writing to disk and decrypted when loaded.
//! The user passphrase is used to derive an encryption key via Argon2id with
//! memory-hard parameters resistant to GPU/ASIC attacks.
//!
//! # File Format
//!
//! ```text
//! {
//!   "v": 1,
//!   "s": "<base64 salt (16 bytes)>",
//!   "n": "<base64 nonce (12 bytes)>",
//!   "d": "<base64 ciphertext + auth tag>"
//! }
//! ```

use aead::{Aead, AeadCore, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::aes::cipher::generic_array::GenericArray;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, PasswordHasher, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Encrypted state file format.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedState {
    pub v: u32,
    s: String, // base64 salt
    n: String, // base64 nonce
    d: String, // base64 ciphertext + tag
}

/// Encrypt plaintext JSON into an EncryptedState.
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> anyhow::Result<EncryptedState> {
    let salt = generate_salt();
    let key = derive_key(passphrase, &salt);
    let nonce = generate_nonce();

    let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key");
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    Ok(EncryptedState {
        v: 1,
        s: B64.encode(salt),
        n: B64.encode(nonce.as_slice()),
        d: B64.encode(&ciphertext),
    })
}

/// Decrypt an EncryptedState back to plaintext JSON.
pub fn decrypt(encrypted: &EncryptedState, passphrase: &str) -> anyhow::Result<Vec<u8>> {
    if encrypted.v != 1 {
        return Err(anyhow::anyhow!(
            "Unsupported encryption version: {}",
            encrypted.v
        ));
    }

    let salt = B64
        .decode(&encrypted.s)
        .map_err(|e| anyhow::anyhow!("Invalid salt encoding: {}", e))?;
    let nonce_bytes = B64
        .decode(&encrypted.n)
        .map_err(|e| anyhow::anyhow!("Invalid nonce encoding: {}", e))?;
    if nonce_bytes.len() != 12 {
        return Err(anyhow::anyhow!("Invalid nonce length"));
    }
    let nonce: GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> =
        *GenericArray::from_slice(&nonce_bytes);
    let ciphertext = B64
        .decode(&encrypted.d)
        .map_err(|e| anyhow::anyhow!("Invalid ciphertext encoding: {}", e))?;

    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key");
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Decryption failed - wrong passphrase or corrupted data"))?;

    Ok(plaintext)
}

/// Generate a random 16-byte salt.
fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);
    salt
}

/// Generate a random 12-byte nonce for AES-GCM.
fn generate_nonce() -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill(&mut nonce);
    *GenericArray::from_slice(&nonce)
}

/// Derive a 32-byte encryption key from passphrase using Argon2id.
fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2::Params::new(
            65536,    // 64 MiB memory
            4,        // 4 iterations
            4,        // 4 lanes (parallelism)
            Some(32), // 32-byte hash output
        )
        .expect("valid params"),
    );

    let salt_str = SaltString::encode_b64(salt).expect("salt encodes to b64");
    let hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_str)
        .expect("Argon2id hashing succeeded");

    let mut key = [0u8; 32];
    if let Some(ref hash_bytes) = hash.hash {
        key.copy_from_slice(hash_bytes.as_ref());
    } else {
        panic!("Argon2id should always produce a hash");
    }
    key
}

/// Check if a state file is encrypted.
pub fn is_encrypted(content: &str) -> bool {
    #[derive(Deserialize)]
    struct VersionCheck {
        v: Option<u32>,
        s: Option<String>,
        d: Option<String>,
    }
    let parsed: VersionCheck = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    parsed.v == Some(1) && parsed.s.is_some() && parsed.d.is_some()
}

/// Encrypt content and write to file.
pub fn save(path: &Path, content: &str, passphrase: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let encrypted = encrypt(content.as_bytes(), passphrase)?;
    let json = serde_json::to_string_pretty(&encrypted)?;
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = r#"{"test": "data", "value": 42}"#;
        let passphrase = "test-passphrase-123";

        let encrypted = encrypt(plaintext.as_bytes(), passphrase).unwrap();
        assert_ne!(encrypted.d, plaintext);

        let decrypted = decrypt(&encrypted, passphrase).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), plaintext);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let plaintext = r#"{"test": "data"}"#;
        let encrypted = encrypt(plaintext.as_bytes(), "correct").unwrap();
        let result = decrypt(&encrypted, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_encrypted() {
        let encrypted_json = serde_json::to_string(&encrypt(b"test", "pass").unwrap()).unwrap();
        assert!(is_encrypted(&encrypted_json));
        assert!(!is_encrypted(r#"{"plain": "data"}"#));
        assert!(!is_encrypted("not json at all"));
    }
}
