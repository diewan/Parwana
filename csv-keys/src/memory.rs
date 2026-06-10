//! Memory-safe key types with automatic zeroization.
//!
//! This module provides types that securely hold cryptographic key material
//! and automatically clear memory when dropped.

use secrecy::{Secret, ExposeSecret, Zeroize};
use zeroize::ZeroizeOnDrop;

/// A 32-byte secret key that is automatically zeroed when dropped.
///
/// This type uses the `secrecy` crate to ensure the key material is never
/// accidentally exposed through Debug, Display, or serialization. The Secret
/// type implements ZeroizeOnDrop to securely clear memory when the value is dropped.
///
/// # Example
///
/// ```
/// use csv_keys::memory::SecretKey;
///
/// let key = SecretKey::new([1u8; 32]);
/// // Key is automatically zeroed when dropped
/// ```
#[derive(Clone)]
pub struct SecretKey(Secret<[u8; 32]>);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl SecretKey {
    /// Create a new SecretKey from raw bytes.
    ///
    /// # Arguments
    /// * `bytes` - 32-byte array containing the key material
    ///
    /// # Example
    /// ```
    /// use csv_keys::memory::SecretKey;
    ///
    /// let key = SecretKey::new([0u8; 32]);
    /// ```
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Generate a new random secret key.
    ///
    /// Uses the OS CSPRNG for secure random generation.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS RNG failed");
        Self(Secret::new(bytes))
    }

    /// Expose the secret key bytes for cryptographic operations.
    ///
    /// # Security Warning
    /// This exposes the raw key material. Only use this when absolutely
    /// necessary for signing operations. The returned reference is tied to
    /// the lifetime of the SecretKey to prevent accidental copying.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// Convert to a Vec<u8>.
    ///
    /// # Security Warning
    /// The returned Vec is NOT zeroized on drop. The caller is
    /// responsible for securely clearing the memory.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.expose_secret().to_vec()
    }
}

/// A passphrase that is automatically zeroed when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Passphrase(String);

impl Passphrase {
    /// Create a new passphrase from a string.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the passphrase as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the passphrase as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A 64-byte seed that is automatically zeroed when dropped.
///
/// This is typically used to hold the BIP-39 seed (derived from mnemonic).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 64]);

impl Seed {
    /// Create a new seed from raw bytes.
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get a reference to the internal seed bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// A 16-byte IV (Initialization Vector) for AES-GCM.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Iv([u8; 16]);

impl Iv {
    /// Create a new IV from raw bytes.
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Generate a random IV.
    ///
    /// # Security
    /// IVs must be unique per encryption operation but don't need to be secret.
    /// Random generation ensures uniqueness with high probability.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).expect("OS RNG failed");
        Self(bytes)
    }

    /// Get the IV bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A 12-byte nonce for AES-GCM (alternative to IV).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Nonce([u8; 12]);

impl Nonce {
    /// Create a new nonce from raw bytes.
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Generate a random nonce.
    pub fn random() -> Self {
        let mut bytes = [0u8; 12];
        getrandom::getrandom(&mut bytes).expect("OS RNG failed");
        Self(bytes)
    }

    /// Get the nonce bytes.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_creation() {
        let key = SecretKey::new([1u8; 32]);
        assert_eq!(key.expose_secret(), &[1u8; 32]);
    }

    #[test]
    fn test_secret_key_random() {
        let key1 = SecretKey::random();
        let key2 = SecretKey::random();
        // Keys should be different with overwhelming probability
        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_passphrase() {
        let pass = Passphrase::new("my secret password");
        assert_eq!(pass.as_str(), "my secret password");
    }

    #[test]
    fn test_seed() {
        let seed = Seed::new([2u8; 64]);
        assert_eq!(seed.as_bytes(), &[2u8; 64]);
    }

    #[test]
    fn test_iv() {
        let iv1 = Iv::random();
        let iv2 = Iv::random();
        // IVs should be different with overwhelming probability
        assert_ne!(iv1.as_bytes(), iv2.as_bytes());
    }

    #[test]
    fn test_nonce() {
        let nonce1 = Nonce::random();
        let nonce2 = Nonce::random();
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());
    }
}
