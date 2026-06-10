//! Unified Signer trait for chain-agnostic signing operations
//!
//! This module provides a unified signing interface that works across all chains.
//! Each chain adapter implements this trait with its specific signing logic.

use async_trait::async_trait;
use csv_hash::Hash;
use csv_protocol::signature::SignatureScheme;
use secrecy::{ExposeSecret, SecretVec};
use std::fmt;

/// Unified signature result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Raw signature bytes
    pub bytes: Vec<u8>,
    /// Signature scheme used
    pub scheme: SignatureScheme,
}

impl Signature {
    /// Create a new signature
    pub fn new(bytes: Vec<u8>, scheme: SignatureScheme) -> Self {
        Self { bytes, scheme }
    }

    /// Get the signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Reference to a signer (for passing around without cloning secrets)
#[derive(Clone)]
pub struct SignerRef {
    /// Signer ID
    pub id: String,
    /// Chain this signer is for
    pub chain: String,
    /// Public key or address
    pub public_key: Vec<u8>,
}

impl fmt::Debug for SignerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignerRef")
            .field("id", &self.id)
            .field("chain", &self.chain)
            .field("public_key", &hex::encode(&self.public_key))
            .finish()
    }
}

/// Unified Signer trait for chain-agnostic signing operations
///
/// This trait provides a consistent interface for signing operations across
/// all supported chains. Each chain adapter implements this trait with its
/// specific signing logic (secp256k1 for Ethereum, ed25519 for Solana, etc.).
#[async_trait]
pub trait Signer: Send + Sync {
    /// Sign a message using this signer's private key
    ///
    /// # Arguments
    /// * `message` - The message bytes to sign
    ///
    /// # Returns
    /// The signature bytes
    async fn sign(&self, message: &[u8]) -> Result<Signature, crate::error::WalletError>;

    /// Sign a hash directly
    ///
    /// # Arguments
    /// * `hash` - The hash to sign
    ///
    /// # Returns
    /// The signature bytes
    async fn sign_hash(&self, hash: &Hash) -> Result<Signature, crate::error::WalletError> {
        self.sign(hash.as_bytes()).await
    }

    /// Get the public key or address for this signer
    ///
    /// # Returns
    /// The public key or address bytes
    fn public_key(&self) -> &[u8];

    /// Get the signature scheme used by this signer
    ///
    /// # Returns
    /// The signature scheme
    fn signature_scheme(&self) -> SignatureScheme;

    /// Get a reference to this signer (for passing around without secrets)
    ///
    /// # Returns
    /// A SignerRef
    fn as_ref(&self) -> SignerRef;

    /// Get the chain this signer is for
    ///
    /// # Returns
    /// The chain identifier
    fn chain(&self) -> &str;
}

/// In-memory signer implementation for testing
pub struct MemorySigner {
    id: String,
    chain: String,
    secret_key: SecretVec<u8>,
    public_key: Vec<u8>,
    scheme: SignatureScheme,
}

impl MemorySigner {
    /// Create a new memory signer
    ///
    /// # Arguments
    /// * `id` - Signer ID
    /// * `chain` - Chain identifier
    /// * `secret_key` - Secret key bytes (will be zeroized on drop)
    /// * `public_key` - Public key bytes
    /// * `scheme` - Signature scheme
    pub fn new(
        id: String,
        chain: String,
        secret_key: Vec<u8>,
        public_key: Vec<u8>,
        scheme: SignatureScheme,
    ) -> Self {
        Self {
            id,
            chain,
            secret_key: SecretVec::new(secret_key),
            public_key,
            scheme,
        }
    }
}

#[async_trait]
impl Signer for MemorySigner {
    async fn sign(&self, message: &[u8]) -> Result<Signature, crate::error::WalletError> {
        match self.scheme {
            SignatureScheme::Secp256k1 => self.sign_secp256k1(message),
            SignatureScheme::Ed25519 => self.sign_ed25519(message),
            SignatureScheme::MlDsa65 => Err(crate::error::WalletError::SigningFailed(
                "MlDsa65 signing not yet implemented".to_string(),
            )),
        }
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.scheme
    }

    fn as_ref(&self) -> SignerRef {
        SignerRef {
            id: self.id.clone(),
            chain: self.chain.clone(),
            public_key: self.public_key.clone(),
        }
    }

    fn chain(&self) -> &str {
        &self.chain
    }
}

impl MemorySigner {
    fn sign_secp256k1(&self, message: &[u8]) -> Result<Signature, crate::error::WalletError> {
        use secp256k1::{Message, SecretKey, Secp256k1};

        let secret_key = SecretKey::from_slice(self.secret_key.expose_secret())
            .map_err(|e| crate::error::WalletError::SigningFailed(format!("Invalid secret key: {}", e)))?;

        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(message)
            .map_err(|e| crate::error::WalletError::SigningFailed(format!("Invalid message: {}", e)))?;

        let signature = secp.sign_ecdsa(&message, &secret_key);
        let signature_bytes = signature.serialize_compact().to_vec();

        Ok(Signature {
            bytes: signature_bytes,
            scheme: SignatureScheme::Secp256k1,
        })
    }

    fn sign_ed25519(&self, message: &[u8]) -> Result<Signature, crate::error::WalletError> {
        use ed25519_dalek::{SigningKey, Signer as EdSigner};

        let secret_bytes = self.secret_key.expose_secret();
        if secret_bytes.len() != 32 {
            return Err(crate::error::WalletError::SigningFailed(
                "Invalid secret key length".to_string(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(secret_bytes);

        let signing_key = SigningKey::from_bytes(&key_array);
        let signature = signing_key.sign(message);
        let signature_bytes = signature.to_bytes().to_vec();

        Ok(Signature {
            bytes: signature_bytes,
            scheme: SignatureScheme::Ed25519,
        })
    }
}
