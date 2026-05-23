//! Signature stub module

use serde::{Deserialize, Serialize};

/// Signature scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureScheme {
    /// Ed25519
    Ed25519,
    /// Secp256k1
    Secp256k1,
    /// BLS
    BLS,
}

/// Signature type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Signature scheme
    pub scheme: SignatureScheme,
    /// Signature bytes
    pub bytes: Vec<u8>,
    /// Signer public key
    pub public_key: Vec<u8>,
}

impl Signature {
    /// Create new signature
    pub fn new(scheme: SignatureScheme, bytes: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            scheme,
            bytes,
            public_key,
        }
    }
}
