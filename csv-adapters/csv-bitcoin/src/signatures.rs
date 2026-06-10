//! Bitcoin signature verification (ECDSA/secp256k1)
//!
//! Bitcoin uses ECDSA signatures over the secp256k1 curve.
//! Signature format: 64 bytes [r (32)] [s (32)] or 65 bytes [recovery_id (1)] [r (32)] [s (32)]

use async_trait::async_trait;
use csv_protocol::error::ProtocolError;
use csv_protocol::error::Result as ProtocolResult;
use csv_protocol::signature::SignatureScheme;
use csv_wallet::{Signer, SignerRef, Signature as WalletSignature, WalletError, Result as WalletResult};
use secrecy::{SecretVec, ExposeSecret};
use std::fmt;

/// Bitcoin Signer implementation using csv-wallet Signer trait
pub struct BitcoinSigner {
    id: String,
    secret_key: SecretVec<u8>,
    public_key: Vec<u8>,
}

impl BitcoinSigner {
    /// Create a new Bitcoin signer from a private key
    ///
    /// # Arguments
    /// * `id` - Signer identifier
    /// * `secret_key` - 32-byte secp256k1 private key
    pub fn new(id: String, secret_key: Vec<u8>) -> ProtocolResult<Self> {
        if secret_key.len() != 32 {
            return Err(ProtocolError::InvalidInput(
                "Private key must be 32 bytes".to_string(),
            ));
        }

        let secp = secp256k1::Secp256k1::new();
        let secret_key_obj = secp256k1::SecretKey::from_slice(&secret_key)
            .map_err(|e| ProtocolError::InvalidInput(format!("Invalid private key: {}", e)))?;
        
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key_obj);
        let public_key_bytes = public_key.serialize();

        Ok(Self {
            id,
            secret_key: SecretVec::new(secret_key),
            public_key: public_key_bytes.to_vec(),
        })
    }

    /// Get the Bitcoin public key for this signer
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

#[async_trait]
impl Signer for BitcoinSigner {
    async fn sign(&self, message: &[u8]) -> WalletResult<WalletSignature> {
        let secret_key_obj = secp256k1::SecretKey::from_slice(self.secret_key.expose_secret())
            .map_err(|e| WalletError::Signing(format!("Invalid secret key: {}", e)))?;
        
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest_slice(message)
            .map_err(|e| WalletError::Signing(format!("Invalid message: {}", e)))?;
        
        let signature = secp.sign_ecdsa(&msg, &secret_key_obj);
        let sig_bytes = signature.serialize_compact();
        
        Ok(WalletSignature::new(sig_bytes.to_vec(), SignatureScheme::Secp256k1))
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }

    fn as_ref(&self) -> SignerRef {
        SignerRef {
            id: self.id.clone(),
            chain: "bitcoin".to_string(),
            public_key: self.public_key.clone(),
        }
    }

    fn chain(&self) -> &str {
        "bitcoin"
    }
}

impl fmt::Debug for BitcoinSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitcoinSigner")
            .field("id", &self.id)
            .field("public_key", &hex::encode(&self.public_key))
            .finish()
    }
}

/// Verify a Bitcoin ECDSA signature
pub fn verify_bitcoin_signature(signature: &[u8], public_key: &[u8], message: &[u8]) -> ProtocolResult<()> {
    if message.len() != 32 {
        return Err(ProtocolError::SignatureVerificationFailed(format!(
            "Message must be 32 bytes, got {}",
            message.len()
        )));
    }

    if signature.len() != 64 && signature.len() != 65 {
        return Err(ProtocolError::SignatureVerificationFailed(format!(
            "Invalid signature length: {} (expected 64 or 65)",
            signature.len()
        )));
    }

    if public_key.len() != 33 && public_key.len() != 65 {
        return Err(ProtocolError::SignatureVerificationFailed(format!(
            "Invalid public key length: {} (expected 33 or 65)",
            public_key.len()
        )));
    }

    let pubkey = if public_key.len() == 33 {
        secp256k1::PublicKey::from_slice(public_key).map_err(|e| {
            ProtocolError::SignatureVerificationFailed(format!(
                "Invalid compressed public key: {}",
                e
            ))
        })?
    } else {
        secp256k1::PublicKey::from_slice(public_key).map_err(|e| {
            ProtocolError::SignatureVerificationFailed(format!(
                "Invalid uncompressed public key: {}",
                e
            ))
        })?
    };

    let sig_bytes = if signature.len() == 64 {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(signature);
        bytes
    } else {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&signature[1..65]);
        bytes
    };

    let sig = secp256k1::ecdsa::Signature::from_compact(&sig_bytes).map_err(|e| {
        ProtocolError::SignatureVerificationFailed(format!("Invalid signature format: {}", e))
    })?;

    let msg = secp256k1::Message::from_digest_slice(message).map_err(|e| {
        ProtocolError::SignatureVerificationFailed(format!("Invalid message hash: {}", e))
    })?;

    let context = secp256k1::Secp256k1::verification_only();

    if context.verify_ecdsa(&msg, &sig, &pubkey).is_ok() {
        Ok(())
    } else {
        Err(ProtocolError::SignatureVerificationFailed(
            "ECDSA signature verification failed".to_string(),
        ))
    }
}

pub fn verify_bitcoin_signatures(signatures: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> ProtocolResult<()> {
    if signatures.is_empty() {
        return Err(ProtocolError::SignatureVerificationFailed(
            "No signatures to verify".to_string(),
        ));
    }

    for (i, (sig, pk, msg)) in signatures.iter().enumerate() {
        verify_bitcoin_signature(sig, pk, msg).map_err(|e| {
            ProtocolError::SignatureVerificationFailed(format!(
                "Signature {} verification failed: {}",
                i, e
            ))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use secp256k1::{Secp256k1, SecretKey};

    fn generate_test_signature() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let message = [0xAB; 32];
        let msg = secp256k1::Message::from_digest_slice(&message).unwrap();
        let signature = secp.sign_ecdsa(&msg, &secret_key);
        let sig_bytes = signature.serialize_compact();
        let pubkey_bytes = public_key.serialize();
        (sig_bytes.to_vec(), pubkey_bytes.to_vec(), message.to_vec())
    }

    #[test]
    fn test_valid_bitcoin_signature() {
        let (sig, pk, msg) = generate_test_signature();
        assert!(verify_bitcoin_signature(&sig, &pk, &msg).is_ok());
    }

    #[test]
    fn test_tampered_signature() {
        let (mut sig, pk, msg) = generate_test_signature();
        sig[0] ^= 0xFF;
        assert!(verify_bitcoin_signature(&sig, &pk, &msg).is_err());
    }
}
