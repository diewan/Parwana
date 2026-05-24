//! Bitcoin signature verification (ECDSA/secp256k1)
//!
//! Bitcoin uses ECDSA signatures over the secp256k1 curve.
//! Signature format: 64 bytes [r (32)] [s (32)] or 65 bytes [recovery_id (1)] [r (32)] [s (32)]

use csv_protocol::error::ProtocolError;
use csv_protocol::error::Result;

/// Verify a Bitcoin ECDSA signature
pub fn verify_bitcoin_signature(signature: &[u8], public_key: &[u8], message: &[u8]) -> Result<()> {
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

pub fn verify_bitcoin_signatures(signatures: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> Result<()> {
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
