//! Ethereum signature verification (ECDSA/secp256k1)
//!
//! Ethereum uses ECDSA signatures over the secp256k1 curve.
//! Signature format: 64 bytes [r (32)] [s (32)] or 65 bytes [recovery_id (1)] [r (32)] [s (32)]

use csv_core::error::ProtocolError;
use csv_core::error::Result;

/// Verify an Ethereum ECDSA signature
///
/// # Arguments
/// * `signature` - 64 or 65 byte signature (r || s || [v])
/// * `public_key` - 33 or 65 byte public key (compressed or uncompressed)
/// * `message` - 32 byte message hash (keccak256)
///
/// # Returns
/// Ok(()) if signature is valid, Err otherwise
pub fn verify_ethereum_signature(
    signature: &[u8],
    public_key: &[u8],
    message: &[u8],
) -> Result<()> {
    // Validate inputs
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

    // Parse the public key
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

    // Parse the signature (64 or 65 bytes)
    let sig_bytes = if signature.len() == 64 {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(signature);
        bytes
    } else {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&signature[0..64]);
        // Handle recovery ID for Ethereum (v is appended at the END of signature for Ethereum)
        let recovery_id = signature[64];
        if recovery_id > 1 && recovery_id != 27 && recovery_id != 28 {
            return Err(ProtocolError::SignatureVerificationFailed(format!(
                "Invalid recovery ID: {}",
                recovery_id
            )));
        }
        bytes
    };

    // Create Signature from compact format
    let sig = secp256k1::ecdsa::Signature::from_compact(&sig_bytes).map_err(|e| {
        ProtocolError::SignatureVerificationFailed(format!("Invalid signature format: {}", e))
    })?;

    // Create message
    let msg = secp256k1::Message::from_digest_slice(message).map_err(|e| {
        ProtocolError::SignatureVerificationFailed(format!("Invalid message hash: {}", e))
    })?;

    // Verify the signature
    let context = secp256k1::Secp256k1::verification_only();

    if context.verify_ecdsa(&msg, &sig, &pubkey).is_ok() {
        Ok(())
    } else {
        Err(ProtocolError::SignatureVerificationFailed(
            "ECDSA signature verification failed".to_string(),
        ))
    }
}

/// Verify multiple Ethereum signatures
pub fn verify_ethereum_signatures(signatures: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> Result<()> {
    if signatures.is_empty() {
        return Err(ProtocolError::SignatureVerificationFailed(
            "No signatures to verify".to_string(),
        ));
    }

    for (i, (sig, pk, msg)) in signatures.iter().enumerate() {
        verify_ethereum_signature(sig, pk, msg).map_err(|e| {
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

        // Message to sign (32 bytes)
        let message = [0xAB; 32];
        let msg = secp256k1::Message::from_digest_slice(&message).unwrap();

        // Sign the message
        let signature = secp.sign_ecdsa(&msg, &secret_key);
        let sig_bytes = signature.serialize_compact();

        // Use compressed public key (33 bytes)
        let pubkey_bytes = public_key.serialize();

        (sig_bytes.to_vec(), pubkey_bytes.to_vec(), message.to_vec())
    }

    #[test]
    fn test_valid_eth_signature() {
        let (sig, pk, msg) = generate_test_signature();
        assert!(verify_ethereum_signature(&sig, &pk, &msg).is_ok());
    }

    #[test]
    fn test_invalid_message_length() {
        let (sig, pk, _) = generate_test_signature();
        let bad_msg = vec![0u8; 16];
        assert!(verify_ethereum_signature(&sig, &pk, &bad_msg).is_err());
    }

    #[test]
    fn test_invalid_signature_length() {
        let (_, pk, msg) = generate_test_signature();
        let bad_sig = vec![0u8; 32];
        assert!(verify_ethereum_signature(&bad_sig, &pk, &msg).is_err());
    }

    #[test]
    fn test_tampered_signature() {
        let (mut sig, pk, msg) = generate_test_signature();
        sig[0] ^= 0xFF;
        assert!(verify_ethereum_signature(&sig, &pk, &msg).is_err());
    }

    #[test]
    fn test_wrong_public_key() {
        let (sig, _, msg) = generate_test_signature();
        let (_, wrong_pk, _) = generate_test_signature();
        assert!(verify_ethereum_signature(&sig, &wrong_pk, &msg).is_err());
    }

    #[test]
    fn test_verify_multiple_signatures() {
        let sig1 = generate_test_signature();
        let sig2 = generate_test_signature();
        let sig3 = generate_test_signature();

        let signatures = vec![sig1, sig2, sig3];
        assert!(verify_ethereum_signatures(&signatures).is_ok());
    }
}
