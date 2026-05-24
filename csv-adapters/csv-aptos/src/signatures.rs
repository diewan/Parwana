//! Aptos signature verification (Ed25519)
//!
//! Aptos uses Ed25519 signatures for transaction authentication.
//! Signature format: 64 bytes (R || S)
//! Public key format: 32 bytes

use csv_protocol::error::ProtocolError;
use csv_protocol::error::Result;

/// Verify an Aptos Ed25519 signature
///
/// # Arguments
/// * `signature` - 64 byte Ed25519 signature (R || S)
/// * `public_key` - 32 byte Ed25519 public key
/// * `message` - Message bytes that were signed
///
/// # Returns
/// Ok(()) if signature is valid, Err otherwise
pub fn verify_aptos_signature(signature: &[u8], public_key: &[u8], message: &[u8]) -> Result<()> {
    // Validate inputs
    if signature.len() != 64 {
        return Err(ProtocolError::SignatureVerificationFailed(format!(
            "Invalid signature length: {} (expected 64)",
            signature.len()
        )));
    }

    if public_key.len() != 32 {
        return Err(ProtocolError::SignatureVerificationFailed(format!(
            "Invalid public key length: {} (expected 32)",
            public_key.len()
        )));
    }

    if message.is_empty() {
        return Err(ProtocolError::SignatureVerificationFailed(
            "Message cannot be empty".to_string(),
        ));
    }

    // Parse the public key
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(public_key.try_into().map_err(|_| {
            ProtocolError::SignatureVerificationFailed("Invalid public key".to_string())
        })?)
        .map_err(|e| {
            ProtocolError::SignatureVerificationFailed(format!("Invalid Ed25519 public key: {}", e))
        })?;

    // Parse the signature
    let sig = ed25519_dalek::Signature::from_bytes(signature.try_into().map_err(|_| {
        ProtocolError::SignatureVerificationFailed("Invalid signature".to_string())
    })?);

    // Verify the signature
    use ed25519_dalek::Verifier;

    verifying_key.verify(message, &sig).map_err(|_| {
        ProtocolError::SignatureVerificationFailed(
            "Ed25519 signature verification failed".to_string(),
        )
    })
}

/// Verify multiple Aptos signatures
pub fn verify_aptos_signatures(signatures: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> Result<()> {
    if signatures.is_empty() {
        return Err(ProtocolError::SignatureVerificationFailed(
            "No signatures to verify".to_string(),
        ));
    }

    for (i, (sig, pk, msg)) in signatures.iter().enumerate() {
        verify_aptos_signature(sig, pk, msg).map_err(|e| {
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
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn generate_test_signature() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Message to sign
        let message = b"test message for Aptos signature verification";

        // Sign the message
        let signature = signing_key.sign(message);

        (
            signature.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
            message.to_vec(),
        )
    }

    #[test]
    fn test_valid_aptos_signature() {
        let (sig, pk, msg) = generate_test_signature();
        assert!(verify_aptos_signature(&sig, &pk, &msg).is_ok());
    }

    #[test]
    fn test_invalid_signature_length() {
        let (_, pk, msg) = generate_test_signature();
        let bad_sig = vec![0u8; 32];
        assert!(verify_aptos_signature(&bad_sig, &pk, &msg).is_err());
    }

    #[test]
    fn test_invalid_public_key_length() {
        let (sig, _, msg) = generate_test_signature();
        let bad_pk = vec![0u8; 33];
        assert!(verify_aptos_signature(&sig, &bad_pk, &msg).is_err());
    }

    #[test]
    fn test_tampered_signature() {
        let (mut sig, pk, msg) = generate_test_signature();
        sig[0] ^= 0xFF;
        assert!(verify_aptos_signature(&sig, &pk, &msg).is_err());
    }

    #[test]
    fn test_wrong_public_key() {
        let (sig, _, msg) = generate_test_signature();
        let (_, wrong_pk, _) = generate_test_signature();
        assert!(verify_aptos_signature(&sig, &wrong_pk, &msg).is_err());
    }

    #[test]
    fn test_wrong_message() {
        let (sig, pk, _) = generate_test_signature();
        let wrong_msg = b"wrong message entirely";
        assert!(verify_aptos_signature(&sig, &pk, wrong_msg).is_err());
    }

    #[test]
    fn test_verify_multiple_signatures() {
        let sig1 = generate_test_signature();
        let sig2 = generate_test_signature();
        let sig3 = generate_test_signature();

        let signatures = vec![sig1, sig2, sig3];
        assert!(verify_aptos_signatures(&signatures).is_ok());
    }

    #[test]
    fn test_verify_empty_signatures() {
        let signatures: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = vec![];
        assert!(verify_aptos_signatures(&signatures).is_err());
    }
}
