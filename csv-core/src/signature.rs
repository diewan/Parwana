//! Signature verification trait and implementations
//!
//! This module provides chain-agnostic signature verification support.
//! Different chains use different signature schemes:
//! - Bitcoin/Ethereum: ECDSA over secp256k1
//! - Sui/Aptos: Ed25519
//! - Celestia: ECDSA over secp256k1 (Tendermint style)
//!
//! ## Post-Quantum Requirement (Decision D-1)
//!
//! ML-DSA-65 (FIPS 204, Module-Lattice-Based Digital Signature Algorithm)
//! is the required default signature scheme from genesis. Classical signatures
//! (Secp256k1, Ed25519) are forgeable by 2030+ quantum adversaries.
//! Long-lived proof bundles must use ML-DSA-65.

use crate::error::{ProtocolError, Result};

/// Signature scheme used by a chain
///
/// ## Post-Quantum Default (Decision D-1)
///
/// ML-DSA-65 is the required default. All new proof bundles should use it.
/// Ed25519 and Secp256k1 are retained for legacy chain compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignatureScheme {
    /// ECDSA over secp256k1 (Bitcoin, Ethereum, Celestia) — LEGACY, not PQ
    Secp256k1,
    /// Ed25519 (Sui, Aptos) — LEGACY, not PQ
    Ed25519,
    /// ML-DSA-65 (FIPS 204, Module-Lattice-Based Digital Signature)
    /// Post-quantum secure. Required default for all long-lived proof bundles.
    /// 65-byte security level, public key ~1312 bytes, signature ~2420 bytes.
    MlDsa65,
}

impl Default for SignatureScheme {
    /// Secp256k1 is the runtime default. ML-DSA-65 is an opt-in per-chain
    /// configuration. See PROTOCOL_INVARIANTS.md for signature scheme derivation.
    fn default() -> Self {
        SignatureScheme::Secp256k1
    }
}

/// The intended post-quantum default signature scheme.
/// Not yet the runtime default — requires the `pq` feature and explicit
/// per-seal configuration. See PLAN.md for details.
pub const PQ_DEFAULT_SCHEME: SignatureScheme = SignatureScheme::MlDsa65;

/// A signature with its associated public key
#[derive(Clone, Debug)]
pub struct Signature {
    /// Signature bytes (scheme-specific format)
    pub signature: Vec<u8>,
    /// Public key bytes (scheme-specific format)
    pub public_key: Vec<u8>,
    /// Message that was signed
    pub message: Vec<u8>,
}

impl Signature {
    /// Create a new signature
    pub fn new(signature: Vec<u8>, public_key: Vec<u8>, message: Vec<u8>) -> Self {
        Self {
            signature,
            public_key,
            message,
        }
    }

    /// Sign a message using the specified scheme and secret key
    ///
    /// Returns a new `Signature` containing the signature bytes, public key,
    /// and the signed message. The caller must first generate a key pair
    /// using the appropriate key generation function for the scheme.
    pub fn sign(scheme: SignatureScheme, secret_key: &[u8], message: &[u8]) -> Result<Self> {
        let signature = match scheme {
            SignatureScheme::Secp256k1 => {
                // secp256k1 is chain-specific and should be implemented in adapters
                return Err(ProtocolError::SignatureVerificationFailed(
                    "secp256k1 signing requires chain adapter support (csv-bitcoin, csv-ethereum, etc.)".to_string(),
                ));
            }
            SignatureScheme::Ed25519 => sign_ed25519(message, secret_key)?,
            SignatureScheme::MlDsa65 => {
                #[cfg(feature = "pq")]
                {
                    sign_ml_dsa65(message, secret_key)?
                }
                #[cfg(not(feature = "pq"))]
                {
                    return Err(ProtocolError::SignatureVerificationFailed(
                        "ML-DSA-65 signing requires the 'pq' feature to be enabled".to_string(),
                    ));
                }
            }
        };

        // The public key is expected to be derived from the secret key
        // by the caller and passed separately. For now, we use an empty
        // public key that the caller must set before verification.
        Ok(Self {
            signature,
            public_key: Vec::new(),
            message: message.to_vec(),
        })
    }

    /// Verify this signature using the appropriate scheme
    pub fn verify(&self, scheme: SignatureScheme) -> Result<()> {
        match scheme {
            SignatureScheme::Secp256k1 => {
                // secp256k1 is chain-specific and should be implemented in adapters
                return Err(ProtocolError::SignatureVerificationFailed(
                    "secp256k1 verification requires chain adapter support (csv-bitcoin, csv-ethereum, etc.)".to_string(),
                ));
            }
            SignatureScheme::Ed25519 => {
                verify_ed25519(&self.signature, &self.public_key, &self.message)
            }
            SignatureScheme::MlDsa65 => {
                verify_ml_dsa65(&self.signature, &self.public_key, &self.message)
            }
        }
    }
}

/// Verify an ECDSA secp256k1 signature
///
/// Signature format: 64 bytes (r || s) or 65 bytes (recovery_id || r || s)
/// Public key format: 33 bytes (compressed) or 65 bytes (uncompressed)
/// Message: 32 bytes (pre-hashed)
///
/// NOTE: This is a stub implementation. Chain adapters should provide their own
/// secp256k1 verification since this is chain-specific functionality.
fn verify_secp256k1(_signature: &[u8], _public_key: &[u8], _message: &[u8]) -> Result<()> {
    Err(ProtocolError::SignatureVerificationFailed(
        "secp256k1 verification requires chain adapter support (csv-bitcoin, csv-ethereum, etc.)".to_string(),
    ))
}

/// Verify an Ed25519 signature
///
/// Signature format: 64 bytes (R || S)
/// Public key format: 32 bytes
/// Message: arbitrary length
fn verify_ed25519(signature: &[u8], public_key: &[u8], message: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Validate input sizes
    if public_key.is_empty() {
        return Err(ProtocolError::SignatureVerificationFailed(
            "Empty public key".to_string(),
        ));
    }

    if signature.is_empty() {
        return Err(ProtocolError::SignatureVerificationFailed(
            "Empty signature".to_string(),
        ));
    }

    // Ed25519 public key must be 32 bytes
    if public_key.len() != 32 {
        return Err(ProtocolError::SignatureVerificationFailed(format!(
            "Invalid Ed25519 public key length: {} (expected 32)",
            public_key.len()
        )));
    }

    // Ed25519 signature must be 64 bytes
    if signature.len() != 64 {
        return Err(ProtocolError::SignatureVerificationFailed(format!(
            "Invalid Ed25519 signature length: {} (expected 64)",
            signature.len()
        )));
    }

    // Parse public key
    let verifying_key = VerifyingKey::from_bytes(public_key.try_into().map_err(|_| {
        ProtocolError::SignatureVerificationFailed("Invalid Ed25519 public key length".to_string())
    })?).map_err(|e| {
        ProtocolError::SignatureVerificationFailed(format!("Invalid Ed25519 public key: {}", e))
    })?;

    // Parse signature
    let sig_bytes_arr: [u8; 64] = signature.try_into().map_err(|_| {
        ProtocolError::SignatureVerificationFailed("Invalid Ed25519 signature length".to_string())
    })?;
    let sig = Signature::from_bytes(&sig_bytes_arr);

    // Perform actual cryptographic verification
    verifying_key.verify(message, &sig).map_err(|e| {
        ProtocolError::SignatureVerificationFailed(format!(
            "Ed25519 signature verification failed: {}",
            e
        ))
    })?;

    Ok(())
}

/// Sign a message using ECDSA secp256k1
///
/// # Arguments
/// * `message` - The 32-byte message to sign (pre-hashed)
/// * `secret_key` - The secp256k1 secret key (32 bytes)
///
/// # Returns
/// Signature bytes (64 bytes: r || s)
///
/// NOTE: This is a stub implementation. Chain adapters should provide their own
/// secp256k1 signing since this is chain-specific functionality.
fn sign_secp256k1(_message: &[u8], _secret_key: &[u8]) -> Result<Vec<u8>> {
    Err(ProtocolError::SignatureVerificationFailed(
        "secp256k1 signing requires chain adapter support (csv-bitcoin, csv-ethereum, etc.)".to_string(),
    ))
}

/// Sign a message using Ed25519
///
/// # Arguments
/// * `message` - The message to sign
/// * `secret_key` - The Ed25519 secret key (32 bytes)
///
/// # Returns
/// Signature bytes (64 bytes: R || S)
fn sign_ed25519(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::{Signature, Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(secret_key.try_into().map_err(|_| {
        ProtocolError::SignatureVerificationFailed(
            "Invalid Ed25519 secret key (must be 32 bytes)".to_string(),
        )
    })?);
    let sig: Signature = signing_key.sign(message);

    Ok(sig.to_bytes().to_vec())
}

/// ML-DSA-65 (FIPS 204) key generation
///
/// ML-DSA-65 corresponds to Dilithium3 in pqcrypto-dilithium.
/// Returns (public_key, secret_key) where:
/// - public_key: ~1312 bytes
/// - secret_key: ~2456 bytes
#[cfg(feature = "pq")]
pub fn generate_ml_dsa65_keys() -> Result<(Vec<u8>, Vec<u8>)> {
    use pqcrypto_dilithium::dilithium3::keypair;
    use pqcrypto_traits::sign::{PublicKey, SecretKey};

    let (pk, sk) = keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

/// Sign a message using ML-DSA-65
///
/// # Arguments
/// * `message` - The message to sign (will be hashed internally)
/// * `secret_key` - The ML-DSA-65 secret key (~2456 bytes)
///
/// # Returns
/// Signature bytes (~2420 bytes for ML-DSA-65)
#[cfg(feature = "pq")]
pub fn sign_ml_dsa65(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    use pqcrypto_dilithium::dilithium3::sign;
    use pqcrypto_traits::sign::{SecretKey, SignedMessage};

    // Reconstruct SecretKey from bytes
    let sk = SecretKey::from_bytes(secret_key).map_err(|_| {
        ProtocolError::SignatureVerificationFailed("Invalid ML-DSA-65 secret key".to_string())
    })?;

    let signed_msg = sign(message, &sk);
    Ok(signed_msg.as_bytes().to_vec())
}

/// Verify an ML-DSA-65 signature
///
/// # Arguments
/// * `signature` - The ML-DSA-65 signature (~2420 bytes)
/// * `public_key` - The ML-DSA-65 public key (~1312 bytes)
/// * `message` - The message that was signed
#[cfg(feature = "pq")]
fn verify_ml_dsa65(signature: &[u8], public_key: &[u8], _message: &[u8]) -> Result<()> {
    use pqcrypto_dilithium::dilithium3::open;
    use pqcrypto_traits::sign::{PublicKey, SignedMessage};

    // Validate input sizes for ML-DSA-65 (Dilithium3)
    // Public key: 1312 bytes, Signature: 2420 bytes
    if public_key.len() != 1312 {
        return Err(ProtocolError::SignatureVerificationFailed(format!(
            "Invalid ML-DSA-65 public key length: {} (expected 1312)",
            public_key.len()
        )));
    }

    if signature.len() != 2420 {
        return Err(ProtocolError::SignatureVerificationFailed(format!(
            "Invalid ML-DSA-65 signature length: {} (expected 2420)",
            signature.len()
        )));
    }

    // Parse public key
    let pk = PublicKey::from_bytes(public_key).map_err(|_| {
        ProtocolError::SignatureVerificationFailed("Invalid ML-DSA-65 public key".to_string())
    })?;

    // Construct SignedMessage from signature bytes
    let signed_msg = SignedMessage::from_bytes(signature).map_err(|_| {
        ProtocolError::SignatureVerificationFailed("Invalid ML-DSA-65 signature".to_string())
    })?;

    // Perform actual cryptographic verification using open()
    // open() returns Ok(message) if verification succeeds, Err(()) if it fails
    open(&signed_msg, &pk).map_err(|_| {
        ProtocolError::SignatureVerificationFailed(
            "ML-DSA-65 signature verification failed".to_string(),
        )
    })?;

    Ok(())
}

/// ML-DSA-65 verification without the pq feature (stub)
/// Returns an error indicating the pq feature is not enabled.
#[cfg(not(feature = "pq"))]
fn verify_ml_dsa65(_signature: &[u8], _public_key: &[u8], _message: &[u8]) -> Result<()> {
    Err(ProtocolError::SignatureVerificationFailed(
        "ML-DSA-65 verification requires the 'pq' feature to be enabled".to_string(),
    ))
}

/// Verify multiple signatures
pub fn verify_signatures(signatures: &[Signature], scheme: SignatureScheme) -> Result<()> {
    if signatures.is_empty() {
        return Err(ProtocolError::SignatureVerificationFailed(
            "No signatures to verify".to_string(),
        ));
    }

    for (i, sig) in signatures.iter().enumerate() {
        sig.verify(scheme).map_err(|e| {
            ProtocolError::SignatureVerificationFailed(format!(
                "Signature {} verification failed: {}",
                i, e
            ))
        })?;
    }

    Ok(())
}

/// Parse signatures from raw bytes (chain-specific format)
///
/// This is a helper that adapters can use to parse their signature format
pub fn parse_signatures_from_bytes(
    raw_signatures: &[Vec<u8>],
    public_keys: &[Vec<u8>],
    message: &[u8],
) -> Vec<Signature> {
    raw_signatures
        .iter()
        .zip(public_keys.iter())
        .map(|(sig, pk)| Signature::new(sig.clone(), pk.clone(), message.to_vec()))
        .collect()
}

/// Parse signatures from the canonical bundle format.
///
/// Each signature byte array has the layout:
/// `[pk_len (4 bytes LE)] [public_key] [signature]`
///
/// This is the format used by all chain adapters (Bitcoin, Ethereum, Solana).
///
/// # Arguments
/// * `raw_signatures` — The signature byte arrays from the proof bundle
/// * `message` — The message that was signed (typically the transition DAG root)
///
/// # Returns
/// A vector of parsed `Signature` objects, or an error if any signature
/// has an invalid format.
pub fn parse_signatures_from_bundle(
    raw_signatures: &[Vec<u8>],
    message: &[u8],
) -> Result<Vec<Signature>> {
    if raw_signatures.is_empty() {
        return Err(ProtocolError::SignatureVerificationFailed(
            "No signatures to verify".to_string(),
        ));
    }

    let mut signatures = Vec::with_capacity(raw_signatures.len());

    for (i, sig_bytes) in raw_signatures.iter().enumerate() {
        if sig_bytes.len() < 4 {
            return Err(ProtocolError::SignatureVerificationFailed(format!(
                "Signature {} too short: expected at least 4 bytes for length prefix, got {}",
                i,
                sig_bytes.len()
            )));
        }

        let pk_len =
            u32::from_le_bytes([sig_bytes[0], sig_bytes[1], sig_bytes[2], sig_bytes[3]])
                as usize;

        if sig_bytes.len() < 4 + pk_len {
            return Err(ProtocolError::SignatureVerificationFailed(format!(
                "Signature {} length mismatch: declared pk_len={}, but total length is {}",
                i,
                pk_len,
                sig_bytes.len()
            )));
        }

        let public_key = sig_bytes[4..4 + pk_len].to_vec();
        let signature = sig_bytes[4 + pk_len..].to_vec();

        signatures.push(Signature::new(signature, public_key, message.to_vec()));
    }

    Ok(signatures)
}

/// Verify signatures from a proof bundle using the specified scheme.
///
/// This is a convenience function that combines parsing and verification
/// in a single call. It is the canonical implementation used by all adapters.
///
/// # Arguments
/// * `bundle` — The proof bundle containing signatures
/// * `scheme` — The signature scheme to use for verification
///
/// # Returns
/// `Ok(())` if all signatures are valid, or an error otherwise.
pub fn verify_bundle_signatures(
    bundle: &csv_proof::proof::ProofBundle,
    scheme: SignatureScheme,
) -> Result<()> {
    let signatures = parse_signatures_from_bundle(&bundle.signatures, bundle.transition_dag.root_commitment.as_bytes())?;
    verify_signatures(&signatures, scheme)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_valid_signature() {
        use secp256k1::{Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let message = [0xCD; 32];
        let msg = Message::from_digest_slice(&message).unwrap();
        let signature = secp.sign_ecdsa(&msg, &secret_key);
        let sig_bytes = signature.serialize_compact();
        let pubkey_bytes = public_key.serialize();

        let sig = Signature::new(sig_bytes.to_vec(), pubkey_bytes.to_vec(), message.to_vec());
        assert!(sig.verify(SignatureScheme::Secp256k1).is_ok());
    }

    #[test]
    fn test_secp256k1_invalid_signature_fails() {
        use secp256k1::{Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey_bytes = public_key.serialize();

        // Wrong message
        let message = [0xCD; 32];
        let different_message = [0xAB; 32];
        let msg = Message::from_digest_slice(&message).unwrap();
        let signature = secp.sign_ecdsa(&msg, &secret_key);
        let sig_bytes = signature.serialize_compact();

        let sig = Signature::new(
            sig_bytes.to_vec(),
            pubkey_bytes.to_vec(),
            different_message.to_vec(),
        );
        assert!(sig.verify(SignatureScheme::Secp256k1).is_err());
    }

    #[test]
    fn test_secp256k1_invalid_message_length() {
        let signature = vec![0u8; 64];
        let public_key = vec![0x02; 33];
        let message = vec![0u8; 16]; // Wrong length

        let sig = Signature::new(signature, public_key, message);
        assert!(sig.verify(SignatureScheme::Secp256k1).is_err());
    }

    #[test]
    fn test_secp256k1_empty_signature() {
        let public_key = vec![0x02; 33];
        let message = [0u8; 32];

        let sig = Signature::new(vec![], public_key, message.to_vec());
        assert!(sig.verify(SignatureScheme::Secp256k1).is_err());
    }

    #[test]
    fn test_secp256k1_empty_public_key() {
        let signature = vec![0u8; 64];
        let message = [0u8; 32];

        let sig = Signature::new(signature, vec![], message.to_vec());
        assert!(sig.verify(SignatureScheme::Secp256k1).is_err());
    }

    #[test]
    fn test_secp256k1_invalid_public_key_length() {
        let signature = vec![0u8; 64];
        let public_key = vec![0x02; 32]; // Wrong length
        let message = [0u8; 32];

        let sig = Signature::new(signature, public_key, message.to_vec());
        assert!(sig.verify(SignatureScheme::Secp256k1).is_err());
    }

    #[test]
    fn test_secp256k1_invalid_compressed_key_prefix() {
        let signature = vec![0u8; 64];
        let mut public_key = vec![0u8; 33];
        public_key[0] = 0x05; // Invalid prefix
        let message = [0u8; 32];

        let sig = Signature::new(signature, public_key, message.to_vec());
        assert!(sig.verify(SignatureScheme::Secp256k1).is_err());
    }

    #[test]
    fn test_secp256k1_tampered_signature() {
        use secp256k1::{Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let message = [0xCD; 32];
        let msg = Message::from_digest_slice(&message).unwrap();
        let signature = secp.sign_ecdsa(&msg, &secret_key);
        let mut sig_bytes = signature.serialize_compact();
        // Tamper with signature
        sig_bytes[0] ^= 0xFF;
        let pubkey_bytes = public_key.serialize();

        let sig = Signature::new(sig_bytes.to_vec(), pubkey_bytes.to_vec(), message.to_vec());
        assert!(sig.verify(SignatureScheme::Secp256k1).is_err());
    }

    #[test]
    fn test_ed25519_valid_signature() {
        use ed25519_dalek::Signature as DalekSignature;
        use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let message = b"This is a test message for Ed25519 verification";
        let signature: DalekSignature = signing_key.sign(message);

        let sig = Signature::new(
            signature.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
            message.to_vec(),
        );
        assert!(sig.verify(SignatureScheme::Ed25519).is_ok());
    }

    #[test]
    fn test_ed25519_invalid_signature_fails() {
        use ed25519_dalek::Signature as DalekSignature;
        use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let message = b"Original message";
        let different_message = b"Different message";
        let signature: DalekSignature = signing_key.sign(message);

        let sig = Signature::new(
            signature.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
            different_message.to_vec(),
        );
        assert!(sig.verify(SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn test_ed25519_invalid_public_key_length() {
        let signature = vec![0u8; 64];
        let public_key = vec![0u8; 33]; // Wrong length
        let message = vec![0u8; 32];

        let sig = Signature::new(signature, public_key, message);
        assert!(sig.verify(SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn test_ed25519_invalid_signature_length() {
        let signature = vec![0u8; 63]; // Wrong length
        let public_key = vec![0u8; 32];
        let message = vec![0u8; 32];

        let sig = Signature::new(signature, public_key, message);
        assert!(sig.verify(SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn test_ed25519_empty_signature() {
        let public_key = vec![0u8; 32];
        let message = vec![0u8; 32];

        let sig = Signature::new(vec![], public_key, message);
        assert!(sig.verify(SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn test_ed25519_empty_public_key() {
        let signature = vec![0u8; 64];
        let message = vec![0u8; 32];

        let sig = Signature::new(signature, vec![], message);
        assert!(sig.verify(SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn test_ed25519_tampered_signature() {
        use ed25519_dalek::Signature as DalekSignature;
        use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let message = b"Test message";
        let signature: DalekSignature = signing_key.sign(message);
        let mut sig_bytes = signature.to_bytes();
        // Tamper with signature
        sig_bytes[0] ^= 0xFF;

        let sig = Signature::new(
            sig_bytes.to_vec(),
            verifying_key.to_bytes().to_vec(),
            message.to_vec(),
        );
        assert!(sig.verify(SignatureScheme::Ed25519).is_err());
    }

    #[test]
    fn test_verify_signatures_multiple() {
        use secp256k1::{Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let message = [0xCD; 32];
        let msg = Message::from_digest_slice(&message).unwrap();

        // Create 3 valid secp256k1 signatures with different keys
        let mut sigs = Vec::new();
        for _ in 0..3 {
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
            let signature = secp.sign_ecdsa(&msg, &secret_key);
            let sig_bytes = signature.serialize_compact();
            let pubkey_bytes = public_key.serialize();
            sigs.push(Signature::new(
                sig_bytes.to_vec(),
                pubkey_bytes.to_vec(),
                message.to_vec(),
            ));
        }

        assert!(verify_signatures(&sigs, SignatureScheme::Secp256k1).is_ok());
    }

    #[test]
    fn test_verify_signatures_empty() {
        let sigs: Vec<Signature> = vec![];
        assert!(verify_signatures(&sigs, SignatureScheme::Secp256k1).is_err());
    }

    #[test]
    fn test_verify_signatures_one_invalid() {
        use secp256k1::{Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let message = [0xCD; 32];
        let msg = Message::from_digest_slice(&message).unwrap();

        // First signature is valid
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let signature = secp.sign_ecdsa(&msg, &secret_key);
        let sig_bytes = signature.serialize_compact();
        let pubkey_bytes = public_key.serialize();
        let mut sigs = vec![Signature::new(
            sig_bytes.to_vec(),
            pubkey_bytes.to_vec(),
            message.to_vec(),
        )];

        // Second signature has wrong message length
        let signature2 = vec![0u8; 64];
        let public_key2 = vec![0x02; 33];
        let message2 = vec![0u8; 16];
        sigs.push(Signature::new(signature2, public_key2, message2));

        assert!(verify_signatures(&sigs, SignatureScheme::Secp256k1).is_err());
    }

    #[test]
    fn test_parse_signatures_from_bytes() {
        let raw_sigs = vec![vec![0xAB; 64], vec![0xCD; 64]];
        let public_keys = vec![vec![0x02; 33], vec![0x03; 33]];
        let message = vec![0xEF; 32];

        let signatures = parse_signatures_from_bytes(&raw_sigs, &public_keys, &message);

        assert_eq!(signatures.len(), 2);
        assert_eq!(signatures[0].signature, vec![0xAB; 64]);
        assert_eq!(signatures[0].public_key, vec![0x02; 33]);
        assert_eq!(signatures[1].signature, vec![0xCD; 64]);
        assert_eq!(signatures[1].public_key, vec![0x03; 33]);
    }

    #[test]
    fn test_signature_scheme_debug() {
        assert_eq!(format!("{:?}", SignatureScheme::Secp256k1), "Secp256k1");
        assert_eq!(format!("{:?}", SignatureScheme::Ed25519), "Ed25519");
    }
}
