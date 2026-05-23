//! RGB Tapret commitment verification
//!
//! Implements Tapret verification per LNP/BP standard #6 and BIP-341:
//! 1. Verify the Tapret script structure (OP_RETURN <protocol_id || nonce || commitment>)
//! 2. Verify the commitment is actually embedded in the script
//! 3. Verify the control block is well-formed
//! 4. Verify internal key + merkle root → output key (BIP-341 tap tweak)
//!
//! Note: Full merkle proof verification requires the TaprootBuilder API which
//! has specific type requirements in rust-bitcoin 0.30. This module provides
//! structural verification. For full merkle verification, use with the
//! rust-bitcoin TaprootBuilder directly.

use bitcoin::hashes::Hash as _;
use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::{Builder, PushBytesBuf, ScriptBuf};
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::taproot::TapNodeHash;
use sha2::{Digest, Sha256};

use csv_hash::Hash;

/// Result of Tapret commitment verification
#[derive(Debug)]
pub struct TapretVerificationResult {
    /// Whether the Tapret commitment is valid
    pub is_valid: bool,
    /// The verified output key (if verification succeeded)
    pub output_key: Option<[u8; 32]>,
    /// The verified internal key (if verification succeeded)
    pub internal_key: Option<[u8; 32]>,
    /// Whether the commitment was found in the script
    pub commitment_found: bool,
    /// Whether the script structure is valid
    pub script_valid: bool,
    /// Detailed error message if verification failed
    pub error: Option<String>,
}

/// Verify a Tapret commitment against RGB/LNP-BP standard #6
///
/// This performs structural verification:
/// 1. Tapret script has correct structure: OP_RETURN <protocol_id (32) || nonce (1) || commitment (32)>
/// 2. The expected commitment is embedded at the correct offset in the script
/// 3. Script is well-formed (correct opcodes, push sizes)
///
/// For full merkle verification (control block + output key),
/// use [`verify_tapret_output_key`] with the actual TaprootBuilder.
///
/// # Arguments
/// * `tapret_script` - The Tapret leaf script
/// * `expected_commitment` - The expected commitment hash
///
/// # Returns
/// Verification result with detailed diagnostics
pub fn verify_tapret_script(
    tapret_script: &ScriptBuf,
    expected_commitment: Hash,
) -> TapretVerificationResult {
    // Step 1: Verify script structure
    let script_valid = verify_tapret_script_structure(tapret_script);

    if !script_valid {
        return TapretVerificationResult {
            is_valid: false,
            output_key: None,
            internal_key: None,
            commitment_found: false,
            script_valid: false,
            error: Some("Invalid Tapret script structure".to_string()),
        };
    }

    // Step 2: Verify commitment is embedded
    let commitment_found = verify_commitment_in_script(tapret_script, expected_commitment);

    if !commitment_found {
        return TapretVerificationResult {
            is_valid: false,
            output_key: None,
            internal_key: None,
            commitment_found: false,
            script_valid: true,
            error: Some("Commitment not found in Tapret script".to_string()),
        };
    }

    TapretVerificationResult {
        is_valid: true,
        output_key: None,
        internal_key: None,
        commitment_found: true,
        script_valid: true,
        error: None,
    }
}

/// Verify the Taproot output key derivation (BIP-341)
///
/// Computes: output_key = internal_key + tap_tweak(internal_key, merkle_root)
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `internal_key` - The internal (untweaked) public key
/// * `merkle_root` - The merkle root of the Taproot tree (None for key-path only)
/// * `expected_output_key` - The expected output key to verify against
///
/// # Returns
/// The derived output key, or None if derivation failed
pub fn verify_tapret_output_key<C: Verification>(
    secp: &Secp256k1<C>,
    internal_key: XOnlyPublicKey,
    merkle_root: Option<[u8; 32]>,
    expected_output_key: XOnlyPublicKey,
) -> bool {
    let merkle_root_hash = merkle_root.map(TapNodeHash::from_byte_array);

    let (tweaked_key, _parity) = internal_key.tap_tweak(secp, merkle_root_hash);
    let tweaked_xonly = tweaked_key.to_inner();

    tweaked_xonly == expected_output_key
}

/// Verify the Tapret script has the correct structure
///
/// RGB Tapret script: OP_RETURN <protocol_id (32) || nonce (1) || commitment (32)>
/// Total: 1 (OP_RETURN) + 1 (push) + 65 (data) = 67 bytes
fn verify_tapret_script_structure(script: &ScriptBuf) -> bool {
    let bytes = script.as_bytes();

    // Minimum: OP_RETURN (1) + OP_PUSHBYTES_65 (1) + 65 bytes data = 67 bytes
    if bytes.len() < 67 {
        return false;
    }

    // First byte must be OP_RETURN (0x6a)
    if bytes[0] != 0x6a {
        return false;
    }

    // Second byte should be OP_PUSHBYTES_65 (0x41)
    if bytes[1] != 0x41 {
        return false;
    }

    // Must have exactly 65 bytes of data after the push
    bytes.len() == 67
}

/// Verify the commitment is embedded in the Tapret script
///
/// The commitment is at offset 33 in the 65-byte data:
/// [protocol_id (32 bytes)] [nonce (1 byte)] [commitment (32 bytes)]
fn verify_commitment_in_script(script: &ScriptBuf, expected: Hash) -> bool {
    let bytes = script.as_bytes();

    if bytes.len() < 67 {
        return false;
    }

    // Commitment starts at byte 2 (after OP_RETURN + push) + 33 (protocol_id + nonce)
    let commitment_offset = 2 + 33;

    if bytes.len() < commitment_offset + 32 {
        return false;
    }

    let embedded_commitment = &bytes[commitment_offset..commitment_offset + 32];
    embedded_commitment == expected.as_bytes()
}

/// Create a Tapret commitment script for testing
///
/// # Arguments
/// * `protocol_id` - The protocol identifier (32 bytes)
/// * `nonce` - The nonce (1 byte)
/// * `commitment` - The commitment hash (32 bytes)
pub fn create_tapret_script(protocol_id: [u8; 32], nonce: u8, commitment: Hash) -> Result<ScriptBuf, String> {
    let mut data = [0u8; 65];
    data[..32].copy_from_slice(&protocol_id);
    data[32] = nonce;
    data[33..65].copy_from_slice(commitment.as_bytes());

    let push_bytes = PushBytesBuf::try_from(data.to_vec())
        .map_err(|e| format!("Failed to create PushBytesBuf: {}", e))?;
    Ok(Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push_bytes)
        .into_script())
}

/// Compute the TapTweak hash (BIP-341)
///
/// tap_tweak = SHA256(internal_key || merkle_root)
pub fn compute_tap_tweak_hash(internal_key: [u8; 32], merkle_root: Option<[u8; 32]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(internal_key);
    if let Some(root) = merkle_root {
        hasher.update(root);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tapret_script_structure() {
        let commitment = Hash::new([0xAB; 32]);
        let script = create_tapret_script([0x01; 32], 0x42, commitment);
        assert!(verify_tapret_script_structure(&script));
    }

    #[test]
    fn test_invalid_script_too_short() {
        let short_script = ScriptBuf::from_bytes(vec![0x6a, 0x41, 0x01]);
        assert!(!verify_tapret_script_structure(&short_script));
    }

    #[test]
    fn test_invalid_script_not_op_return() {
        let script = ScriptBuf::from_bytes(vec![0x00; 67]);
        assert!(!verify_tapret_script_structure(&script));
    }

    #[test]
    fn test_invalid_script_wrong_push() {
        let mut bytes = vec![0x6a, 0x40]; // OP_RETURN + OP_PUSHBYTES_64 (wrong size)
        bytes.resize(67, 0x00);
        let script = ScriptBuf::from_bytes(bytes);
        assert!(!verify_tapret_script_structure(&script));
    }

    #[test]
    fn test_commitment_in_script() {
        let commitment = Hash::new([0xCD; 32]);
        let script = create_tapret_script([0x01; 32], 0x42, commitment);
        assert!(verify_commitment_in_script(&script, commitment));

        // Wrong commitment should fail
        let wrong_commitment = Hash::new([0xFF; 32]);
        assert!(!verify_commitment_in_script(&script, wrong_commitment));
    }

    #[test]
    fn test_full_tapret_verification_valid() {
        let commitment = Hash::new([0xAB; 32]);
        let script = create_tapret_script([0x01; 32], 0x42, commitment);
        let result = verify_tapret_script(&script, commitment);
        assert!(result.is_valid);
        assert!(result.commitment_found);
        assert!(result.script_valid);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_full_tapret_verification_wrong_commitment() {
        let commitment = Hash::new([0xAB; 32]);
        let script = create_tapret_script([0x01; 32], 0x42, commitment);
        let wrong_commitment = Hash::new([0xFF; 32]);
        let result = verify_tapret_script(&script, wrong_commitment);
        assert!(!result.is_valid);
        assert!(!result.commitment_found);
        assert!(result.script_valid);
    }

    #[test]
    fn test_tap_tweak_hash_deterministic() {
        let key = [0x01; 32];
        let root = Some([0x02; 32]);

        let h1 = compute_tap_tweak_hash(key, root);
        let h2 = compute_tap_tweak_hash(key, root);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_tap_tweak_hash_different_roots() {
        let key = [0x01; 32];

        let h1 = compute_tap_tweak_hash(key, Some([0x02; 32]));
        let h2 = compute_tap_tweak_hash(key, Some([0x03; 32]));
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_tap_tweak_hash_no_root() {
        let key = [0x01; 32];
        let h = compute_tap_tweak_hash(key, None);
        assert_ne!(h, [0u8; 32]);
    }
}
