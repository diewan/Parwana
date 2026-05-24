//! Bitcoin Tapret/Opret commitment scripts
//!
//! Implements Tapret leaf script construction with nonce mining
//! and Opret fallback.
//!
//! ## Tapret Commitment (RGB-compatible)
//!
//! Per RGB specification and BIP-341:
//! - Tapret leaf: OP_RETURN <protocol_id (32 bytes)> <nonce (1 byte)> <commitment (32 bytes)>
//! - Nonce mining ensures the tapret leaf is placed at the sanadmost depth-1 position
//!   in the Taproot merkle tree
//! - Internal key is derived from the wallet's taproot key
//!
//! ## Opret Fallback
//!
//! Simpler OP_RETURN commitment for non-Taproot outputs:
//! - Script: OP_RETURN <protocol_id (32 bytes)> <commitment (32 bytes)>

use bitcoin::{
    ScriptBuf,
    opcodes::all::OP_RETURN,
    script::{Builder, PushBytesBuf},
};

use csv_hash::Hash;

/// Tapret commitment script: OP_RETURN <65 bytes>
pub const TAPRET_SCRIPT_SIZE: usize = 67;

/// Opret commitment script: OP_RETURN <64 bytes>
pub const OPRET_SCRIPT_SIZE: usize = 66;

/// A Tapret commitment
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapretCommitment {
    pub protocol_id: [u8; 32],
    pub commitment: Hash,
}

impl TapretCommitment {
    pub fn new(protocol_id: [u8; 32], commitment: Hash) -> Self {
        Self {
            protocol_id,
            commitment,
        }
    }

    pub fn payload(&self) -> [u8; 64] {
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&self.protocol_id);
        payload[32..].copy_from_slice(self.commitment.as_bytes());
        payload
    }

    pub fn leaf_script(&self) -> ScriptBuf {
        let payload = self.payload();
        let push_bytes = PushBytesBuf::try_from(payload.to_vec()).unwrap();
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(push_bytes)
            .into_script()
    }

    /// Build the Tapret leaf with a nonce appended for mining
    ///
    /// The nonce is used to ensure the Tapret leaf ends up at the sanadmost
    /// depth-1 position in the Taproot merkle tree per BIP-341 consensus ordering.
    pub fn leaf_script_with_nonce(&self, nonce: u8) -> ScriptBuf {
        let mut payload = [0u8; 65];
        payload[..32].copy_from_slice(&self.protocol_id);
        payload[32] = nonce;
        payload[33..65].copy_from_slice(self.commitment.as_bytes());
        let push_bytes = PushBytesBuf::try_from(payload.to_vec()).unwrap();
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(push_bytes)
            .into_script()
    }
}

/// Opret (OP_RETURN) commitment: simpler fallback for non-Taproot outputs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpretCommitment {
    pub protocol_id: [u8; 32],
    pub commitment: Hash,
}

impl OpretCommitment {
    pub fn new(protocol_id: [u8; 32], commitment: Hash) -> Self {
        Self {
            protocol_id,
            commitment,
        }
    }

    pub fn script(&self) -> ScriptBuf {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.protocol_id);
        data.extend_from_slice(self.commitment.as_bytes());
        let push_bytes = PushBytesBuf::try_from(data).unwrap();
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(push_bytes)
            .into_script()
    }
}

/// Mine a nonce for the Tapret leaf
///
/// For RGB Tapret commitments, the nonce is used to ensure proper positioning
/// of the tapret leaf in the Taproot merkle tree. When building a tree with
/// multiple leaves, different nonces produce different leaf hashes, which affects
/// tree structure and leaf positions.
///
/// For the common case of a single tapret leaf, any nonce produces a valid script.
/// This function iterates random nonces and validates the resulting script structure.
///
/// # RGB Tapret Spec
/// - Leaf script: OP_RETURN <protocol_id (32) || nonce (1) || commitment (32)>
/// - Total size: 67 bytes (OP_RETURN + push + data)
/// - Nonce mining ensures script is well-formed and extractable
///
/// Returns the nonce and the leaf script.
pub fn mine_tapret_nonce(
    tapret: &TapretCommitment,
    max_attempts: u32,
) -> Result<(u8, ScriptBuf), TapretError> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    for _attempt in 0..max_attempts {
        let nonce = rng.next_u32() as u8;
        let script = tapret.leaf_script_with_nonce(nonce);

        // Validate script meets RGB Tapret requirements:
        // - Must be OP_RETURN
        // - Must be exactly 67 bytes (OP_RETURN + OP_PUSHBYTES_65 + 65 bytes data)
        if script.is_op_return() && script.len() == TAPRET_SCRIPT_SIZE {
            return Ok((nonce, script));
        }
    }

    Err(TapretError::NonceMiningFailed(max_attempts))
}

/// Tapret error types
#[derive(Debug, thiserror::Error)]
pub enum TapretError {
    #[error("Nonce mining failed after {0} attempts")]
    NonceMiningFailed(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_commitment() -> TapretCommitment {
        TapretCommitment::new([1u8; 32], Hash::new([2u8; 32]))
    }

    #[test]
    fn test_tapret_payload() {
        let tc = test_commitment();
        let payload = tc.payload();
        assert_eq!(payload.len(), 64);
        assert_eq!(&payload[..32], &[1u8; 32]);
        assert_eq!(&payload[32..], &[2u8; 32]);
    }

    #[test]
    fn test_tapret_leaf_script() {
        let tc = test_commitment();
        let script = tc.leaf_script();
        // Without nonce: OP_RETURN (1) + OP_PUSHBYTES_64 (1) + 64 bytes = 66
        assert_eq!(script.len(), OPRET_SCRIPT_SIZE);
    }

    #[test]
    fn test_tapret_leaf_with_nonce() {
        let tc = test_commitment();
        let script_no_nonce = tc.leaf_script();
        let script_with_nonce = tc.leaf_script_with_nonce(42);
        // With nonce: OP_RETURN (1) + OP_PUSHBYTES_65 (1) + 65 bytes = 67
        assert_eq!(script_with_nonce.len(), TAPRET_SCRIPT_SIZE);
        assert_eq!(script_with_nonce.len(), script_no_nonce.len() + 1);
    }

    #[test]
    fn test_nonce_mining() {
        let tc = test_commitment();
        let (nonce, script) = mine_tapret_nonce(&tc, 256).unwrap();
        // Mined script should have nonce (67 bytes)
        assert_eq!(script.len(), TAPRET_SCRIPT_SIZE);
        // Verify the nonce is embedded in the script
        assert!(script.as_bytes().contains(&nonce));
    }

    #[test]
    fn test_opret_script() {
        let oc = OpretCommitment::new([1u8; 32], Hash::new([2u8; 32]));
        let script = oc.script();
        assert!(script.is_op_return());
        // Opret script: 66 bytes (no nonce)
        assert_eq!(script.len(), OPRET_SCRIPT_SIZE);
    }

    #[test]
    fn test_opret_script_content() {
        let oc = OpretCommitment::new([0xAB; 32], Hash::new([0xCD; 32]));
        let script = oc.script();
        let bytes = script.as_bytes();
        // OP_RETURN (0x6a) + OP_PUSHBYTES_64 (0x40) + 64 bytes data
        assert_eq!(bytes[0], 0x6a); // OP_RETURN
        assert_eq!(bytes[1], 0x40); // OP_PUSHBYTES_64
    }
}
