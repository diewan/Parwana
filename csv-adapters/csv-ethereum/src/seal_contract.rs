//! Ethereum seal contract interface
//!
//! This module defines the ABI and interface for the CSVSeal.sol contract
//! that manages single-use storage slot seals on Ethereum.
//!
//! The contract provides:
//! - `markSealUsed(sealId, commitment)` — consumes a seal and emits an event
//! - `isSealUsed(sealId) -> bool` — checks if a seal has been consumed
//! - `SealUsed(sealId, commitment)` — LOG event emitted when a seal is consumed

use tiny_keccak::{Hasher, Keccak};

/// Compute keccak256 at runtime (cached via once_cell pattern)
fn compute_keccak256(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

/// The `SealUsed` event signature: keccak256("SealUsed(bytes32,bytes32)")
/// Computed at runtime, cached for repeated use.
fn seal_used_signature() -> [u8; 32] {
    compute_keccak256(b"SealUsed(bytes32,bytes32)")
}

/// The canonical `SanadLocked` event signature.
fn sanad_locked_signature() -> [u8; 32] {
    compute_keccak256(b"SanadLocked(bytes32,bytes32,address,bytes32,bytes,uint256)")
}

/// The legacy `CrossChainLock` event emitted alongside `SanadLocked`.
/// Computed at runtime, cached for repeated use.
fn cross_chain_lock_signature() -> [u8; 32] {
    compute_keccak256(b"CrossChainLock(bytes32,bytes32,address,bytes32,bytes,uint256)")
}

/// The canonical `SanadCreated` event signature, emitted by `create_seal`.
/// `event SanadCreated(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint256 timestamp)`
fn sanad_created_signature() -> [u8; 32] {
    compute_keccak256(b"SanadCreated(bytes32,bytes32,address,uint256)")
}

/// The CSVSeal contract interface
///
/// Seal identifiers are 32-byte values. When consumed, they emit a LOG event
/// with the seal ID and the commitment hash.
#[derive(Default)]
pub struct CsvSealAbi;

impl CsvSealAbi {
    /// The `SealUsed` event signature (keccak256 of "SealUsed(bytes32,bytes32)")
    pub fn seal_used_event_signature() -> [u8; 32] {
        seal_used_signature()
    }

    /// The `CrossChainLock` event signature (keccak256 of "CrossChainLock(...)")
    pub fn cross_chain_lock_event_signature() -> [u8; 32] {
        cross_chain_lock_signature()
    }

    pub fn sanad_locked_event_signature() -> [u8; 32] {
        sanad_locked_signature()
    }

    /// The `SanadCreated` event signature (emitted by `create_seal`).
    pub fn sanad_created_event_signature() -> [u8; 32] {
        sanad_created_signature()
    }

    /// Encode the `lock_sanad(sanadId, commitment, destinationChain, destinationOwner)` calldata
    /// This is the public function for creating/locking a Sanad on Ethereum
    /// Note: Matches Solidity function signature: lock_sanad(bytes32,bytes32,bytes32,bytes)
    pub fn encode_lock_sanad(
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        destination_chain: [u8; 32],
        destination_owner: &[u8],
    ) -> Vec<u8> {
        // Function selector: keccak256("lock_sanad(bytes32,bytes32,bytes32,bytes)")[:4]
        let selector = compute_keccak256(b"lock_sanad(bytes32,bytes32,bytes32,bytes)");
        let dest_owner_len = destination_owner.len();
        let mut calldata = Vec::with_capacity(4 + 32 + 32 + 32 + 32 + dest_owner_len);
        calldata.extend_from_slice(&selector[..4]);

        // sanadId (offset 0x20)
        calldata.extend_from_slice(&sanad_id);

        // commitment (offset 0x40)
        calldata.extend_from_slice(&commitment);

        // destinationChain (offset 0x60) - bytes32, not uint8
        calldata.extend_from_slice(&destination_chain);

        // destinationOwner offset (offset 0x80)
        let mut offset_bytes = [0u8; 32];
        let offset: u32 = 0x80;
        offset_bytes[28..].copy_from_slice(&offset.to_be_bytes());
        calldata.extend_from_slice(&offset_bytes);

        // destinationOwner data (at offset 0x80)
        let mut len_bytes = [0u8; 32];
        // Length is encoded as a 32-byte big-endian integer
        let len = dest_owner_len as u64;
        len_bytes[24..].copy_from_slice(&len.to_be_bytes());
        calldata.extend_from_slice(&len_bytes);
        calldata.extend_from_slice(destination_owner);

        calldata
    }

    /// Encode the `create_seal(commitment, sealId)` calldata.
    ///
    /// This is the canonical Sanad-creation entrypoint: it anchors the
    /// commitment and sets `sanadStates[sealId] = Created`, keyed by `sealId`
    /// (which callers pass as the canonical `sanad_id`). Matches the Solidity
    /// signature `create_seal(bytes32,bytes32)` with argument order
    /// `(commitment, sealId)`.
    pub fn encode_create_seal(commitment: [u8; 32], seal_id: [u8; 32]) -> Vec<u8> {
        // Function selector: keccak256("create_seal(bytes32,bytes32)")[:4]
        let selector = compute_keccak256(b"create_seal(bytes32,bytes32)");
        let mut calldata = Vec::with_capacity(4 + 32 + 32);
        calldata.extend_from_slice(&selector[..4]);

        // commitment (offset 0x20)
        calldata.extend_from_slice(&commitment);

        // sealId (offset 0x40)
        calldata.extend_from_slice(&seal_id);

        calldata
    }

    /// Encode the `markSealUsed(sealId, commitment)` calldata
    /// This function consumes a seal and emits a SealUsed event
    pub fn encode_mark_seal_used(seal_id: [u8; 32], commitment: [u8; 32]) -> Vec<u8> {
        // Function selector: keccak256("markSealUsed(bytes32,bytes32)")[:4]
        let selector = compute_keccak256(b"markSealUsed(bytes32,bytes32)");
        let mut calldata = Vec::with_capacity(4 + 32 + 32);
        calldata.extend_from_slice(&selector[..4]);

        // sealId (offset 0x20)
        calldata.extend_from_slice(&seal_id);

        // commitment (offset 0x40)
        calldata.extend_from_slice(&commitment);

        calldata
    }

    /// Decode a `SealUsed` event from LOG data
    pub fn decode_seal_used_event(topics: &[[u8; 32]], data: &[u8]) -> Option<SealUsedEvent> {
        if topics.is_empty() {
            return None;
        }
        if topics[0] != Self::seal_used_event_signature() {
            return None;
        }
        if data.len() < 64 {
            return None;
        }

        let mut seal_id = [0u8; 32];
        seal_id.copy_from_slice(&data[..32]);

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&data[32..64]);

        Some(SealUsedEvent {
            seal_id,
            commitment,
        })
    }

    /// Check if a LOG entry matches the CSVSeal contract's SealUsed event
    pub fn matches_seal_used_event(
        address: &[u8; 20],
        contract_address: &[u8; 20],
        topics: &[[u8; 32]],
    ) -> bool {
        if address != contract_address {
            return false;
        }
        if topics.is_empty() {
            return false;
        }
        topics[0] == Self::seal_used_event_signature()
    }
}

/// Decoded SealUsed event
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealUsedEvent {
    pub seal_id: [u8; 32],
    pub commitment: [u8; 32],
}

/// The CSVSeal Solidity source (for reference)
pub const CSV_SEAL_SOL: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CSVSeal {
    mapping(bytes32 => bool) public usedSeals;

    event SealUsed(bytes32 indexed sealId, bytes32 commitment);

    function markSealUsed(bytes32 sealId, bytes32 commitment) external {
        require(!usedSeals[sealId], "Seal already used");
        usedSeals[sealId] = true;
        emit SealUsed(sealId, commitment);
    }

    function isSealUsed(bytes32 sealId) external view returns (bool) {
        return usedSeals[sealId];
    }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_mark_seal_used() {
        let calldata = CsvSealAbi::encode_mark_seal_used([1u8; 32], [2u8; 32]);
        assert_eq!(calldata.len(), 4 + 32 + 32);
    }

    #[test]
    fn test_decode_seal_used_event() {
        let seal_id = [1u8; 32];
        let commitment = [2u8; 32];

        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&seal_id);
        data.extend_from_slice(&commitment);

        let topics = vec![CsvSealAbi::seal_used_event_signature()];
        let event = CsvSealAbi::decode_seal_used_event(&topics, &data).unwrap();
        assert_eq!(event.seal_id, seal_id);
        assert_eq!(event.commitment, commitment);
    }

    #[test]
    fn test_decode_seal_used_wrong_signature() {
        let data = vec![0u8; 64];
        let topics = vec![[0xFF; 32]]; // Wrong signature
        assert!(CsvSealAbi::decode_seal_used_event(&topics, &data).is_none());
    }

    #[test]
    fn test_decode_seal_used_short_data() {
        let topics = vec![CsvSealAbi::seal_used_event_signature()];
        assert!(CsvSealAbi::decode_seal_used_event(&topics, &[0u8; 32]).is_none());
    }

    #[test]
    fn test_matches_seal_used_event() {
        let address = [1u8; 20];
        let contract = [1u8; 20];
        let topics = vec![CsvSealAbi::seal_used_event_signature()];

        assert!(CsvSealAbi::matches_seal_used_event(
            &address, &contract, &topics
        ));
    }

    #[test]
    fn test_matches_seal_used_wrong_address() {
        let address = [1u8; 20];
        let contract = [2u8; 20];
        let topics = vec![CsvSealAbi::seal_used_event_signature()];

        assert!(!CsvSealAbi::matches_seal_used_event(
            &address, &contract, &topics
        ));
    }

    #[test]
    fn test_encode_mark_seal_used_selector() {
        let calldata = CsvSealAbi::encode_mark_seal_used([1u8; 32], [2u8; 32]);
        assert_eq!(calldata.len(), 4 + 32 + 32);
        // Selector is first 4 bytes of keccak256("markSealUsed(bytes32,bytes32)")
        assert_ne!(&calldata[..4], &[0xDE, 0xAD, 0xBE, 0xEF]); // No longer temporary
    }

    #[test]
    fn test_seal_used_signature_is_valid_keccak() {
        let sig = CsvSealAbi::seal_used_event_signature();
        // Should not be all zeros or the old temporary value
        assert!(sig.iter().any(|&b| b != 0));
        assert_ne!(sig, [0u8; 32]);
    }

    #[test]
    fn deployed_lock_event_signatures_match_receipt_topics() {
        assert_eq!(
            hex::encode(CsvSealAbi::sanad_locked_event_signature()),
            "52c9f67ca4166f0d847d41f1534595f94ecbc4199343811303902a5c77809008"
        );
        assert_eq!(
            hex::encode(CsvSealAbi::cross_chain_lock_event_signature()),
            "985c262386f4528df2619b0f2d852de0df5d9b76cf6b8330a3fb561a607726de"
        );
    }
}
