//! Ethereum Sanad Contract Interfaces
//!
//! This module provides ABI encoding/decoding for the CSVLock.sol and CSVMint.sol
//! contracts that manage cross-chain sanad operations on Ethereum.

use tiny_keccak::{Hasher, Keccak};

/// Compute keccak256 hash for Ethereum ABI selectors and event signatures.
///
/// Solidity uses raw keccak256 for function/event signatures. Domain separation
/// is achieved through the function/event signature strings themselves (e.g.,
/// "lockSanad(bytes32,bytes32,uint8,bytes)" is distinct from "mintSanad(...)").
fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// CSVLock contract ABI
///
/// Manages locking and refunding of sanads for cross-chain transfers.
#[derive(Default)]
pub struct CsvLockAbi;

impl CsvLockAbi {
    /// Function selector for lockSanad(bytes32,bytes32,uint8,bytes)
    pub fn encode_lock_sanad(
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        destination_chain: u8,
        destination_owner: &[u8],
    ) -> Vec<u8> {
        // selector = keccak256("lockSanad(bytes32,bytes32,uint8,bytes)")[:4]
        let selector = keccak256(b"lockSanad(bytes32,bytes32,uint8,bytes)");
        let mut calldata = Vec::with_capacity(
            4 + 32 + 32 + 32 + 32 + destination_owner.len().next_multiple_of(32),
        );

        // Function selector
        calldata.extend_from_slice(&selector[..4]);

        // sanad_id (bytes32)
        calldata.extend_from_slice(&sanad_id);

        // commitment (bytes32)
        calldata.extend_from_slice(&commitment);

        // destination_chain (uint8) - padded to 32 bytes
        calldata.extend_from_slice(&[0u8; 31]);
        calldata.push(destination_chain);

        // destination_owner (bytes) - offset to dynamic data
        let data_offset = 4 + 32 + 32 + 32 + 32; // 4 + 4 * 32 = 132
        calldata.extend_from_slice(&[0u8; 29]);
        calldata.extend_from_slice(&(data_offset as u32).to_be_bytes());

        // Dynamic data: length + padded bytes
        let owner_len = destination_owner.len();
        calldata.extend_from_slice(&(owner_len as u32).to_be_bytes());
        calldata.extend_from_slice(&[0u8; 28]);

        // Owner bytes with padding
        calldata.extend_from_slice(destination_owner);
        let padding = (32 - (owner_len % 32)) % 32;
        calldata.extend_from_slice(&vec![0u8; padding]);

        calldata
    }

    /// Function selector for refundSanad(bytes32,bytes32)
    pub fn encode_refund_sanad(sanad_id: [u8; 32], destination_owner_hash: [u8; 32]) -> Vec<u8> {
        let selector = keccak256(b"refundSanad(bytes32,bytes32)");
        let mut calldata = Vec::with_capacity(4 + 32 + 32);
        calldata.extend_from_slice(&selector[..4]);
        calldata.extend_from_slice(&sanad_id);
        calldata.extend_from_slice(&destination_owner_hash);
        calldata
    }

    /// Function selector for isSealUsed(bytes32) -> bool
    pub fn encode_is_seal_used(seal_id: [u8; 32]) -> Vec<u8> {
        let selector = keccak256(b"isSealUsed(bytes32)");
        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&selector[..4]);
        calldata.extend_from_slice(&seal_id);
        calldata
    }

    /// Function selector for getLockInfo(bytes32)
    pub fn encode_get_lock_info(sanad_id: [u8; 32]) -> Vec<u8> {
        let selector = keccak256(b"getLockInfo(bytes32)");
        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&selector[..4]);
        calldata.extend_from_slice(&sanad_id);
        calldata
    }

    /// Decode isSealUsed response
    pub fn decode_is_seal_used_response(data: &[u8]) -> Option<bool> {
        if data.len() < 32 {
            return None;
        }
        // bool is the last byte of the 32-byte word
        Some(data[31] != 0)
    }
}

/// CSVMint contract ABI
///
/// Manages minting of sanads from cross-chain transfers.
#[derive(Default)]
pub struct CsvMintAbi;

impl CsvMintAbi {
    /// Function selector for mintSanad(bytes32,bytes32,bytes32,uint8,bytes,bytes,bytes32)
    #[allow(clippy::too_many_arguments)]
    pub fn encode_mint_sanad(
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        state_root: [u8; 32],
        source_chain: u8,
        source_seal_point: &[u8],
        proof: &[u8],
        proof_root: [u8; 32],
    ) -> Vec<u8> {
        // Calculate offsets for dynamic data
        let static_params_end = 4 + 7 * 32; // 4 + 7 * 32 = 228
        let source_seal_offset = static_params_end;
        let proof_offset = static_params_end + 32 + source_seal_point.len().next_multiple_of(32);

        let selector = keccak256(b"mintSanad(bytes32,bytes32,bytes32,uint8,bytes,bytes,bytes32)");
        let mut calldata = Vec::new();

        // Function selector
        calldata.extend_from_slice(&selector[..4]);

        // sanad_id
        calldata.extend_from_slice(&sanad_id);

        // commitment
        calldata.extend_from_slice(&commitment);

        // state_root
        calldata.extend_from_slice(&state_root);

        // source_chain (uint8 padded)
        calldata.extend_from_slice(&[0u8; 31]);
        calldata.push(source_chain);

        // source_seal_point offset
        calldata.extend_from_slice(&[0u8; 28]);
        calldata.extend_from_slice(&(source_seal_offset as u32).to_be_bytes());

        // proof offset
        calldata.extend_from_slice(&[0u8; 28]);
        calldata.extend_from_slice(&(proof_offset as u32).to_be_bytes());

        // proof_root
        calldata.extend_from_slice(&proof_root);

        // Dynamic data: source_seal_point
        let seal_len = source_seal_point.len();
        calldata.extend_from_slice(&(seal_len as u32).to_be_bytes());
        calldata.extend_from_slice(&[0u8; 28]);
        calldata.extend_from_slice(source_seal_point);
        let seal_padding = (32 - (seal_len % 32)) % 32;
        calldata.extend_from_slice(&vec![0u8; seal_padding]);

        // Dynamic data: proof
        let proof_len = proof.len();
        calldata.extend_from_slice(&(proof_len as u32).to_be_bytes());
        calldata.extend_from_slice(&[0u8; 28]);
        calldata.extend_from_slice(proof);
        let proof_padding = (32 - (proof_len % 32)) % 32;
        calldata.extend_from_slice(&vec![0u8; proof_padding]);

        calldata
    }

    /// Function selector for isSanadMinted(bytes32) -> bool
    pub fn encode_is_sanad_minted(sanad_id: [u8; 32]) -> Vec<u8> {
        let selector = keccak256(b"isSanadMinted(bytes32)");
        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&selector[..4]);
        calldata.extend_from_slice(&sanad_id);
        calldata
    }

    /// Decode isSanadMinted response
    pub fn decode_is_sanad_minted_response(data: &[u8]) -> Option<bool> {
        if data.len() < 32 {
            return None;
        }
        Some(data[31] != 0)
    }
}

/// CrossChainLock event signature
pub fn cross_chain_lock_signature() -> [u8; 32] {
    keccak256(b"CrossChainLock(bytes32,bytes32,address,uint8,bytes,bytes32,uint8,bytes32,bytes32,uint8,bytes32)")
}

/// SanadMinted event signature
pub fn sanad_minted_signature() -> [u8; 32] {
    keccak256(
        b"SanadMinted(bytes32,bytes32,address,uint8,bytes,uint8,bytes32,bytes32,uint8,bytes32)",
    )
}

/// SanadRefunded event signature
pub fn sanad_refunded_signature() -> [u8; 32] {
    keccak256(b"SanadRefunded(bytes32,bytes32,address,uint256)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_lock_sanad() {
        let sanad_id = [1u8; 32];
        let commitment = [2u8; 32];
        let destination_owner = b"0x1234567890abcdef";

        let calldata = CsvLockAbi::encode_lock_sanad(
            sanad_id,
            commitment,
            5, // destination chain
            destination_owner,
        );

        // Should have at least selector + 4 * 32 bytes of static params + dynamic data
        assert!(calldata.len() >= 68);

        // Check selector is correct
        let expected_selector = &keccak256(b"lockSanad(bytes32,bytes32,uint8,bytes)")[..4];
        assert_eq!(&calldata[..4], expected_selector);
    }

    #[test]
    fn test_encode_refund_sanad() {
        let sanad_id = [1u8; 32];
        let owner_hash = [2u8; 32];

        let calldata = CsvLockAbi::encode_refund_sanad(sanad_id, owner_hash);

        assert_eq!(calldata.len(), 68); // 4 + 32 + 32

        let expected_selector = &keccak256(b"refundSanad(bytes32,bytes32)")[..4];
        assert_eq!(&calldata[..4], expected_selector);
    }

    #[test]
    fn test_encode_mint_sanad() {
        let sanad_id = [1u8; 32];
        let commitment = [2u8; 32];
        let state_root = [3u8; 32];
        let proof_root = [4u8; 32];
        let source_seal = b"seal123";
        let proof = b"proof123";

        let calldata = CsvMintAbi::encode_mint_sanad(
            sanad_id,
            commitment,
            state_root,
            1, // source chain
            source_seal,
            proof,
            proof_root,
        );

        assert!(calldata.len() > 228); // At least static params size

        let expected_selector =
            &keccak256(b"mintSanad(bytes32,bytes32,bytes32,uint8,bytes,bytes,bytes32)")[..4];
        assert_eq!(&calldata[..4], expected_selector);
    }

    #[test]
    fn test_decode_bool_response() {
        let mut true_data = vec![0u8; 32];
        true_data[31] = 1;
        assert_eq!(
            CsvLockAbi::decode_is_seal_used_response(&true_data),
            Some(true)
        );

        let false_data = vec![0u8; 32];
        assert_eq!(
            CsvLockAbi::decode_is_seal_used_response(&false_data),
            Some(false)
        );

        assert_eq!(CsvLockAbi::decode_is_seal_used_response(&[0u8; 16]), None);
    }
}
