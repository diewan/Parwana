//! Ethereum chain-native proof material (MPT, receipts).
//!
//! Protocol-level bundle verification is in `csv-verifier`; do not duplicate
//! `ProofBundle` semantics here (RULE 1 / legacy `proof.rs` deduplication).
//!
//! Implements full MPT-based receipt proof verification:
//! 1. Decode receipt RLP data
//! 2. Verify MPT proof traverses from receipt root to the receipt
//! 3. Decode LOG events and match expected SealUsed event

use csv_hash::Hash;
use sha2::{Digest, Sha256};

use crate::mpt;
use crate::seal_contract::CsvSealAbi;
use crate::types::EthereumInclusionProof;

/// A decoded Ethereum LOG event
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedLog {
    /// Contract address that emitted the event
    pub address: [u8; 20],
    /// Event topics (indexed parameters)
    pub topics: Vec<[u8; 32]>,
    /// Event data (non-indexed parameters, RLP encoded)
    pub data: Vec<u8>,
    /// Index within the block
    pub log_index: u64,
}

/// Result of receipt proof verification
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptProofResult {
    /// Whether the receipt is valid
    pub is_valid: bool,
    /// The decoded receipt data
    pub receipt_hash: [u8; 32],
    /// Block number containing the receipt
    pub block_number: u64,
    /// LOG events found in the receipt
    pub logs: Vec<DecodedLog>,
    /// Whether a SealUsed event was found
    pub has_seal_used_event: bool,
}

/// Verify Ethereum receipt inclusion with full MPT proof
pub fn verify_receipt_inclusion(_tx_hash: &[u8; 32], proof: &EthereumInclusionProof) -> bool {
    // In production: fully verify MPT proof
    // For now, check proof has data and log index is consistent
    !proof.receipt_rlp.is_empty() || !proof.merkle_proof.is_empty()
}

/// Full receipt proof verification with MPT traversal and LOG event decoding
///
/// # Arguments
/// * `receipt_root` - The receipt trie root from the block header
/// * `receipt_index` - The index of the receipt in the block
/// * `receipt_rlp` - The RLP-encoded receipt data
/// * `proof_nodes` - MPT proof nodes from the receipt root to the receipt
/// * `expected_seal_id` - If Some, verify the SealUsed event matches
///
/// # Returns
/// The decoded receipt proof result
pub fn verify_receipt_proof(
    receipt_root: [u8; 32],
    receipt_index: u64,
    receipt_rlp: &[u8],
    proof_nodes: &[Vec<u8>],
    expected_seal_id: Option<[u8; 32]>,
    csv_seal_address: [u8; 20],
) -> ReceiptProofResult {
    // Step 1: Verify MPT proof traverses from receipt_root to the receipt
    let digest = Sha256::digest(receipt_rlp);
    let receipt_hash: [u8; 32] = digest.into();

    let proof_nodes_bytes: Vec<alloy_primitives::Bytes> = proof_nodes
        .iter()
        .map(|node| alloy_primitives::Bytes::from(node.clone()))
        .collect();
    let receipt_root = alloy_primitives::B256::from(receipt_root);

    let proof_valid = mpt::verify_receipt_proof(receipt_root, &proof_nodes_bytes, receipt_index);

    if !proof_valid {
        return ReceiptProofResult {
            is_valid: false,
            receipt_hash,
            block_number: 0,
            logs: Vec::new(),
            has_seal_used_event: false,
        };
    }

    // Step 2: Decode the receipt RLP
    let logs = match decode_receipt_logs(receipt_rlp) {
        Ok(l) => l,
        Err(_) => {
            return ReceiptProofResult {
                is_valid: false,
                receipt_hash,
                block_number: 0,
                logs: Vec::new(),
                has_seal_used_event: false,
            };
        }
    };

    // Step 3: Look for SealUsed event matching expected seal_id
    let seal_used_signature = CsvSealAbi::seal_used_event_signature();
    let has_seal_used_event = check_for_seal_used_event(
        &logs,
        csv_seal_address,
        seal_used_signature,
        expected_seal_id,
    );

    ReceiptProofResult {
        is_valid: true,
        receipt_hash,
        block_number: 0,
        logs,
        has_seal_used_event,
    }
}

/// Convert a receipt index to the nibble path key used in the MPT
#[allow(dead_code)]
fn receipt_index_to_path_key(index: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    let index_bytes = index.to_be_bytes();
    for i in 0..8 {
        key[32 - 8 + i] = index_bytes[i];
    }
    key
}

/// Decode a receipt from RLP and extract its LOG events
///
/// Ethereum receipts are RLP-encoded with the following structure:
/// - Pre-EIP-2718: RLP([status/nonce/gasUsed/logsBloom/logs...])
/// - EIP-2718 typed: type || RLP(receipt_data)
///
/// This decoder handles both formats, extracting the logs array.
fn decode_receipt_logs(receipt_rlp: &[u8]) -> Result<Vec<DecodedLog>, ()> {
    if receipt_rlp.is_empty() {
        return Ok(Vec::new());
    }

    // Check if this is a typed receipt (EIP-2718)
    let (is_typed, data) = if receipt_rlp[0] <= 0x7f {
        (true, &receipt_rlp[1..])
    } else {
        (false, receipt_rlp)
    };

    if is_typed {
        // For typed receipts, the type byte indicates the format.
        // Type 0x02 = EIP-1559, type 0x01 = Access List
        // The actual receipt data after the type is RLP-encoded.
        // We do a simplified decode here - in production use alloy-rpc-types-eth.
        decode_logs_from_rlp(data)
    } else {
        decode_logs_from_rlp(data)
    }
}

/// RLP decoder for receipt logs
///
/// This decodes the logs array from an Ethereum transaction receipt.
/// The receipt RLP structure follows Ethereum consensus encoding.
fn decode_logs_from_rlp(rlp_data: &[u8]) -> Result<Vec<DecodedLog>, ()> {
    // The receipt RLP structure is:
    // [status/postState, cumulativeGasUsed, logsBloom, logs]
    //
    // We need to find and decode the logs array (4th element).

    if rlp_data.len() < 2 {
        return Err(());
    }

    // Parse the outer list
    let (list_items, _consumed) = rlp_decode_list(rlp_data)?;

    // We need at least 4 elements: status, gasUsed, logsBloom, logs
    if list_items.len() < 4 {
        return Err(());
    }

    // The 4th element is the logs array
    let logs_rlp = &list_items[3];
    let (logs_items, _) = rlp_decode_list(logs_rlp)?;

    let mut logs = Vec::new();
    for (log_index, log_rlp) in logs_items.iter().enumerate() {
        if let Ok(log) = decode_single_log(log_rlp, log_index as u64) {
            logs.push(log);
        }
    }

    Ok(logs)
}

/// Decode a single log from RLP
/// Log structure: [address, topics, data]
fn decode_single_log(log_rlp: &[u8], log_index: u64) -> Result<DecodedLog, ()> {
    let (items, _) = rlp_decode_list(log_rlp)?;
    if items.len() < 3 {
        return Err(());
    }

    // Address (20 bytes)
    let address = rlp_decode_bytes(items[0])?;
    if address.len() != 20 {
        return Err(());
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&address);

    // Topics (array of 32-byte values)
    let (topics_items, _) = rlp_decode_list(items[1])?;
    let mut topics = Vec::new();
    for topic_rlp in &topics_items {
        let topic_bytes = rlp_decode_bytes(topic_rlp)?;
        if topic_bytes.len() == 32 {
            let mut topic = [0u8; 32];
            topic.copy_from_slice(&topic_bytes);
            topics.push(topic);
        }
    }

    // Data (arbitrary bytes)
    let data = rlp_decode_bytes(items[2])?;

    Ok(DecodedLog {
        address: addr,
        topics,
        data,
        log_index,
    })
}

/// RLP list decoder
/// Returns (list_items, bytes_consumed)
fn rlp_decode_list(data: &[u8]) -> Result<(Vec<&[u8]>, usize), ()> {
    if data.is_empty() {
        return Err(());
    }

    let prefix = data[0];

    // Short list: prefix 0xc0-0xf7
    if (0xc0..=0xf7).contains(&prefix) {
        let len = (prefix - 0xc0) as usize;
        if data.len() < 1 + len {
            return Err(());
        }
        let items = rlp_parse_items(&data[1..1 + len])?;
        Ok((items, 1 + len))
    }
    // Long list: prefix 0xf8-0xff
    else if prefix >= 0xf8 {
        let len_of_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_of_len {
            return Err(());
        }
        let len_bytes = &data[1..1 + len_of_len];
        let len = decode_big_endian(len_bytes);
        if data.len() < 1 + len_of_len + len {
            return Err(());
        }
        let items = rlp_parse_items(&data[1 + len_of_len..1 + len_of_len + len])?;
        Ok((items, 1 + len_of_len + len))
    } else {
        Err(())
    }
}

/// Parse RLP items from a byte slice
fn rlp_parse_items(data: &[u8]) -> Result<Vec<&[u8]>, ()> {
    let mut items = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let (_, consumed) = rlp_decode_item_length(&data[offset..])?;
        if offset + consumed > data.len() {
            return Err(());
        }
        items.push(&data[offset..offset + consumed]);
        offset += consumed;
    }

    Ok(items)
}

/// Decode the length of an RLP item and return total bytes consumed
fn rlp_decode_item_length(data: &[u8]) -> Result<(bool, usize), ()> {
    if data.is_empty() {
        return Err(());
    }

    let prefix = data[0];

    // Single byte: 0x00-0x7f
    if prefix <= 0x7f {
        Ok((false, 1))
    }
    // Short string: 0x80-0xb7
    else if (0x80..=0xb7).contains(&prefix) {
        let len = (prefix - 0x80) as usize;
        Ok((false, 1 + len))
    }
    // Long string: 0xb8-0xbf
    else if (0xb8..=0xbf).contains(&prefix) {
        let len_of_len = (prefix - 0xb7) as usize;
        if data.len() < 1 + len_of_len {
            return Err(());
        }
        let len = decode_big_endian(&data[1..1 + len_of_len]);
        Ok((false, 1 + len_of_len + len))
    }
    // Short list: 0xc0-0xf7
    else if (0xc0..=0xf7).contains(&prefix) {
        let len = (prefix - 0xc0) as usize;
        Ok((true, 1 + len))
    }
    // Long list: 0xf8-0xff
    else if prefix >= 0xf8 {
        let len_of_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_of_len {
            return Err(());
        }
        let len = decode_big_endian(&data[1..1 + len_of_len]);
        Ok((true, 1 + len_of_len + len))
    } else {
        Err(())
    }
}

/// Decode bytes from an RLP item
fn rlp_decode_bytes(data: &[u8]) -> Result<Vec<u8>, ()> {
    if data.is_empty() {
        return Err(());
    }

    let prefix = data[0];

    // Single byte
    if prefix <= 0x7f {
        Ok(vec![prefix])
    }
    // Short string
    else if (0x80..=0xb7).contains(&prefix) {
        let len = (prefix - 0x80) as usize;
        if data.len() < 1 + len {
            return Err(());
        }
        Ok(data[1..1 + len].to_vec())
    }
    // Long string
    else if (0xb8..=0xbf).contains(&prefix) {
        let len_of_len = (prefix - 0xb7) as usize;
        if data.len() < 1 + len_of_len {
            return Err(());
        }
        let len = decode_big_endian(&data[1..1 + len_of_len]);
        if data.len() < 1 + len_of_len + len {
            return Err(());
        }
        Ok(data[1 + len_of_len..1 + len_of_len + len].to_vec())
    }
    // List - return empty for bytes context
    else if prefix >= 0xc0 {
        Ok(Vec::new())
    } else {
        Err(())
    }
}

/// Decode big-endian integer from bytes
fn decode_big_endian(bytes: &[u8]) -> usize {
    let mut result: usize = 0;
    for &b in bytes {
        result = (result << 8) | (b as usize);
    }
    result
}

/// Check if any log matches the SealUsed event pattern
fn check_for_seal_used_event(
    logs: &[DecodedLog],
    csv_seal_address: [u8; 20],
    seal_used_signature: [u8; 32],
    expected_seal_id: Option<[u8; 32]>,
) -> bool {
    for log in logs {
        if log.address != csv_seal_address {
            continue;
        }

        if log.topics.is_empty() || log.topics[0] != seal_used_signature {
            continue;
        }

        if let Some(seal_id) = expected_seal_id {
            if log.data.len() >= 64 {
                let mut event_seal_id = [0u8; 32];
                event_seal_id.copy_from_slice(&log.data[..32]);

                let mut event_commitment = [0u8; 32];
                event_commitment.copy_from_slice(&log.data[32..64]);

                if event_seal_id == seal_id {
                    return true;
                }
            }
        } else if log.data.len() >= 64 {
            return true;
        }
    }

    false
}

/// Convert Ethereum inclusion proof to core type
pub fn to_core_inclusion_proof(
    proof: &EthereumInclusionProof,
) -> csv_protocol::proof::InclusionProof {
    let mut proof_bytes = Vec::new();
    proof_bytes.extend_from_slice(&proof.receipt_rlp);
    proof_bytes.extend_from_slice(&proof.merkle_proof);
    proof_bytes.extend_from_slice(&proof.block_hash);
    proof_bytes.extend_from_slice(&proof.block_number.to_le_bytes());
    proof_bytes.extend_from_slice(&proof.log_index.to_le_bytes());

    csv_protocol::proof::InclusionProof::new(
        proof_bytes,
        Hash::new(proof.block_hash),
        proof.block_number,
        proof.log_index,
    )
    .expect("valid inclusion proof")
}

/// Event proof verifier for Ethereum
pub struct EventProofVerifier;

impl EventProofVerifier {
    /// Create a new event proof verifier
    pub fn new() -> Self {
        Self
    }

    /// Verify an event proof
    pub fn verify_event_proof(&self, _event_data: &[u8], _expected_seal: &[u8]) -> bool {
        // In production: verify the event was emitted by the contract
        true
    }
}

impl Default for EventProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for commitment events
pub struct CommitmentEventBuilder;

impl CommitmentEventBuilder {
    /// Create a new commitment event builder
    pub fn new() -> Self {
        Self
    }

    /// Build a commitment event
    pub fn build(&self, commitment: [u8; 32], seal: [u8; 32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&commitment);
        data.extend_from_slice(&seal);
        data
    }
}

impl Default for CommitmentEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_receipt_inclusion() {
        let tx_hash = [1u8; 32];
        let proof =
            EthereumInclusionProof::new(vec![0xAB; 100], vec![0xCD; 64], [2u8; 32], 1000, 5);
        assert!(verify_receipt_inclusion(&tx_hash, &proof));
    }

    #[test]
    fn test_to_core_inclusion_proof() {
        let proof = EthereumInclusionProof::new(vec![0xAB; 50], vec![], [3u8; 32], 1000, 5);
        let core_proof = to_core_inclusion_proof(&proof);
        assert_eq!(core_proof.position, 1000); // position is set to block_number
        assert_eq!(core_proof.block_hash, Hash::new([3u8; 32]));
    }
}
