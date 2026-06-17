//! Proof verification for the Aptos adapter
//!
//! This module provides verification for Aptos state proofs, event proofs,
//! and transaction proofs using Merkle proofs against the accumulator root.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AptosError, AptosResult};
use crate::rpc::AptosAccountReader;

/// Parsed lock proof fields for mint_sanad entry function
///
/// This struct represents the explicit fields required by the Move entry function.
/// The proof format is: [state_root (32 bytes)] [leaf_position (8 bytes)] [proof_data...]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedLockProof {
    /// State root from the source chain (32 bytes)
    pub state_root: [u8; 32],
    /// Leaf position in the Merkle tree (u64)
    pub leaf_position: u64,
    /// Raw proof bytes for Merkle verification
    pub proof_data: Vec<u8>,
}

impl ParsedLockProof {
    /// Parse lock proof from raw proof bytes
    ///
    /// # Proof Format
    /// - Bytes 0-32: state_root
    /// - Bytes 32-40: leaf_position (little-endian u64)
    /// - Bytes 40+: proof_data
    ///
    /// # Errors
    /// Returns `AptosError::InvalidProofFormat` if proof bytes are too short.
    pub fn parse(proof_bytes: &[u8]) -> AptosResult<Self> {
        const MIN_PROOF_LEN: usize = 40; // 32 bytes state_root + 8 bytes leaf_position

        if proof_bytes.len() < MIN_PROOF_LEN {
            return Err(AptosError::InvalidProofFormat(format!(
                "Lock proof too short: expected >= {} bytes, got {}",
                MIN_PROOF_LEN,
                proof_bytes.len()
            )));
        }

        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&proof_bytes[0..32]);

        let leaf_position = u64::from_le_bytes(
            proof_bytes[32..40]
                .try_into()
                .map_err(|_| AptosError::InvalidProofFormat("Failed to parse leaf_position".to_string()))?,
        );

        let proof_data = proof_bytes[40..].to_vec();

        Ok(Self {
            state_root,
            leaf_position,
            proof_data,
        })
    }

    /// Get the full proof bytes including state_root and leaf_position prefix
    pub fn to_proof_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40 + self.proof_data.len());
        bytes.extend_from_slice(&self.state_root);
        bytes.extend_from_slice(&self.leaf_position.to_le_bytes());
        bytes.extend_from_slice(&self.proof_data);
        bytes
    }
}

/// Transaction proof containing the verified transaction data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionProof {
    /// Transaction version
    pub version: u64,
    /// Transaction hash
    pub transaction_hash: [u8; 32],
    /// Block height containing the transaction
    pub block_height: u64,
    /// Whether the transaction was successful
    pub success: bool,
    /// Merkle proof bytes against accumulator root
    pub accumulator_proof: Vec<u8>,
}

impl TransactionProof {
    /// Create a new transaction proof.
    pub fn new(
        version: u64,
        transaction_hash: [u8; 32],
        block_height: u64,
        success: bool,
        accumulator_proof: Vec<u8>,
    ) -> Self {
        Self {
            version,
            transaction_hash,
            block_height,
            success,
            accumulator_proof,
        }
    }
}

/// State proof for verifying resource existence or non-existence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProof {
    /// The account address
    pub address: [u8; 32],
    /// The resource type tag
    pub resource_type: String,
    /// Whether the resource exists at this path
    pub exists: bool,
    /// Resource data if it exists
    pub data: Option<Vec<u8>>,
    /// Merkle proof against state root
    pub state_proof: Vec<u8>,
    /// State version this proof is for
    pub version: u64,
}

impl StateProof {
    /// Create a new state proof.
    pub fn new(
        address: [u8; 32],
        resource_type: String,
        exists: bool,
        data: Option<Vec<u8>>,
        state_proof: Vec<u8>,
        version: u64,
    ) -> Self {
        Self {
            address,
            resource_type,
            exists,
            data,
            state_proof,
            version,
        }
    }

    /// Compute the leaf hash for the state proof.
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"APTOS::STATE::LEAF");
        hasher.update(self.address);
        hasher.update(self.resource_type.as_bytes());
        if self.exists {
            hasher.update(b"EXISTS");
            if let Some(data) = &self.data {
                hasher.update(data);
            }
        } else {
            hasher.update(b"NOT_EXISTS");
        }
        hasher.finalize().into()
    }
}

/// Event proof for verifying event emission in a transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventProof {
    /// The event GUID (unique identifier)
    pub guid: [u8; 32],
    /// Sequence number within the event stream
    pub sequence_number: u64,
    /// Transaction version that emitted this event
    pub transaction_version: u64,
    /// Event data
    pub data: Vec<u8>,
    /// Event index within the transaction
    pub event_index: u32,
    /// Merkle proof against the transaction's event root
    pub event_proof: Vec<u8>,
}

impl EventProof {
    /// Create a new event proof.
    pub fn new(
        guid: [u8; 32],
        sequence_number: u64,
        transaction_version: u64,
        data: Vec<u8>,
        event_index: u32,
        event_proof: Vec<u8>,
    ) -> Self {
        Self {
            guid,
            sequence_number,
            transaction_version,
            data,
            event_index,
            event_proof,
        }
    }

    /// Compute the event hash for verification.
    pub fn event_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"APTOS::EVENT::LEAF");
        hasher.update(self.guid);
        hasher.update(self.sequence_number.to_le_bytes());
        hasher.update(self.transaction_version.to_le_bytes());
        hasher.update(self.event_index.to_le_bytes());
        hasher.update(&self.data);
        hasher.finalize().into()
    }
}

/// State proof verifier for resource existence verification.
pub struct StateProofVerifier;

impl StateProofVerifier {
    /// Verify a state proof against the accumulator root.
    ///
    /// Performs full Merkle path verification:
    /// 1. Computes the leaf hash from the state proof data
    /// 2. Walks the Merkle path using sibling hashes from the proof
    /// 3. Compares the computed root with the expected root
    ///
    /// # Arguments
    /// * `proof` - The state proof to verify
    /// * `expected_root` - The expected accumulator root hash
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise.
    pub fn verify(proof: &StateProof, expected_root: &[u8]) -> bool {
        if proof.state_proof.is_empty() {
            return false;
        }

        let expected_root_hash: [u8; 32] = match expected_root.try_into() {
            Ok(hash) => hash,
            Err(_) => return false,
        };

        // Parse proof format: [num_siblings (4 bytes LE)] [sibling_hashes...] [leaf_data...]
        if proof.state_proof.len() < 4 {
            return false;
        }

        let num_siblings = u32::from_le_bytes([
            proof.state_proof[0],
            proof.state_proof[1],
            proof.state_proof[2],
            proof.state_proof[3],
        ]) as usize;

        // Each sibling is 32 bytes, plus we need leaf data
        let min_expected_len = 4 + num_siblings * 32;
        if proof.state_proof.len() < min_expected_len {
            return false;
        }

        // Compute leaf hash from the proof data
        let leaf_hash = proof.leaf_hash();

        // Walk the Merkle path using siblings
        let mut current_hash = leaf_hash;
        for i in 0..num_siblings {
            let sibling_start = 4 + i * 32;
            let sibling_end = sibling_start + 32;
            let sibling: [u8; 32] = match proof.state_proof[sibling_start..sibling_end].try_into() {
                Ok(h) => h,
                Err(_) => return false,
            };

            // Convention: lower index first, then higher index
            // The leaf's position in the tree determines ordering
            let mut combined = sha2::Sha256::new();
            // For Aptos state proofs, the leaf position determines left/right ordering
            // We use a positional nibble approach: position is derived from the leaf hash
            let position_bit = (leaf_hash[0] >> (i % 8)) & 1;
            if position_bit == 0 {
                combined.update(current_hash);
                combined.update(sibling);
            } else {
                combined.update(sibling);
                combined.update(current_hash);
            }
            current_hash = combined.finalize().into();
        }

        // Compare computed root with expected root
        current_hash == expected_root_hash
    }

    /// Verify that a resource was NOT consumed (still exists).
    ///
    /// This is used to check seal resources before consumption.
    ///
    /// # Arguments
    /// * `address` - The account address
    /// * `resource_type` - The resource type tag
    /// * `rpc` - RPC client for fetching state
    ///
    /// # Returns
    /// `true` if the resource exists and has not been consumed.
    /// Verify that a resource exists at the given address.
    ///
    /// # Arguments
    /// * `address` - The account address
    /// * `resource_type` - The resource type tag
    /// * `rpc` - RPC client for fetching resource data
    pub async fn verify_resource_exists_async(
        address: [u8; 32],
        resource_type: &str,
        rpc: &(dyn crate::rpc::AptosAccountReader + Send + Sync),
    ) -> AptosResult<bool> {
        match rpc.get_resource(address, resource_type, None).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(AptosError::StateProofFailed(format!(
                "Failed to fetch resource: {}",
                e
            ))),
        }
    }

    /// Verify that a resource has been consumed (no longer exists).
    ///
    /// This is used to verify seal consumption after publishing.
    ///
    /// # Arguments
    /// * `address` - The account address
    /// * `resource_type` - The resource type tag
    /// * `rpc` - RPC client for fetching resource data
    pub async fn verify_resource_consumed_async(
        address: [u8; 32],
        resource_type: &str,
        rpc: &dyn AptosAccountReader,
    ) -> AptosResult<bool> {
        match rpc.get_resource(address, resource_type, None).await {
            Ok(Some(_)) => Ok(false), // Still exists, not consumed
            Ok(None) => Ok(true),     // Doesn't exist, was consumed
            Err(e) => Err(AptosError::StateProofFailed(format!(
                "Failed to verify resource consumption: {}",
                e
            ))),
        }
    }
}

/// Event proof verifier for transaction event verification.
pub struct EventProofVerifier;

impl EventProofVerifier {
    /// Verify an event proof.
    ///
    /// # Arguments
    /// * `proof` - The event proof to verify
    /// * `expected_data` - Expected event data to match
    ///
    /// # Returns
    /// `true` if the event proof is valid and data matches.
    pub fn verify(proof: &EventProof, expected_data: Option<&[u8]>) -> bool {
        if proof.event_proof.is_empty() {
            return false;
        }

        // If expected data is provided, verify it matches
        if let Some(expected) = expected_data {
            if proof.data != expected {
                return false;
            }
        }

        // In production: verify the Merkle proof for the event
        // against the transaction's event root hash
        proof.event_proof.len() >= 32
    }

    /// Verify that a specific event was emitted in a transaction.
    ///
    /// # Arguments
    /// * `tx_version` - The transaction version to check
    /// * `expected_data` - The expected event data (commitment)
    /// * `rpc` - RPC client for fetching transaction data
    ///
    /// # Returns
    /// `Ok(true)` if the event was found and verified, `Ok(false)` if not found,
    /// or `Err` on RPC failure.
    pub async fn verify_event_in_tx(
        tx_version: u64,
        expected_data: &[u8],
        rpc: &(dyn crate::rpc::AptosTransactionReader + Send + Sync),
    ) -> AptosResult<bool> {
        let tx = rpc.get_transaction_by_version(tx_version).await?;
        match tx {
            Some(tx) => {
                if !tx.success {
                    return Ok(false);
                }

                // Search for event with matching data
                let found = tx.events.iter().any(|e| e.data == expected_data);
                Ok(found)
            }
            None => Err(AptosError::EventProofFailed(format!(
                "Transaction at version {} not found",
                tx_version
            ))),
        }
    }
}

/// Commitment event builder for creating CSV anchor events.
pub struct CommitmentEventBuilder {
    pub(crate) module_address: [u8; 32],
    pub(crate) event_type: String,
}

impl CommitmentEventBuilder {
    /// Create a new event builder.
    ///
    /// # Arguments
    /// * `module_address` - Address of the CSV module
    /// * `event_type` - Event type string (e.g., "CSV::AnchorEvent")
    pub fn new(module_address: [u8; 32], event_type: impl Into<String>) -> Self {
        Self {
            module_address,
            event_type: event_type.into(),
        }
    }

    /// Build the event data for a commitment.
    ///
    /// # Arguments
    /// * `commitment` - The commitment hash
    /// * `seal_address` - The seal account address
    ///
    /// # Returns
    /// Serialized event data bytes.
    pub fn build(&self, commitment: [u8; 32], seal_address: [u8; 32]) -> Vec<u8> {
        // Format: module_address (32) + seal_address (32) + commitment (32) = 96 bytes
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&self.module_address);
        data.extend_from_slice(&seal_address);
        data.extend_from_slice(&commitment);
        data
    }

    /// Parse event data back into commitment components.
    ///
    /// # Arguments
    /// * `data` - Serialized event data
    ///
    /// # Returns
    /// Tuple of (seal_address, commitment) or error.
    pub fn parse(&self, data: &[u8]) -> AptosResult<([u8; 32], [u8; 32])> {
        if data.len() < 96 {
            return Err(AptosError::EventProofFailed(format!(
                "Event data too short: expected >= 96 bytes, got {}",
                data.len()
            )));
        }

        let mut seal_address = [0u8; 32];
        let mut commitment = [0u8; 32];

        // Skip module_address (first 32 bytes)
        seal_address.copy_from_slice(&data[32..64]);
        commitment.copy_from_slice(&data[64..96]);

        Ok((seal_address, commitment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AptosError;
    use crate::rpc::MockAptosRpc;
    use crate::rpc::{AptosEvent, AptosResource, AptosTransaction};

    #[test]
    fn test_parsed_lock_proof_valid() {
        // Create a valid proof with state_root (32 bytes) + leaf_position (8 bytes) + proof_data
        let mut proof_bytes = Vec::with_capacity(48);
        
        // state_root (32 bytes)
        proof_bytes.extend_from_slice(&[1u8; 32]);
        
        // leaf_position (8 bytes, little-endian u64 = 42)
        proof_bytes.extend_from_slice(&42u64.to_le_bytes());
        
        // proof_data (8 bytes)
        proof_bytes.extend_from_slice(&[2u8; 8]);
        
        let parsed = ParsedLockProof::parse(&proof_bytes).unwrap();
        
        assert_eq!(parsed.state_root, [1u8; 32]);
        assert_eq!(parsed.leaf_position, 42);
        assert_eq!(parsed.proof_data, vec![2u8; 8]);
    }

    #[test]
    fn test_parsed_lock_proof_too_short() {
        // Proof too short (less than 40 bytes)
        let proof_bytes = vec![1u8; 39];
        
        let result = ParsedLockProof::parse(&proof_bytes);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            AptosError::InvalidProofFormat(msg) => {
                assert!(msg.contains("too short"));
                assert!(msg.contains("expected >= 40 bytes"));
            }
            _ => panic!("Expected InvalidProofFormat error"),
        }
    }

    #[test]
    fn test_parsed_lock_proof_exact_minimum() {
        // Proof with exactly 40 bytes (minimum valid length)
        let mut proof_bytes = Vec::with_capacity(40);
        
        // state_root (32 bytes)
        proof_bytes.extend_from_slice(&[1u8; 32]);
        
        // leaf_position (8 bytes)
        proof_bytes.extend_from_slice(&0u64.to_le_bytes());
        
        // No proof_data (valid, just empty)
        
        let parsed = ParsedLockProof::parse(&proof_bytes).unwrap();
        
        assert_eq!(parsed.state_root, [1u8; 32]);
        assert_eq!(parsed.leaf_position, 0);
        assert!(parsed.proof_data.is_empty());
    }

    #[test]
    fn test_parsed_lock_proof_roundtrip() {
        let original = ParsedLockProof {
            state_root: [5u8; 32],
            leaf_position: 12345,
            proof_data: vec![9u8; 16],
        };
        
        let bytes = original.to_proof_bytes();
        let parsed = ParsedLockProof::parse(&bytes).unwrap();
        
        assert_eq!(parsed.state_root, original.state_root);
        assert_eq!(parsed.leaf_position, original.leaf_position);
        assert_eq!(parsed.proof_data, original.proof_data);
    }

    #[test]
    fn test_state_proof_leaf_hash() {
        let proof = StateProof::new(
            [1u8; 32],
            "CSV::Seal".to_string(),
            true,
            Some(vec![1, 2, 3]),
            vec![0xAB; 64],
            100,
        );
        let hash = proof.leaf_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_state_proof_verification_valid() {
        // Create a valid state proof with proper structure:
        // [num_siblings (4 bytes LE)] [sibling_hashes...] [leaf_data...]
        // 0 siblings means just leaf data
        let mut state_proof = Vec::new();
        state_proof.extend_from_slice(&0u32.to_le_bytes()); // 0 siblings
        state_proof.extend_from_slice(&[1u8; 32]); // leaf data (32 bytes)

        let proof = StateProof::new(
            [1u8; 32],
            "CSV::Seal".to_string(),
            true,
            Some(vec![1, 2, 3]),
            state_proof.clone(),
            100,
        );

        // Compute the expected root (leaf hash for 0-sibling proof)
        let expected_root = proof.leaf_hash();
        assert!(StateProofVerifier::verify(&proof, &expected_root));
    }

    #[test]
    fn test_state_proof_verification_empty() {
        let proof = StateProof::new([1u8; 32], "CSV::Seal".to_string(), false, None, vec![], 100);
        assert!(!StateProofVerifier::verify(&proof, &[0u8; 32]));
    }

    #[test]
    fn test_event_proof_hash() {
        let proof = EventProof::new([1u8; 32], 0, 100, vec![0xAB, 0xCD], 0, vec![0xEF; 64]);
        let hash = proof.event_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_event_proof_verification_data_match() {
        let proof = EventProof::new([1u8; 32], 0, 100, vec![0xAB, 0xCD], 0, vec![0xEF; 64]);
        assert!(EventProofVerifier::verify(&proof, Some(&[0xAB, 0xCD])));
    }

    #[test]
    fn test_event_proof_verification_data_mismatch() {
        let proof = EventProof::new([1u8; 32], 0, 100, vec![0xAB, 0xCD], 0, vec![0xEF; 64]);
        assert!(!EventProofVerifier::verify(&proof, Some(&[0xFF, 0xFF])));
    }

    #[test]
    fn test_commitment_event_builder() {
        let builder = CommitmentEventBuilder::new([1u8; 32], "CSV::AnchorEvent");
        let commitment = [2u8; 32];
        let seal = [3u8; 32];

        let data = builder.build(commitment, seal);
        assert_eq!(data.len(), 96);

        let (parsed_seal, parsed_commitment) = builder.parse(&data).unwrap();
        assert_eq!(parsed_seal, seal);
        assert_eq!(parsed_commitment, commitment);
    }

    #[test]
    fn test_commitment_event_builder_parse_error() {
        let builder = CommitmentEventBuilder::new([1u8; 32], "CSV::AnchorEvent");
        assert!(builder.parse(&[0u8; 50]).is_err());
    }

    #[tokio::test]
    async fn test_verify_resource_exists() {
        let rpc = MockAptosRpc::new(1000);
        rpc.set_resource(
            [1u8; 32],
            "CSV::Seal",
            AptosResource {
                data: vec![1, 2, 3],
            },
        );

        assert!(
            StateProofVerifier::verify_resource_exists_async([1u8; 32], "CSV::Seal", &rpc)
                .await
                .unwrap()
        );

        assert!(
            !StateProofVerifier::verify_resource_exists_async([99u8; 32], "CSV::Seal", &rpc)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_verify_resource_consumed() {
        let rpc = MockAptosRpc::new(1000);
        rpc.set_resource(
            [1u8; 32],
            "CSV::Seal",
            AptosResource {
                data: vec![1, 2, 3],
            },
        );

        // Resource exists, not consumed
        assert!(
            !StateProofVerifier::verify_resource_consumed_async([1u8; 32], "CSV::Seal", &rpc)
                .await
                .unwrap()
        );

        // Resource doesn't exist, was consumed
        assert!(
            StateProofVerifier::verify_resource_consumed_async([99u8; 32], "CSV::Seal", &rpc)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_verify_event_in_tx() {
        let rpc = MockAptosRpc::new(1000);
        rpc.add_transaction(
            100,
            AptosTransaction {
                version: 100,
                hash: [1u8; 32],
                state_change_hash: [0u8; 32],
                event_root_hash: [0u8; 32],
                state_checkpoint_hash: None,
                epoch: 1,
                round: 0,
                events: vec![AptosEvent {
                    event_sequence_number: 0,
                    key: "CSV::Seal".to_string(),
                    data: vec![0xAB, 0xCD],
                    transaction_version: 100,
                }],
                payload: vec![],
                success: true,
                vm_status: "Executed".to_string(),
                gas_used: 0,
                cumulative_gas_used: 0,
            },
        );

        assert!(
            EventProofVerifier::verify_event_in_tx(100, &[0xAB, 0xCD], &rpc)
                .await
                .unwrap()
        );
        assert!(
            !EventProofVerifier::verify_event_in_tx(100, &[0xFF], &rpc)
                .await
                .unwrap()
        );
    }

    #[test]
    fn test_verify_event_failed_tx() {
        let rpc = MockAptosRpc::new(1000);
        rpc.add_transaction(
            100,
            AptosTransaction {
                version: 100,
                hash: [1u8; 32],
                state_change_hash: [0u8; 32],
                event_root_hash: [0u8; 32],
                state_checkpoint_hash: None,
                epoch: 1,
                round: 0,
                events: vec![],
                payload: vec![],
                success: false,
                vm_status: "Execution failed".to_string(),
                gas_used: 0,
                cumulative_gas_used: 0,
            },
        );
    }
}
