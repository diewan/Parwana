//! Typed EntryFunction builders for CSV Seal on Aptos
//!
//! This module provides strongly-typed EntryFunction payload builders for the
//! csv-seal Move module, using proper BCS serialization and type-safe argument construction.

use serde_json::{json, Value};
use std::fmt;

/// CSV Seal module address (configured at runtime)
pub const CSV_SEAL_MODULE_NAME: &str = "CSVSeal";

/// EntryFunction function names
pub mod functions {
    pub const CONSUME_SEAL: &str = "consume_seal";
    pub const LOCK_SANAD: &str = "lock_sanad";
    pub const MINT_SANAD: &str = "mint_sanad";
    pub const REFUND_SANAD: &str = "refund_sanad";
}

/// Aptos Move argument type for BCS serialization.
///
/// The Aptos REST API reconstructs transactions from JSON arguments and verifies
/// signatures against that reconstruction. The BCS encoding used when signing
/// MUST match the API's encoding. This enum ensures correct serialization:
/// - `U64` → 8-byte big-endian (Move u64/u128)
/// - `U8` → 1-byte (Move u8)
/// - `Bytes` → length-prefixed raw bytes (Move vector<u8>)
#[derive(Debug, Clone)]
pub enum EntryFunctionArgument {
    U64(u64),
    U8(u8),
    Bytes(Vec<u8>),
}

impl EntryFunctionArgument {
    /// Serialize this argument to its JSON representation for the Aptos REST API.
    pub fn to_json_value(&self) -> Value {
        match self {
            EntryFunctionArgument::U64(n) => Value::String(n.to_string()),
            EntryFunctionArgument::U8(n) => Value::Number(serde_json::Number::from(*n)),
            EntryFunctionArgument::Bytes(b) => Value::String(format!("0x{}", hex::encode(b))),
        }
    }

    /// Serialize this argument to BCS bytes for RawTransaction signing.
    /// The encoding MUST match what the Aptos REST API produces from the JSON representation.
    pub fn to_bcs_bytes(&self) -> Vec<u8> {
        match self {
            EntryFunctionArgument::U64(n) => {
                aptos_bcs::to_bytes(n).unwrap_or_else(|e| panic!("Failed to serialize u64: {}", e))
            }
            EntryFunctionArgument::U8(n) => {
                // u8 must be serialized as a single byte to match Aptos REST API behavior
                vec![*n]
            }
            EntryFunctionArgument::Bytes(b) => {
                aptos_bcs::to_bytes(b).unwrap_or_else(|e| panic!("Failed to serialize bytes: {}", e))
            }
        }
    }
}

impl From<u64> for EntryFunctionArgument {
    fn from(n: u64) -> Self {
        EntryFunctionArgument::U64(n)
    }
}

impl From<u8> for EntryFunctionArgument {
    fn from(n: u8) -> Self {
        EntryFunctionArgument::U8(n)
    }
}

impl From<Vec<u8>> for EntryFunctionArgument {
    fn from(b: Vec<u8>) -> Self {
        EntryFunctionArgument::Bytes(b)
    }
}

/// EntryFunction payload builder
pub struct EntryFunctionBuilder {
    module_address: String,
}

impl EntryFunctionBuilder {
    /// Create a new EntryFunction builder with the module address
    pub fn new(module_address: String) -> Self {
        Self { module_address }
    }

    /// Get the full function name for a given function
    fn function_name(&self, function: &str) -> String {
        format!(
            "{}::{}::{}",
            self.module_address, CSV_SEAL_MODULE_NAME, function
        )
    }

    /// Build consume_seal EntryFunction payload
    ///
    /// # Arguments
    /// * `commitment` - The commitment hash (32 bytes)
    pub fn consume_seal(&self, commitment: [u8; 32]) -> EntryFunctionPayload {
        let function = self.function_name(functions::CONSUME_SEAL);
        let arguments = vec![EntryFunctionArgument::Bytes(commitment.to_vec())];

        EntryFunctionPayload {
            function,
            type_arguments: vec![],
            arguments,
        }
    }

    /// Build lock_sanad EntryFunction payload
    ///
    /// # Arguments
    /// * `nonce` - The seal nonce (u64)
    /// * `sanad_id` - Unique Sanad identifier (32 bytes)
    /// * `destination_chain` - Destination chain ID (u8)
    /// * `destination_owner` - Destination owner address (32 bytes)
    pub fn lock_sanad(
        &self,
        nonce: u64,
        sanad_id: [u8; 32],
        destination_chain: u8,
        destination_owner: [u8; 32],
    ) -> EntryFunctionPayload {
        let function = self.function_name(functions::LOCK_SANAD);
        // Explicit types ensure BCS encoding matches Aptos REST API reconstruction
        let arguments = vec![
            EntryFunctionArgument::U64(nonce),
            EntryFunctionArgument::Bytes(sanad_id.to_vec()),
            EntryFunctionArgument::U8(destination_chain),
            EntryFunctionArgument::Bytes(destination_owner.to_vec()),
        ];

        EntryFunctionPayload {
            function,
            type_arguments: vec![],
            arguments,
        }
    }

    /// Build mint_sanad EntryFunction payload
    ///
    /// # Arguments
    /// * `sanad_id` - Unique Sanad identifier (32 bytes)
    /// * `commitment` - Commitment hash (32 bytes)
    /// * `state_root` - Off-chain state root (32 bytes)
    /// * `source_chain` - Source chain ID (u8)
    /// * `source_seal_ref` - Reference to source chain seal (32 bytes)
    /// * `proof` - Cross-chain Merkle proof bytes
    /// * `proof_root` - Trusted proof root for verification (32 bytes)
    /// * `leaf_position` - Position of leaf in Merkle tree (u64)
    #[allow(clippy::too_many_arguments)]
    pub fn mint_sanad(
        &self,
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        state_root: [u8; 32],
        source_chain: u8,
        source_seal_ref: [u8; 32],
        proof: Vec<u8>,
        proof_root: [u8; 32],
        leaf_position: u64,
    ) -> EntryFunctionPayload {
        let function = self.function_name(functions::MINT_SANAD);
        // Explicit types ensure BCS encoding matches Aptos REST API reconstruction
        let arguments = vec![
            EntryFunctionArgument::Bytes(sanad_id.to_vec()),
            EntryFunctionArgument::Bytes(commitment.to_vec()),
            EntryFunctionArgument::Bytes(state_root.to_vec()),
            EntryFunctionArgument::U8(source_chain),
            EntryFunctionArgument::Bytes(source_seal_ref.to_vec()),
            EntryFunctionArgument::Bytes(proof),
            EntryFunctionArgument::Bytes(proof_root.to_vec()),
            EntryFunctionArgument::U64(leaf_position),
        ];

        EntryFunctionPayload {
            function,
            type_arguments: vec![],
            arguments,
        }
    }

    /// Build refund_sanad EntryFunction payload
    ///
    /// # Arguments
    /// * `lock_account_address` - The lock account address (32 bytes)
    /// * `state_root` - Off-chain state root (32 bytes)
    pub fn refund_sanad(
        &self,
        lock_account_address: [u8; 32],
        state_root: [u8; 32],
    ) -> EntryFunctionPayload {
        let function = self.function_name(functions::REFUND_SANAD);
        let arguments = vec![
            EntryFunctionArgument::Bytes(lock_account_address.to_vec()),
            EntryFunctionArgument::Bytes(state_root.to_vec()),
        ];

        EntryFunctionPayload {
            function,
            type_arguments: vec![],
            arguments,
        }
    }
}

/// EntryFunction payload representation
#[derive(Debug, Clone)]
pub struct EntryFunctionPayload {
    /// Fully qualified function name (e.g., "0x1::csv_seal::lock_sanad")
    pub function: String,
    /// Type arguments (generic type parameters)
    pub type_arguments: Vec<String>,
    /// Function arguments with explicit types for correct BCS serialization.
    /// The Aptos REST API reconstructs transactions from JSON and verifies
    /// signatures against that reconstruction, so BCS encoding must match.
    pub arguments: Vec<EntryFunctionArgument>,
}

impl EntryFunctionPayload {
    /// Convert to Aptos REST API payload format.
    /// Arguments are converted to their JSON representations.
    pub fn to_api_payload(&self) -> serde_json::Value {
        let json_args: Vec<Value> = self.arguments.iter().map(|a| a.to_json_value()).collect();
        json!({
            "type": "entry_function_payload",
            "function": self.function,
            "type_arguments": self.type_arguments,
            "arguments": json_args
        })
    }

    /// Get the function name without module path
    pub fn function_short_name(&self) -> &str {
        self.function.split("::").last().unwrap_or(&self.function)
    }
}

impl fmt::Display for EntryFunctionPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}(args={})",
            self.function_short_name(),
            self.arguments.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_function_builder_creation() {
        let builder = EntryFunctionBuilder::new("0x1".to_string());
        assert_eq!(builder.module_address, "0x1");
    }

    #[test]
    fn test_consume_seal_payload() {
        let builder = EntryFunctionBuilder::new("0x1".to_string());
        let commitment = [1u8; 32];
        let payload = builder.consume_seal(commitment);

        assert_eq!(payload.function_short_name(), "consume_seal");
        assert_eq!(payload.arguments.len(), 1);
        assert_eq!(payload.arguments[0].to_json_value().as_str().unwrap().starts_with("0x"), true);
        assert_eq!(payload.type_arguments.len(), 0);
    }

    #[test]
    fn test_lock_sanad_payload() {
        let builder = EntryFunctionBuilder::new("0x1".to_string());
        let nonce = 42u64;
        let sanad_id = [2u8; 32];
        let destination_chain = 1u8;
        let destination_owner = [3u8; 32];
        let payload = builder.lock_sanad(nonce, sanad_id, destination_chain, destination_owner);

        assert_eq!(payload.function_short_name(), "lock_sanad");
        assert_eq!(payload.arguments.len(), 4);
        // nonce (u64) → JSON string
        assert_eq!(payload.arguments[0].to_json_value().as_str().unwrap(), "42");
        // sanad_id (vector<u8>) → JSON hex string
        assert_eq!(payload.arguments[1].to_json_value().as_str().unwrap(), format!("0x{}", hex::encode(sanad_id)));
        // destination_chain (u8) → JSON number
        assert_eq!(payload.arguments[2].to_json_value().as_u64().unwrap(), 1);
        // destination_owner (vector<u8>) → JSON hex string
        assert_eq!(payload.arguments[3].to_json_value().as_str().unwrap(), format!("0x{}", hex::encode(destination_owner)));
    }

    #[test]
    fn test_mint_sanad_payload() {
        let builder = EntryFunctionBuilder::new("0x1".to_string());
        let sanad_id = [4u8; 32];
        let commitment = [5u8; 32];
        let state_root = [6u8; 32];
        let source_chain = 2u8;
        let source_seal_ref = [7u8; 32];
        let proof = vec![8u8; 64];
        let proof_root = [9u8; 32];
        let leaf_position = 0u64;
        let payload = builder.mint_sanad(
            sanad_id,
            commitment,
            state_root,
            source_chain,
            source_seal_ref,
            proof,
            proof_root,
            leaf_position,
        );

        assert_eq!(payload.function_short_name(), "mint_sanad");
        assert_eq!(payload.arguments.len(), 8);
        // source_chain (u8) → JSON number
        assert_eq!(payload.arguments[3].to_json_value().as_u64().unwrap(), 2);
        // leaf_position (u64) → JSON string
        assert_eq!(payload.arguments[7].to_json_value().as_str().unwrap(), "0");
    }

    #[test]
    fn test_refund_sanad_payload() {
        let builder = EntryFunctionBuilder::new("0x1".to_string());
        let lock_account_address = [10u8; 32];
        let state_root = [11u8; 32];
        let payload = builder.refund_sanad(lock_account_address, state_root);

        assert_eq!(payload.function_short_name(), "refund_sanad");
        assert_eq!(payload.arguments.len(), 2);
    }

    #[test]
    fn test_to_api_payload() {
        let builder = EntryFunctionBuilder::new("0x1".to_string());
        let commitment = [1u8; 32];
        let payload = builder.consume_seal(commitment);
        let api_payload = payload.to_api_payload();

        assert_eq!(api_payload["type"], "entry_function_payload");
        assert!(
            api_payload["function"]
                .as_str()
                .unwrap()
                .contains("consume_seal")
        );
        assert_eq!(api_payload["type_arguments"].as_array().unwrap().len(), 0);
        assert_eq!(api_payload["arguments"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_bcs_encoding_u8_vs_u64() {
        // u8 should serialize as 1 byte, u64 as 8 bytes (little-endian)
        let u8_arg = EntryFunctionArgument::U8(1);
        let u64_arg = EntryFunctionArgument::U64(1);

        assert_eq!(u8_arg.to_bcs_bytes().len(), 1);
        assert_eq!(u8_arg.to_bcs_bytes(), vec![1]);

        assert_eq!(u64_arg.to_bcs_bytes().len(), 8);
        assert_eq!(u64_arg.to_bcs_bytes(), vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }
}
