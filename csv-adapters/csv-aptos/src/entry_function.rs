//! Typed EntryFunction builders for CSV Seal on Aptos
//!
//! This module provides strongly-typed EntryFunction payload builders for the
//! csv-seal Move module, using proper BCS serialization and type-safe argument construction.

use serde_json::json;
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
        let arguments = vec![format!("0x{}", hex::encode(commitment))];

        EntryFunctionPayload {
            function,
            type_arguments: vec![],
            arguments,
        }
    }

    /// Build lock_sanad EntryFunction payload
    ///
    /// # Arguments
    /// * `nonce` - The seal nonce
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
        let arguments = vec![
            nonce.to_string(),
            format!("0x{}", hex::encode(sanad_id)),
            destination_chain.to_string(),
            format!("0x{}", hex::encode(destination_owner)),
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
        let arguments = vec![
            format!("0x{}", hex::encode(sanad_id)),
            format!("0x{}", hex::encode(commitment)),
            format!("0x{}", hex::encode(state_root)),
            source_chain.to_string(),
            format!("0x{}", hex::encode(source_seal_ref)),
            format!("0x{}", hex::encode(&proof)),
            format!("0x{}", hex::encode(proof_root)),
            leaf_position.to_string(),
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
            format!("0x{}", hex::encode(lock_account_address)),
            format!("0x{}", hex::encode(state_root)),
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
    /// Function arguments as hex-encoded strings
    pub arguments: Vec<String>,
}

impl EntryFunctionPayload {
    /// Convert to Aptos REST API payload format
    pub fn to_api_payload(&self) -> serde_json::Value {
        // Convert string arguments to proper JSON types
        let json_arguments: Vec<serde_json::Value> = self.arguments.iter().map(|arg| {
            // Try to parse as u64 first
            if let Ok(num) = arg.parse::<u64>() {
                serde_json::Value::Number(serde_json::Number::from(num))
            } else if let Ok(num) = arg.parse::<i64>() {
                serde_json::Value::Number(serde_json::Number::from(num))
            } else {
                // Keep as string (for hex-encoded bytes)
                serde_json::Value::String(arg.clone())
            }
        }).collect();

        json!({
            "type": "entry_function_payload",
            "function": self.function,
            "type_arguments": self.type_arguments,
            "arguments": json_arguments
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
        assert!(payload.arguments[0].starts_with("0x"));
        assert_eq!(payload.type_arguments.len(), 0);
    }

    #[test]
    fn test_lock_sanad_payload() {
        let builder = EntryFunctionBuilder::new("0x1".to_string());
        let seal_address = [2u8; 32];
        let destination_chain = 1u8;
        let destination_owner = [3u8; 32];
        let payload = builder.lock_sanad(seal_address, destination_chain, destination_owner);

        assert_eq!(payload.function_short_name(), "lock_sanad");
        assert_eq!(payload.arguments.len(), 3);
        assert_eq!(payload.arguments[1], "1"); // destination_chain
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
        assert_eq!(payload.arguments[3], "2"); // source_chain
        assert_eq!(payload.arguments[7], "0"); // leaf_position
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
}
