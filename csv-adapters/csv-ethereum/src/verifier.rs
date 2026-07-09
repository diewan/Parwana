//! Ethereum chain-specific verification helpers (MPT, seal registry).

use csv_hash::Hash;
use csv_protocol::verification_results::{
    FinalityStrength, InclusionStrength, VerificationAssurance, VerificationFailure,
    VerificationResult, VerifiedComponents,
};

use crate::config::EthereumConfig;
use crate::error::EthereumError;
use crate::rpc::EthereumRpc;

/// Verifies Ethereum-specific proofs (seal registry, inclusion).
pub struct EthereumVerifier {
    rpc: Box<dyn EthereumRpc>,
    csv_seal_address: [u8; 20],
    // Held for RPC/address configuration; the verifier reads the fields above.
    #[allow(dead_code)]
    config: EthereumConfig,
}

impl EthereumVerifier {
    /// Create a new Ethereum verifier.
    pub fn new(
        rpc: Box<dyn EthereumRpc>,
        csv_seal_address: [u8; 20],
        config: EthereumConfig,
    ) -> Self {
        Self {
            rpc,
            csv_seal_address,
            config,
        }
    }

    /// Check whether a seal is still available in the on-chain registry.
    ///
    /// This performs an actual on-chain query to the CSVLock contract's
    /// `isSealUsed(bytes32 sealId)` view function to verify the seal status.
    ///
    /// Returns `valid: true` when the seal has **not** been consumed.
    /// Returns `valid: false` when the seal has already been used on-chain.
    ///
    /// # Security Critical
    /// This method MUST perform actual on-chain verification. Local registry
    /// checks alone are insufficient for replay protection.
    #[cfg(feature = "rpc")]
    pub async fn verify_seal_registry(
        &self,
        seal_id: Hash,
    ) -> Result<VerificationResult, Box<dyn std::error::Error>> {
        use crate::bindings::csv_lock::CSVLock;
        use alloy_primitives::{Address, FixedBytes};
        use alloy_sol_types::SolCall;

        // Construct the isSealUsed call
        let seal_id_fixed = FixedBytes::from(*seal_id.as_bytes());
        let call = CSVLock::isSealUsedCall {
            sealId: seal_id_fixed,
        };

        // Encode the call
        let call_data = call.abi_encode();

        // Construct the eth_call parameters
        let contract_address = Address::from(self.csv_seal_address);
        let call_params = serde_json::json!({
            "to": format!("0x{}", hex::encode(contract_address)),
            "data": format!("0x{}", hex::encode(&call_data))
        });

        // Execute the call on-chain
        let result = self
            .rpc
            .eth_call(call_params, "latest")
            .await
            .map_err(|e| {
                Box::new(EthereumError::RpcError(format!(
                    "Failed to call isSealUsed on contract: {}",
                    e
                ))) as Box<dyn std::error::Error>
            })?;

        // Parse the result - isSealUsed returns a single boolean
        // The ABI encoding of bool is 32 bytes, 0x00...00 for false, 0x01...00 for true
        if result.len() < 32 {
            return Err(Box::new(EthereumError::RpcError(
                "Invalid response length from isSealUsed".to_string(),
            )) as Box<dyn std::error::Error>);
        }

        // Check if the seal is used (true = used, false = available)
        // In Solidity, bool true is encoded as 1 in the last byte of the 32-byte word
        let is_used = result[31] == 1;

        // Seal is valid (available) if it has NOT been used
        let is_valid = !is_used;

        Ok(VerificationResult {
            valid: is_valid,
            assurance: VerificationAssurance::Cryptographic,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: true,
                ownership_signature: false,
            },
            error: if is_used {
                Some(VerificationFailure::ReplayDetected)
            } else {
                None
            },
        })
    }

    /// Check whether a seal is still available in the on-chain registry.
    ///
    /// Without RPC feature, this method is unavailable and returns an error.
    /// This is a fail-closed design to prevent silent bypass of verification.
    #[cfg(not(feature = "rpc"))]
    pub async fn verify_seal_registry(
        &self,
        _seal_id: Hash,
    ) -> Result<VerificationResult, Box<dyn std::error::Error>> {
        Err(Box::new(EthereumError::RpcError(
            "On-chain seal registry verification requires RPC feature".to_string(),
        )) as Box<dyn std::error::Error>)
    }
}
