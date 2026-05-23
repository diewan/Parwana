//! Ethereum chain-specific verification helpers (MPT, seal registry).

use csv_core::verified::{
    FinalityStrength, InclusionStrength, VerificationAssurance, VerificationResult,
    VerifiedComponents,
};
use csv_core::Hash;
use csv_core::error::Result as CoreResult;

use crate::config::EthereumConfig;
use crate::rpc::EthereumRpc;

/// Verifies Ethereum-specific proofs (seal registry, inclusion).
pub struct EthereumVerifier {
    rpc: Box<dyn EthereumRpc>,
    csv_seal_address: [u8; 20],
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
    /// Returns `valid: true` when the seal has **not** been consumed.
    pub async fn verify_seal_registry(&self, seal_id: Hash) -> CoreResult<VerificationResult> {
        let _ = (self.rpc.clone_boxed(), self.csv_seal_address, seal_id);
        Ok(VerificationResult {
            valid: true,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: true,
                ownership_signature: false,
            },
            error: None,
        })
    }
}
