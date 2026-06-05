//! Adapter registry ports and implementation.
//!
//! The runtime does not import chain adapters directly. Adapters register
//! themselves behind capability-scoped ports so orchestration code can depend on
//! the smallest authority surface it needs.

#![allow(missing_docs)]

use csv_adapter_core::{
    AdapterError, ChainAdapter, LockResult, MintResult, SealRegistryStatus,
    CrossChainTransfer, ChainCapabilityPort, ChainLockPort, ChainMintPort,
    ChainSealRegistryPort, ChainProofPort, ChainReadPort, AdapterRegistry as AdapterRegistryTrait,
};
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::proof_types::ProofBundle;
use csv_protocol::signature::SignatureScheme;

/// Implementation of the adapter registry.
pub struct AdapterRegistryImpl {
    adapters: std::collections::HashMap<String, Box<dyn ChainAdapter>>,
}

impl AdapterRegistryImpl {
    pub fn new() -> Self {
        Self {
            adapters: std::collections::HashMap::new(),
        }
    }

    pub fn register_adapter(&mut self, adapter: Box<dyn ChainAdapter>) -> Result<(), AdapterError> {
        let chain_id = adapter.chain_id().to_string();
        self.adapters.insert(chain_id, adapter);
        Ok(())
    }

    fn adapter(&self, chain_id: &str) -> Result<&dyn ChainAdapter, AdapterError> {
        self.adapters
            .get(chain_id)
            .map(|adapter| adapter.as_ref())
            .ok_or(AdapterError::Generic(format!(
                "Adapter not found for chain: {}",
                chain_id
            )))
    }

    /// Get a mutable reference to an adapter by chain ID (for registration operations)
    pub fn get(&mut self, chain_id: &str) -> Option<&mut Box<dyn ChainAdapter>> {
        self.adapters.get_mut(chain_id)
    }
}

impl Default for AdapterRegistryImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainCapabilityPort for AdapterRegistryImpl {
    fn capabilities(&self, chain_id: &str) -> Option<ChainCapabilities> {
        self.adapters.get(chain_id).map(|a| a.capabilities())
    }

    fn signature_scheme(&self, chain_id: &str) -> Option<SignatureScheme> {
        self.adapters.get(chain_id).map(|a| a.signature_scheme())
    }
}

#[async_trait::async_trait]
impl ChainLockPort for AdapterRegistryImpl {
    async fn lock_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError> {
        self.adapter(chain_id)?.lock_sanad(transfer).await
    }
}

#[async_trait::async_trait]
impl ChainMintPort for AdapterRegistryImpl {
    async fn mint_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        self.adapter(chain_id)?
            .mint_sanad(transfer, proof_bundle)
            .await
    }
}

#[async_trait::async_trait]
impl ChainSealRegistryPort for AdapterRegistryImpl {
    async fn check_seal_registry(
        &self,
        chain_id: &str,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        self.adapter(chain_id)?.check_seal_registry(seal_id).await
    }
}

#[async_trait::async_trait]
impl ChainProofPort for AdapterRegistryImpl {
    async fn build_inclusion_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        self.adapter(chain_id)?
            .build_inclusion_proof(transfer, lock_result)
            .await
    }

    async fn validate_source_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        self.adapter(chain_id)?
            .validate_source_proof(transfer, proof_bundle)
            .await
    }
}

#[async_trait::async_trait]
impl ChainReadPort for AdapterRegistryImpl {
    async fn confirm_tx(&self, chain_id: &str, tx_hash: &str) -> Result<MintResult, AdapterError> {
        self.adapter(chain_id)?.confirm_tx(tx_hash).await
    }

    async fn get_balance(&self, chain_id: &str, address: &str) -> Result<String, AdapterError> {
        self.adapter(chain_id)?.get_balance(address).await
    }
}

#[async_trait::async_trait]
impl AdapterRegistryTrait for AdapterRegistryImpl {
    fn capabilities(&self, chain_id: &str) -> Option<ChainCapabilities> {
        ChainCapabilityPort::capabilities(self, chain_id)
    }

    fn signature_scheme(&self, chain_id: &str) -> Option<SignatureScheme> {
        ChainCapabilityPort::signature_scheme(self, chain_id)
    }

    async fn lock_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError> {
        ChainLockPort::lock_sanad(self, chain_id, transfer).await
    }

    async fn mint_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        ChainMintPort::mint_sanad(self, chain_id, transfer, proof_bundle).await
    }

    async fn check_seal_registry(
        &self,
        chain_id: &str,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        ChainSealRegistryPort::check_seal_registry(self, chain_id, seal_id).await
    }

    async fn build_inclusion_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        ChainProofPort::build_inclusion_proof(self, chain_id, transfer, lock_result).await
    }

    async fn validate_source_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        ChainProofPort::validate_source_proof(self, chain_id, transfer, proof_bundle).await
    }

    async fn confirm_tx(&self, chain_id: &str, tx_hash: &str) -> Result<MintResult, AdapterError> {
        ChainReadPort::confirm_tx(self, chain_id, tx_hash).await
    }

    async fn get_balance(&self, chain_id: &str, address: &str) -> Result<String, AdapterError> {
        ChainReadPort::get_balance(self, chain_id, address).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAdapter {
        caps: ChainCapabilities,
    }

    impl MockAdapter {
        fn new() -> Self {
            Self {
                caps: ChainCapabilities::bitcoin(),
            }
        }
    }

    #[async_trait::async_trait]
    impl ChainAdapter for MockAdapter {
        fn chain_id(&self) -> &str {
            "mock-chain"
        }

        fn capabilities(&self) -> ChainCapabilities {
            self.caps.clone()
        }

        async fn lock_sanad(
            &self,
            _transfer: &CrossChainTransfer,
        ) -> Result<LockResult, AdapterError> {
            Ok(LockResult {
                tx_hash: "0xmock".to_string(),
                block_height: 100,
            })
        }

        async fn mint_sanad(
            &self,
            _transfer: &CrossChainTransfer,
            _proof_bundle: &[u8],
        ) -> Result<MintResult, AdapterError> {
            Ok(MintResult {
                tx_hash: "0xmock".to_string(),
                block_height: 200,
            })
        }

        async fn build_inclusion_proof(
            &self,
            transfer: &CrossChainTransfer,
            _lock_result: &LockResult,
        ) -> Result<ProofBundle, AdapterError> {
            use csv_hash::dag::{DAGNode, DAGSegment};
            use csv_hash::seal::{CommitAnchor, SealPoint};
            use csv_protocol::proof_types::InclusionProof;

            let node = DAGNode::new(
                csv_hash::Hash::new([1u8; 32]),
                vec![],
                vec![],
                vec![],
                vec![],
            );
            Ok(ProofBundle::new(
                DAGSegment::new(vec![node], csv_hash::Hash::new([0u8; 32])),
                vec![vec![0u8; 64]],
                SealPoint::new(transfer.sanad_id.as_bytes().to_vec(), Some(0), None).unwrap(),
                CommitAnchor::new(vec![0u8; 32], 100, vec![]).unwrap(),
                InclusionProof::new(vec![], csv_hash::Hash::new([0u8; 32]), 100, 0).unwrap(),
                csv_protocol::proof_types::FinalityProof::new(vec![0u8; 32], 6, true).unwrap(),
            )
            .unwrap())
        }

        async fn validate_source_proof(
            &self,
            transfer: &CrossChainTransfer,
            proof_bundle: &ProofBundle,
        ) -> Result<(), AdapterError> {
            if proof_bundle.seal_ref.id != transfer.sanad_id.as_bytes() {
                return Err(AdapterError::Generic(
                    "proof does not bind the transfer sanad".to_string(),
                ));
            }
            Ok(())
        }

        async fn check_seal_registry(
            &self,
            _seal_id: &[u8],
        ) -> Result<SealRegistryStatus, AdapterError> {
            Ok(SealRegistryStatus::Available)
        }

        async fn get_balance(&self, _address: &str) -> Result<String, AdapterError> {
            Ok("1000".to_string())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[tokio::test]
    async fn test_adapter_registry_lock_sanad() {
        let mut registry = AdapterRegistryImpl::new();
        let adapter = MockAdapter::new();
        registry.register_adapter(Box::new(adapter)).unwrap();

        let transfer = CrossChainTransfer {
            id: "test-transfer".to_string(),
            source_chain: "mock-chain".to_string(),
            destination_chain: "mock-chain".to_string(),
            lock_tx_hash: vec![0u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([1u8; 32]),
            transition_id: vec![0u8; 32],
        };

        let result = ChainLockPort::lock_sanad(&registry, "mock-chain", &transfer).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().tx_hash, "0xmock");
    }
}
