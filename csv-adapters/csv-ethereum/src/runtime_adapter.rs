//! Runtime adapter wrapper for Ethereum chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Ethereum-specific implementation with the generic
//! runtime orchestration layer.

use csv_adapter_core::{
    AdapterError, ChainAdapter, CrossChainTransfer, LockResult, MintResult, SealRegistryStatus,
    TxFinality,
};
use csv_protocol::chain_adapter_traits::{ChainBackend, ChainQuery};
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::signature::SignatureScheme;
use std::sync::Arc;

use crate::ops::EthereumBackend;

/// Runtime adapter wrapper for Ethereum
pub struct EthereumRuntimeAdapter {
    /// Chain identifier
    chain_id: String,
    /// Chain capabilities
    capabilities: ChainCapabilities,
    /// Signature scheme
    signature_scheme: SignatureScheme,
    /// The underlying ChainBackend implementation
    backend: Arc<EthereumBackend>,
}

impl EthereumRuntimeAdapter {
    /// Create a new Ethereum runtime adapter
    pub fn new(backend: Arc<EthereumBackend>) -> Self {
        let chain_id = backend.chain_id().to_string();
        let capabilities = ChainCapabilities::ethereum();
        let signature_scheme = SignatureScheme::Secp256k1;

        Self {
            chain_id,
            capabilities,
            signature_scheme,
            backend,
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for EthereumRuntimeAdapter {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn capabilities(&self) -> ChainCapabilities {
        self.capabilities.clone()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    async fn lock_sanad(&self, transfer: &CrossChainTransfer) -> Result<LockResult, AdapterError> {
        // Use the backend's lock_sanad method which properly constructs and signs the transaction
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let destination_chain = &transfer.destination_chain;

        let result = self
            .backend
            .lock_sanad(
                &sanad_id,
                destination_chain,
                "0x0000000000000000000000000000000000000000",
            )
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to lock sanad: {}", e)))?;

        // Extract tx_hash and block_height from the result
        let tx_hash = result.transaction_hash;
        let block_height = result.block_height;

        Ok(LockResult {
            tx_hash,
            block_height,
        })
    }

    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        // Use the backend's mint_sanad method which properly constructs and signs the transaction
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let source_chain = &transfer.source_chain;

        // Parse proof bundle to extract commitment and state_root
        // The proof bundle is CBOR-encoded ProofBundle
        let proof_bundle: csv_protocol::proof_taxonomy::ProofBundle =
            ProofBundle::from_canonical_bytes(proof_bundle)
                .map_err(|e| format!("Failed to deserialize proof bundle: {}", e))
                .map_err(|e| {
                    AdapterError::Generic(format!("Failed to decode proof bundle: {}", e))
                })?;

        // Extract commitment from anchor_ref (anchor_id is Vec<u8>, need to convert to [u8; 32])
        let mut commitment_bytes = [0u8; 32];
        let len = proof_bundle.anchor_ref.anchor_id.len().min(32);
        commitment_bytes[..len].copy_from_slice(&proof_bundle.anchor_ref.anchor_id[..len]);
        let _commitment = csv_hash::Hash::new(commitment_bytes);

        // Use the inclusion_proof directly
        let inclusion_proof = &proof_bundle.inclusion_proof;

        let result = self
            .backend
            .mint_sanad(
                source_chain,
                &sanad_id,
                inclusion_proof,
                "0x0000000000000000000000000000000000000000",
            )
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to mint sanad: {}", e)))?;

        // Extract tx_hash and block_height from the result (these are not Option types)
        let tx_hash = result.transaction_hash;
        let block_height = result.block_height;

        Ok(MintResult {
            tx_hash,
            block_height,
        })
    }

    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        use csv_hash::dag::{DAGNode, DAGSegment};
        use csv_hash::seal::{CommitAnchor as CoreCommitAnchor, SealPoint as CoreSealPoint};
        use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};

        // Decode the lock transaction hash (display/hex form -> raw bytes).
        let lock_tx_hash = lock_result.tx_hash.trim_start_matches("0x");
        let lock_tx_bytes = hex::decode(lock_tx_hash)
            .map_err(|e| AdapterError::Generic(format!("Invalid lock tx hash: {}", e)))?;
        if lock_tx_bytes.len() != 32 {
            return Err(AdapterError::Generic(format!(
                "Invalid lock tx hash length: expected 32 bytes, got {}",
                lock_tx_bytes.len()
            )));
        }
        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&lock_tx_bytes);

        // Real chain-specific inclusion evidence: fetch the transaction receipt
        // for the lock transaction. If the RPC backend cannot produce a real,
        // confirmed receipt, fail closed instead of shipping a fabricated proof.
        let receipt = self
            .backend
            .rpc()
            .get_transaction_receipt(txid_array)
            .await
            .map_err(|e| {
                AdapterError::Generic(format!(
                    "Cannot build inclusion proof: failed to fetch receipt for {}: {}",
                    lock_result.tx_hash, e
                ))
            })?
            .ok_or_else(|| {
                AdapterError::Generic(format!(
                    "Cannot build inclusion proof: no receipt found for lock tx {}",
                    lock_result.tx_hash
                ))
            })?;

        if receipt.status != 1 {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Cannot build inclusion proof: lock tx {} reverted (status={})",
                lock_result.tx_hash, receipt.status
            )));
        }
        if receipt.block_number != lock_result.block_height {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Cannot build inclusion proof: receipt block {} does not match reported lock block {}",
                receipt.block_number, lock_result.block_height
            )));
        }

        // Find the SanadLocked log emitted by the lock transaction and bind it
        // to this transfer's Sanad ID, so the proof cannot be reused for a
        // different transfer's lock event.
        let sanad_locked_sig = crate::seal_contract::CsvSealAbi::sanad_locked_event_signature();
        let sanad_id_bytes = transfer.sanad_id.as_bytes();
        let lock_log = receipt
            .logs
            .iter()
            .find(|log| {
                log.topics.len() >= 2
                    && log.topics[0] == sanad_locked_sig
                    && log.topics[1] == *sanad_id_bytes
            })
            .ok_or_else(|| {
                AdapterError::ProofVerificationFailed(format!(
                    "Cannot build inclusion proof: no SanadLocked log for sanad {} in tx {}",
                    hex::encode(sanad_id_bytes),
                    lock_result.tx_hash
                ))
            })?;

        // Real finality evidence: confirmation depth measured against current
        // tip, enforced against the chain's configured finality depth.
        let current_height = self
            .backend
            .rpc()
            .block_number()
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to get block number: {}", e)))?;
        let required_depth = self.capabilities.finality_depth;
        let confirmations = current_height.saturating_sub(receipt.block_number);
        if confirmations < required_depth {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Cannot build inclusion proof: insufficient confirmations (got {}, need {})",
                confirmations, required_depth
            )));
        }

        // Encode real inclusion evidence: block hash/number, log index, and
        // the matched log's topics/data, so the bytes are not fabricated
        // filler but a deterministic encoding of the actual receipt evidence
        // this proof is vouching for.
        let mut proof_bytes = Vec::new();
        proof_bytes.extend_from_slice(&receipt.block_hash);
        proof_bytes.extend_from_slice(&receipt.block_number.to_le_bytes());
        proof_bytes.extend_from_slice(&lock_log.log_index.to_le_bytes());
        for topic in &lock_log.topics {
            proof_bytes.extend_from_slice(topic);
        }
        proof_bytes.extend_from_slice(&lock_log.data);

        let inclusion_proof = InclusionProof::new(
            proof_bytes,
            csv_hash::Hash::new(receipt.block_hash),
            receipt.block_number,
            lock_log.log_index,
        )
        .map_err(|e| AdapterError::Generic(format!("Invalid inclusion proof: {}", e)))?;

        let finality_proof =
            FinalityProof::new(confirmations.to_le_bytes().to_vec(), confirmations, true)
                .map_err(|e| AdapterError::Generic(format!("Invalid finality proof: {}", e)))?;

        // The anchor is bound to the Sanad ID being transferred (required by
        // downstream binding checks), with the lock txid/log index carried as
        // metadata.
        let mut anchor_metadata = Vec::with_capacity(32 + 8);
        anchor_metadata.extend_from_slice(&txid_array);
        anchor_metadata.extend_from_slice(&lock_log.log_index.to_le_bytes());
        let anchor_ref = CoreCommitAnchor::new(
            transfer.sanad_id.as_bytes().to_vec(),
            receipt.block_number,
            anchor_metadata,
        )
        .map_err(|e| AdapterError::Generic(format!("Invalid anchor reference: {}", e)))?;

        let seal_ref = CoreSealPoint::new(txid_array.to_vec(), Some(lock_log.log_index), None)
            .map_err(|e| AdapterError::Generic(format!("Invalid seal reference: {}", e)))?;

        // Real authorizing signature over the DAG root commitment, signed by
        // this backend's configured Ethereum signer (the same key that
        // authorized the lock transaction).
        let root_commitment = *transfer.sanad_id.as_bytes();
        let encoded_signature = build_ethereum_signature(&self.backend, &root_commitment);
        if encoded_signature.is_empty() {
            return Err(AdapterError::Generic(
                "Cannot build inclusion proof: no signer configured to authorize proof bundle"
                    .to_string(),
            ));
        }

        // Real transition DAG: a single node carrying the lock receipt's log
        // data, bound to the lock txid and witnessed by the proof signature,
        // rooted at the Sanad ID being transferred.
        let dag_node = DAGNode::new(
            csv_hash::Hash::new(root_commitment),
            txid_array.to_vec(),
            encoded_signature.clone(),
            vec![lock_result.tx_hash.clone().into_bytes()],
            vec![],
        );
        let transition_dag = DAGSegment::new(vec![dag_node], csv_hash::Hash::new(root_commitment));

        ProofBundle::with_signature_scheme(
            csv_protocol::signature::SignatureScheme::Secp256k1,
            transition_dag,
            encoded_signature,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| AdapterError::Generic(format!("Failed to build proof bundle: {}", e)))
    }

    async fn validate_source_proof(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        // Verify the proof is bound to this transfer's Sanad ID. This stops a
        // proof bundle built for a different transfer from being replayed
        // here, even if it otherwise passes structural verification.
        if proof_bundle.anchor_ref.anchor_id != transfer.sanad_id.as_bytes().to_vec() {
            return Err(AdapterError::ProofVerificationFailed(
                "Proof Sanad ID does not match transfer Sanad ID".to_string(),
            ));
        }

        if proof_bundle.signatures.is_empty() || proof_bundle.transition_dag.nodes.is_empty() {
            return Err(AdapterError::ProofVerificationFailed(
                "Proof bundle carries no signatures or transition data".to_string(),
            ));
        }

        if proof_bundle.inclusion_proof.proof_bytes.is_empty() {
            return Err(AdapterError::ProofVerificationFailed(
                "Proof bundle carries no inclusion evidence".to_string(),
            ));
        }

        // Enforce the chain's configured finality depth against the
        // confirmations actually recorded in the finality proof. This
        // guarantees the destination chain cannot mint on a source-chain
        // event that has not yet reached the required confirmation depth,
        // even if a caller tries to submit a proof bundle built before
        // finality was reached.
        let required_depth = self.capabilities.finality_depth;
        if proof_bundle.finality_proof.confirmations < required_depth {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Insufficient confirmations in proof bundle: got {}, need {}",
                proof_bundle.finality_proof.confirmations, required_depth
            )));
        }

        // Verify the source-chain lock referenced by this proof is still
        // recorded as locked on-chain. This is the Ethereum-source analogue
        // of double-spend prevention: a proof bundle cannot be used to mint
        // unless the lock it claims to evidence is actually present on the
        // source chain's contract state.
        #[cfg(feature = "rpc")]
        {
            match self
                .backend
                .is_sanad_locked(transfer.sanad_id.as_bytes())
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Err(AdapterError::ProofVerificationFailed(
                        "Source chain does not report this Sanad as locked".to_string(),
                    ));
                }
                Err(e) => {
                    return Err(AdapterError::Generic(format!(
                        "Failed to verify source-chain lock state: {}",
                        e
                    )));
                }
            }

            Ok(())
        }
        #[cfg(not(feature = "rpc"))]
        {
            Err(AdapterError::Generic(
                "Cannot verify source-chain lock state: the 'rpc' feature is not enabled"
                    .to_string(),
            ))
        }
    }

    async fn tx_finality(&self, tx_hash: &str) -> Result<TxFinality, AdapterError> {
        // Decode the lock txid the same way `build_inclusion_proof` does.
        let lock_tx_bytes = hex::decode(tx_hash.trim_start_matches("0x"))
            .map_err(|e| AdapterError::Generic(format!("Invalid tx hash: {}", e)))?;
        if lock_tx_bytes.len() != 32 {
            return Err(AdapterError::Generic(format!(
                "Invalid tx hash length: expected 32 bytes, got {}",
                lock_tx_bytes.len()
            )));
        }
        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&lock_tx_bytes);

        // No receipt yet → transaction is still unconfirmed / pending.
        let receipt = match self.backend.rpc().get_transaction_receipt(txid_array).await {
            Ok(Some(receipt)) => receipt,
            Ok(None) => {
                return Ok(TxFinality {
                    block_height: 0,
                    confirmations: 0,
                });
            }
            Err(e) => {
                return Err(AdapterError::RpcError(format!(
                    "Failed to fetch receipt for {}: {}",
                    tx_hash, e
                )));
            }
        };
        if receipt.status != 1 {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Lock tx {} reverted (status={})",
                tx_hash, receipt.status
            )));
        }

        let tip = self
            .backend
            .rpc()
            .block_number()
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to get block number: {}", e)))?;
        // Match `build_inclusion_proof`'s `tip - block_number` convention so the
        // runtime finality gate agrees with the proof builder's own depth check.
        let confirmations = tip.saturating_sub(receipt.block_number);

        Ok(TxFinality {
            block_height: receipt.block_number,
            confirmations,
        })
    }

    async fn check_seal_registry(
        &self,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        #[cfg(feature = "rpc")]
        {
            match self.backend.is_sanad_locked(seal_id).await {
                Ok(locked) => {
                    if locked {
                        Ok(SealRegistryStatus::Consumed)
                    } else {
                        Ok(SealRegistryStatus::Available)
                    }
                }
                Err(e) => {
                    log::warn!("Failed to check seal registry on Ethereum: {}", e);
                    Ok(SealRegistryStatus::Available)
                }
            }
        }
        #[cfg(not(feature = "rpc"))]
        {
            let _ = seal_id;
            Ok(SealRegistryStatus::Available)
        }
    }

    async fn get_balance(&self, address: &str) -> Result<String, AdapterError> {
        let balance = self
            .backend
            .get_balance(address)
            .await
            .map_err(|e| AdapterError::Generic(format!("Balance query failed: {}", e)))?;

        Ok(balance.total.to_string())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "rpc")]
fn build_ethereum_signature(backend: &EthereumBackend, message: &[u8]) -> Vec<Vec<u8>> {
    if let Ok(sig) = backend.sign_message(message) {
        let pk = backend
            .rpc()
            .as_any()
            .and_then(|any| any.downcast_ref::<crate::node::EthereumNode>())
            .and_then(|node| node.public_key());

        if let Some(pk_bytes) = pk {
            let mut encoded = Vec::with_capacity(4 + pk_bytes.len() + sig.len());
            encoded.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
            encoded.extend_from_slice(&pk_bytes);
            encoded.extend_from_slice(&sig);
            return vec![encoded];
        }
    }
    vec![]
}

#[cfg(not(feature = "rpc"))]
fn build_ethereum_signature(_backend: &EthereumBackend, _message: &[u8]) -> Vec<Vec<u8>> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EthereumConfig, Network};
    use crate::rpc::{LogEntry, MockEthereumRpc, RpcBlock, TransactionReceipt};
    use csv_hash::Hash;

    fn test_adapter(rpc: MockEthereumRpc) -> EthereumRuntimeAdapter {
        let config = EthereumConfig {
            network: Network::Sepolia,
            finality_depth: 15,
            use_checkpoint_finality: true,
            rpc_url: "http://127.0.0.1:8545".to_string(),
            private_key: None,
            contract_address: Some([0xAAu8; 20]),
        };
        let backend = EthereumBackend::new(Box::new(rpc), config)
            .expect("EthereumBackend::new should succeed with a mock RPC");
        EthereumRuntimeAdapter::new(Arc::new(backend))
    }

    fn test_transfer(sanad_id: Hash) -> CrossChainTransfer {
        CrossChainTransfer {
            id: "test-transfer-1".to_string(),
            source_chain: "ethereum".to_string(),
            destination_chain: "sui".to_string(),
            lock_tx_hash: vec![0xAAu8; 32],
            lock_output_index: 0,
            sanad_id,
            transition_id: vec![1u8; 32],
        }
    }

    fn sanad_locked_log(sanad_id: Hash, log_index: u64) -> LogEntry {
        let sig = crate::seal_contract::CsvSealAbi::sanad_locked_event_signature();
        LogEntry {
            address: [0xAAu8; 20],
            topics: vec![sig, *sanad_id.as_bytes(), [0u8; 32]],
            data: vec![0xCDu8; 32],
            log_index,
        }
    }

    #[tokio::test]
    async fn build_inclusion_proof_fails_closed_without_receipt() {
        let rpc = MockEthereumRpc::new(200);
        let adapter = test_adapter(rpc);
        let sanad_id = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad_id);
        let lock_result = LockResult {
            tx_hash: hex::encode([0xAAu8; 32]),
            block_height: 100,
        };

        let result = adapter.build_inclusion_proof(&transfer, &lock_result).await;
        assert!(
            result.is_err(),
            "must fail closed when the lock transaction has no receipt"
        );
    }

    #[tokio::test]
    async fn build_inclusion_proof_fails_closed_without_matching_lock_log() {
        let rpc = MockEthereumRpc::new(200);
        let lock_txid = [0xAAu8; 32];
        // Receipt exists but carries no SanadLocked log for this sanad ID.
        rpc.add_receipt(
            lock_txid,
            TransactionReceipt {
                tx_hash: lock_txid,
                block_number: 100,
                block_hash: [0x11u8; 32],
                contract_address: None,
                logs: vec![],
                status: 1,
                gas_used: 21000,
                success: true,
            },
        );
        let adapter = test_adapter(rpc);
        let sanad_id = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad_id);
        let lock_result = LockResult {
            tx_hash: hex::encode(lock_txid),
            block_height: 100,
        };

        let result = adapter.build_inclusion_proof(&transfer, &lock_result).await;
        assert!(
            result.is_err(),
            "must fail closed when no SanadLocked log binds the receipt to this sanad"
        );
    }

    #[tokio::test]
    async fn build_inclusion_proof_fails_closed_on_reverted_tx() {
        let rpc = MockEthereumRpc::new(200);
        let lock_txid = [0xAAu8; 32];
        let sanad_id = Hash::new([2u8; 32]);
        rpc.add_receipt(
            lock_txid,
            TransactionReceipt {
                tx_hash: lock_txid,
                block_number: 100,
                block_hash: [0x11u8; 32],
                contract_address: None,
                logs: vec![sanad_locked_log(sanad_id, 0)],
                status: 0, // reverted
                gas_used: 21000,
                success: false,
            },
        );
        let adapter = test_adapter(rpc);
        let transfer = test_transfer(sanad_id);
        let lock_result = LockResult {
            tx_hash: hex::encode(lock_txid),
            block_height: 100,
        };

        let result = adapter.build_inclusion_proof(&transfer, &lock_result).await;
        assert!(result.is_err(), "must fail closed on a reverted lock tx");
    }

    #[tokio::test]
    async fn build_inclusion_proof_fails_closed_below_finality_depth() {
        // block_number() reports 105, lock confirmed at 100: only 5
        // confirmations, but Ethereum requires 15 (ChainCapabilities::ethereum()).
        let rpc = MockEthereumRpc::new(105);
        let lock_txid = [0xAAu8; 32];
        let sanad_id = Hash::new([2u8; 32]);
        rpc.add_receipt(
            lock_txid,
            TransactionReceipt {
                tx_hash: lock_txid,
                block_number: 100,
                block_hash: [0x11u8; 32],
                contract_address: None,
                logs: vec![sanad_locked_log(sanad_id, 0)],
                status: 1,
                gas_used: 21000,
                success: true,
            },
        );
        let adapter = test_adapter(rpc);
        let transfer = test_transfer(sanad_id);
        let lock_result = LockResult {
            tx_hash: hex::encode(lock_txid),
            block_height: 100,
        };

        let result = adapter.build_inclusion_proof(&transfer, &lock_result).await;
        assert!(
            result.is_err(),
            "must fail closed when confirmations are below the chain's finality depth"
        );
    }

    #[tokio::test]
    async fn build_inclusion_proof_fails_closed_without_signer_even_when_finalized() {
        // Even with a fully confirmed, well-formed receipt, MockEthereumRpc
        // has no configured signer (has_signer() == false, and it does not
        // downcast to EthereumNode), so the adapter must never fabricate a
        // signature - it must fail closed instead of shipping an
        // unsigned/fake-signed proof bundle.
        let rpc = MockEthereumRpc::new(200);
        let lock_txid = [0xAAu8; 32];
        let sanad_id = Hash::new([2u8; 32]);
        rpc.add_block(RpcBlock {
            number: 100,
            hash: [0x11u8; 32],
            state_root: [0x22u8; 32],
            timestamp: 0,
        });
        rpc.add_receipt(
            lock_txid,
            TransactionReceipt {
                tx_hash: lock_txid,
                block_number: 100,
                block_hash: [0x11u8; 32],
                contract_address: None,
                logs: vec![sanad_locked_log(sanad_id, 0)],
                status: 1,
                gas_used: 21000,
                success: true,
            },
        );
        let adapter = test_adapter(rpc);
        let transfer = test_transfer(sanad_id);
        let lock_result = LockResult {
            tx_hash: hex::encode(lock_txid),
            block_height: 100,
        };

        let result = adapter.build_inclusion_proof(&transfer, &lock_result).await;
        assert!(
            result.is_err(),
            "must fail closed rather than fabricate a signature when no signer is configured"
        );
    }

    fn test_proof_bundle(sanad_id: Hash, confirmations: u64) -> ProofBundle {
        use csv_hash::dag::{DAGNode, DAGSegment};
        use csv_hash::seal::{CommitAnchor, SealPoint};
        use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};

        let inclusion_proof =
            InclusionProof::new(vec![0xABu8; 32], Hash::new([3u8; 32]), 100, 0).unwrap();
        let finality_proof = FinalityProof::new(vec![], confirmations, true).unwrap();
        let anchor_ref = CommitAnchor::new(sanad_id.as_bytes().to_vec(), 100, vec![]).unwrap();
        let seal_ref = SealPoint::new(vec![0xAAu8; 32], Some(0), None).unwrap();
        let dag_node = DAGNode::new(
            sanad_id,
            vec![0xAAu8; 32],
            vec![vec![0xCDu8; 68]],
            vec![vec![0xEFu8; 4]],
            vec![],
        );
        let transition_dag = DAGSegment::new(vec![dag_node], sanad_id);

        ProofBundle::with_signature_scheme(
            csv_protocol::signature::SignatureScheme::Secp256k1,
            transition_dag,
            vec![vec![0xCDu8; 68]],
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn validate_source_proof_rejects_mismatched_sanad_binding() {
        let rpc = MockEthereumRpc::new(200);
        let adapter = test_adapter(rpc);
        let transfer = test_transfer(Hash::new([2u8; 32]));
        // Proof bundle bound to a *different* sanad ID than the transfer.
        let proof_bundle = test_proof_bundle(Hash::new([9u8; 32]), 20);

        let result = adapter
            .validate_source_proof(&transfer, &proof_bundle)
            .await;
        assert!(
            result.is_err(),
            "must reject a proof bound to a different sanad"
        );
    }

    #[tokio::test]
    async fn validate_source_proof_rejects_insufficient_confirmations() {
        let rpc = MockEthereumRpc::new(200);
        let adapter = test_adapter(rpc);
        let sanad_id = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad_id);
        // Only 5 confirmations, but Ethereum requires 15.
        let proof_bundle = test_proof_bundle(sanad_id, 5);

        let result = adapter
            .validate_source_proof(&transfer, &proof_bundle)
            .await;
        assert!(
            result.is_err(),
            "must reject a proof bundle that has not reached the chain's finality depth"
        );
    }

    #[tokio::test]
    async fn validate_source_proof_rejects_empty_inclusion_evidence() {
        use csv_hash::dag::{DAGNode, DAGSegment};
        use csv_hash::seal::{CommitAnchor, SealPoint};
        use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};

        let rpc = MockEthereumRpc::new(200);
        let adapter = test_adapter(rpc);
        let sanad_id = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad_id);

        let inclusion_proof = InclusionProof::new(vec![], Hash::new([3u8; 32]), 100, 0).unwrap();
        let finality_proof = FinalityProof::new(vec![], 20, true).unwrap();
        let anchor_ref = CommitAnchor::new(sanad_id.as_bytes().to_vec(), 100, vec![]).unwrap();
        let seal_ref = SealPoint::new(vec![0xAAu8; 32], Some(0), None).unwrap();
        let dag_node = DAGNode::new(
            sanad_id,
            vec![0xAAu8; 32],
            vec![vec![0xCDu8; 68]],
            vec![vec![0xEFu8; 4]],
            vec![],
        );
        let transition_dag = DAGSegment::new(vec![dag_node], sanad_id);
        let proof_bundle = ProofBundle::with_signature_scheme(
            csv_protocol::signature::SignatureScheme::Secp256k1,
            transition_dag,
            vec![vec![0xCDu8; 68]],
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .unwrap();

        let result = adapter
            .validate_source_proof(&transfer, &proof_bundle)
            .await;
        assert!(
            result.is_err(),
            "must reject a proof bundle with empty inclusion proof bytes"
        );
    }
}
