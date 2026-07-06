//! Runtime adapter wrapper for Sui chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Sui-specific implementation with the generic
//! runtime orchestration layer.

use csv_adapter_core::{
    AdapterError, ChainAdapter, CrossChainTransfer, LockResult, MintResult, RuntimeMintRequest,
    SealRegistryStatus,
};
use csv_protocol::chain_adapter_traits::ChainBackend;
use csv_protocol::finality::capabilities::{
    ChainCapabilities, ChainRole, FinalityModel, ProofModel, ReorgRisk, ReplayProtectionModel,
    StateModel,
};
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::signature::SignatureScheme;
use std::sync::Arc;

use crate::ops::SuiBackend;

/// Runtime adapter wrapper for Sui
pub struct SuiRuntimeAdapter {
    /// Chain identifier
    chain_id: String,
    /// Chain capabilities
    capabilities: ChainCapabilities,
    /// Signature scheme
    signature_scheme: SignatureScheme,
    /// The underlying ChainBackend implementation
    backend: Arc<SuiBackend>,
}

impl SuiRuntimeAdapter {
    /// Create a new Sui runtime adapter
    pub fn new(backend: Arc<SuiBackend>) -> Self {
        let chain_id = backend.chain_id().to_string();
        let capabilities = ChainCapabilities {
            state_model: StateModel::Object,
            finality_model: FinalityModel::BftInstant,
            finality_depth: 15,
            deterministic_finality: true,
            proof_model: ProofModel::CheckpointMerkle,
            replay_protection: ReplayProtectionModel::ObjectDeleted,
            native_single_use_semantics: true,
            reorg_risk: ReorgRisk::Low,
            max_safe_reorg_depth: 0,
            supports_light_client_proofs: true,
            supports_state_proofs: false,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: false,
            supports_zk_proofs: false,
            chain_role: ChainRole::Settlement,
        };
        let signature_scheme = SignatureScheme::Ed25519;

        Self {
            chain_id,
            capabilities,
            signature_scheme,
            backend,
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for SuiRuntimeAdapter {
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
                "0x0000000000000000000000000000000000000000000000000000000000000000",
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
        // `proof_bundle` is the runtime's canonical-CBOR `RuntimeMintRequest`
        // (RFC-0012 §3/§9): the §9.2 attestation inputs the runtime bound after
        // its off-chain canonical verifier already adjudicated the source proof
        // (`validate_source_proof` on the *source* adapter, journaled by the
        // coordinator before this call). This adapter is the thin-registry
        // submitter: it binds `destination_contract = Registry` object id,
        // forces `destination_chain_id = keccak256("csv.chain.sui")`, computes the
        // frozen §9.2 digest, signs it with the secp256k1 verifier key, and
        // submits `csv_seal::mint_sanad`. There is no proof root and no Merkle
        // proof anywhere on this path.
        let request: RuntimeMintRequest =
            csv_codec::from_canonical_cbor(proof_bundle).map_err(|e| {
                AdapterError::Generic(format!("Failed to decode runtime mint request: {}", e))
            })?;

        // Bind the request to this transfer: a payload whose attestation is for a
        // different Sanad must never be signed or submitted here.
        if request.attestation.sanad_id != *transfer.sanad_id.as_bytes() {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Mint request Sanad {} does not match transfer Sanad {}",
                hex::encode(request.attestation.sanad_id),
                hex::encode(transfer.sanad_id.as_bytes())
            )));
        }

        #[cfg(feature = "rpc")]
        {
            // Bind `destination_contract` to the shared Registry object id and
            // force `destination_chain_id` to the frozen Sui chain tag, exactly
            // as the Move contract derives them, so the signed digest matches the
            // value the Registry recomputes on-chain.
            let registry_id = self.backend.registry_object_id().map_err(|e| {
                AdapterError::Generic(format!("No mint Registry configured: {}", e))
            })?;
            let mut attestation = request.attestation.clone();
            attestation.destination_contract = registry_id;
            attestation.destination_chain_id = sui_contract_chain_id();

            // The recipient must be a concrete 32-byte Sui address. These same
            // bytes enter the digest (via `keccak256(destination_owner)`) and the
            // Move `address` argument, so they cannot diverge.
            let destination_owner = crate::mint::parse_destination_owner(
                &attestation.destination_owner,
            )
            .map_err(|e| {
                AdapterError::ProofVerificationFailed(format!("Invalid mint recipient: {}", e))
            })?;

            // Compute the frozen §9.2 digest and attest it with the configured
            // verifier key. Fails closed (no signer -> no signature) rather than
            // emitting an unauthenticated mint the Registry would reject.
            let digest = attestation.attestation_digest();
            let signature = self
                .backend
                .sign_mint_attestation_digest(&digest)
                .map_err(|e| {
                    AdapterError::Generic(format!("Failed to sign §9.2 mint attestation: {}", e))
                })?;
            let mut verifier_signatures = request.verifier_signatures.clone();
            verifier_signatures.push(signature);

            let args = crate::mint::build_sui_mint_args(
                &attestation,
                destination_owner,
                &verifier_signatures,
            );
            let (tx_hash, block_height) = self
                .backend
                .submit_attested_mint(args)
                .await
                .map_err(|e| AdapterError::Generic(format!("Failed to submit mint: {}", e)))?;

            Ok(MintResult {
                tx_hash,
                block_height,
            })
        }
        #[cfg(not(feature = "rpc"))]
        {
            let _ = request;
            Err(AdapterError::Generic(
                "Cannot submit attested mint: the 'rpc' feature is not enabled".to_string(),
            ))
        }
    }

    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        // Decode lock tx hash
        let lock_tx_hash = hex::decode(&lock_result.tx_hash)
            .map_err(|e| AdapterError::Generic(format!("Invalid lock tx hash: {}", e)))?;
        let lock_tx_hash = csv_hash::Hash::try_from(lock_tx_hash.as_slice())
            .map_err(|_| AdapterError::Generic("Invalid lock tx hash length".to_string()))?;

        // Build inclusion proof using the backend
        use csv_protocol::chain_adapter_traits::ChainProofProvider;

        let inclusion_proof = self
            .backend
            .build_inclusion_proof(
                &transfer.sanad_id,
                lock_result.block_height,
                lock_tx_hash.as_bytes(),
            )
            .await
            .map_err(|e| {
                AdapterError::Generic(format!("Failed to build inclusion proof: {}", e))
            })?;

        // Convert to ProofBundle - need to construct it properly
        // For now, return a minimal ProofBundle with the inclusion proof
        use csv_hash::seal::{CommitAnchor, SealPoint};
        use csv_protocol::proof_taxonomy::FinalityProof;

        let seal_point = SealPoint::new(vec![0u8; 32], Some(0), None)
            .map_err(|e| AdapterError::Generic(format!("Failed to create seal point: {}", e)))?;
        let commit_anchor = CommitAnchor::new(
            lock_tx_hash.as_bytes().to_vec(),
            lock_result.block_height,
            vec![],
        )
        .map_err(|e| AdapterError::Generic(format!("Failed to create commit anchor: {}", e)))?;

        // Create a canonical ProofLeafV1 for this transfer
        use csv_protocol::proof_taxonomy::ProofLeafV1;
        let proof_leaf = ProofLeafV1::new(
            transfer.source_chain.clone(),
            transfer.destination_chain.clone(),
            transfer.sanad_id,
            lock_tx_hash, // Use the lock transaction hash as commitment
        );
        let leaf_hash = proof_leaf.hash().map_err(|e| {
            AdapterError::Generic(format!("Failed to compute proof leaf hash: {}", e))
        })?;

        // Create a minimal DAG with one node using the canonical proof leaf hash
        let root_commitment = csv_hash::Hash::new([9u8; 32]);
        let node = csv_hash::dag::DAGNode::new(leaf_hash, vec![], vec![], vec![], vec![]);

        Ok(ProofBundle {
            version: 1,
            transition_dag: csv_hash::dag::DAGSegment::new(vec![node], root_commitment),
            signatures: vec![],
            signature_scheme: csv_protocol::signature::SignatureScheme::Ed25519,
            seal_ref: seal_point,
            anchor_ref: commit_anchor,
            inclusion_proof: inclusion_proof,
            finality_proof: FinalityProof::default(),
        })
    }

    async fn validate_source_proof(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainProofProvider;

        // Validate the proof bundle using the backend's ChainProofProvider implementation
        let inclusion_proof = &proof_bundle.inclusion_proof;
        let finality_proof = &proof_bundle.finality_proof;
        let commitment = &transfer.sanad_id;

        let is_valid = self
            .backend
            .verify_proof_bundle(inclusion_proof, finality_proof, commitment)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to verify proof bundle: {}", e)))?;

        if !is_valid {
            return Err(AdapterError::Generic(
                "Proof bundle validation failed".to_string(),
            ));
        }

        Ok(())
    }

    async fn check_seal_registry(
        &self,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        // Sui uses object-based seals - check if the seal object exists on-chain
        // Convert seal_id to object ID for querying
        if seal_id.len() != 32 {
            return Err(AdapterError::Generic(format!(
                "Invalid seal ID length: expected 32 bytes, got {}",
                seal_id.len()
            )));
        }

        let mut object_id_bytes = [0u8; 32];
        object_id_bytes.copy_from_slice(seal_id);

        // Use the SuiBackend's internal node to check object existence
        // This is the same pattern used in verify_sanad_state and get_sanad_state
        let object_id = sui_sdk_types::Address::from_bytes(&object_id_bytes)
            .map_err(|e| AdapterError::Generic(format!("Invalid object ID: {}", e)))?;

        let client = self.backend.node().client();
        let mut client_guard = client.lock().await;

        use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
        let request = GetObjectRequest::new(&object_id);

        let object_response = (*client_guard)
            .ledger_client()
            .get_object(request)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to query seal object: {}", e)))?;

        let object = object_response.into_inner().object;

        // If object exists, it's available for use
        // If object doesn't exist, it's available to create (not yet minted)
        // Note: In Sui, deleted/consumed objects are not returned by GetObjectRequest
        match object {
            Some(_) => Ok(SealRegistryStatus::Available),
            None => Ok(SealRegistryStatus::Available), // Object doesn't exist yet
        }
    }

    async fn get_balance(&self, address: &str) -> Result<String, AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainQuery;

        // Get balance using the backend's ChainQuery implementation
        let balance_info = self
            .backend
            .get_balance(address)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to get balance: {}", e)))?;

        Ok(balance_info.total.to_string())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Contract-layer Sui chain identity: `keccak256("csv.chain.sui")`.
///
/// The Move `csv_seal` module hardcodes this tag (`CHAIN_SUI_TAG`) as
/// `destinationChainId` in the §9.2 preimage regardless of network, so the
/// adapter forces the same value rather than trusting the runtime-supplied
/// destination chain name.
#[cfg(feature = "rpc")]
fn sui_contract_chain_id() -> [u8; 32] {
    use csv_protocol::cross_chain::CrossChainHashAlgorithm;
    *CrossChainHashAlgorithm::Keccak256
        .hash_bytes(b"csv.chain.sui")
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SealContractConfig, SuiConfig, SuiNetwork};
    use crate::node::SuiNode;
    use crate::ops::SuiBackend;
    use csv_adapter_core::MintAttestationInputs;
    use csv_hash::Hash;

    const REGISTRY_ID: &str = "0x00000000000000000000000000000000000000000000000000000000000000aa";

    fn test_config(registry: Option<&str>) -> SuiConfig {
        SuiConfig {
            seal_contract: SealContractConfig {
                package_id: Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
                        .to_string(),
                ),
                registry_id: registry.map(|s| s.to_string()),
                ..Default::default()
            },
            ..SuiConfig::new(SuiNetwork::Testnet)
        }
    }

    fn test_backend(
        registry: Option<&str>,
        verifier: Option<secp256k1::SecretKey>,
    ) -> Arc<SuiBackend> {
        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443").unwrap());
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut backend =
            SuiBackend::with_signing_key(test_config(registry), node, Some(signing_key));
        if let Some(v) = verifier {
            backend = backend.with_verifier_key(v);
        }
        Arc::new(backend)
    }

    fn test_transfer(sanad_id: Hash) -> CrossChainTransfer {
        CrossChainTransfer {
            id: "sui-transfer-1".to_string(),
            source_chain: "ethereum".to_string(),
            destination_chain: "sui".to_string(),
            lock_tx_hash: vec![0xAAu8; 32],
            lock_output_index: 0,
            sanad_id,
            transition_id: vec![1u8; 32],
        }
    }

    fn mint_attestation(sanad_id: Hash) -> MintAttestationInputs {
        MintAttestationInputs {
            destination_chain_id: [0u8; 32],
            destination_contract: [0u8; 32],
            sanad_id: *sanad_id.as_bytes(),
            commitment: [8u8; 32],
            source_chain: [9u8; 32],
            // A concrete 32-byte Sui recipient address.
            destination_owner: vec![0x11u8; 32],
            lock_event_id: [0xAu8; 32],
            nullifier: [0xBu8; 32],
            attestation_expiry: 0,
        }
    }

    fn runtime_mint_request_cbor(sanad_id: Hash) -> Vec<u8> {
        let request = RuntimeMintRequest {
            attestation: mint_attestation(sanad_id),
            verifier_signatures: vec![],
            proof_bundle: vec![],
        };
        csv_codec::to_canonical_cbor(&request).expect("encode runtime mint request")
    }

    #[tokio::test]
    async fn mint_sanad_rejects_request_bound_to_other_sanad() {
        // A payload whose attestation is for a different Sanad must be rejected
        // before any registry lookup, signing, or submission.
        let backend = test_backend(Some(REGISTRY_ID), None);
        let adapter = SuiRuntimeAdapter::new(backend);
        let transfer = test_transfer(Hash::new([2u8; 32]));
        let payload = runtime_mint_request_cbor(Hash::new([9u8; 32]));

        let result = adapter.mint_sanad(&transfer, &payload).await;
        assert!(
            result.is_err(),
            "must reject a mint request bound to a different sanad"
        );
    }

    #[tokio::test]
    async fn mint_sanad_rejects_undecodable_payload() {
        let backend = test_backend(Some(REGISTRY_ID), None);
        let adapter = SuiRuntimeAdapter::new(backend);
        let transfer = test_transfer(Hash::new([2u8; 32]));

        let result = adapter.mint_sanad(&transfer, b"not-a-mint-request").await;
        assert!(
            result.is_err(),
            "must reject a payload that is not a canonical RuntimeMintRequest"
        );
    }

    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn mint_sanad_fails_closed_without_registry() {
        // No Registry object id configured: the verifier signature is scoped to a
        // specific Registry, so the adapter cannot build a mint and must fail
        // closed instead of submitting an unscoped call.
        let backend = test_backend(None, None);
        let adapter = SuiRuntimeAdapter::new(backend);
        let sanad = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad);
        let payload = runtime_mint_request_cbor(sanad);

        let result = adapter.mint_sanad(&transfer, &payload).await;
        let err = result.expect_err("must fail closed without a Registry");
        assert!(
            format!("{}", err).contains("Registry"),
            "error should point at the missing Registry: {}",
            err
        );
    }

    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn mint_sanad_fails_closed_without_verifier_key() {
        // Registry configured but no secp256k1 verifier key: the adapter cannot
        // attest the §9.2 digest and must fail closed rather than submit an
        // unauthenticated mint.
        let backend = test_backend(Some(REGISTRY_ID), None);
        let adapter = SuiRuntimeAdapter::new(backend);
        let sanad = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad);
        let payload = runtime_mint_request_cbor(sanad);

        let result = adapter.mint_sanad(&transfer, &payload).await;
        assert!(
            result.is_err(),
            "must fail closed when no verifier signer is configured"
        );
    }

    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn mint_sanad_rejects_missing_destination_owner() {
        // The runtime leaves `destination_owner` empty until owner-binding wires a
        // recipient; the Sui mint needs a concrete 32-byte address, so an empty
        // owner must fail closed before signing.
        let secp = secp256k1::Secp256k1::new();
        let (secret, _pubkey) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let backend = test_backend(Some(REGISTRY_ID), Some(secret));
        let adapter = SuiRuntimeAdapter::new(backend);
        let sanad = Hash::new([2u8; 32]);
        let transfer = test_transfer(sanad);

        let mut attestation = mint_attestation(sanad);
        attestation.destination_owner = Vec::new(); // un-bound owner
        let request = RuntimeMintRequest {
            attestation,
            verifier_signatures: vec![],
            proof_bundle: vec![],
        };
        let payload = csv_codec::to_canonical_cbor(&request).unwrap();

        let result = adapter.mint_sanad(&transfer, &payload).await;
        assert!(
            result.is_err(),
            "must reject a mint with an unspecified destination owner"
        );
    }

    #[tokio::test]
    async fn verifier_signature_recovers_to_configured_key_over_digest() {
        // The §9.2 signature the adapter attaches must recover — over the raw
        // preimage hashed with SHA-256, exactly as Sui's `secp256k1_ecrecover`
        // does — to the configured verifier public key. This pins the signature
        // format (raw recovery id, no EVM +27) that the Move Registry accepts.
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let (secret, expected_pubkey) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let backend = test_backend(Some(REGISTRY_ID), Some(secret));

        let mut attestation = mint_attestation(Hash::new([2u8; 32]));
        attestation.destination_contract = [0xAAu8; 32];
        attestation.destination_chain_id = sui_contract_chain_id();
        let digest = attestation.attestation_digest();

        let sig = backend
            .sign_mint_attestation_digest(&digest)
            .expect("verifier key configured");
        assert_eq!(sig.len(), 65, "recoverable signature is r || s || v");

        let recovery_id = RecoveryId::from_i32(sig[64] as i32).expect("valid recovery id");
        let recoverable =
            RecoverableSignature::from_compact(&sig[..64], recovery_id).expect("valid signature");
        let msg = Message::from_digest(digest);
        let recovered = secp
            .recover_ecdsa(&msg, &recoverable)
            .expect("recover verifier pubkey");
        assert_eq!(
            recovered, expected_pubkey,
            "signature must recover to the configured verifier key"
        );
    }
}
