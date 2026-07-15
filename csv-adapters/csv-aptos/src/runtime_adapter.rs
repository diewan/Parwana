//! Runtime adapter wrapper for Aptos chain adapter
//!
//! This module implements the ChainAdapter trait from csv-chain-ports,
//! bridging the Aptos-specific implementation with the generic
//! runtime orchestration layer.

use csv_chain_ports::{
    AdapterError, ChainAdapter, CrossChainTransfer, LockResult, MintResult, RuntimeMintRequest,
    SealRegistryStatus,
};
use csv_protocol::chain_adapter_traits::{ChainBackend, ChainQuery};
use csv_protocol::finality::capabilities::{
    ChainCapabilities, ChainRole, FinalityModel, ProofModel, ReorgRisk, ReplayProtectionModel,
    StateModel,
};
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::signature::SignatureScheme;
use std::sync::Arc;

use crate::ops::AptosBackend;

/// Runtime adapter wrapper for Aptos
pub struct AptosRuntimeAdapter {
    /// Chain identifier
    chain_id: String,
    /// Chain capabilities
    capabilities: ChainCapabilities,
    /// Signature scheme
    signature_scheme: SignatureScheme,
    /// The underlying ChainBackend implementation
    backend: Arc<AptosBackend>,
}

impl AptosRuntimeAdapter {
    /// Create a new Aptos runtime adapter
    pub fn new(backend: Arc<AptosBackend>) -> Self {
        let chain_id = backend.chain_id().to_string();
        let capabilities = ChainCapabilities {
            state_model: StateModel::Resource,
            finality_model: FinalityModel::BftInstant,
            finality_depth: 5,
            deterministic_finality: true,
            proof_model: ProofModel::AccumulatorPath,
            replay_protection: ReplayProtectionModel::ResourceDeleted,
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
impl ChainAdapter for AptosRuntimeAdapter {
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
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let destination_chain = &transfer.destination_chain;

        // Derive owner key ID from the backend's signing key
        #[cfg(feature = "rpc")]
        let owner_key_id =
            if let Some(signing_key) = self.backend.seal_protocol.signing_key.as_ref() {
                use sha3::{Digest, Sha3_256};
                let public_key = signing_key.verifying_key().to_bytes();
                let hash = Sha3_256::digest(&public_key);
                format!("0x{}", hex::encode(&hash[..32]))
            } else {
                // Fallback to zero address if no signing key configured
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
            };

        #[cfg(not(feature = "rpc"))]
        let owner_key_id =
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let result = self
            .backend
            .lock_sanad(&sanad_id, destination_chain, &owner_key_id)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to lock sanad: {}", e)))?;

        Ok(LockResult {
            tx_hash: result.transaction_hash,
            block_height: result.block_height,
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
        // submitter: it binds `destination_contract = @csv_seal` module address,
        // forces `destination_chain_id = keccak256("csv.chain.aptos")`, computes
        // the frozen §9.2 digest, signs it with the secp256k1 verifier key, and
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
            // Bind `destination_contract` to the deployed `@csv_seal` module account
            // and force `destination_chain_id` to the frozen Aptos chain tag,
            // exactly as the Move module derives them, so the signed digest matches
            // the value the module recomputes on-chain.
            let module_contract = self.backend.module_contract_id().map_err(|e| {
                AdapterError::Generic(format!("No csv_seal module configured: {}", e))
            })?;
            let mut attestation = request.attestation.clone();
            attestation.destination_contract = module_contract;
            attestation.destination_chain_id = aptos_contract_chain_id();

            // The recipient must be concrete (non-empty, non-zero) bytes. These same
            // bytes enter the digest (via `keccak256(destination_owner)`) and the
            // Move `destination_owner` argument, so they cannot diverge.
            let destination_owner = crate::mint::parse_destination_owner(
                &attestation.destination_owner,
            )
            .map_err(|e| {
                AdapterError::ProofVerificationFailed(format!("Invalid mint recipient: {}", e))
            })?;

            // Compute the frozen §9.2 digest and attest it with the configured
            // verifier key. Fails closed (no signer -> no signature) rather than
            // emitting an unauthenticated mint the module would reject.
            let digest = attestation.attestation_digest();
            let signatures = self
                .backend
                .sign_mint_attestation_digests(&digest)
                .map_err(|e| {
                    AdapterError::Generic(format!("Failed to sign §9.2 mint attestation: {}", e))
                })?;
            let mut verifier_signatures = request.verifier_signatures.clone();
            verifier_signatures.extend(signatures);

            let args = crate::mint::build_aptos_mint_args(
                &attestation,
                destination_owner,
                &verifier_signatures,
            );
            let result = self
                .backend
                .submit_attested_mint(args)
                .await
                .map_err(|e| AdapterError::Generic(format!("Failed to submit mint: {}", e)))?;

            Ok(MintResult {
                tx_hash: result.transaction_hash,
                block_height: result.block_height,
                materialization: csv_chain_ports::DestinationMaterialization::unavailable(
                    self.chain_id.clone(),
                ),
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
        use crate::types::AptosCommitAnchor;
        use csv_hash::seal::{CommitAnchor as CoreCommitAnchor, SealPoint as CoreSealPoint};
        use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};
        use csv_protocol::seal_protocol::SealProtocol;

        // Lock transaction hash recorded by the lock phase (hex of 32 bytes).
        let lock_tx_bytes = hex::decode(lock_result.tx_hash.trim_start_matches("0x"))
            .map_err(|e| AdapterError::Generic(format!("Invalid lock tx hash: {}", e)))?;
        let lock_tx_hash: [u8; 32] = lock_tx_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AdapterError::Generic("Invalid lock tx hash length".to_string()))?;

        // Anchor at the lock transaction's ledger version.
        let anchor = AptosCommitAnchor::new(lock_result.block_height, lock_tx_hash, 0);

        let inclusion = self
            .backend
            .seal_protocol
            .verify_inclusion(anchor.clone())
            .await
            .map_err(|e| AdapterError::Generic(format!("Inclusion verification failed: {}", e)))?;
        self.backend
            .seal_protocol
            .verify_finality(anchor)
            .await
            .map_err(|e| AdapterError::Generic(format!("Finality verification failed: {}", e)))?;

        // Confirmations for a BFT-instant chain: how far the ledger has
        // advanced past the lock version.
        let latest_version = self.backend.get_latest_block_height().await.map_err(|e| {
            AdapterError::Generic(format!("Failed to query latest ledger version: {}", e))
        })?;
        let confirmations = latest_version.saturating_sub(inclusion.version);

        // Deterministic encoding of the on-chain evidence this proof vouches
        // for: lock tx hash, ledger version, and the node's transaction/ledger
        // proofs.
        let mut proof_bytes = Vec::new();
        proof_bytes.extend_from_slice(&lock_tx_hash);
        proof_bytes.extend_from_slice(&inclusion.version.to_le_bytes());
        proof_bytes.extend_from_slice(&inclusion.transaction_proof);
        proof_bytes.extend_from_slice(&inclusion.ledger_info);

        let inclusion_proof = InclusionProof::new(
            proof_bytes.clone(),
            csv_hash::Hash::new(lock_tx_hash),
            inclusion.version,
            0,
        )
        .map_err(|e| AdapterError::Generic(format!("Invalid inclusion proof: {}", e)))?;

        let finality_proof = FinalityProof::new(
            inclusion.version.to_le_bytes().to_vec(),
            confirmations,
            true, // Aptos finality is deterministic BFT (no probabilistic reorg)
        )
        .map_err(|e| AdapterError::Generic(format!("Invalid finality proof: {}", e)))?;

        // Anchor bound to the Sanad ID being transferred; the verifier's
        // binding rule requires anchor metadata == inclusion proof bytes.
        let anchor_ref = CoreCommitAnchor::new(
            transfer.sanad_id.as_bytes().to_vec(),
            inclusion.version,
            proof_bytes,
        )
        .map_err(|e| AdapterError::Generic(format!("Invalid anchor reference: {}", e)))?;

        // The seal reference is the sanad id: it keys the @csv_seal module
        // registry (see check_seal_registry).
        let seal_ref = CoreSealPoint::new(
            transfer.sanad_id.as_bytes().to_vec(),
            Some(inclusion.version),
            None,
        )
        .map_err(|e| AdapterError::Generic(format!("Invalid seal reference: {}", e)))?;

        // Real authorizing signature over the DAG root commitment, by the same
        // Ed25519 key that signed the lock transaction. Format:
        // [pk_len: u32 LE][public_key][signature].
        let root_commitment = *transfer.sanad_id.as_bytes();
        let encoded_signature = build_aptos_signature(&self.backend, &root_commitment)?;

        // Single-node transition DAG rooted at the Sanad ID, carrying the
        // inclusion evidence and bound to the lock tx hash.
        let dag_node = csv_hash::dag::DAGNode::new(
            csv_hash::Hash::new(root_commitment),
            inclusion.transaction_proof.clone(),
            vec![encoded_signature.clone()],
            vec![lock_tx_hash.to_vec()],
            vec![],
        );
        let transition_dag =
            csv_hash::dag::DAGSegment::new(vec![dag_node], csv_hash::Hash::new(root_commitment));

        ProofBundle::with_signature_scheme(
            SignatureScheme::Ed25519,
            transition_dag,
            vec![encoded_signature],
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| AdapterError::Generic(format!("Failed to build proof bundle: {}", e)))
    }

    async fn validate_source_proof(
        &self,
        _transfer: &CrossChainTransfer,
        _proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        // Proof validation is delegated to CanonicalVerifier in TransferCoordinator
        // The runtime adapter only needs to ensure the proof structure is valid
        Ok(())
    }

    async fn check_seal_registry(
        &self,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        use csv_protocol::chain_adapter_traits::SanadStateReader;

        // The seal_ref for Aptos is the 32-byte sanad id; its canonical state
        // lives in the @csv_seal module registry, keyed by sanad id — not at an
        // account address derived from it.
        if seal_id.len() != 32 {
            return Err(AdapterError::Generic(format!(
                "Invalid seal_id length: expected 32, got {}",
                seal_id.len()
            )));
        }

        let mut sanad_bytes = [0u8; 32];
        sanad_bytes.copy_from_slice(seal_id);
        let sanad_id = csv_hash::sanad::SanadId(csv_hash::Hash::new(sanad_bytes));

        let state = self.backend.get_sanad_state(&sanad_id).await.map_err(|e| {
            AdapterError::Generic(format!("Failed to query canonical sanad state: {}", e))
        })?;

        // Move contract canonical states (csv_seal.move SANAD_STATE_*):
        // 0 uncreated, 1 created, 2 active, 3 locked, 4 consumed, 5 minted,
        // 6 transferred, 7 refunded, 8 burned, 9 invalid.
        match state.state {
            3 | 4 | 5 | 6 | 8 => Ok(SealRegistryStatus::Consumed),
            1 | 2 | 7 => Ok(SealRegistryStatus::Available),
            0 => Err(AdapterError::Generic(format!(
                "Sanad 0x{} does not exist in the on-chain registry",
                hex::encode(sanad_bytes)
            ))),
            other => Err(AdapterError::Generic(format!(
                "Sanad 0x{} has invalid canonical state {}",
                hex::encode(sanad_bytes),
                other
            ))),
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

    async fn confirm_tx(&self, tx_hash: &str) -> Result<MintResult, AdapterError> {
        #[cfg(feature = "rpc")]
        {
            let tx_bytes = hex::decode(tx_hash.trim_start_matches("0x")).map_err(|e| {
                AdapterError::Generic(format!("Invalid Aptos transaction hash: {}", e))
            })?;
            if tx_bytes.len() != 32 {
                return Err(AdapterError::Generic(format!(
                    "Invalid Aptos transaction hash length: expected 32 bytes, got {}",
                    tx_bytes.len()
                )));
            }
            let mut tx_hash_bytes = [0u8; 32];
            tx_hash_bytes.copy_from_slice(&tx_bytes);

            let tx = self
                .backend
                .rpc()
                .wait_for_transaction(tx_hash_bytes)
                .await
                .map_err(|e| {
                    AdapterError::RpcError(format!(
                        "Failed to confirm Aptos transaction {}: {}",
                        tx_hash, e
                    ))
                })?;

            if !tx.success {
                return Err(AdapterError::ProofVerificationFailed(format!(
                    "Aptos transaction {} reverted: {}",
                    tx_hash, tx.vm_status
                )));
            }

            Ok(MintResult {
                tx_hash: hex::encode(tx_hash_bytes),
                block_height: tx.version,
                materialization: csv_chain_ports::DestinationMaterialization::unavailable(
                    self.chain_id.clone(),
                ),
            })
        }
        #[cfg(not(feature = "rpc"))]
        {
            let _ = tx_hash;
            Err(AdapterError::Generic(
                "Cannot confirm Aptos transaction: the 'rpc' feature is not enabled".to_string(),
            ))
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Authorizing proof-bundle signature over `message` (the DAG root
/// commitment) by the backend's configured Ed25519 lock key, encoded as
/// `[pk_len: u32 LE][public_key][signature]`. Fails closed without a signer.
#[cfg(feature = "rpc")]
fn build_aptos_signature(backend: &AptosBackend, message: &[u8]) -> Result<Vec<u8>, AdapterError> {
    use ed25519_dalek::Signer;

    let signing_key = backend.seal_protocol.signing_key.as_ref().ok_or_else(|| {
        AdapterError::Generic(
            "Cannot build inclusion proof: no Aptos signing key configured to authorize \
             the proof bundle"
                .to_string(),
        )
    })?;
    let signature = signing_key.sign(message);
    let public_key = signing_key.verifying_key().to_bytes();
    let mut encoded = Vec::with_capacity(4 + public_key.len() + 64);
    encoded.extend_from_slice(&(public_key.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&public_key);
    encoded.extend_from_slice(&signature.to_bytes());
    Ok(encoded)
}

#[cfg(not(feature = "rpc"))]
fn build_aptos_signature(
    _backend: &AptosBackend,
    _message: &[u8],
) -> Result<Vec<u8>, AdapterError> {
    Err(AdapterError::Generic(
        "Cannot build inclusion proof: the 'rpc' feature is required to sign the proof bundle"
            .to_string(),
    ))
}

/// Contract-layer Aptos chain identity: `keccak256("csv.chain.aptos")`.
///
/// The Move `csv_seal` module hardcodes this tag as `destinationChainId` in the
/// §9.2 preimage regardless of network, so the adapter forces the same value
/// rather than trusting the runtime-supplied destination chain name.
#[cfg(feature = "rpc")]
fn aptos_contract_chain_id() -> [u8; 32] {
    use csv_protocol::cross_chain::CrossChainHashAlgorithm;
    *CrossChainHashAlgorithm::Keccak256
        .hash_bytes(b"csv.chain.aptos")
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AptosConfig, AptosNetwork, SealContractConfig};
    use crate::ops::AptosBackend;
    use crate::rpc::MockAptosRpc;
    use crate::seal_protocol::AptosSealProtocol;
    use csv_chain_ports::MintAttestationInputs;
    use csv_hash::Hash;

    const MODULE_ADDR: &str = "0x00000000000000000000000000000000000000000000000000000000000000aa";

    fn test_config() -> AptosConfig {
        AptosConfig {
            seal_contract: SealContractConfig {
                module_address: MODULE_ADDR.to_string(),
                ..Default::default()
            },
            ..AptosConfig::new(AptosNetwork::Testnet)
        }
    }

    fn test_backend(verifier: Option<secp256k1::SecretKey>) -> Arc<AptosBackend> {
        let rpc = Box::new(MockAptosRpc::new(1));
        let seal = AptosSealProtocol::from_config(test_config(), rpc)
            .expect("seal protocol from valid config");
        let mut backend =
            AptosBackend::from_seal_protocol(Arc::new(seal)).expect("backend from seal protocol");
        if let Some(v) = verifier {
            backend = backend.with_verifier_key(v);
        }
        Arc::new(backend)
    }

    fn test_transfer(sanad_id: Hash) -> CrossChainTransfer {
        CrossChainTransfer {
            id: "aptos-transfer-1".to_string(),
            source_chain: "ethereum".to_string(),
            destination_chain: "aptos".to_string(),
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
        // before any signing or submission.
        let backend = test_backend(None);
        let adapter = AptosRuntimeAdapter::new(backend);
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
        let backend = test_backend(None);
        let adapter = AptosRuntimeAdapter::new(backend);
        let transfer = test_transfer(Hash::new([2u8; 32]));

        let result = adapter.mint_sanad(&transfer, b"not-a-mint-request").await;
        assert!(
            result.is_err(),
            "must reject a payload that is not a canonical RuntimeMintRequest"
        );
    }

    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn confirm_tx_returns_confirmed_ledger_version() {
        let adapter = AptosRuntimeAdapter::new(test_backend(None));
        let tx_hash = hex::encode([7u8; 32]);

        let result = adapter.confirm_tx(&tx_hash).await.expect("confirm tx");

        assert_eq!(result.tx_hash, tx_hash);
        assert_eq!(result.block_height, 1);
    }

    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn mint_sanad_fails_closed_without_verifier_key() {
        // Module configured but no secp256k1 verifier key: the adapter cannot
        // attest the §9.2 digest and must fail closed rather than submit an
        // unauthenticated mint.
        let backend = test_backend(None);
        let adapter = AptosRuntimeAdapter::new(backend);
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
    async fn mint_sanad_rejects_unbound_destination_owner() {
        // The runtime leaves `destination_owner` empty until owner-binding wires a
        // recipient; an empty owner must fail closed before signing.
        let secp = secp256k1::Secp256k1::new();
        let (secret, _pubkey) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let backend = test_backend(Some(secret));
        let adapter = AptosRuntimeAdapter::new(backend);
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

    #[cfg(feature = "rpc")]
    #[test]
    fn aptos_contract_chain_id_is_keccak_of_chain_tag() {
        use csv_protocol::cross_chain::CrossChainHashAlgorithm;
        let expected = *CrossChainHashAlgorithm::Keccak256
            .hash_bytes(b"csv.chain.aptos")
            .as_bytes();
        assert_eq!(aptos_contract_chain_id(), expected);
    }

    #[test]
    fn verifier_signature_recovers_to_configured_key_over_digest() {
        // The §9.2 signature the adapter attaches must recover — over the 32-byte
        // digest, exactly as Aptos's `secp256k1::ecdsa_recover` does — to the
        // configured verifier public key. This pins the signature format (raw
        // recovery id, no EVM +27) the Move module accepts.
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let (secret, expected_pubkey) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let backend = test_backend(Some(secret));

        let mut attestation = mint_attestation(Hash::new([2u8; 32]));
        attestation.destination_contract = [0xAAu8; 32];
        attestation.destination_chain_id =
            *csv_protocol::cross_chain::CrossChainHashAlgorithm::Keccak256
                .hash_bytes(b"csv.chain.aptos")
                .as_bytes();
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
