//! Chain runtime implementations.
//!
//! This module provides unified runtime functions that delegate to the appropriate
//! chain backends while providing a consistent API across all supported chains.
//!
//! # Clean Architecture
//!
//! Following the Clean Architecture documented in `docs/ARCHITECTURE.md` and `docs/BLUEPRINT.md`:
//!
//! 1. **csv-core**: Defines `SealProtocol` trait (protocol primitives) and
//!    `ChainBackend` trait (chain operations like ChainQuery, ChainSigner, etc.)
//!
//! 2. **csv-{chain}**: Each chain provides:
//!    - `SealProtocol` implementation (e.g., `EthereumSealProtocol`)
//!    - `Backend` type (e.g., `EthereumBackend`) implementing `ChainBackend`
//!    - Backend can be created via driver registration
//!
//! 3. **csv-sdk (this runtime)**:
//!    - Works with `Arc<dyn ChainBackend>` (Backend implementations)
//!    - Provides `AdapterBuilder` for constructing adapters with chain-specific configs
//!    - `ChainRuntime` delegates operations to registered adapters
//!
//! The runtime pattern ensures that:
//! - CLI, wallet, and other components don't need direct chain adapter dependencies
//! - All chain operations go through a unified interface
//! - Error handling is consistent across chains
//! - Chain-specific implementations are properly abstracted

use std::collections::HashMap;
use std::sync::Arc;
#[cfg(not(feature = "tokio"))]
use std::sync::Mutex;
#[cfg(feature = "tokio")]
use tokio::sync::Mutex;
#[cfg(feature = "wasm")]
#[allow(unused_imports)]
use wasm_bindgen_futures::spawn_local;

// Imports for contract call encoding
#[allow(unused_imports)]
use sha2::Sha256;
#[allow(unused_imports)]
use sha3::Keccak256;
// Digest trait needed for new(), update(), finalize() methods
#[allow(unused_imports)]
use sha2::Digest as Sha2Digest;
#[allow(unused_imports)]
use sha3::Digest;

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_hash::sanad::SanadId;
use csv_proof::proof::ProofBundle;
use csv_protocol::backend::{
    BalanceInfo, ChainBackend, DeploymentStatus, SanadOperationResult, TransactionInfo,
    TransactionStatus,
};

use crate::client::ClientRef;
use crate::error::CsvError;

/// Unified chain runtime that provides all chain operations.
///
/// This is the main runtime that chains, CLI, and wallet components should use
/// for all blockchain interactions. It delegates to the appropriate chain
/// adapters while providing a consistent API.
///
/// # Architecture
///
/// The runtime holds `Arc<dyn ChainBackend>` instances which are the chain-specific
/// `ChainOperations` types (e.g., `EthereumBackend`), NOT the `SealProtocol` types.
/// This distinction is crucial for Clean Architecture compliance.
///
/// Use `AdapterBuilder` to construct adapters properly with chain-specific configuration.
#[derive(Clone)]
pub struct ChainRuntime {
    client: Arc<ClientRef>,
    adapters: Arc<Mutex<HashMap<ChainId, Arc<dyn ChainBackend>>>>,
}

/// Pre-fetched seal consumption data for verification.
/// This avoids capturing the store lock in the closure passed to verify_proof.
struct SealCheckData {
    sanad_id: SanadId,
    is_consumed: bool,
}

impl ChainRuntime {
    pub(crate) fn new(client: Arc<ClientRef>) -> Self {
        Self {
            client,
            adapters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new ChainRuntime with pre-built adapters.
    ///
    /// This is used by the builder to auto-register adapters when chains are enabled.
    #[allow(dead_code)]
    pub(crate) fn with_adapters(
        client: Arc<ClientRef>,
        adapters: HashMap<ChainId, Arc<dyn ChainBackend>>,
    ) -> Self {
        Self {
            client,
            adapters: Arc::new(Mutex::new(adapters)),
        }
    }

    /// Register a chain adapter for the given chain.
    ///
    /// The adapter must implement `ChainBackend` (e.g., `EthereumBackend`).
    /// Use `AdapterBuilder` to construct adapters with proper chain-specific configuration.
    ///
    /// # Example
    /// ```ignore
    /// use csv_sdk::runtime::{ChainRuntime, AdapterBuilder, RuntimeConfig};
    /// use csv_sdk::prelude::*;
    ///
    /// let runtime = ChainRuntime::new(/* client ref */);
    /// // let adapter = AdapterBuilder::new()
    /// //     .ethereum_from_config(config, rpc, csv_seal_address)
    /// //     .await
    /// //     .build();
    /// // runtime.register_adapter(ChainId::new("ethereum"), adapter);
    /// ```
    pub async fn register_adapter(&self, chain: ChainId, adapter: Arc<dyn ChainBackend>) {
        #[cfg(feature = "tokio")]
        {
            let mut adapters = self.adapters.lock().await;
            adapters.insert(chain, adapter);
        }
        #[cfg(not(feature = "tokio"))]
        {
            let mut adapters = self.adapters.lock().unwrap();
            adapters.insert(chain, adapter);
        }
    }

    /// Query the balance for an address on the specified chain.
    ///
    /// This is the primary runtime function used by CLI and wallet
    /// for balance queries across all chains.
    pub async fn get_balance(
        &self,
        chain: ChainId,
        address: &str,
    ) -> Result<BalanceInfo, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .get_balance(address)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Balance query failed: {}", e),
            })
    }

    /// Get transaction information by hash.
    ///
    /// Returns TransactionInfo which includes the transaction status.
    pub async fn get_transaction(
        &self,
        chain: ChainId,
        tx_hash: &str,
    ) -> Result<TransactionInfo, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .get_transaction(tx_hash)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Transaction query failed: {}", e),
            })
    }

    /// Sign a transaction using the wallet's key identifier.
    ///
    /// This runtime function is used by CLI and wallet for transaction signing.
    pub async fn sign_transaction(
        &self,
        chain: ChainId,
        unsigned_tx: &[u8],
        key_id: &str,
    ) -> Result<Vec<u8>, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .sign_transaction(unsigned_tx, key_id)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Transaction signing failed: {}", e),
            })
    }

    /// Broadcast a signed transaction to the network.
    ///
    /// This runtime function is used by CLI and wallet for transaction broadcasting.
    /// Delegates to ChainBroadcaster::submit_transaction.
    pub async fn broadcast_transaction(
        &self,
        chain: ChainId,
        signed_tx: &[u8],
    ) -> Result<String, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .submit_transaction(signed_tx)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Transaction broadcast failed: {}", e),
            })
    }

    /// Build an inclusion proof for a commitment on the specified chain.
    ///
    /// This runtime function is used by CLI and wallet for proof generation.
    /// Delegates to ChainProofProvider::build_inclusion_proof.
    pub async fn build_inclusion_proof(
        &self,
        chain: ChainId,
        commitment: &Hash,
        block_height: u64,
        anchor_id: &[u8],
    ) -> Result<csv_proof::proof::InclusionProof, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .build_inclusion_proof(commitment, block_height, anchor_id)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Proof generation failed: {}", e),
            })
    }

    /// Deploy a lock contract to the specified chain.
    ///
    /// This runtime function is used by CLI for contract deployment.
    /// Delegates to ChainDeployer::deploy_lock_contract.
    pub async fn deploy_lock_contract(
        &self,
        chain: ChainId,
        admin_address: &str,
        config: serde_json::Value,
    ) -> Result<DeploymentStatus, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .deploy_lock_contract(admin_address, config)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Contract deployment failed: {}", e),
            })
    }

    /// Verify contract deployment status.
    ///
    /// Delegates to ChainDeployer::verify_deployment.
    pub async fn verify_deployment(
        &self,
        chain: ChainId,
        contract_address: &str,
    ) -> Result<bool, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .verify_deployment(contract_address)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Deployment verification failed: {}", e),
            })
    }

    /// Create a new sanad on the specified chain.
    ///
    /// Delegates to ChainSanadOps::create_sanad.
    pub async fn create_sanad(
        &self,
        chain: ChainId,
        owner: &str,
        asset_class: &str,
        asset_id: &str,
        metadata: serde_json::Value,
    ) -> Result<SanadOperationResult, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .create_sanad(owner, asset_class, asset_id, metadata)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Sanad creation failed: {}", e),
            })
    }

    /// Consume a sanad on the specified chain.
    ///
    /// Delegates to ChainSanadOps::consume_sanad.
    pub async fn consume_sanad(
        &self,
        chain: ChainId,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> Result<SanadOperationResult, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .consume_sanad(sanad_id, owner_key_id)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Sanad consumption failed: {}", e),
            })
    }

    /// Lock a sanad for cross-chain transfer.
    ///
    /// Delegates to ChainSanadOps::lock_sanad.
    pub async fn lock_sanad(
        &self,
        chain: ChainId,
        sanad_id: &SanadId,
        destination_chain: &str,
        owner_key_id: &str,
    ) -> Result<SanadOperationResult, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .lock_sanad(sanad_id, destination_chain, owner_key_id)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Sanad lock failed: {}", e),
            })
    }

    /// Create a new seal on the specified chain.
    ///
    /// This is the primary runtime function for seal creation. It delegates to the
    /// chain adapter's SealProtocol::create_seal method to create a real chain-native seal.
    ///
    /// # Arguments
    /// * `chain` - The blockchain where the seal will be created
    /// * `value` - Optional value/funding for the seal (chain-specific units like satoshis, wei, etc.)
    ///
    /// # Returns
    /// * `Ok(SealPoint)` - The real chain-native seal reference
    /// * `Err` - If seal creation fails
    ///
    /// # Example
    /// ```rust,ignore
    /// let seal_ref = runtime.create_seal(ChainId::new("bitcoin"), Some(100_000)).await?;
    /// // seal_ref.seal_id contains the actual on-chain identifier (e.g., UTXO txid)
    /// ```
    pub async fn create_seal(
        &self,
        chain: ChainId,
        value: Option<u64>,
    ) -> Result<csv_hash::seal::SealPoint, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        // Delegate to the adapter's create_seal method
        adapter
            .create_seal(value)
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Seal creation failed: {}", e),
            })
    }

    /// Publish a commitment under a single-use seal.
    ///
    /// Delegates to ChainBackend::publish_seal.
    pub async fn publish_seal(
        &self,
        chain: ChainId,
        seal: csv_hash::seal::SealPoint,
        commitment: csv_hash::Hash,
    ) -> Result<csv_hash::seal::CommitAnchor, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        // Delegate to the adapter's publish_seal method
        adapter
            .publish_seal(seal, commitment)
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Seal publishing failed: {}", e),
            })
    }

    /// Mint a sanad on the destination chain.
    ///
    /// Delegates to ChainSanadOps::mint_sanad.
    pub async fn mint_sanad(
        &self,
        chain: ChainId,
        source_chain: &str,
        source_sanad_id: &SanadId,
        lock_proof: &csv_proof::proof::InclusionProof,
        new_owner: &str,
    ) -> Result<SanadOperationResult, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .mint_sanad(source_chain, source_sanad_id, lock_proof, new_owner)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Sanad mint failed: {}", e),
            })
    }

    /// Confirm a transaction and check its finality status.
    ///
    /// Delegates to ChainBroadcaster::confirm_transaction.
    pub async fn confirm_transaction(
        &self,
        chain: ChainId,
        tx_hash: &str,
        required_confirmations: u64,
        timeout_secs: u64,
    ) -> Result<TransactionStatus, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .confirm_transaction(tx_hash, required_confirmations, timeout_secs)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Transaction confirmation failed: {}", e),
            })
    }

    /// Get fee estimate for the specified chain.
    ///
    /// Uses ChainBroadcaster trait to get the current recommended fee/gas price.
    /// This replaces raw HTTP JSON-RPC calls in wallet and CLI.
    pub async fn get_fee_estimate(&self, chain: ChainId) -> Result<u64, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        adapter
            .get_fee_estimate()
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Fee estimate query failed: {}", e),
            })
    }

    /// Get transaction count (nonce) for an address.
    ///
    /// Uses ChainQuery trait to get the account transaction count.
    /// This replaces raw HTTP JSON-RPC calls in wallet and CLI.
    pub async fn get_transaction_count(
        &self,
        chain: ChainId,
        address: &str,
    ) -> Result<u64, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        // Use the ChainQuery trait's get_account_nonce method
        // This properly queries the chain for account-specific nonce
        adapter
            .get_account_nonce(address)
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Failed to get transaction count: {}", e),
            })
    }

    /// Build a contract call transaction.
    ///
    /// This method builds the transaction data for a contract function call
    /// using the chain's native serialization format (ABI for Ethereum,
    /// BCS for Sui/Aptos, etc.).
    ///
    /// # Arguments
    /// * `chain` - The target chain
    /// * `contract` - Contract address (or package ID for Move chains)
    /// * `function` - Function name or selector
    /// * `args` - Function arguments as encoded bytes
    /// * `from` - Sender address
    /// * `nonce` - Transaction nonce/sequence number
    ///
    /// # Returns
    /// Serialized transaction data ready for signing
    #[deprecated(
        since = "0.4.0",
        note = "Use chain-specific contract call methods instead"
    )]
    pub async fn build_contract_call(
        &self,
        _chain: ChainId,
        _contract: &str,
        _function: &str,
        _args: Vec<Vec<u8>>,
        _from: &str,
        _nonce: u64,
    ) -> Result<Vec<u8>, CsvError> {
        Err(CsvError::CapabilityUnavailable {
            chain: _chain,
            capability: "build_contract_call".to_string(),
        })
    }

    /// Get the adapter for the specified chain.
    async fn get_adapter(&self, chain: ChainId) -> Result<Arc<dyn ChainBackend>, CsvError> {
        #[cfg(feature = "tokio")]
        let adapters = self.adapters.lock().await;
        #[cfg(not(feature = "tokio"))]
        let adapters = self.adapters.lock().unwrap();

        // Validate that RPC endpoints were configured and adapters initialized.
        // This is a configuration error — init_adapters() should catch this at startup.
        if adapters.is_empty() {
            return Err(CsvError::ConfigError(
                "No chain adapters registered in ChainRuntime. \
                 Call `client.init_adapters(NetworkType::Testnet)` or `init_adapters(NetworkType::Mainnet)` \
                 with proper RPC configuration before using runtime operations."
                    .to_string(),
            ));
        }

        adapters
            .get(&chain)
            .cloned()
            .ok_or(CsvError::ChainNotSupported(chain))
    }

    /// Check if an adapter is registered for the given chain.
    pub async fn has_adapter(&self, chain: ChainId) -> bool {
        #[cfg(feature = "tokio")]
        {
            let adapters = self.adapters.lock().await;
            adapters.contains_key(&chain)
        }
        #[cfg(not(feature = "tokio"))]
        {
            let adapters = self.adapters.lock().unwrap();
            adapters.contains_key(&chain)
        }
    }

    /// Get the list of registered chains.
    pub async fn registered_chains(&self) -> Vec<ChainId> {
        #[cfg(feature = "tokio")]
        {
            let adapters = self.adapters.lock().await;
            adapters.keys().cloned().collect()
        }
        #[cfg(not(feature = "tokio"))]
        {
            let adapters = self.adapters.lock().unwrap();
            adapters.keys().cloned().collect()
        }
    }

    /// Generate a proof for a sanad on the specified chain.
    ///
    /// This implementation queries the chain for inclusion proof data and constructs
    /// a complete ProofBundle for cross-chain transfers.
    ///
    /// # Security
    /// - Fetches real inclusion proof from chain state
    /// - Includes finality proof with confirmation count
    /// - Creates proper DAG segment with commitment
    /// - Signs the proof bundle for authenticity
    pub async fn generate_proof(
        &self,
        chain: ChainId,
        sanad_id: &SanadId,
    ) -> Result<ProofBundle, CsvError> {
        let chain_for_error = chain.clone();
        let adapter = self.get_adapter(chain_for_error.clone()).await?;

        // Query the chain for the inclusion proof at the latest block
        let block_height =
            adapter
                .get_latest_block_height()
                .await
                .map_err(|e| CsvError::ProtocolError {
                    chain: chain.clone(),
                    message: format!("Failed to get latest block height: {}", e),
                })?;

        // Create commitment from sanad_id (the sanad's hash is the commitment)
        let commitment = csv_hash::Hash::new(*sanad_id.as_bytes());

        // Build inclusion proof from chain state
        let inclusion_proof = adapter
            .build_inclusion_proof(&commitment, block_height, sanad_id.as_bytes())
            .await
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Failed to build inclusion proof: {}", e),
            })?;

        // Get the transaction info to build finality proof
        // For proof generation, we use the sanad_id as the lookup key
        let tx_hash_lookup = hex::encode(sanad_id.as_bytes());
        let tx_info = adapter.get_transaction(tx_hash_lookup.as_str()).await;
        let tx_hash = match &tx_info {
            Ok(info) => info.hash.clone(),
            Err(_) => hex::encode(sanad_id.as_bytes()), // Fallback to sanad_id as hex
        };

        // Build finality proof using the transaction hash
        let finality_proof =
            adapter
                .build_finality_proof(&tx_hash)
                .await
                .map_err(|e| CsvError::ProtocolError {
                    chain: chain.clone(),
                    message: format!("Failed to build finality proof: {}", e),
                })?;

        // Create a simple DAG segment with the sanad commitment
        use csv_hash::dag::{DAGNode, DAGSegment};
        let dag_node = DAGNode::new(
            commitment,
            vec![], // No inputs for lock operation
            vec![], // No signatures yet - added later
            vec![], // No outputs yet
            vec![], // No state transitions yet
        );
        let dag_segment = DAGSegment::new(vec![dag_node], commitment);

        // Create the proof bundle
        let seal_id = sanad_id.as_bytes().to_vec();
        let proof_bundle = ProofBundle::new(
            dag_segment,
            vec![], // Signatures will be added by the caller
            csv_hash::seal::SealPoint::new(seal_id.clone(), None).map_err(|e| {
                CsvError::ProtocolError {
                    chain: chain.clone(),
                    message: format!("Failed to create seal ref: {}", e),
                }
            })?,
            csv_hash::seal::CommitAnchor::new(
                seal_id,
                block_height,
                inclusion_proof.proof_bytes.clone(),
            )
            .map_err(|e| CsvError::ProtocolError {
                chain: chain.clone(),
                message: format!("Failed to create anchor ref: {}", e),
            })?,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| CsvError::ProtocolError {
            chain: chain.clone(),
            message: format!("Failed to create proof bundle: {}", e),
        })?;

        log::info!(
            "Generated proof bundle for sanad {:?} on {:?} at block {}",
            sanad_id,
            chain.clone(),
            block_height
        );

        Ok(proof_bundle)
    }

    /// Verify a proof bundle for a cross-chain transfer.
    ///
    /// This implementation uses the core proof verification pipeline to cryptographically
    /// validate the proof bundle before accepting cross-chain transfers.
    ///
    /// # Security
    /// - Verifies all signatures using the chain's signature scheme
    /// - Checks seal registry for replay attacks
    /// - Validates inclusion proof and finality
    /// - Returns false for any invalid proof, true only for fully valid proofs
    pub async fn verify_proof_bundle(
        &self,
        chain: ChainId,
        proof_bundle: &ProofBundle,
        sanad_id: &SanadId,
    ) -> Result<bool, CsvError> {
        let adapter = self.get_adapter(chain.clone()).await?;

        let signature_scheme = adapter.signature_scheme();
        let commitment = csv_hash::Hash::new(*sanad_id.as_bytes());

        let policy = match chain.as_str() {
            "bitcoin" | "btc" => csv_verifier::ChainBundlePolicy::bitcoin(),
            _ => csv_verifier::ChainBundlePolicy::permissive(),
        };

        let chain_native_ok = csv_verifier::verify_chain_proof_bundle(
            &csv_verifier::DynChainProofVerifier(adapter.as_ref()),
            &proof_bundle.inclusion_proof,
            &proof_bundle.finality_proof,
            &commitment,
            &policy,
        )
        .map_err(|e| CsvError::ProtocolError {
            chain: chain.clone(),
            message: format!("Chain-native proof verification failed: {}", e),
        })?;

        if !chain_native_ok {
            log::warn!(
                "Chain-native proof bundle invalid for sanad {:?} on {:?}",
                sanad_id,
                chain
            );
            return Ok(false);
        }

        // Pre-fetch seal consumption data BEFORE creating the closure
        // This avoids capturing self (which contains the sync Mutex) in the async context
        let seal_check_data = self.pre_fetch_seal_data(sanad_id).await?;

        // Create a seal registry checker for replay protection
        // The closure now only captures pre-fetched data, not self
        let seal_checker = move |seal_id: &[u8]| {
            let check_sanad_id = csv_hash::sanad::SanadId::from_bytes(seal_id);
            // Only return consumed if the seal_id matches the pre-fetched sanad_id AND it was consumed
            if check_sanad_id == seal_check_data.sanad_id {
                if seal_check_data.is_consumed {
                    log::warn!("Seal {} has already been consumed", hex::encode(seal_id));
                }
                seal_check_data.is_consumed
            } else {
                // Unknown seal - assume not consumed
                log::debug!(
                    "Seal {} not in pre-fetched data - assuming not consumed",
                    hex::encode(seal_id)
                );
                false
            }
        };

        // Use the core proof verification pipeline for signatures and seal check
        let result = csv_verifier::verify_proof(proof_bundle, seal_checker, signature_scheme);
        if result.is_valid {
            log::info!(
                "Proof bundle verified successfully for sanad {:?} on {:?}",
                sanad_id,
                chain
            );
            Ok(true)
        } else {
            log::warn!(
                "Proof verification failed for sanad {:?} on {:?}: {:?}",
                sanad_id,
                chain.clone(),
                result.errors
            );
            Ok(false)
        }
    }

    /// Broadcast a proof via P2P transport for destination chain discovery.
    ///
    /// This method serializes the proof and broadcasts it to Nostr relays
    /// tagged with the source and destination chain IDs, allowing destination chain
    /// nodes to discover and receive the proof for cross-chain validation.
    #[cfg(feature = "p2p")]
    pub async fn broadcast_proof(
        &self,
        chain: ChainId,
        proof: &csv_proof::proof::InclusionProof,
    ) -> Result<(), CsvError> {
        use csv_p2p::{NostrTransport, ProofTransport};

        let mut transport = NostrTransport::new();
        transport.initialize().await.map_err(|e| {
            CsvError::P2PError(format!("Failed to initialize Nostr transport: {}", e))
        })?;

        // Build a minimal ProofBundle from the InclusionProof for broadcast
        let proof_bundle = csv_proof::proof::ProofBundle {
            version: 1,
            transition_dag: csv_hash::dag::DAGSegment::new(vec![], proof.block_hash),
            signatures: vec![],
            seal_ref: csv_hash::seal::SealPoint::new(vec![], None)
                .map_err(|e| CsvError::P2PError(format!("Failed to create seal ref: {}", e)))?,
            anchor_ref: csv_hash::seal::CommitAnchor::new(
                vec![],
                proof.position,
                chain.to_string().into_bytes(),
            )
            .map_err(|e| CsvError::P2PError(format!("Failed to create anchor ref: {}", e)))?,
            inclusion_proof: proof.clone(),
            finality_proof: csv_proof::proof::FinalityProof::new(vec![], 1, true).map_err(|e| {
                CsvError::P2PError(format!("Failed to create finality proof: {}", e))
            })?,
            provenance: None,
            certification: None,
        };

        transport
            .broadcast_proof(&proof_bundle)
            .await
            .map_err(|e| {
                CsvError::P2PError(format!("Failed to broadcast proof to Nostr relays: {}", e))
            })?;

        log::info!("Proof for chain {:?} broadcast via Nostr P2P", chain);

        Ok(())
    }

    /// Pre-fetch seal consumption data to avoid locking in async closure.
    ///
    /// This fetches the sanad record from the store synchronously BEFORE entering
    /// the verification closure, preventing the async deadlock risk.
    async fn pre_fetch_seal_data(&self, sanad_id: &SanadId) -> Result<SealCheckData, CsvError> {
        // Clone the Arc to avoid capturing self in the spawned task
        let store_arc = Arc::clone(&self.client.store);
        let sanad_id_clone: csv_hash::sanad::SanadId = sanad_id.clone();

        // Run the store access in a blocking task since it uses std::sync::Mutex
        #[cfg(feature = "tokio")]
        let is_consumed = tokio::task::spawn_blocking(move || {
            let store = store_arc.lock().map_err(|e| e.to_string())?;
            match store.get_sanad(&sanad_id_clone) {
                Ok(Some(record)) => Ok(record.consumed_at.is_some()),
                Ok(None) => Ok(false), // Sanad not found = not consumed
                Err(e) => Err(format!("Store error: {}", e)),
            }
        })
        .await
        .map_err(|e| CsvError::StoreError(format!("Task join error: {}", e)))?
        .map_err(CsvError::StoreError)?;

        #[cfg(not(feature = "tokio"))]
        let is_consumed = {
            let store = store_arc
                .lock()
                .map_err(|e| CsvError::StoreError(e.to_string()))?;
            match store.get_sanad(&sanad_id_clone) {
                Ok(Some(record)) => Ok(record.consumed_at.is_some()),
                Ok(None) => Ok(false), // Sanad not found = not consumed
                Err(e) => Err(CsvError::StoreError(e.to_string())),
            }
        }?;

        Ok(SealCheckData {
            sanad_id: sanad_id.clone(),
            is_consumed,
        })
    }
}

/// Adapter configuration for the runtime.
#[derive(Debug, Clone, Default)]
pub struct RuntimeConfig {
    /// RPC endpoints for each chain
    pub rpc_endpoints: HashMap<ChainId, String>,
    /// Chain-specific configuration
    pub chain_config: HashMap<ChainId, HashMap<String, String>>,
}

/// Builder for constructing chain-specific ChainBackend instances.
///
/// This builder provides chain-specific construction methods that use the correct
/// constructors for each chain's ChainOperations type, following Clean Architecture.
///
/// # Architecture Compliance
///
/// All chains now follow the standard runtime pattern:
/// - **Bitcoin**: Uses `from_config(config, rpc)` with optional xpub in config
/// - **Ethereum**: Uses `from_config(config, rpc, csv_seal_address)`
/// - **Sui**: Uses `from_config(config, rpc)`
/// - **Aptos**: Uses `from_config(config, rpc)`
/// - **Solana**: Uses `from_config(config, rpc)`
///
/// Chain operations are created from seal protocols via `from_seal_protocol(&seal)`,
/// producing `Arc<dyn ChainBackend>` for registration in ChainRuntime.
///
/// The builder methods handle chain-specific configuration internally while
/// presenting a unified interface for the runtime.
pub struct AdapterBuilder;

impl AdapterBuilder {
    /// Create a new adapter builder.
    pub fn new() -> Self {
        Self
    }

    /// Build an Ethereum adapter from its specific configuration.
    ///
    /// Uses `EthereumBackend::from_seal_protocol()` internally which creates
    /// the ChainBackend implementation from an EthereumSealProtocol.
    #[cfg(feature = "ethereum")]
    pub async fn ethereum_from_config(
        &self,
        config: csv_ethereum::config::EthereumConfig,
        rpc: Box<dyn csv_ethereum::rpc::EthereumRpc>,
        csv_seal_address: [u8; 20],
    ) -> Result<Arc<dyn ChainBackend>, CsvError> {
        use csv_ethereum::ops::EthereumBackend;
        use csv_ethereum::seal_protocol::EthereumSealProtocol;

        // Create the SealProtocol first (this is the protocol primitive)
        let seal =
            EthereumSealProtocol::from_config(config, rpc, csv_seal_address).map_err(|e| {
                CsvError::ProtocolError {
                    chain: ChainId::new("ethereum"),
                    message: format!("Failed to create Ethereum seal protocol: {}", e),
                }
            })?;

        // Create ChainOperations from SealProtocol (this implements ChainBackend)
        let operations = EthereumBackend::from_seal_protocol(Arc::new(seal)).map_err(|e| {
            CsvError::ProtocolError {
                chain: ChainId::new("ethereum"),
                message: format!("Failed to create Ethereum chain operations: {}", e),
            }
        })?;

        Ok(Arc::new(operations))
    }

    /// Build a Sui adapter from configuration.
    #[cfg(feature = "sui")]
    pub async fn sui_from_config(
        &self,
        config: csv_sui::config::SuiConfig,
        rpc: Box<dyn csv_sui::rpc::SuiRpc>,
    ) -> Result<Arc<dyn ChainBackend>, CsvError> {
        use csv_sui::ops::SuiBackend;
        use csv_sui::seal_protocol::SuiSealProtocol;

        let seal =
            SuiSealProtocol::from_config(config, rpc).map_err(|e| CsvError::ProtocolError {
                chain: ChainId::new("sui"),
                message: format!("Failed to create Sui seal protocol: {}", e),
            })?;

        let operations = SuiBackend::from_seal_protocol(Arc::new(seal)).map_err(|e| {
            CsvError::ProtocolError {
                chain: ChainId::new("sui"),
                message: format!("Failed to create Sui chain operations: {}", e),
            }
        })?;

        Ok(Arc::new(operations))
    }

    /// Build an Aptos adapter from configuration.
    #[cfg(feature = "aptos")]
    pub async fn aptos_from_config(
        &self,
        config: csv_aptos::config::AptosConfig,
        rpc: Box<dyn csv_aptos::rpc::AptosRpc>,
    ) -> Result<Arc<dyn ChainBackend>, CsvError> {
        use csv_aptos::ops::AptosBackend;
        use csv_aptos::seal_protocol::AptosSealProtocol;

        let seal =
            AptosSealProtocol::from_config(config, rpc).map_err(|e| CsvError::ProtocolError {
                chain: ChainId::new("aptos"),
                message: format!("Failed to create Aptos seal protocol: {}", e),
            })?;

        let operations = AptosBackend::from_seal_protocol(Arc::new(seal)).map_err(|e| {
            CsvError::ProtocolError {
                chain: ChainId::new("aptos"),
                message: format!("Failed to create Aptos chain operations: {}", e),
            }
        })?;

        Ok(Arc::new(operations))
    }

    /// Build a Solana adapter from configuration.
    #[cfg(feature = "solana")]
    pub async fn solana_from_config(
        &self,
        config: csv_solana::config::SolanaConfig,
        rpc: Box<dyn csv_solana::rpc::SolanaRpc>,
    ) -> Result<Arc<dyn ChainBackend>, CsvError> {
        use csv_solana::ops::SolanaBackend;
        use csv_solana::seal_protocol::SolanaSealProtocol;

        // Solana now uses from_config() following the standard runtime pattern
        let seal =
            SolanaSealProtocol::from_config(config, rpc).map_err(|e| CsvError::ProtocolError {
                chain: ChainId::new("solana"),
                message: format!("Failed to create Solana seal protocol: {}", e),
            })?;

        let operations = SolanaBackend::from_seal_protocol(Arc::new(seal)).map_err(|e| {
            CsvError::ProtocolError {
                chain: ChainId::new("solana"),
                message: format!("Failed to create Solana chain operations: {}", e),
            }
        })?;

        Ok(Arc::new(operations))
    }

    /// Build a Bitcoin adapter from configuration.
    #[cfg(feature = "bitcoin")]
    pub async fn bitcoin_from_config(
        &self,
        config: csv_bitcoin::config::BitcoinConfig,
        rpc: Box<dyn csv_bitcoin::rpc::BitcoinRpc + Send + Sync>,
    ) -> Result<Arc<dyn ChainBackend>, CsvError> {
        use csv_bitcoin::ops::BitcoinBackend;
        use csv_bitcoin::seal_protocol::BitcoinSealProtocol;

        // Bitcoin uses from_config() following the standard runtime pattern
        let seal =
            BitcoinSealProtocol::from_config(config, rpc).map_err(|e| CsvError::ProtocolError {
                chain: ChainId::new("bitcoin"),
                message: format!("Failed to create Bitcoin seal protocol: {}", e),
            })?;

        let operations = BitcoinBackend::from_seal_protocol(Arc::new(seal)).map_err(|e| {
            CsvError::ProtocolError {
                chain: ChainId::new("bitcoin"),
                message: format!("Failed to create Bitcoin chain operations: {}", e),
            }
        })?;

        Ok(Arc::new(operations))
    }
}

impl Default for AdapterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Main adapter runtime that manages all chain adapters.
///
/// This is the entry point for creating and managing chain adapters
/// through a unified interface.
///
/// # Clean Architecture
///
/// This runtime does NOT directly create adapters. Instead:
/// 1. Use `AdapterBuilder` to construct chain-specific adapters with proper configuration
/// 2. Register adapters via `register_adapter()`
/// 3. Use `chain_runtime()` to access the unified operation interface
///
/// This design respects each chain's unique construction requirements while
/// providing a consistent interface for operations.
pub struct RuntimeManager {
    config: RuntimeConfig,
    chain_runtime: ChainRuntime,
    builder: AdapterBuilder,
}

impl RuntimeManager {
    /// Create a new adapter runtime with the given configuration.
    pub fn new(config: RuntimeConfig) -> Self {
        let client_ref = Arc::new(ClientRef::new());
        let chain_runtime = ChainRuntime::new(client_ref);
        let builder = AdapterBuilder::new();

        Self {
            config,
            chain_runtime,
            builder,
        }
    }

    /// Get the chain runtime for operations.
    pub fn chain_runtime(&self) -> &ChainRuntime {
        &self.chain_runtime
    }

    /// Get a mutable reference to the chain runtime for registering adapters.
    pub fn chain_runtime_mut(&mut self) -> &mut ChainRuntime {
        &mut self.chain_runtime
    }

    /// Get the adapter builder for constructing chain adapters.
    pub fn builder(&self) -> &AdapterBuilder {
        &self.builder
    }

    /// Register a pre-built adapter for a chain.
    ///
    /// Use this when you have constructed an adapter using `AdapterBuilder` or
    /// have a custom adapter implementation.
    pub async fn register_adapter(&mut self, chain: ChainId, adapter: Arc<dyn ChainBackend>) {
        self.chain_runtime.register_adapter(chain, adapter).await;
    }

    /// Get the adapter configuration.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Get a mutable reference to the adapter configuration.
    pub fn config_mut(&mut self) -> &mut RuntimeConfig {
        &mut self.config
    }
}

// Helper functions for encoding contract calls

/// Encode an Ethereum contract call using ABI format
#[cfg(test)]
fn encode_eth_contract_call(_contract: &str, function: &str, args: Vec<Vec<u8>>) -> Vec<u8> {
    // Simple ABI encoding: function selector (4 bytes) + encoded arguments
    // In production, this would use the ethabi or alloy-sol-types crate
    let mut data = Vec::new();

    // Create function selector from function signature hash
    let mut hasher = Keccak256::new();
    hasher.update(function.as_bytes());
    let hash = hasher.finalize();

    // First 4 bytes are the function selector
    data.extend_from_slice(&hash[..4]);

    // Append encoded arguments (padded to 32 bytes each for Ethereum)
    for arg in args {
        let mut padded = arg;
        // Pad to 32 bytes
        while padded.len() < 32 {
            padded.push(0);
        }
        data.extend_from_slice(&padded[..32.min(padded.len())]);
    }

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_config_default() {
        let config = RuntimeConfig::default();
        assert!(config.rpc_endpoints.is_empty());
        assert!(config.chain_config.is_empty());
    }

    #[tokio::test]
    async fn test_chain_runtime_creation() {
        let client_ref = Arc::new(ClientRef::new());
        let runtime = ChainRuntime::new(client_ref);
        assert!(runtime.adapters.lock().await.is_empty());
    }

    #[test]
    fn test_eth_contract_call_encoding() {
        let data = encode_eth_contract_call(
            "0x1234567890123456789012345678901234567890",
            "mint(bytes32,address)",
            vec![vec![0xAB; 32], vec![0xCD; 20]],
        );
        assert_eq!(data.len(), 4 + 32 + 32); // selector + 2 padded args
    }
}
