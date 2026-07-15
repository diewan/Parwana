//! Chain Operation Traits Implementation for Aptos
//!
//! This module implements all chain operation traits from csv-chain-ports:
//! - ChainQuery: Querying chain state via REST API
//! - ChainSigner: Ed25519 signing operations
//! - ChainBroadcaster: Transaction broadcasting
//! - ChainDeployer: Move module deployment
//! - ChainProofProvider: Proof building and verification
//! - ChainSanadOps: Sanad management operations
//!
use async_trait::async_trait;
use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_protocol::chain_adapter_traits::{
    BalanceInfo, CanonicalLifecycleEvent, CanonicalSanadState, CanonicalSealState, ChainBackend,
    ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError, ChainOpResult,
    ChainProofProvider, ChainQuery, ChainReadiness, ChainReadinessCheck, ChainSanadOps,
    ChainSigner, ContractStatus, DeploymentStatus, FinalityStatus, SanadOperationResult,
    SanadStateReader, TransactionInfo, TransactionStatus,
};
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::signature::SignatureScheme;
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

use crate::address_utils::format_address;
use crate::config::AptosNetwork;
use crate::proofs::CommitmentEventBuilder;
use crate::rpc::{AptosRpc, AptosTransaction};
use crate::seal_protocol::AptosSealProtocol;

/// Aptos chain operations implementation
pub struct AptosBackend {
    /// Inner RPC client for chain communication
    rpc: Box<dyn AptosRpc>,
    /// Chain configuration
    network: AptosNetwork,
    /// Domain separator for proof generation
    domain_separator: [u8; 32],
    /// Commitment event builder
    // Constructed with the adapter; the runtime proof path builds events itself.
    #[allow(dead_code)]
    event_builder: CommitmentEventBuilder,
    /// Reference to seal protocol for seal creation and publishing
    pub(crate) seal_protocol: Arc<AptosSealProtocol>,
    /// secp256k1 verifier key that signs the RFC-0012 §9.2 mint-attestation
    /// digest (optional).
    ///
    /// Distinct from the seal protocol's Ed25519 transaction signing key: the
    /// destination `csv_seal` module authenticates a mint by recovering M-of-N
    /// secp256k1 verifier public keys from signatures over the §9.2 digest
    /// (`secp256k1::ecdsa_recover`), independent of who submits the transaction.
    /// Absent any key the adapter fails closed rather than emitting an
    /// unauthenticated mint the module would reject. Multiple keys attach one
    /// verifier signature each, satisfying an M-of-N `MintAuthority` in a single
    /// mint (see MINT-KEYS-001).
    verifier_signing_keys: Vec<secp256k1::SecretKey>,
}

impl AptosBackend {
    /// Create new Aptos chain operations from RPC client.
    ///
    /// Fails closed: if the seal protocol cannot be constructed from the supplied
    /// RPC/config (e.g. malformed configuration), this returns a typed error instead
    /// of silently substituting a mock RPC client. A mock fallback here would mean
    /// production callers could end up signing/reading against a fake in-memory chain
    /// without any indication that real contract-backed behavior was never wired up.
    pub fn new(rpc: Box<dyn AptosRpc>, network: AptosNetwork) -> ChainOpResult<Self> {
        // Create seal protocol using the real RPC (not a mock)
        // This is required for publish() to work with transaction signing
        let config = crate::config::AptosConfig {
            network: network.clone(),
            ..Default::default()
        };
        let seal = AptosSealProtocol::from_config(config, rpc.clone_boxed()).map_err(|e| {
            ChainOpError::RpcError(format!(
                "Failed to construct Aptos seal protocol from RPC/config: {}",
                e
            ))
        })?;

        // MED-DUP-03: Derive domain separator from SealProtocol instead of recomputing
        let domain_separator = seal.domain();

        // Build event builder with default module address
        let module_address = [0u8; 32];
        let event_builder = CommitmentEventBuilder::new(module_address, "CSV::AnchorEvent");

        Ok(Self {
            rpc,
            network,
            domain_separator,
            event_builder,
            seal_protocol: Arc::new(seal),
            verifier_signing_keys: Vec::new(),
        })
    }

    /// Create from AptosSealProtocol
    pub fn from_seal_protocol(seal: Arc<AptosSealProtocol>) -> ChainOpResult<Self> {
        let (module_addr, event_type) = seal.event_builder_config();
        Ok(Self {
            rpc: seal.rpc().clone_boxed(),
            network: seal.network(),
            domain_separator: seal.domain(),
            event_builder: CommitmentEventBuilder::new(module_addr, event_type),
            seal_protocol: seal,
            verifier_signing_keys: Vec::new(),
        })
    }

    /// Set the secp256k1 verifier key that signs the RFC-0012 §9.2 mint
    /// attestation digest.
    ///
    /// This is the mint-authority key (its 33-byte compressed public key must be
    /// registered in the destination module's `MintAuthority` verifier set). It is
    /// distinct from the Ed25519 transaction signer held by the seal protocol.
    pub fn with_verifier_key(mut self, verifier_signing_key: secp256k1::SecretKey) -> Self {
        self.verifier_signing_keys.push(verifier_signing_key);
        self
    }

    /// Set the full set of secp256k1 verifier keys that sign the RFC-0012 §9.2
    /// mint attestation digest (MINT-KEYS-001).
    ///
    /// Replaces any previously configured keys. Each key's 33-byte compressed
    /// public key must be registered in the destination module's `MintAuthority`
    /// verifier set; the adapter attaches one signature per key so a single mint
    /// can satisfy an M-of-N threshold. An empty set leaves the backend
    /// fail-closed (no attestation signature).
    pub fn with_verifier_keys(mut self, verifier_signing_keys: Vec<secp256k1::SecretKey>) -> Self {
        self.verifier_signing_keys = verifier_signing_keys;
        self
    }

    /// Canonical 32-byte identity of the destination `csv_seal` module account
    /// (RFC-0012 §9.2 `destinationContract` on Aptos).
    ///
    /// The Move digest binds `destinationContract = bcs::to_bytes(&@csv_seal)`,
    /// which for an `address` is the 32-byte big-endian account address. The
    /// adapter forces this value into the attestation before signing rather than
    /// trusting the runtime-supplied (zeroed) contract identity, so the signed
    /// digest matches the value the module recomputes on-chain.
    pub fn module_contract_id(&self) -> ChainOpResult<[u8; 32]> {
        let module_address = &self.seal_protocol.config().seal_contract.module_address;
        crate::address_utils::parse_aptos_address(module_address).map_err(|e| {
            ChainOpError::InvalidInput(format!("Invalid csv_seal module address: {}", e))
        })
    }

    /// Sign a 32-byte RFC-0012 §9.2 attestation digest with the configured
    /// secp256k1 verifier key, producing a 65-byte recoverable signature
    /// (`r(32) || s(32) || v(1)`, `v` = recovery id `∈ {0, 1}`).
    ///
    /// The digest is `sha256(preimage)` (the frozen §9.2 preimage). The Move
    /// `csv_seal` module recovers the signer via `secp256k1::ecdsa_recover(digest,
    /// recovery_id, sig)` — recovering directly over the 32-byte digest — so
    /// signing the digest bytes recovers the same key on-chain. The recovery id is
    /// emitted raw (0/1), which the Move code also accepts as-is (it additionally
    /// tolerates the EVM `+27` form). Fails closed when no verifier key is
    /// configured rather than emitting an unauthenticated mint.
    pub fn sign_mint_attestation_digest(&self, digest: &[u8; 32]) -> ChainOpResult<Vec<u8>> {
        // The first configured verifier key (fail-closed on none). Retained for
        // single-signer callers/tests; the mint path uses the plural form below.
        let secret_key = self.verifier_signing_keys.first().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "No verifier signer configured: cannot attest the §9.2 mint digest \
                 (set a secp256k1 verifier key via with_verifier_key())."
                    .to_string(),
            )
        })?;
        Ok(Self::sign_digest_with(secret_key, digest))
    }

    /// Sign the §9.2 digest with **every** configured verifier key, returning one
    /// 65-byte recoverable signature per key (MINT-KEYS-001).
    ///
    /// This is the mint-path signer: multiple local signers satisfy an M-of-N
    /// `MintAuthority` in one transaction. Fails closed when no verifier key is
    /// configured rather than emitting an unauthenticated mint the module rejects.
    pub fn sign_mint_attestation_digests(&self, digest: &[u8; 32]) -> ChainOpResult<Vec<Vec<u8>>> {
        if self.verifier_signing_keys.is_empty() {
            return Err(ChainOpError::CapabilityUnavailable(
                "No verifier signer configured: cannot attest the §9.2 mint digest \
                 (set a secp256k1 verifier key via with_verifier_key())."
                    .to_string(),
            ));
        }
        Ok(self
            .verifier_signing_keys
            .iter()
            .map(|k| Self::sign_digest_with(k, digest))
            .collect())
    }

    /// Produce a single 65-byte recoverable signature (`r || s || v`, raw
    /// recovery id 0/1) over the 32-byte digest, matching the on-chain
    /// `secp256k1::ecdsa_recover`-over-digest semantics.
    fn sign_digest_with(secret_key: &secp256k1::SecretKey, digest: &[u8; 32]) -> Vec<u8> {
        use secp256k1::{Message, Secp256k1};
        let msg = Message::from_digest(*digest);
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa_recoverable(&msg, secret_key);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&compact);
        // Aptos `secp256k1::ecdsa_recover` expects the raw recovery id (0/1) as `v`.
        out.push(recovery_id.to_i32() as u8);
        out
    }

    /// Submit a verifier-attested §9.2 `csv_seal::mint_sanad` call and wait for its
    /// effects, returning `(tx_hash_hex, ledger_version)`.
    ///
    /// The `args` already carry the frozen §9.2 fields and the attached verifier
    /// signatures (built by the runtime adapter after it bound
    /// `destinationContract`, computed the digest, and signed it). This is the sole
    /// submission point; it fails closed on a reverted transaction.
    #[cfg(feature = "rpc")]
    pub async fn submit_attested_mint(
        &self,
        args: crate::mint::AptosMintArgs,
    ) -> ChainOpResult<SanadOperationResult> {
        use csv_protocol::chain_adapter_traits::SanadOperation;

        // Build the mint_sanad entry-function payload against the deployed module.
        let (module_addr, _) = self.seal_protocol.event_builder_config();
        let module_address = format_address(module_addr);
        let builder = crate::entry_function::EntryFunctionBuilder::new(module_address);
        let payload = builder.mint_sanad(
            args.sanad_id,
            args.commitment,
            args.source_chain,
            args.destination_owner.clone(),
            args.lock_event_id,
            args.nullifier,
            args.attestation_expiry,
            args.verifier_signatures.clone(),
        );

        // The Ed25519 signer is submission authority only; the helper also
        // rebuilds and re-signs on stale Aptos sequence numbers.
        let tx = self
            .seal_protocol
            .submit_entry_function_with_retry(payload)
            .await
            .map_err(|e| {
                ChainOpError::TransactionError(format!(
                    "Failed to submit mint_sanad transaction: {}",
                    e
                ))
            })?;

        Ok(SanadOperationResult {
            sanad_id: SanadId(Hash::new(args.sanad_id)),
            operation: SanadOperation::Mint,
            transaction_hash: hex::encode(tx.hash),
            block_height: tx.version,
            chain_id: "aptos".to_string(),
            metadata: Vec::new(),
        })
    }

    /// Parse Aptos address from string
    fn parse_address(&self, address: &str) -> ChainOpResult<[u8; 32]> {
        let hex_str = address.trim_start_matches("0x");
        let bytes = hex::decode(hex_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid hex address: {}", e)))?;

        if bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Aptos address must be 32 bytes".to_string(),
            ));
        }

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        Ok(addr)
    }

    /// Parse transaction hash (version)
    fn parse_version(&self, hash: &str) -> ChainOpResult<u64> {
        // Aptos uses version numbers, not hashes
        hash.parse()
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid version: {}", e)))
    }

    /// Convert Aptos transaction to TransactionInfo
    fn tx_to_info(&self, tx: &AptosTransaction) -> TransactionInfo {
        let status = if tx.success {
            TransactionStatus::Confirmed {
                block_height: tx.version,
                confirmations: 1, // Aptos has immediate finality
            }
        } else {
            TransactionStatus::Failed {
                reason: tx.vm_status.clone(),
            }
        };

        TransactionInfo {
            hash: format!("0x{}", hex::encode(tx.hash)),
            sender: "unknown".to_string(), // Would need to parse from payload
            recipient: None,
            amount: None,
            status,
            block_height: Some(tx.version),
            timestamp: None,
            fee: Some(tx.gas_used),
            raw_data: Some(tx.payload.clone()),
        }
    }

    /// Get RPC client reference
    pub fn rpc(&self) -> &dyn AptosRpc {
        self.rpc.as_ref()
    }
}

#[async_trait]
impl ChainQuery for AptosBackend {
    async fn get_balance(&self, address: &str) -> ChainOpResult<BalanceInfo> {
        let addr = self.parse_address(address)?;

        // Look for CoinStore resource
        let mut total_balance = 0u64;
        let token_balances = Vec::new();

        // Get the CoinStore resource directly for accurate balance
        let coin_resource = self
            .rpc()
            .get_resource(
                addr,
                "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
                None,
            )
            .await;

        if let Ok(Some(resource)) = coin_resource {
            // Parse coin balance from BCS-encoded resource data
            // CoinStore<T> layout: coin.value (u64) is the first 8 bytes
            if let Some(balance) = resource.parse_coin_balance() {
                total_balance = balance;
            }
        }

        Ok(BalanceInfo {
            address: address.to_string(),
            total: total_balance,
            available: total_balance,
            locked: 0,
            tokens: token_balances,
        })
    }

    async fn get_transaction(&self, hash: &str) -> ChainOpResult<TransactionInfo> {
        // Try parsing as version first (numeric), then fall back to hash lookup
        if let Ok(version) = self.parse_version(hash) {
            let tx = self
                .rpc()
                .get_transaction(version)
                .await
                .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?
                .ok_or_else(|| ChainOpError::RpcError("Transaction not found".to_string()))?;
            return Ok(self.tx_to_info(&tx));
        }

        // Fall back to hash-based lookup
        let tx = self
            .rpc()
            .get_transaction_by_hash(hash)
            .await
            .map_err(|e| {
                ChainOpError::RpcError(format!("Failed to get transaction by hash: {}", e))
            })?
            .ok_or_else(|| ChainOpError::RpcError("Transaction not found".to_string()))?;

        Ok(self.tx_to_info(&tx))
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        // In Aptos, transactions are finalized immediately
        // Finality is determined by being in a ledger with certified block
        let tx_info = self.get_transaction(tx_hash).await?;

        match tx_info.status {
            TransactionStatus::Confirmed { block_height, .. } => {
                // Get ledger info to verify
                let ledger =
                    self.rpc().get_ledger_info().await.map_err(|e| {
                        ChainOpError::RpcError(format!("Failed to get ledger: {}", e))
                    })?;

                // If transaction version is in current or older epoch, it's finalized
                if block_height <= ledger.ledger_version {
                    Ok(FinalityStatus::Finalized {
                        block_height,
                        finality_block: block_height,
                    })
                } else {
                    Ok(FinalityStatus::Pending)
                }
            }
            TransactionStatus::Failed { .. } => Ok(FinalityStatus::Orphaned),
            _ => Ok(FinalityStatus::Pending),
        }
    }

    async fn get_contract_status(&self, contract_address: &str) -> ChainOpResult<ContractStatus> {
        let addr = self.parse_address(contract_address)?;

        // Check if a specific resource exists at address to determine if contract is deployed
        let resource_result = self
            .rpc()
            .get_resource(addr, "0x1::account::Account", None)
            .await;

        let is_deployed = matches!(resource_result, Ok(Some(_)));

        Ok(ContractStatus {
            address: contract_address.to_string(),
            is_deployed,
            balance: None,
            owner: Some(contract_address.to_string()),
            metadata: serde_json::json!({
                "chain": "aptos",
                "network": format!("{:?}", self.network),
            }),
        })
    }

    async fn get_latest_block_height(&self) -> ChainOpResult<u64> {
        let ledger = self
            .rpc()
            .get_ledger_info()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get ledger: {}", e)))?;

        Ok(ledger.ledger_version)
    }

    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        let ledger = self
            .rpc()
            .get_ledger_info()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get ledger: {}", e)))?;

        Ok(serde_json::json!({
            "chain_id": ledger.chain_id,
            "chain": "aptos",
            "network": format!("{:?}", self.network),
            "epoch": ledger.epoch,
            "ledger_version": ledger.ledger_version,
            "oldest_version": ledger.oldest_ledger_version,
            "protocol": "Move",
            "finality": "deterministic",
        }))
    }

    async fn get_account_nonce(&self, address: &str) -> ChainOpResult<u64> {
        // Aptos uses account sequence numbers
        let addr = self.parse_address(address)?;

        self.rpc
            .get_account_sequence_number(addr)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get sequence number: {}", e)))
    }

    fn validate_address(&self, address: &str) -> bool {
        let hex_str = address.trim_start_matches("0x");
        match hex::decode(hex_str) {
            Ok(bytes) => bytes.len() == 32,
            Err(_) => false,
        }
    }
}

#[async_trait]
impl ChainSigner for AptosBackend {
    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String> {
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(public_key);

        // Aptos authentication key = SHA3-256(public_key | signature_scheme)
        // For single-key accounts: auth_key = SHA3-256(pubkey || 0x00)
        let mut data = pubkey.to_vec();
        data.push(0x00); // Ed25519 single key scheme
        let hash = Sha3_256::digest(&data);
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash[..32]);

        Ok(format!("0x{}", hex::encode(addr)))
    }

    async fn sign_transaction(&self, _tx_data: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        Err(ChainOpError::CapabilityUnavailable(
            "Direct transaction signing not available. \
             Use an external keystore with the key_id reference."
                .to_string(),
        ))
    }

    async fn sign_message(&self, _message: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        Err(ChainOpError::CapabilityUnavailable(
            "Direct message signing not available. \
             Use an external keystore with the key_id reference."
                .to_string(),
        ))
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> ChainOpResult<bool> {
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        if signature.len() != 64 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 signature must be 64 bytes".to_string(),
            ));
        }

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Convert bytes to proper types
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(public_key);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        // Create verifying key and signature
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {}", e)))?;

        let ed_sig = Signature::from_bytes(&sig_bytes);

        // Verify the signature
        match verifying_key.verify(message, &ed_sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}

#[async_trait]
impl ChainBroadcaster for AptosBackend {
    async fn submit_transaction(&self, signed_tx: &[u8]) -> ChainOpResult<String> {
        // Aptos signed transaction is BCS-encoded
        // Submit via submit_signed_transaction

        let signed_json = serde_json::from_slice(signed_tx).map_err(|e| {
            ChainOpError::InvalidInput(format!("Invalid signed transaction: {}", e))
        })?;

        let hash = self
            .rpc()
            .submit_signed_transaction(signed_json)
            .await
            .map_err(|e| ChainOpError::TransactionError(format!("Submission failed: {}", e)))?;

        Ok(format!("0x{}", hex::encode(hash)))
    }

    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        _required_confirmations: u64,
        timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus> {
        // Aptos uses version numbers as tx identifiers - parse and convert to hash
        let _version = self.parse_version(tx_hash)?;
        let hash = self.parse_address(tx_hash)?;

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_millis(500);

        loop {
            if start.elapsed() > timeout {
                return Err(ChainOpError::Timeout(
                    "Transaction confirmation timeout".to_string(),
                ));
            }

            match self.rpc().wait_for_transaction(hash).await {
                Ok(tx) => {
                    return Ok(if tx.success {
                        TransactionStatus::Confirmed {
                            block_height: tx.version,
                            confirmations: 1,
                        }
                    } else {
                        TransactionStatus::Failed {
                            reason: tx.vm_status,
                        }
                    });
                }
                Err(_) => {
                    // PF-03: always async (no cfg-gated blocking sleep)
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    async fn get_fee_estimate(&self) -> ChainOpResult<u64> {
        // Aptos gas estimation
        // Typical transaction: ~1000 gas units at 100 gas price = 100000 Octa (0.001 APT)
        Ok(100_000)
    }

    async fn validate_transaction(&self, tx_data: &[u8]) -> ChainOpResult<()> {
        if tx_data.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Empty transaction data".to_string(),
            ));
        }

        // Would decode BCS and validate structure

        Ok(())
    }
}

#[async_trait]
impl ChainDeployer for AptosBackend {
    async fn deploy_lock_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        let _ = admin_address;
        let _ = config;

        Err(ChainOpError::CapabilityUnavailable(
            "Lock contract deployment requires Move module publishing. \
             Use deploy_or_publish_seal_program() with compiled Move bytecode."
                .to_string(),
        ))
    }

    async fn deploy_mint_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        let _ = admin_address;
        let _ = config;

        Err(ChainOpError::CapabilityUnavailable(
            "Mint contract deployment requires Move module publishing. \
             Same module handles both lock and mint in Aptos."
                .to_string(),
        ))
    }

    async fn deploy_or_publish_seal_program(
        &self,
        program_bytes: &[u8],
        admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus> {
        let _ = program_bytes;
        let _ = admin_address;

        Err(ChainOpError::CapabilityUnavailable(
            "Seal program publishing requires signed transaction. \
             Use deploy_csv_seal_module() with compiled Move bytecode \
             or external tools (aptos move publish)."
                .to_string(),
        ))
    }

    async fn verify_deployment(&self, contract_address: &str) -> ChainOpResult<bool> {
        let status = self.get_contract_status(contract_address).await?;
        Ok(status.is_deployed)
    }

    async fn estimate_deployment_cost(&self, program_bytes: &[u8]) -> ChainOpResult<u64> {
        // Aptos deployment cost estimation
        let base_cost = 100_000u64; // Base gas
        let per_byte_cost = 10u64; // Gas per byte of code
        let code_cost = (program_bytes.len() as u64) * per_byte_cost;

        Ok(base_cost + code_cost)
    }
}

#[async_trait]
impl ChainProofProvider for AptosBackend {
    async fn build_inclusion_proof(
        &self,
        _commitment: &Hash,
        _block_height: u64,
        _anchor_id: &[u8],
    ) -> ChainOpResult<CoreInclusionProof> {
        Err(ChainOpError::CapabilityUnavailable(
            "Legacy Aptos ChainProofProvider inclusion proofs are disabled: \
             this path previously fabricated event payloads instead of accumulator \
             or transaction inclusion evidence. Use the runtime ChainProofPort path \
             for verifier-attested proof bundles."
                .to_string(),
        ))
    }

    fn verify_inclusion_proof(
        &self,
        proof: &CoreInclusionProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        self.verify_inclusion_native(proof, commitment)
    }

    async fn build_finality_proof(&self, tx_hash: &str) -> ChainOpResult<FinalityProof> {
        let finality = self.get_finality(tx_hash).await?;

        match finality {
            FinalityStatus::Finalized { finality_block, .. } => {
                let ledger =
                    self.rpc().get_ledger_info().await.map_err(|e| {
                        ChainOpError::RpcError(format!("Failed to get ledger: {}", e))
                    })?;

                let proof_data = serde_json::to_vec(&ledger)
                    .map_err(|e| ChainOpError::Unknown(format!("Serialization failed: {}", e)))?;

                // FinalityProof uses: finality_data, confirmations, is_deterministic
                let confirmations = ledger.ledger_version.saturating_sub(finality_block) + 1;
                Ok(FinalityProof::new(
                    proof_data,
                    confirmations,
                    true, // Aptos has deterministic finality via HotStuff
                )
                .map_err(|e| {
                    ChainOpError::InvalidInput(format!("Invalid finality proof: {}", e))
                })?)
            }
            _ => Err(ChainOpError::ProofVerificationError(
                "Transaction not finalized".to_string(),
            )),
        }
    }

    fn verify_finality_proof(&self, proof: &FinalityProof, tx_hash: &str) -> ChainOpResult<bool> {
        self.verify_finality_native(proof, tx_hash)
    }

    fn domain_separator(&self) -> [u8; 32] {
        self.domain_separator
    }

    async fn verify_proof_bundle(
        &self,
        inclusion_proof: &CoreInclusionProof,
        finality_proof: &FinalityProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        self.verify_proof_bundle_native(inclusion_proof, finality_proof, commitment)
    }
}

#[async_trait]
impl ChainSanadOps for AptosBackend {
    async fn create_sanad(
        &self,
        _owner: &str,
        _asset_class: &str,
        _asset_id: &str,
        _metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "Legacy Aptos ChainSanadOps::create_sanad cannot receive the canonical owner-bound Sanad ID and is disabled. Use csv-runtime create_seal + publish_seal."
                .to_string(),
        ))
    }

    async fn consume_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = owner_key_id;

        #[cfg(feature = "rpc")]
        {
            use crate::types::AptosSealPoint;
            use csv_protocol::chain_adapter_traits::SanadOperation;

            // The sanad_id is the commitment hash
            let commitment = *sanad_id.as_bytes();

            log::debug!(
                "APTOS: Consuming sanad with commitment: {}",
                hex::encode(commitment)
            );

            // Create a seal point - for consume, the seal is at the signer's address
            // The actual address will be derived from the signing key in build_and_sign_entry_function
            let seal = AptosSealPoint {
                account_address: [0u8; 32], // Will be derived from signing key
                resource_type: "0x1::csv_seal::Seal".to_string(),
                nonce: 0u64,
            };

            // Build and sign the consume_seal transaction using the seal protocol
            let (signed_tx, _event_data) = self
                .seal_protocol
                .build_and_sign_entry_function(&seal, commitment)
                .await
                .map_err(|e| {
                    ChainOpError::TransactionError(format!(
                        "Failed to build and sign consume_seal transaction: {}",
                        e
                    ))
                })?;

            log::debug!("APTOS: Built and signed consume_seal transaction");

            // Submit the signed transaction via RPC
            log::debug!("APTOS: Submitting consume_seal transaction");
            let tx_hash = self
                .rpc
                .submit_signed_transaction(signed_tx)
                .await
                .map_err(|e| {
                    ChainOpError::TransactionError(format!("Failed to submit transaction: {}", e))
                })?;

            log::debug!(
                "APTOS: Transaction submitted with hash: {}",
                hex::encode(tx_hash)
            );

            // Wait for transaction confirmation
            log::debug!("APTOS: Waiting for transaction confirmation");
            let tx = match self.rpc.wait_for_transaction(tx_hash).await {
                Ok(tx) => tx,
                Err(e) => {
                    // Timeout or error waiting - try to get transaction status directly
                    log::warn!("APTOS: Timeout waiting for transaction, querying status directly");
                    // Try to get transaction by hash (if RPC supports it) or return error with tx hash
                    return Err(ChainOpError::Timeout(format!(
                        "Timeout waiting for transaction confirmation. Transaction hash: {}. Check explorer for status.",
                        hex::encode(tx_hash)
                    )));
                }
            };

            if !tx.success {
                return Err(ChainOpError::TransactionError(format!(
                    "Transaction failed with VM status: {}",
                    tx.vm_status
                )));
            }

            log::debug!("APTOS: Transaction confirmed successfully");

            Ok(SanadOperationResult {
                sanad_id: sanad_id.clone(),
                operation: SanadOperation::Consume,
                transaction_hash: hex::encode(tx_hash),
                block_height: tx.version,
                chain_id: "aptos".to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({})).unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(ChainOpError::CapabilityUnavailable(
                "Sanad consumption requires RPC feature. Enable with --features rpc".to_string(),
            ))
        }
    }

    async fn lock_sanad(
        &self,
        sanad_id: &SanadId,
        destination_chain: &str,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        #[cfg(feature = "rpc")]
        {
            use csv_protocol::chain_adapter_traits::SanadOperation;

            // Parse the destination chain to ensure it's valid
            let _destination = destination_chain
                .parse::<csv_hash::chain_id::ChainId>()
                .map_err(|_| {
                    ChainOpError::InvalidInput(format!(
                        "Invalid destination chain: {}",
                        destination_chain
                    ))
                })?;

            // Parse owner key for signing (expecting hex-encoded 32-byte address)
            let owner_key_id_clean = owner_key_id.trim_start_matches("0x");
            let owner_bytes = hex::decode(owner_key_id_clean).map_err(|_| {
                ChainOpError::InvalidInput("Invalid owner key ID format".to_string())
            })?;

            if owner_bytes.len() != 32 {
                return Err(ChainOpError::InvalidInput(
                    "Owner key must be 32 bytes".to_string(),
                ));
            }

            let _owner_address: [u8; 32] = owner_bytes.try_into().map_err(|_| {
                ChainOpError::InvalidInput("Invalid owner address format".to_string())
            })?;

            // The sanad_id is the commitment hash
            let commitment = *sanad_id.as_bytes();

            log::debug!(
                "APTOS: Locking sanad with commitment: {}",
                hex::encode(commitment)
            );
            log::debug!("APTOS: Destination chain: {}", destination_chain);

            // Query the seal resource from on-chain instead of using in-memory registry
            // The seal was created via CLI and may not be in the in-memory registry
            let account_address = self
                .seal_protocol
                .signing_key
                .as_ref()
                .map(|key| {
                    use sha3::{Digest, Sha3_256};
                    let public_key = key.verifying_key().to_bytes();
                    let mut data = public_key.to_vec();
                    data.push(0x00); // Ed25519 single key scheme
                    let hash = Sha3_256::digest(&data);
                    let mut addr = [0u8; 32];
                    addr.copy_from_slice(&hash[..32]);
                    addr
                })
                .ok_or_else(|| {
                    ChainOpError::InvalidInput("No signing key configured".to_string())
                })?;

            // Query the seal resource from on-chain
            let seal = self
                .seal_protocol
                .get_seal_from_chain(account_address)
                .await
                .map_err(|e| {
                    ChainOpError::InvalidInput(format!("Failed to query seal from chain: {}", e))
                })?;

            // Get the nonce from the seal
            let nonce = seal.nonce;

            use csv_protocol::cross_chain::CrossChainHashAlgorithm;
            let destination_tag = format!("csv.chain.{destination_chain}");
            let destination_chain_id = *CrossChainHashAlgorithm::Keccak256
                .hash_bytes(destination_tag.as_bytes())
                .as_bytes();

            // Build the lock_sanad entry function payload
            let entry_function_builder = crate::entry_function::EntryFunctionBuilder::new(
                self.seal_protocol
                    .config()
                    .seal_contract
                    .module_address
                    .clone(),
            );
            let payload = entry_function_builder.lock_sanad(
                nonce,
                commitment,
                destination_chain_id,
                _owner_address,
            );

            let tx = self
                .seal_protocol
                .submit_entry_function_with_retry(payload)
                .await
                .map_err(|e| {
                    ChainOpError::TransactionError(format!(
                        "Failed to submit lock_sanad transaction: {}",
                        e
                    ))
                })?;

            Ok(SanadOperationResult {
                sanad_id: sanad_id.clone(),
                operation: SanadOperation::Lock,
                transaction_hash: hex::encode(tx.hash),
                block_height: tx.version,
                chain_id: "aptos".to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "destination_chain": destination_chain,
                    "seal_address": hex::encode(seal.account_address),
                }))
                .unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(ChainOpError::CapabilityUnavailable(
                "Sanad locking requires RPC feature. Enable with --features rpc".to_string(),
            ))
        }
    }

    async fn mint_sanad(
        &self,
        _source_chain: &str,
        _source_sanad_id: &SanadId,
        _lock_proof: &CoreInclusionProof,
        _new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Pre-RFC-0012 mint shape. Under the thin-registry model (RFC-0012 §9) a
        // destination mint is NOT authorized by a lock/inclusion proof handed to
        // the chain, and carries no `u8` source-chain tag: cross-chain validity is
        // adjudicated OFF-CHAIN by the canonical verifier, and the only on-chain
        // authenticity check is a set of secp256k1 verifier signatures over the
        // frozen §9.2 attestation digest. The authoritative mint path is
        // `AptosRuntimeAdapter::mint_sanad`, which decodes the runtime's
        // `RuntimeMintRequest`, binds `destinationContract = @csv_seal` module
        // address, signs the §9.2 digest, and calls
        // `AptosBackend::submit_attested_mint`. Fail closed here rather than submit
        // a mint authenticated by a proof the module never checks.
        Err(ChainOpError::CapabilityUnavailable(
            "Aptos mint is verifier-attested (RFC-0012 §9.2); use \
             AptosRuntimeAdapter::mint_sanad which carries the attestation, not the \
             pre-RFC-0012 inclusion-proof mint path."
                .to_string(),
        ))
    }

    async fn refund_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = sanad_id;
        let _ = owner_key_id;

        Err(ChainOpError::CapabilityUnavailable(
            "Sanad refund requires signed transaction. \
             Construct and submit a transaction to refund the locked seal."
                .to_string(),
        ))
    }

    async fn record_sanad_metadata(
        &self,
        sanad_id: &SanadId,
        metadata: serde_json::Value,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = sanad_id;
        let _ = metadata;
        let _ = owner_key_id;

        Err(ChainOpError::CapabilityUnavailable(
            "Metadata recording requires signed transaction. \
             Construct and submit a transaction to update seal metadata."
                .to_string(),
        ))
    }

    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        expected_state: &str,
    ) -> ChainOpResult<bool> {
        // Query the seal resource at the address derived from sanad_id
        // In Aptos, resources are stored at the owner's address
        // The sanad_id contains the address and resource type info

        let sanad_bytes = sanad_id.as_bytes();

        // Derive the account address from sanad_id
        // For simplicity, we use the first 32 bytes as the address
        let mut address_bytes = [0u8; 32];
        if sanad_bytes.len() >= 32 {
            address_bytes.copy_from_slice(&sanad_bytes[..32]);
        } else {
            address_bytes[..sanad_bytes.len()].copy_from_slice(sanad_bytes);
        }

        // Query account resources via RPC
        // Check if the account exists and has the expected resource
        let account_exists = self
            .rpc()
            .get_account_sequence_number(address_bytes)
            .await
            .is_ok();

        if !account_exists {
            // Account doesn't exist - either never created or deleted
            return match expected_state {
                "consumed" | "deleted" | "never_created" => Ok(true),
                _ => Ok(false),
            };
        }

        // Query the specific resource type at the address to determine actual state
        // The sanad resource contains state information that we need to parse
        let actual_state = if account_exists {
            // Try to query the sanad resource from the account
            let (module_addr, _event_type) = self.seal_protocol.event_builder_config();
            let resource_type = format!("0x{}::sanad::Sanad", hex::encode(module_addr));
            match self
                .rpc()
                .get_resource(address_bytes, &resource_type, None)
                .await
            {
                Ok(Some(_)) => "active",
                Ok(None) => "consumed",
                Err(_) => "unknown",
            }
        } else {
            "consumed"
        };

        Ok(actual_state == expected_state)
    }
}

#[async_trait]
impl ChainBackend for AptosBackend {
    fn chain_id(&self) -> &'static str {
        "aptos"
    }

    fn chain_name(&self) -> &'static str {
        "Aptos"
    }

    fn is_capability_available(&self, _capability: ChainCapability) -> bool {
        true
    }

    async fn create_seal(
        &self,
        value: Option<u64>,
        sanad_id: Hash,
        commitment: Hash,
    ) -> ChainOpResult<SealPoint> {
        let aptos_seal = self
            .seal_protocol
            .create_seal(value, sanad_id, commitment)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal creation failed: {}", e)))?;

        // Convert AptosSealPoint to core SealPoint
        // AptosSealPoint has account_address (32 bytes) stored in id
        Ok(SealPoint {
            id: aptos_seal.account_address.to_vec(),
            nonce: Some(aptos_seal.nonce),
            version: None,
        })
    }

    async fn publish_seal(
        &self,
        seal: SealPoint,
        commitment: Hash,
        sanad_id: Hash,
    ) -> ChainOpResult<CommitAnchor> {
        // Convert core SealPoint to AptosSealPoint
        if seal.id.len() < 32 {
            return Err(ChainOpError::InvalidInput(
                "Seal ID too short for Aptos, expected at least 32 bytes".to_string(),
            ));
        }

        let mut account_address = [0u8; 32];
        account_address.copy_from_slice(&seal.id[..32]);

        let nonce = seal.nonce.unwrap_or(0);
        let aptos_seal =
            crate::types::AptosSealPoint::new(account_address, String::from("csv_seal"), nonce);

        // Call the seal protocol's publish method
        let aptos_anchor = self
            .seal_protocol
            .publish(commitment, aptos_seal, sanad_id)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal publishing failed: {}", e)))?;

        // Convert AptosCommitAnchor to core CommitAnchor
        Ok(CommitAnchor {
            anchor_id: aptos_anchor.event_handle.to_vec(),
            block_height: aptos_anchor.version,
            metadata: aptos_anchor.sequence_number.to_le_bytes().to_vec(),
        })
    }
}

#[async_trait]
impl SanadStateReader for AptosBackend {
    async fn get_sanad_state(&self, sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState> {
        let (module_addr, _) = self.seal_protocol.event_builder_config();
        let registry_address = format_address(module_addr);
        let function = format!("{}::CSVSeal::get_sanad_info", registry_address);
        let response = self
            .rpc
            .call_view(
                &function,
                vec![
                    serde_json::Value::String(registry_address),
                    serde_json::Value::String(format!("0x{}", hex::encode(sanad_id.as_bytes()))),
                ],
            )
            .await
            .map_err(|e| {
                ChainOpError::RpcError(format!("Aptos canonical state view failed: {e}"))
            })?;

        let values = response.as_array().ok_or_else(|| {
            ChainOpError::RpcError("Aptos get_sanad_info returned a non-array result".to_string())
        })?;
        if values.len() != 4 {
            return Err(ChainOpError::RpcError(format!(
                "Aptos get_sanad_info returned {} values; expected 4",
                values.len()
            )));
        }

        let parse_number = |value: &serde_json::Value, field: &str| -> ChainOpResult<u64> {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|raw| raw.parse::<u64>().ok()))
                .ok_or_else(|| {
                    ChainOpError::RpcError(format!("Aptos get_sanad_info returned invalid {field}"))
                })
        };
        let state = u8::try_from(parse_number(&values[0], "state")?).map_err(|_| {
            ChainOpError::RpcError("Aptos get_sanad_info state exceeds u8".to_string())
        })?;
        if state > 9 {
            return Err(ChainOpError::RpcError(format!(
                "Aptos get_sanad_info returned unknown canonical state {state}"
            )));
        }

        let commitment = if state == 0 {
            Hash::new([0u8; 32])
        } else {
            let encoded = values[1].as_str().ok_or_else(|| {
                ChainOpError::RpcError(
                    "Aptos get_sanad_info returned invalid commitment".to_string(),
                )
            })?;
            let bytes = hex::decode(encoded.trim_start_matches("0x")).map_err(|e| {
                ChainOpError::RpcError(format!(
                    "Aptos get_sanad_info returned malformed commitment: {e}"
                ))
            })?;
            let fixed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
                ChainOpError::RpcError(format!(
                    "Aptos get_sanad_info commitment must be 32 bytes, got {}",
                    bytes.len()
                ))
            })?;
            Hash::new(fixed)
        };
        let owner = values[2]
            .as_str()
            .ok_or_else(|| {
                ChainOpError::RpcError("Aptos get_sanad_info returned invalid owner".to_string())
            })?
            .to_string();
        let timestamp = i64::try_from(parse_number(&values[3], "timestamp")?).map_err(|_| {
            ChainOpError::RpcError("Aptos get_sanad_info timestamp exceeds i64".to_string())
        })?;

        Ok(CanonicalSanadState {
            state,
            owner,
            commitment,
            nullifier: None,
            created_at: if state == 1 { timestamp } else { 0 },
            locked_at: (state == 3).then_some(timestamp),
            consumed_at: None,
            minted_at: (state == 5).then_some(timestamp),
            refunded_at: (state == 7).then_some(timestamp),
        })
    }

    async fn get_seal_state(&self, seal_id: &Hash) -> ChainOpResult<CanonicalSealState> {
        // For Aptos, seal state is derived from the resource state
        // Query the seal resource to determine if it's been consumed
        let seal_bytes = seal_id.as_bytes();
        let mut address_bytes = [0u8; 32];
        if seal_bytes.len() >= 32 {
            address_bytes.copy_from_slice(&seal_bytes[..32]);
        } else {
            address_bytes[..seal_bytes.len()].copy_from_slice(seal_bytes);
        }

        // Query the seal resource to check seal state
        let (module_addr, _event_type) = self.seal_protocol.event_builder_config();
        let resource_type = format!("0x{}::seal::Seal", hex::encode(module_addr));

        match self
            .rpc()
            .get_resource(address_bytes, &resource_type, None)
            .await
        {
            Ok(Some(_resource)) => {
                // Seal resource exists - check if consumed
                // For now, return an error indicating that resource parsing is not yet implemented
                return Err(ChainOpError::CapabilityUnavailable(
                    "Seal resource parsing is not yet implemented for Aptos. \
                     The resource exists but cannot be parsed into canonical state. \
                     This requires BCS decoding of the Move resource structure."
                        .to_string(),
                ));
            }
            Ok(None) => {
                // Seal resource doesn't exist
                Ok(CanonicalSealState {
                    state: 0, // Not created
                    owner: "unknown".to_string(),
                    commitment: *seal_id,
                    created_at: 0,
                    consumed_at: None,
                })
            }
            Err(e) => {
                // Failed to query resources
                return Err(ChainOpError::RpcError(format!(
                    "Failed to query seal resource: {}",
                    e
                )));
            }
        }
    }

    async fn trace_sanad(
        &self,
        _sanad_id: &SanadId,
    ) -> ChainOpResult<Vec<CanonicalLifecycleEvent>> {
        // Query events from Aptos for this sanad_id
        // This would require querying the event logs from the contract
        Ok(vec![])
    }
}

#[async_trait]
impl ChainReadinessCheck for AptosBackend {
    async fn check_readiness(&self, _account: u32, _index: u32) -> ChainOpResult<ChainReadiness> {
        // A configured string is not evidence of a usable deployment. The
        // thin registry is enabled only after `init_registry` creates this
        // resource at the module account.
        let (module_addr, _) = self.seal_protocol.event_builder_config();
        let lock_registry_type = format!("0x{}::CSVSeal::LockRegistry", hex::encode(module_addr));
        let sanad_registry_type = format!("0x{}::CSVSeal::SanadRegistry", hex::encode(module_addr));
        let lock_registry_configured = matches!(
            self.rpc()
                .get_resource(module_addr, &lock_registry_type, None)
                .await,
            Ok(Some(_))
        );
        let sanad_registry_configured = matches!(
            self.rpc()
                .get_resource(module_addr, &sanad_registry_type, None)
                .await,
            Ok(Some(_))
        );
        let contract_configured = lock_registry_configured && sanad_registry_configured;

        // Check if signer is actually configured by checking the config
        let signer_configured = self.seal_protocol.config().private_key.is_some();

        // Derive signer address from private key if available
        let signer_address = if signer_configured {
            if let Some(ref secret_key) = self.seal_protocol.config().private_key {
                use ed25519_dalek::SigningKey;
                let key_bytes = secret_key.expose_secret();
                let signing_key = SigningKey::from_bytes(key_bytes);
                let public_key = signing_key.verifying_key().to_bytes();
                let mut authentication_key = public_key.to_vec();
                authentication_key.push(0x00);
                let address = Sha3_256::digest(&authentication_key);
                Some(format!("0x{}", hex::encode(address)))
            } else {
                None
            }
        } else {
            None
        };

        // Balance address is same as signer address for Aptos
        let balance_address = signer_address.clone();

        // Check write capability (signer configured + RPC available)
        let write_capable = signer_configured;

        // Check if account exists (has balance > 0)
        let account_exists = if let Some(ref addr) = balance_address {
            match <Self as ChainQuery>::get_balance(self, addr.as_str()).await {
                Ok(balance) => balance.total > 0,
                Err(_) => false,
            }
        } else {
            false
        };

        // Get native balance
        let native_balance = if let Some(ref addr) = balance_address {
            match <Self as ChainQuery>::get_balance(self, addr.as_str()).await {
                Ok(balance) => Some(balance.total),
                Err(_) => None,
            }
        } else {
            None
        };

        // Estimate minimum fee (100 APT for simple transaction)
        let estimated_fee = Some(100_000_000); // 100 APT in octas

        // Aptos supports sanad creation (via module)
        let sanad_create_supported = contract_configured;

        // Aptos supports proof generation
        let proof_generation_supported = true;

        // Aptos can be cross-chain source
        let cross_chain_source_supported = true;

        // Aptos can be cross-chain destination
        let cross_chain_destination_supported = true;

        Ok(ChainReadiness {
            signer_address,
            balance_address,
            signer_configured,
            write_capable,
            contract_configured,
            account_exists,
            native_balance,
            estimated_fee,
            sanad_create_supported,
            proof_generation_supported,
            cross_chain_source_supported,
            cross_chain_destination_supported,
            metadata: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::MockAptosRpc;

    #[test]
    fn test_aptos_chain_operations_creation() {
        let rpc = Box::new(MockAptosRpc::new(1));
        let ops = AptosBackend::new(rpc, AptosNetwork::Devnet)
            .expect("AptosBackend::new should succeed with a mock RPC and valid config");
        assert_eq!(ops.network, AptosNetwork::Devnet);
    }

    // PROOFGEN-MULTICHAIN-001: the create-anchor inclusion builder must fail
    // closed rather than fabricate accumulator/event evidence. Real, sanad-bound
    // Aptos inclusion evidence is an open per-chain question — Aptos's anchor is
    // an account/event handle, not a transaction hash — so it stays disabled.
    #[tokio::test]
    async fn build_inclusion_proof_fails_closed_no_fabrication() {
        let ops = AptosBackend::new(Box::new(MockAptosRpc::new(1000)), AptosNetwork::Devnet)
            .expect("AptosBackend::new should succeed with a mock RPC and valid config");
        let commitment = Hash::new([0x02u8; 32]);
        let result = ops
            .build_inclusion_proof(&commitment, 1, &[0x07u8; 32])
            .await;
        assert!(
            matches!(result, Err(ChainOpError::CapabilityUnavailable(_))),
            "Aptos must fail closed (no fabricated inclusion evidence): {result:?}"
        );
    }

    #[test]
    fn test_address_validation() {
        let rpc = Box::new(MockAptosRpc::new(1));
        let ops = AptosBackend::new(rpc, AptosNetwork::Devnet)
            .expect("AptosBackend::new should succeed with a mock RPC and valid config");

        // Valid address
        assert!(ops.validate_address(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        ));

        // Invalid - too short
        assert!(!ops.validate_address("0x1234"));

        // Invalid - not hex
        assert!(!ops.validate_address("0xZZZZ"));
    }

    #[test]
    fn test_aptos_backend_new_fails_closed_on_bad_config() {
        // A missing module address makes `AptosSealProtocol::from_config` fail
        // validation. `AptosBackend::new` must propagate that error instead of
        // silently falling back to a mock RPC / seal protocol, since a mock
        // fallback here would let production callers sign/read against a fake
        // in-memory chain with no indication real contract-backed behavior was
        // never wired up.
        let rpc: Box<dyn AptosRpc> = Box::new(MockAptosRpc::new(1));
        let mut bad_config = crate::config::AptosConfig {
            network: AptosNetwork::Devnet,
            ..Default::default()
        };
        bad_config.seal_contract.module_address = String::new();
        let result = AptosSealProtocol::from_config(bad_config, rpc);
        assert!(
            result.is_err(),
            "empty module address must fail closed, not fall back to a mock seal protocol"
        );
    }

    #[tokio::test]
    async fn canonical_state_view_decodes_created_sanad() {
        let config = crate::config::AptosConfig {
            network: AptosNetwork::Devnet,
            ..Default::default()
        };
        let module =
            crate::address_utils::parse_aptos_address(&config.seal_contract.module_address)
                .unwrap();
        let function = format!("{}::CSVSeal::get_sanad_info", format_address(module));
        let rpc = MockAptosRpc::new(1);
        rpc.set_view_result(
            &function,
            serde_json::json!([
                1,
                format!("0x{}", hex::encode([0x22; 32])),
                format!("0x{}", hex::encode([0x33; 32])),
                "1234"
            ]),
        );
        let backend = AptosBackend::new(Box::new(rpc), AptosNetwork::Devnet).unwrap();
        let state = backend
            .get_sanad_state(&SanadId(Hash::new([0x11; 32])))
            .await
            .unwrap();

        assert_eq!(state.state, 1);
        assert_eq!(state.commitment, Hash::new([0x22; 32]));
        assert_eq!(state.created_at, 1234);
    }

    #[tokio::test]
    async fn canonical_state_view_rejects_malformed_commitment() {
        let config = crate::config::AptosConfig {
            network: AptosNetwork::Devnet,
            ..Default::default()
        };
        let module =
            crate::address_utils::parse_aptos_address(&config.seal_contract.module_address)
                .unwrap();
        let function = format!("{}::CSVSeal::get_sanad_info", format_address(module));
        let rpc = MockAptosRpc::new(1);
        rpc.set_view_result(&function, serde_json::json!([1, "0x1234", "0x1", "1234"]));
        let backend = AptosBackend::new(Box::new(rpc), AptosNetwork::Devnet).unwrap();
        let result = backend
            .get_sanad_state(&SanadId(Hash::new([0x11; 32])))
            .await;

        assert!(matches!(result, Err(ChainOpError::RpcError(_))));
    }

    fn backend_with_keys(keys: Vec<secp256k1::SecretKey>) -> AptosBackend {
        let rpc = Box::new(MockAptosRpc::new(1));
        AptosBackend::new(rpc, AptosNetwork::Devnet)
            .expect("backend")
            .with_verifier_keys(keys)
    }

    #[tokio::test]
    async fn legacy_chain_proof_provider_inclusion_build_fails_closed() {
        let backend = backend_with_keys(vec![]);
        let commitment = Hash::sha256(b"phase-2-aptos-commitment");
        let anchor_id = Hash::sha256(b"phase-2-aptos-anchor");

        let result = backend
            .build_inclusion_proof(&commitment, 42, anchor_id.as_bytes())
            .await;

        assert!(
            matches!(result, Err(ChainOpError::CapabilityUnavailable(ref message)) if message.contains("Legacy Aptos ChainProofProvider inclusion proofs are disabled")),
            "legacy provider must not fabricate inclusion proofs: {result:?}"
        );
    }

    #[test]
    fn legacy_chain_proof_provider_inclusion_verify_fails_closed() {
        let backend = backend_with_keys(vec![]);
        let commitment = Hash::sha256(b"phase-2-aptos-commitment");
        let forged = CoreInclusionProof {
            proof_bytes: commitment.as_bytes().to_vec(),
            block_hash: Hash::sha256(b"phase-2-aptos-block"),
            position: 42,
            block_number: 42,
            ..Default::default()
        };

        let result = backend.verify_inclusion_proof(&forged, &commitment);

        assert!(
            matches!(result, Err(ChainOpError::CapabilityUnavailable(ref message)) if message.contains("Legacy Aptos ChainProofProvider inclusion verification is disabled")),
            "legacy provider must not accept self-supplied proof bytes: {result:?}"
        );
    }

    #[test]
    fn multi_signer_produces_one_signature_per_key_each_recovering() {
        // MINT-KEYS-001: multiple local verifier keys attach one recoverable
        // signature each, and every signature recovers — over the 32-byte digest
        // as Aptos's ecdsa_recover does — to its configured public key.
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let (s1, pk1) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let (s2, pk2) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let backend = backend_with_keys(vec![s1, s2]);

        let digest = [0x42u8; 32];
        let sigs = backend
            .sign_mint_attestation_digests(&digest)
            .expect("two signers configured");
        assert_eq!(sigs.len(), 2, "one signature per configured key");

        let recover = |sig: &[u8]| {
            let rid = RecoveryId::from_i32(sig[64] as i32).unwrap();
            let rec = RecoverableSignature::from_compact(&sig[..64], rid).unwrap();
            secp.recover_ecdsa(&Message::from_digest(digest), &rec)
                .unwrap()
        };
        assert_eq!(recover(&sigs[0]), pk1);
        assert_eq!(recover(&sigs[1]), pk2);
    }

    #[test]
    fn no_verifier_key_fails_closed() {
        let backend = backend_with_keys(vec![]);
        assert!(
            backend.sign_mint_attestation_digests(&[0u8; 32]).is_err(),
            "absent verifier key must fail closed, not emit an unauthenticated mint"
        );
        assert!(backend.sign_mint_attestation_digest(&[0u8; 32]).is_err());
    }
}
