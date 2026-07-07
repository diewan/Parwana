#![allow(dead_code)]
#![allow(unused_variables)]
//! Chain Operation Traits Implementation for Ethereum
//!
//! This module implements all chain operation traits from csv-adapter-core:
//! - ChainQuery: Querying chain state via RPC
//! - ChainSigner: ECDSA signing operations
//! - ChainBroadcaster: Transaction broadcasting
//! - ChainDeployer: Contract deployment via CREATE/CREATE2
//! - ChainProofProvider: MPT inclusion and finality proofs
//! - ChainSanadOps: Sanad management via CSV seal contract

use async_trait::async_trait;
use csv_protocol::chain_adapter_traits::{
    BalanceInfo, CanonicalLifecycleEvent, CanonicalSanadState, CanonicalSealState, ChainBackend,
    ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError, ChainOpResult,
    ChainProofProvider, ChainQuery, ChainReadiness, ChainReadinessCheck, ChainSanadOps,
    ChainSigner, ContractStatus, DeploymentStatus, FinalityStatus, SanadOperationResult,
    SanadStateReader, TransactionInfo, TransactionStatus,
};

use csv_hash::Hash;
#[cfg(feature = "rpc")]
use csv_protocol::chain_adapter_traits::SanadOperation;
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::sanad::SanadId;
use csv_protocol::seal::{CommitAnchor, SealPoint};
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::signature::SignatureScheme;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::EthereumConfig;
use crate::finality::FinalityChecker;
use crate::proofs::{CommitmentEventBuilder, EventProofVerifier};
use crate::rpc::{EthereumRpc, RpcBlock, RpcTransaction};
use crate::seal_contract::CsvSealAbi;
use crate::seal_protocol::EthereumSealProtocol;
#[cfg(feature = "rpc")]
use alloy_sol_types::SolCall;

/// Ethereum chain operations implementation
#[path = "chain_verification.rs"]
mod chain_verification;

pub struct EthereumBackend {
    /// Inner RPC client for chain communication
    rpc: Box<dyn EthereumRpc>,
    /// Chain configuration
    config: EthereumConfig,
    /// Domain separator for proof generation
    domain_separator: [u8; 32],
    /// Finality checker
    #[allow(dead_code)]
    finality_checker: FinalityChecker,
    /// Seal contract ABI for sanad operations
    #[allow(dead_code)]
    seal_contract: CsvSealAbi,
    /// Seal contract address (for sanad operations - merged lock + mint)
    contract_address: Option<[u8; 20]>,
    /// Event proof verifier
    #[allow(dead_code)]
    proof_verifier: EventProofVerifier,
    /// Commitment event builder
    event_builder: CommitmentEventBuilder,
    /// Reference to seal protocol for seal creation and publishing
    pub(crate) seal_protocol: Arc<EthereumSealProtocol>,
    /// secp256k1 verifier key that signs the RFC-0012 §9.2 mint-attestation digest.
    ///
    /// Distinct from the EVM wallet signer that submits and pays for the transaction:
    /// the contract authenticates mint authority by recovering this verifier from
    /// the digest signature, independent of `msg.sender`.
    verifier_signing_key: Option<secp256k1::SecretKey>,
}

/// Unsigned deployment transaction for contract deployment
/// This represents a contract creation transaction before signing
#[derive(Debug, Clone)]
pub struct UnsignedDeployTx {
    /// Transaction nonce
    pub nonce: u64,
    /// Gas price
    pub gas_price: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Deployment data (constructor + bytecode)
    pub data: Vec<u8>,
    /// Chain ID
    pub chain_id: u64,
    /// Sender address
    pub from: [u8; 20],
}

impl EthereumBackend {
    /// Create new Ethereum chain operations from RPC client.
    ///
    /// Fails closed: if the seal protocol cannot be constructed from the supplied
    /// RPC/config (e.g. malformed configuration), this returns a typed error instead
    /// of silently substituting a mock RPC client. A mock fallback here would mean
    /// production callers could end up signing/reading against a fake in-memory chain
    /// without any indication that real contract-backed behavior was never wired up.
    pub fn new(rpc: Box<dyn EthereumRpc>, config: EthereumConfig) -> ChainOpResult<Self> {
        let mut domain = [0u8; 32];
        domain[..10].copy_from_slice(b"CSV-ETH---");
        let chain_id = config.network.chain_id().to_le_bytes();
        domain[10..18].copy_from_slice(&chain_id);

        let finality_checker = FinalityChecker::new(crate::finality::FinalityConfig {
            confirmation_depth: config.finality_depth,
            prefer_checkpoint_finality: config.use_checkpoint_finality,
        });

        // Create seal protocol using the real RPC (not a mock). This is required for
        // publish() to work, which downcasts to EthereumNode. No mock fallback: if this
        // fails, construction fails closed with a typed error.
        let csv_seal_address = config.contract_address.unwrap_or([0u8; 20]);
        let seal =
            EthereumSealProtocol::from_config(config.clone(), rpc.clone_boxed(), csv_seal_address)
                .map_err(|e| {
                    ChainOpError::RpcError(format!(
                        "Failed to construct Ethereum seal protocol from RPC/config: {}",
                        e
                    ))
                })?;

        Ok(Self {
            rpc,
            config: config.clone(),
            domain_separator: domain,
            finality_checker,
            seal_contract: CsvSealAbi,
            contract_address: config.contract_address,
            proof_verifier: EventProofVerifier::new(),
            event_builder: CommitmentEventBuilder::new(),
            seal_protocol: Arc::new(seal),
            verifier_signing_key: None,
        })
    }

    /// Create from EthereumSealProtocol
    pub fn from_seal_protocol(seal: Arc<EthereumSealProtocol>) -> ChainOpResult<Self> {
        let config = seal.config_clone();
        Ok(Self {
            rpc: seal.rpc().clone_boxed(),
            config,
            domain_separator: seal.domain(),
            finality_checker: seal.finality_checker_clone(),
            seal_contract: CsvSealAbi,
            contract_address: seal.config_clone().contract_address,
            proof_verifier: EventProofVerifier::new(),
            event_builder: CommitmentEventBuilder::new(),
            seal_protocol: seal,
            verifier_signing_key: None,
        })
    }

    /// Set the seal contract address for sanad operations
    pub fn with_contract(mut self, address: [u8; 20]) -> Self {
        self.contract_address = Some(address);
        self
    }

    /// Set the secp256k1 verifier key that signs the RFC-0012 §9.2 mint-attestation
    /// digest. This key must correspond to the verifier authorized by the deployed
    /// CSVSeal contract; it is not used to pay gas.
    pub fn with_verifier_key(mut self, verifier_signing_key: secp256k1::SecretKey) -> Self {
        self.verifier_signing_key = Some(verifier_signing_key);
        self
    }

    /// Get the seal contract address if set
    fn contract(&self) -> ChainOpResult<[u8; 20]> {
        self.contract_address.ok_or_else(|| {
            ChainOpError::InvalidInput(
                "Seal contract address not configured. Set it with with_contract()".to_string(),
            )
        })
    }

    /// Parse Ethereum address from string
    fn parse_address(&self, address: &str) -> ChainOpResult<[u8; 20]> {
        let hex_str = address.trim_start_matches("0x");
        let bytes = hex::decode(hex_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid hex address: {}", e)))?;

        if bytes.len() != 20 {
            return Err(ChainOpError::InvalidInput(
                "Ethereum address must be 20 bytes".to_string(),
            ));
        }

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        Ok(addr)
    }

    /// Format an address to hex string
    #[allow(dead_code)]
    fn format_address(&self, addr: [u8; 20]) -> String {
        format!("0x{}", hex::encode(addr))
    }

    /// Derive the canonical Ethereum address for a secp256k1 public key.
    ///
    /// Ethereum uses the last 20 bytes of Keccak256 over the 64-byte uncompressed
    /// public key body (`x || y`), excluding the SEC1 `0x04` prefix. Callers may
    /// provide either compressed or uncompressed SEC1 public keys.
    fn ethereum_address_from_public_key(public_key: &[u8]) -> ChainOpResult<[u8; 20]> {
        use secp256k1::PublicKey;
        use sha3::{Digest, Keccak256};

        let public_key = PublicKey::from_slice(public_key)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {}", e)))?;
        let uncompressed = public_key.serialize_uncompressed();
        let hash = Keccak256::digest(&uncompressed[1..]);

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);
        Ok(addr)
    }

    fn ethereum_address_from_secret_key(
        secret_key: &secp256k1::SecretKey,
    ) -> ChainOpResult<[u8; 20]> {
        use secp256k1::{PublicKey, Secp256k1};

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, secret_key);
        Self::ethereum_address_from_public_key(&public_key.serialize_uncompressed())
    }

    /// Encode a view function call with a bytes32 argument
    fn _encode_view_call(&self, function_sig: &str, arg: &[u8; 32]) -> Vec<u8> {
        // Compute function selector: first 4 bytes of keccak256(function_sig)
        let selector = self._keccak256(function_sig.as_bytes());
        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&selector[..4]);
        // Pad argument to 32 bytes
        calldata.extend_from_slice(arg);
        calldata
    }

    /// Encode a call with two bytes32 arguments (e.g. create_seal(bytes32,bytes32),
    /// consume_seal(bytes32,bytes32)).
    fn _encode_call_2args(&self, function_sig: &str, arg1: &[u8; 32], arg2: &[u8; 32]) -> Vec<u8> {
        let selector = self._keccak256(function_sig.as_bytes());
        let mut calldata = Vec::with_capacity(4 + 32 + 32);
        calldata.extend_from_slice(&selector[..4]);
        calldata.extend_from_slice(arg1);
        calldata.extend_from_slice(arg2);
        calldata
    }

    /// Query a uint256 storage slot via eth_call
    async fn _query_uint256_slot(
        &self,
        contract_address: &[u8; 20],
        function_sig: &str,
        arg: &[u8; 32],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let call_data = self._encode_view_call(function_sig, arg);
        let result = self
            .rpc
            .eth_call(
                serde_json::json!({
                    "to": format!("0x{}", hex::encode(contract_address)),
                    "data": format!("0x{}", hex::encode(&call_data))
                }),
                "latest",
            )
            .await?;
        // Parse uint256 result (32 bytes, big-endian) - take last 8 bytes for u64
        if result.len() >= 32 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&result[24..32]);
            Ok(u64::from_be_bytes(buf))
        } else {
            Ok(0)
        }
    }

    /// Decode event type from topic hash
    fn _decode_event_type(&self, topic: &str) -> String {
        // Map common event signatures to human-readable names
        match topic {
            t if t.contains("SanadCreated") || t.contains("sanadcreated") => {
                "SanadCreated".to_string()
            }
            t if t.contains("SanadConsumed") || t.contains("sanadconsumed") => {
                "SanadConsumed".to_string()
            }
            t if t.contains("SanadLocked") || t.contains("sanadlocked") => {
                "SanadLocked".to_string()
            }
            t if t.contains("SanadMinted") || t.contains("sanadminted") => {
                "SanadMinted".to_string()
            }
            t if t.contains("SanadRefunded") || t.contains("sanadrefunded") => {
                "SanadRefunded".to_string()
            }
            t if t.contains("SanadTransferred") || t.contains("sanadtransferred") => {
                "SanadTransferred".to_string()
            }
            _ => "Unknown".to_string(),
        }
    }

    /// Simple keccak256 hash (for function selectors)
    fn _keccak256(&self, data: &[u8]) -> [u8; 32] {
        use sha3::Digest;
        let mut hasher = sha3::Keccak256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Parse transaction hash
    fn parse_tx_hash(&self, hash: &str) -> ChainOpResult<[u8; 32]> {
        let hex_str = hash.trim_start_matches("0x");
        let bytes = hex::decode(hex_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid hex hash: {}", e)))?;

        if bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Transaction hash must be 32 bytes".to_string(),
            ));
        }

        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&bytes);
        Ok(tx_hash)
    }

    /// Convert RPC transaction to TransactionInfo
    fn tx_to_info(&self, tx: &RpcTransaction, block: Option<&RpcBlock>) -> TransactionInfo {
        let status = if tx.block_number.is_some() {
            TransactionStatus::Confirmed {
                block_height: tx.block_number.unwrap_or(0),
                confirmations: block
                    .map(|b| b.number.saturating_sub(tx.block_number.unwrap_or(0)) + 1)
                    .unwrap_or(1),
            }
        } else {
            TransactionStatus::Pending
        };

        TransactionInfo {
            hash: format!("0x{}", hex::encode(tx.hash)),
            sender: format!("0x{}", hex::encode(tx.from)),
            recipient: tx.to.map(|a| format!("0x{}", hex::encode(a))),
            amount: tx.value,
            status,
            block_height: tx.block_number,
            timestamp: block.map(|b| b.timestamp),
            fee: tx.gas_price.map(|gp| gp * tx.gas),
            raw_data: None,
        }
    }

    /// Get RPC client reference
    pub fn rpc(&self) -> &dyn EthereumRpc {
        self.rpc.as_ref()
    }

    /// Compute keccak256 hash
    fn keccak256(&self, input: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        Keccak256::digest(input).into()
    }

    /// Check if a sanad is locked on-chain by querying getLockInfo
    #[cfg(feature = "rpc")]
    pub async fn is_sanad_locked(&self, sanad_id: &[u8]) -> ChainOpResult<bool> {
        let contract_addr = self.contract().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to get contract address: {}", e))
        })?;

        let sanad_id_bytes = alloy_primitives::FixedBytes::<32>::from_slice(sanad_id);
        let calldata = crate::bindings::csv_lock::CsvLockClient::new(contract_addr.into())
            .get_lock_info_call(sanad_id_bytes);

        let encoded = hex::encode(calldata.abi_encode());

        let result = self
            .rpc()
            .eth_call(
                serde_json::json!({
                    "to": format!("0x{}", hex::encode(contract_addr)),
                    "data": format!("0x{}", encoded)
                }),
                "latest",
            )
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to call getLockInfo: {}", e)))?;

        // Decode the response: (bytes32 commitment, uint256 timestamp, uint8 destinationChain, bool refunded)
        // If commitment is all zeros, the sanad is not locked
        let commitment = &result[..64]; // First 32 bytes of commitment, but we need to check if it's all zeros
        Ok(!commitment.iter().all(|&b| b == 0))
    }

    /// Build, sign, and send a transaction to a contract
    #[cfg(feature = "rpc")]
    async fn build_sign_and_send_transaction(
        &self,
        to: [u8; 20],
        calldata: &[u8],
        _signer_key: &str,
    ) -> ChainOpResult<[u8; 32]> {
        use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
        use alloy::eips::eip2718::Encodable2718;
        use alloy::primitives::{Address, Bytes, TxKind, U256};
        use alloy::signers::SignerSync;

        // Get signer from RPC client (set via with_signer during initialization)
        let signer = self
            .rpc()
            .as_any()
            .and_then(|any| any.downcast_ref::<crate::node::EthereumNode>())
            .and_then(|node| node.signer())
            .ok_or_else(|| {
                ChainOpError::SigningError(
                    "No signer configured - call with_signer() on the RPC client first".to_string(),
                )
            })?;

        // Get sender address
        let sender: Address = signer.address();
        let sender_bytes: [u8; 20] = sender.into();

        // Get nonce using "pending" to account for transactions in mempool
        let nonce = match self.rpc().get_transaction_count_pending(sender_bytes).await {
            Ok(nonce) => nonce,
            Err(_) => {
                // Fallback if pending method not available
                self.rpc()
                    .get_transaction_count(sender_bytes)
                    .await
                    .map_err(|e| ChainOpError::RpcError(format!("Failed to get nonce: {}", e)))?
            }
        };

        // Get gas price
        let gas_price = self
            .rpc()
            .get_gas_price()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get gas price: {}", e)))?;

        // Build EIP-1559 transaction with gas bumping retry logic
        let max_retries = 3;
        let (mut current_max_fee, max_priority_fee) = eip1559_fee_caps(gas_price as u128);

        for retry_count in 0..max_retries {
            let tx = TxEip1559 {
                chain_id: self.config.network.chain_id(),
                nonce,
                max_fee_per_gas: current_max_fee,
                max_priority_fee_per_gas: max_priority_fee,
                gas_limit: 500_000u64,
                to: TxKind::Call(to.into()),
                value: U256::ZERO,
                input: Bytes::from(calldata.to_vec()),
                access_list: Default::default(),
            };

            // Sign the transaction
            let sig_hash = tx.signature_hash();
            let signature = signer.sign_hash_sync(&sig_hash).map_err(|e| {
                ChainOpError::SigningError(format!("Failed to sign transaction: {}", e))
            })?;

            // Convert to signed transaction and encode
            let signed_tx = tx.into_signed(signature);
            let tx_envelope = TxEnvelope::Eip1559(signed_tx);
            let tx_bytes = tx_envelope.encoded_2718();

            // Send the raw transaction
            match self.rpc().send_raw_transaction(tx_bytes.to_vec()).await {
                Ok(tx_hash) => return Ok(tx_hash),
                Err(e) => {
                    let error_str = e.to_string();
                    if error_str.contains("replacement transaction underpriced")
                        || error_str.contains("underpriced") && retry_count < max_retries - 1
                    {
                        // Bump gas price by 10% and retry
                        current_max_fee = (current_max_fee as u128).saturating_mul(110) / 100;
                        continue;
                    } else {
                        return Err(ChainOpError::TransactionError(format!(
                            "Failed to send transaction: {}",
                            e
                        )));
                    }
                }
            }
        }

        Err(ChainOpError::TransactionError(
            "Failed to send transaction after retries".to_string(),
        ))
    }

    /// Wait for a transaction receipt
    #[cfg(feature = "rpc")]
    async fn wait_for_receipt(
        &self,
        tx_hash: &[u8; 32],
    ) -> ChainOpResult<crate::rpc::TransactionReceipt> {
        use tokio::time::{Duration, sleep};

        let max_attempts = 30;
        let poll_interval = Duration::from_secs(2);

        for _ in 0..max_attempts {
            match self.rpc().get_transaction_receipt(*tx_hash).await {
                Ok(Some(receipt)) => return Ok(receipt),
                Ok(None) => {
                    // Transaction pending, wait and retry
                    sleep(poll_interval).await;
                }
                Err(e) => {
                    return Err(ChainOpError::RpcError(format!(
                        "Failed to get receipt: {}",
                        e
                    )));
                }
            }
        }

        Err(ChainOpError::Timeout(
            "Transaction not confirmed within timeout period".to_string(),
        ))
    }

    /// Recover sender address from transaction signature
    #[cfg(feature = "rpc")]
    #[allow(dead_code)]
    async fn recover_sender(
        &self,
        signature: &secp256k1::ecdsa::RecoverableSignature,
        tx: &alloy::consensus::TxLegacy,
        _chain_id: u64,
    ) -> ChainOpResult<[u8; 20]> {
        use alloy_primitives::keccak256;
        use secp256k1::Message;

        // Build the transaction hash for signing (RLP encode with chain ID)
        let tx_hash =
            keccak256(alloy::consensus::SignableTransaction::signature_hash(tx).as_slice());

        // Create message from hash
        let message = Message::from_digest(tx_hash.into());

        // Recover public key
        let secp = secp256k1::Secp256k1::new();
        let public_key = secp
            .recover_ecdsa(&message, signature)
            .map_err(|e| ChainOpError::InvalidInput(format!("Signature recovery failed: {}", e)))?;

        // Convert public key to address (keccak256 hash of pubkey, last 20 bytes)
        let pubkey_bytes = public_key.serialize_uncompressed();
        let hash = keccak256(&pubkey_bytes[1..]); // Skip 0x04 prefix
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        Ok(address)
    }

    /// Deployed CSVSeal contract address (20 bytes).
    ///
    /// The destination adapter binds this into the RFC-0012 §9.2 attestation
    /// digest (`destination_contract`, left-padded to 32 bytes) so a verifier
    /// signature is scoped to exactly one contract deployment and cannot be
    /// replayed against a different CSVSeal instance. Fails closed when no
    /// contract address is configured.
    pub fn contract_address(&self) -> ChainOpResult<[u8; 20]> {
        self.contract()
    }

    /// Sign a 32-byte RFC-0012 §9.2 attestation digest with the configured
    /// secp256k1 key, producing a 65-byte EVM-recoverable signature
    /// (`r(32) || s(32) || v(1)`, `v ∈ {27, 28}`).
    ///
    /// This is a raw ECDSA signature over the digest itself — NOT an
    /// `eth_sign`/personal-message signature — so it recovers under the
    /// contract's `ecrecover(digest, v, r, s)` verifier check. Fails closed when
    /// no verifier signer is configured rather than emitting an unauthenticated mint.
    #[cfg(feature = "rpc")]
    pub fn sign_mint_attestation_digest(&self, digest: &[u8; 32]) -> ChainOpResult<Vec<u8>> {
        use secp256k1::{Message, Secp256k1};

        let secret_key = self.verifier_signing_key.as_ref().ok_or_else(|| {
            ChainOpError::SigningError(
                "No verifier signer configured: cannot attest the §9.2 mint digest \
                 (set CSV_MINT_VERIFIER_KEY to the verifier key registered in CSVSeal)"
                    .to_string(),
            )
        })?;

        // Sign the digest bytes directly (no Ethereum message prefix), matching
        // on-chain ecrecover semantics.
        let msg = Message::from_digest(*digest);
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa_recoverable(&msg, &secret_key);
        let (recovery_id, compact) = signature.serialize_compact();

        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&compact);
        // EVM `v` = recovery id (0/1) + 27.
        out.push(recovery_id.to_i32() as u8 + 27);
        Ok(out)
    }

    /// Submit pre-encoded mint calldata to the CSVSeal contract, wait for its
    /// receipt, and fail closed if the mint reverted.
    ///
    /// Used by the runtime adapter after it has built the §9.2 digest and
    /// attached verifier signatures; returns `(tx_hash_hex, block_height)`.
    #[cfg(feature = "rpc")]
    pub async fn submit_and_confirm_mint(
        &self,
        calldata: Vec<u8>,
        signer_ref: &str,
    ) -> ChainOpResult<(String, u64)> {
        let contract = self.contract()?;
        let tx_hash = self
            .build_sign_and_send_transaction(contract, &calldata, signer_ref)
            .await?;
        let receipt = self.wait_for_receipt(&tx_hash).await?;
        if receipt.status == 0 {
            return Err(ChainOpError::TransactionError(format!(
                "mint_sanad reverted on-chain (tx {})",
                hex::encode(tx_hash)
            )));
        }
        Ok((hex::encode(tx_hash), receipt.block_number))
    }
}

#[async_trait]
impl ChainQuery for EthereumBackend {
    async fn get_balance(&self, address: &str) -> ChainOpResult<BalanceInfo> {
        let addr = self.parse_address(address)?;

        let balance = self
            .rpc()
            .get_balance(addr)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get balance: {}", e)))?;

        Ok(BalanceInfo {
            address: address.to_string(),
            total: balance,
            available: balance,
            locked: 0,
            tokens: Vec::new(), // Would query token contracts for ERC20 balances
        })
    }

    async fn get_transaction(&self, hash: &str) -> ChainOpResult<TransactionInfo> {
        let tx_hash = self.parse_tx_hash(hash)?;

        let tx = self
            .rpc()
            .get_transaction(tx_hash)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?
            .ok_or_else(|| ChainOpError::RpcError("Transaction not found".to_string()))?;

        // Get block for timestamp
        let block = if let Some(block_num) = tx.block_number {
            self.rpc()
                .get_block_by_number(block_num)
                .await
                .ok()
                .flatten()
        } else {
            None
        };

        Ok(self.tx_to_info(&tx, block.as_ref()))
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        let hash = self.parse_tx_hash(tx_hash)?;

        // Get transaction receipt
        let receipt = match self
            .rpc()
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get receipt: {}", e)))?
        {
            Some(r) => r,
            None => return Ok(FinalityStatus::Pending),
        };
        let block_number = receipt.block_number;

        // Get latest block
        let latest =
            self.rpc().block_number().await.map_err(|e| {
                ChainOpError::RpcError(format!("Failed to get block number: {}", e))
            })?;

        let confirmations = latest.saturating_sub(block_number) + 1;

        // Check finality based on configured depth
        if confirmations >= self.config.finality_depth {
            Ok(FinalityStatus::Finalized {
                block_height: block_number,
                finality_block: block_number,
            })
        } else {
            Ok(FinalityStatus::Pending)
        }
    }

    async fn get_contract_status(&self, contract_address: &str) -> ChainOpResult<ContractStatus> {
        let addr = self.parse_address(contract_address)?;

        // Get code at address
        let code = self
            .rpc()
            .get_code(addr)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get code: {}", e)))?;

        let is_deployed = !code.is_empty();

        // Get balance
        let balance = self
            .rpc()
            .get_balance(addr)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get balance: {}", e)))?;

        Ok(ContractStatus {
            address: contract_address.to_string(),
            is_deployed,
            balance: Some(balance),
            owner: None, // Would require querying contract state
            metadata: serde_json::json!({
                "chain": "ethereum",
                "network": format!("{:?}", self.config.network),
                "code_size": code.len(),
            }),
        })
    }

    async fn get_latest_block_height(&self) -> ChainOpResult<u64> {
        self.rpc()
            .block_number()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get block number: {}", e)))
    }

    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        let block_number = self.get_latest_block_height().await?;
        let chain_id = self.config.network.chain_id();

        Ok(serde_json::json!({
            "chain_id": chain_id,
            "chain": "ethereum",
            "network": format!("{:?}", self.config.network),
            "latest_block": block_number,
            "finality_depth": self.config.finality_depth,
            "protocol": "EVM",
            "finality": "probabilistic",
        }))
    }

    async fn get_account_nonce(&self, address: &str) -> ChainOpResult<u64> {
        let addr = self.parse_address(address)?;

        // Query the Ethereum RPC for transaction count (nonce)
        self.rpc
            .get_transaction_count(addr)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get nonce: {}", e)))
    }

    fn validate_address(&self, address: &str) -> bool {
        let hex_str = address.trim_start_matches("0x");
        match hex::decode(hex_str) {
            Ok(bytes) => bytes.len() == 20,
            Err(_) => false,
        }
    }
}

#[async_trait]
impl ChainSigner for EthereumBackend {
    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String> {
        if public_key.len() != 33 && public_key.len() != 65 {
            return Err(ChainOpError::InvalidInput(
                "Secp256k1 public key must be 33 (compressed) or 65 (uncompressed) bytes"
                    .to_string(),
            ));
        }

        let addr = Self::ethereum_address_from_public_key(public_key)?;
        Ok(format!("0x{}", hex::encode(addr)))
    }

    async fn sign_transaction(&self, _tx_data: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        // Signing requires access to private keys which should be managed
        // by a secure keystore, not stored in this operations struct.
        Err(ChainOpError::CapabilityUnavailable(
            "Direct transaction signing not available. \
             Use an external keystore with the key_id reference."
                .to_string(),
        ))
    }

    async fn sign_message(&self, message: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>> {
        // Sign an Ethereum personal message using ECDSA
        // Ethereum adds a prefix: "\x19Ethereum Signed Message:\n" + len(message) + message

        use secp256k1::ecdsa::RecoverableSignature;
        use secp256k1::{Message, Secp256k1, SecretKey};
        use sha3::{Digest, Keccak256};

        // Parse key_id as hex-encoded private key (production would use keystore)
        let key_bytes = hex::decode(key_id).map_err(|_| {
            ChainOpError::SigningError(
                "Invalid key_id format. Expected hex-encoded key.".to_string(),
            )
        })?;

        if key_bytes.len() != 32 {
            return Err(ChainOpError::SigningError(
                "Invalid key length. Expected 32 bytes.".to_string(),
            ));
        }

        let secret_key = SecretKey::from_slice(&key_bytes)
            .map_err(|e| ChainOpError::SigningError(format!("Invalid secret key: {}", e)))?;

        // Create Ethereum personal message prefix
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut full_message = Vec::new();
        full_message.extend_from_slice(prefix.as_bytes());
        full_message.extend_from_slice(message);

        // Hash with Keccak-256
        let hash = Keccak256::digest(&full_message);
        let msg = Message::from_digest_slice(&hash)
            .map_err(|e| ChainOpError::SigningError(format!("Failed to create message: {}", e)))?;

        // Sign the message with recoverable signature
        let secp = Secp256k1::new();
        let signature: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &secret_key);

        // Serialize signature: 65 bytes (r: 32, s: 32, v: 1)
        let (recovery_id, sig_bytes) = signature.serialize_compact();
        let mut full_sig = sig_bytes.to_vec();
        full_sig.push(recovery_id.to_i32() as u8 + 27); // Ethereum adds 27 to recovery id

        Ok(full_sig)
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> ChainOpResult<bool> {
        // Ethereum uses ECDSA with secp256k1
        // Signature format: r (32 bytes) || s (32 bytes) || v (1 byte, recovery id)

        use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
        use sha3::{Digest, Keccak256};

        if signature.len() != 65 {
            return Err(ChainOpError::InvalidInput(
                "ECDSA signature must be 65 bytes (r + s + v)".to_string(),
            ));
        }

        // Parse public key
        let pub_key = PublicKey::from_slice(public_key)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {}", e)))?;

        // Extract signature components
        let r_s_bytes: [u8; 64] = signature[0..64]
            .try_into()
            .map_err(|_| ChainOpError::InvalidInput("Invalid signature length".to_string()))?;
        let _v = signature[64]; // Recovery id (27-30 for Ethereum)

        // Parse the signature
        let sig = Signature::from_compact(&r_s_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid signature: {}", e)))?;

        // Create Ethereum personal message hash (same as sign_message)
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut full_message = Vec::new();
        full_message.extend_from_slice(prefix.as_bytes());
        full_message.extend_from_slice(message);

        let hash = Keccak256::digest(&full_message);
        let msg = Message::from_digest_slice(&hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Failed to create message: {}", e)))?;

        // Verify the signature
        let secp = Secp256k1::new();
        match secp.verify_ecdsa(&msg, &sig, &pub_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }
}

#[async_trait]
impl ChainBroadcaster for EthereumBackend {
    async fn submit_transaction(&self, signed_tx: &[u8]) -> ChainOpResult<String> {
        // signed_tx is RLP-encoded signed transaction
        let tx_hash = self
            .rpc()
            .send_raw_transaction(signed_tx.to_vec())
            .await
            .map_err(|e| ChainOpError::TransactionError(format!("Submission failed: {}", e)))?;

        Ok(format!("0x{}", hex::encode(tx_hash)))
    }

    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        required_confirmations: u64,
        timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus> {
        let hash = self.parse_tx_hash(tx_hash)?;
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_secs(12); // Ethereum block time

        loop {
            if start.elapsed() > timeout {
                return Err(ChainOpError::Timeout(
                    "Transaction confirmation timeout".to_string(),
                ));
            }

            // Get receipt
            match self.rpc().get_transaction_receipt(hash).await {
                Ok(Some(receipt)) => {
                    if receipt.status == 0 {
                        return Ok(TransactionStatus::Failed {
                            reason: "Transaction reverted".to_string(),
                        });
                    }

                    let block_number = receipt.block_number;

                    // Get latest for confirmation count
                    let latest = self.rpc().block_number().await.map_err(|e| {
                        ChainOpError::RpcError(format!("Failed to get block number: {}", e))
                    })?;

                    let confirmations = latest.saturating_sub(block_number) + 1;

                    if confirmations >= required_confirmations {
                        return Ok(TransactionStatus::Confirmed {
                            block_height: block_number,
                            confirmations,
                        });
                    }

                    // Not enough confirmations yet, wait (PF-03: always async)
                    tokio::time::sleep(poll_interval).await;
                }
                Ok(None) => {
                    // Receipt not available yet, wait and retry (PF-03: always async)
                    tokio::time::sleep(poll_interval).await;
                }
                Err(e) => {
                    return Err(ChainOpError::RpcError(format!(
                        "Failed to get receipt: {}",
                        e
                    )));
                }
            }
        }
    }

    async fn get_fee_estimate(&self) -> ChainOpResult<u64> {
        // Get current gas price - use a default if not available
        let gas_price = self.rpc().get_gas_price().await.unwrap_or(20_000_000_000); // Default 20 Gwei

        // Estimate gas limit for a typical transaction (21000 for simple transfer)
        let gas_limit = 21000;

        Ok(gas_price * gas_limit)
    }

    async fn validate_transaction(&self, tx_data: &[u8]) -> ChainOpResult<()> {
        // RLP decode and validate transaction structure
        if tx_data.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Empty transaction data".to_string(),
            ));
        }

        #[cfg(feature = "rpc")]
        {
            use alloy::rlp::Decodable;
            use alloy_consensus::TxEnvelope;
            use alloy_consensus::transaction::SignerRecoverable;

            // Decode the transaction using alloy's TxEnvelope
            let tx_envelope = match TxEnvelope::decode(&mut &tx_data[..]) {
                Ok(tx) => tx,
                Err(e) => {
                    return Err(ChainOpError::InvalidInput(format!(
                        "Failed to decode transaction: {}",
                        e
                    )));
                }
            };

            // Recover the signer from the transaction signature
            let recovered_signer = match tx_envelope.recover_signer() {
                Ok(signer) => signer,
                Err(e) => {
                    return Err(ChainOpError::InvalidInput(format!(
                        "Failed to recover signer: {}",
                        e
                    )));
                }
            };

            // Validate that the recovered signer is a valid address
            if recovered_signer == alloy_primitives::Address::ZERO {
                return Err(ChainOpError::InvalidInput(
                    "Invalid signer address (zero address)".to_string(),
                ));
            }

            // Signature validation is now complete via recover_signer
            // The recovered signer can be used for further validation if needed
        }

        #[cfg(not(feature = "rpc"))]
        {
            // Without RPC, we can only do basic structure validation
            // Transaction validation requires chain state access
            return Err(ChainOpError::FeatureNotEnabled(
                "rpc feature required for full transaction validation".to_string(),
            ));
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}

#[async_trait]
impl ChainDeployer for EthereumBackend {
    async fn deploy_lock_contract(
        &self,
        _admin_address: &str,
        _config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        // Contract deployment is intentionally delegated to Foundry/forge for better security and tooling.
        // This approach ensures:
        // 1. Proper contract verification on block explorers
        // 2. Access to Foundry's comprehensive testing framework
        // 3. Standard deployment patterns used in production
        // 4. Ability to use deployment scripts with proper configuration
        //
        // To deploy the CSVSeal contract (merged lock + mint):
        // 1. Navigate to csv-contracts/ethereum/contracts
        // 2. Run: forge script script/DeploySeal.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
        // 3. Copy the deployed address
        // 4. Configure the backend with the deployed address via EthereumConfig.contract_address
        Err(ChainOpError::FeatureNotEnabled(
            "Contract deployment is delegated to Foundry/forge for security and tooling benefits. \
             Deploy contracts manually using: forge script script/DeploySeal.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast \
             Then configure the deployed address in EthereumConfig.contract_address".to_string()
        ))
    }

    async fn deploy_mint_contract(
        &self,
        _admin_address: &str,
        _config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        // Lock and mint contracts have been merged into CSVSeal
        Err(ChainOpError::FeatureNotEnabled(
            "Lock and mint contracts have been merged into CSVSeal. Use deploy_lock_contract to deploy the unified contract.".to_string()
        ))
    }

    async fn deploy_or_publish_seal_program(
        &self,
        _program_bytes: &[u8],
        _admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus> {
        Err(ChainOpError::FeatureNotEnabled(
            "Contract deployment is not supported. Deploy contracts manually using Foundry/forge and provide the address.".to_string()
        ))
    }

    async fn verify_deployment(&self, contract_address: &str) -> ChainOpResult<bool> {
        let status = self.get_contract_status(contract_address).await?;
        Ok(status.is_deployed)
    }

    async fn estimate_deployment_cost(&self, program_bytes: &[u8]) -> ChainOpResult<u64> {
        // Ethereum deployment cost:
        // 1. Base cost: 32000 gas for CREATE
        // 2. Storage cost: 200 gas per byte of init code
        // 3. Storage cost: 20000 gas per 32-byte word of runtime code

        let base_cost = 32000u64;
        let init_code_cost = (program_bytes.len() as u64) * 200;
        let runtime_estimate = (program_bytes.len() as u64) * 20000 / 32;

        let total_gas = base_cost + init_code_cost + runtime_estimate;

        // Get gas price - use a default if not available
        let gas_price = self.rpc().get_gas_price().await.unwrap_or(20_000_000_000); // Default 20 Gwei

        Ok(total_gas * gas_price)
    }
}

#[async_trait]
impl ChainProofProvider for EthereumBackend {
    async fn build_inclusion_proof(
        &self,
        commitment: &Hash,
        block_height: u64,
        anchor_id: &[u8],
    ) -> ChainOpResult<CoreInclusionProof> {
        // Get the block
        let block = self
            .rpc()
            .get_block_by_number(block_height)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get block: {}", e)))?
            .ok_or_else(|| ChainOpError::RpcError("Block not found".to_string()))?;

        // Build event proof for the commitment
        let seal_address = [0u8; 32];
        let event_data = self
            .event_builder
            .build(*commitment.as_bytes(), seal_address);

        // Build MPT proof for the transaction containing the event
        // This would require finding the transaction that emitted the event
        let _proof_data = serde_json::to_vec(&block)
            .map_err(|e| ChainOpError::Unknown(format!("Serialization failed: {}", e)))?;

        // In a real implementation, we would use the anchor_id (which should be the transaction hash)
        // to fetch the specific transaction and construct a proper inclusion proof.
        // The anchor_id is expected to be the 32-byte transaction hash.
        let _tx_hash = {
            if anchor_id.len() != 32 {
                return Err(ChainOpError::InvalidInput(format!(
                    "Invalid anchor_id length for Ethereum: expected 32 bytes, got {}",
                    anchor_id.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(anchor_id);
            arr
        };

        Ok(CoreInclusionProof {
            proof_bytes: event_data,
            block_hash: Hash::new(block.state_root),
            block_number: block_height,
            position: block_height,
            ..Default::default()
        })
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
                // Get block for proof
                let block = self
                    .rpc()
                    .get_block_by_number(finality_block)
                    .await
                    .map_err(|e| ChainOpError::RpcError(format!("Failed to get block: {}", e)))?
                    .ok_or_else(|| ChainOpError::RpcError("Block not found".to_string()))?;

                // Build proof from block header
                let proof_data = serde_json::to_vec(&block)
                    .map_err(|e| ChainOpError::Unknown(format!("Serialization failed: {}", e)))?;

                // Calculate confirmations
                let latest = self.rpc().block_number().await.map_err(|e| {
                    ChainOpError::RpcError(format!("Failed to get block number: {}", e))
                })?;
                let confirmations = latest.saturating_sub(finality_block) + 1;

                Ok(FinalityProof::new(
                    proof_data,
                    confirmations,
                    confirmations >= self.config.finality_depth,
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
impl ChainSanadOps for EthereumBackend {
    async fn create_sanad(
        &self,
        owner: &str,
        asset_class: &str,
        asset_id: &str,
        metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult> {
        let contract = self.contract()?;

        // `owner` is informational (the actual on-chain owner is msg.sender, derived
        // from the configured signer); validate it so malformed input fails closed
        // instead of being silently dropped.
        if !owner.is_empty() {
            self.parse_address(owner)?;
        }

        // create_seal(bytes32 commitment, bytes32 sealId) anchors a commitment and
        // creates a Sanad entry owned by msg.sender. The contract does not accept
        // owner/asset_class/metadata directly; metadata is recorded separately via
        // record_sanad_metadata. Derive a deterministic sealId/commitment from the
        // caller-supplied asset_id so repeated calls with the same asset_id collide
        // (matching create_seal's own anchor-replay protection) instead of silently
        // minting a fresh identity from nothing.
        if asset_id.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "asset_id must not be empty: it is used to derive the Sanad commitment".to_string(),
            ));
        }
        let seal_id = self.keccak256(format!("csv.sanad.create.{}", asset_id).as_bytes());
        let commitment = self.keccak256(format!("csv.sanad.commitment.{}", asset_id).as_bytes());

        #[cfg(feature = "rpc")]
        {
            let calldata =
                self._encode_call_2args("create_seal(bytes32,bytes32)", &commitment, &seal_id);

            let tx_hash = self
                .build_sign_and_send_transaction(contract, &calldata, owner)
                .await?;

            let receipt = self.wait_for_receipt(&tx_hash).await?;

            let created_sanad_id = SanadId::new(seal_id);

            Ok(SanadOperationResult {
                sanad_id: created_sanad_id,
                operation: SanadOperation::Create,
                transaction_hash: hex::encode(tx_hash),
                block_height: receipt.block_number,
                chain_id: self.config.network.chain_id().to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "operation": "create",
                    "asset_class": asset_class,
                    "asset_id": asset_id,
                    "owner": owner,
                    "metadata": metadata,
                    "contract": hex::encode(contract),
                }))
                .unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            let _ = (contract, asset_class, metadata, seal_id, commitment);
            Err(ChainOpError::FeatureNotEnabled(
                "Sanad creation requires the 'rpc' feature for transaction signing. \
                 Enable it in Cargo.toml: csv-adapter-ethereum = { features = ['rpc'] }"
                    .to_string(),
            ))
        }
    }

    async fn consume_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let contract = self.contract()?;
        let sanad_id_bytes = sanad_id.0.as_bytes();

        #[cfg(feature = "rpc")]
        {
            // Canonical contract function is `consume_seal(bytes32 sealId, bytes32 nullifier)`
            // (the legacy `markSealUsed` function no longer exists on the deployed
            // CSVSeal.sol). A zero nullifier is a valid, contract-supported input: the
            // contract only registers a nullifier mapping entry when it is non-zero.
            let nullifier = [0u8; 32];
            let calldata = self._encode_call_2args(
                "consume_seal(bytes32,bytes32)",
                sanad_id_bytes,
                &nullifier,
            );

            let tx_hash = self
                .build_sign_and_send_transaction(contract, &calldata, owner_key_id)
                .await?;

            let receipt = self.wait_for_receipt(&tx_hash).await?;

            Ok(SanadOperationResult {
                sanad_id: sanad_id.clone(),
                operation: SanadOperation::Consume,
                transaction_hash: hex::encode(tx_hash),
                block_height: receipt.block_number,
                chain_id: self.config.network.chain_id().to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "operation": "consume",
                    "contract": hex::encode(contract),
                }))
                .unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(ChainOpError::FeatureNotEnabled(
                "Sanad consumption requires the 'rpc' feature for transaction signing. \
                 Enable it in Cargo.toml: csv-adapter-ethereum = { features = ['rpc'] }"
                    .to_string(),
            ))
        }
    }

    async fn lock_sanad(
        &self,
        sanad_id: &SanadId,
        destination_chain: &str,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let contract = self.contract()?;
        let sanad_id_bytes = sanad_id.0.as_bytes();
        let commitment = sanad_id_bytes;

        // Parse destination chain ID (convert string chain name to u8)
        let dest_chain_id = parse_chain_id(destination_chain)?;

        // Parse owner address for destination
        let owner_addr = self.parse_address(owner_key_id)?;

        // Note: destination_chain is now bytes32 (chain ID hash), not uint8
        use tiny_keccak::{Hasher, Keccak};
        let destination_chain_hash = match destination_chain {
            "bitcoin" => {
                let mut hasher = Keccak::v256();
                let mut output = [0u8; 32];
                hasher.update(b"csv.chain.bitcoin");
                hasher.finalize(&mut output);
                output
            }
            "ethereum" => {
                let mut hasher = Keccak::v256();
                let mut output = [0u8; 32];
                hasher.update(b"csv.chain.ethereum");
                hasher.finalize(&mut output);
                output
            }
            "sui" => {
                let mut hasher = Keccak::v256();
                let mut output = [0u8; 32];
                hasher.update(b"csv.chain.sui");
                hasher.finalize(&mut output);
                output
            }
            "aptos" => {
                let mut hasher = Keccak::v256();
                let mut output = [0u8; 32];
                hasher.update(b"csv.chain.aptos");
                hasher.finalize(&mut output);
                output
            }
            "solana" => {
                let mut hasher = Keccak::v256();
                let mut output = [0u8; 32];
                hasher.update(b"csv.chain.solana");
                hasher.finalize(&mut output);
                output
            }
            _ => [0u8; 32], // Default to zero hash for unknown chains
        };

        #[cfg(feature = "rpc")]
        {
            // Build the lock transaction using generated Alloy bindings
            use crate::bindings::csv_seal::lock_sanadCall;
            let call = lock_sanadCall {
                sanadId: alloy_primitives::FixedBytes::<32>::from_slice(sanad_id_bytes),
                commitment: alloy_primitives::FixedBytes::<32>::from_slice(commitment),
                destinationChain: alloy_primitives::FixedBytes::<32>::from_slice(
                    &destination_chain_hash,
                ),
                destinationOwner: alloy_primitives::Bytes::from(owner_addr.to_vec()),
            };

            // Encode the calldata from the generated call struct
            let calldata = call.abi_encode();

            // Build and sign transaction using Alloy
            let tx_hash = self
                .build_sign_and_send_transaction(contract, &calldata, owner_key_id)
                .await?;

            // Wait for receipt
            let receipt = self.wait_for_receipt(&tx_hash).await?;

            Ok(SanadOperationResult {
                sanad_id: sanad_id.clone(),
                operation: SanadOperation::Lock,
                transaction_hash: hex::encode(tx_hash),
                block_height: receipt.block_number,
                chain_id: self.config.network.chain_id().to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "operation": "lock",
                    "destination_chain": destination_chain,
                    "contract": hex::encode(contract),
                }))
                .unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            let _ = (contract, commitment, destination_chain_hash, owner_addr);
            Err(ChainOpError::FeatureNotEnabled(
                "Sanad locking requires the 'rpc' feature for transaction signing. \
                 Enable it in Cargo.toml: csv-adapter-ethereum = { features = ['rpc'] }"
                    .to_string(),
            ))
        }
    }

    async fn mint_sanad(
        &self,
        source_chain: &str,
        source_sanad_id: &SanadId,
        lock_proof: &CoreInclusionProof,
        new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // The finalized CSVSeal ABI (VERSION 6, RFC-0012 §9 / ABI_CONSTITUTION.md) makes the
        // destination mint a THIN REGISTRY: `mint_sanad` authenticity is a set of verifier
        // signatures over the frozen §9.2 attestation digest. This low-level trait method only
        // receives a source inclusion proof and the new owner — it carries none of the attestation
        // inputs (`lockEventId`, `nullifier`, `attestationExpiry`, `verifierSignatures`).
        // Constructing a call without them would send a request the contract rejects, violating
        // the "no fabricated blockchain interaction" invariant.
        //
        // The real cross-chain mint runs through the runtime path
        // (`EthereumRuntimeAdapter::mint_sanad`, TRM-ETH-ADPT-001): it decodes the runtime's
        // verifier-signed `RuntimeMintRequest`, binds `destination_contract`, computes the §9.2
        // digest, attaches verifier signature(s), and submits via the regenerated bindings. This
        // `ChainSanadOps` entry point has no such inputs, so it stays fail-closed by design.
        let _ = (source_sanad_id, lock_proof, new_owner);
        let _ = self.contract()?;
        Err(ChainOpError::CapabilityUnavailable(format!(
            "Ethereum ChainSanadOps::mint_sanad cannot mint from a bare inclusion proof: the \
             thin-registry mint (RFC-0012 §9) requires a verifier-attested RuntimeMintRequest \
             (lockEventId, nullifier, attestationExpiry, and verifierSignatures over the §9.2 \
             digest). Use the runtime mint path (EthereumRuntimeAdapter::mint_sanad) for \
             {source_chain}->ethereum transfers; refusing to send an unauthenticated mint."
        )))
    }

    async fn refund_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let contract = self.contract()?;
        let sanad_id_bytes = sanad_id.0.as_bytes();

        // Compute destination owner hash for verification
        let owner_addr = self.parse_address(owner_key_id)?;
        let owner_hash = self.keccak256(&owner_addr);

        #[cfg(feature = "rpc")]
        {
            // Build the refund transaction using generated Alloy bindings
            use crate::bindings::csv_seal::refund_sanadCall;
            let call = refund_sanadCall {
                sanadId: alloy_primitives::FixedBytes::<32>::from_slice(sanad_id_bytes),
                destinationOwnerHash: alloy_primitives::FixedBytes::<32>::from_slice(&owner_hash),
            };

            // Encode the calldata
            let calldata = call.abi_encode();

            // Build and sign transaction
            let tx_hash = self
                .build_sign_and_send_transaction(contract, &calldata, owner_key_id)
                .await?;

            // Wait for receipt
            let receipt = self.wait_for_receipt(&tx_hash).await?;

            Ok(SanadOperationResult {
                sanad_id: sanad_id.clone(),
                operation: SanadOperation::Refund,
                transaction_hash: hex::encode(tx_hash),
                block_height: receipt.block_number,
                chain_id: self.config.network.chain_id().to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "operation": "refund",
                    "contract": hex::encode(contract),
                }))
                .unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            let _ = (contract, owner_hash);
            Err(ChainOpError::FeatureNotEnabled(
                "Sanad refund requires the 'rpc' feature for transaction signing. \
                 Enable it in Cargo.toml: csv-adapter-ethereum = { features = ['rpc'] }"
                    .to_string(),
            ))
        }
    }

    async fn record_sanad_metadata(
        &self,
        sanad_id: &SanadId,
        metadata: serde_json::Value,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // The deployed CSVSeal.sol contract exposes a canonical
        // record_sanad_metadata(bytes32,uint8,bytes32,bytes32,uint8,bytes32) function
        // (see CSVSeal.sol). Call it directly rather than relying on lock-time recording.
        let contract = self.contract()?;
        let sanad_id_bytes = *sanad_id.0.as_bytes();

        let asset_class = metadata
            .get("asset_class")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;
        let proof_system = metadata
            .get("proof_system")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;
        let asset_id = parse_metadata_hash_field(&metadata, "asset_id")?;
        let metadata_hash = parse_metadata_hash_field(&metadata, "metadata_hash")?;
        let proof_root = parse_metadata_hash_field(&metadata, "proof_root")?;

        #[cfg(feature = "rpc")]
        {
            let selector = self
                ._keccak256(b"record_sanad_metadata(bytes32,uint8,bytes32,bytes32,uint8,bytes32)");
            let mut calldata = Vec::with_capacity(4 + 6 * 32);
            calldata.extend_from_slice(&selector[..4]);
            calldata.extend_from_slice(&sanad_id_bytes);
            calldata.extend_from_slice(&[0u8; 31]);
            calldata.push(asset_class);
            calldata.extend_from_slice(&asset_id);
            calldata.extend_from_slice(&metadata_hash);
            calldata.extend_from_slice(&[0u8; 31]);
            calldata.push(proof_system);
            calldata.extend_from_slice(&proof_root);

            let tx_hash = self
                .build_sign_and_send_transaction(contract, &calldata, owner_key_id)
                .await?;

            let receipt = self.wait_for_receipt(&tx_hash).await?;

            Ok(SanadOperationResult {
                sanad_id: sanad_id.clone(),
                operation: SanadOperation::RecordMetadata,
                transaction_hash: hex::encode(tx_hash),
                block_height: receipt.block_number,
                chain_id: self.config.network.chain_id().to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "operation": "record_metadata",
                    "contract": hex::encode(contract),
                }))
                .unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            let _ = (
                contract,
                sanad_id_bytes,
                asset_class,
                proof_system,
                asset_id,
                metadata_hash,
                proof_root,
                owner_key_id,
            );
            Err(ChainOpError::FeatureNotEnabled(
                "Metadata recording requires the 'rpc' feature for transaction signing. \
                 Enable it in Cargo.toml: csv-adapter-ethereum = { features = ['rpc'] }"
                    .to_string(),
            ))
        }
    }

    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        expected_state: &str,
    ) -> ChainOpResult<bool> {
        // Reuse the canonical state reader (SanadStateReader::get_sanad_state), which
        // already queries the deployed CSVSeal.sol contract's sanadStates(bytes32)
        // mapping via eth_call. This keeps a single source of truth for "what is the
        // on-chain state of this Sanad" instead of a second, divergent encoding path.
        let canonical = SanadStateReader::get_sanad_state(self, sanad_id).await?;

        let expected_numeric = canonical_sanad_state_code(expected_state).ok_or_else(|| {
            ChainOpError::InvalidInput(format!(
                "Unknown expected_state '{}'. Expected one of: uncreated, created, active, \
                 locked, consumed, minted, transferred, refunded, burned, invalid, or a \
                 numeric state code (0-9).",
                expected_state
            ))
        })?;

        Ok(canonical.state == expected_numeric)
    }
}

/// Map a canonical Sanad state name (or numeric string) to its contract state code.
///
/// Mirrors the `SanadState` enum in CSVSeal.sol:
/// 0=Uncreated, 1=Created, 2=Active, 3=Locked, 4=Consumed, 5=Minted, 6=Transferred,
/// 7=Refunded, 8=Burned, 9=Invalid.
fn canonical_sanad_state_code(expected_state: &str) -> Option<u8> {
    match expected_state.to_lowercase().as_str() {
        "uncreated" => Some(0),
        "created" => Some(1),
        "active" => Some(2),
        "locked" => Some(3),
        "consumed" => Some(4),
        "minted" => Some(5),
        "transferred" => Some(6),
        "refunded" => Some(7),
        "burned" => Some(8),
        "invalid" => Some(9),
        other => other.parse::<u8>().ok(),
    }
}

fn eip1559_fee_caps(gas_price: u128) -> (u128, u128) {
    let max_priority_fee = 1_000_000_000u128; // 1 Gwei priority fee
    let max_fee = gas_price.max(max_priority_fee);
    (max_fee, max_priority_fee)
}

/// Parse an optional 32-byte hex field out of a metadata JSON object.
///
/// Missing fields default to the zero hash (a valid, contract-supported "unset"
/// value per CSVSeal.sol's SanadMetadata defaults). Present-but-malformed fields
/// fail closed with a typed error rather than silently defaulting.
fn parse_metadata_hash_field(metadata: &serde_json::Value, field: &str) -> ChainOpResult<[u8; 32]> {
    match metadata.get(field).and_then(|v| v.as_str()) {
        None => Ok([0u8; 32]),
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim_start_matches("0x")).map_err(|e| {
                ChainOpError::InvalidInput(format!(
                    "Invalid hex for metadata field '{}': {}",
                    field, e
                ))
            })?;
            if bytes.len() != 32 {
                return Err(ChainOpError::InvalidInput(format!(
                    "Metadata field '{}' must be 32 bytes, got {}",
                    field,
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
    }
}

/// Parse a chain name string into a chain ID (u8)
///
/// Used for cross-chain transfers to identify destination/source chains.
fn parse_chain_id(chain_name: &str) -> ChainOpResult<u8> {
    match chain_name.to_lowercase().as_str() {
        "bitcoin" | "btc" => Ok(0),
        "ethereum" | "eth" => Ok(1),
        "sui" => Ok(2),
        "aptos" => Ok(3),
        "solana" | "sol" => Ok(4),
        "celestia" => Ok(5),
        "starknet" => Ok(6),
        _ => {
            // Try to parse as a number
            chain_name.parse::<u8>()
                .map_err(|_| ChainOpError::InvalidInput(
                    format!("Unknown chain: {}. Supported: bitcoin, ethereum, sui, aptos, solana, or numeric ID", chain_name)
                ))
        }
    }
}

#[cfg(feature = "rpc")]
impl EthereumBackend {
    pub fn sign_message(&self, message: &[u8]) -> ChainOpResult<Vec<u8>> {
        use alloy::signers::SignerSync;

        let signer = self
            .rpc()
            .as_any()
            .and_then(|any| any.downcast_ref::<crate::node::EthereumNode>())
            .and_then(|node| node.signer())
            .ok_or_else(|| {
                ChainOpError::SigningError(
                    "No signer configured - call with_signer() on the RPC client first".to_string(),
                )
            })?;

        let hash = alloy_primitives::FixedBytes::<32>::from_slice(message);
        let signature = signer
            .sign_hash_sync(&hash)
            .map_err(|e| ChainOpError::SigningError(format!("Failed to sign message: {}", e)))?;

        Ok(signature.as_bytes().to_vec())
    }
}

#[async_trait]
impl ChainBackend for EthereumBackend {
    fn chain_id(&self) -> &'static str {
        "ethereum"
    }

    fn chain_name(&self) -> &'static str {
        "Ethereum"
    }

    fn is_capability_available(&self, _capability: ChainCapability) -> bool {
        true
    }

    async fn create_seal(&self, value: Option<u64>) -> ChainOpResult<SealPoint> {
        let ethereum_seal = self
            .seal_protocol
            .create_seal(value)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal creation failed: {}", e)))?;

        // Convert EthereumSealPoint to core SealPoint
        // EthereumSealPoint has contract_address (20 bytes) + slot_index (8 bytes) stored in id
        let mut id_bytes = Vec::with_capacity(32);
        id_bytes.extend_from_slice(&ethereum_seal.contract_address);
        id_bytes.extend_from_slice(&ethereum_seal.slot_index.to_le_bytes());

        Ok(SealPoint {
            id: id_bytes,
            nonce: Some(ethereum_seal.nonce),
            version: None,
        })
    }

    async fn publish_seal(
        &self,
        seal: SealPoint,
        commitment: Hash,
        sanad_id: Hash,
    ) -> ChainOpResult<CommitAnchor> {
        // Convert core SealPoint to EthereumSealPoint
        if seal.id.len() < 28 {
            return Err(ChainOpError::InvalidInput(
                "Seal ID too short for Ethereum, expected at least 28 bytes".to_string(),
            ));
        }

        let mut contract_address = [0u8; 20];
        contract_address.copy_from_slice(&seal.id[..20]);
        let slot_index = u64::from_le_bytes(
            seal.id[20..28]
                .try_into()
                .expect("seal ID must be at least 28 bytes for slot_index extraction"),
        );

        let nonce = seal.nonce.unwrap_or(0);
        let ethereum_seal =
            crate::types::EthereumSealPoint::new(contract_address, slot_index, nonce);

        // Call the seal protocol's publish method. The on-chain state is keyed
        // by the canonical sanad_id via create_seal(commitment, sanad_id).
        let ethereum_anchor = self
            .seal_protocol
            .publish(commitment, ethereum_seal, sanad_id)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal publishing failed: {}", e)))?;

        // Convert EthereumCommitAnchor to core CommitAnchor
        Ok(CommitAnchor {
            anchor_id: ethereum_anchor.tx_hash.to_vec(),
            block_height: ethereum_anchor.block_number,
            metadata: ethereum_anchor.log_index.to_le_bytes().to_vec(),
        })
    }
}

#[async_trait]
impl SanadStateReader for EthereumBackend {
    async fn get_sanad_state(&self, sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState> {
        let contract_address = self.contract_address.ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Contract address not configured. Set contract_address in EthereumConfig."
                    .to_string(),
            )
        })?;

        let sanad_id_bytes = sanad_id.as_bytes();

        // Query sanadStates[sanadId] - returns SanadState enum (uint8)
        let state_result = self
            .rpc
            .eth_call(
                serde_json::json!({
                    "to": format!("0x{}", hex::encode(contract_address)),
                    "data": format!("0x{}", hex::encode(self._encode_view_call("sanadStates(bytes32)", sanad_id_bytes)))
                }),
                "latest",
            )
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to query sanadStates: {}", e)))?;

        let state = if state_result.len() >= 32 {
            state_result[31]
        } else {
            return Err(ChainOpError::RpcError(format!(
                "Invalid sanadStates response length: {}",
                state_result.len()
            )));
        };

        // Query locks[sanadId]. The auto-generated getter for the LockRecord struct
        // returns every field (the nested SanadMetadata struct is inlined). All members
        // are static value types, so the return is a fixed 11-slot (352-byte) ABI tuple:
        //   [0..32]    commitment           (bytes32)
        //   [32..64]   owner                (address, right-aligned -> [44..64])
        //   [64..96]   timestamp            (uint256)
        //   [96..128]  destinationChain     (bytes32)
        //   [128..160] destinationOwnerRoot (bytes32)
        //   [160..320] metadata             (5 static slots)
        //   [320..352] refunded             (bool -> byte 351)
        let lock_result = self
            .rpc
            .eth_call(
                serde_json::json!({
                    "to": format!("0x{}", hex::encode(contract_address)),
                    "data": format!("0x{}", hex::encode(self._encode_view_call("locks(bytes32)", sanad_id_bytes)))
                }),
                "latest",
            )
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to query locks: {}", e)))?;

        let (commitment, owner, refunded) = if lock_result.len() >= 352 {
            // commitment: bytes32 in slot 0
            let mut commitment_bytes = [0u8; 32];
            commitment_bytes.copy_from_slice(&lock_result[0..32]);
            let commitment = Hash::new(commitment_bytes);

            // owner: 20-byte address right-aligned in the 32-byte slot [32..64]
            let mut owner_full = [0u8; 20];
            owner_full.copy_from_slice(&lock_result[44..64]);
            let owner = format!("0x{}", hex::encode(owner_full));

            // refunded: bool in the final slot [320..352]
            let refunded = lock_result[351] == 1;

            (commitment, owner, refunded)
        } else {
            return Err(ChainOpError::RpcError(format!(
                "Invalid locks response length: {}",
                lock_result.len()
            )));
        };

        // Query timestamps
        let created_at = self
            ._query_uint256_slot(&contract_address, "sanadCreatedAt(bytes32)", sanad_id_bytes)
            .await
            .map_err(|e| {
                ChainOpError::RpcError(format!("Failed to query sanadCreatedAt: {}", e))
            })?;

        let locked_at = self
            ._query_uint256_slot(&contract_address, "sanadLockedAt(bytes32)", sanad_id_bytes)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to query sanadLockedAt: {}", e)))?;

        let consumed_at = self
            ._query_uint256_slot(
                &contract_address,
                "sanadConsumedAt(bytes32)",
                sanad_id_bytes,
            )
            .await
            .map_err(|e| {
                ChainOpError::RpcError(format!("Failed to query sanadConsumedAt: {}", e))
            })?;

        let minted_at = self
            ._query_uint256_slot(&contract_address, "sanadMintedAt(bytes32)", sanad_id_bytes)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to query sanadMintedAt: {}", e)))?;

        let refunded_at = self
            ._query_uint256_slot(
                &contract_address,
                "sanadRefundedAt(bytes32)",
                sanad_id_bytes,
            )
            .await
            .map_err(|e| {
                ChainOpError::RpcError(format!("Failed to query sanadRefundedAt: {}", e))
            })?;

        // The contract's `nullifiers` mapping is keyed by the nullifier hash, which
        // is not recoverable from sanad state alone (it is revealed at mint/consume
        // time). Until that preimage is plumbed through, report None and rely on the
        // canonical `state` for Consumed/Minted detection.
        let nullifier = None;

        Ok(CanonicalSanadState {
            state,
            owner,
            commitment,
            nullifier,
            created_at: created_at as i64,
            locked_at: if locked_at > 0 {
                Some(locked_at as i64)
            } else {
                None
            },
            consumed_at: if consumed_at > 0 {
                Some(consumed_at as i64)
            } else {
                None
            },
            minted_at: if minted_at > 0 {
                Some(minted_at as i64)
            } else {
                None
            },
            refunded_at: if refunded_at > 0 {
                Some(refunded_at as i64)
            } else {
                None
            },
        })
    }

    async fn get_seal_state(&self, seal_id: &Hash) -> ChainOpResult<CanonicalSealState> {
        let contract_address = self.contract_address.ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Contract address not configured. Set contract_address in EthereumConfig."
                    .to_string(),
            )
        })?;

        let seal_id_bytes = seal_id.as_bytes();

        // Query usedSeals[sealId] - returns bool
        let is_used = self
            .rpc
            .eth_call(
                serde_json::json!({
                    "to": format!("0x{}", hex::encode(contract_address)),
                    "data": format!("0x{}", hex::encode(self._encode_view_call("usedSeals(bytes32)", seal_id_bytes)))
                }),
                "latest",
            )
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to query usedSeals: {}", e)))?;

        let seal_used = if is_used.len() >= 32 {
            is_used[31] == 1
        } else {
            return Err(ChainOpError::RpcError(format!(
                "Invalid usedSeals response length: {}",
                is_used.len()
            )));
        };

        // Query sealOwners[sealId] - returns address
        let owner_result = self
            .rpc
            .eth_call(
                serde_json::json!({
                    "to": format!("0x{}", hex::encode(contract_address)),
                    "data": format!("0x{}", hex::encode(self._encode_view_call("sealOwners(bytes32)", seal_id_bytes)))
                }),
                "latest",
            )
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to query sealOwners: {}", e)))?;

        let owner = if owner_result.len() >= 52 {
            // address is right-aligned in 32-byte slot
            let owner_bytes = &owner_result[52..68];
            let mut owner_full = [0u8; 20];
            owner_full.copy_from_slice(owner_bytes);
            format!("0x{}", hex::encode(owner_full))
        } else {
            "0x0000000000000000000000000000000000000000".to_string()
        };

        // Determine seal state: 0=Created, 1=Consumed, 2=Locked, 3=Minted, 4=Refunded
        let state = if seal_used { 1 } else { 0 };

        Ok(CanonicalSealState {
            state,
            owner,
            commitment: *seal_id,
            created_at: 0,
            consumed_at: if seal_used { Some(0) } else { None },
        })
    }

    async fn trace_sanad(&self, sanad_id: &SanadId) -> ChainOpResult<Vec<CanonicalLifecycleEvent>> {
        let contract_address = self.contract_address.ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Contract address not configured. Set contract_address in EthereumConfig."
                    .to_string(),
            )
        })?;

        let sanad_id_hex = hex::encode(sanad_id.as_bytes());

        // Query contract events for this sanad_id using eth_getLogs
        let logs = self
            .rpc
            .eth_get_logs(serde_json::json!({
                "fromBlock": "0x0",
                "toBlock": "latest",
                "address": format!("0x{}", hex::encode(contract_address)),
                "topics": [
                    null,
                    format!("0x{}", sanad_id_hex)
                ]
            }))
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to query event logs: {}", e)))?;

        let events: Vec<CanonicalLifecycleEvent> = logs
            .iter()
            .filter_map(|log| {
                let topics = log.get("topics")?.as_array()?;
                let event_type = if !topics.is_empty() {
                    self._decode_event_type(topics[0].as_str()?)
                } else {
                    "Unknown".to_string()
                };
                let timestamp = log.get("timeStamp")?.as_str()?.parse::<i64>().ok()?;
                let tx_hash = log.get("transactionHash")?.as_str()?.to_string();

                Some(CanonicalLifecycleEvent {
                    event_type,
                    timestamp,
                    tx_hash,
                    data: HashMap::new(),
                })
            })
            .collect();

        Ok(events)
    }
}

#[async_trait]
impl ChainReadinessCheck for EthereumBackend {
    async fn check_readiness(&self, _account: u32, _index: u32) -> ChainOpResult<ChainReadiness> {
        // Check if contract is configured
        let contract_configured = self.contract_address.is_some();

        // Check if signer is configured by checking if the RPC client has a signer
        // The signer is added to the RPC client in the factory, not stored in the config
        let signer_configured = self.rpc.has_signer();

        // Derive signer address from private key if available
        let signer_address = if signer_configured {
            if let Some(ref secret_key) = self.seal_protocol.config().private_key {
                use secp256k1::SecretKey;
                let key_bytes = secret_key.expose_secret();
                let secret_key_obj = SecretKey::from_slice(key_bytes).map_err(|e| {
                    ChainOpError::InvalidInput(format!("Invalid secret key: {}", e))
                })?;
                Some(format!(
                    "0x{}",
                    hex::encode(Self::ethereum_address_from_secret_key(&secret_key_obj)?)
                ))
            } else {
                None
            }
        } else {
            None
        };

        // Balance address is same as signer address for Ethereum
        let balance_address = signer_address.clone();

        // Check write capability (signer configured + RPC available)
        let write_capable = signer_configured;

        // Check if account exists (has balance > 0)
        let account_exists = if let Some(ref addr) = balance_address {
            // Parse address to bytes for RPC call
            if let Ok(addr_bytes) = hex::decode(addr.trim_start_matches("0x")) {
                if addr_bytes.len() == 20 {
                    let mut addr_array = [0u8; 20];
                    addr_array.copy_from_slice(&addr_bytes);
                    match self.rpc.get_balance(addr_array).await {
                        Ok(balance) => balance > 0,
                        Err(_) => false,
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // Get native balance
        let native_balance = if let Some(ref addr) = balance_address {
            // Parse address to bytes for RPC call
            if let Ok(addr_bytes) = hex::decode(addr.trim_start_matches("0x")) {
                if addr_bytes.len() == 20 {
                    let mut addr_array = [0u8; 20];
                    addr_array.copy_from_slice(&addr_bytes);
                    self.rpc.get_balance(addr_array).await.ok()
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Estimate minimum fee (gas price * gas limit for simple tx)
        let estimated_fee = match self.rpc.get_gas_price().await {
            Ok(gas_price) => Some(gas_price.saturating_mul(21000)), // 21000 gas for simple transfer
            Err(_) => Some(20_000_000_000),                         // 20 gwei fallback
        };

        // Ethereum supports sanad creation (via seal contract)
        let sanad_create_supported = contract_configured;

        // Ethereum supports proof generation (MPT proofs)
        let proof_generation_supported = true;

        // Ethereum can be cross-chain source
        let cross_chain_source_supported = true;

        // Ethereum can be cross-chain destination
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
    use crate::config::Network;
    use crate::rpc::MockEthereumRpc;

    #[test]
    fn test_ethereum_chain_operations_creation() {
        let rpc = Box::new(MockEthereumRpc::new(1000));
        let config = EthereumConfig {
            network: Network::Mainnet,
            finality_depth: 15,
            use_checkpoint_finality: true,
            rpc_url: "http://127.0.0.1:8545".to_string(),
            private_key: None,
            contract_address: None,
        };
        let ops = EthereumBackend::new(rpc, config)
            .expect("EthereumBackend::new should succeed with a mock RPC and valid config");
        assert_eq!(ops.config.network.chain_id(), 1);
    }

    #[test]
    fn test_address_validation() {
        let rpc = Box::new(MockEthereumRpc::new(1000));
        let config = EthereumConfig {
            network: Network::Mainnet,
            finality_depth: 15,
            use_checkpoint_finality: true,
            rpc_url: "http://127.0.0.1:8545".to_string(),
            private_key: None,
            contract_address: None,
        };
        let ops = EthereumBackend::new(rpc, config)
            .expect("EthereumBackend::new should succeed with a mock RPC and valid config");

        // Valid address
        assert!(ops.validate_address("0x0000000000000000000000000000000000000000"));

        // Invalid - too short
        assert!(!ops.validate_address("0x1234"));

        // Invalid - not hex
        assert!(!ops.validate_address("0xZZZZ"));
    }

    fn test_ops_with_contract(contract_address: Option<[u8; 20]>) -> EthereumBackend {
        let rpc = Box::new(MockEthereumRpc::new(1000));
        let config = EthereumConfig {
            network: Network::Sepolia,
            finality_depth: 15,
            use_checkpoint_finality: true,
            rpc_url: "http://127.0.0.1:8545".to_string(),
            private_key: None,
            contract_address,
        };
        EthereumBackend::new(rpc, config)
            .expect("EthereumBackend::new should succeed with a mock RPC and valid config")
    }

    #[test]
    fn test_canonical_sanad_state_code_maps_names() {
        assert_eq!(canonical_sanad_state_code("uncreated"), Some(0));
        assert_eq!(canonical_sanad_state_code("Created"), Some(1));
        assert_eq!(canonical_sanad_state_code("ACTIVE"), Some(2));
        assert_eq!(canonical_sanad_state_code("locked"), Some(3));
        assert_eq!(canonical_sanad_state_code("consumed"), Some(4));
        assert_eq!(canonical_sanad_state_code("minted"), Some(5));
        assert_eq!(canonical_sanad_state_code("transferred"), Some(6));
        assert_eq!(canonical_sanad_state_code("refunded"), Some(7));
        assert_eq!(canonical_sanad_state_code("burned"), Some(8));
        assert_eq!(canonical_sanad_state_code("invalid"), Some(9));
        assert_eq!(canonical_sanad_state_code("4"), Some(4));
        assert_eq!(canonical_sanad_state_code("not-a-state"), None);
    }

    #[test]
    fn test_eip1559_fee_caps_keep_max_fee_at_least_priority_fee() {
        let (max_fee, priority_fee) = eip1559_fee_caps(100_000_000);
        assert_eq!(priority_fee, 1_000_000_000);
        assert_eq!(max_fee, priority_fee);

        let (max_fee, priority_fee) = eip1559_fee_caps(2_000_000_000);
        assert_eq!(priority_fee, 1_000_000_000);
        assert_eq!(max_fee, 2_000_000_000);
    }

    #[test]
    fn ethereum_address_derivation_matches_foundry_vm_addr_semantics() {
        use secp256k1::{PublicKey, Secp256k1, SecretKey};

        let ops = test_ops_with_contract(None);
        let cases = [
            (
                "3c2277ba7f668351804ac0efa97137f338fedadb63e7b70d417de0084b7ef2f2",
                "4691babba8bf9a962c83c42bed1cadc7c7d01073",
            ),
            (
                "4809be89a096884aab1c50d0d2959bf7669a47649f39d9dc009a6ce981151f8f",
                "643805b7b33790b310d0792f303e42eaf8d5e5ae",
            ),
        ];

        for (key_hex, expected_address) in cases {
            let key_bytes = hex::decode(key_hex).unwrap();
            let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
            let secp = Secp256k1::new();
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            let expected_address_hex = format!("0x{}", expected_address);

            assert_eq!(
                ops.derive_address(&public_key.serialize_uncompressed())
                    .unwrap(),
                expected_address_hex
            );
            assert_eq!(
                ops.derive_address(&public_key.serialize()).unwrap(),
                expected_address_hex
            );
            assert_eq!(
                hex::encode(
                    EthereumBackend::ethereum_address_from_secret_key(&secret_key).unwrap()
                ),
                expected_address
            );
        }
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn mint_attestation_signature_recovers_configured_verifier_address() {
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
        use secp256k1::{Message, Secp256k1, SecretKey};

        let key_bytes =
            hex::decode("3c2277ba7f668351804ac0efa97137f338fedadb63e7b70d417de0084b7ef2f2")
                .unwrap();
        let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
        let ops = test_ops_with_contract(None).with_verifier_key(secret_key);
        let digest = [0x42u8; 32];

        let signature = ops.sign_mint_attestation_digest(&digest).unwrap();
        assert_eq!(signature.len(), 65);
        assert!(signature[64] == 27 || signature[64] == 28);

        let recovery_id = RecoveryId::from_i32((signature[64] - 27) as i32).unwrap();
        let recoverable =
            RecoverableSignature::from_compact(&signature[..64], recovery_id).unwrap();
        let recovered = Secp256k1::new()
            .recover_ecdsa(&Message::from_digest(digest), &recoverable)
            .unwrap();

        assert_eq!(
            hex::encode(
                EthereumBackend::ethereum_address_from_public_key(
                    &recovered.serialize_uncompressed()
                )
                .unwrap()
            ),
            "4691babba8bf9a962c83c42bed1cadc7c7d01073"
        );
    }

    #[test]
    fn test_parse_metadata_hash_field_defaults_to_zero() {
        let metadata = serde_json::json!({});
        let result = parse_metadata_hash_field(&metadata, "asset_id").unwrap();
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_parse_metadata_hash_field_parses_hex() {
        let hex_val = "0x".to_string() + &"ab".repeat(32);
        let metadata = serde_json::json!({ "asset_id": hex_val });
        let result = parse_metadata_hash_field(&metadata, "asset_id").unwrap();
        assert_eq!(result, [0xabu8; 32]);
    }

    #[test]
    fn test_parse_metadata_hash_field_rejects_wrong_length() {
        let metadata = serde_json::json!({ "asset_id": "0xabcd" });
        assert!(parse_metadata_hash_field(&metadata, "asset_id").is_err());
    }

    #[test]
    fn test_parse_metadata_hash_field_rejects_invalid_hex() {
        let metadata = serde_json::json!({ "asset_id": "not-hex" });
        assert!(parse_metadata_hash_field(&metadata, "asset_id").is_err());
    }

    #[test]
    fn test_encode_call_2args_layout() {
        let ops = test_ops_with_contract(None);
        let arg1 = [1u8; 32];
        let arg2 = [2u8; 32];
        let calldata = ops._encode_call_2args("consume_seal(bytes32,bytes32)", &arg1, &arg2);
        assert_eq!(calldata.len(), 4 + 32 + 32);
        assert_eq!(&calldata[4..36], &arg1[..]);
        assert_eq!(&calldata[36..68], &arg2[..]);

        let expected_selector = ops._keccak256(b"consume_seal(bytes32,bytes32)");
        assert_eq!(&calldata[..4], &expected_selector[..4]);
    }

    #[tokio::test]
    async fn test_create_sanad_rejects_empty_asset_id() {
        let ops = test_ops_with_contract(Some([0x11u8; 20]));
        let result = ops
            .create_sanad(
                "0x0000000000000000000000000000000000000000",
                "fungible",
                "",
                serde_json::json!({}),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_sanad_rejects_malformed_owner() {
        let ops = test_ops_with_contract(Some([0x11u8; 20]));
        let result = ops
            .create_sanad(
                "not-an-address",
                "fungible",
                "asset-1",
                serde_json::json!({}),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_sanad_requires_contract_configured() {
        let ops = test_ops_with_contract(None);
        let result = ops
            .create_sanad(
                "0x0000000000000000000000000000000000000000",
                "fungible",
                "asset-1",
                serde_json::json!({}),
            )
            .await;
        assert!(result.is_err());
    }
}
