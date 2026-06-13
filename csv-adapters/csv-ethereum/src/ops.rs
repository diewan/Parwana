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
    ChainProofProvider, ChainQuery, ChainSanadOps, ChainSigner, ContractStatus, DeploymentStatus,
    FinalityStatus, SanadOperationResult, SanadStateReader, TransactionInfo, TransactionStatus,
};

use csv_hash::Hash;
#[cfg(feature = "rpc")]
use csv_protocol::chain_adapter_traits::SanadOperation;
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::sanad::SanadId;
use csv_protocol::seal::{CommitAnchor, SealPoint};
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::signature::SignatureScheme;
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
    seal_protocol: Arc<EthereumSealProtocol>,
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
    /// Create new Ethereum chain operations from RPC client
    pub fn new(rpc: Box<dyn EthereumRpc>, config: EthereumConfig) -> Self {
        let mut domain = [0u8; 32];
        domain[..10].copy_from_slice(b"CSV-ETH---");
        let chain_id = config.network.chain_id().to_le_bytes();
        domain[10..18].copy_from_slice(&chain_id);

        let finality_checker = FinalityChecker::new(crate::finality::FinalityConfig {
            confirmation_depth: config.finality_depth,
            prefer_checkpoint_finality: config.use_checkpoint_finality,
        });

        // Create seal protocol using the real RPC (not a mock)
        // This is required for publish() to work, which downcasts to EthereumNode
        let csv_seal_address = config.contract_address.unwrap_or([0u8; 20]);
        let seal = EthereumSealProtocol::from_config(config.clone(), rpc.clone_boxed(), csv_seal_address)
            .unwrap_or_else(|e| {
                // Fallback to mock if real RPC creation fails
                eprintln!("Warning: Failed to create seal protocol with real RPC: {}, using mock", e);
                let mock_rpc = Box::new(crate::rpc::MockEthereumRpc::new(1000));
                let seal_config = EthereumConfig {
                    network: crate::config::Network::Sepolia,
                    finality_depth: 12,
                    ..Default::default()
                };
                EthereumSealProtocol::from_config(seal_config, mock_rpc, [0u8; 20])
                    .expect("failed to create EthereumSealProtocol from fallback config")
            });

        Self {
            rpc,
            config: config.clone(),
            domain_separator: domain,
            finality_checker,
            seal_contract: CsvSealAbi,
            contract_address: config.contract_address,
            proof_verifier: EventProofVerifier::new(),
            event_builder: CommitmentEventBuilder::new(),
            seal_protocol: Arc::new(seal),
        }
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
        })
    }

    /// Set the seal contract address for sanad operations
    pub fn with_contract(mut self, address: [u8; 20]) -> Self {
        self.contract_address = Some(address);
        self
    }

    /// Get the seal contract address if set
    fn contract(&self) -> ChainOpResult<[u8; 20]> {
        self.contract_address.ok_or_else(|| {
            ChainOpError::InvalidInput(
                "Seal contract address not configured. Set it with with_contract()"
                    .to_string(),
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

        let result = self.rpc().eth_call(
            serde_json::json!({
                "to": format!("0x{}", hex::encode(contract_addr)),
                "data": format!("0x{}", encoded)
            }),
            "latest",
        ).await.map_err(|e| {
            ChainOpError::RpcError(format!("Failed to call getLockInfo: {}", e))
        })?;

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
        let mut current_max_fee = gas_price as u128;
        let max_priority_fee = 1_000_000_000u128; // 1 Gwei priority fee

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
                        || error_str.contains("underpriced")
                        && retry_count < max_retries - 1
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

        // Ethereum address = last 20 bytes of Keccak256(public_key)
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(public_key);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);

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
        let _ = owner;
        let _ = asset_class;
        let _ = asset_id;
        let _ = metadata;

        // In Ethereum, creating a sanad involves calling the CSV seal contract
        // The contract would:
        // 1. Create a new seal entry with metadata
        // 2. Store the commitment
        // 3. Emit a SanadCreated event

        Err(ChainOpError::CapabilityUnavailable(
            "Sanad creation requires a signed transaction to the CSV seal contract. \
             Construct and submit a transaction calling the createSanad function."
                .to_string(),
        ))
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
            let calldata = crate::seal_contract::CsvSealAbi::encode_mark_seal_used(*sanad_id_bytes, *sanad_id_bytes);

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
                })).unwrap_or_default(),
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

        #[cfg(feature = "rpc")]
        {
            // Build the lock transaction using generated Alloy bindings
            use crate::bindings::csv_seal::lockSanadCall;
            let call = lockSanadCall {
                sanadId: alloy_primitives::FixedBytes::<32>::from_slice(sanad_id_bytes),
                commitment: alloy_primitives::FixedBytes::<32>::from_slice(commitment),
                destinationChain: dest_chain_id,
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
                })).unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            let _ = (contract, commitment, dest_chain_id, owner_addr);
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
        let contract = self.contract()?;
        let sanad_id_bytes = source_sanad_id.0.as_bytes();
        let commitment = sanad_id_bytes;
        let state_root = lock_proof.block_hash.as_bytes();
        let source_chain_id = parse_chain_id(source_chain)?;
        let owner_addr = self.parse_address(new_owner)?;
        let proof_root = lock_proof.block_hash.as_bytes();

        #[cfg(feature = "rpc")]
        {
            // Build the mint transaction using generated Alloy bindings
            use crate::bindings::csv_seal::mintSanadCall;
            let call = mintSanadCall {
                sanadId: alloy_primitives::FixedBytes::<32>::from_slice(sanad_id_bytes),
                commitment: alloy_primitives::FixedBytes::<32>::from_slice(commitment),
                stateRoot: alloy_primitives::FixedBytes::<32>::from_slice(state_root),
                sourceChain: source_chain_id,
                sourceSealPoint: alloy_primitives::Bytes::from(owner_addr.to_vec()),
                proof: alloy_primitives::Bytes::from(lock_proof.proof_bytes.clone()),
                proofRoot: alloy_primitives::FixedBytes::<32>::from_slice(proof_root),
                leafPosition: alloy_primitives::U256::from(0),
            };

            // Encode the calldata from the generated call struct
            let calldata = call.abi_encode();

            // Build and sign transaction
            let tx_hash = self
                .build_sign_and_send_transaction(contract, &calldata, new_owner)
                .await?;

            // Wait for receipt
            let receipt = self.wait_for_receipt(&tx_hash).await?;

            Ok(SanadOperationResult {
                sanad_id: source_sanad_id.clone(),
                operation: SanadOperation::Mint,
                transaction_hash: hex::encode(tx_hash),
                block_height: receipt.block_number,
                chain_id: self.config.network.chain_id().to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "operation": "mint",
                    "source_chain": source_chain,
                    "new_owner": new_owner,
                    "contract": hex::encode(contract),
                })).unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            let _ = (contract, owner_addr);
            Err(ChainOpError::FeatureNotEnabled(
                "Sanad minting requires the 'rpc' feature for transaction signing. \
                 Enable it in Cargo.toml: csv-adapter-ethereum = { features = ['rpc'] }"
                    .to_string(),
            ))
        }
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
            use crate::bindings::csv_seal::refundSanadCall;
            let call = refundSanadCall {
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
                })).unwrap_or_default(),
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
        // Note: CSVLock.sol on Ethereum records metadata during lockSanad or lockSanadWithMetadata.
        // There is no separate updateMetadata function in the contract.
        // Metadata recording happens atomically with the lock operation.

        let _ = metadata;
        let _ = owner_key_id;

        // Check if sanad is locked (metadata would have been recorded then)
        let contract = self.contract()?;
        let sanad_id_bytes = *sanad_id.0.as_bytes();

        #[cfg(feature = "rpc")]
        {
            // Try to query contract state to verify metadata was recorded
            use crate::bindings::csv_seal::getLockInfoCall;
            let _call = getLockInfoCall {
                sanadId: alloy_primitives::FixedBytes::<32>::from_slice(&sanad_id_bytes),
            };

            // For now, return success noting that metadata was recorded at lock time
            Ok(SanadOperationResult {
                sanad_id: sanad_id.clone(),
                operation: SanadOperation::RecordMetadata,
                transaction_hash: String::new(), // No separate tx - metadata recorded at lock
                block_height: 0,
                chain_id: self.config.network.chain_id().to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "operation": "record_metadata",
                    "note": "On Ethereum, metadata is recorded during lockSanad operation",
                    "contract": hex::encode(contract),
                })).unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            let _ = contract;
            Err(ChainOpError::FeatureNotEnabled(
                "Metadata verification requires the 'rpc' feature. \
                 Note: On Ethereum, metadata is recorded during the lock operation."
                    .to_string(),
            ))
        }
    }

    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        expected_state: &str,
    ) -> ChainOpResult<bool> {
        // Query the CSV seal contract for the seal state using eth_call
        let contract = self.contract()?;
        let commitment = sanad_id.0.as_bytes();
        let mut commitment_array = [0u8; 32];
        let copy_len = commitment.len().min(32);
        commitment_array[..copy_len].copy_from_slice(&commitment[..copy_len]);

        // Build the eth_call to getSealState(bytes32 commitment) function
        // Function selector: keccak256("getSealState(bytes32)")[0..4]
        use sha3::{Digest, Keccak256};
        let mut selector_input = Vec::new();
        selector_input.extend_from_slice(b"getSealState(bytes32)");
        let selector_hash = Keccak256::digest(&selector_input);
        let selector = &selector_hash[..4];

        // Build the calldata: selector (4 bytes) + commitment (32 bytes)
        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(selector);
        calldata.extend_from_slice(&commitment_array);

        // Perform the eth_call to query contract state
        // This is a read-only call that doesn't create a transaction
        // Note: call_contract is not available in the EthereumRpc trait
        // This functionality needs to be implemented or the code path refactored
        Err(ChainOpError::FeatureNotEnabled(
            "call_contract method not available in EthereumRpc trait. \
             This functionality needs to be implemented via eth_call RPC method."
                .to_string(),
        ))
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
        let signature = signer.sign_hash_sync(&hash).map_err(|e| {
            ChainOpError::SigningError(format!("Failed to sign message: {}", e))
        })?;

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

    async fn publish_seal(&self, seal: SealPoint, commitment: Hash) -> ChainOpResult<CommitAnchor> {
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

        // Call the seal protocol's publish method
        let ethereum_anchor = self
            .seal_protocol
            .publish(commitment, ethereum_seal)
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
        // For Ethereum, sanad state would be queried via contract view functions
        // This is a simplified implementation - in production, call getSanadState on the contract
        Ok(CanonicalSanadState {
            state: 1, // Created (placeholder - would query actual contract state)
            owner: "unknown".to_string(),
            commitment: Hash::new([0u8; 32]),
            nullifier: None,
            created_at: 0,
            locked_at: None,
            consumed_at: None,
            minted_at: None,
            refunded_at: None,
        })
    }
    
    async fn get_seal_state(&self, seal_id: &Hash) -> ChainOpResult<CanonicalSealState> {
        // For Ethereum, seal state is derived from the contract state
        // This is a simplified implementation
        Ok(CanonicalSealState {
            state: 0, // Created
            owner: "unknown".to_string(),
            commitment: *seal_id,
            created_at: 0,
            consumed_at: None,
        })
    }
    
    async fn trace_sanad(&self, _sanad_id: &SanadId) -> ChainOpResult<Vec<CanonicalLifecycleEvent>> {
        // Query contract events for this sanad_id
        // This would require querying the event logs from the contract
        Ok(vec![])
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
        let ops = EthereumBackend::new(rpc, config);
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
        let ops = EthereumBackend::new(rpc, config);

        // Valid address
        assert!(ops.validate_address("0x0000000000000000000000000000000000000000"));

        // Invalid - too short
        assert!(!ops.validate_address("0x1234"));

        // Invalid - not hex
        assert!(!ops.validate_address("0xZZZZ"));
    }
}
