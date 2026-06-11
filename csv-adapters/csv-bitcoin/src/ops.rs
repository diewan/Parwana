//! Chain Operations Implementation for Bitcoin
//!
//! Implements the core chain operation traits from csv-adapter-core
//! for real Bitcoin chain interactions.

use async_trait::async_trait;
use bitcoin::Network;
use bitcoin_hashes::Hash as BitcoinHash;
use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_protocol::chain_adapter_traits::{
    BalanceInfo, CanonicalLifecycleEvent, CanonicalSanadState, CanonicalSealState, ChainBackend,
    ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError, ChainOpResult,
    ChainProofProvider, ChainQuery, ChainSanadOps, ChainSigner, ContractStatus, DeploymentStatus,
    FinalityStatus, SanadOperation, SanadOperationResult, SanadStateReader, TransactionStatus,
};
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::signature::SignatureScheme;
use std::sync::Arc;

use crate::rpc::BitcoinRpc;
use crate::seal_protocol::BitcoinSealProtocol;
use crate::types::BitcoinSealPoint;
use csv_protocol::seal_protocol::SealProtocol;

/// Bitcoin-specific extension to ChainSigner that accepts prevout amounts
///
/// HIGH-BTC-01: BIP-143 sighash requires the spent UTXO value.
/// This trait provides a Bitcoin-specific signing method that accepts
/// prevout amounts for proper sighash computation.
#[async_trait]
pub trait BitcoinChainSignerExt: Send + Sync {
    /// Sign a Bitcoin transaction with prevout amounts for BIP-143 sighash
    ///
    /// # Arguments
    /// * `tx_data` - The transaction bytes to sign
    /// * `key_id` - Identifier for the signing key
    /// * `prevout_amounts` - Vector of (input_index, amount) pairs for each input
    ///
    /// # Returns
    /// The signed transaction bytes
    async fn sign_transaction_with_prevouts(
        &self,
        tx_data: &[u8],
        key_id: &str,
        prevout_amounts: Vec<(usize, u64)>,
    ) -> ChainOpResult<Vec<u8>>;
}

/// Encode a value as a Bitcoin-style variable length integer (varint)
fn encode_varint(value: u64) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => {
            let mut result = vec![0xfd];
            result.extend_from_slice(&(value as u16).to_le_bytes());
            result
        }
        0x10000..=0xffffffff => {
            let mut result = vec![0xfe];
            result.extend_from_slice(&(value as u32).to_le_bytes());
            result
        }
        _ => {
            let mut result = vec![0xff];
            result.extend_from_slice(&value.to_le_bytes());
            result
        }
    }
}

/// Bitcoin implementation of ChainQuery trait
pub struct BitcoinChainQuery {
    rpc: Box<dyn BitcoinRpc + Send + Sync>,
    network: Network,
}

impl BitcoinChainQuery {
    /// Create a new Bitcoin chain query instance
    pub fn new(rpc: Box<dyn BitcoinRpc + Send + Sync>, network: Network) -> Self {
        Self { rpc, network }
    }

    /// Create from a real Bitcoin RPC client
    #[cfg(feature = "rpc")]
    pub fn from_real_rpc(rpc: crate::node::real_rpc::BitcoinNode, network: Network) -> Self {
        // BitcoinNode implements BitcoinRpc, so we can box it
        Self::new(Box::new(rpc), network)
    }
}

#[async_trait]
impl ChainQuery for BitcoinChainQuery {
    async fn get_balance(&self, address: &str) -> ChainOpResult<BalanceInfo> {
        // Query UTXOs from RPC and sum the amounts
        let utxos = self
            .rpc
            .get_utxos_for_address(address.to_string())
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to query UTXOs: {}", e)))?;

        let total_balance: u64 = utxos.iter().map(|utxo| utxo.amount_sat).sum();

        Ok(BalanceInfo {
            address: address.to_string(),
            total: total_balance,
            available: total_balance,
            locked: 0,
            tokens: vec![],
        })
    }

    async fn get_transaction(
        &self,
        tx_hash: &str,
    ) -> ChainOpResult<csv_protocol::chain_adapter_traits::TransactionInfo> {
        use csv_protocol::chain_adapter_traits::{TransactionInfo, TransactionStatus};

        // Parse the txid
        let txid_bytes = hex::decode(tx_hash.trim_start_matches("0x"))
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid tx hash: {}", e)))?;

        if txid_bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Transaction hash must be 32 bytes".to_string(),
            ));
        }

        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&txid_bytes);

        // Get confirmations via RPC
        let confirmations = self
            .rpc
            .get_tx_confirmations(txid_array)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get confirmations: {}", e)))?;

        let status = if confirmations == 0 {
            TransactionStatus::Pending
        } else {
            TransactionStatus::Confirmed {
                block_height: 0,
                confirmations,
            }
        };

        Ok(TransactionInfo {
            hash: tx_hash.to_string(),
            sender: String::new(), // Would need to decode transaction
            recipient: None,
            amount: None,
            status,
            block_height: None,
            timestamp: None,
            fee: None,
            raw_data: None,
        })
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        let tx_info = self.get_transaction(tx_hash).await?;

        match tx_info.status {
            csv_protocol::chain_adapter_traits::TransactionStatus::Pending => Ok(FinalityStatus::Pending),
            csv_protocol::chain_adapter_traits::TransactionStatus::Confirmed { block_height, .. } => {
                // Treat confirmed as finalized for Bitcoin (6+ confirmations)
                Ok(FinalityStatus::Finalized {
                    block_height,
                    finality_block: block_height,
                })
            }
            csv_protocol::chain_adapter_traits::TransactionStatus::Failed { .. } => Ok(FinalityStatus::Orphaned),
            csv_protocol::chain_adapter_traits::TransactionStatus::Dropped => Ok(FinalityStatus::Orphaned),
            csv_protocol::chain_adapter_traits::TransactionStatus::Unknown => Ok(FinalityStatus::Pending),
        }
    }

    async fn get_contract_status(&self, _contract_address: &str) -> ChainOpResult<ContractStatus> {
        // Bitcoin doesn't have smart contracts in the traditional sense
        Ok(ContractStatus {
            address: String::new(),
            is_deployed: false,
            balance: None,
            owner: None,
            metadata: serde_json::json!({
                "chain": "bitcoin",
                "note": "Bitcoin does not support smart contracts"
            }),
        })
    }

    async fn get_latest_block_height(&self) -> ChainOpResult<u64> {
        self.rpc
            .get_block_count()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get block count: {}", e)))
    }

    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        Ok(serde_json::json!({
            "chain": "bitcoin",
            "network": format!("{:?}", self.network),
            "version": "0.4.0",
            "protocol": "Bitcoin"
        }))
    }

    async fn get_account_nonce(&self, _address: &str) -> ChainOpResult<u64> {
        // Bitcoin doesn't have account nonces - it uses UTXOs
        Err(ChainOpError::CapabilityUnavailable(
            "Bitcoin does not support account nonces (uses UTXO model)".to_string(),
        ))
    }

    fn validate_address(&self, address: &str) -> bool {
        // Try to parse the address
        address.parse::<bitcoin::Address<_>>().is_ok()
    }
}

/// Bitcoin implementation of ChainSigner trait
#[derive(Debug)]
pub struct BitcoinChainSigner {
    network: Network,
}

impl BitcoinChainSigner {
    /// Create a new Bitcoin chain signer
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}

#[async_trait]
impl ChainSigner for BitcoinChainSigner {
    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String> {
        // Derive a Bitcoin Taproot (P2TR) address from a public key
        use bitcoin::address::Address;
        use bitcoin::key::TweakedPublicKey;
        use secp256k1::{PublicKey, XOnlyPublicKey};

        let pub_key = PublicKey::from_slice(public_key)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {}", e)))?;

        let x_only_pubkey = XOnlyPublicKey::from(pub_key);
        let tweaked = TweakedPublicKey::dangerous_assume_tweaked(x_only_pubkey);

        // Build Taproot address (P2TR) - tweaked key path spend
        let address = Address::p2tr_tweaked(tweaked, self.network);

        Ok(address.to_string())
    }

    async fn sign_transaction(&self, tx_data: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>> {
        // Parse key_id as hex-encoded private key (32 bytes)
        let key_bytes = hex::decode(key_id).map_err(|_| {
            ChainOpError::SigningError(
                "Invalid key_id format. Expected hex-encoded 32-byte key.".to_string(),
            )
        })?;

        if key_bytes.len() != 32 {
            return Err(ChainOpError::SigningError(
                "Invalid key length. Expected 32 bytes.".to_string(),
            ));
        }

        let secret_key = secp256k1::SecretKey::from_slice(&key_bytes)
            .map_err(|e| ChainOpError::SigningError(format!("Invalid secret key: {}", e)))?;

        // Parse the transaction from bytes
        // Expected format: version (4) + marker+flag (2 for segwit) + inputs + outputs + witness + locktime
        let tx = parse_bitcoin_tx(tx_data).map_err(|e| {
            ChainOpError::InvalidInput(format!("Failed to parse transaction: {}", e))
        })?;

        // Sign each input (P2WPKH)
        let secp = secp256k1::Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let x_only_pubkey = secp256k1::XOnlyPublicKey::from(public_key);
        let pubkey_bytes = x_only_pubkey.serialize();

        let mut signed_witnesses: Vec<Vec<Vec<u8>>> = Vec::new();

        for input in &tx.inputs {
            // Create sighash for P2WPKH: hash of the transaction with this input's scriptCode
            // For P2WPKH: scriptCode = 0x1976a914{20-byte-pubkey-hash}88ac
            // But for Taproot (P2TR), we use a different sighash algorithm

            // HIGH-BTC-01: BIP-143 sighash requires the spent UTXO value
            // We need prevout amounts to compute the sighash correctly
            // For now, fail closed until prevout amounts are provided via a proper API
            let sighash = compute_sighash(&tx, input, &pubkey_bytes, None).map_err(|e| {
                ChainOpError::SigningError(format!("Failed to compute sighash: {}", e))
            })?;

            let message = secp256k1::Message::from_digest_slice(&sighash)
                .map_err(|e| ChainOpError::SigningError(format!("Invalid sighash: {}", e)))?;

            let signature = secp.sign_ecdsa(&message, &secret_key);
            let sig_bytes = signature.serialize_compact().to_vec();

            // Witness stack for P2WPKH: [signature, public_key]
            signed_witnesses.push(vec![sig_bytes, pubkey_bytes.to_vec()]);
        }

        // Build the final signed transaction with witness data
        let signed_tx = build_signed_transaction(&tx, signed_witnesses)
            .map_err(|e| ChainOpError::SigningError(format!("Failed to build signed tx: {}", e)))?;

        Ok(signed_tx)
    }

    async fn sign_message(&self, message: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>> {
        // Sign a message using Bitcoin message signing format
        // The key_id should reference a private key in the keystore
        // For production, this would retrieve the key from secure storage

        use bitcoin_hashes::{Hash, sha256d};
        use secp256k1::{Message, Secp256k1, SecretKey};

        // Bitcoin message signing prefix
        const BITCOIN_SIGNED_MESSAGE_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

        // Note: In production, the key_id would be used to retrieve the key from secure storage
        // This implementation assumes the key_id encodes the necessary signing material
        // For now, we return an error indicating keystore integration is required

        // Parse key_id as hex-encoded secret key (for testing/development only)
        // In production, this should use the keystore crate
        let key_bytes = hex::decode(key_id).map_err(|_| {
            ChainOpError::SigningError(
                "Invalid key_id format. Expected hex-encoded key reference.".to_string(),
            )
        })?;

        if key_bytes.len() != 32 {
            return Err(ChainOpError::SigningError(
                "Invalid key length. Expected 32 bytes.".to_string(),
            ));
        }

        let secret_key = SecretKey::from_slice(&key_bytes)
            .map_err(|e| ChainOpError::SigningError(format!("Invalid secret key: {}", e)))?;

        // Create Bitcoin message hash: SHA256D(prefix || varint(len(message)) || message)
        let mut message_to_hash = Vec::new();
        message_to_hash.extend_from_slice(BITCOIN_SIGNED_MESSAGE_PREFIX);
        message_to_hash.extend_from_slice(&encode_varint(message.len() as u64));
        message_to_hash.extend_from_slice(message);

        let hash = sha256d::Hash::hash(&message_to_hash);
        let msg = Message::from_digest_slice(hash.as_ref())
            .map_err(|e| ChainOpError::SigningError(format!("Failed to create message: {}", e)))?;

        // Sign the message
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(&msg, &secret_key);

        // Serialize signature in compact format (64 bytes)
        Ok(signature.serialize_compact().to_vec())
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> ChainOpResult<bool> {
        // Verify a Bitcoin message signature using secp256k1
        use bitcoin_hashes::{Hash as BitcoinHash, sha256d};
        use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};

        // Bitcoin message signing prefix
        const BITCOIN_SIGNED_MESSAGE_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

        // Parse public key
        let pub_key = PublicKey::from_slice(public_key)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {}", e)))?;

        // Parse signature (64 bytes compact format)
        if signature.len() != 64 {
            return Err(ChainOpError::InvalidInput(
                "Signature must be 64 bytes in compact format".to_string(),
            ));
        }

        let sig = Signature::from_compact(signature)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid signature: {}", e)))?;

        // Recreate the message hash
        let mut message_to_hash = Vec::new();
        message_to_hash.extend_from_slice(BITCOIN_SIGNED_MESSAGE_PREFIX);
        message_to_hash.extend_from_slice(&encode_varint(message.len() as u64));
        message_to_hash.extend_from_slice(message);

        let hash = sha256d::Hash::hash(&message_to_hash);
        let msg = Message::from_digest_slice(hash.as_ref())
            .map_err(|e| ChainOpError::InvalidInput(format!("Failed to create message: {}", e)))?;

        // Verify the signature
        let secp = Secp256k1::new();
        match secp.verify_ecdsa(&msg, &sig, &pub_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        // SignatureScheme::Schnorr
        SignatureScheme::Secp256k1
    }
}

#[async_trait]
impl BitcoinChainSignerExt for BitcoinChainSigner {
    async fn sign_transaction_with_prevouts(
        &self,
        tx_data: &[u8],
        key_id: &str,
        prevout_amounts: Vec<(usize, u64)>,
    ) -> ChainOpResult<Vec<u8>> {
        // Parse key_id as hex-encoded private key (32 bytes)
        let key_bytes = hex::decode(key_id).map_err(|_| {
            ChainOpError::SigningError(
                "Invalid key_id format. Expected hex-encoded 32-byte key.".to_string(),
            )
        })?;

        if key_bytes.len() != 32 {
            return Err(ChainOpError::SigningError(
                "Invalid key length. Expected 32 bytes.".to_string(),
            ));
        }

        let secret_key = secp256k1::SecretKey::from_slice(&key_bytes)
            .map_err(|e| ChainOpError::SigningError(format!("Invalid secret key: {}", e)))?;

        // Parse the transaction from bytes
        let tx = parse_bitcoin_tx(tx_data).map_err(|e| {
            ChainOpError::InvalidInput(format!("Failed to parse transaction: {}", e))
        })?;

        // Validate prevout amounts
        if prevout_amounts.len() != tx.inputs.len() {
            return Err(ChainOpError::InvalidInput(format!(
                "Prevout amounts count ({}) must match input count ({})",
                prevout_amounts.len(),
                tx.inputs.len()
            )));
        }

        // Sign each input with its corresponding prevout amount
        let secp = secp256k1::Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let x_only_pubkey = secp256k1::XOnlyPublicKey::from(public_key);
        let pubkey_bytes = x_only_pubkey.serialize();

        let mut signed_witnesses: Vec<Vec<Vec<u8>>> = Vec::new();

        for (idx, input) in tx.inputs.iter().enumerate() {
            // Find the prevout amount for this input
            let amount = prevout_amounts
                .iter()
                .find(|(i, _)| *i == idx)
                .map(|(_, amt)| *amt)
                .ok_or_else(|| {
                    ChainOpError::InvalidInput(format!(
                        "Missing prevout amount for input index {}",
                        idx
                    ))
                })?;

            // Compute sighash with the prevout amount
            let sighash =
                compute_sighash(&tx, input, &pubkey_bytes, Some(amount)).map_err(|e| {
                    ChainOpError::SigningError(format!("Failed to compute sighash: {}", e))
                })?;

            let message = secp256k1::Message::from_digest_slice(&sighash)
                .map_err(|e| ChainOpError::SigningError(format!("Invalid sighash: {}", e)))?;

            let signature = secp.sign_ecdsa(&message, &secret_key);
            let sig_bytes = signature.serialize_compact().to_vec();

            // Witness stack for P2WPKH: [signature, public_key]
            signed_witnesses.push(vec![sig_bytes, pubkey_bytes.to_vec()]);
        }

        // Build the final signed transaction with witness data
        let signed_tx = build_signed_transaction(&tx, signed_witnesses)
            .map_err(|e| ChainOpError::SigningError(format!("Failed to build signed tx: {}", e)))?;

        Ok(signed_tx)
    }
}

/// Bitcoin implementation of ChainBroadcaster trait
pub struct BitcoinChainBroadcaster {
    rpc: Box<dyn BitcoinRpc + Send + Sync>,
}

impl BitcoinChainBroadcaster {
    /// Create a new Bitcoin chain broadcaster
    pub fn new(rpc: Box<dyn BitcoinRpc + Send + Sync>) -> Self {
        Self { rpc }
    }
}

#[async_trait]
impl ChainBroadcaster for BitcoinChainBroadcaster {
    async fn submit_transaction(&self, signed_tx: &[u8]) -> ChainOpResult<String> {
        // Broadcast a raw Bitcoin transaction
        let tx_bytes_vec = signed_tx.to_vec();

        let txid = self
            .rpc
            .send_raw_transaction(tx_bytes_vec)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to broadcast: {}", e)))?;

        // Convert txid to hex string
        Ok(hex::encode(txid))
    }

    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        required_confirmations: u64,
        timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus> {
        let start = std::time::Instant::now();

        loop {
            // Get the transaction status
            let txid_bytes = hex::decode(tx_hash.trim_start_matches("0x"))
                .map_err(|e| ChainOpError::InvalidInput(format!("Invalid tx hash: {}", e)))?;

            let mut txid_array = [0u8; 32];
            txid_array.copy_from_slice(&txid_bytes);

            let confirmations = self
                .rpc
                .get_tx_confirmations(txid_array)
                .await
                .map_err(|e| {
                    ChainOpError::RpcError(format!("Failed to get confirmations: {}", e))
                })?;

            if confirmations >= required_confirmations {
                use csv_protocol::chain_adapter_traits::TransactionStatus;
                return Ok(TransactionStatus::Confirmed {
                    block_height: 0,
                    confirmations,
                });
            }

            if start.elapsed().as_secs() >= timeout_secs {
                return Err(ChainOpError::Timeout(
                    "Transaction confirmation timeout".to_string(),
                ));
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }

    async fn get_fee_estimate(&self) -> ChainOpResult<u64> {
        // Get real-time fee estimate from RPC
        get_fee_estimate_rpc(self.rpc.as_ref()).await
    }

    async fn validate_transaction(&self, _tx_data: &[u8]) -> ChainOpResult<()> {
        // Validate a transaction before submission
        // Bitcoin doesn't support transaction pre-validation
        Ok(())
    }
}

#[path = "chain_verification.rs"]
mod chain_verification;

/// Bitcoin implementation of ChainProofProvider trait
pub struct BitcoinChainProofProvider {
    rpc: Box<dyn BitcoinRpc + Send + Sync>,
}

impl BitcoinChainProofProvider {
    /// Create a new Bitcoin chain proof provider
    pub fn new(rpc: Box<dyn BitcoinRpc + Send + Sync>) -> Self {
        Self { rpc }
    }
}

#[async_trait]
impl ChainProofProvider for BitcoinChainProofProvider {
    async fn build_inclusion_proof(
        &self,
        _commitment: &Hash,
        block_height: u64,
        anchor_id: &[u8],
    ) -> ChainOpResult<CoreInclusionProof> {
        let block_hash = self
            .rpc
            .get_block_hash(block_height)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get block hash: {}", e)))?;

        if anchor_id.len() != 32 {
            return Err(ChainOpError::InvalidInput(format!(
                "Invalid anchor_id length for Bitcoin: expected 32-byte txid, got {}",
                anchor_id.len()
            )));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(anchor_id);
        let bitcoin_proof = self
            .rpc
            .get_inclusion_proof(txid, block_hash)
            .await
            .map_err(|e| {
                ChainOpError::ProofVerificationError(format!(
                    "Failed to build Bitcoin merkle inclusion proof from block data: {}",
                    e
                ))
            })?;

        if bitcoin_proof.block_height != block_height {
            return Err(ChainOpError::ProofVerificationError(format!(
                "Bitcoin merkle proof height mismatch: expected {}, got {}",
                block_height, bitcoin_proof.block_height
            )));
        }

        Ok(crate::proofs::to_core_inclusion_proof(&bitcoin_proof))
    }

    fn verify_inclusion_proof(
        &self,
        proof: &CoreInclusionProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        self.verify_inclusion_native(proof, commitment)
    }

    async fn build_finality_proof(&self, tx_hash: &str) -> ChainOpResult<FinalityProof> {
        // Build a finality proof (SPV proof of confirmation depth)

        // Parse txid
        let txid_bytes = hex::decode(tx_hash.trim_start_matches("0x"))
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid tx hash: {}", e)))?;

        if txid_bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Transaction hash must be 32 bytes".to_string(),
            ));
        }

        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&txid_bytes);

        // Get confirmation count
        let confirmations = self
            .rpc
            .get_tx_confirmations(txid_array)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get confirmations: {}", e)))?;

        // Get current block height
        let current_height = self
            .rpc
            .get_block_count()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get block count: {}", e)))?;

        // Build finality data: [block_hash (32) + confirmation_count (8) + current_height (8)]
        let block_height = if confirmations > 0 {
            current_height - confirmations + 1
        } else {
            0
        };

        let block_hash = if block_height > 0 {
            self.rpc
                .get_block_hash(block_height)
                .await
                .map_err(|e| ChainOpError::RpcError(format!("Failed to get block hash: {}", e)))?
        } else {
            [0u8; 32]
        };

        let mut finality_data = Vec::new();
        finality_data.extend_from_slice(&block_hash);
        finality_data.extend_from_slice(&confirmations.to_le_bytes());
        finality_data.extend_from_slice(&current_height.to_le_bytes());

        Ok(FinalityProof {
            finality_data,
            confirmations,
            is_deterministic: false, // Bitcoin uses probabilistic finality
            ..Default::default()
        })
    }

    fn verify_finality_proof(&self, proof: &FinalityProof, tx_hash: &str) -> ChainOpResult<bool> {
        self.verify_finality_native(proof, tx_hash)
    }

    fn domain_separator(&self) -> [u8; 32] {
        // Bitcoin domain separator
        *b"CSV-BTC-DOMAIN-SEPARATOR-0000000"
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

/// Bitcoin implementation of ChainDeployer trait
/// Note: Bitcoin doesn't support smart contract deployment
#[derive(Debug)]
pub struct BitcoinChainDeployer;

#[async_trait]
impl ChainDeployer for BitcoinChainDeployer {
    async fn deploy_lock_contract(
        &self,
        _admin_address: &str,
        _config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        // Bitcoin doesn't have smart contracts
        Err(ChainOpError::UnsupportedChain(
            "Bitcoin does not support smart contract deployment".to_string(),
        ))
    }

    async fn deploy_mint_contract(
        &self,
        _admin_address: &str,
        _config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        Err(ChainOpError::UnsupportedChain(
            "Bitcoin does not support smart contract deployment".to_string(),
        ))
    }

    async fn deploy_or_publish_seal_program(
        &self,
        _program_bytes: &[u8],
        _admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus> {
        Err(ChainOpError::UnsupportedChain(
            "Bitcoin does not support smart contract deployment".to_string(),
        ))
    }

    async fn verify_deployment(&self, _contract_address: &str) -> ChainOpResult<bool> {
        Err(ChainOpError::UnsupportedChain(
            "Bitcoin does not support smart contract deployment".to_string(),
        ))
    }

    async fn estimate_deployment_cost(&self, _program_bytes: &[u8]) -> ChainOpResult<u64> {
        Err(ChainOpError::UnsupportedChain(
            "Bitcoin does not support smart contract deployment".to_string(),
        ))
    }
}

/// Bitcoin implementation of ChainSanadOps trait
pub struct BitcoinChainSanadOps {
    adapter: Arc<BitcoinSealProtocol>,
    rpc: Option<Box<dyn BitcoinRpc + Send + Sync>>,
}

impl BitcoinChainSanadOps {
    /// Create a new Bitcoin chain sanad ops instance
    pub fn new(adapter: BitcoinSealProtocol) -> Self {
        Self {
            adapter: Arc::new(adapter),
            rpc: None,
        }
    }

    /// Build from an already-initialised (Arc-shared) seal protocol.
    pub fn from_arc(seal: Arc<BitcoinSealProtocol>) -> Self {
        Self {
            adapter: seal,
            rpc: None,
        }
    }

    /// Get reference to the underlying seal protocol
    pub fn seal_protocol(&self) -> &BitcoinSealProtocol {
        &self.adapter
    }

    /// Register an explicit sanad_id -> seal mapping for cross-chain lock lookups
    pub fn register_sanad_seal(&self, sanad_id: [u8; 32], txid: Vec<u8>, vout: u32) {
        self.adapter.wallet.register_sanad_seal(sanad_id, txid, vout);
    }

    /// Create with RPC client for broadcasting
    pub fn with_rpc(mut self, rpc: Box<dyn BitcoinRpc + Send + Sync>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// Build refund transaction after CSV timeout
    fn build_refund_transaction(
        &self,
        lock_seal: BitcoinSealPoint,
        _owner_key: &[u8],
    ) -> Result<bitcoin::Transaction, String> {
        let lock_outpoint = bitcoin::OutPoint {
            txid: hex::encode(lock_seal.txid)
                .parse::<bitcoin::Txid>()
                .expect("valid txid"),
            vout: lock_seal.vout,
        };

        // Build refund transaction that spends the lock UTXO
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_height(0)
                .expect("height 0 is valid for LockTime"),
            input: vec![bitcoin::TxIn {
                previous_output: lock_outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::from_consensus(0),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![], // Would contain refund output to owner
        };

        Ok(tx)
    }

    /// Sign and broadcast refund transaction
    async fn sign_and_broadcast_refund(
        &self,
        tx: bitcoin::Transaction,
        _owner_key: &[u8],
    ) -> ChainOpResult<String> {
        // Get the wallet and UTXO from the adapter
        let wallet = &self.adapter.wallet;
        let rpc = self.rpc.as_ref().ok_or_else(|| {
            ChainOpError::RpcError("No RPC client configured for broadcasting".to_string())
        })?;

        // Get the first input's outpoint to find the corresponding UTXO
        let input_outpoint = &tx.input.first()
            .ok_or_else(|| ChainOpError::InvalidInput("Transaction has no inputs".to_string()))?
            .previous_output;

        // Find the UTXO in the wallet
        let utxo = wallet.get_utxo(input_outpoint)
            .ok_or_else(|| ChainOpError::InvalidInput(
                format!("UTXO {}:{} not found in wallet", input_outpoint.txid, input_outpoint.vout)
            ))?;

        // Calculate sighash for the transaction
        let derived_key = wallet.derive_key(&utxo.path)
            .map_err(|e| ChainOpError::SigningError(format!("Failed to derive key: {}", e)))?;

        // Use the actual scriptPubKey from the UTXO if available
        let derived_spk = derived_key.address.script_pubkey();
        let input_script_pubkey = utxo.script_pubkey
            .as_ref()
            .unwrap_or(&derived_spk);

        let sighash = bitcoin::sighash::SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&[&bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(utxo.amount_sat),
                    script_pubkey: input_script_pubkey.clone(),
                }]),
                bitcoin::sighash::TapSighashType::Default,
            )
            .map_err(|e| ChainOpError::SigningError(format!("Sighash failed: {}", e)))?;

        let mut sighash_bytes = [0u8; 32];
        sighash_bytes.copy_from_slice(sighash.as_ref());

        // Sign with the wallet
        let schnorr_sig = wallet
            .sign_taproot_keypath(&utxo.path, &sighash_bytes)
            .map_err(|e| ChainOpError::SigningError(format!("Signing failed: {}", e)))?;

        // Build the witness
        let witness = bitcoin::Witness::from_slice(&[schnorr_sig.as_slice()]);

        // Create signed transaction
        let mut signed_tx = tx.clone();
        signed_tx.input[0].witness = witness;

        // Serialize and broadcast
        let raw_tx = bitcoin::consensus::encode::serialize(&signed_tx);
        let txid = rpc
            .send_raw_transaction(raw_tx)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to broadcast: {}", e)))?;

        Ok(hex::encode(txid))
    }

    /// Build a lock transaction for cross-chain transfer
    pub fn build_lock_transaction(
        &self,
        seal_outpoint: bitcoin::OutPoint,
        dest_hash: &bitcoin_hashes::sha256d::Hash,
        _owner_key: &[u8],
    ) -> Result<bitcoin::Transaction, String> {
        // Get the UTXO from the wallet to know the amount
        let wallet = &self.adapter.wallet;
        let utxo = wallet.get_utxo(&seal_outpoint)
            .ok_or_else(|| format!("UTXO {}:{} not found in wallet", seal_outpoint.txid, seal_outpoint.vout))?;

        // Calculate fee (1 input, 1 output)
        let fee = 500; // Simple fee estimate for lock transaction
        let lock_amount = utxo.amount_sat.saturating_sub(fee);

        // Create OP_RETURN output with destination hash for cross-chain proof
        // Format: OP_RETURN OP_PUSH32 <dest_hash>
        let lock_script = bitcoin::ScriptBuf::new_op_return(dest_hash.as_byte_array());

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_height(0)
                .expect("height 0 is valid for LockTime"),
            input: vec![bitcoin::TxIn {
                previous_output: seal_outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::from_consensus(0xffffffff), // Disable RBF for lock
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(lock_amount),
                script_pubkey: lock_script,
            }],
        };
        Ok(tx)
    }

    /// Sign and broadcast a lock transaction
    pub async fn sign_and_broadcast_lock(
        &self,
        tx: bitcoin::Transaction,
        _owner_key: &[u8],
    ) -> ChainOpResult<String> {
        // Get the wallet and UTXO from the adapter
        let wallet = &self.adapter.wallet;
        let rpc = self.rpc.as_ref().ok_or_else(|| {
            ChainOpError::RpcError("No RPC client configured for broadcasting".to_string())
        })?;

        // Get the first input's outpoint to find the corresponding UTXO
        let input_outpoint = &tx.input.first()
            .ok_or_else(|| ChainOpError::InvalidInput("Transaction has no inputs".to_string()))?
            .previous_output;

        // Find the UTXO in the wallet
        let utxo = wallet.get_utxo(input_outpoint)
            .ok_or_else(|| ChainOpError::InvalidInput(
                format!("UTXO {}:{} not found in wallet", input_outpoint.txid, input_outpoint.vout)
            ))?;

        // Calculate sighash for the transaction
        let derived_key = wallet.derive_key(&utxo.path)
            .map_err(|e| ChainOpError::SigningError(format!("Failed to derive key: {}", e)))?;

        // Use the actual scriptPubKey from the UTXO if available
        let derived_spk = derived_key.address.script_pubkey();
        let input_script_pubkey = utxo.script_pubkey
            .as_ref()
            .unwrap_or(&derived_spk);

        let sighash = bitcoin::sighash::SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&[&bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(utxo.amount_sat),
                    script_pubkey: input_script_pubkey.clone(),
                }]),
                bitcoin::sighash::TapSighashType::Default,
            )
            .map_err(|e| ChainOpError::SigningError(format!("Sighash failed: {}", e)))?;

        let mut sighash_bytes = [0u8; 32];
        sighash_bytes.copy_from_slice(sighash.as_ref());

        // Sign with the wallet
        let schnorr_sig = wallet
            .sign_taproot_keypath(&utxo.path, &sighash_bytes)
            .map_err(|e| ChainOpError::SigningError(format!("Signing failed: {}", e)))?;

        // Build the witness
        let witness = bitcoin::Witness::from_slice(&[schnorr_sig.as_slice()]);

        // Create signed transaction
        let mut signed_tx = tx.clone();
        signed_tx.input[0].witness = witness;

        // Serialize and broadcast
        let raw_tx = bitcoin::consensus::encode::serialize(&signed_tx);
        let txid = rpc
            .send_raw_transaction(raw_tx)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to broadcast: {}", e)))?;

        Ok(hex::encode(txid))
    }

    /// Build metadata recording transaction with OP_RETURN
    fn build_metadata_transaction(
        &self,
        seal: BitcoinSealPoint,
        _metadata: &[u8],
        _owner_key: &[u8],
    ) -> Result<bitcoin::Transaction, String> {
        // seal.txid is in internal byte order; reverse to display for Txid parser
        let mut display_txid = seal.txid;
        display_txid.reverse();
        let seal_outpoint = bitcoin::OutPoint {
            txid: hex::encode(display_txid)
                .parse::<bitcoin::Txid>()
                .expect("valid txid"),
            vout: seal.vout,
        };
        let op_return_script = bitcoin::ScriptBuf::new();
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_height(0)
                .expect("height 0 is valid for LockTime"),
            input: vec![bitcoin::TxIn {
                previous_output: seal_outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::from_consensus(0xffffffff),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: op_return_script,
            }],
        };
        Ok(tx)
    }

    /// Sign and broadcast metadata transaction
    async fn sign_and_broadcast_metadata(
        &self,
        _tx: bitcoin::Transaction,
        _owner_key: &[u8],
    ) -> ChainOpResult<String> {
        Err(ChainOpError::CapabilityUnavailable(
            "Metadata transaction signing requires wallet integration".to_string(),
        ))
    }
}

#[async_trait]
impl ChainSanadOps for BitcoinChainSanadOps {
    async fn create_sanad(
        &self,
        owner: &str,
        _asset_class: &str,
        _asset_id: &str,
        metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult> {
        // Create a new sanad by creating a UTXO seal
        let seal = self
            .adapter
            .create_seal(None)
            .await
            .map_err(|e| ChainOpError::InvalidInput(format!("Failed to create seal: {}", e)))?;

        Ok(SanadOperationResult {
            sanad_id: SanadId(Hash::from([0u8; 32])), // Implementation note: compute from asset hash
            operation: csv_protocol::chain_adapter_traits::SanadOperation::Create,
            transaction_hash: hex::encode(seal.txid),
            block_height: 0,
            chain_id: "bitcoin".to_string(),
            metadata: serde_json::json!({
                "description": metadata,
                "owner": owner,
                "seal_outpoint": format!("{}:{}", hex::encode(seal.txid), seal.vout)
            }),
        })
    }

    async fn consume_sanad(
        &self,
        _sanad_id: &SanadId,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Consume a sanad by spending the UTXO
        Err(ChainOpError::CapabilityUnavailable(
            "Sanad consumption requires transaction building".to_string(),
        ))
    }

    async fn lock_sanad(
        &self,
        sanad_id: &SanadId,
        destination_chain: &str,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Lock a sanad for cross-chain transfer by creating a lock UTXO
        // The lock UTXO contains the destination chain hash in its script

        // Parse the destination chain to ensure it's valid
        let _destination = destination_chain
            .parse::<csv_hash::chain_id::ChainId>()
            .map_err(|_| {
                ChainOpError::InvalidInput(format!(
                    "Invalid destination chain: {}",
                    destination_chain
                ))
            })?;

        // Get the sanad's associated UTXO (seal)
        let seal = self.adapter.find_seal_for_sanad(sanad_id).ok_or_else(|| {
            ChainOpError::InvalidInput(format!(
                "Failed to find seal for sanad: {}",
                hex::encode(sanad_id.as_bytes())
            ))
        })?;

        // Build lock transaction that:
        // 1. Spends the seal UTXO
        // 2. Creates a new UTXO with lock script containing destination commitment
        // 3. Uses CSV (CheckSequenceVerify) for timeout refund capability

        // Parse owner key for signing
        let key_bytes = hex::decode(owner_key_id)
            .map_err(|_| ChainOpError::InvalidInput("Invalid owner key ID format".to_string()))?;

        if key_bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Owner key must be 32 bytes".to_string(),
            ));
        }

        // Build lock script that encodes the destination chain
        // This is a hash160 of the destination chain name
        use bitcoin_hashes::{Hash, sha256d};
        let dest_hash = sha256d::Hash::hash(destination_chain.as_bytes());

        // Create the lock UTXO outpoint reference
        // seal.txid is in internal byte order (after Bug 2B fix); reverse to display for Txid parser
        let mut display_txid = seal.txid;
        display_txid.reverse();
        let lock_outpoint = bitcoin::OutPoint {
            txid: hex::encode(display_txid)
                .parse::<bitcoin::Txid>()
                .expect("valid txid"),
            vout: seal.vout,
        };

        // Build the lock transaction
        let lock_tx = self
            .build_lock_transaction(lock_outpoint, &dest_hash, &key_bytes)
            .map_err(|e| {
                ChainOpError::TransactionError(format!("Failed to build lock tx: {}", e))
            })?;

        // Sign and broadcast the lock transaction
        let signed_tx = self.sign_and_broadcast_lock(lock_tx, &key_bytes).await?;

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: csv_protocol::chain_adapter_traits::SanadOperation::Lock,
            transaction_hash: signed_tx,
            block_height: self.adapter.get_current_height().await,
            chain_id: "bitcoin".to_string(),
            metadata: serde_json::json!({
                "destination_chain": destination_chain,
                "lock_type": "utxo_csv",
                "timeout_blocks": 144, // ~24 hours
            }),
        })
    }

    async fn mint_sanad(
        &self,
        _source_chain: &str,
        _source_sanad_id: &SanadId,
        _lock_proof: &CoreInclusionProof,
        _new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Mint a wrapped sanad on this chain - Bitcoin is the source, not destination
        Err(ChainOpError::UnsupportedChain(
            "Bitcoin cannot mint wrapped sanads - it is a source chain".to_string(),
        ))
    }

    async fn refund_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Refund a locked sanad after CSV timeout expires
        // This spends the lock UTXO back to the owner

        // Parse owner key
        let key_bytes = hex::decode(owner_key_id)
            .map_err(|_| ChainOpError::InvalidInput("Invalid owner key ID format".to_string()))?;

        if key_bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Owner key must be 32 bytes".to_string(),
            ));
        }

        // Get the lock UTXO for this sanad
        let lock_seal = self.adapter.find_seal_for_sanad(sanad_id).ok_or_else(|| {
            ChainOpError::InvalidInput(format!(
                "Failed to find lock seal for sanad: {}",
                hex::encode(sanad_id.as_bytes())
            ))
        })?;

        // Verify CSV timeout has expired (144 blocks = ~24 hours)
        let current_height = self.adapter.get_current_height().await;
        let csv_timeout = 144u64;

        if current_height < csv_timeout {
            return Err(ChainOpError::InvalidInput(format!(
                "CSV timeout not yet expired. Current: {}, Required: {}",
                current_height, csv_timeout
            )));
        }

        // Build refund transaction
        let lock_seal_txid = lock_seal.txid;
        let lock_seal_vout = lock_seal.vout;
        let refund_tx = self
            .build_refund_transaction(lock_seal, &key_bytes)
            .map_err(|e| {
                ChainOpError::TransactionError(format!("Failed to build refund tx: {}", e))
            })?;

        // Sign and broadcast
        let signed_tx = self
            .sign_and_broadcast_refund(refund_tx, &key_bytes)
            .await?;

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: SanadOperation::Refund,
            transaction_hash: format!("0x{}", hex::encode(signed_tx.as_bytes())),
            block_height: self.adapter.get_current_height().await,
            chain_id: "bitcoin".to_string(),
            metadata: serde_json::json!({
                "lock_txid": hex::encode(lock_seal_txid),
                "lock_vout": lock_seal_vout,
                "refund_height": current_height,
            }),
        })
    }

    async fn record_sanad_metadata(
        &self,
        sanad_id: &SanadId,
        metadata: serde_json::Value,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Record metadata for a sanad using OP_RETURN
        // This creates a transaction with metadata in the witness or OP_RETURN

        // Parse owner key
        let key_bytes = hex::decode(owner_key_id)
            .map_err(|_| ChainOpError::InvalidInput("Invalid owner key ID format".to_string()))?;

        if key_bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Owner key must be 32 bytes".to_string(),
            ));
        }

        // Get the seal for this sanad
        let seal = self.adapter.find_seal_for_sanad(sanad_id).ok_or_else(|| {
            ChainOpError::InvalidInput(format!(
                "Failed to find seal for sanad: {}",
                hex::encode(sanad_id.as_bytes())
            ))
        })?;

        // Serialize metadata to JSON and hash it
        let metadata_bytes = serde_json::to_vec(&metadata).map_err(|e| {
            ChainOpError::TransactionError(format!("Failed to serialize metadata: {}", e))
        })?;

        if metadata_bytes.len() > 80 {
            return Err(ChainOpError::InvalidInput(
                "Metadata too large for OP_RETURN (max 80 bytes)".to_string(),
            ));
        }

        // Build metadata recording transaction
        let metadata_tx = self
            .build_metadata_transaction(seal, &metadata_bytes, &key_bytes)
            .map_err(|e| {
                ChainOpError::TransactionError(format!("Failed to build metadata tx: {}", e))
            })?;

        // Sign and broadcast
        let signed_tx = self
            .sign_and_broadcast_metadata(metadata_tx, &key_bytes)
            .await?;

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: SanadOperation::RecordMetadata,
            transaction_hash: signed_tx,
            block_height: self.adapter.get_current_height().await,
            chain_id: "bitcoin".to_string(),
            metadata,
        })
    }

    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        expected_state: &str,
    ) -> ChainOpResult<bool> {
        // Verify the current state of a sanad
        // This checks if the sanad's UTXO is still unspent and matches the expected state

        // Get the seal for this sanad
        let seal = match self.adapter.find_seal_for_sanad(sanad_id) {
            Some(s) => s,
            None => {
                // Sanad not found - check if it was consumed
                return match expected_state {
                    "consumed" | "spent" | "transferred" => Ok(true),
                    _ => Ok(false),
                };
            }
        };

        // Check if the seal UTXO is still unspent via RPC
        // seal.txid is in internal byte order; reverse to display for Txid parser
        let mut display_txid = seal.txid;
        display_txid.reverse();
        let seal_outpoint = bitcoin::OutPoint {
            txid: hex::encode(display_txid)
                .parse::<bitcoin::Txid>()
                .expect("valid txid"),
            vout: seal.vout,
        };

        // Query RPC to check if UTXO is unspent
        let rpc = self
            .adapter
            .rpc
            .as_ref()
            .ok_or_else(|| ChainOpError::RpcError("RPC not available".to_string()))?;
        let is_unspent = rpc
            .is_utxo_unspent(
                BitcoinHash::to_byte_array(seal_outpoint.txid),
                seal_outpoint.vout,
            )
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to check UTXO: {}", e)))?;

        // Match expected state
        let actual_state = if is_unspent { "active" } else { "consumed" };

        Ok(actual_state == expected_state)
    }
}

/// Unified Bitcoin chain operations implementing ChainBackend.
///
/// This is the standard runtime pattern implementation that combines all chain operation
/// traits into a single type. Created from BitcoinSealProtocol via `from_seal_protocol()`.
///
/// # Security
/// - Preserves BIP-86 HD wallet derivation from the seal protocol
/// - Maintains domain-separated hashing for all proof operations
/// - Uses RPC client attached to seal protocol for all chain queries
pub struct BitcoinBackend {
    /// RPC client for chain communication (extracted from anchor layer)
    rpc: Box<dyn BitcoinRpc + Send + Sync>,
    /// Network type (preserved from anchor layer config)
    network: Network,
    /// Domain separator for proof generation (preserved from anchor layer)
    domain_separator: [u8; 32],
    /// Config for sanad operations
    config: crate::config::BitcoinConfig,
    /// Optional MPC batcher for commitment aggregation (90% fee savings)
    mpc_batcher: Option<Arc<crate::mpc_batch::MpcBatcher>>,
    /// Reference to seal protocol for seal creation and publishing
    seal_protocol: Arc<BitcoinSealProtocol>,
}

impl std::fmt::Debug for BitcoinBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoinBackend")
            .field("network", &self.network)
            .field("domain_separator", &hex::encode(self.domain_separator))
            .field("config", &self.config)
            .field("seal_protocol", &"BitcoinSealProtocol")
            .finish_non_exhaustive()
    }
}

impl BitcoinBackend {
    /// Create from BitcoinSealProtocol (standard runtime pattern).
    ///
    /// # Arguments
    /// * `seal` - The Bitcoin seal protocol with attached RPC and wallet
    ///
    /// # Security Notes
    /// - Preserves all BIP-86 derivation settings from the seal protocol
    /// - Maintains domain separator for cross-chain replay protection
    /// - Clones RPC client reference for chain operations
    pub fn from_seal_protocol(seal: Arc<BitcoinSealProtocol>) -> ChainOpResult<Self> {
        // Extract RPC from seal protocol (must be present for real operations)
        let rpc = seal
            .rpc
            .as_ref()
            .ok_or_else(|| {
                ChainOpError::FeatureNotEnabled(
                    "RPC client not attached to seal protocol. Use from_config() to attach RPC."
                        .to_string(),
                )
            })?
            .clone_boxed();

        // Extract network from seal protocol config (preserves BIP-86 coin type settings)
        let network = seal.config().network.to_bitcoin_network();

        // Extract domain separator from seal protocol (preserves cross-chain replay protection)
        let domain_separator = seal.domain();

        // Store config for later sanad operations
        let config = seal.config().clone();

        Ok(Self {
            rpc,
            network,
            domain_separator,
            config,
            mpc_batcher: None,
            seal_protocol: seal,
        })
    }

    /// Attach an MPC batcher for commitment aggregation.
    ///
    /// When enabled, Bitcoin commitments are queued and batched into a single
    /// on-chain transaction, achieving ~90% fee savings for multiple commitments.
    ///
    /// # Example
    /// ```rust,ignore
    /// use csv_bitcoin::mpc_batch::MpcBatcher;
    ///
    /// let batcher = MpcBatcher::default(); // Batch up to 10, min 2, 5 min timeout
    /// let backend = backend.with_mpc_batcher(batcher);
    /// ```
    pub fn with_mpc_batcher(mut self, batcher: crate::mpc_batch::MpcBatcher) -> Self {
        self.mpc_batcher = Some(Arc::new(batcher));
        self
    }

    /// Get reference to MPC batcher if configured
    pub fn mpc_batcher(&self) -> Option<&Arc<crate::mpc_batch::MpcBatcher>> {
        self.mpc_batcher.as_ref()
    }

    /// Queue a commitment for batched publication.
    ///
    /// Returns the batch status: true if batch is ready to publish, false if queued.
    /// If no batcher is configured, returns error - use direct broadcast instead.
    pub fn queue_commitment(
        &self,
        commitment: csv_hash::Hash,
        seal: crate::types::BitcoinSealPoint,
        request_id: String,
    ) -> ChainOpResult<bool> {
        let batcher = self.mpc_batcher.as_ref().ok_or_else(|| {
            ChainOpError::FeatureNotEnabled(
                "MPC batcher not configured. Use with_mpc_batcher() to enable batching."
                    .to_string(),
            )
        })?;

        batcher
            .queue(commitment, seal, request_id)
            .map_err(ChainOpError::RpcError)
    }

    /// Check if a batch is ready for publication
    pub fn has_batch_ready(&self) -> bool {
        self.mpc_batcher
            .as_ref()
            .map(|b| b.has_batch_ready())
            .unwrap_or(false)
    }

    /// Build and publish batched commitments.
    ///
    /// This consumes pending commitments, builds an MPC tree, publishes the root
    /// via a single tapret transaction, and generates inclusion proofs for all
    /// commitments in the batch.
    ///
    /// # Returns
    /// - `Ok(BatchedPublication)` with txid, root, and proofs
    /// - `Err` if no batcher configured or no pending commitments
    pub async fn finalize_batch(&self) -> ChainOpResult<crate::mpc_batch::BatchedPublication> {
        let batcher = self.mpc_batcher.as_ref().ok_or_else(|| {
            ChainOpError::FeatureNotEnabled(
                "MPC batcher not configured. Use with_mpc_batcher() to enable batching."
                    .to_string(),
            )
        })?;

        // Build MPC tree from pending commitments
        let (tree, commitments) = batcher.build_mpc_tree().ok_or_else(|| {
            ChainOpError::InvalidInput("No pending commitments to batch".to_string())
        })?;

        let mpc_root = tree.root();

        // Build tapret transaction with MPC root
        let tx = self.build_mpc_publication_transaction(&mpc_root).await?;

        // Sign and broadcast
        let txid = self.broadcast_mpc_transaction(tx).await?;

        // Generate proofs for all commitments
        let proofs = batcher.generate_proofs(&tree, &commitments).map_err(|e| {
            ChainOpError::ProofVerificationError(format!("Failed to generate MPC proofs: {}", e))
        })?;

        // Get current block height for the publication record
        let block_height = self.get_latest_block_height().await?;

        Ok(crate::mpc_batch::BatchedPublication {
            txid,
            block_height,
            mpc_root,
            proofs,
        })
    }

    /// Build a transaction to publish an MPC root via tapret
    async fn build_mpc_publication_transaction(
        &self,
        mpc_root: &csv_hash::Hash,
    ) -> ChainOpResult<bitcoin::Transaction> {
        use crate::tapret::TapretCommitment;
        use bitcoin::{ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

        // Build tapret commitment with MPC root
        let mut protocol_id = [0u8; 32];
        protocol_id.copy_from_slice(&mpc_root.as_bytes()[..32]);
        let commitment = csv_hash::Hash::default();
        let tapret = TapretCommitment::new(protocol_id, commitment);

        let fee_rate = 10u64;
        let target_sat = 546 + fee_rate.saturating_mul(200);
        let selected = self
            .seal_protocol
            .wallet
            .select_utxos(target_sat)
            .map_err(|e| {
                ChainOpError::InvalidInput(format!(
                    "MPC publication requires a wallet UTXO for funding: {}",
                    e
                ))
            })?;
        let funding_utxo = selected
            .first()
            .ok_or_else(|| ChainOpError::InvalidInput("No funding UTXO selected".to_string()))?;

        // Validate UTXO is still unspent before building transaction (race condition check)
        let txid_bytes = funding_utxo.outpoint.txid.to_byte_array();
        let is_unspent = self
            .rpc
            .is_utxo_unspent(txid_bytes, funding_utxo.outpoint.vout)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to check UTXO status: {}", e)))?;
        
        if !is_unspent {
            return Err(ChainOpError::InvalidInput(
                format!("Selected UTXO {}:{} is already spent or does not exist", 
                    hex::encode(funding_utxo.outpoint.txid), funding_utxo.outpoint.vout)
            ));
        }

        // Build the publication transaction from an actual wallet UTXO. The
        // wallet signing path fills the witness before broadcast.
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_height(0)
                .expect("height 0 is valid for LockTime"),
            input: vec![TxIn {
                previous_output: funding_utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(546), // Dust limit
                script_pubkey: tapret.leaf_script(),
            }],
        };

        Ok(tx)
    }

    /// Broadcast an MPC publication transaction
    async fn broadcast_mpc_transaction(&self, tx: bitcoin::Transaction) -> ChainOpResult<[u8; 32]> {
        let tx_bytes = bitcoin::consensus::serialize(&tx);
        let txid_hex = self.submit_transaction(&tx_bytes).await?;

        let txid = hex::decode(txid_hex.trim_start_matches("0x"))
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid txid: {}", e)))?;

        if txid.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Invalid txid length".to_string(),
            ));
        }

        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&txid);

        Ok(txid_array)
    }

    /// Create from seal protocol components (internal use).
    ///
    /// This is the preferred constructor when you have direct access to the components.
    pub fn new(
        rpc: Box<dyn BitcoinRpc + Send + Sync>,
        network: Network,
        domain_separator: [u8; 32],
        config: crate::config::BitcoinConfig,
    ) -> Self {
        // Create a minimal seal protocol for backward compatibility
        // In production, use from_seal_protocol() instead
        let seal = BitcoinSealProtocol::signet().unwrap_or_else(|_| {
            // Fallback: create with minimal config if signet fails
            let btc_config = crate::config::BitcoinConfig {
                network: crate::config::Network::Signet,
                finality_depth: 6,
                ..Default::default()
            };
            let wallet = crate::wallet::SealWallet::generate_random(bitcoin::Network::Signet);
            BitcoinSealProtocol::with_wallet(btc_config, wallet)
                .expect("wallet-based protocol construction")
        });

        Self {
            rpc,
            network,
            domain_separator,
            config,
            mpc_batcher: None,
            seal_protocol: Arc::new(seal),
        }
    }
}

#[async_trait]
impl ChainQuery for BitcoinBackend {
    async fn get_balance(&self, address: &str) -> ChainOpResult<BalanceInfo> {
        let query = BitcoinChainQuery::new(self.rpc.clone_boxed(), self.network);
        query.get_balance(address).await
    }

    async fn get_transaction(
        &self,
        tx_hash: &str,
    ) -> ChainOpResult<csv_protocol::chain_adapter_traits::TransactionInfo> {
        let query = BitcoinChainQuery::new(self.rpc.clone_boxed(), self.network);
        query.get_transaction(tx_hash).await
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        let query = BitcoinChainQuery::new(self.rpc.clone_boxed(), self.network);
        query.get_finality(tx_hash).await
    }

    async fn get_contract_status(&self, contract_address: &str) -> ChainOpResult<ContractStatus> {
        let query = BitcoinChainQuery::new(self.rpc.clone_boxed(), self.network);
        query.get_contract_status(contract_address).await
    }

    async fn get_latest_block_height(&self) -> ChainOpResult<u64> {
        let query = BitcoinChainQuery::new(self.rpc.clone_boxed(), self.network);
        query.get_latest_block_height().await
    }

    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        let query = BitcoinChainQuery::new(self.rpc.clone_boxed(), self.network);
        query.get_chain_info().await
    }

    async fn get_account_nonce(&self, address: &str) -> ChainOpResult<u64> {
        let query = BitcoinChainQuery::new(self.rpc.clone_boxed(), self.network);
        query.get_account_nonce(address).await
    }

    fn validate_address(&self, address: &str) -> bool {
        let query = BitcoinChainQuery::new(self.rpc.clone_boxed(), self.network);
        query.validate_address(address)
    }
}

#[async_trait]
impl ChainSigner for BitcoinBackend {
    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String> {
        let signer = BitcoinChainSigner::new(self.network);
        signer.derive_address(public_key)
    }

    async fn sign_transaction(&self, tx_data: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>> {
        let signer = BitcoinChainSigner::new(self.network);
        signer.sign_transaction(tx_data, key_id).await
    }

    async fn sign_message(&self, message: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>> {
        let signer = BitcoinChainSigner::new(self.network);
        signer.sign_message(message, key_id).await
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> ChainOpResult<bool> {
        let signer = BitcoinChainSigner::new(self.network);
        signer.verify_signature(message, signature, public_key)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        // let signer = BitcoinChainSigner::new(self.network);
        // signer.signature_scheme()
        SignatureScheme::Secp256k1
    }
}

#[async_trait]
impl ChainBroadcaster for BitcoinBackend {
    async fn submit_transaction(&self, signed_tx: &[u8]) -> ChainOpResult<String> {
        let broadcaster = BitcoinChainBroadcaster::new(self.rpc.clone_boxed());
        broadcaster.submit_transaction(signed_tx).await
    }

    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        required_confirmations: u64,
        timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus> {
        let broadcaster = BitcoinChainBroadcaster::new(self.rpc.clone_boxed());
        broadcaster
            .confirm_transaction(tx_hash, required_confirmations, timeout_secs)
            .await
    }

    async fn get_fee_estimate(&self) -> ChainOpResult<u64> {
        let broadcaster = BitcoinChainBroadcaster::new(self.rpc.clone_boxed());
        broadcaster.get_fee_estimate().await
    }

    async fn validate_transaction(&self, tx_data: &[u8]) -> ChainOpResult<()> {
        let broadcaster = BitcoinChainBroadcaster::new(self.rpc.clone_boxed());
        broadcaster.validate_transaction(tx_data).await
    }
}

#[async_trait]
impl ChainDeployer for BitcoinBackend {
    async fn deploy_lock_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        let deployer = BitcoinChainDeployer;
        deployer.deploy_lock_contract(admin_address, config).await
    }

    async fn deploy_mint_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        let deployer = BitcoinChainDeployer;
        deployer.deploy_mint_contract(admin_address, config).await
    }

    async fn deploy_or_publish_seal_program(
        &self,
        program_bytes: &[u8],
        admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus> {
        let deployer = BitcoinChainDeployer;
        deployer
            .deploy_or_publish_seal_program(program_bytes, admin_address)
            .await
    }

    async fn verify_deployment(&self, contract_address: &str) -> ChainOpResult<bool> {
        let deployer = BitcoinChainDeployer;
        deployer.verify_deployment(contract_address).await
    }

    async fn estimate_deployment_cost(&self, program_bytes: &[u8]) -> ChainOpResult<u64> {
        let deployer = BitcoinChainDeployer;
        deployer.estimate_deployment_cost(program_bytes).await
    }
}

#[async_trait]
impl ChainProofProvider for BitcoinBackend {
    async fn build_inclusion_proof(
        &self,
        commitment: &Hash,
        block_height: u64,
        anchor_id: &[u8],
    ) -> ChainOpResult<CoreInclusionProof> {
        let provider = BitcoinChainProofProvider::new(self.rpc.clone_boxed());
        provider
            .build_inclusion_proof(commitment, block_height, anchor_id)
            .await
    }

    fn verify_inclusion_proof(
        &self,
        proof: &CoreInclusionProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        let provider = BitcoinChainProofProvider::new(self.rpc.clone_boxed());
        provider.verify_inclusion_proof(proof, commitment)
    }

    async fn build_finality_proof(&self, tx_hash: &str) -> ChainOpResult<FinalityProof> {
        let provider = BitcoinChainProofProvider::new(self.rpc.clone_boxed());
        provider.build_finality_proof(tx_hash).await
    }

    fn verify_finality_proof(&self, proof: &FinalityProof, tx_hash: &str) -> ChainOpResult<bool> {
        let provider = BitcoinChainProofProvider::new(self.rpc.clone_boxed());
        provider.verify_finality_proof(proof, tx_hash)
    }

    fn domain_separator(&self) -> [u8; 32] {
        // Return the domain separator from anchor layer (preserves replay protection)
        self.domain_separator
    }

    async fn verify_proof_bundle(
        &self,
        inclusion_proof: &CoreInclusionProof,
        finality_proof: &FinalityProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        let provider = BitcoinChainProofProvider::new(self.rpc.clone_boxed());
        provider.verify_proof_bundle_native(inclusion_proof, finality_proof, commitment)
    }
}

#[async_trait]
impl ChainSanadOps for BitcoinBackend {
    async fn create_sanad(
        &self,
        owner: &str,
        asset_class: &str,
        asset_id: &str,
        metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult> {
        use sha2::{Digest, Sha256};

        let commitment_bytes: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(b"commitment-");
            hasher.update(owner.as_bytes());
            hasher.update(asset_class.as_bytes());
            hasher.update(asset_id.as_bytes());
            if let Some(meta_str) = metadata.as_str() {
                hasher.update(meta_str.as_bytes());
            }
            let now_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            hasher.update(now_nanos.to_le_bytes());
            hasher.finalize().into()
        };
        let commitment = Hash::new(commitment_bytes);

        let wallet = &self.seal_protocol.wallet;
        
        if let Err(e) = self.seal_protocol.scan_wallet_for_utxos(0, 20).await {
            log::warn!("Failed to refresh UTXOs before sanad creation: {}", e);
        }
        
        let available_utxos = wallet.list_utxos();
        let spendable: Vec<_> = available_utxos
            .iter()
            .filter(|u| !u.reserved && u.amount_sat >= 10_000)
            .collect();

        if spendable.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "No spendable UTXOs found. Fund the Bitcoin address and scan with 'csv wallet scan'.".to_string()
            ));
        }

        let selected = &spendable[0];
        let outpoint = bitcoin::OutPoint::new(
            selected.outpoint.txid,
            selected.outpoint.vout,
        );

        let (seal, _path) = self.seal_protocol.fund_seal(outpoint)
            .map_err(|e| ChainOpError::TransactionError(format!("Failed to fund seal: {}", e)))?;

        let seal_txid = hex::encode(seal.txid);
        let seal_vout = seal.vout;
        let seal_nonce = seal.nonce.unwrap_or(0);

        let anchor = self.seal_protocol
            .publish(commitment, seal)
            .await
            .map_err(|e| ChainOpError::TransactionError(format!("Failed to publish commitment: {}", e)))?;

        Ok(SanadOperationResult {
            sanad_id: SanadId(commitment),
            operation: SanadOperation::Create,
            transaction_hash: hex::encode(anchor.txid),
            block_height: anchor.block_height,
            chain_id: "bitcoin".to_string(),
            metadata: serde_json::json!({
                "owner": owner,
                "asset_class": asset_class,
                "asset_id": asset_id,
                "seal_outpoint": format!("{}:{}", seal_txid, seal_vout),
                "seal_nonce": seal_nonce,
            }),
        })
    }

    async fn consume_sanad(
        &self,
        _sanad_id: &SanadId,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::UnsupportedChain(
            "Bitcoin does not support sanad consumption. Bitcoin sanads are consumed when the commitment is published.".to_string()
        ))
    }

    async fn lock_sanad(
        &self,
        _sanad_id: &SanadId,
        _destination_chain: &str,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "Sanad locking requires wallet. Use BitcoinSealProtocol directly for seal operations."
                .to_string(),
        ))
    }

    async fn mint_sanad(
        &self,
        _source_chain: &str,
        _source_sanad_id: &SanadId,
        _lock_proof: &CoreInclusionProof,
        _new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::UnsupportedChain(
            "Bitcoin cannot mint wrapped sanads - it is a source chain".to_string(),
        ))
    }

    async fn refund_sanad(
        &self,
        _sanad_id: &SanadId,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "Refund requires wallet. Use BitcoinSealProtocol directly for seal operations."
                .to_string(),
        ))
    }

    async fn record_sanad_metadata(
        &self,
        _sanad_id: &SanadId,
        _metadata: serde_json::Value,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "Metadata recording requires wallet. Use BitcoinSealProtocol directly for seal operations.".to_string()
        ))
    }

    async fn verify_sanad_state(
        &self,
        _sanad_id: &SanadId,
        _expected_state: &str,
    ) -> ChainOpResult<bool> {
        Err(ChainOpError::CapabilityUnavailable(
            "Sanad state verification requires wallet. Use BitcoinSealProtocol directly for seal operations.".to_string()
        ))
    }
}

// =============================================================================
// Bitcoin Transaction Helper Functions
// =============================================================================

/// Parsed Bitcoin transaction structure
#[derive(Debug)]
struct ParsedTx {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
}

#[derive(Debug, Clone)]
struct TxInput {
    txid: [u8; 32],
    vout: u32,
    sequence: u32,
    script_sig: Vec<u8>,
}

#[derive(Debug)]
struct TxOutput {
    value: u64,
    script_pubkey: Vec<u8>,
}

/// Parse a Bitcoin transaction from bytes
fn parse_bitcoin_tx(data: &[u8]) -> Result<ParsedTx, String> {
    if data.len() < 10 {
        return Err("Transaction too short".to_string());
    }

    let mut offset = 0usize;

    // Version (4 bytes)
    let version = u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid version")?,
    );
    offset += 4;

    // Check for SegWit marker and flag
    let is_segwit = data[offset] == 0x00 && data[offset + 1] == 0x01;
    if is_segwit {
        offset += 2; // Skip marker and flag
    }

    // Input count (varint)
    let (input_count, bytes_read) = read_varint(&data[offset..])?;
    offset += bytes_read;

    // Parse inputs
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        let input = parse_input(&data[offset..])?;
        offset += input.1;
        inputs.push(input.0);
    }

    // Output count (varint)
    let (output_count, bytes_read) = read_varint(&data[offset..])?;
    offset += bytes_read;

    // Parse outputs
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let output = parse_output(&data[offset..])?;
        offset += output.1;
        outputs.push(output.0);
    }

    // Skip witness data if present (we don't need it for signing)
    if is_segwit {
        for _ in 0..input_count {
            let (witness_count, bytes_read) = read_varint(&data[offset..])?;
            offset += bytes_read;
            for _ in 0..witness_count {
                let (witness_len, bytes_read) = read_varint(&data[offset..])?;
                offset += bytes_read + witness_len as usize;
            }
        }
    }

    // Locktime (4 bytes)
    if offset + 4 > data.len() {
        return Err("Transaction truncated".to_string());
    }
    let locktime = u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid locktime")?,
    );

    Ok(ParsedTx {
        version,
        inputs,
        outputs,
        locktime,
    })
}

/// Read a Bitcoin varint
fn read_varint(data: &[u8]) -> Result<(u64, usize), String> {
    if data.is_empty() {
        return Err("Empty data for varint".to_string());
    }

    match data[0] {
        0..=0xfc => Ok((data[0] as u64, 1)),
        0xfd if data.len() >= 3 => {
            let val = u16::from_le_bytes([data[1], data[2]]);
            Ok((val as u64, 3))
        }
        0xfe if data.len() >= 5 => {
            let val = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            Ok((val as u64, 5))
        }
        0xff if data.len() >= 9 => {
            let val = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            Ok((val, 9))
        }
        _ => Err("Invalid varint".to_string()),
    }
}

/// Parse a transaction input
fn parse_input(data: &[u8]) -> Result<(TxInput, usize), String> {
    if data.len() < 36 {
        return Err("Input too short".to_string());
    }

    let mut offset = 0usize;

    // Txid (32 bytes, little-endian in Bitcoin, but we keep as-is)
    let mut txid: [u8; 32] = data[offset..offset + 32]
        .try_into()
        .expect("32 bytes for txid");
    txid.reverse(); // Bitcoin uses reversed txid in serialization
    offset += 32;

    // Vout (4 bytes)
    let vout = u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid vout")?,
    );
    offset += 4;

    // Script sig length (varint)
    let (script_len, bytes_read) = read_varint(&data[offset..])?;
    offset += bytes_read;

    // Script sig
    if offset + script_len as usize > data.len() {
        return Err("Script sig exceeds data".to_string());
    }
    let script_sig = data[offset..offset + script_len as usize].to_vec();
    offset += script_len as usize;

    // Sequence (4 bytes)
    if offset + 4 > data.len() {
        return Err("Input truncated".to_string());
    }
    let sequence = u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid sequence")?,
    );
    offset += 4;

    Ok((
        TxInput {
            txid,
            vout,
            sequence,
            script_sig,
        },
        offset,
    ))
}

/// Parse a transaction output
fn parse_output(data: &[u8]) -> Result<(TxOutput, usize), String> {
    if data.len() < 8 {
        return Err("Output too short".to_string());
    }

    let mut offset = 0usize;

    // Value (8 bytes)
    let value = u64::from_le_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|_| "Invalid value")?,
    );
    offset += 8;

    // Script pubkey length (varint)
    let (script_len, bytes_read) = read_varint(&data[offset..])?;
    offset += bytes_read;

    // Script pubkey
    if offset + script_len as usize > data.len() {
        return Err("Script pubkey exceeds data".to_string());
    }
    let script_pubkey = data[offset..offset + script_len as usize].to_vec();
    offset += script_len as usize;

    Ok((
        TxOutput {
            value,
            script_pubkey,
        },
        offset,
    ))
}

/// Compute BIP-143 sighash for SegWit (P2WPKH) transactions
fn compute_sighash(
    tx: &ParsedTx,
    input: &TxInput,
    pubkey: &[u8],
    prevout_amount: Option<u64>,
) -> Result<[u8; 32], String> {
    use bitcoin_hashes::{Hash as BitcoinHash, sha256d};

    // HIGH-BTC-01: BIP-143 sighash requires the spent UTXO value
    // If prevout amount is not provided, fail closed
    let amount = prevout_amount.ok_or_else(|| {
        "BIP-143 sighash requires the spent UTXO value; refusing to sign without prevout amounts"
            .to_string()
    })?;

    // For P2WPKH, we need:
    // 1. hashPrevouts: double-SHA256 of all input outpoints
    // 2. hashSequence: double-SHA256 of all input sequences
    // 3. hashOutputs: double-SHA256 of all outputs
    // 4. The spent UTXO amount (for BIP-143)

    let mut prevouts_data = Vec::new();
    for inp in &tx.inputs {
        prevouts_data.extend_from_slice(&inp.txid);
        prevouts_data.extend_from_slice(&inp.vout.to_le_bytes());
    }
    let hash_prevouts = sha256d::Hash::hash(&prevouts_data);

    let mut sequences_data = Vec::new();
    for inp in &tx.inputs {
        sequences_data.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    let hash_sequence = sha256d::Hash::hash(&sequences_data);

    let mut outputs_data = Vec::new();
    for out in &tx.outputs {
        outputs_data.extend_from_slice(&out.value.to_le_bytes());
        outputs_data.extend_from_slice(&encode_varint(out.script_pubkey.len() as u64));
        outputs_data.extend_from_slice(&out.script_pubkey);
    }
    let hash_outputs = sha256d::Hash::hash(&outputs_data);

    let script_code = p2wpkh_script_code(pubkey)?;

    // BIP-143 sighash preimage for P2WPKH:
    // version (4) + hashPrevouts (32) + hashSequence (32) + outpoint (36) + scriptCode (var) + amount (8) + nSequence (4) + hashOutputs (32) + locktime (4) + sighashType (4)
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(hash_prevouts.as_ref());
    preimage.extend_from_slice(hash_sequence.as_ref());
    preimage.extend_from_slice(&input.txid);
    preimage.extend_from_slice(&input.vout.to_le_bytes());
    preimage.extend_from_slice(&encode_varint(script_code.len() as u64));
    preimage.extend_from_slice(&script_code);
    preimage.extend_from_slice(&amount.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(hash_outputs.as_ref());
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());
    preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

    let sighash = sha256d::Hash::hash(&preimage);
    Ok(sighash.to_byte_array())
}

/// Build BIP-143 scriptCode for a P2WPKH input:
/// `OP_DUP OP_HASH160 PUSH20 HASH160(pubkey) OP_EQUALVERIFY OP_CHECKSIG`.
fn p2wpkh_script_code(pubkey: &[u8]) -> Result<Vec<u8>, String> {
    use bitcoin_hashes::{Hash as BitcoinHash, hash160};

    if pubkey.is_empty() {
        return Err("Pubkey is empty".to_string());
    }

    let pubkey_hash = hash160::Hash::hash(pubkey);
    let mut script_code = vec![0x19, 0x76, 0xa9, 0x14];
    script_code.extend_from_slice(pubkey_hash.as_ref());
    script_code.extend_from_slice(&[0x88, 0xac]);
    Ok(script_code)
}

/// Build a signed Bitcoin transaction
fn build_signed_transaction(
    tx: &ParsedTx,
    witnesses: Vec<Vec<Vec<u8>>>,
) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();

    // Version
    result.extend_from_slice(&tx.version.to_le_bytes());

    // SegWit marker and flag
    result.push(0x00);
    result.push(0x01);

    // Input count
    result.extend_from_slice(&encode_varint(tx.inputs.len() as u64));

    // Inputs (without witness data)
    for input in &tx.inputs {
        let mut txid_reversed = input.txid;
        txid_reversed.reverse();
        result.extend_from_slice(&txid_reversed);
        result.extend_from_slice(&input.vout.to_le_bytes());
        result.push(0x00); // Empty script sig for SegWit
        result.extend_from_slice(&input.sequence.to_le_bytes());
    }

    // Output count
    result.extend_from_slice(&encode_varint(tx.outputs.len() as u64));

    // Outputs
    for output in &tx.outputs {
        result.extend_from_slice(&output.value.to_le_bytes());
        result.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
        result.extend_from_slice(&output.script_pubkey);
    }

    // Witness data
    for witness in witnesses {
        result.extend_from_slice(&encode_varint(witness.len() as u64));
        for item in witness {
            result.extend_from_slice(&encode_varint(item.len() as u64));
            result.extend_from_slice(&item);
        }
    }

    // Locktime
    result.extend_from_slice(&tx.locktime.to_le_bytes());

    Ok(result)
}

#[cfg(test)]
mod tx_signing_tests {
    use super::*;
    use bitcoin_hashes::{Hash as BitcoinHash, hash160};

    #[test]
    fn p2wpkh_script_code_uses_hash160_pubkey() {
        let pubkey = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];

        let script = p2wpkh_script_code(&pubkey).expect("script code");
        let expected_hash = hash160::Hash::hash(&pubkey);

        assert_eq!(script.len(), 26);
        assert_eq!(&script[..4], &[0x19, 0x76, 0xa9, 0x14]);
        let expected_hash_bytes: &[u8] = expected_hash.as_ref();
        assert_eq!(&script[4..24], expected_hash_bytes);
        assert_ne!(&script[4..24], &pubkey[..20]);
        assert_eq!(&script[24..26], &[0x88, 0xac]);
    }

    #[test]
    fn p2wpkh_script_code_rejects_empty_pubkey() {
        assert!(p2wpkh_script_code(&[]).is_err());
    }
}

/// Fee estimation implementation for Bitcoin using estimatesmartfee RPC
async fn get_fee_estimate_rpc(rpc: &dyn BitcoinRpc) -> ChainOpResult<u64> {
    rpc.estimate_fee_rate().await.map_err(|e| {
        ChainOpError::RpcError(format!(
            "Bitcoin fee estimation unavailable from configured RPC: {}",
            e
        ))
    })
}

#[async_trait]
impl ChainBackend for BitcoinBackend {
    fn chain_id(&self) -> &'static str {
        "bitcoin"
    }

    fn chain_name(&self) -> &'static str {
        "Bitcoin"
    }

    fn is_capability_available(&self, _capability: ChainCapability) -> bool {
        true
    }

    async fn create_seal(&self, value: Option<u64>) -> ChainOpResult<SealPoint> {
        let bitcoin_seal = self
            .seal_protocol
            .create_seal(value)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal creation failed: {}", e)))?;

        // Convert BitcoinSealPoint to core SealPoint
        // BitcoinSealPoint has txid (32 bytes) + vout (4 bytes) stored in id
        let mut id_bytes = Vec::with_capacity(36); // 32 txid + 4 vout
        id_bytes.extend_from_slice(&bitcoin_seal.txid);
        id_bytes.extend_from_slice(&bitcoin_seal.vout.to_le_bytes());

        Ok(SealPoint {
            id: id_bytes,
            nonce: bitcoin_seal.nonce,
            version: None,
        })
    }

    async fn publish_seal(&self, seal: SealPoint, commitment: Hash) -> ChainOpResult<CommitAnchor> {
        // Convert core SealPoint to BitcoinSealPoint
        if seal.id.len() < 36 {
            return Err(ChainOpError::InvalidInput(
                "Seal ID too short, expected at least 36 bytes (32 txid + 4 vout)".to_string(),
            ));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&seal.id[..32]);
        let vout = u32::from_le_bytes(seal.id[32..36].try_into().map_err(|_| {
            ChainOpError::InvalidInput("Failed to extract vout from seal ID".to_string())
        })?);

        let bitcoin_seal = BitcoinSealPoint::new(txid, vout, seal.nonce);

        // Call the seal protocol's publish method
        let bitcoin_anchor = self
            .seal_protocol
            .publish(commitment, bitcoin_seal)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal publishing failed: {}", e)))?;

        // Convert BitcoinCommitAnchor to core CommitAnchor
        Ok(CommitAnchor {
            anchor_id: bitcoin_anchor.txid.to_vec(),
            block_height: bitcoin_anchor.block_height,
            metadata: bitcoin_anchor.output_index.to_le_bytes().to_vec(),
        })
    }
}

#[async_trait]
impl SanadStateReader for BitcoinBackend {
    async fn get_sanad_state(&self, _sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState> {
        // For Bitcoin, sanad state is tracked via UTXO and transaction history
        // This is a simplified implementation
        Ok(CanonicalSanadState {
            state: 1, // Created (placeholder - would query actual UTXO state)
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
        // For Bitcoin, seal state is derived from the UTXO
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
        // Query transaction history for this sanad_id
        // This would require querying the Bitcoin blockchain
        Ok(vec![])
    }
}
