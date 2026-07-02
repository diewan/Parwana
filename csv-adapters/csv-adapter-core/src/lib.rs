//! CSV Adapter Core
//!
//! This crate provides common traits and configuration types for all chain adapters,
//! reducing duplication and ensuring consistency across adapter implementations.

#![warn(missing_docs)]

use async_trait::async_trait;
use csv_hash::{Hash, commitment::Commitment};
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::signature::SignatureScheme;
use serde::{Deserialize, Serialize};

/// Common adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    /// Chain identifier
    pub chain_id: String,
    /// Network type (mainnet, testnet, devnet)
    pub network: String,
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Maximum number of concurrent RPC requests
    pub max_concurrent_requests: usize,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            chain_id: "unknown".to_string(),
            network: "mainnet".to_string(),
            rpc_url: "http://localhost:8545".to_string(),
            max_concurrent_requests: 10,
            request_timeout_secs: 60,
        }
    }
}

/// Common adapter error type
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// RPC error
    #[error("RPC error: {0}")]
    RpcError(String),
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),
    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
    /// Generic error
    #[error("Generic error: {0}")]
    Generic(String),
}

/// Result type for adapter operations
pub type AdapterResult<T> = Result<T, AdapterError>;

/// Trait for proof verification operations
#[async_trait]
pub trait ProofAdapter: Send + Sync {
    /// Verify a proof bundle
    async fn verify_proof_bundle(&self, bundle: &ProofBundle) -> AdapterResult<bool>;

    /// Get chain-specific proof type
    fn proof_type(&self) -> String;
}

/// Trait for mint operations
#[async_trait]
pub trait MintAdapter: Send + Sync {
    /// Mint a Sanad commitment
    async fn mint_commitment(&self, commitment: &Commitment) -> AdapterResult<Hash>;

    /// Get mint status
    async fn get_mint_status(&self, tx_hash: &Hash) -> AdapterResult<MintStatus>;

    /// Get mint receipt
    async fn get_mint_receipt(&self, tx_hash: &Hash) -> AdapterResult<MintReceipt>;
}

/// Mint status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintStatus {
    /// Pending
    Pending,
    /// Confirmed
    Confirmed,
    /// Failed
    Failed,
}

/// Mint receipt
#[derive(Debug, Clone)]
pub struct MintReceipt {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Block number
    pub block_number: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Gas used
    pub gas_used: u64,
}

impl serde::Serialize for MintReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("MintReceipt", 4)?;
        s.serialize_field("tx_hash", &self.tx_hash.0)?;
        s.serialize_field("block_number", &self.block_number)?;
        s.serialize_field("timestamp", &self.timestamp)?;
        s.serialize_field("gas_used", &self.gas_used)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for MintReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            TxHash,
            BlockNumber,
            Timestamp,
            GasUsed,
        }

        struct MintReceiptVisitor;

        impl<'de> serde::de::Visitor<'de> for MintReceiptVisitor {
            type Value = MintReceipt;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct MintReceipt")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let tx_hash_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let block_number = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let timestamp = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let gas_used = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                Ok(MintReceipt {
                    tx_hash: Hash(tx_hash_bytes),
                    block_number,
                    timestamp,
                    gas_used,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut tx_hash = None;
                let mut block_number = None;
                let mut timestamp = None;
                let mut gas_used = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::TxHash => {
                            if tx_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("tx_hash"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            tx_hash = Some(Hash(hash_bytes));
                        }
                        Field::BlockNumber => {
                            if block_number.is_some() {
                                return Err(serde::de::Error::duplicate_field("block_number"));
                            }
                            block_number = Some(map.next_value()?);
                        }
                        Field::Timestamp => {
                            if timestamp.is_some() {
                                return Err(serde::de::Error::duplicate_field("timestamp"));
                            }
                            timestamp = Some(map.next_value()?);
                        }
                        Field::GasUsed => {
                            if gas_used.is_some() {
                                return Err(serde::de::Error::duplicate_field("gas_used"));
                            }
                            gas_used = Some(map.next_value()?);
                        }
                    }
                }

                let tx_hash = tx_hash.ok_or_else(|| serde::de::Error::missing_field("tx_hash"))?;
                let block_number =
                    block_number.ok_or_else(|| serde::de::Error::missing_field("block_number"))?;
                let timestamp =
                    timestamp.ok_or_else(|| serde::de::Error::missing_field("timestamp"))?;
                let gas_used =
                    gas_used.ok_or_else(|| serde::de::Error::missing_field("gas_used"))?;

                Ok(MintReceipt {
                    tx_hash,
                    block_number,
                    timestamp,
                    gas_used,
                })
            }
        }

        deserializer.deserialize_struct(
            "MintReceipt",
            &["tx_hash", "block_number", "timestamp", "gas_used"],
            MintReceiptVisitor,
        )
    }
}

/// Trait for chain operations
#[async_trait]
pub trait ChainOps: Send + Sync {
    /// Get chain height
    async fn get_chain_height(&self) -> AdapterResult<u64>;

    /// Get balance for an address
    async fn get_balance(&self, address: &str) -> AdapterResult<u64>;

    /// Get transaction status
    async fn get_transaction_status(&self, tx_hash: &Hash) -> AdapterResult<TransactionStatus>;

    /// Broadcast a transaction
    async fn broadcast_transaction(&self, tx_bytes: &[u8]) -> AdapterResult<Hash>;
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Pending
    Pending,
    /// Confirmed
    Confirmed,
    /// Failed
    Failed,
    /// Unknown
    Unknown,
}

/// Re-export common types for adapter use
pub use csv_protocol::seal_protocol::SealProtocol;

/// Cross-chain transfer data passed to adapters.
#[derive(Debug, Clone)]
pub struct CrossChainTransfer {
    /// Unique transfer ID
    pub id: String,
    /// Source chain ID
    pub source_chain: String,
    /// Destination chain ID
    pub destination_chain: String,
    /// Lock transaction hash on source chain
    pub lock_tx_hash: Vec<u8>,
    /// Lock output index on source chain
    pub lock_output_index: u32,
    /// Sanad ID being transferred
    pub sanad_id: Hash,
    /// Transition ID for the transfer
    pub transition_id: Vec<u8>,
}

impl serde::Serialize for CrossChainTransfer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CrossChainTransfer", 7)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("source_chain", &self.source_chain)?;
        s.serialize_field("destination_chain", &self.destination_chain)?;
        s.serialize_field("lock_tx_hash", &self.lock_tx_hash)?;
        s.serialize_field("lock_output_index", &self.lock_output_index)?;
        s.serialize_field("sanad_id", &self.sanad_id.0)?;
        s.serialize_field("transition_id", &self.transition_id)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for CrossChainTransfer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Id,
            SourceChain,
            DestinationChain,
            LockTxHash,
            LockOutputIndex,
            SanadId,
            TransitionId,
        }

        struct CrossChainTransferVisitor;

        impl<'de> serde::de::Visitor<'de> for CrossChainTransferVisitor {
            type Value = CrossChainTransfer;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct CrossChainTransfer")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let id = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let source_chain = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let destination_chain = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let lock_tx_hash = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let lock_output_index = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
                let sanad_id_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
                let transition_id = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(6, &self))?;
                Ok(CrossChainTransfer {
                    id,
                    source_chain,
                    destination_chain,
                    lock_tx_hash,
                    lock_output_index,
                    sanad_id: Hash(sanad_id_bytes),
                    transition_id,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut id = None;
                let mut source_chain = None;
                let mut destination_chain = None;
                let mut lock_tx_hash = None;
                let mut lock_output_index = None;
                let mut sanad_id = None;
                let mut transition_id = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Id => {
                            if id.is_some() {
                                return Err(serde::de::Error::duplicate_field("id"));
                            }
                            id = Some(map.next_value()?);
                        }
                        Field::SourceChain => {
                            if source_chain.is_some() {
                                return Err(serde::de::Error::duplicate_field("source_chain"));
                            }
                            source_chain = Some(map.next_value()?);
                        }
                        Field::DestinationChain => {
                            if destination_chain.is_some() {
                                return Err(serde::de::Error::duplicate_field("destination_chain"));
                            }
                            destination_chain = Some(map.next_value()?);
                        }
                        Field::LockTxHash => {
                            if lock_tx_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("lock_tx_hash"));
                            }
                            lock_tx_hash = Some(map.next_value()?);
                        }
                        Field::LockOutputIndex => {
                            if lock_output_index.is_some() {
                                return Err(serde::de::Error::duplicate_field("lock_output_index"));
                            }
                            lock_output_index = Some(map.next_value()?);
                        }
                        Field::SanadId => {
                            if sanad_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("sanad_id"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            sanad_id = Some(Hash(hash_bytes));
                        }
                        Field::TransitionId => {
                            if transition_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("transition_id"));
                            }
                            transition_id = Some(map.next_value()?);
                        }
                    }
                }

                let id = id.ok_or_else(|| serde::de::Error::missing_field("id"))?;
                let source_chain =
                    source_chain.ok_or_else(|| serde::de::Error::missing_field("source_chain"))?;
                let destination_chain = destination_chain
                    .ok_or_else(|| serde::de::Error::missing_field("destination_chain"))?;
                let lock_tx_hash =
                    lock_tx_hash.ok_or_else(|| serde::de::Error::missing_field("lock_tx_hash"))?;
                let lock_output_index = lock_output_index
                    .ok_or_else(|| serde::de::Error::missing_field("lock_output_index"))?;
                let sanad_id =
                    sanad_id.ok_or_else(|| serde::de::Error::missing_field("sanad_id"))?;
                let transition_id = transition_id
                    .ok_or_else(|| serde::de::Error::missing_field("transition_id"))?;

                Ok(CrossChainTransfer {
                    id,
                    source_chain,
                    destination_chain,
                    lock_tx_hash,
                    lock_output_index,
                    sanad_id,
                    transition_id,
                })
            }
        }

        deserializer.deserialize_struct(
            "CrossChainTransfer",
            &[
                "id",
                "source_chain",
                "destination_chain",
                "lock_tx_hash",
                "lock_output_index",
                "sanad_id",
                "transition_id",
            ],
            CrossChainTransferVisitor,
        )
    }
}

/// Result of a lock operation.
#[derive(Debug, Clone)]
pub struct LockResult {
    /// Transaction hash of the lock
    pub tx_hash: String,
    /// Block height of the lock
    pub block_height: u64,
}

/// Result of a mint operation.
#[derive(Debug, Clone)]
pub struct MintResult {
    /// Transaction hash of the mint
    pub tx_hash: String,
    /// Block height of the mint
    pub block_height: u64,
}

/// Confirmation status of an on-chain transaction.
///
/// Used by the runtime finality gate to decide whether a locked transaction has
/// reached the required confirmation depth before an inclusion proof is built.
#[derive(Debug, Clone)]
pub struct TxFinality {
    /// Height of the block that includes the transaction.
    ///
    /// This MUST be the true confirming height (so `get_block_hash(block_height)`
    /// returns the block the tx was mined in). It is `0` when the transaction is
    /// still unconfirmed / in the mempool.
    pub block_height: u64,
    /// Number of confirmations, measured with the same `tip - block_height`
    /// convention used by the proof builders. `0` when unconfirmed.
    pub confirmations: u64,
}

/// Status of a seal in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealRegistryStatus {
    /// Seal is available for use
    Available,
    /// Seal has been consumed
    Consumed,
    /// Seal is locked
    Locked,
}

/// Capability lookup port.
pub trait ChainCapabilityPort: Send + Sync {
    /// Get the chain capabilities for the specified chain.
    fn capabilities(&self, chain_id: &str) -> Option<ChainCapabilities>;

    /// Get the signature scheme for the specified chain.
    fn signature_scheme(&self, chain_id: &str) -> Option<SignatureScheme>;
}

/// Source-chain locking port.
#[async_trait]
pub trait ChainLockPort: Send + Sync {
    /// Lock a Sanad on the source chain for cross-chain transfer.
    async fn lock_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError>;
}

/// Destination-chain minting port.
#[async_trait]
pub trait ChainMintPort: Send + Sync {
    /// Mint a Sanad on the destination chain using the provided proof bundle.
    async fn mint_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError>;
}

/// Seal/replay registry query port.
#[async_trait]
pub trait ChainSealRegistryPort: Send + Sync {
    /// Check the status of a seal in the registry.
    async fn check_seal_registry(
        &self,
        chain_id: &str,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError>;
}

/// Source-chain proof construction port.
#[async_trait]
pub trait ChainProofPort: Send + Sync {
    /// Build an inclusion proof for the locked transaction.
    async fn build_inclusion_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError>;

    /// Cryptographically validate source-chain proof material and bind it to
    /// the transfer whose mint is being authorized.
    async fn validate_source_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError>;
}

/// Non-mutating read port.
#[async_trait]
pub trait ChainReadPort: Send + Sync {
    /// Confirm a transaction on the chain.
    async fn confirm_tx(&self, chain_id: &str, tx_hash: &str) -> Result<MintResult, AdapterError>;

    /// Query the confirmation status of a transaction.
    ///
    /// Returns the true confirming height and confirmation count so the runtime
    /// finality gate can decide whether an inclusion proof can be built.
    async fn tx_finality(&self, chain_id: &str, tx_hash: &str) -> Result<TxFinality, AdapterError>;

    /// Get the balance for an address on the chain.
    async fn get_balance(&self, chain_id: &str, address: &str) -> Result<String, AdapterError>;
}

/// Compatibility facade for runtime paths that still need the full adapter surface.
#[async_trait]
pub trait AdapterRegistry: Send + Sync {
    /// Get the chain capabilities for the specified chain.
    fn capabilities(&self, chain_id: &str) -> Option<ChainCapabilities>;

    /// Get the signature scheme for the specified chain.
    fn signature_scheme(&self, chain_id: &str) -> Option<SignatureScheme>;

    /// Lock a Sanad on the source chain for cross-chain transfer.
    async fn lock_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError>;

    /// Mint a Sanad on the destination chain using the provided proof bundle.
    async fn mint_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError>;

    /// Check the status of a seal in the registry.
    async fn check_seal_registry(
        &self,
        chain_id: &str,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError>;

    /// Build an inclusion proof for the locked transaction.
    async fn build_inclusion_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError>;

    /// Cryptographically validate source-chain proof material and bind it to
    /// the transfer whose mint is being authorized.
    async fn validate_source_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError>;

    /// Confirm a transaction on the chain.
    async fn confirm_tx(&self, chain_id: &str, tx_hash: &str) -> Result<MintResult, AdapterError>;

    /// Query the confirmation status of a transaction on the chain.
    async fn tx_finality(&self, chain_id: &str, tx_hash: &str) -> Result<TxFinality, AdapterError>;

    /// Get the balance for an address on the chain.
    async fn get_balance(&self, chain_id: &str, address: &str) -> Result<String, AdapterError>;
}

/// Legacy full chain adapter facade.
///
/// New code should request the narrow registry ports above. Adapters can migrate
/// to narrower internal modules while continuing to satisfy this compatibility
/// facade at the runtime boundary.
#[async_trait]
pub trait ChainAdapter: Send + Sync {
    /// Get the chain identifier for this adapter.
    fn chain_id(&self) -> &str;

    /// Get the chain capabilities for this adapter.
    fn capabilities(&self) -> ChainCapabilities;

    /// Get the signature scheme for this adapter.
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }

    /// Lock a Sanad on the source chain for cross-chain transfer.
    async fn lock_sanad(&self, transfer: &CrossChainTransfer) -> Result<LockResult, AdapterError>;

    /// Mint a Sanad on the destination chain using the provided proof bundle.
    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError>;

    /// Build an inclusion proof for the locked transaction.
    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError>;

    /// Cryptographically validate source-chain proof material and bind it to
    /// the transfer whose mint is being authorized.
    async fn validate_source_proof(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError>;

    /// Check the status of a seal in the registry.
    async fn check_seal_registry(&self, seal_id: &[u8])
    -> Result<SealRegistryStatus, AdapterError>;

    /// Confirm a transaction on the chain.
    async fn confirm_tx(&self, tx_hash: &str) -> Result<MintResult, AdapterError> {
        Err(AdapterError::Generic(format!(
            "confirm_tx is not implemented for transaction {}",
            tx_hash
        )))
    }

    /// Query the confirmation status of a transaction on the chain.
    ///
    /// The default implementation delegates to [`ChainAdapter::confirm_tx`]:
    /// a successful confirmation is treated as final (`confirmations = u64::MAX`),
    /// which preserves the pre-existing behaviour for adapters that only track a
    /// binary confirmed/unconfirmed status. Chains with a real confirmation-depth
    /// model (Bitcoin, Ethereum) override this to return an accurate count so the
    /// runtime finality gate can enforce `finality_depth`.
    async fn tx_finality(&self, tx_hash: &str) -> Result<TxFinality, AdapterError> {
        let confirmed = self.confirm_tx(tx_hash).await?;
        Ok(TxFinality {
            block_height: confirmed.block_height,
            confirmations: u64::MAX,
        })
    }

    /// Get the balance for an address on the chain.
    async fn get_balance(&self, address: &str) -> Result<String, AdapterError>;

    /// Downcast to concrete type for feature-specific operations
    fn as_any(&self) -> &dyn std::any::Any;
}
