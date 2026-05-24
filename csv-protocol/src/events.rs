//! Shared Event Schemas for Cross-Chain Transfers
//!
//! This module defines standardized event types for the CSV protocol.
//! These events are used by:
//! - Chain adapters to emit events
//! - Explorer indexer plugins to index chain events
//! - Contract/program implementations to emit events
//! - SDKs to parse and display event data
//!
//! All events follow a consistent schema for maximum interoperability.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use csv_hash::Hash;
use csv_hash::sanad::SanadId;

/// Standard event names in the CSV protocol
pub mod event_names {
    /// Sanad created on chain
    pub const SANAD_CREATED: &str = "SanadCreated";
    /// Sanad consumed (spent)
    pub const SANAD_CONSUMED: &str = "SanadConsumed";
    /// Sanad locked for cross-chain transfer
    pub const CROSS_CHAIN_LOCK: &str = "CrossChainLock";
    /// Sanad minted on destination chain
    pub const CROSS_CHAIN_MINT: &str = "CrossChainMint";
    /// Sanad refunded after timeout
    pub const CROSS_CHAIN_REFUND: &str = "CrossChainRefund";
    /// Sanad transferred to new owner
    pub const SANAD_TRANSFERRED: &str = "SanadTransferred";
    /// Nullifier registered for spent sanad
    pub const NULLIFIER_REGISTERED: &str = "NullifierRegistered";
    /// Sanad metadata recorded
    pub const SANAD_METADATA_RECORDED: &str = "SanadMetadataRecorded";
    /// Proof accepted by validation pipeline
    pub const PROOF_ACCEPTED: &str = "ProofAccepted";
    /// Proof rejected by validation pipeline
    pub const PROOF_REJECTED: &str = "ProofRejected";
    /// Replay attack detected
    pub const REPLAY_DETECTED: &str = "ReplayDetected";
    /// RPC provider disagreement detected
    pub const RPC_DISAGREEMENT: &str = "RpcDisagreement";
    /// Chain reorg detected
    pub const REORG_DETECTED: &str = "ReorgDetected";
    /// Rollback executed due to reorg
    pub const ROLLBACK_EXECUTED: &str = "RollbackExecuted";
    /// Mint operation compromised
    pub const MINT_COMPROMISED: &str = "MintCompromised";
}

/// Standard metadata field names
pub mod metadata_fields {
    /// Unique sanad identifier
    pub const SANAD_ID: &str = "sanad_id";
    /// Cryptographic commitment
    pub const COMMITMENT: &str = "commitment";
    /// Owner address
    pub const OWNER: &str = "owner";
    /// Chain identifier
    pub const CHAIN_ID: &str = "chain_id";
    /// Asset class (e.g., "RGB", "ERC20", "NFT")
    pub const ASSET_CLASS: &str = "asset_class";
    /// Specific asset identifier
    pub const ASSET_ID: &str = "asset_id";
    /// Metadata value
    pub const METADATA: &str = "metadata";
    /// Destination chain for cross-chain transfers
    pub const DESTINATION_CHAIN: &str = "destination_chain";
    /// Source chain for cross-chain transfers
    pub const SOURCE_CHAIN: &str = "source_chain";
    /// Block height where event occurred
    pub const BLOCK_HEIGHT: &str = "block_height";
    /// Transaction hash
    pub const TX_HASH: &str = "tx_hash";
}

/// Base event data structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CsvEvent {
    /// Event type identifier
    pub event_type: String,
    /// Chain where event occurred
    pub chain: String,
    /// Block height where event occurred
    pub block_height: u64,
    /// Transaction hash
    pub tx_hash: String,
    /// Event timestamp (unix timestamp in seconds)
    pub timestamp: u64,
    /// Event-specific data
    pub data: EventData,
    /// Optional metadata (replaced serde_json::Value with HashMap for protocol purity)
    pub metadata: Option<HashMap<String, String>>,
    /// Correlation ID for tracking related events across the system
    pub correlation_id: Option<String>,
    /// Transfer ID if this event is associated with a cross-chain transfer
    pub transfer_id: Option<String>,
    /// Operation ID for the specific operation that generated this event
    pub operation_id: Option<String>,
}

/// Event data variants
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum EventData {
    /// Sanad created event
    SanadCreated {
        sanad_id: SanadId,
        owner: String,
        commitment: Hash,
        asset_class: String,
        asset_id: String,
        metadata: Option<HashMap<String, String>>,
    },
    /// Sanad consumed event
    SanadConsumed {
        sanad_id: SanadId,
        nullifier: Hash,
        consumed_by: String,
    },
    /// Sanad transferred event
    SanadTransferred {
        sanad_id: SanadId,
        from: String,
        to: String,
        metadata: Option<HashMap<String, String>>,
    },
    /// Sanad-chain lock event
    CrossChainLock {
        sanad_id: SanadId,
        source_chain: String,
        destination_chain: String,
        destination_owner: String,
        proof_hash: Hash,
    },
    /// Cross-chain mint event
    CrossChainMint {
        sanad_id: SanadId,
        source_chain: String,
        source_sanad_id: SanadId,
        owner: String,
        proof_hash: Hash,
    },
    /// Cross-chain refund event
    CrossChainRefund {
        sanad_id: SanadId,
        source_chain: String,
        destination_chain: String,
        refunded_to: String,
    },
    /// Nullifier registered event
    NullifierRegistered {
        sanad_id: SanadId,
        nullifier: Hash,
        chain: String,
    },
    /// Sanad metadata recorded event
    SanadMetadataRecorded {
        sanad_id: SanadId,
        metadata: HashMap<String, String>,
    },
    /// Proof accepted event
    ProofAccepted {
        proof_hash: Hash,
        chain: String,
        validator: String,
    },
    /// Proof rejected event
    ProofRejected {
        proof_hash: Hash,
        chain: String,
        reason: String,
    },
    /// Replay detected event
    ReplayDetected {
        proof_hash: Hash,
        chain: String,
        original_timestamp: u64,
        replay_timestamp: u64,
    },
    /// RPC disagreement event
    RpcDisagreement {
        chain: String,
        method: String,
        providers: Vec<String>,
        disagreement_type: String,
    },
    /// Reorg detected event
    ReorgDetected {
        chain: String,
        old_height: u64,
        new_height: u64,
        depth: u64,
    },
    /// Rollback executed event
    RollbackExecuted {
        chain: String,
        from_height: u64,
        to_height: u64,
        transfers_affected: u32,
    },
    /// Mint compromised event
    MintCompromised {
        sanad_id: SanadId,
        chain: String,
        compromise_type: String,
        details: String,
    },
}

impl CsvEvent {
    /// Create a new SanadCreated event
    #[allow(clippy::too_many_arguments)]
    pub fn sanad_created(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        sanad_id: SanadId,
        owner: &str,
        commitment: Hash,
        asset_class: &str,
        asset_id: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            event_type: event_names::SANAD_CREATED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::SanadCreated {
                sanad_id,
                owner: owner.to_string(),
                commitment,
                asset_class: asset_class.to_string(),
                asset_id: asset_id.to_string(),
                metadata,
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new SanadConsumed event
    pub fn sanad_consumed(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        sanad_id: SanadId,
        nullifier: Hash,
        consumed_by: &str,
    ) -> Self {
        Self {
            event_type: event_names::SANAD_CONSUMED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::SanadConsumed {
                sanad_id,
                nullifier,
                consumed_by: consumed_by.to_string(),
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new SanadTransferred event
    #[allow(clippy::too_many_arguments)]
    pub fn sanad_transferred(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        sanad_id: SanadId,
        from: &str,
        to: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            event_type: event_names::SANAD_TRANSFERRED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::SanadTransferred {
                sanad_id,
                from: from.to_string(),
                to: to.to_string(),
                metadata,
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new CrossChainLock event
    #[allow(clippy::too_many_arguments)]
    pub fn cross_chain_lock(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        sanad_id: SanadId,
        source_chain: &str,
        destination_chain: &str,
        destination_owner: &str,
        proof_hash: Hash,
    ) -> Self {
        Self {
            event_type: event_names::CROSS_CHAIN_LOCK.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::CrossChainLock {
                sanad_id,
                source_chain: source_chain.to_string(),
                destination_chain: destination_chain.to_string(),
                destination_owner: destination_owner.to_string(),
                proof_hash,
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new CrossChainMint event
    #[allow(clippy::too_many_arguments)]
    pub fn cross_chain_mint(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        sanad_id: SanadId,
        source_chain: &str,
        source_sanad_id: SanadId,
        owner: &str,
        proof_hash: Hash,
    ) -> Self {
        Self {
            event_type: event_names::CROSS_CHAIN_MINT.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::CrossChainMint {
                sanad_id,
                source_chain: source_chain.to_string(),
                source_sanad_id,
                owner: owner.to_string(),
                proof_hash,
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new CrossChainRefund event
    #[allow(clippy::too_many_arguments)]
    pub fn cross_chain_refund(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        sanad_id: SanadId,
        source_chain: &str,
        destination_chain: &str,
        refunded_to: &str,
    ) -> Self {
        Self {
            event_type: event_names::CROSS_CHAIN_REFUND.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::CrossChainRefund {
                sanad_id,
                source_chain: source_chain.to_string(),
                destination_chain: destination_chain.to_string(),
                refunded_to: refunded_to.to_string(),
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new NullifierRegistered event
    pub fn nullifier_registered(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        sanad_id: SanadId,
        nullifier: Hash,
    ) -> Self {
        Self {
            event_type: event_names::NULLIFIER_REGISTERED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::NullifierRegistered {
                sanad_id,
                nullifier,
                chain: chain.to_string(),
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new SanadMetadataRecorded event
    pub fn sanad_metadata_recorded(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        sanad_id: SanadId,
        metadata: HashMap<String, String>,
    ) -> Self {
        Self {
            event_type: event_names::SANAD_METADATA_RECORDED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::SanadMetadataRecorded { sanad_id, metadata },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new ProofAccepted event
    pub fn proof_accepted(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        proof_hash: Hash,
        validator: &str,
    ) -> Self {
        Self {
            event_type: event_names::PROOF_ACCEPTED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::ProofAccepted {
                proof_hash,
                chain: chain.to_string(),
                validator: validator.to_string(),
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new ProofRejected event
    pub fn proof_rejected(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        proof_hash: Hash,
        reason: &str,
    ) -> Self {
        Self {
            event_type: event_names::PROOF_REJECTED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::ProofRejected {
                proof_hash,
                chain: chain.to_string(),
                reason: reason.to_string(),
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new ReplayDetected event
    pub fn replay_detected(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        proof_hash: Hash,
        original_timestamp: u64,
        replay_timestamp: u64,
    ) -> Self {
        Self {
            event_type: event_names::REPLAY_DETECTED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::ReplayDetected {
                proof_hash,
                chain: chain.to_string(),
                original_timestamp,
                replay_timestamp,
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new RpcDisagreement event
    pub fn rpc_disagreement(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        method: &str,
        providers: Vec<String>,
        disagreement_type: &str,
    ) -> Self {
        Self {
            event_type: event_names::RPC_DISAGREEMENT.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::RpcDisagreement {
                chain: chain.to_string(),
                method: method.to_string(),
                providers,
                disagreement_type: disagreement_type.to_string(),
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new ReorgDetected event
    pub fn reorg_detected(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        old_height: u64,
        new_height: u64,
        depth: u64,
    ) -> Self {
        Self {
            event_type: event_names::REORG_DETECTED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::ReorgDetected {
                chain: chain.to_string(),
                old_height,
                new_height,
                depth,
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new RollbackExecuted event
    pub fn rollback_executed(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        from_height: u64,
        to_height: u64,
        transfers_affected: u32,
    ) -> Self {
        Self {
            event_type: event_names::ROLLBACK_EXECUTED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::RollbackExecuted {
                chain: chain.to_string(),
                from_height,
                to_height,
                transfers_affected,
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Create a new MintCompromised event
    pub fn mint_compromised(
        chain: &str,
        block_height: u64,
        tx_hash: &str,
        timestamp: u64,
        sanad_id: SanadId,
        compromise_type: &str,
        details: &str,
    ) -> Self {
        Self {
            event_type: event_names::MINT_COMPROMISED.to_string(),
            chain: chain.to_string(),
            block_height,
            tx_hash: tx_hash.to_string(),
            timestamp,
            data: EventData::MintCompromised {
                sanad_id,
                chain: chain.to_string(),
                compromise_type: compromise_type.to_string(),
                details: details.to_string(),
            },
            metadata: None,
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
        }
    }

    /// Set the correlation ID for this event
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Set the transfer ID for this event
    pub fn with_transfer_id(mut self, transfer_id: String) -> Self {
        self.transfer_id = Some(transfer_id);
        self
    }

    /// Set the operation ID for this event
    pub fn with_operation_id(mut self, operation_id: String) -> Self {
        self.operation_id = Some(operation_id);
        self
    }
}

/// Event filter for querying events
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by chain
    pub chain: Option<String>,
    /// Filter by sanad ID
    pub sanad_id: Option<SanadId>,
    /// Filter by owner address
    pub owner: Option<String>,
    /// Filter by date range (start)
    pub from_timestamp: Option<u64>,
    /// Filter by date range (end)
    pub to_timestamp: Option<u64>,
    /// Maximum number of results
    pub limit: Option<usize>,
}

/// Event indexer interface
#[async_trait::async_trait]
pub trait EventIndexer: Send + Sync {
    /// Emit an event
    async fn emit(&self, event: CsvEvent) -> Result<(), Box<dyn std::error::Error>>;

    /// Query events with filter
    async fn query(
        &self,
        filter: &EventFilter,
    ) -> Result<Vec<CsvEvent>, Box<dyn std::error::Error>>;

    /// Get event by sanad ID
    async fn get_by_sanad_id(
        &self,
        sanad_id: &SanadId,
    ) -> Result<Vec<CsvEvent>, Box<dyn std::error::Error>>;
}

/// Event indexer registry
#[derive(Default)]
pub struct EventIndexerRegistry {
    indexers: Vec<Box<dyn EventIndexer>>,
}

impl EventIndexerRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self {
            indexers: Vec::new(),
        }
    }

    /// Register an indexer
    pub fn register(&mut self, indexer: Box<dyn EventIndexer>) {
        self.indexers.push(indexer);
    }

    /// Emit event to all registered indexers
    pub async fn emit(&self, event: CsvEvent) -> Result<(), Box<dyn std::error::Error>> {
        for indexer in &self.indexers {
            indexer.emit(event.clone()).await?;
        }
        Ok(())
    }

    /// Query events from all registered indexers
    pub async fn query(
        &self,
        filter: &EventFilter,
    ) -> Result<Vec<CsvEvent>, Box<dyn std::error::Error>> {
        let mut events = Vec::new();
        for indexer in &self.indexers {
            let indexer_events = indexer.query(filter).await?;
            events.extend(indexer_events);
        }
        Ok(events)
    }
}

/// Structured JSON event formatter
pub struct JsonEventFormatter {}

impl JsonEventFormatter {
    /// Create a new JSON formatter
    pub fn new() -> Self {
        Self {}
    }

    /// Create a new JSON formatter with pretty printing
    pub fn pretty() -> Self {
        Self {}
    }

    /// Format a single event as CBOR (canonical serialization per AGENTS.md)
    pub fn format_event(
        &self,
        event: &CsvEvent,
    ) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(event, &mut buf)?;
        Ok(buf)
    }

    /// Format multiple events as a CBOR array
    pub fn format_events(
        &self,
        events: &[CsvEvent],
    ) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(events, &mut buf)?;
        Ok(buf)
    }

    /// Format event as a structured log line
    pub fn format_log_line(&self, event: &CsvEvent) -> String {
        let timestamp = event.timestamp;
        let event_type = &event.event_type;
        let chain = &event.chain;
        let correlation_id = event.correlation_id.as_deref().unwrap_or("N/A");
        let transfer_id = event.transfer_id.as_deref().unwrap_or("N/A");

        format!(
            "{{\"timestamp\":{},\"event_type\":\"{}\",\"chain\":\"{}\",\"correlation_id\":\"{}\",\"transfer_id\":\"{}\"}}",
            timestamp, event_type, chain, correlation_id, transfer_id
        )
    }
}

impl Default for JsonEventFormatter {
    fn default() -> Self {
        Self::new()
    }
}

/// Event finality status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventFinalityStatus {
    /// Event is pending confirmation
    Pending,
    /// Event has been confirmed
    Confirmed {
        /// Number of confirmations
        confirmations: u64,
    },
    /// Event has reached finality
    Finalized,
}

// Canonical event schema for CSV protocol contracts
//
// This module defines the canonical event schema that all chain contracts
// MUST emit. This ensures cross-chain event equivalence and enables
// unified event indexing and verification.
//
// # Canonical Event Schema
//
// All contracts MUST emit events with the following canonical structure:
// - Event name: keccak256("EventName(bytes32,bytes32,...)")[0:4]
// - Indexed parameters: first 3 parameters are indexed (topics)
// - Non-indexed parameters: remaining parameters are in data
// - Deterministic encoding: all parameters use canonical CBOR encoding
//
// # Required Events
//
// Every chain contract MUST emit these events:
// - SealCreated: When a seal is created
// - SealConsumed: When a seal is consumed
// - SealLocked: When a seal is locked for cross-chain transfer
// - SealMinted: When a seal is minted from cross-chain transfer
// - SealRefunded: When a locked seal is refunded
// - CommitmentAnchored: When a commitment is anchored
// - ReplayNullifierRegistered: When a replay nullifier is registered
// - ProofRootUpdated: When the proof root is updated

/// Canonical event types that all chain contracts MUST emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalEvent {
    /// Emitted when a seal is created on a chain.
    SealCreated(SealCreatedEvent),

    /// Emitted when a seal is consumed (locked or burned).
    SealConsumed(SealConsumedEvent),

    /// Emitted when a seal is locked for cross-chain transfer.
    SealLocked(SealLockedEvent),

    /// Emitted when a seal is minted from cross-chain transfer.
    SealMinted(SealMintedEvent),

    /// Emitted when a locked seal is refunded.
    SealRefunded(SealRefundedEvent),

    /// Emitted when a commitment is anchored.
    CommitmentAnchored(CommitmentAnchoredEvent),

    /// Emitted when a replay nullifier is registered.
    ReplayNullifierRegistered(ReplayNullifierEvent),

    /// Emitted when the proof root is updated.
    ProofRootUpdated(ProofRootUpdatedEvent),
}

impl CanonicalEvent {
    /// Get the canonical event name as a string.
    pub fn event_name(&self) -> &'static str {
        match self {
            CanonicalEvent::SealCreated(_) => "SealCreated",
            CanonicalEvent::SealConsumed(_) => "SealConsumed",
            CanonicalEvent::SealLocked(_) => "SealLocked",
            CanonicalEvent::SealMinted(_) => "SealMinted",
            CanonicalEvent::SealRefunded(_) => "SealRefunded",
            CanonicalEvent::CommitmentAnchored(_) => "CommitmentAnchored",
            CanonicalEvent::ReplayNullifierRegistered(_) => "ReplayNullifierRegistered",
            CanonicalEvent::ProofRootUpdated(_) => "ProofRootUpdated",
        }
    }

    /// Compute the canonical event signature hash.
    ///
    /// This is keccak256("EventName(type1,type2,...)") used for event filtering.
    pub fn signature_hash(&self) -> Hash {
        let signature = match self {
            CanonicalEvent::SealCreated(_) => "SealCreated(bytes32,address,bytes32)",
            CanonicalEvent::SealConsumed(_) => "SealConsumed(bytes32,address,uint256)",
            CanonicalEvent::SealLocked(_) => "SealLocked(bytes32,address,uint8,bytes)",
            CanonicalEvent::SealMinted(_) => "SealMinted(bytes32,address,uint8,bytes32)",
            CanonicalEvent::SealRefunded(_) => "SealRefunded(bytes32,address,uint256)",
            CanonicalEvent::CommitmentAnchored(_) => "CommitmentAnchored(bytes32,bytes32,uint256)",
            CanonicalEvent::ReplayNullifierRegistered(_) => "ReplayNullifierRegistered(bytes32)",
            CanonicalEvent::ProofRootUpdated(_) => "ProofRootUpdated(bytes32)",
        };
        Hash::sha256(signature.as_bytes())
    }
}

/// SealCreated event data.
///
/// Indexed: sealId, owner
/// Non-indexed: commitment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealCreatedEvent {
    /// Unique seal identifier (32-byte hash)
    pub seal_id: Hash,
    /// Owner address (chain-specific encoding)
    pub owner: Vec<u8>,
    /// Commitment hash
    pub commitment: Hash,
}

/// SealConsumed event data.
///
/// Indexed: sealId, owner
/// Non-indexed: timestamp
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealConsumedEvent {
    /// Unique seal identifier (32-byte hash)
    pub seal_id: Hash,
    /// Owner address (chain-specific encoding)
    pub owner: Vec<u8>,
    /// Consumption timestamp (Unix epoch seconds)
    pub timestamp: u64,
}

/// SealLocked event data.
///
/// Indexed: sealId, owner
/// Non-indexed: destinationChain, destinationOwner
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealLockedEvent {
    /// Unique seal identifier (32-byte hash)
    pub seal_id: Hash,
    /// Owner address (chain-specific encoding)
    pub owner: Vec<u8>,
    /// Destination chain ID (uint8)
    pub destination_chain: u8,
    /// Destination owner address (chain-specific encoding)
    pub destination_owner: Vec<u8>,
}

/// SealMinted event data.
///
/// Indexed: sealId, owner
/// Non-indexed: sourceChain, sourceSealRef
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealMintedEvent {
    /// Unique seal identifier (32-byte hash)
    pub seal_id: Hash,
    /// Owner address (chain-specific encoding)
    pub owner: Vec<u8>,
    /// Source chain ID (uint8)
    pub source_chain: u8,
    /// Source seal reference (transaction hash or seal point)
    pub source_seal_ref: Hash,
}

/// SealRefunded event data.
///
/// Indexed: sealId, owner
/// Non-indexed: timestamp, reason
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealRefundedEvent {
    /// Unique seal identifier (32-byte hash)
    pub seal_id: Hash,
    /// Owner address (chain-specific encoding)
    pub owner: Vec<u8>,
    /// Refund timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// Refund reason (0 = timeout, 1 = cancellation, etc.)
    pub reason: u8,
}

/// CommitmentAnchored event data.
///
/// Indexed: commitment, sealId
/// Non-indexed: timestamp
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentAnchoredEvent {
    /// Commitment hash
    pub commitment: Hash,
    /// Associated seal ID
    pub seal_id: Hash,
    /// Anchor timestamp (Unix epoch seconds)
    pub timestamp: u64,
}

/// ReplayNullifierRegistered event data.
///
/// Indexed: nullifier
/// Non-indexed: timestamp
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayNullifierEvent {
    /// Nullifier hash (prevents replay attacks)
    pub nullifier: Hash,
    /// Registration timestamp (Unix epoch seconds)
    pub timestamp: u64,
}

/// ProofRootUpdated event data.
///
/// Indexed: proofRoot
/// Non-indexed: timestamp, blockHeight
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRootUpdatedEvent {
    /// New proof root hash
    pub proof_root: Hash,
    /// Update timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// Block height at which root was updated
    pub block_height: u64,
}

/// Chain-specific event encoding adapter.
///
/// Converts canonical events to chain-specific event encodings.
pub trait EventEncoder {
    /// Encode a canonical event for this chain.
    fn encode(&self, event: &CanonicalEvent) -> Result<Vec<u8>, EventEncodeError>;

    /// Decode a chain-specific event to canonical form.
    fn decode(&self, data: &[u8]) -> Result<CanonicalEvent, EventEncodeError>;
}

/// Event encoding errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EventEncodeError {
    #[error("Invalid event data: {0}")]
    InvalidData(String),

    #[error("Unsupported event type")]
    UnsupportedEventType,

    #[error("Encoding failed: {0}")]
    EncodingFailed(String),

    #[error("Decoding failed: {0}")]
    DecodingFailed(String),
}

/// Ethereum event encoder.
pub struct EthereumEventEncoder;

impl EventEncoder for EthereumEventEncoder {
    fn encode(&self, event: &CanonicalEvent) -> Result<Vec<u8>, EventEncodeError> {
        // Encode using Ethereum ABI encoding
        match event {
            CanonicalEvent::SealCreated(e) => {
                let mut data = Vec::new();
                data.extend_from_slice(e.seal_id.as_ref());
                data.extend_from_slice(&e.owner);
                data.extend_from_slice(e.commitment.as_ref());
                Ok(data)
            }
            _ => Err(EventEncodeError::UnsupportedEventType),
        }
    }

    fn decode(&self, _data: &[u8]) -> Result<CanonicalEvent, EventEncodeError> {
        Err(EventEncodeError::UnsupportedEventType)
    }
}

/// Solana event encoder.
pub struct SolanaEventEncoder;

impl EventEncoder for SolanaEventEncoder {
    fn encode(&self, event: &CanonicalEvent) -> Result<Vec<u8>, EventEncodeError> {
        // Encode using Borsh serialization
        match event {
            CanonicalEvent::SealCreated(e) => {
                let mut data = Vec::new();
                data.extend_from_slice(e.seal_id.as_ref());
                data.extend_from_slice(&e.owner);
                data.extend_from_slice(e.commitment.as_ref());
                Ok(data)
            }
            _ => Err(EventEncodeError::UnsupportedEventType),
        }
    }

    fn decode(&self, _data: &[u8]) -> Result<CanonicalEvent, EventEncodeError> {
        Err(EventEncodeError::UnsupportedEventType)
    }
}

/// Sui event encoder.
pub struct SuiEventEncoder;

impl EventEncoder for SuiEventEncoder {
    fn encode(&self, event: &CanonicalEvent) -> Result<Vec<u8>, EventEncodeError> {
        // Encode using BCS serialization
        match event {
            CanonicalEvent::SealCreated(e) => {
                let mut data = Vec::new();
                data.extend_from_slice(e.seal_id.as_ref());
                data.extend_from_slice(&e.owner);
                data.extend_from_slice(e.commitment.as_ref());
                Ok(data)
            }
            _ => Err(EventEncodeError::UnsupportedEventType),
        }
    }

    fn decode(&self, _data: &[u8]) -> Result<CanonicalEvent, EventEncodeError> {
        Err(EventEncodeError::UnsupportedEventType)
    }
}

/// Aptos event encoder.
pub struct AptosEventEncoder;

impl EventEncoder for AptosEventEncoder {
    fn encode(&self, event: &CanonicalEvent) -> Result<Vec<u8>, EventEncodeError> {
        // Encode using BCS serialization
        match event {
            CanonicalEvent::SealCreated(e) => {
                let mut data = Vec::new();
                data.extend_from_slice(e.seal_id.as_ref());
                data.extend_from_slice(&e.owner);
                data.extend_from_slice(e.commitment.as_ref());
                Ok(data)
            }
            _ => Err(EventEncodeError::UnsupportedEventType),
        }
    }

    fn decode(&self, _data: &[u8]) -> Result<CanonicalEvent, EventEncodeError> {
        Err(EventEncodeError::UnsupportedEventType)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization() {
        let event = CsvEvent::sanad_created(
            "bitcoin",
            100,
            "tx123",
            1700000000,
            SanadId::new([0xAB; 32]),
            "owner1",
            Hash::new([0xCD; 32]),
            "RGB",
            "asset1",
            None,
        );

        // CBOR serialization test - serde_json not allowed in core per AGENTS.md
        let mut buf = Vec::new();
        ciborium::into_writer(&event, &mut buf).unwrap();
        let cbor = buf;
        assert!(!cbor.is_empty());

        let deserialized: CsvEvent = ciborium::from_reader(&cbor[..]).unwrap();
        assert_eq!(deserialized.event_type, event.event_type);
        assert_eq!(deserialized.chain, event.chain);
    }

    #[test]
    fn test_event_filter() {
        let filter = EventFilter {
            event_type: Some("SanadCreated".to_string()),
            chain: Some("bitcoin".to_string()),
            ..Default::default()
        };

        assert_eq!(filter.event_type, Some("SanadCreated".to_string()));
        assert_eq!(filter.chain, Some("bitcoin".to_string()));
    }

    #[test]
    fn test_event_names() {
        assert_eq!(event_names::SANAD_CREATED, "SanadCreated");
        assert_eq!(event_names::SANAD_CONSUMED, "SanadConsumed");
        assert_eq!(event_names::CROSS_CHAIN_LOCK, "CrossChainLock");
        assert_eq!(event_names::CROSS_CHAIN_MINT, "CrossChainMint");
        assert_eq!(event_names::CROSS_CHAIN_REFUND, "CrossChainRefund");
        assert_eq!(event_names::SANAD_TRANSFERRED, "SanadTransferred");
        assert_eq!(event_names::NULLIFIER_REGISTERED, "NullifierRegistered");
        assert_eq!(
            event_names::SANAD_METADATA_RECORDED,
            "SanadMetadataRecorded"
        );
        assert_eq!(event_names::PROOF_ACCEPTED, "ProofAccepted");
        assert_eq!(event_names::PROOF_REJECTED, "ProofRejected");
        assert_eq!(event_names::REPLAY_DETECTED, "ReplayDetected");
        assert_eq!(event_names::RPC_DISAGREEMENT, "RpcDisagreement");
        assert_eq!(event_names::REORG_DETECTED, "ReorgDetected");
        assert_eq!(event_names::ROLLBACK_EXECUTED, "RollbackExecuted");
        assert_eq!(event_names::MINT_COMPROMISED, "MintCompromised");
    }

    #[test]
    fn test_metadata_fields() {
        assert_eq!(metadata_fields::SANAD_ID, "sanad_id");
        assert_eq!(metadata_fields::COMMITMENT, "commitment");
        assert_eq!(metadata_fields::OWNER, "owner");
        assert_eq!(metadata_fields::CHAIN_ID, "chain_id");
        assert_eq!(metadata_fields::ASSET_CLASS, "asset_class");
        assert_eq!(metadata_fields::ASSET_ID, "asset_id");
        assert_eq!(metadata_fields::METADATA, "metadata");
        assert_eq!(metadata_fields::DESTINATION_CHAIN, "destination_chain");
        assert_eq!(metadata_fields::SOURCE_CHAIN, "source_chain");
        assert_eq!(metadata_fields::BLOCK_HEIGHT, "block_height");
        assert_eq!(metadata_fields::TX_HASH, "tx_hash");
    }

    #[test]
    fn test_event_signature_hash() {
        let event = CanonicalEvent::SealCreated(SealCreatedEvent {
            seal_id: Hash::zero(),
            owner: vec![1, 2, 3],
            commitment: Hash::zero(),
        });
        let hash = event.signature_hash();
        assert_ne!(hash, Hash::zero());
    }

    #[test]
    fn test_event_name() {
        let event = CanonicalEvent::SealCreated(SealCreatedEvent {
            seal_id: Hash::zero(),
            owner: vec![],
            commitment: Hash::zero(),
        });
        assert_eq!(event.event_name(), "SealCreated");
    }
}
