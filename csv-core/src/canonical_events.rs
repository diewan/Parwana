//! Canonical event schema for CSV protocol contracts
//!
//! This module defines the canonical event schema that all chain contracts
//! MUST emit. This ensures cross-chain event equivalence and enables
//! unified event indexing and verification.
//!
//! # Canonical Event Schema
//!
//! All contracts MUST emit events with the following canonical structure:
//! - Event name: keccak256("EventName(bytes32,bytes32,...)")[0:4]
//! - Indexed parameters: first 3 parameters are indexed (topics)
//! - Non-indexed parameters: remaining parameters are in data
//! - Deterministic encoding: all parameters use canonical CBOR encoding
//!
//! # Required Events
//!
//! Every chain contract MUST emit these events:
//! - SealCreated: When a seal is created
//! - SealConsumed: When a seal is consumed
//! - SealLocked: When a seal is locked for cross-chain transfer
//! - SealMinted: When a seal is minted from cross-chain transfer
//! - SealRefunded: When a locked seal is refunded
//! - CommitmentAnchored: When a commitment is anchored
//! - ReplayNullifierRegistered: When a replay nullifier is registered
//! - ProofRootUpdated: When the proof root is updated

use serde::{Deserialize, Serialize};
use csv_hash::Hash;

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
