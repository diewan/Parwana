#![allow(unexpected_cfgs)]
#![allow(clippy::let_and_return)]
#![allow(clippy::collapsible_if)]
//! P2P proof transport layer for the CSV protocol.
//!
//! This crate provides traits and implementations for distributing proof
//! bundles across peer-to-peer networks using Nostr as the primary transport.
//!
//! # Architecture
//!
//! - `ProofTransport` — trait defining the transport interface
//! - `ProofFilter` — filters for subscribing to specific proofs
//! - `NostrTransport` — Nostr-based implementation (feature-gated)
//! - `ProofRouter` — routes proof bundles to available transports

pub mod ipfs;
pub mod nostr;
pub mod proof_delivery;

#[cfg(feature = "ipfs")]
pub use ipfs::IpfsTransport;
#[cfg(feature = "nostr")]
pub use nostr::NostrTransport;
pub use proof_delivery::{ProofFilter, ProofRouter};

use csv_protocol::proof_taxonomy::ProofBundle;
use thiserror::Error;

/// Errors that can occur during P2P proof transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Nostr relay error: {0}")]
    Nostr(String),

    #[error("IPFS error: {0}")]
    Ipfs(String),

    #[error("No relays available")]
    NoRelays,

    #[error("Timeout waiting for response")]
    Timeout,

    #[error("Transport not initialized")]
    NotInitialized,

    #[error("Event publish failed")]
    PublishFailed,

    #[error("Invalid event: {0}")]
    InvalidEvent(String),
}

/// Unique identifier for a Nostr event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventId(pub String);

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl EventId {
    /// Create a new EventId from a hex string.
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    /// Get the event ID as a hex string.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// A delivered proof received from a P2P transport.
#[derive(Debug, Clone)]
pub struct DeliveredProof {
    /// The proof bundle.
    pub proof: ProofBundle,
    /// Source event ID (for deduplication).
    pub event_id: EventId,
    /// Author public key (hex-encoded).
    pub author_pubkey: String,
    /// Timestamp of the event.
    pub timestamp: u64,
}

/// The primary transport trait for P2P proof delivery.
///
/// Implementations can use Nostr, libp2p, or any other P2P protocol.
/// The trait supports both broadcasting proofs and subscribing to incoming proofs.
#[async_trait::async_trait]
pub trait ProofTransport: Send + Sync {
    /// Broadcast a proof bundle to all connected peers/relays.
    ///
    /// Returns the event ID if broadcast successfully.
    async fn broadcast_proof(&self, proof: &ProofBundle) -> Result<EventId, TransportError>;

    /// Subscribe to incoming proofs matching the given filter.
    ///
    /// Returns a stream of `DeliveredProof` objects. The caller is responsible
    /// for consuming the stream; the transport will continue delivering proofs
    /// until the stream is dropped or the transport is stopped.
    #[cfg(feature = "nostr")]
    async fn subscribe_proofs(
        &self,
        filter: ProofFilter,
    ) -> Result<tokio_stream::wrappers::ReceiverStream<DeliveredProof>, TransportError>
    where
        Self: Sized;

    /// Check if the transport is connected and ready.
    async fn is_connected(&self) -> bool;

    /// Get the transport name (e.g., "nostr").
    fn transport_name(&self) -> &str;

    /// Disconnect and clean up resources.
    async fn disconnect(&self);
}

/// Default Nostr relays used by the CSV protocol.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
    "wss://purplepag.es",
];

/// Serialize a proof bundle to JSON bytes.
pub fn serialize_proof(proof: &ProofBundle) -> Result<Vec<u8>, TransportError> {
    serde_json::to_vec(proof).map_err(|e| TransportError::Serialization(e.to_string()))
}

/// Deserialize a proof bundle from JSON bytes.
pub fn deserialize_proof(data: &[u8]) -> Result<ProofBundle, TransportError> {
    serde_json::from_slice(data).map_err(|e| TransportError::Serialization(e.to_string()))
}
