//! Canonical event schema for CSV protocol contracts
//!
//! This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::events::{
    CanonicalEvent, SealCreatedEvent, SealConsumedEvent, SealLockedEvent,
    SealMintedEvent, SealRefundedEvent, CommitmentAnchoredEvent,
    ReplayNullifierEvent, ProofRootUpdatedEvent,
    EventEncoder, EventEncodeError,
    EthereumEventEncoder, SolanaEventEncoder, SuiEventEncoder, AptosEventEncoder,
};
