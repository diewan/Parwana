//! Celestia Adapter for CSV (Client-Side Validation)
#![allow(clippy::let_and_return)]
#![allow(clippy::collapsible_if)]
#![allow(unexpected_cfgs)]
#![deny(clippy::unwrap_used)]
//!
//! This adapter provides **Data Availability (DA)** for large Sanad proofs,
//! particularly STARK proofs that are too large for on-chain storage.
//!
//! ## Single Use Seal + Data Availability
//!
//! Celestia is ideal for CSV because:
//! - **Cheap DA**: Store large STARK proofs at ~1% the cost of Ethereum
//! - **Namespace isolation**: Each Sanad type gets its own namespace
//! - **Light client verification**: Users can verify proof availability without full nodes
//! - **Consensus-finalized**: Tendermint provides deterministic finality
//!
//! ## IPFS Integration
//!
//! For very large proofs (>1MB), the adapter uses IPFS as complementary storage:
//! - **Large data** goes to IPFS (content-addressed, distributed)
//! - **CID anchor** goes to Celestia (small commitment, ~100 bytes)
//! - **Sanad metadata** points to the anchor for verification
//!
//! This hybrid approach gives the best of both worlds:
//! - Celestia's DA guarantees for availability
//! - IPFS's cheaper storage for large data
//! - Content-addressing prevents tampering
//!
//! ## Architecture
//!
//! ```text
//! Sanad Proof (Large STARK)
//!         |
//!         +---> [Blob] ---> Celestia DA (if < 1MB)
//!         |
//!         +---> [IPFS] ---> CID ---> Celestia Anchor (if > 1MB)
//!         |
//!         +---> [Metadata] ---> Points to Proof Location
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use csv_celestia::{CelestiaClient, Namespace, ProofLocation};
//!
//! // Create a namespace for your Sanad proofs
//! let namespace = Namespace::bitcoin_stark();
//!
//! // Create a Celestia client (requires rpc feature for real RPC)
//! // let client = CelestiaClient::new("rpc.url").unwrap();
//!
//! // Post a large STARK proof - auto-routes to IPFS if > 1MB
//! // let proof_bytes = vec![/* large STARK proof */];
//! // let location: ProofLocation = client.store(proof_bytes, Some(namespace)).await.unwrap();
//!
//! // The location (ProofId or CID+anchor) is what gets anchored on-chain (small!)
//! // The actual proof lives on Celestia DA layer or IPFS (cheap!)
//! ```
//!
//! ## Fraud Proofs
//!
//! If data claimed to be available cannot be retrieved:
//! 1. Challenger posts fraud proof to Celestia fraud namespace
//! 2. Fraud proof references the original Sanad metadata
//! 3. Sanad is invalidated if fraud is proven
//!
//! ## Production
//!
//! Enable the `rpc` feature to use real Celestia and IPFS RPC calls:
//! ```toml
//! [dependencies]
//! csv-celestia = { version = "0.4", features = ["rpc"] }
//! ```

#![warn(missing_docs)]
#![allow(missing_docs)]
#![allow(dead_code)]

pub mod blob;
pub mod client;
pub mod commitment;
pub mod da_layer;
pub mod error;
pub mod ipfs;
pub mod metadata;
pub mod namespace;
pub mod proof_id;
pub mod rpc;
pub mod seal_protocol;
pub mod types;

#[cfg(feature = "rpc")]
pub mod node;

// Core types
pub use blob::{Blob, BlobWithMetadata};
pub use commitment::{BlobCommitment, CommitmentProof, FraudEvidence, FraudProof};
pub use error::CelestiaError;
pub use namespace::Namespace;
pub use proof_id::{ProofId, ProofLocation};
pub use types::{CelestiaAnchor, CelestiaFinalityProof, CelestiaMetadata, CelestiaSealPoint};

// Client and DA
pub use client::{CelestiaClient, ClientConfig, create_test_client};
pub use da_layer::{CelestiaDaLayer, CelestiaRpc, DaLayerConfig, DataAvailabilityLayer};

// IPFS
pub use ipfs::{HybridStorageInfo, IpfsCid, IpfsClient, IpfsReference, MockIpfsClient};

// Metadata
pub use metadata::{
    ChallengeRecord, MetadataBatch, ProofInfo, SanadMetadata, VerificationRequirements,
};

// Seal Protocol
pub use seal_protocol::{CelestiaSealProtocol, CelestiaSealProtocolBuilder};

// RPC (with feature flag)
#[cfg(feature = "rpc")]
pub use node::CelestiaNode;
#[cfg(feature = "rpc")]
pub use rpc::{CelestiaNode as CelestiaRpcClient, IpfsRpcClient};
