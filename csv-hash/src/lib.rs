//! CSV Hash - Hash registry, tagged hashing, domain separation, Merkle construction, proof commitments
//!
//! This crate provides cryptographic hashing utilities for the CSV protocol.
//! All hash operations must use this crate to ensure domain separation and
//! cross-chain compatibility.

#![warn(missing_docs)]
#![allow(deprecated)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::range_plus_one)]
#![allow(clippy::format_in_format_args)]
#![allow(dead_code)]
#![allow(clippy::empty_line_after_doc_comments)]

pub mod chain_id;
pub mod commit_mux;
pub mod commitment;
pub mod dag;
pub mod domain_hash;
pub mod domain_separation;
pub mod domains;
pub mod hash_registry;
pub mod merkle;
pub mod nullifier;
pub mod proof_commitments;
pub mod registry;
pub mod sanad;
pub mod seal;
pub mod tagged_hash;

// Re-export canonical serialization from csv-codec
pub use chain_id::ChainId;
pub use commit_mux::{CommitMux, MerkleBranchNode, MuxLeaf, MuxProof, ProtocolId};
pub use commitment::{COMMITMENT_VERSION, Commitment};
pub use csv_codec::canonical;
pub use dag::{DAGNode, DAGSegment};
pub use domain_hash::{Domain, DomainSeparatedHash};
pub use domain_separation::{DomainSeparator, derive_domain_separator};
pub use domains::{
    AptosAnchorDomain, BitcoinSealDomain, EthereumMintDomain, GenesisDomain, ProofBundleDomain,
    ReplayRegistryDomain, SchemaDomain, TransferCommitmentDomain, TransitionDomain,
};
pub use hash_registry::{
    CommitmentHash, DomainCategory, Hash, HashDomain, HashParseError, MerkleHash, NullifierHash,
    ReplayIdHash, SanadIdHash, SealHash, VerificationHash,
};
pub use merkle::{
    MerkleProof, MerkleTree, StreamingMerkleBuilder, StreamingMerkleProofGenerator,
    compute_root_from_proof, verify_merkle_proof, verify_merkle_proofs_batch,
};
#[cfg(feature = "std")]
pub use nullifier::{BloomFilter, FilterStats, OptimizedSealNullifier};
pub use nullifier::{DoubleSpendError, SealConsumption, SealNullifier, SealStatus};
pub use registry::{ContentHash, ProofHash, SealHash as TypedSealHash, TypedHashDomain};
pub use sanad::SanadId;
pub use seal::{
    CommitAnchor, MAX_ANCHOR_ID_SIZE, MAX_ANCHOR_METADATA_SIZE, MAX_SEAL_ID_SIZE, SealPoint,
};
pub use tagged_hash::{CSV_TAG_PREFIX, TaggedHash, csv_tagged_hash, tagged_hash, tagged_hash_str};
