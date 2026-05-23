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

pub mod hash_registry;
pub mod registry;
pub mod tagged_hash;
pub mod domain_separation;
pub mod domain_hash;
pub mod domains;
pub mod merkle;
pub mod proof_commitments;
pub mod commit_mux;
pub mod canonical;
pub mod seal;
pub mod commitment;
pub mod sanad;
pub mod chain_id;
pub mod nullifier;
pub mod dag;

// Re-exports
pub use hash_registry::{
    HashDomain, Hash, HashParseError, DomainCategory,
    SealHash, CommitmentHash, SanadIdHash, NullifierHash, ReplayIdHash,
    VerificationHash, MerkleHash,
};
pub use registry::{TypedHashDomain, ContentHash, ProofHash, SealHash as TypedSealHash};
pub use tagged_hash::{TaggedHash, tagged_hash, tagged_hash_str, csv_tagged_hash, CSV_TAG_PREFIX};
pub use domain_separation::{DomainSeparator, derive_domain_separator};
pub use domain_hash::{Domain, DomainSeparatedHash};
pub use domains::{
    AptosAnchorDomain, BitcoinSealDomain, EthereumMintDomain, GenesisDomain,
    ProofBundleDomain, ReplayRegistryDomain, SchemaDomain, TransferCommitmentDomain, TransitionDomain,
};
pub use merkle::{MerkleProof, MerkleTree, verify_merkle_proof, verify_merkle_proofs_batch, compute_root_from_proof, StreamingMerkleBuilder, StreamingMerkleProofGenerator};
pub use commit_mux::{CommitMux, MuxLeaf, MuxProof, MerkleBranchNode, ProtocolId};
pub use canonical::{
    CanonicalError, to_canonical_cbor, from_canonical_cbor, canonical_hash,
    to_canonical_cbor_with_tag, to_canonical_cbor_with_checksum, from_canonical_cbor_with_checksum,
    from_canonical_cbor_full, CBOR_TAG_RANGE_START, CBOR_TAG_RANGE_END,
};
pub use canonical::cbor_tags;
pub use seal::{SealPoint, CommitAnchor, MAX_SEAL_ID_SIZE, MAX_ANCHOR_ID_SIZE, MAX_ANCHOR_METADATA_SIZE};
pub use commitment::{Commitment, COMMITMENT_VERSION};
pub use sanad::SanadId;
pub use chain_id::ChainId;
pub use nullifier::{SealConsumption, SealStatus, SealNullifier, DoubleSpendError};
pub use dag::{DAGNode, DAGSegment};
#[cfg(feature = "std")]
pub use nullifier::{OptimizedSealNullifier, BloomFilter, FilterStats};
