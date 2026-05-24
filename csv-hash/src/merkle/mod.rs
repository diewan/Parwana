//! Canonical Merkle tree implementation
//!
//! This module provides a canonical Merkle tree with:
//! - Ordered hashing (left < right deterministically)
//! - Leaf tagging (leaves are domain-separated from internal nodes)
//! - Internal node tagging (internal nodes use a different domain)
//! - Deterministic balancing (odd leaves are duplicated to maintain balance)
//! - Proof compression (sibling hashes only, no position metadata needed)
//!
//! ## Modules
//!
//! - `tree` - Core Merkle tree and proof types
//! - `verifier` - Standalone proof verification
//! - `streaming` - Incremental tree construction

pub mod streaming;
pub mod tree;
pub mod verifier;

// Re-exports for backward compatibility
pub use streaming::{StreamingMerkleBuilder, StreamingMerkleProofGenerator};
pub use tree::{MerkleProof, MerkleTree};
pub use verifier::{compute_root_from_proof, verify_merkle_proof, verify_merkle_proofs_batch};
