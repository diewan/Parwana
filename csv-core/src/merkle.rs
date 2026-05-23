//! Merkle tree and proof types for cryptographic inclusion proofs.
//!
//! This module provides generic Merkle tree construction and verification
//! used across chain adapters for SPV-style proofs.
//! Migrated to csv-hash - this file now re-exports from csv-hash.

// Re-export from csv-hash
pub use csv_hash::{MerkleProof, MerkleTree};
