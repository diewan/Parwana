//! Tagged hashing
//!
//! This module provides tagged hashing for domain separation.
//! Migrated from csv-core/src/tagged_hash.rs as part of hash-related modularization.

use super::{Hash, HashDomain};
use sha2::{Digest, Sha256};
use std::format;

/// The domain tag prefix for all CSV-related hashes
pub const CSV_TAG_PREFIX: &str = "urn:lnp-bp:csv:";

/// Tagged hash for domain separation (HashDomain-based)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaggedHash {
    /// The hash value
    pub hash: Hash,
    /// The domain tag
    pub domain: HashDomain,
}

/// Compute a tagged hash with HashDomain
pub fn tagged_hash(domain: HashDomain, data: &[u8]) -> TaggedHash {
    let tag = domain.tag();
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update(data);
    let result = hasher.finalize();
    TaggedHash {
        hash: Hash(result.into()),
        domain,
    }
}

/// Compute a tagged hash with domain separation (string-based).
///
/// `tagged_hash(tag, data) = sha256(sha256(tag) || sha256(tag) || data)`
///
/// This matches BIP-340 (Taproot) tagged hashing, preventing
/// cross-protocol hash collision attacks.
pub fn tagged_hash_str(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = {
        let mut hasher = Sha256::new();
        hasher.update(tag.as_bytes());
        hasher.finalize()
    };

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    let result = hasher.finalize();

    let mut array = [0u8; 32];
    array.copy_from_slice(&result);
    array
}

/// Compute a tagged hash with the CSV domain prefix.
///
/// Convenience wrapper: `csv_tagged_hash(name, data) = tagged_hash("urn:lnp-bp:csv:" || name, data)`
pub fn csv_tagged_hash(name: &str, data: &[u8]) -> [u8; 32] {
    let full_tag = format!("{}{}", CSV_TAG_PREFIX, name);
    tagged_hash_str(&full_tag, data)
}

impl TaggedHash {
    /// Get the hash bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.hash.as_bytes()
    }

    /// Get the domain
    pub fn domain(&self) -> HashDomain {
        self.domain
    }
}
