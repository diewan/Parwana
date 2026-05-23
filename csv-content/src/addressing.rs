//! Content addressing
//!
//! This module provides content addressing utilities.

use csv_hash::Hash;

/// Content address (hash of content)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentAddress(Hash);

impl ContentAddress {
    /// Create a new content address from hash
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Get the underlying hash
    pub fn hash(&self) -> Hash {
        self.0
    }

    /// Get the address bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Compute content address from data
pub fn compute_content_address(data: &[u8]) -> ContentAddress {
    ContentAddress::new(Hash::sha256(data))
}
