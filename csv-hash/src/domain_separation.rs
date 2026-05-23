//! Domain separation
//!
//! This module provides domain separation utilities for cryptographic operations.

use super::Hash;

/// Domain separator for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DomainSeparator([u8; 32]);

impl DomainSeparator {
    /// Create a new domain separator from a string
    pub fn from_string(s: &str) -> Self {
        Self(Hash::sha256(s.as_bytes()).0)
    }

    /// Get the domain separator bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a domain separator for a specific context
    pub fn derive_domain_separator(context: &str) -> Self {
        Self::from_string(context)
    }
}

/// Derive a domain separator
pub fn derive_domain_separator(context: &str) -> DomainSeparator {
    DomainSeparator::derive_domain_separator(context)
}
