//! Aptos anchor domain for cryptographic separation
//!
//! This domain is used for all Aptos anchor-related hashing operations,
//! preventing replay of Aptos proofs on other chains.
//! Migrated from csv-core/src/domains/aptos_anchor.rs as part of hash-related modularization.

use super::super::domain_hash::Domain;

/// Domain marker for Aptos anchor operations
pub struct AptosAnchorDomain;

impl Domain for AptosAnchorDomain {
    const DOMAIN: &'static [u8] = b"csv.aptos.anchor.v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aptos_anchor_domain() {
        assert_eq!(AptosAnchorDomain::DOMAIN, b"csv.aptos.anchor.v1");
    }
}
