//! Genesis Domain
//!
//! Domain-separated hashing for CSV contract genesis.
//! Migrated from csv-core/src/domains/genesis.rs as part of hash-related modularization.

use super::super::domain_hash::Domain;

/// Genesis domain for CSV contract genesis hashing
pub struct GenesisDomain;

impl Domain for GenesisDomain {
    const DOMAIN: &'static [u8] = b"csv.genesis.v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_domain_tag() {
        assert_eq!(GenesisDomain::DOMAIN, b"csv.genesis.v1");
    }
}
