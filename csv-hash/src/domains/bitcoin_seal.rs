//! Bitcoin seal domain for cryptographic separation
//!
//! This domain is used for all Bitcoin seal-related hashing operations,
//! preventing replay of Bitcoin proofs on other chains.
//! Migrated from csv-core/src/domains/bitcoin_seal.rs as part of hash-related modularization.

use super::super::domain_hash::Domain;

/// Domain marker for Bitcoin seal operations
pub struct BitcoinSealDomain;

impl Domain for BitcoinSealDomain {
    const DOMAIN: &'static [u8] = b"csv.bitcoin.seal.v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_seal_domain() {
        assert_eq!(BitcoinSealDomain::DOMAIN, b"csv.bitcoin.seal.v1");
    }
}
