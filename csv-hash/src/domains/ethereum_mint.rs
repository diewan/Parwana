//! Ethereum mint domain for cryptographic separation
//!
//! This domain is used for all Ethereum mint-related hashing operations,
//! preventing replay of Ethereum proofs on other chains.
//! Migrated from csv-core/src/domains/ethereum_mint.rs as part of hash-related modularization.

use super::super::domain_hash::Domain;

/// Domain marker for Ethereum mint operations
pub struct EthereumMintDomain;

impl Domain for EthereumMintDomain {
    const DOMAIN: &'static [u8] = b"csv.ethereum.mint.v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_mint_domain() {
        assert_eq!(EthereumMintDomain::DOMAIN, b"csv.ethereum.mint.v1");
    }
}
