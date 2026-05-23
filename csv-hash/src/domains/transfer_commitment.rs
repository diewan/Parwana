//! Transfer commitment domain for cryptographic separation
//!
//! This domain is used for all transfer commitment hashing operations,
//! ensuring transfer commitments cannot be replayed across different contexts.
//! Migrated from csv-core/src/domains/transfer_commitment.rs as part of hash-related modularization.

use super::super::domain_hash::Domain;

/// Domain marker for transfer commitment operations
pub struct TransferCommitmentDomain;

impl Domain for TransferCommitmentDomain {
    const DOMAIN: &'static [u8] = b"csv.transfer.commitment.v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_commitment_domain() {
        assert_eq!(
            TransferCommitmentDomain::DOMAIN,
            b"csv.transfer.commitment.v1"
        );
    }
}
