//! Proof bundle domain for cryptographic separation
//!
//! This domain is used for all proof bundle hashing operations,
//! preventing replay of proof bundles across different contexts.
//! Migrated from csv-core/src/domains/proof_bundle.rs as part of hash-related modularization.

use super::super::domain_hash::Domain;

/// Domain marker for proof bundle operations
pub struct ProofBundleDomain;

impl Domain for ProofBundleDomain {
    const DOMAIN: &'static [u8] = b"csv.proof.bundle.v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_bundle_domain() {
        assert_eq!(ProofBundleDomain::DOMAIN, b"csv.proof.bundle.v1");
    }
}
