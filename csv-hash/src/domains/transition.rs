//! Transition Domain
//!
//! Domain-separated hashing for CSV contract transitions.
//! Migrated from csv-core/src/domains/transition.rs as part of hash-related modularization.

use super::super::domain_hash::Domain;

/// Transition domain for CSV contract transition hashing
pub struct TransitionDomain;

impl Domain for TransitionDomain {
    const DOMAIN: &'static [u8] = b"csv.transition.v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transition_domain_tag() {
        assert_eq!(TransitionDomain::DOMAIN, b"csv.transition.v1");
    }
}
