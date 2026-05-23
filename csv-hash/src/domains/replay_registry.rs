//! Replay registry domain for cryptographic separation
//!
//! This domain is used for all replay registry hashing operations,
//! ensuring replay protection keys cannot be forged or replayed.
//! Migrated from csv-core/src/domains/replay_registry.rs as part of hash-related modularization.

use super::super::domain_hash::Domain;

/// Domain marker for replay registry operations
pub struct ReplayRegistryDomain;

impl Domain for ReplayRegistryDomain {
    const DOMAIN: &'static [u8] = b"csv.replay.registry.v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_registry_domain() {
        assert_eq!(ReplayRegistryDomain::DOMAIN, b"csv.replay.registry.v1");
    }
}
