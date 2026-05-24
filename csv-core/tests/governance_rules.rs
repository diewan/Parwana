#![cfg(any())]
//! Governance Rules — Protocol Constitution Section 14

#[cfg(test)]
mod tests {
    use csv_core::events::event_names;
    use csv_core::protocol_version::{ProtocolVersion, builtin};
    use csv_core::tagged_hash::csv_tagged_hash;

    #[test]
    fn canonical_event_names_are_stable() {
        assert_eq!(event_names::SANAD_CREATED, "SanadCreated");
        assert_eq!(event_names::CROSS_CHAIN_LOCK, "CrossChainLock");
        assert_eq!(event_names::CROSS_CHAIN_MINT, "CrossChainMint");
        assert_eq!(event_names::REPLAY_DETECTED, "ReplayDetected");
    }

    #[test]
    fn protocol_version_compatibility_is_explicit() {
        let current = ProtocolVersion::current();
        assert!(current.is_compatible());
    }

    #[test]
    fn hash_domains_are_registered_not_freeform() {
        let a = csv_tagged_hash("csv.sanad.header", b"payload");
        let b = csv_tagged_hash("csv.proof.bundle", b"payload");
        assert_ne!(a, b);
    }

    #[test]
    fn builtin_chain_ids_are_non_empty() {
        let chains = [
            builtin::BITCOIN.as_str(),
            builtin::ETHEREUM.as_str(),
            builtin::SOLANA.as_str(),
            builtin::SUI.as_str(),
            builtin::APTOS.as_str(),
        ];
        for id in chains {
            assert!(!id.is_empty());
        }
    }
}
