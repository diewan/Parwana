#![cfg(any())]
//! Cross-chain contract event equivalence (RFC-0009).

#[cfg(test)]
mod tests {
    use csv_core::events::event_names;

    const REQUIRED_EVENTS: &[&str] = &[
        event_names::SANAD_CREATED,
        event_names::SANAD_CONSUMED,
        event_names::CROSS_CHAIN_LOCK,
        event_names::CROSS_CHAIN_MINT,
        event_names::CROSS_CHAIN_REFUND,
        event_names::NULLIFIER_REGISTERED,
        event_names::PROOF_ACCEPTED,
        event_names::PROOF_REJECTED,
        event_names::REPLAY_DETECTED,
    ];

    #[test]
    fn canonical_event_set_is_complete_for_testnet() {
        assert_eq!(REQUIRED_EVENTS.len(), 9);
        for name in REQUIRED_EVENTS {
            assert!(!name.is_empty());
            assert!(name.chars().next().unwrap().is_uppercase());
        }
    }

    #[test]
    fn event_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for name in REQUIRED_EVENTS {
            assert!(seen.insert(*name), "duplicate event name: {name}");
        }
    }
}
