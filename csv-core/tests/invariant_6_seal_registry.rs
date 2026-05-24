#![cfg(any())]
//! Invariant 6: SealRegistry Must Be Checked Before Accepting Any Transfer
//!
//! Rule: `SealRegistry::check_consumed` must run before accepting any incoming transfer.
//! Prohibited: Skipping double-spend check for "fast path" optimizations.

#[cfg(test)]
mod tests {
    use csv_core::ChainId;
    use csv_core::Hash;
    use csv_core::replay_registry::{ReplayKey, ReplayRegistry};

    /// Property: New seal is not consumed initially
    #[test]
    fn test_new_seal_not_consumed() {
        let registry = ReplayRegistry::new();
        let seal_id = Hash::new([1u8; 32]);
        let replay_key = ReplayKey::new(
            seal_id,
            seal_id,
            seal_id,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        assert!(!registry.has_been_seen(&replay_key));
    }

    /// Property: Consumed seal is detected on subsequent checks
    #[test]
    fn test_consumed_seal_detected() {
        let mut registry = ReplayRegistry::new();
        let seal_id = Hash::new([1u8; 32]);
        let replay_key = ReplayKey::new(
            seal_id,
            seal_id,
            seal_id,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        registry
            .consume_if_unconsumed(replay_key.clone(), 1000)
            .unwrap();
        assert!(registry.has_been_seen(&replay_key));
    }

    /// Property: Double consumption is idempotent
    #[test]
    fn test_double_consumption_idempotent() {
        let mut registry = ReplayRegistry::new();
        let seal_id = Hash::new([1u8; 32]);
        let replay_key = ReplayKey::new(
            seal_id,
            seal_id,
            seal_id,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        let result1 = registry.consume_if_unconsumed(replay_key.clone(), 1000);
        assert!(result1.unwrap());

        let result2 = registry.consume_if_unconsumed(replay_key.clone(), 2000);
        assert!(!result2.unwrap());
    }

    /// Property: Different replay keys are independent
    #[test]
    fn test_different_replay_keys_independent() {
        let mut registry = ReplayRegistry::new();

        let seal_id = Hash::new([1u8; 32]);
        let key1 = ReplayKey::new(
            seal_id,
            seal_id,
            seal_id,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        let key2 = ReplayKey::new(
            seal_id,
            seal_id,
            seal_id,
            ChainId::new("bitcoin"),
            ChainId::new("solana"),
        );

        registry.consume_if_unconsumed(key1.clone(), 1000).unwrap();
        assert!(registry.has_been_seen(&key1));
        assert!(!registry.has_been_seen(&key2));
    }

    /// Property: Registry entries are trackable
    #[test]
    fn test_registry_entries_trackable() {
        let mut registry = ReplayRegistry::new();
        let seal_id = Hash::new([1u8; 32]);
        let replay_key = ReplayKey::new(
            seal_id,
            seal_id,
            seal_id,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        assert!(registry.entries().is_empty());

        registry.consume_if_unconsumed(replay_key, 1000).unwrap();
        assert!(!registry.entries().is_empty());
    }

    /// Property: Registry handles multiple seals
    #[test]
    fn test_registry_multiple_seals() {
        let mut registry = ReplayRegistry::new();

        for i in 0..10 {
            let seal_id = Hash::new([i as u8; 32]);
            let replay_key = ReplayKey::new(
                seal_id,
                seal_id,
                seal_id,
                ChainId::new("bitcoin"),
                ChainId::new("ethereum"),
            );
            registry
                .consume_if_unconsumed(replay_key, 1000 + i)
                .unwrap();
        }

        assert_eq!(registry.entries().len(), 10);
    }
}
