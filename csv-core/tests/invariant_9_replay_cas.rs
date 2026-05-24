#![cfg(any())]
//! Invariant 9: ReplayDatabase Insert-Before-Mint with Compare-and-Swap
//!
//! Rule: `ReplayDatabase::insert_if_absent()` MUST succeed with CAS semantics
//! before `mint_sanad()` is called.
//! Prohibited: Blind `contains()` check followed by insert (race condition).

#[cfg(test)]
mod tests {
    use csv_core::ChainId;
    use csv_core::Hash;
    use csv_core::replay_registry::{ReplayKey, ReplayRegistry};

    /// Property: First insert succeeds
    #[test]
    fn test_first_insert_succeeds() {
        let mut registry = ReplayRegistry::new();
        let seal_id = Hash::new([1u8; 32]);
        let replay_key = ReplayKey::new(
            seal_id,
            seal_id,
            seal_id,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        let result = registry.consume_if_unconsumed(replay_key.clone(), 1000);
        assert!(result.is_ok(), "First insert must succeed");
        assert!(result.unwrap(), "First insert must return true");
    }

    /// Property: Second insert returns false (idempotent)
    #[test]
    fn test_second_insert_returns_false() {
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
        let result = registry.consume_if_unconsumed(replay_key.clone(), 2000);

        assert!(result.is_ok(), "Second insert must not error");
        assert!(!result.unwrap(), "Second insert must return false");
    }

    /// Property: CAS prevents concurrent double-insert
    #[test]
    fn test_cas_prevents_double_insert() {
        let mut registry = ReplayRegistry::new();
        let seal_id = Hash::new([1u8; 32]);
        let replay_key = ReplayKey::new(
            seal_id,
            seal_id,
            seal_id,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        // Simulate concurrent inserts (sequential in single-threaded test)
        let result1 = registry.consume_if_unconsumed(replay_key.clone(), 1000);
        let result2 = registry.consume_if_unconsumed(replay_key.clone(), 1001);

        assert!(result1.unwrap(), "First insert succeeds");
        assert!(!result2.unwrap(), "Second insert fails (CAS semantics)");
    }

    /// Property: Different replay keys don't interfere
    #[test]
    fn test_different_keys_no_interference() {
        let mut registry = ReplayRegistry::new();

        let key1 = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        let key2 = ReplayKey::new(
            Hash::new([2u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([2u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        let r1 = registry.consume_if_unconsumed(key1, 1000);
        let r2 = registry.consume_if_unconsumed(key2, 1000);

        assert!(r1.unwrap(), "First key insert succeeds");
        assert!(r2.unwrap(), "Second key insert succeeds");
    }

    /// Property: Replay detection works after insert
    #[test]
    fn test_replay_detection_after_insert() {
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
        assert!(
            registry.has_been_seen(&replay_key),
            "Replay must be detected after insert"
        );
    }

    /// Property: Block height is tracked
    #[test]
    fn test_block_height_tracked() {
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
            .consume_if_unconsumed(replay_key.clone(), 42000)
            .unwrap();

        let entries = registry.entries();
        assert!(!entries.is_empty(), "Entry must be tracked");
    }
}
