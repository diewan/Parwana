//! Replay Protection Rules — Protocol Constitution Section 6
//!
//! Tests for ReplayId derivation and replay registry requirements.

#[cfg(test)]
mod tests {
    use csv_core::replay_registry::{ReplayRegistry, ReplayKey};
    use csv_core::Hash;
    use csv_core::ChainId;

    /// Property: ReplayKey is unique per transfer
    #[test]
    fn test_replay_key_uniqueness() {
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
        assert_ne!(key1.hash(), key2.hash(), "Different transfers must have different replay keys");
    }

    /// Property: ReplayKey includes chain pair
    #[test]
    fn test_replay_key_includes_chains() {
        let key1 = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        let key2 = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("solana"),
        );
        assert_ne!(key1.hash(), key2.hash(), "Different chain pairs must have different replay keys");
    }

    /// Property: Replay registry is append-only
    #[test]
    fn test_replay_registry_append_only() {
        let mut registry = ReplayRegistry::new();
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        
        let initial_count = registry.entries().len();
        registry.consume_if_unconsumed(key.clone(), 1000).unwrap();
        assert_eq!(registry.entries().len(), initial_count + 1);
        
        // Cannot remove entries (append-only)
        registry.consume_if_unconsumed(key.clone(), 2000).unwrap();
        assert_eq!(registry.entries().len(), initial_count + 1);
    }

    /// Property: Replay detection is immediate
    #[test]
    fn test_replay_detection_immediate() {
        let mut registry = ReplayRegistry::new();
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        
        registry.consume_if_unconsumed(key.clone(), 1000).unwrap();
        assert!(registry.has_been_seen(&key), "Replay must be detected immediately");
    }

    /// Property: ReplayKey hash is consistent
    #[test]
    fn test_replay_key_hash_consistent() {
        let key = ReplayKey::new(
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            Hash::new([1u8; 32]),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        let h1 = key.hash();
        let h2 = key.hash();
        assert_eq!(h1, h2, "ReplayKey hash must be consistent");
    }

    /// Property: Replay registry handles many entries
    #[test]
    fn test_replay_registry_many_entries() {
        let mut registry = ReplayRegistry::new();
        
        for i in 0..100 {
            let key = ReplayKey::new(
                Hash::new([i as u8; 32]),
                Hash::new([i as u8; 32]),
                Hash::new([i as u8; 32]),
                ChainId::new("bitcoin"),
                ChainId::new("ethereum"),
            );
            registry.consume_if_unconsumed(key, 1000 + i).unwrap();
        }
        
        assert_eq!(registry.entries().len(), 100);
    }
}
