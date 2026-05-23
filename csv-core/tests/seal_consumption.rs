//! Property tests for seal consumption
//!
//! These tests verify that seals can only be consumed once,
//! and that double-spend attacks are prevented using the replay registry.

#[cfg(test)]
mod tests {
    use csv_core::seal::SealPoint;
    use csv_core::Hash;
    use csv_core::replay_registry::{ReplayRegistry, ReplayKey};
    use csv_core::ChainId;

    /// Property: A seal can only be consumed once
    #[test]
    fn test_seal_consumption_idempotency() {
        let mut registry = ReplayRegistry::new();

        // Create a seal point
        let _seal_point = SealPoint::new(vec![1u8; 16], Some(1)).unwrap();
        let seal_id = Hash::new([1u8; 32]);

        // Create a replay key for this seal
        let replay_key = ReplayKey::new(
            seal_id,
            seal_id, // seal_id (simplified)
            seal_id, // commitment_hash (simplified)
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        // First consumption should succeed (seal not yet consumed)
        let is_consumed = registry.has_been_seen(&replay_key);
        assert!(!is_consumed, "Seal should not be consumed initially");

        // Consume the seal using atomic consume_if_unconsumed
        let result = registry.consume_if_unconsumed(replay_key.clone(), 1000);
        assert!(result.is_ok(), "First consumption should succeed");
        assert!(result.unwrap(), "First consumption should return true");

        // Second consumption attempt should be idempotent (return false, not error)
        let result_2 = registry.consume_if_unconsumed(replay_key.clone(), 2000);
        assert!(result_2.is_ok(), "Second consumption should not error");
        assert!(!result_2.unwrap(), "Second consumption should return false (idempotent)");
    }

    /// Property: Each seal has a unique identifier
    #[test]
    fn test_seal_uniqueness() {
        let seal1 = SealPoint::new(vec![1u8; 16], Some(1)).unwrap();
        let seal2 = SealPoint::new(vec![2u8; 16], Some(2)).unwrap();
        
        assert_ne!(seal1.id, seal2.id, "Different seals should have different IDs");
    }

    /// Property: Seal consumption is tracked via nullifier registration
    #[test]
    fn test_seal_consumption_tracking() {
        let mut registry = ReplayRegistry::new();

        let seal_id = Hash::new([1u8; 32]);
        let commitment_hash = Hash::new([2u8; 32]);

        // Create replay key
        let replay_key = ReplayKey::new(
            seal_id,
            seal_id, // seal_id
            commitment_hash,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        // Initially, no replay detected
        assert!(!registry.has_been_seen(&replay_key));

        // Consume the seal using atomic consume_if_unconsumed
        registry.consume_if_unconsumed(replay_key.clone(), 1000).unwrap();

        // Now replay should be detected
        assert!(registry.has_been_seen(&replay_key));

        // Verify the nullifier is registered
        let entries = registry.entries();
        assert!(!entries.is_empty(), "Replay registry should have entries after consumption");
    }

    /// Property: Different chains have independent seal consumption
    #[test]
    fn test_cross_chain_seal_independence() {
        let mut registry = ReplayRegistry::new();

        let seal_id = Hash::new([1u8; 32]);
        let commitment_hash = Hash::new([2u8; 32]);

        // Consume seal on Bitcoin -> Ethereum
        let replay_key_1 = ReplayKey::new(
            seal_id,
            seal_id,
            commitment_hash,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        registry.consume_if_unconsumed(replay_key_1, 1000).unwrap();

        // Same seal on different destination chain should be considered different
        let replay_key_2 = ReplayKey::new(
            seal_id,
            seal_id,
            commitment_hash,
            ChainId::new("bitcoin"),
            ChainId::new("solana"), // Different destination
        );

        // Should not be a replay since destination chain is different
        assert!(!registry.has_been_seen(&replay_key_2));
    }

    /// Property: Different commitment hashes create different replay keys
    #[test]
    fn test_commitment_hash_uniqueness() {
        let seal_id = Hash::new([1u8; 32]);
        let commitment_hash_1 = Hash::new([2u8; 32]);
        let commitment_hash_2 = Hash::new([3u8; 32]);
        
        let replay_key_1 = ReplayKey::new(
            seal_id,
            seal_id,
            commitment_hash_1,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        
        let replay_key_2 = ReplayKey::new(
            seal_id,
            seal_id,
            commitment_hash_2,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );
        
        // Different commitment hashes should produce different replay keys
        assert_ne!(replay_key_1.hash(), replay_key_2.hash());
    }

    /// Property: Replay registry prevents double-spend across multiple attempts
    #[test]
    fn test_double_spend_prevention() {
        let mut registry = ReplayRegistry::new();

        let seal_id = Hash::new([1u8; 32]);
        let commitment_hash = Hash::new([2u8; 32]);

        let replay_key = ReplayKey::new(
            seal_id,
            seal_id,
            commitment_hash,
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
        );

        // First attempt - should succeed
        let result_1 = registry.consume_if_unconsumed(replay_key.clone(), 1000);
        assert!(result_1.is_ok(), "First consumption should succeed");
        assert!(result_1.unwrap(), "First consumption should return true");

        // Second attempt - should be idempotent (return false, not error)
        let result_2 = registry.consume_if_unconsumed(replay_key.clone(), 2000);
        assert!(result_2.is_ok(), "Second consumption should not error");
        assert!(!result_2.unwrap(), "Second consumption should return false (idempotent)");

        // Third attempt - should also be idempotent
        let result_3 = registry.consume_if_unconsumed(replay_key.clone(), 3000);
        assert!(result_3.is_ok(), "Third consumption should not error");
        assert!(!result_3.unwrap(), "Third consumption should return false (idempotent)");
    }
}
