//! Property tests for replay resistance
//!
//! These tests verify that the protocol prevents replay attacks
//! across chains and over time.

#[cfg(test)]
mod tests {
    use csv_core::replay_registry::{ReplayRegistry, ReplayKey, ReplayEntry};
    use csv_core::Hash;
    use csv_core::sanad::SanadId;

    #[test]
    fn test_replay_detection() {
        let mut registry = ReplayRegistry::new();
        
        let proof_hash = Hash::new([1u8; 32]);
        let seal_id = Hash::new([2u8; 32]);
        let commitment_hash = Hash::new([3u8; 32]);
        
        let key = ReplayKey::new(proof_hash, seal_id, commitment_hash, "bitcoin", "ethereum");
        
        // First submission should succeed
        let entry = ReplayEntry::new(proof_hash, seal_id, commitment_hash, "bitcoin", "ethereum", 1000);
        let result = registry.record(key.clone(), entry.clone());
        assert!(result.is_ok());
        
        // Replay should be detected
        let result = registry.record(key, entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_cross_chain_replay_prevention() {
        // A proof from bitcoin->ethereum should not be replayable on ethereum->bitcoin
        let mut registry = ReplayRegistry::new();
        
        let proof_hash = Hash::new([1u8; 32]);
        let seal_id = Hash::new([2u8; 32]);
        let commitment_hash = Hash::new([3u8; 32]);
        
        let key1 = ReplayKey::new(proof_hash, seal_id, commitment_hash, "bitcoin", "ethereum");
        let key2 = ReplayKey::new(proof_hash, seal_id, commitment_hash, "ethereum", "bitcoin");
        
        let entry = ReplayEntry::new(proof_hash, seal_id, commitment_hash, "bitcoin", "ethereum", 1000);
        
        // First submission should succeed
        registry.record(key1, entry.clone()).unwrap();
        
        // Cross-chain replay should also be detected
        let result = registry.record(key2, entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_replay_registry_persistence() {
        // Replay registry should persist across restarts
        // This is a placeholder - actual implementation would test persistence
    }
}
