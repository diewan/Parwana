//! Property tests for serialization roundtrip
//!
//! These tests verify that all critical types can be serialized
//! and deserialized without data loss.

#[cfg(test)]
mod tests {
    use csv_core::Hash;
    use csv_core::sanad::SanadId;
    use csv_core::transfer_state::{Locked, TransferData};
    use csv_core::protocol_version::ChainId;

    #[test]
    fn test_hash_serialization_roundtrip() {
        let hash = Hash::new([1u8; 32]);
        
        let serialized = serde_json::to_string(&hash).unwrap();
        let deserialized: Hash = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_sanad_id_serialization_roundtrip() {
        let sanad_id = SanadId(Hash::new([1u8; 32]));
        
        let serialized = serde_json::to_string(&sanad_id).unwrap();
        let deserialized: SanadId = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(sanad_id, deserialized);
    }

    #[test]
    fn test_transfer_state_serialization_roundtrip() {
        let data = TransferData::new(
            Hash::new([1u8; 32]),
            SanadId(Hash::new([2u8; 32])),
            ChainId::new("bitcoin"),
            ChainId::new("ethereum"),
            vec![3u8; 32],
            Hash::new([4u8; 32]),
        );
        
        let locked = Locked::new(data, 100, vec![5u8; 32]);
        
        let serialized = serde_json::to_string(&locked).unwrap();
        let deserialized: Locked = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(locked.lock_height, deserialized.lock_height);
        assert_eq!(locked.lock_tx_hash, deserialized.lock_tx_hash);
    }

    #[test]
    fn test_chain_id_serialization_roundtrip() {
        let chain_id = ChainId::new("bitcoin");
        
        let serialized = serde_json::to_string(&chain_id).unwrap();
        let deserialized: ChainId = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(chain_id.as_str(), deserialized.as_str());
    }
}
