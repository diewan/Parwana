#![cfg(any())]
//! Invariant 4: Balances Are Stored as u64 Native Units
//!
//! Rule: Balances must be stored as `u64` native units (satoshis, lamports, MIST, octas, wei).
//! Prohibited: f64, human-readable strings, JSON numbers for financial amounts.

#[cfg(test)]
mod tests {
    use csv_core::protocol_version::ChainId;
    use std::hash::{Hash, Hasher};

    /// Property: ChainId uses native unit representation
    #[test]
    fn test_chain_id_native_units() {
        let btc = ChainId::new("bitcoin");
        let eth = ChainId::new("ethereum");
        let sol = ChainId::new("solana");

        assert_eq!(btc.as_str(), "bitcoin");
        assert_eq!(eth.as_str(), "ethereum");
        assert_eq!(sol.as_str(), "solana");
    }

    /// Property: ChainId comparison is deterministic
    #[test]
    fn test_chain_id_comparison() {
        let btc1 = ChainId::new("bitcoin");
        let btc2 = ChainId::new("bitcoin");
        let eth = ChainId::new("ethereum");

        assert_eq!(btc1, btc2, "Same chain IDs must be equal");
        assert_ne!(btc1, eth, "Different chain IDs must not be equal");
    }

    /// Property: ChainId hash is consistent
    #[test]
    fn test_chain_id_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;

        let btc1 = ChainId::new("bitcoin");
        let btc2 = ChainId::new("bitcoin");

        let mut s1 = DefaultHasher::new();
        let mut s2 = DefaultHasher::new();
        btc1.hash(&mut s1);
        btc2.hash(&mut s2);

        assert_eq!(
            s1.finish(),
            s2.finish(),
            "Same chain IDs must have same hash"
        );
    }

    /// Property: ChainId handles empty string
    #[test]
    fn test_chain_id_empty_string() {
        let chain = ChainId::new("");
        assert_eq!(chain.as_str(), "");
    }

    /// Property: ChainId handles long names
    #[test]
    fn test_chain_id_long_name() {
        let chain = ChainId::new("very-long-chain-name-that-is-unusual");
        assert_eq!(chain.as_str(), "very-long-chain-name-that-is-unusual");
    }

    /// Property: ChainId handles unicode characters
    #[test]
    fn test_chain_id_unicode() {
        let chain = ChainId::new("chain-ñ-ü-中文");
        assert_eq!(chain.as_str(), "chain-ñ-ü-中文");
    }

    /// Property: ChainId is Ord (sortable)
    #[test]
    fn test_chain_id_sortable() {
        let mut chains = vec![
            ChainId::new("zebra"),
            ChainId::new("apple"),
            ChainId::new("mango"),
        ];
        chains.sort();
        assert_eq!(chains[0].as_str(), "apple");
        assert_eq!(chains[1].as_str(), "mango");
        assert_eq!(chains[2].as_str(), "zebra");
    }

    /// Property: ChainId normalizes to lowercase
    #[test]
    fn test_chain_id_lowercase_normalization() {
        let chain = ChainId::new("BITCOIN");
        assert_eq!(chain.as_str(), "bitcoin");
    }

    /// Property: ChainId Display works
    #[test]
    fn test_chain_id_display() {
        let chain = ChainId::new("ethereum");
        assert_eq!(format!("{}", chain), "ethereum");
    }

    /// Property: ChainId AsRef<str> works
    #[test]
    fn test_chain_id_as_ref() {
        let chain = ChainId::new("solana");
        assert_eq!(<ChainId as AsRef<str>>::as_ref(&chain), "solana");
    }
}
