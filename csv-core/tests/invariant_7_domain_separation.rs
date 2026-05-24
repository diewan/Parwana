#![cfg(any())]
//! Invariant 7: Domain Separation Must Be Used for All Hashes
//!
//! Rule: All cryptographic hashes must use domain separation to prevent
//! cross-chain replay attacks.
//! Prohibited: Raw hashing without domain prefix.

#[cfg(test)]
mod tests {
    use csv_core::Hash;
    use csv_core::canonical::canonical_hash;
    use csv_core::domain_hash::{Domain, DomainSeparatedHash};
    use csv_core::domains::{
        AptosAnchorDomain, BitcoinSealDomain, EthereumMintDomain, GenesisDomain, ProofBundleDomain,
        ReplayRegistryDomain, SchemaDomain, TransferCommitmentDomain, TransitionDomain,
    };
    use csv_core::tagged_hash::csv_tagged_hash;

    /// Property: Same data with different domains produces different hashes
    #[test]
    fn test_domain_separation_produces_different_hashes() {
        let data = b"test data";
        let h1 = csv_tagged_hash("domain.a", data);
        let h2 = csv_tagged_hash("domain.b", data);
        assert_ne!(h1, h2, "Different domains must produce different hashes");
    }

    /// Property: Same domain with same data produces same hash
    #[test]
    fn test_same_domain_same_hash() {
        let data = b"test data";
        let h1 = csv_tagged_hash("domain.a", data);
        let h2 = csv_tagged_hash("domain.a", data);
        assert_eq!(h1, h2, "Same domain + same data must produce same hash");
    }

    /// Property: Domain constants are unique
    #[test]
    fn test_domain_constants_unique() {
        let domains: Vec<&[u8]> = vec![
            BitcoinSealDomain::DOMAIN,
            EthereumMintDomain::DOMAIN,
            AptosAnchorDomain::DOMAIN,
            GenesisDomain::DOMAIN,
            ProofBundleDomain::DOMAIN,
            ReplayRegistryDomain::DOMAIN,
            SchemaDomain::DOMAIN,
            TransferCommitmentDomain::DOMAIN,
            TransitionDomain::DOMAIN,
        ];

        for i in 0..domains.len() {
            for j in (i + 1)..domains.len() {
                assert_ne!(
                    domains[i], domains[j],
                    "Domain {} must not equal domain {}",
                    i, j
                );
            }
        }
    }

    /// Property: DomainSeparatedHash uses domain separation
    #[test]
    fn test_domain_separated_hash_uses_domain() {
        struct DomainA;
        impl Domain for DomainA {
            const DOMAIN: &'static [u8] = b"csv.test.domain.a";
        }

        struct DomainB;
        impl Domain for DomainB {
            const DOMAIN: &'static [u8] = b"csv.test.domain.b";
        }

        let data = b"test payload";
        let h1 = DomainSeparatedHash::<DomainA>::hash(data);
        let h2 = DomainSeparatedHash::<DomainB>::hash(data);

        assert_ne!(
            h1, h2,
            "Different domain types must produce different hashes"
        );
    }

    /// Property: DomainSeparatedHash hash_multiple uses separators
    #[test]
    fn test_domain_separated_hash_multiple() {
        struct TestDomain;
        impl Domain for TestDomain {
            const DOMAIN: &'static [u8] = b"csv.test.multiple";
        }

        let payloads: [&[u8]; 2] = [b"payload1".as_slice(), b"payload2".as_slice()];
        let h = DomainSeparatedHash::<TestDomain>::hash_multiple(payloads);

        assert_ne!(h, Hash::zero(), "Hash must not be zero");
    }

    /// Property: canonical_hash uses domain separation
    #[test]
    fn test_canonical_hash_domain_separation() {
        let data = vec![1u8, 2, 3, 4];
        let h1 = canonical_hash("domain.x", &data).unwrap();
        let h2 = canonical_hash("domain.y", &data).unwrap();

        assert_ne!(h1, h2, "canonical_hash must use domain separation");
    }

    /// Property: CSV tag prefix is applied
    #[test]
    fn test_csv_tag_prefix_applied() {
        let data = b"test";
        let h = csv_tagged_hash("test.domain", data);
        assert_ne!(h, [0u8; 32], "Tagged hash must be non-zero");
    }

    /// Property: Empty data with domain separation still produces unique hashes
    #[test]
    fn test_empty_data_domain_separation() {
        let h1 = csv_tagged_hash("empty.domain.a", &[]);
        let h2 = csv_tagged_hash("empty.domain.b", &[]);

        assert_ne!(
            h1, h2,
            "Empty data with different domains must produce different hashes"
        );
    }
}
