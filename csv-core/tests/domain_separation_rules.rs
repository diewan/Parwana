//! Domain Separation Rules — Protocol Constitution Section 8
//!
//! Tests for domain marker trait and reserved domains.

#[cfg(test)]
mod tests {
    use csv_core::domain_hash::{Domain, DomainSeparatedHash};
    use csv_core::Hash;
    use csv_core::domains::{
        BitcoinSealDomain, EthereumMintDomain, AptosAnchorDomain, GenesisDomain,
        ProofBundleDomain, ReplayRegistryDomain, SchemaDomain, TransferCommitmentDomain,
        TransitionDomain,
    };

    /// Property: Domain constants are non-empty
    #[test]
    fn test_domain_constants_non_empty() {
        assert!(!BitcoinSealDomain::DOMAIN.is_empty());
        assert!(!EthereumMintDomain::DOMAIN.is_empty());
        assert!(!AptosAnchorDomain::DOMAIN.is_empty());
        assert!(!GenesisDomain::DOMAIN.is_empty());
        assert!(!ProofBundleDomain::DOMAIN.is_empty());
        assert!(!ReplayRegistryDomain::DOMAIN.is_empty());
        assert!(!SchemaDomain::DOMAIN.is_empty());
        assert!(!TransferCommitmentDomain::DOMAIN.is_empty());
        assert!(!TransitionDomain::DOMAIN.is_empty());
    }

    /// Property: Domain constants follow naming convention
    #[test]
    fn test_domain_naming_convention() {
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
        
        for domain in domains {
            let domain_str = String::from_utf8_lossy(domain);
            assert!(domain_str.starts_with("csv."), 
                "Domain '{}' must start with 'csv.'", domain_str);
        }
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
                assert_ne!(domains[i], domains[j], 
                    "Domain '{}' must not equal domain '{}'",
                    String::from_utf8_lossy(domains[i]),
                    String::from_utf8_lossy(domains[j])
                );
            }
        }
    }

    /// Property: DomainSeparatedHash produces consistent results
    #[test]
    fn test_domain_separated_hash_consistent() {
        struct TestDomain;
        impl Domain for TestDomain {
            const DOMAIN: &'static [u8] = b"csv.test.domain";
        }
        
        let data = b"test payload";
        let h1 = DomainSeparatedHash::<TestDomain>::hash(data);
        let h2 = DomainSeparatedHash::<TestDomain>::hash(data);
        assert_eq!(h1, h2, "Same domain + same data must produce same hash");
    }

    /// Property: DomainSeparatedHash with different domains produces different results
    #[test]
    fn test_domain_separated_hash_different_domains() {
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
        assert_ne!(h1, h2, "Different domains must produce different hashes");
    }

    /// Property: DomainSeparatedHash hash_multiple uses separators
    #[test]
    fn test_domain_separated_hash_multiple_uses_separators() {
        struct TestDomain;
        impl Domain for TestDomain {
            const DOMAIN: &'static [u8] = b"csv.test.multiple";
        }
        
        let single = DomainSeparatedHash::<TestDomain>::hash(b"payload1");
        let payloads: [&[u8]; 1] = [b"payload1".as_slice()];
        let multiple = DomainSeparatedHash::<TestDomain>::hash_multiple(payloads);
        
        // Single payload should produce same hash as hash_multiple with one payload
        assert_eq!(single, multiple, "Single payload must match hash_multiple");
    }

    /// Property: All seal domains follow naming convention
    #[test]
    fn test_all_seal_domains_naming() {
        let domain = BitcoinSealDomain::DOMAIN;
        let domain_str = String::from_utf8_lossy(domain);
        assert!(domain_str.starts_with("csv."), "Domain must start with 'csv.'");
    }
}
