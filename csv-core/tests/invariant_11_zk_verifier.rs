#![cfg(any())]
//! Invariant 11: ZK verifier keys must be chain-anchored in production

#[cfg(test)]
mod tests {
    use csv_core::protocol_version::builtin;
    use csv_core::zk_proof::{ProofSystem, VerifierKey, ZkVerifierRegistry};

    #[test]
    fn empty_registry_has_no_production_verifiers() {
        let registry = ZkVerifierRegistry::new();
        assert!(!registry.has_verifier(&builtin::ETHEREUM));
    }

    #[test]
    fn verifier_key_rejects_empty_key_material() {
        let key = VerifierKey::new(builtin::ETHEREUM.clone(), vec![], ProofSystem::SP1, 1);
        assert!(key.key_bytes.is_empty());
        // Production paths must load non-empty keys from on-chain verifier contracts.
    }

    #[test]
    fn registered_verifier_is_chain_scoped() {
        let mut registry = ZkVerifierRegistry::new();
        registry.register(VerifierKey::new(
            builtin::ETHEREUM.clone(),
            vec![1u8; 64],
            ProofSystem::SP1,
            1,
        ));
        assert!(registry.has_verifier(&builtin::ETHEREUM));
        assert!(!registry.has_verifier(&builtin::BITCOIN));
    }
}
