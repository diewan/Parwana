//! Invariant 3: ConsignmentValidator runs before accepting Sanads

#[cfg(test)]
mod tests {
    use csv_core::consignment::{Consignment, CONSIGNMENT_VERSION};
    use csv_core::genesis::Genesis;
    use csv_core::Hash;
    use csv_core::validator::ConsignmentValidator;
    use csv_core::ChainId;

    fn minimal_consignment() -> Consignment {
        let schema = Hash::new([2u8; 32]);
        let genesis = Genesis::new(
            Hash::new([1u8; 32]),
            schema,
            vec![],
            vec![],
            vec![],
        );
        Consignment::new(genesis, vec![], vec![], vec![], schema)
    }

    #[test]
    fn validate_structure_accepts_minimal_consignment() {
        let c = minimal_consignment();
        assert!(c.validate_structure().is_ok());
    }

    #[test]
    fn consignment_validator_runs_before_acceptance() {
        let c = minimal_consignment();
        let report = ConsignmentValidator::new()
            .validate_consignment(&c, ChainId::new("bitcoin"));
        assert!(!report.steps.is_empty());
    }

    #[test]
    fn consignment_validator_rejects_bad_version() {
        let mut c = minimal_consignment();
        c.version = CONSIGNMENT_VERSION.wrapping_add(99);
        assert!(c.validate_structure().is_err());
        let report = ConsignmentValidator::new()
            .validate_consignment(&c, ChainId::new("bitcoin"));
        assert!(!report.passed);
    }
}
