use csv_accountability::{
    ASSURANCE_DIMENSIONS, AssuranceProfile, DimensionGateRule, DimensionResult, DimensionStatus,
    GateDisposition, GateOutcome, GateProfile, VerificationContextId,
};

fn profile(status: DimensionStatus) -> AssuranceProfile {
    AssuranceProfile {
        verification_context_id: VerificationContextId::from_digest([1; 32]),
        dimensions: ASSURANCE_DIMENSIONS
            .iter()
            .map(|dimension| DimensionResult {
                dimension: *dimension,
                status,
                assurance_level: None,
                reason_codes: vec!["org.diewan.reason.test.v1".into()],
                supporting_evidence_refs: vec![],
                limitations: vec![],
            })
            .collect(),
    }
}

fn gate() -> GateProfile {
    GateProfile {
        registry_id: "org.diewan.gate.production-deploy.v1".into(),
        version: 1,
        rules: ASSURANCE_DIMENSIONS
            .iter()
            .map(|dimension| DimensionGateRule {
                dimension: *dimension,
                satisfied: GateDisposition::Allow,
                not_satisfied: GateDisposition::Block,
                indeterminate: GateDisposition::Attention,
                not_applicable: GateDisposition::Allow,
            })
            .collect(),
    }
}

#[test]
fn all_four_dimension_statuses_are_representable() {
    for status in [
        DimensionStatus::Satisfied,
        DimensionStatus::NotSatisfied,
        DimensionStatus::Indeterminate,
        DimensionStatus::NotApplicable,
    ] {
        assert!(profile(status).validate().is_ok());
    }
}

#[test]
fn gate_derives_three_outcomes_without_hiding_dimensions() {
    let gate = gate();
    let pass = profile(DimensionStatus::Satisfied);
    assert_eq!(gate.evaluate(&pass).unwrap().outcome, GateOutcome::Pass);
    let attention = profile(DimensionStatus::Indeterminate);
    assert_eq!(
        gate.evaluate(&attention).unwrap().outcome,
        GateOutcome::AttentionRequired
    );
    let block = profile(DimensionStatus::NotSatisfied);
    assert_eq!(gate.evaluate(&block).unwrap().outcome, GateOutcome::Block);
    assert_eq!(block.dimensions.len(), ASSURANCE_DIMENSIONS.len());
}

#[test]
fn gate_result_binds_policy_context_and_assurance_profile() {
    let gate = gate();
    let profile = profile(DimensionStatus::Satisfied);
    let result = gate.evaluate(&profile).unwrap();
    assert_eq!(result.gate_profile_id, gate.id().unwrap());
    assert_eq!(
        result.verification_context_id,
        profile.verification_context_id
    );
    assert_eq!(result.assurance_profile_id, profile.id().unwrap());
}
