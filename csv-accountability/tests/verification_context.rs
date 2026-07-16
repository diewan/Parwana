use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ContextBoundOutput,
    ContextExtension, VerificationContext,
};

fn context() -> VerificationContext {
    VerificationContext {
        context_version: ACCOUNTABILITY_OBJECT_VERSION,
        protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
        evaluation_time: 1_750_000_000,
        verifier_policy_digest: [1; 32],
        trust_package_digest: [2; 32],
        revocation_snapshot_digest: [3; 32],
        algorithm_policy_digest: [4; 32],
        external_evidence_policy_digest: [5; 32],
        assurance_thresholds_digest: [6; 32],
        extensions: vec![ContextExtension {
            registry_id: "org.diewan.context.fixed-clock.v1".into(),
            parameters_digest: [7; 32],
        }],
    }
}

#[test]
fn every_context_input_is_hash_bound() {
    let original = context();
    let original_id = original.id().unwrap();
    let mut mutations = Vec::new();
    let mut value = original.clone();
    value.evaluation_time += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.verifier_policy_digest[0] ^= 1;
    mutations.push(value);
    let mut value = original.clone();
    value.trust_package_digest[0] ^= 1;
    mutations.push(value);
    let mut value = original.clone();
    value.revocation_snapshot_digest[0] ^= 1;
    mutations.push(value);
    let mut value = original.clone();
    value.algorithm_policy_digest[0] ^= 1;
    mutations.push(value);
    let mut value = original.clone();
    value.external_evidence_policy_digest[0] ^= 1;
    mutations.push(value);
    let mut value = original.clone();
    value.assurance_thresholds_digest[0] ^= 1;
    mutations.push(value);
    let mut value = original.clone();
    value.extensions[0].parameters_digest[0] ^= 1;
    mutations.push(value);

    for mutation in mutations {
        assert_ne!(mutation.id().unwrap(), original_id);
    }
}

#[test]
fn fixed_clock_is_repeatable_and_output_echoes_context() {
    let context = context();
    assert_eq!(context.id(), context.id());
    let output = ContextBoundOutput::new(&context, "indeterminate").unwrap();
    assert_eq!(output.verification_context_id, context.id().unwrap());
}
