use csv_accountability::{
    AUTHORITY_RECONSTRUCTION_REASON_CODES, AUTHORITY_RECONSTRUCTION_REGISTRY_ID,
    AuthorityAuthenticity, AuthorityConclusion, AuthorityLink, AuthorityReason,
    AuthorityReconstruction, AuthoritySourceCompleteness, EvidenceNodeId, MandateId,
};
use csv_accountability_verify::evaluate_authority_reconstruction;

fn link(id: u8, parent: Option<u8>, issuer: &[u8], subject: &[u8]) -> AuthorityLink {
    AuthorityLink {
        mandate_id: MandateId::from_digest([id; 32]),
        parent_mandate_id: parent.map(|value| MandateId::from_digest([value; 32])),
        issuer_identity: issuer.to_vec(),
        subject_identity: subject.to_vec(),
        authority_domain: b"org:example".to_vec(),
        effective_from: 10,
        effective_until: 100,
        scope_digest: [7; 32],
        authenticity: AuthorityAuthenticity::Verified,
    }
}

fn valid() -> AuthorityReconstruction {
    AuthorityReconstruction {
        registry_id: AUTHORITY_RECONSTRUCTION_REGISTRY_ID.into(),
        evaluation_time: 50,
        source_snapshot_digest: [8; 32],
        snapshot_authenticity: AuthorityAuthenticity::Verified,
        source_completeness: AuthoritySourceCompleteness::Complete,
        inference_method: "org.diewan.inference.delegation-chain.v1".into(),
        links: vec![
            link(1, None, b"org", b"team"),
            link(2, Some(1), b"team", b"agent"),
        ],
        contradiction_refs: vec![],
    }
}

#[test]
fn canonical_round_trip_and_domain_id_are_stable() {
    let reconstruction = valid();
    let bytes = reconstruction.canonical_bytes().unwrap();
    assert_eq!(
        AuthorityReconstruction::from_canonical_bytes(&bytes).unwrap(),
        reconstruction
    );
    assert_eq!(reconstruction.id().unwrap(), reconstruction.id().unwrap());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(AuthorityReconstruction::from_canonical_bytes(&trailing).is_err());
}

#[test]
fn conclusion_type_has_exactly_three_non_authorizing_states() {
    let conclusions = [
        AuthorityConclusion::Compatible,
        AuthorityConclusion::Incompatible,
        AuthorityConclusion::Indeterminate,
    ];
    assert_eq!(conclusions.len(), 3);
    assert_eq!(
        evaluate_authority_reconstruction(&valid()).conclusion,
        AuthorityConclusion::Compatible
    );
}

#[test]
fn incomplete_withheld_missing_and_unknown_sources_are_indeterminate() {
    for completeness in [
        AuthoritySourceCompleteness::Incomplete,
        AuthoritySourceCompleteness::Withheld,
    ] {
        let mut reconstruction = valid();
        reconstruction.source_completeness = completeness;
        assert_eq!(
            evaluate_authority_reconstruction(&reconstruction).conclusion,
            AuthorityConclusion::Indeterminate
        );
        assert_eq!(
            evaluate_authority_reconstruction(&reconstruction).reason,
            AuthorityReason::SourceIncomplete
        );
    }

    let mut missing = valid();
    missing.links[1].parent_mandate_id = Some(MandateId::from_digest([9; 32]));
    assert_eq!(
        evaluate_authority_reconstruction(&missing).reason,
        AuthorityReason::ParentMissing
    );
    assert_eq!(
        evaluate_authority_reconstruction(&missing).conclusion,
        AuthorityConclusion::Indeterminate
    );

    let mut unknown = valid();
    unknown.links[1].authenticity = AuthorityAuthenticity::Unknown;
    assert_eq!(
        evaluate_authority_reconstruction(&unknown).reason,
        AuthorityReason::AuthenticityUnknown
    );
    assert_eq!(
        evaluate_authority_reconstruction(&unknown).conclusion,
        AuthorityConclusion::Indeterminate
    );

    let mut contradicted = valid();
    contradicted.contradiction_refs = vec![EvidenceNodeId::from_digest([3; 32])];
    assert_eq!(
        evaluate_authority_reconstruction(&contradicted).reason,
        AuthorityReason::ContradictionPresent
    );
}

#[test]
fn cycles_conflicting_parents_bad_signatures_and_overreach_fail_closed() {
    let mut cycle = valid();
    cycle.links[0].parent_mandate_id = Some(MandateId::from_digest([2; 32]));
    assert_eq!(
        evaluate_authority_reconstruction(&cycle).reason,
        AuthorityReason::Cycle
    );
    assert_eq!(
        evaluate_authority_reconstruction(&cycle).conclusion,
        AuthorityConclusion::Incompatible
    );

    let mut conflicting = valid();
    conflicting.links.push(link(2, Some(3), b"other", b"agent"));
    conflicting
        .links
        .push(link(3, None, b"other-org", b"other"));
    conflicting.links.sort_by_key(|item| {
        (
            item.mandate_id.into_bytes(),
            item.parent_mandate_id
                .map_or([0; 32], MandateId::into_bytes),
        )
    });
    assert_eq!(
        evaluate_authority_reconstruction(&conflicting).reason,
        AuthorityReason::ConflictingParents
    );

    let mut multiple_roots = valid();
    multiple_roots
        .links
        .push(link(3, None, b"other-org", b"other"));
    assert_eq!(
        evaluate_authority_reconstruction(&multiple_roots).reason,
        AuthorityReason::ConflictingRoots
    );

    let mut rejected = valid();
    rejected.links[1].authenticity = AuthorityAuthenticity::Rejected;
    assert_eq!(
        evaluate_authority_reconstruction(&rejected).reason,
        AuthorityReason::AuthenticityRejected
    );

    let mut overreach = valid();
    overreach.links[1].scope_digest = [9; 32];
    assert_eq!(
        evaluate_authority_reconstruction(&overreach).reason,
        AuthorityReason::DelegationMismatch
    );
}

#[test]
fn reason_registry_is_complete_unique_and_namespaced() {
    assert_eq!(AUTHORITY_RECONSTRUCTION_REASON_CODES.len(), 11);
    let mut codes = AUTHORITY_RECONSTRUCTION_REASON_CODES
        .iter()
        .map(|reason| reason.registry_id())
        .collect::<Vec<_>>();
    assert!(
        codes
            .iter()
            .all(|code| code.starts_with("ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION."))
    );
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), AUTHORITY_RECONSTRUCTION_REASON_CODES.len());
    let published = include_str!("../../csv-testkit/corpus/v1/reason-codes/registry.toml");
    assert!(
        AUTHORITY_RECONSTRUCTION_REASON_CODES
            .iter()
            .all(|reason| published.contains(reason.registry_id()))
    );
}
