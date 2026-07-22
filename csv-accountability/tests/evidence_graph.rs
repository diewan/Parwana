use csv_accountability::{
    EvidenceError, EvidenceKind, EvidenceNode, EvidenceNodeId, SourceLocator,
    validate_evidence_graph,
};

fn node(kind: EvidenceKind, relationships: Vec<EvidenceNodeId>) -> EvidenceNode {
    EvidenceNode {
        kind,
        producer_identity: b"producer:1".to_vec(),
        collected_at: 20,
        asserted_event_at: Some(10),
        content_digest: [3; 32],
        media_type: "application/cbor".into(),
        source_locator: SourceLocator::Disclosed("provider:object:1".into()),
        authenticity: None,
        disclosure_classification: "internal".into(),
        relationships,
    }
}

#[test]
fn bounded_acyclic_graph_validates() {
    let leaf = node(
        EvidenceKind::Claim {
            proposition_digest: [1; 32],
        },
        vec![],
    );
    let leaf_id = leaf.id().unwrap();
    let root = node(
        EvidenceKind::Observation {
            method_id: "org.diewan.observe.github-api.v1".into(),
        },
        vec![leaf_id],
    );
    assert_eq!(
        validate_evidence_graph(&[(root.id().unwrap(), root), (leaf_id, leaf)]),
        Ok(())
    );
}

#[test]
fn missing_edges_and_cycles_fail_closed() {
    let missing = node(
        EvidenceKind::Claim {
            proposition_digest: [1; 32],
        },
        vec![EvidenceNodeId::from_digest([9; 32])],
    );
    assert_eq!(
        validate_evidence_graph(&[(missing.id().unwrap(), missing)]),
        Err(EvidenceError::MissingRelationship)
    );

    let first_id = EvidenceNodeId::from_digest([7; 32]);
    let second_id = EvidenceNodeId::from_digest([8; 32]);
    let first = node(
        EvidenceKind::Claim {
            proposition_digest: [1; 32],
        },
        vec![second_id],
    );
    let second = node(
        EvidenceKind::Claim {
            proposition_digest: [2; 32],
        },
        vec![first_id],
    );
    assert_eq!(
        validate_evidence_graph(&[(first_id, first), (second_id, second)]),
        Err(EvidenceError::Cycle)
    );
}

#[test]
fn claim_observation_confusion_and_future_event_times_are_rejected() {
    let confused = node(
        EvidenceKind::Observation {
            method_id: "claim-from-executor".into(),
        },
        vec![],
    );
    assert_eq!(confused.validate(), Err(EvidenceError::SemanticConfusion));

    let mut future = node(
        EvidenceKind::Claim {
            proposition_digest: [1; 32],
        },
        vec![],
    );
    future.asserted_event_at = Some(21);
    assert_eq!(
        future.validate(),
        Err(EvidenceError::InvalidField("time_or_digest"))
    );
}

#[test]
fn v02_conflict_and_custody_nodes_have_distinct_canonical_bytes() {
    let subject = node(
        EvidenceKind::Claim {
            proposition_digest: [1; 32],
        },
        vec![],
    );
    let subject_id = subject.id().unwrap();
    let counterclaim = node(
        EvidenceKind::Counterclaim {
            subject_evidence_id: subject_id,
            proposition_digest: [2; 32],
        },
        vec![subject_id],
    );
    let counterclaim_id = counterclaim.id().unwrap();
    let mut conflict_relationships = vec![subject_id, counterclaim_id];
    conflict_relationships.sort_unstable();
    let contradiction = node(
        EvidenceKind::Contradiction {
            left_evidence_id: subject_id,
            right_evidence_id: counterclaim_id,
            analysis_digest: [4; 32],
        },
        conflict_relationships,
    );
    let custody = node(
        EvidenceKind::CustodyRecord {
            subject_evidence_id: subject_id,
            previous_custody_id: None,
            custodian_identity: b"custodian:1".to_vec(),
        },
        vec![subject_id],
    );

    let ids = [
        subject_id,
        counterclaim_id,
        contradiction.id().unwrap(),
        custody.id().unwrap(),
    ];
    for (index, id) in ids.iter().enumerate() {
        assert!(!ids[index + 1..].contains(id));
    }
    for value in [&counterclaim, &contradiction, &custody] {
        let canonical = value.canonical_bytes().unwrap();
        assert_eq!(EvidenceNode::from_canonical_bytes(&canonical).unwrap(), *value);
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            EvidenceNode::from_canonical_bytes(&trailing),
            Err(EvidenceError::MalformedEncoding)
        );
    }
    assert_eq!(
        validate_evidence_graph(&[
            (subject_id, subject),
            (counterclaim_id, counterclaim),
            (contradiction.id().unwrap(), contradiction),
            (custody.id().unwrap(), custody),
        ]),
        Ok(())
    );
}

#[test]
fn malformed_v02_relationships_fail_closed() {
    let subject_id = EvidenceNodeId::from_digest([1; 32]);
    let unrelated_id = EvidenceNodeId::from_digest([2; 32]);
    let counterclaim = node(
        EvidenceKind::Counterclaim {
            subject_evidence_id: subject_id,
            proposition_digest: [3; 32],
        },
        vec![unrelated_id],
    );
    assert_eq!(
        counterclaim.validate(),
        Err(EvidenceError::InvalidField("counterclaim"))
    );

    let contradiction = node(
        EvidenceKind::Contradiction {
            left_evidence_id: subject_id,
            right_evidence_id: subject_id,
            analysis_digest: [4; 32],
        },
        vec![subject_id],
    );
    assert_eq!(
        contradiction.validate(),
        Err(EvidenceError::InvalidField("contradiction"))
    );

    let custody = node(
        EvidenceKind::CustodyRecord {
            subject_evidence_id: subject_id,
            previous_custody_id: Some(subject_id),
            custodian_identity: b"custodian:1".to_vec(),
        },
        vec![subject_id],
    );
    assert_eq!(
        custody.validate(),
        Err(EvidenceError::InvalidField("custody_relationship"))
    );

    let subject = node(
        EvidenceKind::Claim {
            proposition_digest: [5; 32],
        },
        vec![],
    );
    let subject_id = subject.id().unwrap();
    let other = node(
        EvidenceKind::Claim {
            proposition_digest: [6; 32],
        },
        vec![],
    );
    let other_id = other.id().unwrap();
    let first = node(
        EvidenceKind::CustodyRecord {
            subject_evidence_id: subject_id,
            previous_custody_id: None,
            custodian_identity: b"custodian:1".to_vec(),
        },
        vec![subject_id],
    );
    let first_id = first.id().unwrap();
    let mut relationships = vec![other_id, first_id];
    relationships.sort_unstable();
    let wrong_chain = node(
        EvidenceKind::CustodyRecord {
            subject_evidence_id: other_id,
            previous_custody_id: Some(first_id),
            custodian_identity: b"custodian:2".to_vec(),
        },
        relationships,
    );
    assert_eq!(
        validate_evidence_graph(&[
            (subject_id, subject),
            (other_id, other),
            (first_id, first),
            (wrong_chain.id().unwrap(), wrong_chain),
        ]),
        Err(EvidenceError::InvalidRelationshipSemantics)
    );
}
