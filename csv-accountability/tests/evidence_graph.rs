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
