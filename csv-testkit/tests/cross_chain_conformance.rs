//! Cross-chain conflict-domain isolation (PAR-XCHAIN-001).
//!
//! Runs the one abstract conformance suite against every advertised Stage 5
//! adapter, then adds the tests that only exist *between* chains:
//!
//! - the same source cannot authorize closure-valid successors on two
//!   destination chains;
//! - a proof cannot be replayed across chains, contracts, networks,
//!   deployments, or proof kinds;
//! - source closure and destination settlement stay separate invariants.
//!
//! Passing this file also writes the machine-readable support matrix, so the
//! matrix can never advertise a chain the suite did not just verify.

mod fixtures;

use csv_hash::Hash;
use csv_protocol::{ClosureDimensionStatus, ClosureTrustMode, SourceNullifier};
use csv_testkit::closure_conformance::{
    CLOSURE_CONFORMANCE_SUITE_VERSION, ClosureConformanceAdapter, ClosureScenario,
    ClosureSupportMatrix, assert_shared_conflict_identity, conformance_equivocating_successor,
    conformance_source, conformance_successor, run_closure_conformance,
};

use fixtures::{AptosFixture, EthereumFixture, SolanaFixture, SuiFixture};

/// Path the support matrix is published to, relative to the crate root.
const SUPPORT_MATRIX_PATH: &str = "conformance/stage5-closure-support-matrix.json";

#[test]
fn every_advertised_chain_passes_the_same_conformance_suite() {
    let evidence = vec![
        run_closure_conformance(&EthereumFixture::new()),
        run_closure_conformance(&SuiFixture::new()),
        run_closure_conformance(&AptosFixture::new()),
        run_closure_conformance(&SolanaFixture::new()),
    ];

    assert_eq!(evidence.len(), 4, "all four Stage 5 chains must be covered");
    for entry in &evidence {
        assert!(
            !entry.finality_establishing_trust_modes.is_empty(),
            "{}: must declare a finality-establishing trust mode",
            entry.chain_id
        );
    }

    // Publish the matrix only after every chain has passed.
    let matrix = ClosureSupportMatrix {
        suite_version: CLOSURE_CONFORMANCE_SUITE_VERSION,
        chains: evidence,
    };
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(SUPPORT_MATRIX_PATH);
    std::fs::create_dir_all(path.parent().expect("matrix path has a parent"))
        .expect("matrix directory must be creatable");
    let json = serde_json::to_string_pretty(&matrix).expect("matrix must serialize");
    std::fs::write(&path, format!("{json}\n")).expect("matrix must be writable");

    // The published matrix must round-trip, so a consumer reads what we wrote.
    let reloaded: ClosureSupportMatrix =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("matrix must be readable"))
            .expect("matrix must deserialize");
    assert_eq!(reloaded, matrix);
}

#[test]
fn one_source_has_one_conflict_identity_on_every_chain() {
    // The load-bearing invariant. If this ever varies by destination, the same
    // source can be closed once per chain.
    let sources = vec![
        conformance_source(),
        csv_protocol::ConsumedStateRef::new(Hash::new([0x22; 32]), 0, 1),
        csv_protocol::ConsumedStateRef::new(Hash::new([0x33; 32]), 9, 4096),
    ];
    assert_shared_conflict_identity(&sources);

    // And concretely: the nullifier each adapter would write is the same value.
    let source = conformance_source();
    let expected = SourceNullifier::derive(&source);
    assert_eq!(
        EthereumFixture::new().nullifier_written(&source),
        *expected.as_bytes()
    );
    assert_eq!(
        SuiFixture::new().nullifier_written(&source),
        *expected.as_bytes()
    );
    assert_eq!(
        AptosFixture::new().nullifier_written(&source),
        *expected.as_bytes()
    );
    assert_eq!(
        SolanaFixture::new().nullifier_written(&source),
        *expected.as_bytes()
    );
}

#[test]
fn the_same_source_cannot_close_valid_successors_on_two_chains() {
    // A holder closes the source honestly on Ethereum, then tries to close it
    // for a *different* successor on each other chain. Every chain writes the
    // same nullifier key, so the second closure is a detectable conflict rather
    // than an independently valid closure.
    let source = conformance_source();
    let honest = conformance_successor();
    let equivocating = conformance_equivocating_successor();

    let ethereum = EthereumFixture::new();
    let first = ethereum.build_closure(&source, &honest);
    let first_result = ethereum
        .verify(
            &first.proof,
            &first.checkpoint,
            first.observed_head,
            ClosureTrustMode::FullNode,
        )
        .expect("honest Ethereum closure must evaluate");
    assert_eq!(
        first_result.source_closure,
        ClosureDimensionStatus::Satisfied
    );

    let conflict_key = SourceNullifier::derive(&source);

    for (chain, nullifier) in [
        ("sui", SuiFixture::new().nullifier_written(&source)),
        ("aptos", AptosFixture::new().nullifier_written(&source)),
        ("solana", SolanaFixture::new().nullifier_written(&source)),
    ] {
        // A competing closure on another chain targets the identical key, so a
        // recipient that has accepted the first rejects the second on conflict.
        assert_eq!(
            nullifier,
            *conflict_key.as_bytes(),
            "{chain}: an equivocating closure must collide with the first"
        );
    }

    // And the equivocating successor is not itself proven by the honest proof.
    let mut equivocating_proof = first.proof.clone();
    equivocating_proof.successor_commitment = equivocating;
    let result = ethereum
        .verify(
            &equivocating_proof,
            &first.checkpoint,
            first.observed_head,
            ClosureTrustMode::FullNode,
        )
        .expect("evaluation must succeed");
    assert_ne!(result.source_closure, ClosureDimensionStatus::Satisfied);
}

#[test]
fn proofs_do_not_replay_across_chains() {
    // Each adapter's honest proof, offered to every other adapter's verifier.
    let source = conformance_source();
    let successor = conformance_successor();

    let ethereum = EthereumFixture::new();
    let sui = SuiFixture::new();
    let aptos = AptosFixture::new();
    let solana = SolanaFixture::new();

    let scenarios = [
        ("ethereum", ethereum.build_closure(&source, &successor)),
        ("sui", sui.build_closure(&source, &successor)),
        ("aptos", aptos.build_closure(&source, &successor)),
        ("solana", solana.build_closure(&source, &successor)),
    ];

    for (origin, scenario) in &scenarios {
        for (target_name, verify) in verifiers(&ethereum, &sui, &aptos, &solana) {
            if &target_name == origin {
                continue;
            }
            let outcome = verify(scenario);
            match outcome {
                Ok(result) => assert_ne!(
                    result.source_closure,
                    ClosureDimensionStatus::Satisfied,
                    "a {origin} proof must not establish closure on {target_name}"
                ),
                Err(_) => { /* rejected outright */ }
            }
        }
    }
}

#[test]
fn bindings_are_distinct_across_every_chain_pair() {
    // Domain separation at the value level: no two chains produce the same
    // binding for the same source and successor, so no stored value can be
    // lifted from one chain's state and presented as another's.
    let source = conformance_source();
    let successor = conformance_successor();

    let bindings = vec![
        EthereumFixture::new().binding(&source, &successor),
        SuiFixture::new().binding(&source, &successor),
        AptosFixture::new().binding(&source, &successor),
        SolanaFixture::new().binding(&source, &successor),
    ];

    for (i, first) in bindings.iter().enumerate() {
        for (j, second) in bindings.iter().enumerate() {
            if i != j {
                assert_ne!(first, second, "bindings {i} and {j} must differ");
            }
        }
    }
}

#[test]
fn destination_settlement_success_never_substitutes_for_source_closure() {
    // There is no path by which a settled destination becomes closure evidence:
    // closure is established only by a chain-native proof about the *source*.
    // A proof whose material is replaced by any settlement-shaped payload must
    // not verify.
    let source = conformance_source();
    let successor = conformance_successor();
    let ethereum = EthereumFixture::new();
    let scenario = ethereum.build_closure(&source, &successor);

    for settlement_payload in [
        b"SETTLED".to_vec(),
        b"MINTED".to_vec(),
        vec![1u8; 128],
        Vec::new(),
    ] {
        let mut proof = scenario.proof.clone();
        proof.proof_material = settlement_payload;
        match ethereum.verify(
            &proof,
            &scenario.checkpoint,
            scenario.observed_head,
            ClosureTrustMode::FullNode,
        ) {
            Ok(result) => assert_ne!(
                result.source_closure,
                ClosureDimensionStatus::Satisfied,
                "settlement-shaped material must not establish closure"
            ),
            Err(_) => { /* rejected outright */ }
        }
    }
}

#[test]
fn source_closure_success_never_implies_destination_settlement() {
    let source = conformance_source();
    let successor = conformance_successor();
    let ethereum = EthereumFixture::new();
    let scenario = ethereum.build_closure(&source, &successor);
    let result = ethereum
        .verify(
            &scenario.proof,
            &scenario.checkpoint,
            scenario.observed_head,
            ClosureTrustMode::FullNode,
        )
        .expect("honest closure must evaluate");

    assert_eq!(result.source_closure, ClosureDimensionStatus::Satisfied);
    csv_testkit::closure_conformance::assert_closure_does_not_imply_settlement(&result);
}

type Verifier<'a> =
    Box<dyn Fn(&ClosureScenario) -> Result<csv_protocol::ClosureVerificationResult, String> + 'a>;

fn verifiers<'a>(
    ethereum: &'a EthereumFixture,
    sui: &'a SuiFixture,
    aptos: &'a AptosFixture,
    solana: &'a SolanaFixture,
) -> Vec<(String, Verifier<'a>)> {
    vec![
        (
            "ethereum".to_string(),
            Box::new(move |scenario: &ClosureScenario| {
                ethereum.verify(
                    &scenario.proof,
                    &scenario.checkpoint,
                    scenario.observed_head,
                    ClosureTrustMode::FullNode,
                )
            }) as Verifier<'a>,
        ),
        (
            "sui".to_string(),
            Box::new(move |scenario: &ClosureScenario| {
                sui.verify(
                    &scenario.proof,
                    &scenario.checkpoint,
                    scenario.observed_head,
                    ClosureTrustMode::FullNode,
                )
            }),
        ),
        (
            "aptos".to_string(),
            Box::new(move |scenario: &ClosureScenario| {
                aptos.verify(
                    &scenario.proof,
                    &scenario.checkpoint,
                    scenario.observed_head,
                    ClosureTrustMode::FullNode,
                )
            }),
        ),
        (
            "solana".to_string(),
            Box::new(move |scenario: &ClosureScenario| {
                solana.verify(
                    &scenario.proof,
                    &scenario.checkpoint,
                    scenario.observed_head,
                    ClosureTrustMode::FullNode,
                )
            }),
        ),
    ]
}
