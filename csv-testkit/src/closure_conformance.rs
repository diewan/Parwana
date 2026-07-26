//! The abstract closure conformance suite (PAR-XCHAIN-001).
//!
//! Every advertised Stage 5 chain passes *this* suite, not a per-chain suite of
//! its own. A chain-specific test can only prove that an adapter is
//! self-consistent; a shared suite is what makes "advertised" mean the same
//! thing on every chain.
//!
//! # The two invariants, kept apart
//!
//! The suite tests source closure and destination settlement as **separate**
//! invariants, because they fail separately and conflating them is the bug the
//! whole stage exists to prevent:
//!
//! - **Source closure** asks: was this source consumed in favour of exactly this
//!   successor, provably? It is answered by a chain-native proof plus a final
//!   checkpoint, and it is the only question this suite lets an adapter answer.
//! - **Destination settlement** asks: did something useful subsequently happen
//!   on the destination? Nothing in [`ClosureVerificationResult`] reports it,
//!   and no adapter may imply it. A settled destination is not evidence that the
//!   source was closed, and a closed source is not a promise that anything
//!   settled.
//!
//! [`assert_closure_does_not_imply_settlement`] pins the direction that would
//! otherwise be tempting to blur.
//!
//! # What the suite deliberately does not assume
//!
//! It does not assume every chain can reach `Satisfied`. Chains differ in what a
//! recipient can independently verify — Ethereum has state proofs, Sui and Aptos
//! have committee-signed checkpoints, Solana has neither — so each adapter
//! declares which trust modes can establish finality for it, and the suite holds
//! it to that declaration in **both** directions: the declared modes must reach
//! closure, and the undeclared ones must never report it.

use csv_hash::Hash;
use csv_protocol::{
    ClosureDimensionStatus, ClosureProof, ClosureProofKind, ClosureTrustMode,
    ClosureVerificationResult, ConsumedStateRef, FinalizedCheckpoint, SourceNullifier,
};
use serde::{Deserialize, Serialize};

/// One honest closure, ready to verify.
#[derive(Clone, Debug)]
pub struct ClosureScenario {
    /// The closure proof a sender would publish.
    pub proof: ClosureProof,
    /// The checkpoint the proof was built against.
    pub checkpoint: FinalizedCheckpoint,
    /// Chain head the provider reports (height, sequence, version, or slot).
    pub observed_head: u64,
}

/// An adapter under conformance test.
///
/// Implementors expose only what the suite needs: how to build an honest
/// closure, how to verify one, and what their chain can actually establish.
pub trait ClosureConformanceAdapter {
    /// Stable chain identifier.
    fn chain_id(&self) -> &str;

    /// Stable network identifier.
    fn network_id(&self) -> &str;

    /// Proof family this adapter issues and accepts.
    fn proof_kind(&self) -> ClosureProofKind;

    /// Trust modes under which this chain can establish checkpoint finality.
    ///
    /// Declaring a mode here is a claim the suite will test, not documentation.
    fn finality_establishing_trust_modes(&self) -> Vec<ClosureTrustMode>;

    /// Every trust mode the protocol defines.
    fn all_trust_modes() -> Vec<ClosureTrustMode> {
        vec![
            ClosureTrustMode::FullNode,
            ClosureTrustMode::LightClient,
            ClosureTrustMode::RpcQuorum,
            ClosureTrustMode::AttestedRegistry,
        ]
    }

    /// Build an honest closure of `consumed` in favour of `successor`.
    fn build_closure(&self, consumed: &ConsumedStateRef, successor: &Hash) -> ClosureScenario;

    /// Verify a proof, returning the typed result or an evaluation error.
    fn verify(
        &self,
        proof: &ClosureProof,
        checkpoint: &FinalizedCheckpoint,
        observed_head: u64,
        trust_mode: ClosureTrustMode,
    ) -> Result<ClosureVerificationResult, String>;
}

/// Evidence recorded for one chain that passed the suite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainConformanceEvidence {
    /// Chain identifier.
    pub chain_id: String,
    /// Network the vectors were built for.
    pub network_id: String,
    /// Proof family name.
    pub proof_kind: String,
    /// Trust modes that can establish finality on this chain.
    pub finality_establishing_trust_modes: Vec<String>,
    /// Trust modes that cannot, and therefore never report closure.
    pub indeterminate_trust_modes: Vec<String>,
    /// Conformance checks this chain passed, by name.
    pub checks_passed: Vec<String>,
}

/// The machine-readable Stage 5 support matrix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureSupportMatrix {
    /// Suite version, so a stale matrix is detectable.
    pub suite_version: u32,
    /// One entry per advertised chain.
    pub chains: Vec<ChainConformanceEvidence>,
}

/// Version of the conformance suite that produces a support matrix.
pub const CLOSURE_CONFORMANCE_SUITE_VERSION: u32 = 1;

/// Names of every check [`run_closure_conformance`] performs.
pub const CONFORMANCE_CHECKS: &[&str] = &[
    "positive_closure_verifies",
    "closure_is_deterministic",
    "result_is_self_consistent",
    "second_successor_is_not_closure",
    "other_source_is_not_closure",
    "insufficient_finality_is_not_closure",
    "orphaned_checkpoint_is_not_closure",
    "random_material_is_not_closure",
    "foreign_proof_kind_is_rejected",
    "undeclared_trust_modes_never_report_closure",
    "closure_does_not_imply_settlement",
];

fn trust_mode_name(mode: ClosureTrustMode) -> String {
    match mode {
        ClosureTrustMode::FullNode => "FullNode",
        ClosureTrustMode::LightClient => "LightClient",
        ClosureTrustMode::RpcQuorum => "RpcQuorum",
        ClosureTrustMode::AttestedRegistry => "AttestedRegistry",
    }
    .to_string()
}

fn proof_kind_name(kind: &ClosureProofKind) -> String {
    match kind {
        ClosureProofKind::BitcoinTransactionInclusion => {
            "bitcoin-transaction-inclusion".to_string()
        }
        ClosureProofKind::ChainSpecific(name) => name.clone(),
    }
}

/// A source and two competing successors, shared by every chain's run.
pub fn conformance_source() -> ConsumedStateRef {
    ConsumedStateRef::new(Hash::new([0x11; 32]), 2, 7)
}

/// The honest successor.
pub fn conformance_successor() -> Hash {
    Hash::new([0x55; 32])
}

/// A competing successor of the same source.
pub fn conformance_equivocating_successor() -> Hash {
    Hash::new([0x66; 32])
}

/// Assert that a closure result makes no claim about destination settlement.
///
/// `ClosureVerificationResult` has no settlement field, so the guarantee is
/// structural. This check pins the *behavioural* half: a satisfied source
/// closure must not be accompanied by a reason code that asserts settlement,
/// which is how such a claim would most plausibly leak in.
pub fn assert_closure_does_not_imply_settlement(result: &ClosureVerificationResult) {
    for reason in &result.reason_codes {
        let lowered = reason.to_ascii_lowercase();
        assert!(
            !lowered.contains("settle")
                && !lowered.contains("mint")
                && !lowered.contains("deliver"),
            "closure result must not assert destination settlement, got reason {reason}"
        );
    }
}

/// Run the full conformance suite against one adapter.
///
/// Panics with a descriptive message on the first failure, and returns the
/// evidence entry for the support matrix on success.
pub fn run_closure_conformance<A: ClosureConformanceAdapter>(
    adapter: &A,
) -> ChainConformanceEvidence {
    let source = conformance_source();
    let successor = conformance_successor();
    let chain = adapter.chain_id().to_string();

    let establishing = adapter.finality_establishing_trust_modes();
    assert!(
        !establishing.is_empty(),
        "{chain}: an advertised chain must declare at least one trust mode that can establish finality"
    );
    let strongest = establishing[0];

    // 1. An honest closure verifies under a mode that can establish finality.
    let scenario = adapter.build_closure(&source, &successor);
    let result = adapter
        .verify(
            &scenario.proof,
            &scenario.checkpoint,
            scenario.observed_head,
            strongest,
        )
        .unwrap_or_else(|error| panic!("{chain}: honest closure must evaluate, got {error}"));
    assert_eq!(
        result.source_closure,
        ClosureDimensionStatus::Satisfied,
        "{chain}: honest closure must be satisfied under {strongest:?}"
    );
    assert_eq!(
        result.proof_validity,
        ClosureDimensionStatus::Satisfied,
        "{chain}: honest proof must be valid"
    );

    // 2. Building the same closure twice produces the same bytes.
    let rebuilt = adapter.build_closure(&source, &successor);
    assert_eq!(
        scenario.proof.proof_material, rebuilt.proof.proof_material,
        "{chain}: closure construction must be deterministic"
    );

    // 3. The result is self-consistent and names its own chain.
    result
        .validate()
        .unwrap_or_else(|error| panic!("{chain}: result must validate, got {error}"));
    assert_eq!(
        result.chain_id, chain,
        "{chain}: result must name its chain"
    );
    assert_eq!(
        result.proof_kind,
        adapter.proof_kind(),
        "{chain}: result must name its proof family"
    );

    // 4. A second successor of the same source is not closure.
    let mut equivocating = scenario.proof.clone();
    equivocating.successor_commitment = conformance_equivocating_successor();
    assert_not_closed(
        adapter,
        &equivocating,
        &scenario.checkpoint,
        scenario.observed_head,
        strongest,
        &chain,
        "a second successor of the same source",
    );

    // 5. A different source is not closed by this proof.
    let mut other_source = scenario.proof.clone();
    other_source.consumed_state.output_index += 1;
    assert_not_closed(
        adapter,
        &other_source,
        &scenario.checkpoint,
        scenario.observed_head,
        strongest,
        &chain,
        "a different source",
    );

    // 6. A valid proof under an unfinalized checkpoint is not closure.
    let under_final = adapter.verify(
        &scenario.proof,
        &scenario.checkpoint,
        scenario.observed_head.saturating_sub(1),
        strongest,
    );
    if let Ok(result) = under_final {
        assert_ne!(
            result.source_closure,
            ClosureDimensionStatus::Satisfied,
            "{chain}: closure must not be satisfied below the finality threshold"
        );
    }

    // 7. A checkpoint the proof was not built against is not closure.
    let mut orphaned = scenario.checkpoint.clone();
    orphaned.block_id = vec![0xEE; 32];
    assert_not_closed(
        adapter,
        &scenario.proof,
        &orphaned,
        scenario.observed_head,
        strongest,
        &chain,
        "an orphaned checkpoint",
    );

    // 8. Random bytes are not a proof.
    let mut random = scenario.proof.clone();
    random.proof_material = vec![0xAB; 192];
    assert_not_closed(
        adapter,
        &random,
        &scenario.checkpoint,
        scenario.observed_head,
        strongest,
        &chain,
        "random proof material",
    );

    // 9. A proof of another family is not read by this verifier.
    let mut foreign = scenario.proof.clone();
    foreign.proof_kind = ClosureProofKind::ChainSpecific("not-a-real-proof-family".into());
    assert_not_closed(
        adapter,
        &foreign,
        &scenario.checkpoint,
        scenario.observed_head,
        strongest,
        &chain,
        "a foreign proof family",
    );

    // 10. Trust modes the chain did not declare must never report closure.
    let mut indeterminate_modes = Vec::new();
    for mode in A::all_trust_modes() {
        if establishing.contains(&mode) {
            let result = adapter
                .verify(
                    &scenario.proof,
                    &scenario.checkpoint,
                    scenario.observed_head,
                    mode,
                )
                .unwrap_or_else(|error| {
                    panic!("{chain}: declared mode {mode:?} must evaluate, got {error}")
                });
            assert_eq!(
                result.source_closure,
                ClosureDimensionStatus::Satisfied,
                "{chain}: declared trust mode {mode:?} must establish closure"
            );
            continue;
        }
        let result = adapter
            .verify(
                &scenario.proof,
                &scenario.checkpoint,
                scenario.observed_head,
                mode,
            )
            .unwrap_or_else(|error| {
                panic!("{chain}: undeclared mode {mode:?} must still evaluate, got {error}")
            });
        assert_ne!(
            result.source_closure,
            ClosureDimensionStatus::Satisfied,
            "{chain}: undeclared trust mode {mode:?} must not report closure"
        );
        assert_eq!(
            result.checkpoint_finality,
            ClosureDimensionStatus::Indeterminate,
            "{chain}: undeclared trust mode {mode:?} must report finality as indeterminate"
        );
        indeterminate_modes.push(trust_mode_name(mode));
    }

    // 11. Source closure claims nothing about destination settlement.
    assert_closure_does_not_imply_settlement(&result);

    ChainConformanceEvidence {
        chain_id: chain,
        network_id: adapter.network_id().to_string(),
        proof_kind: proof_kind_name(&adapter.proof_kind()),
        finality_establishing_trust_modes: establishing
            .iter()
            .map(|mode| trust_mode_name(*mode))
            .collect(),
        indeterminate_trust_modes: indeterminate_modes,
        checks_passed: CONFORMANCE_CHECKS
            .iter()
            .map(|check| check.to_string())
            .collect(),
    }
}

/// Assert a proof does not establish closure, whether by error or by dimension.
///
/// Both outcomes are acceptable and meaningfully different: an error means the
/// material could not be read as a proof about this deployment at all, while a
/// failed dimension means it was read and disproven. What must never happen is
/// `Satisfied`.
fn assert_not_closed<A: ClosureConformanceAdapter>(
    adapter: &A,
    proof: &ClosureProof,
    checkpoint: &FinalizedCheckpoint,
    observed_head: u64,
    trust_mode: ClosureTrustMode,
    chain: &str,
    what: &str,
) {
    match adapter.verify(proof, checkpoint, observed_head, trust_mode) {
        Ok(result) => assert_ne!(
            result.source_closure,
            ClosureDimensionStatus::Satisfied,
            "{chain}: {what} must not establish closure"
        ),
        Err(_) => { /* rejected outright, which is stronger */ }
    }
}

/// Assert that one source has one conflict identity on every chain.
///
/// This is the cross-chain invariant in its most direct form: if these digests
/// ever differ per chain, a holder could close the same source once per
/// destination and each chain would accept its own "first" closure.
pub fn assert_shared_conflict_identity(sources: &[ConsumedStateRef]) {
    for source in sources {
        let first = SourceNullifier::derive(source);
        for _ in 0..4 {
            assert_eq!(
                SourceNullifier::derive(source),
                first,
                "the portable conflict identity must not vary"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_name_is_unique() {
        let mut sorted = CONFORMANCE_CHECKS.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "check names must be unique");
    }

    #[test]
    fn settlement_claims_in_reason_codes_are_caught() {
        let mut result = sample_result();
        result.reason_codes = vec!["CHAIN.SETTLEMENT.CONFIRMED".into()];
        let caught = std::panic::catch_unwind(move || {
            assert_closure_does_not_imply_settlement(&result);
        });
        assert!(caught.is_err(), "a settlement claim must be rejected");
    }

    #[test]
    fn ordinary_closure_reason_codes_pass() {
        assert_closure_does_not_imply_settlement(&sample_result());
    }

    fn sample_result() -> ClosureVerificationResult {
        ClosureVerificationResult {
            chain_id: "testchain".into(),
            network_id: "testnet".into(),
            proof_kind: ClosureProofKind::ChainSpecific("test-v1".into()),
            checkpoint: csv_protocol::FinalizedCheckpoint {
                chain_id: "testchain".into(),
                network_id: "testnet".into(),
                block_height: 1,
                block_id: vec![1; 32],
                finality_policy: csv_protocol::FinalityPolicy::Confirmations(1),
            },
            proof_validity: ClosureDimensionStatus::Satisfied,
            checkpoint_finality: ClosureDimensionStatus::Satisfied,
            checkpoint_freshness: ClosureDimensionStatus::Indeterminate,
            source_closure: ClosureDimensionStatus::Satisfied,
            trust_mode: ClosureTrustMode::FullNode,
            verifier_id: "test".into(),
            proof_provider_id: "test".into(),
            reason_codes: vec!["TESTCHAIN.CLOSURE.VERIFIED".into()],
        }
    }
}
