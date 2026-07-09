//! Integration tests for adversarial testkit wiring.

use csv_protocol::signature::SignatureScheme;
use csv_testkit::{AdversarialConfig, AdversarialRunner, ByzantineBehavior, TestProofBundle};
use csv_verifier::VerificationContext;

#[test]
fn adversarial_runner_rejects_minimal_fixture_via_canonical_verifier() {
    let runner = AdversarialRunner::new(AdversarialConfig {
        behaviors: vec![ByzantineBehavior::AcceptInvalidProofs],
        ..Default::default()
    });
    let bundle = TestProofBundle::minimal();
    assert!(runner.assert_tampered_bundle_rejected(&bundle, "bitcoin"));
}

#[test]
fn verification_context_builds_for_test_chains() {
    let ctx = csv_testkit::TestContext::verification_context("ethereum");
    assert_eq!(ctx.chain_id, "ethereum");
    assert_eq!(ctx.signature_scheme, SignatureScheme::Secp256k1);
    let _ = VerificationContext {
        chain_id: ctx.chain_id,
        signature_scheme: ctx.signature_scheme,
        required_confirmations: ctx.required_confirmations,
        current_block_height: ctx.current_block_height,
        seal_registry: ctx.seal_registry,
        chain_data: ctx.chain_data,
        native_proof_validated: ctx.native_proof_validated,
        sanad_id: ctx.sanad_id,
        lock_tx: ctx.lock_tx,
        lock_output_index: ctx.lock_output_index,
        transition_id: ctx.transition_id,
        destination_chain: ctx.destination_chain,
        authorized_signers: ctx.authorized_signers,
    };
}
