//! Compile-fail test: ProofValidated to Locked (backward transition)
//!
//! This test ensures that going backward from ProofValidated to Locked
//! is impossible at compile time with csv-algebra typestate.

use csv_algebra::state::{Locked, ProofValidated};
use csv_algebra::transfer::{SealId, ChainId};

fn main() {
    let locked = Locked {
        seal_id: SealId([1u8; 32]),
        source_chain: 1,
        dest_chain: 2,
    };

    let proof_building = locked.begin_proof();
    let awaiting_finality = proof_building.submit_proof(
        csv_algebra::proof::CanonicalProof::new(100, [2u8; 32], [3u8; 32], vec![], 1),
        10,
    );
    let proof_validated = awaiting_finality.accept(csv_algebra::finality::FinalityEvidence::new([2u8; 32], 100, vec![], 0));

    // This should fail to compile - cannot go backward from ProofValidated to Locked
    // Locked has no method to accept a ProofValidated
    let _locked = Locked::from(proof_validated); // ERROR: no such method
}
