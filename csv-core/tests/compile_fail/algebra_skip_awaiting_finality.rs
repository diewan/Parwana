//! Compile-fail test: Skip AwaitingFinality state
//!
//! This test ensures that skipping from ProofBuilding to ProofValidated
//! is impossible at compile time with csv-algebra typestate.

use csv_algebra::state::{Locked, ProofBuilding, ProofValidated};
use csv_algebra::transfer::{SealId, ChainId};

fn main() {
    let locked = Locked {
        seal_id: SealId([1u8; 32]),
        source_chain: 1,
        dest_chain: 2,
    };

    let proof_building = locked.begin_proof();

    // This should fail to compile - cannot skip AwaitingFinality
    // ProofBuilding has no method to go directly to ProofValidated
    let _proof_validated = proof_building.validate(
        csv_algebra::finality::FinalityEvidence::new([2u8; 32], 100, vec![], 0)
    ); // ERROR: no such method
}
