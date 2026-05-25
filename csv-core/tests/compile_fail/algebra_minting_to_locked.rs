//! Compile-fail test: Minting to Locked (backward transition)
//!
//! This test ensures that going backward from Minting to Locked
//! is impossible at compile time with csv-algebra typestate.

use csv_algebra::state::{Locked, Minting};
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
    let minting = proof_validated.mint([4u8; 32]);

    // This should fail to compile - cannot go backward from Minting to Locked
    // The Locked type has no method to accept a Minting
    let _locked = Locked::from(minting); // ERROR: no such method
}
