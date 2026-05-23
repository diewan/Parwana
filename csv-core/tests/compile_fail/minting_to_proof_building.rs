//! Compile-fail test: Minting to ProofBuilding (backward transition)
//!
//! This test ensures that going backward from Minting to ProofBuilding
//! is impossible at compile time. Transitions must follow the state machine
//! forward direction only.

use csv_core::transfer_state::{Minting, ProofBuilding, TransferData};
use csv_core::Hash;
use csv_core::protocol_version::ChainId;

fn main() {
    let data = TransferData::new(
        Hash::new([1u8; 32]),
        csv_core::sanad::SanadId(Hash::new([2u8; 32])),
        ChainId::new("bitcoin"),
        ChainId::new("ethereum"),
        vec![3u8; 32],
        Hash::new([4u8; 32]),
    );

    let minting = Minting::new(data);

    // This should fail to compile - cannot go backward from Minting to ProofBuilding
    // The state machine only allows forward transitions.
    // Valid path: Locked -> AwaitingFinality -> ProofBuilding -> ProofValidated -> Minting -> Completed
    let _proof_building = ProofBuilding::new(minting.data); // ERROR: backward transition not allowed
}
