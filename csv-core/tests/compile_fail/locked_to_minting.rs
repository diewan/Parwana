//! Compile-fail test: Locked to Minting (skips states)
//!
//! This test ensures that skipping directly from Locked to Minting
//! is caught at compile time. Transitions must follow the state machine.

use csv_core::transfer_state::{Locked, Minting, TransferData};
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

    let locked = Locked::new(data, 100, vec![5u8; 32]);

    // This should fail to compile - cannot skip from Locked to Minting
    // Must go through: Locked -> AwaitingFinality -> ProofBuilding -> ProofValidated -> Minting
    let _minting = Minting::new(locked.data, vec![6u8; 32]); // ERROR: invalid state transition
}
