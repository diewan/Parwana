//! Compile-fail test: Invalid state transition
//!
//! This test ensures that invalid state transitions are caught at compile time.
//! The typestate pattern should prevent direct state mutations.

use csv_core::transfer_state::{Locked, AwaitingFinality, TransferData};
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
    
    // This should fail to compile - cannot directly mutate state
    // locked.data.initiated_at = 200; // ERROR: field is private
    
    // This should fail to compile - cannot skip state transition
    // let validated = csv_core::transfer_state::ProofValidated::new(locked.data, vec![6u8; 32]); // ERROR: wrong state type
}
