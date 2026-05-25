//! Compile-fail test: Locked to Minting (skip states)
//!
//! This test ensures that skipping from Locked to Minting
//! is impossible at compile time with csv-algebra typestate.

use csv_algebra::state::{Locked, Minting};
use csv_algebra::transfer::{SealId, ChainId};

fn main() {
    let locked = Locked {
        seal_id: SealId([1u8; 32]),
        source_chain: 1,
        dest_chain: 2,
    };

    // This should fail to compile - cannot skip from Locked to Minting
    // Locked has no method to go directly to Minting
    let _minting = locked.mint([4u8; 32]); // ERROR: no such method
}
