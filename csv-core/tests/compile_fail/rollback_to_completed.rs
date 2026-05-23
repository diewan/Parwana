//! Compile-fail test: RolledBack to Completed (invalid terminal transition)
//!
//! This test ensures that a rolled back transfer cannot transition to Completed.
//! RolledBack is a terminal state - the transfer must be restarted from Locked.

use csv_core::transfer_state::{Completed, RolledBack, TransferData};
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

    let rolled_back = RolledBack::new(data, 100, "reorg".to_string());

    // This should fail to compile - RolledBack is a terminal state
    // Cannot transition from RolledBack to Completed
    // Must restart the transfer from Locked state
    let _completed = Completed::new(rolled_back.data, vec![5u8; 32]); // ERROR: rolled back transfers cannot complete
}
