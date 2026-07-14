//! Temporary diagnostic: dump the runtime execution journal entries.
//! Usage: cargo run -p csv-runtime --features persistent --example dump_journal -- ~/.csv/data/runtime/journal.redb

use csv_runtime::execution_journal::RedbExecutionJournal;

fn main() {
    let path = std::env::args().nth(1).expect("journal path argument");
    let journal = RedbExecutionJournal::open(&path).expect("open journal");
    for (sequence, entry) in journal.entries().expect("read journal").iter().enumerate() {
        println!(
            "{:020} transfer={} phase={:?} outcome={:?} ctx={}",
            sequence,
            entry.transfer_id,
            entry.phase,
            entry.outcome,
            entry
                .transfer_context
                .as_ref()
                .map(|c| format!(
                    "{}->{} sanad={}",
                    c.source_chain, c.destination_chain, c.sanad_id.bytes
                ))
                .unwrap_or_else(|| "-".to_string()),
        );
    }
}
