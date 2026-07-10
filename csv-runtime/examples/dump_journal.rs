//! Temporary diagnostic: dump the runtime execution journal entries.
//! Usage: cargo run -p csv-runtime --features persistent --example dump_journal -- ~/.csv/data/runtime/journal

fn main() {
    let path = std::env::args().nth(1).expect("journal path argument");
    let options = rocksdb::Options::default();
    let db = rocksdb::DB::open_for_read_only(&options, &path, false).expect("open journal");
    for item in db.prefix_iterator(b"phase/") {
        let (key, bytes) = item.expect("iterate");
        match csv_codec::from_canonical_cbor::<csv_runtime::execution_journal::TransferPhaseEntry>(
            bytes.as_ref(),
        ) {
            Ok(entry) => {
                println!(
                    "{} transfer={} phase={:?} outcome={:?} ctx={}",
                    String::from_utf8_lossy(key.as_ref()),
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
            Err(e) => println!(
                "{} <decode error: {}>",
                String::from_utf8_lossy(key.as_ref()),
                e
            ),
        }
    }
}
