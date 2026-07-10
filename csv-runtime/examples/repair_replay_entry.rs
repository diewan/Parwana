//! One-off operator repair: fix a replay-DB transfer entry whose recorded
//! lock_tx_hash points at a reverted duplicate lock transaction instead of the
//! real on-chain SanadLocked transaction (pre-fix double-submit incident).
//!
//! Usage:
//!   cargo run -p csv-runtime --features persistent --example repair_replay_entry -- \
//!     <replay_db_path> <sanad_id_hex> [<correct_lock_tx_hex>]
//!
//! Without <correct_lock_tx_hex> the entry is printed and left untouched.

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("replay db path");
    let sanad_hex = args.next().expect("sanad id hex");
    let new_lock_hex = args.next();

    let sanad_bytes = hex::decode(&sanad_hex).expect("sanad hex");

    let mut options = rocksdb::Options::default();
    options.create_if_missing(false);
    let cfs = ["replay_entries", "replay_conflicts", "transfer_entries"];
    let db = rocksdb::DB::open_cf(&options, &path, cfs).expect("open replay db");
    let cf = db.cf_handle("transfer_entries").expect("cf");

    let val = db
        .get_cf(cf, &sanad_bytes)
        .expect("read")
        .expect("no transfer entry for this sanad id");
    let mut entry = csv_protocol::cross_chain::HashEntry::from_canonical_bytes(&val)
        .expect("decode entry");

    println!("transfer_id:  {}", entry.transfer_id);
    println!("source:       {}", entry.source_chain);
    println!("destination:  {}", entry.destination_chain);
    println!("lock_tx_hash: {}", hex::encode(entry.lock_tx_hash.as_bytes()));
    println!("source_seal:  {}", hex::encode(&entry.source_seal.id));

    let Some(new_lock_hex) = new_lock_hex else {
        println!("(dry run — no change written)");
        return;
    };
    let new_lock = hex::decode(&new_lock_hex).expect("lock tx hex");
    let new_lock_arr: [u8; 32] = new_lock.clone().try_into().expect("32-byte lock tx");

    entry.lock_tx_hash = csv_hash::Hash::new(new_lock_arr);
    // source_seal.id embeds lock_tx || output_index (LE u32); preserve the index.
    if entry.source_seal.id.len() >= 36 {
        let idx = entry.source_seal.id[entry.source_seal.id.len() - 4..].to_vec();
        let mut id = new_lock;
        id.extend_from_slice(&idx);
        entry.source_seal.id = id;
    }

    let bytes = entry.to_canonical_bytes().expect("encode");
    db.put_cf(cf, &sanad_bytes, bytes).expect("write");
    println!("updated lock_tx_hash -> {}", new_lock_hex);
}
