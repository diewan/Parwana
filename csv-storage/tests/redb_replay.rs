//! RocksDB replay backend integration test.

use csv_storage::{ReplayDatabase, RocksDbReplayDb};

#[tokio::test]
async fn rocksdb_replay_cas() {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDbReplayDb::open(dir.path().to_str().unwrap()).unwrap();
    let id = b"01234567890123456789012345678901";
    assert!(!db.contains(id).await.unwrap());
    db.insert_if_absent(id).await.unwrap();
    assert!(db.contains(id).await.unwrap());
    let dup = db.insert_if_absent(id).await;
    assert!(dup.is_err());
}
