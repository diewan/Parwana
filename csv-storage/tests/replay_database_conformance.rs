//! Conformance tests for ReplayDatabase implementations.
//!
//! This module provides a test suite that all ReplayDatabase implementations
//! must pass to ensure consistent behavior across different backends.

use csv_protocol::proof_types::ReplayId;
use csv_protocol::cross_chain::HashEntry as CrossChainRegistryEntry;
use csv_storage::{InMemoryReplayDb, ReplayDatabase, ReplayDbError};

/// Test helper to run conformance tests on any ReplayDatabase implementation.
async fn test_replay_database_conformance(db: &dyn ReplayDatabase) {
    let id = b"test-replay-id-32-bytes-padding!!";
    let id_bytes = &id[..32];

    // Test 1: contains returns false for non-existent ID
    assert!(!db.contains(id_bytes).await.unwrap());

    // Test 2: insert_if_absent succeeds for new ID
    db.insert_if_absent(id_bytes).await.unwrap();
    assert!(db.contains(id_bytes).await.unwrap());

    // Test 3: insert_if_absent fails for existing ID (CAS semantics)
    let result = db.insert_if_absent(id_bytes).await;
    assert!(matches!(result, Err(ReplayDbError::AlreadyExists)));

    // Test 4: consume_if_unconsumed succeeds for non-existent ID (inserts as Pending)
    let id4 = b"consume-test-32-bytes-padding!!!";
    let id4_bytes = &id4[..32];
    db.consume_if_unconsumed(id4_bytes).await.unwrap();
    assert!(db.contains(id4_bytes).await.unwrap());

    // Test 5: consume_if_unconsumed is idempotent for already Consumed entries
    // First mark as Consumed via confirm_consumed
    let mut replay_id4_bytes = [0u8; 32];
    replay_id4_bytes.copy_from_slice(id4_bytes);
    let replay_id4 = ReplayId {
        version: ReplayId::CURRENT_VERSION,
        id: replay_id4_bytes,
    };
    db.confirm_consumed_replay_id(&replay_id4).await.unwrap();
    // Now consume_if_unconsumed should succeed (idempotent)
    db.consume_if_unconsumed(id4_bytes).await.unwrap();

    // Test 6: consume_if_unconsumed fails for Pending entries (CAS semantics)
    let result = db.consume_if_unconsumed(id_bytes).await;
    assert!(matches!(result, Err(ReplayDbError::AlreadyExists)));

    // Test 7: confirm_consumed promotes Pending to Consumed
    let id2 = b"another-test-id-32-bytes-padding!!";
    let id2_bytes = &id2[..32];
    db.insert_if_absent(id2_bytes).await.unwrap();
    let mut replay_id_bytes = [0u8; 32];
    replay_id_bytes.copy_from_slice(id2_bytes);
    let replay_id = ReplayId {
        version: ReplayId::CURRENT_VERSION,
        id: replay_id_bytes,
    };
    db.confirm_consumed_replay_id(&replay_id).await.unwrap();

    // Test 8: confirm_consumed is idempotent for already Consumed entries
    db.confirm_consumed_replay_id(&replay_id).await.unwrap();

    // Test 9: mark_rolled_back promotes Pending to RolledBack
    let id3 = b"third-test-id-32-bytes-padding!!";
    let id3_bytes = &id3[..32];
    db.insert_if_absent(id3_bytes).await.unwrap();
    let mut replay_id3_bytes = [0u8; 32];
    replay_id3_bytes.copy_from_slice(id3_bytes);
    let replay_id3 = ReplayId {
        version: ReplayId::CURRENT_VERSION,
        id: replay_id3_bytes,
    };
    db.mark_rolled_back(&replay_id3).await.unwrap();

    // Test 10: mark_rolled_back is idempotent for already RolledBack entries
    db.mark_rolled_back(&replay_id3).await.unwrap();

    // Test 10b: mark_rolled_back still fails for Consumed entries
    let result = db.mark_rolled_back(&replay_id).await;
    assert!(result.is_err());

    // Test 11: store_transfer_entry and load_all_transfers
    let sanad_id = csv_hash::Hash::new([1u8; 32]);
    let entry = CrossChainRegistryEntry {
        transfer_id: "conformance-transfer".to_string(),
        sanad_id,
        source_chain: csv_hash::chain_id::ChainId::new("bitcoin"),
        source_seal: csv_hash::seal::SealPoint {
            id: vec![1, 2, 3, 4],
            nonce: None,
        },
        destination_chain: csv_hash::chain_id::ChainId::new("ethereum"),
        destination_seal: csv_hash::seal::SealPoint {
            id: vec![],
            nonce: None,
        },
        lock_tx_hash: csv_hash::Hash::new([2u8; 32]),
        transition_id: vec![3, 4, 5, 6],
        mint_tx_hash: csv_hash::Hash::new([3u8; 32]),
        timestamp: 1234567890,
    };
    db.store_transfer_entry(&entry).await.unwrap();

    let transfers = db.load_all_transfers().await.unwrap();
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].sanad_id, sanad_id);
}

#[tokio::test]
async fn test_in_memory_replay_database_conformance() {
    let db = InMemoryReplayDb::new();
    test_replay_database_conformance(&db).await;
}

#[cfg(feature = "rocksdb")]
#[tokio::test]
async fn test_rocksdb_replay_database_conformance() {
    use csv_storage::backends::rocksdb::RocksDbReplayDb;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_replay_db");

    let db = RocksDbReplayDb::open(
        db_path
            .to_str()
            .expect("temporary RocksDB path should be valid UTF-8"),
    )
    .expect("Failed to open RocksDB");
    test_replay_database_conformance(&db).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore] // Requires PostgreSQL instance - run with: cargo test --features postgres -- --ignored
async fn test_postgres_replay_database_conformance() {
    use csv_storage::backends::postgres::PostgresReplayDb;
    use std::env;

    // Get PostgreSQL connection string from environment
    let database_url = env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost:5432/csv_test".to_string());

    let db = PostgresReplayDb::connect(&database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    // Run migrations
    db.run_migrations().await.expect("Failed to run migrations");

    test_replay_database_conformance(&db).await;
}

#[tokio::test]
async fn test_replay_database_idempotency() {
    let db = InMemoryReplayDb::new();
    let id = b"idempotency-test-32-bytes-padding!!";
    let id_bytes = &id[..32];

    // Use consume_if_unconsumed for initial insert
    db.consume_if_unconsumed(id_bytes).await.unwrap();

    // Mark as Consumed
    let mut replay_id_bytes = [0u8; 32];
    replay_id_bytes.copy_from_slice(id_bytes);
    let replay_id = ReplayId {
        version: ReplayId::CURRENT_VERSION,
        id: replay_id_bytes,
    };
    db.confirm_consumed_replay_id(&replay_id).await.unwrap();

    // Multiple consume_if_unconsumed calls should all succeed (idempotent for Consumed)
    for _ in 0..5 {
        db.consume_if_unconsumed(id_bytes).await.unwrap();
    }

    // Verify the entry still exists
    assert!(db.contains(id_bytes).await.unwrap());
}

#[tokio::test]
async fn test_replay_database_cas_semantics() {
    let db = InMemoryReplayDb::new();
    let id = b"cas-semantics-32-bytes-padding!!";
    let id_bytes = &id[..32];

    // First insert should succeed
    assert!(db.insert_if_absent(id_bytes).await.is_ok());

    // Second insert should fail with AlreadyExists
    assert!(matches!(
        db.insert_if_absent(id_bytes).await,
        Err(ReplayDbError::AlreadyExists)
    ));
}

#[tokio::test]
async fn test_replay_database_state_transitions() {
    let db = InMemoryReplayDb::new();
    let id = b"state-transitions-32-bytes-padding!!";
    let id_bytes = &id[..32];
    let mut replay_id_bytes = [0u8; 32];
    replay_id_bytes.copy_from_slice(id_bytes);
    let replay_id = ReplayId {
        version: ReplayId::CURRENT_VERSION,
        id: replay_id_bytes,
    };

    // Initial state: Pending (after insert_if_absent)
    db.insert_if_absent(id_bytes).await.unwrap();

    // Transition: Pending -> Consumed
    db.confirm_consumed_replay_id(&replay_id).await.unwrap();

    // Transition: Consumed -> Consumed (idempotent)
    db.confirm_consumed_replay_id(&replay_id).await.unwrap();

    // Test another entry: Pending -> RolledBack
    let id2 = b"state-transitions-2-32-bytes-padding!!";
    let id2_bytes = &id2[..32];
    let mut replay_id2_bytes = [0u8; 32];
    replay_id2_bytes.copy_from_slice(id2_bytes);
    let replay_id2 = ReplayId {
        version: ReplayId::CURRENT_VERSION,
        id: replay_id2_bytes,
    };
    db.insert_if_absent(id2_bytes).await.unwrap();
    db.mark_rolled_back(&replay_id2).await.unwrap();
}
