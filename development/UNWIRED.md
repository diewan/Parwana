Bind proof recovery to transfer - add sanad_id, lock_tx, output_index, transition_id, destination to VerificationContext and validate in verify_recovery_proof

Implement persistent execution journal - replace InMemoryJournal with PostgreSQL-backed implementation in csv-runtime

Fix recovery lease authority - replace synthetic one-hour lease with proper lease validation in resume_transfers and execute_from_mint

Strip serde from L0-L4 internal types - remove Serialize/Deserialize derives from 196 types per serde_audit_manifest.md

Wire chain-adapter RPCs through csv-wire - implement BitcoinTxWire, Ethereum RPC types, Solana, Aptos in csv-wire/src/rpc/

Enforce csv-wire via deny.toml - add cargo-deny rule and architecture guard test for serde in L0-L4 crates

Migrate csv-sdk off csv-core - replace all csv_core imports, move client/wallet_types to csv-sdk, remove csv-core dependency

Add architecture guard for csv-core elimination - test nothing_new_depends_on_csv_core

Delete csv-core crate - remove from workspace, delete directory, create TOMBSTONE.md

Implement execute_from_lock recovery - load LockConfirmed journal entry, reconstruct Locked typestate, resume at AwaitingFinality

Implement execute_from_proof recovery - load proof bytes from journal, skip proof generation, go straight to mint

Implement AwaitingFinality recovery - re-poll finality monitor with proof height from journal

Implement ProofBuilding recovery - check for persisted checkpoint, resume if exists

Wire proof_payload into ExecutionJournalEntry - add block_height, tx_hash_bytes, proof_payload fields and SQL migration

Wire csv-coordinator isolation-domain behavior - implement actual per-chain execution cell logic in csv-coordinator/src/cell.rs

Integrate observability types into runtime - replace HealthMonitor with RuntimeHealth from csv-observability

Add Celestia to Chain enum in csv-cli - enable Celestia across all CLI commands

Add Solana to test matrix - include solana pairs in csv-cli commands/tests.rs test run

Wire chain_management.rs commands - connect ChainCommands (discover, validate, create-template) to Commands enum in main.rs

Add runtime subcommand - implement runtime status, events, health commands for admission control and event bus

Add content subcommand - implement content tree and selective disclosure CLI commands

Add trust subcommand - implement trust export/import/verify commands
