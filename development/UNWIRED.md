Bind proof recovery to transfer - add sanad_id, lock_tx, output_index, transition_id, destination to VerificationContext and validate in verify_recovery_proof

[x] Implement persistent execution journal - PostgreSQL-backed implementation in csv-runtime/src/postgres_store.rs with PostgresExecutionJournal

[x] Fix recovery lease authority - aligned LeaseConfig defaults with lease module constants (30s default, 300s max) in both production and development configs

[ ] Strip serde from L0-L4 internal types - remove Serialize/Deserialize derives from 196 types per serde_audit_manifest.md (deferred — requires refactoring 196 types; deny.toml rules already in place)

[x] Wire chain-adapter RPCs through csv-wire - implemented BitcoinTxWire, Ethereum RPC types, Solana, Aptos in csv-wire/src/rpc/

[x] Enforce csv-wire via deny.toml - cargo-deny rules in place for serde in L0-L4 crates

[x] Migrate csv-sdk off csv-core - replaced all csv_core imports, moved client/wallet_types to csv-sdk

[x] Add architecture guard for csv-core elimination - test nothing_new_depends_on_csv_core passes

[x] Delete csv-core crate - removed from workspace, deleted directory, created csv-core-TOMBSTONE.md

[ ] Implement execute_from_lock recovery - load LockConfirmed journal entry, reconstruct Locked typestate, resume at AwaitingFinality

[ ] Implement execute_from_proof recovery - load proof bytes from journal, skip proof generation, go straight to mint

[ ] Implement AwaitingFinality recovery - re-poll finality monitor with proof height from journal

[ ] Implement ProofBuilding recovery - check for persisted checkpoint, resume if exists

[x] Wire proof_payload into ExecutionJournalEntry - added block_height, tx_hash_bytes, proof_payload fields and SQL migration

[ ] Wire csv-coordinator isolation-domain behavior - implement actual per-chain execution cell logic in csv-coordinator/src/cell.rs

[x] Integrate observability types into runtime - replaced HealthMonitor with RuntimeHealth from csv-observability

[x] Add Celestia to Chain enum in csv-cli - enabled Celestia across all CLI commands (parse_chain, default config, get_rpc_url)

[ ] Add Solana to test matrix - include solana pairs in csv-cli commands/tests.rs test run

[ ] Wire chain_management.rs commands - connect ChainCommands (discover, validate, create-template) to Commands enum in main.rs

[x] Add runtime subcommand - implemented runtime status, health, admission, events commands using csv_runtime::HealthMonitor, csv_admission::AdmissionController, csv_observability::runtime_health::{RuntimeHealth, DegradedReason}

[x] Add content subcommand - implemented content tree and selective disclosure CLI commands using csv_content::content_tree::{ContentTree, ContentProof, DisclosureProof}, csv_content::addressing::compute_content_address, csv_content::attachments::{AttachmentRef, MediaType}, csv_content::participants::{Participant, ParticipantRole, ParticipantSet, ParticipantId}, csv_content::claims::{Claim, ClaimPredicate, ContentRights}, csv_content::encryption::{EncryptionDescriptor, EncryptionEnvelope, KeyAccess}, csv_content::resource_accounting::VerificationLimit

[x] Add trust subcommand - implemented trust export/import/verify/rotate commands with TrustPackage struct (version, genesis_hash, checkpoint, validators, expiry, multi-sig signature)

[x] Organize examples - moved to csv-examples/getting-started/, csv-examples/advanced/, csv-examples/cli-tutorial/

[x] Create CLI tutorial - comprehensive csv-cli-tutorial.md with testnet examples for all commands
