**CSV Protocol - Testnet Release Implementation Plan**

# ** Complete Actionable Implementation Plan**

Ordered by severity. Each issue includes exact file paths, the specific change required, and the test that validates it. Work items are numbered for tracking.

**⚠ DO NOT begin external testnet until all CRITICAL items (T1-T6) are complete. HIGH items (T7-T12) must be complete before inviting external validators. MEDIUM items (T13-T20) required before public testnet announcement.**

## **T1 - CRITICAL: Remove Finality Stub, Implement Hard-Fail Enforcement**

ℹ File: csv-runtime/src/transfer_coordinator.rs | File: csv-runtime/src/policy.rs | File: csv-runtime/src/runtime_mode.rs

Current state: FinalityProof::new(vec!\[0u8; 32\], 6, false) is used as the actual finality proof. The check_finality call is commented out. RuntimeMode::Degraded sets enforces_strict_finality = false, silently bypassing finality on RPC failure.

### **T1.1 - Uncomment and wire finality check in execute_transfer**

// In TransferCoordinator::execute_transfer(), replace the stub:

// FinalityProof::new(vec!\[0u8; 32\], 6, false).unwrap() // DELETE THIS

let finality_proof = adapter_registry

.get_adapter(&transfer.source_chain)?

.check_finality(&transfer.source_chain, lock_result.block_height)

.await

.map_err(|e| TransferCoordinatorError::FinalityFailed(e.to_string()))?;

if !finality_proof.is_verified {

return Err(TransferCoordinatorError::FinalityFailed(

"Finality not achieved - transfer aborted".into()

));

}

### **T1.2 - Hard-fail finality against DeploymentProfile threshold**

// In RuntimePolicy::check_finality_threshold():

pub fn check_finality_threshold(

&self, chain: &str, observed: u64

) -> Result&lt;(), TransferCoordinatorError&gt; {

let required = self.finality_depth_for_chain(chain);

if observed < required {

return Err(TransferCoordinatorError::FinalityFailed(format!(

"Chain {chain}: observed {observed} < required {required}"

)));

}

Ok(())

}

### **T1.3 - Remove Degraded-mode finality bypass**

// In RuntimeMode::enforces_strict_finality():

pub fn enforces_strict_finality(&self) -> bool {

// BEFORE: Degraded returned false - WRONG

// AFTER: All modes enforce strict finality

true // finality is never optional

}

Note: Degraded mode may allow RPC fallback but MUST NOT reduce finality requirements. Decouple the two concerns.

### **T1 Validation Tests**

| **Test Name**                         | **Assertion**                                                  | **Type**  |
| ------------------------------------- | -------------------------------------------------------------- | --------- |
| finality_stub_absent                  | grep FinalityProof.\*0u8.\*32 csv-runtime/src/ = zero matches  | CI lint   |
| finality_threshold_enforced           | Test: observed=5 on chain requiring 6 → Err(FinalityFailed)    | Unit test |
| degraded_mode_still_enforces_finality | Test: RuntimeMode::Degraded.enforces_strict_finality() == true | Unit test |

## **T2 - CRITICAL: Implement TransferExecutionLog (Durable Execution Journal)**

ℹ New file: csv-runtime/src/execution_journal.rs | Modified: csv-runtime/src/transfer_coordinator.rs

No durable execution journal exists. Crash between any two transfer phases loses progress and risks duplicate mint or missed rollback. CheckpointManager stores snapshots but does not constitute a phase journal.

### **T2.1 - Define TransferExecutionLog**

// csv-runtime/src/execution_journal.rs

pub struct TransferPhaseEntry {

pub transfer_id: String,

pub replay_id: ReplayIdHash,

pub proof_hash: \[u8; 32\],

pub phase: TransferStage,

pub ts: SystemTime,

pub outcome: PhaseOutcome, // Entered | Completed | Failed(reason)

pub attempt: u32,

}

pub trait ExecutionJournal: Send + Sync {

fn record(&self, entry: TransferPhaseEntry) -> Result&lt;(), JournalError&gt;;

fn incomplete_transfers(&self) -> Result&lt;Vec<IncompleteTransfer&gt;, JournalError>;

fn latest_phase(&self, transfer_id: &str) -> Result&lt;Option<TransferStage&gt;, JournalError>;

}

### **T2.2 - Inject journal into TransferCoordinator**

pub struct TransferCoordinator {

// ... existing fields ...

journal: Arc&lt;dyn ExecutionJournal&gt;, // ADD

}

// Before EVERY phase transition in execute_transfer:

self.journal.record(TransferPhaseEntry {

transfer_id: transfer_id.clone(),

phase: TransferStage::LockConfirmed,

outcome: PhaseOutcome::Entered,

attempt: attempt_count,

..

})?;

// ... perform phase ...

self.journal.record(TransferPhaseEntry {

phase: TransferStage::LockConfirmed,

outcome: PhaseOutcome::Completed,

..

})?;

### **T2.3 - Add resume_transfer() entry point**

impl TransferCoordinator {

pub async fn resume_transfer(

&self, transfer_id: &str

) -> Result&lt;TransferReceipt, TransferCoordinatorError&gt; {

let phase = self.journal.latest_phase(transfer_id)?

.ok_or(TransferCoordinatorError::NotFound)?;

match phase {

TransferStage::Initialized => self.execute_from_lock(transfer_id).await,

TransferStage::LockConfirmed => self.execute_from_proof(transfer_id).await,

TransferStage::ProofGenerated => self.execute_from_mint(transfer_id).await,

TransferStage::MintBroadcast => self.execute_from_mint_confirm(transfer_id).await,

TransferStage::Completed => Err(TransferCoordinatorError::AlreadyComplete),

TransferStage::RolledBack => Err(TransferCoordinatorError::AlreadyRolledBack),

}

}

}

### **T2 Crash Recovery Test Matrix**

| **Crash Point**                  | **Inject Method**                       | **Required Recovery Behavior**                          |
| -------------------------------- | --------------------------------------- | ------------------------------------------------------- |
| before_lock                      | SIGKILL before lock broadcast           | restart → detects Initialized → re-lock → no duplicate  |
| after_lock_before_proof          | SIGKILL after lock confirmed            | restart → resumes from LockConfirmed → generates proof  |
| after_proof_before_mint          | SIGKILL after proof stored              | restart → resumes from ProofGenerated → mint only       |
| during_mint_broadcast            | SIGKILL after tx submit, before receipt | restart → idempotent mint (contract rejects duplicate)  |
| during_rollback                  | SIGKILL mid-rollback                    | restart → rollback completes idempotently               |
| after_replay_persist_before_mint | SIGKILL at exact boundary               | restart → replay already recorded → mint resumes safely |
| during_finality_wait             | SIGKILL mid-finality poll               | restart → re-polls finality → no state corruption       |
| before_proof_generation          | SIGKILL before ZK proof                 | restart → proof re-generated from journal entry         |

## **T3 - CRITICAL: Eliminate .expect() from All Production Paths**

ℹ Files: All production Rust files across 8+ crates

Policy: clippy.toml has expect-used = deny per-crate. Audit found .expect() in csv-cli, all 6 adapters, csv-core (14 sites), csv-hash, csv-keys, csv-proof, csv-runtime, csv-sdk, csv-storage. Policy != enforcement because per-crate clippy.toml scope may not cover all modules.

### **T3.1 - Immediate fix: CSV-CLI lease.rs**

// csv-cli/src/commands/cross_chain/lease.rs - BEFORE:

.get(&sanad_id_hash)

.expect("lease should exist after acquisition")

// AFTER:

.get(&sanad_id_hash)

.ok_or_else(|| anyhow::anyhow!(

"Lease acquisition succeeded but lease not found in registry - internal error"

))?;

### **T3.2 - Workspace-level clippy enforcement**

// Root Cargo.toml \[workspace.lints\]:

\[workspace.lints.clippy\]

expect_used = "deny"

unwrap_used = "deny"

panic = "deny"

// Then: cargo clippy --workspace -- -D warnings

Exceptions: build.rs scripts and bin/ generator tools may use expect; add #\[allow(clippy::expect_used)\] with justification comment.

### **T3.3 - RocksDB column family panic fix**

// csv-storage/src/backends/rocksdb.rs - replace:

.expect("replay_entries CF")

// with:

.ok_or_else(|| StorageError::MissingColumnFamily("replay_entries"))?

### **T3 Validation**

| **Check**               | **Command**                                        | **Gate Type**              |
| ----------------------- | -------------------------------------------------- | -------------------------- |
| no_expect_in_production | cargo clippy --workspace -- -D clippy::expect_used | CI gate (must block merge) |
| no_unwrap_in_production | cargo clippy --workspace -- -D clippy::unwrap_used | CI gate                    |
| no_panic_in_production  | cargo clippy --workspace -- -D clippy::panic       | CI gate                    |

## **T4 - CRITICAL: Move Lease and Transfer State Out of CLI**

ℹ File: csv-cli/src/state.rs | File: csv-cli/src/commands/cross_chain/lease.rs | File: csv-runtime/src/transfer_coordinator.rs

UnifiedStateManager in CLI owns leases (in-memory HashMap) and transfer records. CLI calls state.store_lease() inside command execution. This makes the CLI a co-authority on protocol state, which breaks the authority model.

### **T4.1 - Remove lease storage from CLI state**

// csv-cli/src/state.rs - REMOVE:

leases: HashMap&lt;String, LeaseInfo&gt;, // DELETE

pub fn store_lease(...) { ... } // DELETE

pub fn get_lease(...) { ... } // DELETE

// csv-cli/src/state.rs - ADD:

// CLI state holds only: wallet keys, config, sanad display records

// All protocol authority lives in csv-runtime

### **T4.2 - Lease acquisition returns only an opaque token**

// csv-cli/src/commands/cross_chain/lease.rs - AFTER refactor:

let lease_token = csv_runtime_client

.acquire_lease(sanad_id, chain, ttl_secs)

.await?;

// Display the token; do NOT store in CLI state

output::success(&format!("Lease token: {}", lease_token));

output::info("Pass this token to the transfer command.");

### **T4.3 - CLI command taxonomy (target architecture)**

| **Command**                      | **Action**                         | **CLI Role** |
| -------------------------------- | ---------------------------------- | ------------ |
| csv transfer create              | Issues transfer request to runtime | Stateless    |
| csv transfer inspect &lt;id&gt;  | Reads from runtime journal         | Read-only    |
| csv transfer resume &lt;id&gt;   | Calls runtime.resume_transfer()    | Delegated    |
| csv transfer rollback &lt;id&gt; | Calls runtime.rollback_transfer()  | Delegated    |
| csv runtime health               | Reads runtime HealthStatus         | Read-only    |
| csv runtime reconcile            | Triggers runtime reconciliation    | Delegated    |
| csv runtime recover &lt;id&gt;   | Calls journal-driven recovery      | Delegated    |
| csv lease acquire                | Returns opaque token only          | Stateless    |

## **T5 - CRITICAL: Unify Replay Storage Backend (SQLite vs PostgreSQL)**

ℹ File: csv-store/src/operations/replay_store.rs | File: csv-runtime/src/postgres_store.rs | File: csv-storage/src/backends/

Two independent replay implementations exist: SQLite (csv-store) and PostgreSQL (csv-runtime/postgres_store.rs). They share no common trait verification. CI likely runs SQLite path. Production runs PostgreSQL. Divergence risk is high.

### **T5.1 - Define a single ReplayDatabase trait (it already exists in csv-storage, extend it)**

// csv-storage/src/traits.rs - ensure this covers:

pub trait ReplayDatabase: Send + Sync {

async fn insert_if_absent(&self, id: ReplayIdHash) -> Result&lt;(), ReplayError&gt;;

async fn contains(&self, id: ReplayIdHash) -> Result&lt;bool, ReplayError&gt;;

async fn record_conflict(&self, id: ReplayIdHash) -> Result&lt;(), ReplayError&gt;;

async fn conflict_count(&self, id: ReplayIdHash) -> Result&lt;u64, ReplayError&gt;;

}

### **T5.2 - Both backends must pass the same test suite**

// csv-storage/tests/replay_conformance.rs

macro_rules! replay_conformance_suite {

(\$backend:expr) => {

async fn insert_if_absent_is_atomic() { ... }

async fn duplicate_rejected() { ... }

async fn conflict_count_increments() { ... }

async fn concurrent_inserts_no_duplicate() { ... }

}

}

replay_conformance_suite!(RocksDbReplayDb::open_temp());

replay_conformance_suite!(PostgresReplayDb::connect_test());

replay_conformance_suite!(SqliteReplayStore::open_temp());

### **T5 Validation**

| **Test**             | **Assertion**                                           | **Status** |
| -------------------- | ------------------------------------------------------- | ---------- |
| sqlite_conformance   | All 4 conformance tests pass on SQLite backend          | Required   |
| postgres_conformance | All 4 conformance tests pass on PostgreSQL backend      | Required   |
| rocksdb_conformance  | All 4 conformance tests pass on RocksDB backend         | Required   |
| no_divergence_gate   | CI runs conformance suite on all 3 backends in same job | CI gate    |

## **T6 - CRITICAL: Add csv-wallet to Workspace, Resolve Documentation Drift**

ℹ File: Cargo.toml | File: AGENTS.md

AGENTS.md references csv-wallet as a core crate. The WASM build CI command references --package csv-wallet. Cargo.toml workspace.members does not include csv-wallet. This means WASM CI fails silently or errors unreported.

// Cargo.toml workspace.members - ADD if crate exists:

"csv-wallet",

// OR update AGENTS.md and CI to remove the reference if the crate

// has been subsumed into csv-sdk. Pick one canonical answer.

Resolution: Audit all AGENTS.md crate references against workspace members. Every referenced crate must be in the workspace. Every workspace crate must have an entry in AGENTS.md.

# **HIGH Priority Items (Required Before External Validators)**

## **T7 - HIGH: Implement Lease Invariant Assertions + Adversarial Lease Tests**

ℹ File: csv-runtime/src/lease.rs | File: csv-runtime/src/postgres_store.rs | New: csv-testkit/tests/lease_adversarial.rs

The lease data model is correct. The missing piece is continuous runtime assertion that exactly one coordinator is active, and adversarial tests for lease edge cases.

### **T7.1 - Runtime invariant assertion**

// csv-runtime/src/transfer_coordinator.rs

fn assert_single_active_coordinator(

&self, transfer_id: &str

) -> Result&lt;(), TransferCoordinatorError&gt; {

let lease = self.coordinator_lease

.as_ref()

.ok_or(TransferCoordinatorError::NoLeaseBackend)?

.get_active_lease(transfer_id)?;

if lease.owner_runtime_id != self.runtime_id {

return Err(TransferCoordinatorError::LeaseViolation(

format!("Coordinator {} does not own lease for {}",

self.runtime_id, transfer_id)

));

}

Ok(())

}

// Call this at the start of EVERY mutating operation

### **T7 Adversarial Lease Test Matrix**

| **Scenario**           | **Inject Method**                                                   | **Required Outcome**                                  |
| ---------------------- | ------------------------------------------------------------------- | ----------------------------------------------------- |
| duplicate_coordinators | Two coordinators attempt acquire on same transfer_id simultaneously | Second must fail with LeaseConflict                   |
| expired_lease_reuse    | Runtime crashes; lease expires (wait TTL); second runtime acquires  | Second must succeed with new epoch                    |
| clock_drift            | System clock moves backward by 60s during lease renewal             | Lease must not appear expired; renewal must succeed   |
| network_partition      | Postgres unreachable during renewal; lease expires                  | Coordinator must detect and halt operations           |
| db_failover            | Postgres primary fails; replica promoted mid-transfer               | Transfer must resume after failover without duplicate |
| delayed_renewal        | Renewal delayed until 5s before expiry                              | Renewal must succeed; operations must continue        |

## **T8 - HIGH: Add Forensic Fields to TransferEvent**

ℹ File: csv-runtime/src/event_bus.rs

Every TransferEvent variant currently carries only transfer_id: String. Forensic debugging requires replay_id, proof_hash, coordinator_id, lease_id, finality_state, rollback_reason, and recovery_attempt on each event.

// csv-runtime/src/event_bus.rs - replace scalar events with structured context:

pub struct TransferContext {

pub transfer_id: String,

pub replay_id: Option&lt;ReplayIdHash&gt;,

pub proof_hash: Option&lt;\[u8; 32\]&gt;,

pub coordinator_id: Uuid,

pub lease_id: Option&lt;Uuid&gt;,

pub source_chain: String,

pub dest_chain: String,

pub finality_state: FinalityState,

pub recovery_attempt: u32,

}

pub enum TransferEvent {

Locking(TransferContext),

AwaitingFinality(TransferContext),

BuildingProof(TransferContext),

ProofVerified(TransferContext),

Minting(TransferContext),

Complete(TransferContext),

RollbackTriggered { ctx: TransferContext, reason: String },

ReplayDetected(TransferContext),

}

## **T9 - HIGH: Mandatory End-to-End Integration Test Matrix (No Optional Fallbacks)**

ℹ File: .github/workflows/integration.yml or CI config | New: tests/e2e/

Integration tests use || echo fallback, making failures non-blocking. Every supported chain pair must have mandatory, blocking integration tests.

### **T9.1 - Remove all || echo fallbacks from CI**

\# Before (non-blocking):

run_bitcoin_tests || echo "No Bitcoin integration tests yet"

\# After (blocking):

run_bitcoin_tests # Failure = CI failure

### **T9 Required Integration Matrix**

| **Chain Pair**     | **Required Capabilities**                                                    |
| ------------------ | ---------------------------------------------------------------------------- |
| bitcoin → aptos    | seal, proof, replay-reject, reorg, rollback, finality, verify, mint-recovery |
| bitcoin → ethereum | seal, proof, replay-reject, reorg, rollback, finality, verify, mint-recovery |
| ethereum → aptos   | seal, proof, replay-reject, reorg, rollback, finality, verify, mint-recovery |
| ethereum → solana  | seal, proof, replay-reject, reorg, rollback, finality, verify, mint-recovery |
| solana → sui       | seal, proof, replay-reject, reorg, rollback, finality, verify, mint-recovery |
| sui → aptos        | seal, proof, replay-reject, reorg, rollback, finality, verify, mint-recovery |

### **T9.2 - Chaos injection per integration test**

| **Chaos Scenario**       | **Inject Method**                  | **Required Behavior**                       |
| ------------------------ | ---------------------------------- | ------------------------------------------- |
| RPC timeout              | Inject 30s delay mid-proof         | Transfer must retry and complete            |
| Stale node response      | Return block N-100 to RPC call     | Finality check must reject stale block      |
| Malformed proof bytes    | Flip 1 bit in proof bundle         | Verifier must reject; rollback must trigger |
| Delayed block visibility | Withhold block for 30s then reveal | Finality wait must handle and proceed       |
| Conflicting RPC nodes    | 50% nodes return different root    | Quorum check must detect conflict           |

## **T10 - HIGH: Aggressive Byzantine Replay Testing**

ℹ File: csv-testkit/src/adversarial.rs | New: csv-testkit/tests/replay_byzantine.rs

ByzantineBehavior enum exists. Only quorum_agrees() and assert_tampered_bundle_rejected() are implemented. Concurrency-based replay attacks are not tested.

| **Byzantine Scenario**      | **Method**                                                        | **Required Outcome**                                        |
| --------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------- |
| duplicate_transfer_race     | Two goroutines submit same transfer_id simultaneously             | Exactly one must succeed; second must return ReplayDetected |
| replay_db_lag               | Replay DB write delayed 500ms; retry arrives before confirmation  | Atomic CAS must reject second attempt                       |
| stale_coordinator_snapshot  | Coordinator loads checkpoint from 5 min ago; replays old transfer | Replay nullifier must reject even against old snapshot      |
| concurrent_proof_submission | 100 concurrent proof submits for same seal                        | Exactly one consumed; 99 rejected                           |
| partial_replay_write        | Crash after replay ID written but before transfer state persisted | Restart must detect inconsistency and not mint              |

## **T11 - HIGH: EventStore Integration with TransferCoordinator**

ℹ File: csv-runtime/src/event_store.rs | File: csv-runtime/src/transfer_coordinator.rs

EventStore trait and PostgresEventStore implementation exist. TransferCoordinator does not write to EventStore on state transitions. The EventBus (in-memory callbacks) is separate and not durable.

// TransferCoordinator must inject and write to EventStore:

pub struct TransferCoordinator {

event_store: Arc&lt;dyn EventStore&gt;, // ADD - durable

event_bus: EventBus, // KEEP - in-memory fanout

}

// On every state transition:

let envelope = RuntimeEventEnvelope {

aggregate_id: transfer_id.clone(),

event_type: "TransferPhaseCompleted".into(),

payload: serde_json::to_vec(&phase_data)?,

version: next_version,

};

self.event_store.append(&envelope)?; // durable write FIRST

self.event_bus.emit(TransferEvent::...); // then notify subscribers

## **T12 - HIGH: Contract Adversarial Suite**

ℹ Contracts: csv-contracts/ethereum/, csv-contracts/aptos/, csv-contracts/solana/, csv-contracts/sui/

| **Attack Scenario**    | **Method**                                | **Required Contract Behavior**                   |
| ---------------------- | ----------------------------------------- | ------------------------------------------------ |
| double_consume         | Submit same proof bundle twice            | Second tx must revert with AlreadyConsumed       |
| malformed_merkle_proof | Flip 1 byte in Merkle sibling             | Verification must fail; no state change          |
| replay_nullifier_reuse | Use consumed nullifier in new transfer    | Contract must reject                             |
| stale_checkpoint       | Submit proof against checkpoint N-5 (old) | Contract must reject; require current checkpoint |
| forged_anchor          | Submit anchor hash not in event log       | Contract must reject anchor verification         |
| partial_event_replay   | Omit 1 event from event bundle            | Merkle root mismatch; contract rejects           |
| duplicate_mint_proof   | Submit valid mint proof twice             | Second mint must revert                          |

# **MEDIUM Priority Items (Required Before Public Testnet Announcement)**

## **T13 - MEDIUM: Serialization Constitution v1**

ℹ New file: docs/SERIALIZATION_CONSTITUTION.md | File: FREEZE_POLICY.md

FREEZE_POLICY.md declares a freeze but has no automated CI enforcement. The 'should be added' CI checks were never added. Before external tooling is built against the protocol, canonical formats must freeze.

| **Area**            | **Freeze Mechanism**                            | **Enforcement**                                            |
| ------------------- | ----------------------------------------------- | ---------------------------------------------------------- |
| proof_bundle_layout | CBOR schema published; golden fixture locked    | Automated golden test must block regression                |
| replay_identity     | ReplayId derivation inputs frozen               | csv-runtime/tests/protocol_constitution/hash_stability.rs  |
| mux_tree_ordering   | MuxTree leaf ordering frozen                    | Golden CBOR fixture                                        |
| hash_preimages      | All domain separation strings frozen            | proof_domain_separation.rs - extend with freeze assertions |
| event_formats       | TransferEvent serialization schema frozen       | Schema registry test                                       |
| contract_abi        | All contract function signatures frozen         | Foundry/Anchor snapshot test                               |
| cli_export_formats  | \--output cbor and --output json formats frozen | CLI golden output test                                     |

### **T13.1 - CI Serialization Freeze Check**

\# Add to CI:

cargo test -p csv-core --test golden # already exists

cargo test -p csv-runtime --test protocol_constitution # extend

\# Block merge if golden fixtures change without explicit re-generation

## **T14 - MEDIUM: Reorg Survivability Tests**

ℹ File: csv-adapters/csv-bitcoin/tests/reorg_tests.rs | Add: csv-adapters/csv-ethereum/tests/reorg_tests.rs

csv-bitcoin has reorg_tests.rs skeleton. No evidence it covers transfer state recovery after a reorg. Ethereum has no reorg tests.

| **Reorg Scenario**          | **Trigger**                                     | **Required Behavior**                                     |
| --------------------------- | ----------------------------------------------- | --------------------------------------------------------- |
| reorg_before_lock_confirmed | Reorg removes lock tx from canonical chain      | Runtime must detect and re-lock or rollback               |
| reorg_after_proof_generated | Reorg invalidates block containing proof anchor | Runtime must regenerate proof from new canonical block    |
| reorg_during_finality_wait  | Reorg during confirmation counting              | Finality depth counter must reset; wait must restart      |
| reorg_after_mint            | Destination chain reorgs after mint             | Source lock must remain locked until re-finality achieved |

## **T15 - MEDIUM: CLI Security UX Features**

ℹ File: csv-cli/src/encrypt.rs | File: csv-cli/src/main.rs

| **Feature**           | **Implementation Note**                                                                | **Priority** |
| --------------------- | -------------------------------------------------------------------------------------- | ------------ |
| encrypted_keystore    | csv-cli/src/encrypt.rs exists; verify Argon2id params are testnet-grade (t=3, m=65536) | REQUIRED     |
| transaction_preview   | csv transfer create must show: from, to, amount, gas, replay_id before signing         | REQUIRED     |
| deterministic_dry_run | csv transfer create --dry-run: full execution path, no broadcast                       | REQUIRED     |
| proof_inspection      | csv proof inspect &lt;id&gt;: show proof fields before submission                      | REQUIRED     |
| replay_status         | csv replay status &lt;id&gt;: show nullifier registry entry                            | REQUIRED     |
| lease_inspection      | csv lease inspect &lt;id&gt;: show lease owner, TTL, epoch                             | REQUIRED     |
| recovery_command_set  | csv transfer resume/rollback/recover commands wired to runtime                         | REQUIRED     |
| hardware_wallet       | HW wallet integration for signing; software signer must warn                           | RECOMMENDED  |

## **T16 - MEDIUM: Resolve Move Contract Warnings**

ℹ File: csv-contracts/aptos/

Build output contains: unknown attribute #\[cmd\]. This indicates the Aptos Move compiler does not recognize an attribute used in contract code. While not a security vulnerability, it signals incomplete contract hygiene and may produce unexpected behavior in future compiler versions.

// Audit all #\[cmd\] usages in Aptos Move contracts

// Replace with #\[view\] or correct Aptos framework attribute

// Run: aptos move compile 2>&1 | grep -i warning

// Target: zero warnings on contract compilation

## **T17 - MEDIUM: CI Must Enforce Integration Success**

ℹ File: CI configuration

\# Remove ALL of these patterns:

command || echo "..."

command || true

\# Replace with:

command # naked - failure fails the job

\# For tests requiring RPC secrets, use:

\# 1. Environment-gated secrets in CI

\# 2. Local mock RPC for unit path

\# 3. Real RPC for integration path - both REQUIRED

## **T18 - MEDIUM: Crash Recovery Smoke Test in CI**

ℹ New: csv-runtime/tests/crash_recovery_smoke.rs

Implement a deterministic crash-recovery smoke test that does not require a real chain. Use in-memory adapters and an injected failure point.

// csv-runtime/tests/crash_recovery_smoke.rs

# \[tokio::test\]

async fn crash_at_proof_phase_resumes_correctly() {

let coordinator = test_coordinator_with_failure_at(TransferStage::ProofGenerated);

let result = coordinator.execute_transfer(test_transfer()).await;

assert!(matches!(result, Err(TransferCoordinatorError::InjectedFailure)));

// Simulate restart

let coordinator2 = test_coordinator_with_journal(coordinator.journal());

let resumed = coordinator2.resume_transfer("test-transfer-id").await;

assert!(resumed.is_ok(), "Resume must succeed from ProofGenerated phase");

}

## **T19 - MEDIUM: Observability Completeness Audit**

ℹ File: csv-observability/ | File: csv-runtime/src/event_bus.rs

Every transfer must emit all required forensic fields (see T8). Additionally, Prometheus metrics must cover: transfer count by chain pair, replay rejection rate, finality wait duration, crash recovery count, lease acquisition failure rate.

| **Metric**                   | **Prometheus Definition**                      | **Status** |
| ---------------------------- | ---------------------------------------------- | ---------- |
| transfer_count_by_chain_pair | Counter: csv_transfers_total{from, to}         | REQUIRED   |
| replay_rejection_rate        | Counter: csv_replay_rejections_total{chain}    | REQUIRED   |
| finality_wait_duration       | Histogram: csv_finality_wait_seconds{chain}    | REQUIRED   |
| crash_recovery_count         | Counter: csv_crash_recoveries_total{phase}     | REQUIRED   |
| lease_acquisition_failure    | Counter: csv_lease_failures_total{reason}      | REQUIRED   |
| proof_generation_duration    | Histogram: csv_proof_generation_seconds{chain} | REQUIRED   |

## **T20 - MEDIUM: Runtime Sovereignty Completion**

Final architectural target: csv-runtime is the sole authority for all protocol execution. The CLI and SDK are clients only.

| **Capability**       | **Implementation**                               | **Authority**                                |
| -------------------- | ------------------------------------------------ | -------------------------------------------- |
| Execution journal    | T2 above                                         | Runtime owns it                              |
| Lease registry       | T4 + T7 above                                    | Runtime owns it                              |
| Replay registry      | T5 above                                         | Runtime owns it                              |
| Coordinator identity | RuntimeId (Uuid) - already in lease.rs           | Runtime owns it                              |
| Recovery commands    | T2.3 resume_transfer() + CLI wiring              | Runtime owns it                              |
| Rollback authority   | TransferCoordinator::rollback_transfer()         | Runtime owns it - verify CLI just calls this |
| Reconciliation       | TransferCoordinator::reconcile() against journal | Runtime owns it - not implemented yet        |

# ** Execution Roadmap to L4 Testnet**

## **Phase 1 - Foundation Fixes (Week 1-2)**

Complete all CRITICAL items. No external sharing until this phase is done.

| **ID** | **Task**                                       | **Estimate** | **Rationale**                |
| ------ | ---------------------------------------------- | ------------ | ---------------------------- |
| T1     | Finality hard-fail enforcement                 | 2 days       | Unblock protocol correctness |
| T3     | Workspace-wide .expect() elimination           | 2 days       | Unblock CI gate              |
| T6     | csv-wallet workspace resolution                | 0.5 days     | Unblock WASM CI              |
| T2     | TransferExecutionLog + resume_transfer()       | 4 days       | Largest item; parallelizable |
| T4     | Lease/transfer state out of CLI                | 2 days       | Depends on T2                |
| T5     | Replay backend unification + conformance suite | 2 days       | Independent                  |

## **Phase 2 - Hardening (Week 3-4)**

Complete all HIGH items. Can begin internal adversarial testnet at end of this phase.

| **ID** | **Task**                                       | **Estimate** | **Rationale**             |
| ------ | ---------------------------------------------- | ------------ | ------------------------- |
| T7     | Lease invariant assertions + adversarial tests | 3 days       | Depends on T4             |
| T8     | TransferEvent forensic fields                  | 1 day        | Independent               |
| T9     | Mandatory integration matrix + chaos injection | 4 days       | Requires real RPC secrets |
| T10    | Byzantine replay testing                       | 2 days       | Independent               |
| T11    | EventStore integration in coordinator          | 1.5 days     | Depends on T2             |
| T12    | Contract adversarial suite                     | 3 days       | Independent               |

## **Phase 3 - Testnet Preparation (Week 5-6)**

Complete all MEDIUM items. Run 72-hour internal adversarial soak. Then L4 closed testnet.

| **ID** | **Task**                                       | **Estimate** | **Rationale**                |
| ------ | ---------------------------------------------- | ------------ | ---------------------------- |
| T13    | Serialization Constitution v1 + CI enforcement | 2 days       | Freezes external API surface |
| T14    | Reorg survivability tests                      | 3 days       | Bitcoin + Ethereum           |
| T15    | CLI security UX features                       | 3 days       | Operator safety              |
| T16    | Move contract warning resolution               | 0.5 days     | Contract hygiene             |
| T17    | CI mandatory integration enforcement           | 0.5 days     | CI config change             |
| T18    | Crash recovery smoke test in CI                | 1 day        | Depends on T2                |
| T19    | Observability completeness                     | 2 days       | Prometheus metrics           |
| T20    | Runtime sovereignty audit                      | 1 day        | Verification pass            |

## **L4 Readiness Checklist**

All items must be checked before any external validator is invited.

| **Item**     | **Condition**                                                       | **Gate**                           |
| ------------ | ------------------------------------------------------------------- | ---------------------------------- |
| T1 complete  | Finality stub removed; hard-fail enforced                           | Verified by CI test                |
| T2 complete  | TransferExecutionLog wired; all 8 crash points tested               | Recovery matrix test passes        |
| T3 complete  | Zero .expect()/.unwrap() in production code; CI gate active         | cargo clippy -D expect_used passes |
| T4 complete  | CLI holds zero protocol state; lease/transfer in runtime only       | Code review + test                 |
| T5 complete  | All 3 replay backends pass conformance suite                        | Conformance tests pass             |
| T6 complete  | csv-wallet in workspace or documentation corrected                  | cargo build --workspace succeeds   |
| T7 complete  | Lease invariant assertions + all 6 adversarial scenarios pass       | Test suite                         |
| T8 complete  | All TransferEvent variants have full forensic context               | Code review                        |
| T9 complete  | All 6 chain pairs × 8 capabilities tested; no \| echo fallbacks     | CI integration pass                |
| T10 complete | All 5 Byzantine replay scenarios pass                               | Test suite                         |
| T11 complete | EventStore writes on every coordinator state transition             | Code review + test                 |
| T12 complete | All 7 contract attacks rejected                                     | Contract test suite                |
| T13 complete | Serialization Constitution signed; CI golden tests block regression | CI pass                            |
| T14 complete | All 4 reorg scenarios pass on Bitcoin and Ethereum                  | Test suite                         |
| T15 complete | All required CLI security features present                          | Feature audit                      |
| 72h soak     | Internal adversarial testnet ran 72h with zero consensus failures   | Operator sign-off                  |

**Final Assessment**

The Principal Architect's assessment was accurate on all major points. Code-level audit confirms and, in two cases, upgrades the severity: the finality check is not merely unenforced - it is commented-out stub code shipping as implementation. The .expect() scope is workspace-wide, not a single instance.

The architecture is sound. csv-runtime, TransferCoordinator, lease.rs, CheckpointManager, and EventStore are well-designed. The gap is exclusively in operational wiring: the structures exist but are not connected into a crash-safe execution path.

Completing Phase 1 (T1-T6) transforms this from demo software into infrastructure software. Completing Phases 2-3 (T7-T20) makes it credible for a closed external testnet with validators who will actively probe the system.
