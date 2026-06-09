# Integrated Implementation Plan — CSV Protocol

**Created:** 2026-06-09
**Last Updated:** 2026-06-09
**Status:** Active — Phase 1.3 in progress (CLI state types, state/trace commands, cmd_list fix)
**Priority Order:** Contracts-Audit (CLI first) > AUDIT critical blockers > Serde stripping > Chain registry > Recovery > Naming reorganization > Contract freeze

---

## Progress Log

| Date | Phase | Tasks Completed |
|---|---|---|
| 2026-06-09 | PLAN.md created | Plan document created, conflicts resolved |
| 2026-06-09 | 1.1 | `SanadLifecycleState`, `SealLifecycleState`, `CanonicalSanadState`, `CanonicalSealState`, `CanonicalLifecycleEvent`, `LifecycleEventType` added to `csv-store/src/state/domain.rs` |
| 2026-06-09 | 1.2 | `csv sanad state` and `csv sanad trace` subcommands added to CLI. Query functions for all 6 chains implemented. |
| 2026-06-09 | 1.3 | `cmd_list` state collapsing fixed — now displays full `SanadLifecycleState` enum instead of "Active"/"Consumed" |
| 2026-06-09 | 2.1 | `CANONICAL-NAMING.md` created — unified function/event/state naming across all 4 chains |
| 2026-06-09 | 2.2 | `CSVSeal.sol` rewritten with canonical snake_case names, SanadState enum, SanadStateView, get_sanad_state(), canonical events |
| 2026-06-09 | 2.3 | `CSVLock.sol` and `CSVMint.sol` archived to `legacy/` directory |
| 2026-06-09 | 2.4 | Solana `SanadAccount` updated with `state: u8` field (replaces consumed/locked booleans), canonical events added (SanadLocked, SanadMinted, SanadRefunded), view functions stubbed |
| 2026-06-09 | 2.5 | Sui `csv_seal.move` updated with `state: u8` field, canonical events (SanadLocked, SanadMinted, SanadRefunded, SanadTransferred), canonical function names (transfer_sanad, is_seal_consumed), missing functions added (refund_sanad, anchor_commitment, record_sanad_metadata, get_sanad_state, etc.) |
| 2026-06-09 | 2.6 | Aptos `CSVSeal.move` updated with `state: u8` field in Seal resource, canonical events, canonical function names, missing functions added (refund_sanad, transfer_sanad, anchor_commitment, record_sanad_metadata, get_sanad_state, can_refund, etc.) |
| 2026-06-09 | Cleanup | Removed deployment output files (deployment.out, deploy-output-testnet.txt, deploy-output-testnet.json). Archived CSVLock.sol and CSVMint.sol to legacy/ directory. |
| 2026-06-09 | Deploy scripts | Rewrote deploy.sh — removed --verify flag (causes failures), adds ~/.csv/config.toml updates, adds ~/.csv/deployment-ethereum.json generation, adds repo deployments folder updates. Rewrote update_manifest.rs with proper bytecode hash computation. |

---

## Source Documents

| Document | Purpose | Priority |
|---|---|---|
| `Contracts-Audit.md` | Canonical lifecycle, CLI state collapse, contract naming | **P0** |
| `AUDIT.md` | 20 critical release blockers, 196 issues | **P0** |
| `UNWIRED.md` | Execution checklist (11 done, 7 pending) | **P1** |
| `config-data-oriented-chain-addition-plan.md` | Chain registry, config-driven addition | **P2** |
| `self-expressive-architecture-plan.md` | Naming reorganization, directory structure | **P3** |

## Guardrails

| Document | Key Rules |
|---|---|
| `AGENTS.md` | Dependency rules, serde_json forbidden in hashing, finality never optional |
| `csv-docs/PROTOCOL_INVARIANTS.md` | Seal IDs from real tx, commitments published before proof building |
| `csv-docs/PROTOCOL_CONSTITUTION.md` | Canonical CBOR, CBOR tags 0x1C0-0x1FF, field declaration order |
| `csv-docs/THREAT_MODEL.md` | RPC untrusted, quorum required, finality depth checks |
| `csv-docs/rfcs/RFC-0009-contract-canonical-events.md` | Canonical event names (SanadCreated, SanadConsumed, etc.) |
| `csv-docs/rfcs/RFC-0011-config-driven-chain-addition.md` | Chain registry spec |
| `deny.toml` | Compile-time dependency constraints |

---

## Conflict Resolutions

| Conflict | Resolution |
|---|---|
| AUDIT B-001: csv-core excluded vs UNWIRED: csv-core deleted | **Resolved.** csv-core is deleted (UNWIRED complete). Self-expressive plan's "rename csv-core to csv-advanced" is moot. |
| Self-expressive: migrate csv-core modules vs csv-core deleted | **Resolved.** Migration targets are already in their destinations. Skip csv-core migration. |
| AUDIT: strip serde from 196 types vs Config-driven: ChainConfig derives Serialize | **Resolved.** ChainConfig is L5+ config metadata (allowed). Serde stripping applies to L0-L4 protocol types only. |
| Contracts-Audit: canonical events vs ABI constitution: different names | **Resolved.** Phase 2 aligns ABI constitution with RFC-0009 canonical names, then updates Solidity contracts. |
| Contracts-Audit: get_sanad_state on all chains vs AUDIT B-003: Sanad descriptor | **Resolved.** Phase 1 adds CLI state types. Phase 2 adds on-chain state. Phase 6 fixes Sanad ID/descriptor. |

---

## Phase Overview

| Phase | Description | Depends On | Est. Days | Status |
|---|---|---|---|---|
| 1.1 | Canonical state types in csv-store | — | 0.5 | **DONE** |
| 1.2 | CLI state/trace subcommands | 1.1 | 1 | **DONE** |
| 1.3 | Fix state collapsing in cmd_list | 1.2 | 0.5 | **DONE** |
| 1.4 | Fix Ethereum state mapping | 1.3 | 0.5 | **DONE** |
| 1.5 | Fix Sui/Solana/Aptos state mapping | 1.3 | 0.5 | **DONE** |
| 1.6 | Display formatting | 1.3 | 0.5 | **DONE** |
| 2 | Ethereum contract unification + canonical events | Phase 1 | 3-4 | Pending |
| 3 | ABI constitution alignment + binding generation | Phase 2 | 2-3 | Pending |
| 4 | Solana/Sui/Aptos canonical state + events | Phase 1 | 3-4 | Pending |
| 5 | CLI adapter trait SanadStateReader | Phase 1 | 2-3 | Pending |
| 6 | AUDIT critical blockers (Sanad ID, proof, schema, ZK, MPT, secrets) | Phase 1 | 5-7 | Pending |
| 7 | Serde audit manifest + L0-L4 stripping | Phase 6 | 5-7 | Pending |
| 8 | Chain registry + config-driven addition | Phase 7 | 4-6 | Pending |
| 9 | Recovery implementation (execute_from_lock/proof, AwaitingFinality, ProofBuilding) | Phase 6, 7 | 4-6 | Pending |
| 10 | Solana test matrix + chain management wiring | Phase 6 | 2-3 | Pending |
| 11 | Self-expressive naming reorganization | Phase 1-10 | 5-7 | Pending |
| 12 | Contract freeze (ABI hash, bytecode hash, governance, adversarial tests) | Phase 2-4 | 4-6 | Pending |

---

## Dependency Graph

```
Phase 1 (CLI state) ─────────────────────────────────┐
    │                                                 │
    ▼                                                 ▼
Phase 2 (ETH contracts) ── Phase 3 (ABI constitution) ── Phase 12 (Contract freeze)
    │                                                             │
    ▼                                                             ▼
Phase 4 (Sol/Sui/Aptos) ── Phase 5 (CLI adapter trait) ── Phase 10 (Solana test)
    │
    ▼
Phase 6 (AUDIT blockers) ─────────────────────────────┐
    │                                                  │
    ▼                                                  ▼
Phase 7 (Serde stripping) ── Phase 8 (Chain registry) ── Phase 11 (Naming)
    │
    ▼
Phase 9 (Recovery)
```

**Parallelism:**
- Phase 2-4 (contracts) can run in parallel after Phase 1
- Phase 5 (CLI adapter) depends on Phase 1 only
- Phase 6 (AUDIT blockers) is independent of contract work
- Phase 12 (contract freeze) depends on Phase 2-4

---

## Phase 1: CLI Canonical State + Commands

**Source:** `Contracts-Audit.md` sections "CLI fixes", "Recommended canonical model"
**UNWIRED items:** N/A (new work)
**AUDIT items:** B-003 (Sanad flexibility), B-013 (CLI Sanad create)

### Problem
CLI collapses all states to "Active"/"Consumed" (`csv-cli/src/commands/sanads.rs:734-763`). Ethereum returns state enum but collapses it (`sanads.rs:1030-1037`). Sui/Solana/Aptos return only "Active"/"Consumed" based on boolean flags.

### Tasks

#### 1.1 Define canonical state types in csv-store

**File:** `csv-store/src/state/domain.rs`

Add:
```rust
pub enum SanadLifecycleState {
    Uncreated,
    Created,
    Active,
    Locked,
    Consumed,
    Minted,
    Transferred,
    Refunded,
    Burned,
    Invalid,
    Unknown,
}

pub enum SealLifecycleState {
    Created,
    Consumed,
    Locked,
    Minted,
    Refunded,
    Unknown,
}

pub struct CanonicalSanadState {
    pub sanad_id: String,
    pub seal_id: Option<String>,
    pub chain: ChainId,
    pub state: SanadLifecycleState,
    pub owner: Option<String>,
    pub commitment: Option<String>,
    pub nullifier: Option<String>,
    pub source_chain: Option<ChainId>,
    pub destination_chain: Option<ChainId>,
    pub tx_hash: Option<String>,
    pub block_height: Option<u64>,
    pub updated_at: Option<u64>,
}

pub struct CanonicalSealState {
    pub seal_id: String,
    pub chain: ChainId,
    pub state: SealLifecycleState,
    pub sanad_id: Option<String>,
    pub commitment: Option<String>,
    pub tx_hash: Option<String>,
    pub block_height: Option<u64>,
    pub updated_at: Option<u64>,
}
```

**Reference:** `Contracts-Audit.md` lines 283-315

#### 1.2 Add state/trace subcommands to CLI

**File:** `csv-cli/src/commands/sanads.rs`

Add to `SanadAction` enum:
```rust
State { chain: Chain, sanad_id: String },
Trace { chain: Chain, sanad_id: String },
```

Add `cmd_state()` — calls chain adapter, returns `CanonicalSanadState`, displays as table.
Add `cmd_trace()` — calls chain adapter, returns lifecycle events, displays as timeline.

**File:** `csv-cli/src/commands/seals.rs`

Add to seal commands:
```rust
State { chain: Chain, seal_ref: String },
```

**Reference:** `Contracts-Audit.md` lines 275-278

#### 1.3 Fix state collapsing in cmd_list

**File:** `csv-cli/src/commands/sanads.rs`

Replace collapse logic at lines 734-763:
- `check_sanad_on_chain_status` returns `Option<SanadLifecycleState>` instead of `Option<String>`
- Each chain returns its actual state, not "Active"/"Consumed"
- `cmd_list` displays full state enum, not collapsed

#### 1.4 Fix Ethereum state mapping

**File:** `csv-cli/src/commands/sanads.rs`

Replace collapse at lines 1030-1037:
```rust
// Current: 3,4 -> Consumed, everything else -> Active
// Fix: Map each state value to SanadLifecycleState variant
```

#### 1.5 Fix Sui/Solana/Aptos state mapping

**File:** `csv-cli/src/commands/sanads.rs`

- Sui (lines 1077-1179): Parse consumed+locked flags into proper state enum
- Solana (lines 1183-1253): Parse consumed+locked flags into proper state enum
- Aptos (lines 855-971): Parse consumed flag + AnchorData existence into proper state enum

#### 1.6 Add display formatting

**File:** `csv-cli/src/output.rs`

Add table formatter for `CanonicalSanadState`:
```
Sanad ID | Chain | State | Owner | Seal | Nullifier | Last Tx | Updated
```

Add timeline formatter for trace output:
```
Time | Chain | Event | From | To | Tx | State After
```

### Exit Criteria
- `csv sanad state --chain ethereum --sanad-id <id>` returns full state
- `csv sanad trace --chain solana --sanad-id <id>` returns lifecycle events
- `csv sanad list` shows full state enum, not collapsed
- `cargo test --package csv-cli` passes
- `cargo clippy --package csv-cli -- -D warnings` passes

---

## Phase 2: Ethereum Contract Unification

**Source:** `Contracts-Audit.md` "Chain-by-chain contract fixes — Ethereum"
**AUDIT items:** B-010 (ABI constitution mismatch), B-011 (merged contract), B-012 (cross-chain verification)

### Tasks

#### 2.1 Freeze CSVSeal as canonical contract

- Keep `CSVSeal.sol` as the single deployed contract
- Archive `CSVLock.sol` and `CSVMint.sol` as legacy (move to `legacy/` subdirectory)
- Update `foundry.toml` deploy script to only deploy CSVSeal

#### 2.2 Add SanadState enum to CSVSeal

```solidity
enum SanadState {
    Uncreated,
    Created,
    Active,
    Locked,
    Consumed,
    Minted,
    Transferred,
    Refunded,
    Burned,
    Invalid
}

struct SanadStateRecord {
    SanadState state;
    bytes32 sanadId;
    bytes32 sealId;
    bytes32 commitment;
    address owner;
    uint8 sourceChain;
    uint8 currentChain;
    uint8 destinationChain;
    bytes32 nullifier;
    uint256 createdAt;
    uint256 updatedAt;
    uint256 lockedAt;
    uint256 consumedAt;
    uint256 mintedAt;
    uint256 refundedAt;
}
```

#### 2.3 Rename events to canonical names

| Current Name | Canonical Name |
|---|---|
| `SealUsed` | `SanadConsumed` (emit both during transition) |
| `SanadMinted` | `CrossChainMint` (emit both during transition) |
| `SanadRefunded` | `CrossChainRefund` (emit both during transition) |
| `SanadCreated` | (add — currently missing from CSVSeal) |
| `SanadTransferred` | (add — currently missing from CSVSeal) |
| `ProofAccepted` | (add — currently missing from CSVSeal) |
| `ProofRejected` | (add — currently missing from CSVSeal) |
| `ReplayDetected` | (add — currently missing from CSVSeal) |

#### 2.4 Add get_sanad_state view function

```solidity
function getSanadState(bytes32 sanadId) external view returns (SanadStateView memory)
```

#### 2.5 Update all lifecycle functions to update state record

Every function that changes state must:
1. Update `sanadStates[sanadId]`
2. Emit canonical event
3. Emit legacy event (for backward compatibility)

### Exit Criteria
- `forge build` compiles CSVSeal.sol
- CSVSeal emits all 10 canonical events
- `getSanadState()` returns full state record
- Legacy events still emitted for backward compatibility
- `forge test` passes

---

## Phase 3: ABI Constitution + Binding Generation

**Source:** `Contracts-Audit.md` "Implementation order" item 1-2
**AUDIT items:** B-010 (ABI constitution), B-013 (contract metadata)

### Tasks

#### 3.1 Update ABI constitution to match RFC-0009

**File:** `csv-contract-bindings/src/abi_constitution.rs`

Align required events with RFC-0009 canonical names:
```rust
required_events: vec![
    "SanadCreated",
    "SanadConsumed",
    "CrossChainLock",
    "CrossChainMint",
    "CrossChainRefund",
    "SanadTransferred",
    "NullifierRegistered",
    "ProofAccepted",
    "ProofRejected",
    "ReplayDetected",
]
```

Align required functions:
```rust
pub enum RequiredFunction {
    LockSanad,
    MintSanad,
    ConsumeSanad,
    RefundSanad,
    TransferSanad,
    RegisterNullifier,
    UpdateProofRoot,
    GetSanadState,
}
```

#### 3.2 Generate bindings from compiled artifacts

- Run `forge build` in `csv-contracts/ethereum/contracts/`
- Parse `out/CSVSeal.sol/CSVSeal.json` for ABI
- Generate Rust bindings from compiled ABI (not hand-written)
- Store ABI hash for deployment verification

#### 3.3 Update deployment scripts

- Verify bytecode hash matches pinned hash
- Verify ABI hash matches constitution
- Support dry-run, verify, deploy modes

### Exit Criteria
- `cargo test --package csv-contract-bindings` passes
- ABI constitution check passes against compiled CSVSeal
- Bindings match actual contract ABI
- `cargo deny check` passes

---

## Phase 4: Solana/Sui/Aptos Canonical State

**Source:** `Contracts-Audit.md` "Chain-by-chain contract fixes" — Solana, Sui, Aptos sections

### Tasks

#### 4.1 Solana — Add explicit state field

**File:** `csv-contracts/solana/contracts/programs/csv-seal/src/state.rs`

Add `state: u8` field to `SanadAccount`. Replace boolean flags with state enum:
```rust
pub const STATE_ACTIVE: u8 = 2;
pub const STATE_CONSUMED: u8 = 4;
pub const STATE_LOCKED: u8 = 3;
pub const STATE_MINTED: u8 = 5;
pub const STATE_REFUNDED: u8 = 7;
```

Add `get_sanad_state()` account query function.

#### 4.2 Sui — Add state field to Seal object

**File:** `csv-contracts/sui/sources/csv_seal.move`

Add `state: u8` field to Seal object. Add:
```move
public fun state(seal: &Seal): u8
public fun seal_state_view(seal: &Seal): SealStateView
```

#### 4.3 Aptos — Add SanadStateRecord resource

**File:** `csv-contracts/aptos/contracts/csv_seal.move`

Add `SanadStateRecord` resource keyed by sanad_id. Replace consumed-only tracking with full state. Add:
```move
public fun get_sanad_state(sanad_id: vector<u8>): SanadStateView
public fun get_seal_state(seal_id: vector<u8>): SealStateView
```

### Exit Criteria
- All four chains expose `get_sanad_state` / equivalent
- All chains use same state enum values (0-9)
- `cargo build` for all adapter crates passes

---

## Phase 5: CLI Adapter Trait SanadStateReader

**Source:** `Contracts-Audit.md` "Replace ad-hoc chain status logic"

### Tasks

#### 5.1 Define SanadStateReader trait

**File:** `csv-protocol/src/chain_adapter_traits.rs` (or new file)

```rust
#[async_trait]
pub trait SanadStateReader {
    async fn get_sanad_state(&self, sanad_id: Hash) -> Result<CanonicalSanadState>;
    async fn get_seal_state(&self, seal_id: Hash) -> Result<CanonicalSealState>;
    async fn trace_sanad(&self, sanad_id: Hash) -> Result<Vec<CanonicalLifecycleEvent>>;
}
```

#### 5.2 Implement for each chain adapter

- `csv-adapters/csv-bitcoin/src/` — UTXO-based state
- `csv-adapters/csv-ethereum/src/` — Contract `getSanadState()` call
- `csv-adapters/csv-solana/src/` — PDA account decode
- `csv-adapters/csv-sui/src/` — Object query
- `csv-adapters/csv-aptos/src/` — REST table query
- `csv-adapters/csv-celestia/src/` — DA layer query

#### 5.3 Wire into CLI commands

Replace ad-hoc RPC calls in `csv-cli/src/commands/sanads.rs:792-1258` with trait calls.

### Exit Criteria
- `csv sanad state` works for all 6 chains
- `csv seal state` works for all 6 chains
- `csv sanad trace` works for all 6 chains
- No more ad-hoc per-chain state checking in CLI

---

## Phase 6: AUDIT Critical Blockers

**Source:** `AUDIT.md` Section 0 (Immediate release blockers)

### Tasks (in dependency order)

#### 6.1 B-003: Sanad ID derivation fix
- Use `SanadIdPreimage` with domain tag, include salt
- Add golden vector tests
- **Reference:** `AUDIT.md` lines 86-93, 186-190

#### 6.2 B-005: Schema validation
- Implement real validation in `csv-codec/src/schema.rs`
- Or delete the path if not needed
- **Reference:** `AUDIT.md` lines 17, 899

#### 6.3 B-006: Proof validation
- Replace placeholder in `csv-proof/src/proof_validation.rs`
- Route through canonical verifier
- **Reference:** `AUDIT.md` lines 18, 168-169

#### 6.4 B-007: ZK proof empty proof rejection
- Reject empty proofs unless explicitly in non-ZK mode
- Remove placeholder verifier keys from production code
- **Reference:** `AUDIT.md` lines 19, 902

#### 6.5 B-008: Ethereum MPT real verification
- Replace placeholder account key with real account proof decoding
- **Reference:** `AUDIT.md` lines 20, 930

#### 6.6 B-009: Move fake proofs to csv-testkit
- Move fake proof builders from `csv-runtime/src/transfer_coordinator.rs`
- **Reference:** `AUDIT.md` lines 21, 907

#### 6.7 B-015: Typed secret handles
- Replace `Option<String>` private keys with typed secret handles
- Use `secrecy` crate, zeroize on drop
- **Reference:** `AUDIT.md` lines 27, 368-376

#### 6.8 B-044: Fake encryption deletion
- Delete or implement real AEAD encryption in `csv-cli content encrypt`
- **Reference:** `AUDIT.md` lines 26, 378-380, 384

### Exit Criteria
- All 8 blockers fixed
- `cargo test --workspace --all-features` passes
- No placeholder/mock code in production crates
- `cargo clippy --workspace --all-features -- -D warnings` passes

---

## Phase 7: Serde Audit Manifest + L0-L4 Stripping

**Source:** `AUDIT.md` Section 5.4, Section 9.2; `UNWIRED.md` serde item

### Tasks

#### 7.1 Generate serde_audit_manifest.md

Scan all L0-L4 crates for `Serialize`/`Deserialize` derives:
- csv-hash: ~18 types
- csv-verifier: ~4 types
- csv-proof: ~15 types
- csv-protocol: ~100 types
- csv-schema + csv-content: audit as needed

Classify each: **Remove**, **Wire type** (move to csv-wire), or **Exempt** (L5+ config/CLI/test).

#### 7.2 Strip serde from csv-hash (18 types)

Hash types never serialize directly — they go through csv-wire wire types.

#### 7.3 Strip serde from csv-verifier (4 types)

Verification results use typed enums.

#### 7.4 Strip serde from csv-proof (15 types)

Proof bundles serialize through csv-wire wire types.

#### 7.5 Strip serde from csv-protocol (100 types)

The bulk of work. Protocol state types serialize through csv-wire. Domain types use wire types. Config/metadata types are exempt.

#### 7.6 Update csv-wire

Add wire types for any types previously serialized directly.

#### 7.7 Update deny.toml

Add: `csv-hash → serde::Serialize` forbidden edge (already partially in place).

### Exit Criteria
- `serde_audit_manifest.md` exists with all 196 types classified
- `cargo deny check` passes for serde edges
- `cargo test --workspace --all-features` passes
- csv-wire has wire types for all previously-directly-serialized types

---

## Phase 8: Chain Registry + Config-Driven Addition

**Source:** `config-data-oriented-chain-addition-plan.md`; `csv-docs/rfcs/RFC-0011-config-driven-chain-addition.md`

### Tasks

#### 8.1 Create chain_registry.rs

**File:** `csv-protocol/src/chain_registry.rs`

- `ChainConfig` struct (serde-allowed, L5 config type)
- `NetworkType` enum (Utxo, Account, DataAvailability)
- `ChainFeatures` struct
- `ChainRegistry` with `load_from_config()`, `get_chain()`, `register_chain()`

#### 8.2 Convert existing chains/*.toml

Convert all 6 chain configs to new format with `[wallet]` and `[features]` sections.

#### 8.3 Create chain_discovery.rs in csv-runtime

**File:** `csv-runtime/src/chain_discovery.rs`

- Load configs from `chains/` directory
- Resolve adapter modules to concrete types via feature flags

#### 8.4 Wire into CLI

`csv chain list` reads from registry.

### Exit Criteria
- `csv chain list` shows all 6 chains from TOML configs
- Adding a stub chain requires only config file + adapter crate
- No core code changes needed for new chains

---

## Phase 9: Recovery Implementation

**Source:** `UNWIRED.md` pending items; `AUDIT.md` Section 6

### Tasks

#### 9.1 execute_from_lock recovery
- Load `LockConfirmed` journal entry
- Reconstruct `Locked` typestate
- Resume at `AwaitingFinality`

#### 9.2 execute_from_proof recovery
- Load proof bytes from journal
- Skip proof generation
- Go straight to mint

#### 9.3 AwaitingFinality recovery
- Re-poll finality monitor with proof height from journal

#### 9.4 ProofBuilding recovery
- Check for persisted checkpoint
- Resume if exists

#### 9.5 Recovery tests
- Use deterministic proof fixtures from `csv-testkit`
- Not fake bytes

### Exit Criteria
- All 4 recovery paths implemented
- Crash recovery tests pass with real proof fixtures
- `cargo test --package csv-runtime` passes

---

## Phase 10: Solana Test Matrix + Chain Management Wiring

**Source:** `UNWIRED.md` pending items

### Tasks

#### 10.1 Add Solana to test matrix
**File:** `csv-cli/commands/tests.rs`

#### 10.2 Wire chain_management.rs commands
Connect `ChainCommands` (discover, validate, create-template) to `Commands` enum in `main.rs`.

#### 10.3 Wire csv-coordinator isolation-domain behavior
Implement actual per-chain execution cell logic in `csv-coordinator/src/cell.rs`.

### Exit Criteria
- Solana appears in test matrix
- `csv chain discover`, `csv chain validate`, `csv chain create-template` work
- `csv-coordinator/src/cell.rs` has real isolation logic

---

## Phase 11: Self-Expressive Naming Reorganization

**Source:** `self-expressive-architecture-plan.md`

### Tasks (in order)

#### 11.1 csv-protocol/src/
- `proof.rs` → DELETE (redundant re-export)
- `proof_types.rs` → `proof_taxonomy.rs`
- `canonical_proof.rs` → `proof_validation.rs`
- `verification.rs` → `verification_levels.rs`
- `verified.rs` → `verification_results.rs`
- `backend.rs` → `chain_adapter_traits.rs`
- Create `onchain/`, `offchain/`, `verification/` subdirectories

#### 11.2 csv-runtime/src/
- `coordinator_lease.rs` → `distributed_coordinator_lease.rs`
- `lease.rs` → `user_runtime_lease.rs`
- `event_store.rs` → `event_persistence.rs`
- `replay_db.rs` → `replay_database.rs`
- `replay_record.rs` → `replay_record_types.rs`
- Create `coordination/`, `events/`, `recovery/`, `replay/`, `monitoring/` subdirectories

#### 11.3 csv-verifier/src/
- `anchor.rs` → `anchors.rs`
- `chain_bundle.rs` → `chain_proof_bundle.rs`

#### 11.4 Add module documentation
Use template from self-expressive plan.

### Exit Criteria
- All ambiguous names resolved
- Every module has architectural role documentation
- `cargo test --workspace --all-features` passes

---

## Phase 12: Contract Freeze

**Source:** `AUDIT.md` Section 3; `Contracts-Audit.md` "Critical tests to add"

### Tasks

#### 12.1 Pin ABI hash and bytecode hash
- Generate from compiled CSVSeal.sol
- Store in deployment manifest
- Deploy scripts verify hash before deployment

#### 12.2 Add root governance policy
- Root epoch: `(epoch, root, valid_from, valid_until, previous_root)`
- Monotonic epoch enforcement
- Timelock or multisig authority

#### 12.3 Remove arbitrary owner seal-consumption
- `markSealUsed` should require owner signature, not admin-only

#### 12.4 Standardize chain ID hash
- Use `ChainIdHash = H(canonical(ChainIdentity))` not `u8`

#### 12.5 Add cross-language proof vectors
- Generate test vectors for proof leaf format
- Verify across all four chains

#### 12.6 Add negative adversarial tests
- Double consume, double mint, refund after mint, mint without verified proof
- Replay detection, stale root, admin abuse

#### 12.7 Naming constitution test
- No production contract may emit `SealUsed` without also emitting `SanadConsumed`
- No production contract may emit `SanadMinted` without also emitting `CrossChainMint`

### Exit Criteria
- ABI hash pinned, bytecode hash verified
- Governance policy in place
- All adversarial tests pass
- Naming constitution test passes
- `forge test`, `anchor test`, `sui test` all pass

---

## Tracking

### Completed Phases
- Phase 0 (preparation): Source documents read, conflicts resolved, plan created

### In Progress
- **Phase 1: CLI canonical state** — Started 2026-06-09

### Pending
- Phase 2-12: See status column above

### Cross-Document Task References

| Task | Source Doc | Line Refs |
|---|---|---|
| CLI state enum + commands | Contracts-Audit.md | 275-315 |
| CLI state collapsing fix | Contracts-Audit.md | 27-38 |
| Ethereum contract unification | Contracts-Audit.md | 143-196 |
| Canonical event names | Contracts-Audit.md | 147-158 |
| Solana canonical state | Contracts-Audit.md | 239-262 |
| Sui canonical state | Contracts-Audit.md | 217-237 |
| Aptos canonical state | Contracts-Audit.md | 199-215 |
| Sanad ID derivation fix | AUDIT.md | 86-93, 186-190 |
| Schema validation | AUDIT.md | 17, 899 |
| Proof validation | AUDIT.md | 18, 168-169 |
| ZK empty proof | AUDIT.md | 19, 902 |
| Ethereum MPT | AUDIT.md | 20, 930 |
| Fake proofs to testkit | AUDIT.md | 21, 907 |
| Secret handling | AUDIT.md | 27, 368-376 |
| Fake encryption | AUDIT.md | 26, 378-380, 384 |
| ABI constitution | AUDIT.md | 22, 259, 926 |
| Contract ABI freeze | AUDIT.md | 317-328, 859-875 |
| Serde stripping | AUDIT.md | 7, 196 types |
| Chain registry | config-data-oriented-chain-addition-plan.md | 36-81 |
| Recovery implementation | UNWIRED.md | 19-24 |
| Naming reorganization | self-expressive-architecture-plan.md | 131-298 |
