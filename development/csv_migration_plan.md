**CSV Protocol — Refactoring & Migration Completion Plan**

Finishing the Legacy → New Crate Migration to Testnet-Ready Architecture

10 New Crates · 8 Legacy Crates · Dual-crate overlap · Ordered migration path

# **Part A — Current State Map**

Two generations of crates coexist in the workspace. The new generation was defined first as empty shells; the legacy generation contains the real implementations. Migration is partial — some types have been moved, some are re-exported shims, some are duplicated.

## **A.1 — New Crates (Phase 1 Target Architecture)**

These ten crates define the intended long-term dependency graph. Each has a narrow, single-purpose scope.

| **Crate** | **Purpose** | **Current State** |
| --- | --- | --- |
| csv-codec | Canonical CBOR serialization, byte ordering, versioning | DONE — fully implemented |
| csv-hash | Tagged hashing, domain separation, Merkle, commitments, SanadId, ChainId | DONE — fully implemented |
| csv-proof | Proof taxonomy (8 types), DAGs, composition, material | DONE — fully implemented |
| csv-content | Merkleized content trees, selective disclosure, attachments | DONE — fully implemented |
| csv-schema | Schema registry and JSON Schema validation | DONE — fully implemented |
| csv-protocol | State machines, transfer states, finality, reorg, replay semantics, invariants | PARTIAL — modules exist; state_machine/mod.rs is placeholder stub |
| csv-verifier | Canonical proof verifier, chain bundle verification | DONE — wired; still imports csv-core |
| csv-storage | Storage traits + RocksDB / Postgres / InMemory backends | PARTIAL — imports csv-core; should depend only on csv-hash + csv-protocol |
| csv-testkit | Adversarial fixtures, test helpers, golden vectors | WIP — only 2 scenarios implemented |
| csv-contract-bindings | Type-safe ABI bindings for all supported chains | WIP — no deps on new crates yet |

## **A.2 — Legacy Crates (To Be Refactored / Deprecated)**

These crates are labeled 'Legacy' in Cargo.toml. They contain real production code but will eventually be reduced to thin wrappers or eliminated.

| **Crate** | **Current Role** | **Migration Target** |
| --- | --- | --- |
| csv-core | 65 modules. Canonical home of everything. New crates re-export from here. Still the true source of truth for most types. | Gut to a thin compatibility shim. All real modules move to new crates. |
| csv-runtime | TransferCoordinator, leases, recovery, circuit breakers, event bus. Still imports csv-core heavily. | Keep as orchestration layer but make it depend on new crates instead of csv-core. |
| csv-store | SQLite-backed state, wallet state, browser storage, replay store. Separate from csv-storage (RocksDB/Postgres). | Merge browser/wallet state here; migrate replay/transfer ops to csv-storage. |
| csv-sdk | Public API facade. Imports csv-core, csv-runtime, csv-store, all adapters. | Re-point to new crates. csv-core imports become csv-protocol+csv-hash+csv-proof. |
| csv-cli | CLI binary. Imports csv-sdk, csv-core, csv-verifier, csv-keys, csv-store. | No structural change needed — benefits automatically as deps migrate. |
| csv-keys | BIP-39/44 key management, AES-GCM encryption, chain-specific derivation. | Keep as-is. Remove csv-core dep; use csv-hash for hashing only. |
| csv-p2p | Nostr-based P2P proof transport. | Keep as-is. Remove csv-core dep if possible; narrow to csv-protocol types. |
| csv-observability | Metrics and tracing primitives. | Keep as-is. No protocol types needed — remove csv-core dep entirely. |

## **A.3 — The Core Problem: csv-core is Still the Real Crate**

**csv-core has 65 modules, ~400k chars of real implementation. New crates are correct in design but many are just re-exporting from csv-core. The migration direction exists on paper but is incomplete in code.**

Three specific overlap patterns found in the audit:

- csv-core/src/replay_registry.rs = 60 chars → just a comment saying 'see csv-protocol'. But csv-protocol/src/replay/registry.rs is the real implementation, and csv-core consumers still import from csv_core::replay_registry.
- csv-core/src/dag.rs = 52 chars → stub pointing at csv-hash. But adapters import csv_core::dag directly.
- csv-core/src/transfer_stage.rs = 6155 chars of real code. csv-protocol/src/state_machine/mod.rs says 'placeholder — will be moved from csv-core'. The move hasn't happened.
- csv-verifier imports csv-core — a new crate depending on a legacy crate it's meant to replace.
- csv-storage imports csv-core — same problem.

# **Part B — Target vs Current Dependency Graph**

## **B.1 — Target Dependency Graph (What We're Building Toward)**

**Read bottom to top. Each layer may only depend on layers below it.**

Layer 0 (leaf): csv-codec

Layer 1: csv-hash ← csv-codec

Layer 2: csv-proof ← csv-hash, csv-codec

Layer 2: csv-content ← csv-hash

Layer 2: csv-schema ← csv-codec

Layer 3: csv-protocol ← csv-hash, csv-codec, csv-proof

Layer 4: csv-verifier ← csv-protocol, csv-proof, csv-hash, csv-codec

Layer 4: csv-storage ← csv-protocol, csv-hash, csv-proof

Layer 5: csv-runtime ← csv-protocol, csv-verifier, csv-storage

Layer 5: csv-keys ← csv-hash (no csv-core)

Layer 5: csv-p2p ← csv-protocol (no csv-core)

Layer 5: csv-observability ← (no csv deps)

Layer 5: adapters ← csv-protocol, csv-verifier, csv-proof, csv-storage

Layer 6: csv-sdk ← csv-runtime, adapters, csv-keys

Layer 7: csv-cli ← csv-sdk, csv-schema, csv-keys

csv-core: DEPRECATED — thin re-export shim only, no real code

csv-store: SCOPED — browser/wallet state only, no protocol ops

csv-testkit: cross-cutting test dependency (allowed to import widely)

## **B.2 — Current Violations of the Target Graph**

| **Importer** | **Imports** | **Violation** | **Severity** |
| --- | --- | --- | --- |
| csv-verifier | csv-core | New crate depends on legacy crate | HIGH |
| csv-storage | csv-core | New crate depends on legacy crate | HIGH |
| csv-testkit | csv-core | Test crate depends on legacy crate | MEDIUM |
| csv-protocol | (none, correct) | No violation | DONE |
| csv-hash | (none, correct) | No violation | DONE |
| csv-proof | (none, correct) | No violation | DONE |
| csv-codec | (none, correct) | No violation | DONE |
| csv-content | (none, correct) | No violation | DONE |
| csv-core | csv-hash, csv-proof, csv-protocol, csv-content, csv-codec | Correct direction — core imports new crates | OK  |
| csv-keys | csv-core | Should import csv-hash only | MEDIUM |
| csv-p2p | csv-core | Should import csv-protocol only | MEDIUM |
| csv-observability | (workspace only) | Workspace deps only — acceptable for now | LOW |

# **Part C — Module-by-Module Migration Registry**

Every csv-core module classified into one of four fates: MOVE (real code moves to new crate), STUB (already a shim, just fix imports), KEEP (stays in csv-core as protocol glue), DELETE (dead code or feature-gated experimental).

## **C.1 — Modules to MOVE to New Crates**

| **csv-core Module** | **Size** | **Move To** | **Notes** |
| --- | --- | --- | --- |
| transfer_stage | 6155 | csv-protocol | Real state machine. csv-protocol/state_machine/mod.rs is a placeholder waiting for this. |
| finality | 8124 | csv-protocol | Overlaps csv-protocol/finality/. Merge — csv-core version has FinalityType enum not yet in csv-protocol. |
| finality_anchor | 16028 | csv-protocol | Restart-safe finality anchoring. Belongs in protocol layer. |
| finality_guarantee | 4672 | csv-protocol | Finality grade types. Merge into csv-protocol/finality/. |
| chain_specific | 3932 | csv-protocol | Chain-specific finality grades (SolanaCommitmentGrade etc). Belongs in protocol. |
| replay_constitution | 9772 | csv-protocol | Replay protection rules. csv-protocol/replay/ is the new home. |
| failure_domains | 9105 | csv-protocol | Failure domain classification. Duplicate of csv-runtime/src/failure_domain.rs — one canonical location needed. |
| deterministic_recovery | 9869 | csv-protocol or csv-runtime | Recovery engine types. Move to csv-protocol if pure types; csv-runtime if orchestration. |
| seal_protocol | 25808 | csv-protocol | SealProtocol trait. Core adapter interface — belongs in protocol layer. |
| backend | 22149 | csv-protocol | ChainBackend trait. Same as seal_protocol — protocol layer. |
| signature | 20167 | csv-protocol | SignatureScheme + verification. Used by verifier — move to csv-protocol. |
| verified | 5841 | csv-protocol | VerificationAssurance types. Already in csv-protocol/src/verified.rs — deduplicate. |
| events | 14763 | csv-protocol | Protocol event types. csv-protocol/src/events.rs is the new home. |
| chain_capabilities | 9804 | csv-protocol | Capability flags. Move to csv-protocol/finality/capabilities.rs. |
| hardening | 5794 | csv-protocol | Production hardening invariants. Move to csv-protocol/invariants.rs. |
| commitment_chain | 10907 | csv-proof or csv-hash | Commitment chain types. Belongs with proof primitives. |
| commitments_ext | 16335 | csv-proof | Pedersen commitments, blinding factors. Proof layer. |
| zk_proof | 24321 | csv-proof | ZK proof infrastructure. Belongs with proof types. |
| merkle | 516 | csv-hash | Tiny stub — real impl in csv-hash already. Delete from csv-core. |
| canonical_events | 8955 | csv-protocol | Canonical event schemas. csv-protocol/src/events.rs. |
| abi_constitution | 10483 | csv-contract-bindings | ABI stability rules belong with contract bindings. |
| deployment | 9462 | csv-contract-bindings | Deployment profiles belong with contract layer. |
| monitor | 7020 | csv-protocol | Runtime health monitoring types — protocol layer. |
| performance | 10615 | csv-observability | Performance measurement. Move to observability crate. |

## **C.2 — Modules to STUB (Already Shims — Fix Imports)**

| **csv-core Module** | **Current State** | **Action Required** |
| --- | --- | --- |
| replay_registry | 60-char comment stub | Add pub use csv_protocol::replay::registry::\*; make it compile |
| dag | 52-char comment stub | Add pub use csv_hash::dag::\*; make it compile |
| proof | 606-char stub | Add pub use csv_proof::proof::\*; verify nothing re-implements |
| proof_provenance | 762-char stub | Add pub use csv_proof::proof_material::\*; verify |
| collections | 414-char stub | Keep — no-std HashMap wrapper, too small to move |
| config_validation | 529-char stub | Add pub use csv_protocol::invariants::\*; make it compile |
| runtime_health | 1148-char stub | Add pub use csv_protocol::\*; make it compile |

## **C.3 — Modules to KEEP in csv-core (Protocol Glue / Compatibility)**

| **csv-core Module** | **Reason to Keep** | **Future State** |
| --- | --- | --- |
| protocol_version | Canonical chain IDs, transfer status, error codes, capability flags — the shared contract all consumers mirror | Keep forever as the version-negotiation layer |
| lease | LeaseId, Lease, LeaseManager — lightweight types used by CLI | Move to csv-runtime after T4 (lease state out of CLI) is complete |
| cross_chain | CrossChainTransferRequest and related types used across csv-sdk and csv-runtime | Refactor to csv-protocol after csv-sdk is migrated |
| client | CsvClient trait — sdk-level abstraction | Keep in csv-core or move to csv-sdk |
| consignment | Wire format types for RGB-compatible consignments | Move to csv-protocol when consignment spec stabilizes |
| genesis | Genesis state type | Move to csv-protocol |
| state | SealState, SanadState types | Move to csv-protocol |
| transition | State transition types | Move to csv-protocol (overlap with csv-protocol/src/transition.rs) |
| transfer_stage | KEEP until csv-protocol migration is complete | DELETE after Move (C.1) is done |
| error | CoreError types | Keep as compatibility re-export after csv-protocol/src/error.rs becomes canonical |

## **C.4 — Modules to DELETE or ARCHIVE**

| **csv-core Module** | **Reason** | **Action** |
| --- | --- | --- |
| tapret_verify | Comment says MOVED: chain-specific, should be in csv-bitcoin adapter. Real impl already in csv-adapters/csv-bitcoin/src/tapret.rs | Delete from csv-core |
| rgb | Experimental RGB compat. Feature-gated and commented out in lib.rs | Archive to separate csv-rgb crate or delete |
| vm/mod | Experimental VM. Feature-gated and commented out in lib.rs | Archive to separate csv-vm crate or delete |
| mcp | AI agent types. Useful but not part of core protocol | Move to csv-sdk or a separate csv-mcp crate |
| atomic_swap | 28k chars of HTLSE implementation. Phase 3 experimental. | Archive to csv-atomic-swap crate; gate behind feature flag |
| stealth | Stealth addresses. Phase 3 experimental. | Archive to csv-stealth crate; gate behind feature flag |
| rgb | Deprecated RGB compat | Delete; create csv-rgb-compat if needed |
| merkle | 516-char stub pointing to csv-hash | Delete; all callers should use csv_hash::merkle directly |
| seal | 548-char stub | Delete; callers use csv_hash::seal directly |

# **Part D — Ordered Migration Plan (22 Steps)**

**Steps are ordered by dependency. Each step is self-contained and must compile to green before the next begins. Every step has a CI gate.**

## **Migration Phase 0 — Break csv-verifier and csv-storage Free from csv-core**

These two new crates still import csv-core. Fix them first so subsequent steps don't create circular dependency chains.

### **Step M0.1 — csv-verifier: Replace csv-core imports with csv-protocol + csv-proof + csv-hash**

**File: csv-verifier/Cargo.toml | File: csv-verifier/src/verifier.rs | File: csv-verifier/src/chain_bundle.rs**

\# csv-verifier/Cargo.toml — REMOVE:

csv-core = { path = "../csv-core" }

\# ADD:

csv-protocol = { path = "../csv-protocol" }

\# csv-proof and csv-hash already present — keep them

In verifier.rs: audit every csv_core:: import. Replace:

- csv_core::signature::SignatureScheme → csv_protocol::signature::SignatureScheme (after Step M1.3 moves it)
- csv_core::verified::VerificationAssurance → csv_protocol::verified::VerificationAssurance
- csv_core::proof::\* → csv_proof::proof::\*

\# CI gate:

cargo build -p csv-verifier # must compile with zero csv-core imports

### **Step M0.2 — csv-storage: Replace csv-core imports with csv-protocol + csv-hash**

**File: csv-storage/Cargo.toml | File: csv-storage/src/backends/\*.rs | File: csv-storage/src/traits.rs**

\# csv-storage/Cargo.toml — REMOVE:

csv-core = { path = "../csv-core" }

\# ADD:

csv-protocol = { path = "../csv-protocol" }

In traits.rs and backends: audit every csv_core:: import. Replace:

- csv_core::Hash → csv_hash::Hash
- csv_core::sanad::SanadId → csv_hash::SanadId
- csv_core::protocol_version::ChainId → csv_hash::ChainId
- csv_core::replay_record::GlobalReplayRecord → csv_protocol::replay::registry::ReplayEntry (after M1.1)

\# CI gate:

cargo build -p csv-storage # must compile with zero csv-core imports

### **Step M0.3 — csv-testkit: Replace csv-core imports with csv-protocol + csv-hash + csv-proof**

\# csv-testkit/Cargo.toml — REMOVE:

csv-core = { path = "../csv-core" }

\# ADD csv-protocol = { path = "../csv-protocol" }

\# CI gate: cargo build -p csv-testkit

## **Migration Phase 1 — Move Core Protocol Types into csv-protocol**

Move the real implementations from csv-core into csv-protocol, then make csv-core re-export from csv-protocol. This is the heart of the migration. Each module can be moved independently.

### **Step M1.1 — Move transfer_stage.rs → csv-protocol/src/transfer_state/**

prerequisite: design the capability trait set (AUDIT §1.5) so it's finalized before moving chain_capabilities.rs

**Source: csv-core/src/transfer_stage.rs (6155 chars) | Dest: csv-protocol/src/transfer_state/mod.rs**

- Copy csv-core/src/transfer_stage.rs content into csv-protocol/src/transfer_state/mod.rs (currently a placeholder)
- Update csv-protocol/src/lib.rs to re-export: pub use transfer_state::TransferStage;
- In csv-core/src/transfer_stage.rs, replace with: pub use csv_protocol::transfer_state::TransferStage;
- In csv-core/src/lib.rs, the existing pub use transfer_stage::TransferStage; still works through shim
- Add csv-protocol dep to crates that import TransferStage directly (csv-runtime already has csv-core which has it)

\# CI gate:

cargo test -p csv-protocol --test protocol_constitution

cargo test -p csv-runtime # must still pass

### **Step M1.2 — Move replay_constitution.rs + replay_registry.rs → csv-protocol/src/replay/**

**Source: csv-core/src/replay_constitution.rs (9772 chars) + replay_registry.rs (stub) | Dest: csv-protocol/src/replay/**

- Merge csv-core/src/replay_constitution.rs into csv-protocol/src/replay/registry.rs (which already has the ReplayRegistry impl)
- Review for any types not yet in csv-protocol/replay/. Add them.
- Replace csv-core/src/replay_constitution.rs with: pub use csv_protocol::replay::\*;
- Replace csv-core/src/replay_registry.rs with: pub use csv_protocol::replay::registry::\*;

\# CI gate: cargo test -p csv-protocol && cargo test -p csv-runtime

### **Step M1.3 — Move signature.rs → csv-protocol/src/**

**Source: csv-core/src/signature.rs (20167 chars) | Dest: csv-protocol/src/signature.rs (new file)**

- csv-proof/src/signature.rs already exists as a stub — it's the destination module
- Move the 20k chars of real SignatureScheme implementation from csv-core to csv-protocol
- Replace csv-core/src/signature.rs with: pub use csv_protocol::signature::\*;
- Update csv-verifier (M0.1 already planned this) and csv-proof to import from csv-protocol

\# CI gate: cargo build --workspace

### **Step M1.4 — Move finality.rs + finality_anchor.rs + finality_guarantee.rs + chain_specific.rs → csv-protocol/src/finality/**

**Source: csv-core/src/finality.rs (8124) + finality_anchor.rs (16028) + finality_guarantee.rs (4672) + chain_specific.rs (3932) | Dest: csv-protocol/src/finality/**

- csv-protocol/src/finality/ already has: mod.rs, abstraction.rs, capabilities.rs, monitor.rs, policy.rs, state.rs
- csv-core/finality.rs has FinalityType enum + FinalityConfig — merge into csv-protocol/finality/abstraction.rs
- csv-core/finality_anchor.rs has restart-safe anchoring types — add as csv-protocol/finality/anchor.rs
- csv-core/finality_guarantee.rs has grade types — add as csv-protocol/finality/grades.rs
- csv-core/chain_specific.rs has SolanaCommitmentGrade etc — move to csv-protocol/finality/chain_grades.rs
- Replace all four csv-core modules with re-exports from csv-protocol

\# CI gate: cargo test -p csv-protocol && cargo test -p csv-runtime

### **Step M1.5 — Move seal_protocol.rs + backend.rs → csv-protocol/src/**

**Source: csv-core/src/seal_protocol.rs (25808 chars) + backend.rs (22149 chars)**

- SealProtocol trait is the single most important trait in the codebase — it's the adapter interface
- Move to csv-protocol/src/seal_protocol.rs
- ChainBackend trait: move to csv-protocol/src/backend.rs
- All 6 adapters import csv_core::seal_protocol::SealProtocol — update them to import csv_protocol::seal_protocol::SealProtocol
- (csv-core dep in adapters remains until Phase 2 below, so no breaking change yet)

\# CI gate: cargo build --workspace --all-features

### **Step M1.6 — Move failure_domains.rs + deterministic_recovery.rs → csv-protocol/src/**

**Note: csv-runtime/src/failure_domain.rs is a duplicate — reconcile before moving**

- Compare csv-core/src/failure_domains.rs vs csv-runtime/src/failure_domain.rs — pick the more complete one
- Move winner to csv-protocol/src/failure_domains.rs
- Replace loser with: pub use csv_protocol::failure_domains::\*;
- Move csv-core/src/deterministic_recovery.rs → csv-protocol/src/recovery.rs
- csv-runtime/src/recovery.rs becomes an orchestration layer that uses csv-protocol::recovery types

\# CI gate: cargo test --workspace

### **Step M1.7 — Move events.rs + canonical_events.rs → csv-protocol/src/events.rs**

**Source: csv-core/src/events.rs (14763) + canonical_events.rs (8955) | Dest: csv-protocol/src/events.rs (already exists as placeholder)**

- csv-protocol/src/events.rs already exists — populate it with the two csv-core modules merged
- Replace both csv-core modules with re-exports

\# CI gate: cargo build --workspace

### **Step M1.8 — Move verified.rs → csv-protocol/src/verified.rs**

**csv-protocol/src/verified.rs already exists with VerificationAssurance — deduplicate with csv-core/src/verified.rs**

- Compare both — csv-core/verified.rs has 5841 chars, csv-protocol/verified.rs has content
- Keep the more complete one in csv-protocol; make csv-core a re-export shim

\# CI gate: cargo build --workspace

### **Step M1.9 — Move commitment_chain.rs + commitments_ext.rs + zk_proof.rs → csv-proof/src/**

**Source: csv-core/src/commitment_chain.rs (10907) + commitments_ext.rs (16335) + zk_proof.rs (24321)**

- These are proof-layer types — they belong in csv-proof
- Add as csv-proof/src/commitment_chain.rs, csv-proof/src/commitments_ext.rs, csv-proof/src/zk_proof.rs
- Replace csv-core originals with re-exports
- csv-proof already imports csv-hash and csv-codec — no new dependencies needed

\# CI gate: cargo build -p csv-proof && cargo build --workspace

### **Step M1.10 — Move chain_capabilities.rs + hardening.rs + monitor.rs → csv-protocol/src/**

- chain_capabilities.rs → csv-protocol/finality/capabilities.rs (already stub exists)
- hardening.rs → csv-protocol/src/invariants.rs
- monitor.rs → csv-protocol/src/monitor.rs
- Replace all three csv-core modules with re-exports

\# CI gate: cargo build --workspace

## **Migration Phase 2 — Shrink csv-core to a Compatibility Shim**

After Phase 1, csv-core should contain only re-exports and the few types that belong at the protocol-glue level. Phase 2 completes this.

### **Step M2.1 — Delete dead/experimental modules from csv-core**

| **Module** | **Action** | **Notes** |
| --- | --- | --- |
| tapret_verify | DELETE | Real impl is in csv-adapters/csv-bitcoin/src/tapret.rs |
| merkle | DELETE | All callers should use csv_hash::merkle directly |
| seal (stub) | DELETE | All callers use csv_hash::seal directly |
| rgb | DELETE or ARCHIVE | Experimental; no active users; create csv-rgb if needed |
| vm/mod | DELETE or ARCHIVE | Experimental VM; feature-gated and commented out |
| mcp | MOVE to csv-sdk | AI agent types — not protocol-layer |
| atomic_swap | ARCHIVE | 28k chars of Phase 3 code; gate behind feature flag or separate crate |
| stealth | ARCHIVE | Phase 3 stealth addresses; same as atomic_swap |
| performance | MOVE to csv-observability | Observability layer, not protocol layer |

### **Step M2.2 — Update csv-core/Cargo.toml: Remove internal implementations, re-export only**
prerequisit " naming rationalization pass: one pass through the 7 overlapping proof/seal naming concepts, pick canonical names, apply workspace-wide before deprecated annotations go out.

\# After Phase 1 moves are complete, csv-core should depend on:

csv-hash = { path = "../csv-hash" }

csv-proof = { path = "../csv-proof" }

csv-protocol = { path = "../csv-protocol" }

csv-codec = { path = "../csv-codec" }

csv-content = { path = "../csv-content" }

\# REMOVE: ed25519-dalek, bloomfilter, crc32fast, pqcrypto-dilithium

\# (these should be deps of the crates that actually use them)

### **Step M2.3 — Add #\[deprecated\] annotations to csv-core re-exports**

prerequisite. csv-protocol fully implemented (not stub), all protocol_constitution tests green

// In csv-core/src/lib.rs, for each re-exported type:

#\[deprecated(since = "0.2.0", note = "Use csv_protocol::TransferStage directly")\]

pub use csv_protocol::transfer_state::TransferStage;

This gives consumers a migration path without breaking them immediately. The deprecated warnings appear in CI and guide external crate authors.

## **Migration Phase 3 — Migrate Adapters Off csv-core**

All 6 chain adapters import csv-core. After Phase 1, csv-core re-exports from csv-protocol, so adapters still compile. Phase 3 is a direct import update — no semantic changes.

### **Step M3.1 — Update adapter Cargo.toml files: swap csv-core for csv-protocol**

| **Adapter** | **Current csv-core imports (key ones)** | **New imports** |
| --- | --- | --- |
| csv-bitcoin | csv_core::seal_protocol::SealProtocol, csv_core::signature::SignatureScheme | csv_protocol::seal_protocol::\*, csv_protocol::signature::\* |
| csv-ethereum | csv_core::seal_protocol::SealProtocol, csv_core::Hash (via csv-core) | csv_protocol::seal_protocol::\*, csv_hash::Hash |
| csv-solana | csv_core::seal_protocol::SealProtocol, csv_core::signature::\* | csv_protocol::seal_protocol::\*, csv_protocol::signature::\* |
| csv-sui | csv_core::seal_protocol::SealProtocol, csv_core::Hash | csv_protocol::seal_protocol::\*, csv_hash::Hash |
| csv-aptos | csv_core::seal_protocol::SealProtocol, csv_core::Hash | csv_protocol::seal_protocol::\*, csv_hash::Hash |
| csv-celestia | csv_core::seal_protocol::SealProtocol | csv_protocol::seal_protocol::\* |

\# CI gate after M3.1:

cargo build -p csv-bitcoin -p csv-ethereum -p csv-solana -p csv-sui -p csv-aptos -p csv-celestia

cargo clippy --workspace -- -W deprecated # should emit warnings only, not errors

### **Step M3.2 — Remove csv-core from adapter Cargo.toml**

Once adapters compile with csv-protocol imports, remove the csv-core dependency entirely from each adapter's Cargo.toml. Run cargo build --workspace to confirm nothing breaks.

\# CI gate: cargo build --workspace # no csv-core in adapter dependency trees

## **Migration Phase 4 — Migrate csv-runtime Off csv-core**

csv-runtime is the most complex legacy crate. It imports csv-core for many types and also has internal modules that duplicate csv-core functionality.

### **Step M4.1 — Reconcile duplicate modules between csv-runtime and csv-core**

| **csv-runtime module** | **csv-core duplicate** | **Resolution** |
| --- | --- | --- |
| failure_domain.rs | failure_domains.rs | After M1.6, one canonical location in csv-protocol. csv-runtime re-exports from there. |
| recovery.rs (orchestration) | deterministic_recovery.rs (types) | Keep csv-runtime/recovery.rs as orchestration; types come from csv-protocol::recovery |
| lease.rs (runtime lease) | lease.rs (protocol lease types) | csv-runtime/lease.rs = runtime execution lease (TransferLease, RuntimeId). csv-core/lease.rs = protocol lease (LeaseId, Lease). Both valid — different concepts. No dedup needed. |
| policy.rs | protocol_version.rs (finality depths) | csv-runtime/policy.rs is fine. It reads from csv-protocol::version::FinalityDepths. |

### **Step M4.2 — Update csv-runtime Cargo.toml**

\# csv-runtime/Cargo.toml — ADD:

csv-protocol = { path = "../csv-protocol" }

csv-hash = { path = "../csv-hash" }

\# REMOVE when all imports updated:

csv-core = { path = "../csv-core" }

Update imports in transfer_coordinator.rs, lease.rs, recovery.rs, policy.rs, runtime_mode.rs to use csv-protocol:: instead of csv_core::

\# CI gate: cargo build -p csv-runtime && cargo test -p csv-runtime

## **Migration Phase 5 — Consolidate Storage: csv-store vs csv-storage**

Two storage crates with different scopes must be cleanly separated. csv-storage = protocol-level persistence (replay, transfers). csv-store = application-level state (wallet, browser, UI state).

### **Step M5.1 — Audit and relocate csv-store modules**

| **csv-store Module** | **Keep in csv-store?** | **Action** |
| --- | --- | --- |
| state/wallet.rs | YES | Wallet state is application-level — stays in csv-store |
| state/domain.rs | YES | Application domain state — stays |
| state/storage.rs | YES | Application storage abstraction — stays |
| browser_storage.rs | YES | Browser-specific — stays in csv-store (WASM target) |
| encrypted_storage.rs | YES | Encrypted app state — stays |
| operations/replay_store.rs | NO  | Protocol-level. Move conformance to csv-storage backends (see T5 in prior doc) |
| operations/transfer_store.rs | NO  | Protocol-level. Move to csv-storage |
| operations/reorg_store.rs | NO  | Protocol-level. Move to csv-storage |
| replay_registry_store.rs | NO  | Duplicate of csv-storage functionality. Delete; point callers to csv-storage |
| operations/proof_store.rs | NO  | Move to csv-storage |
| operations/operation_log.rs | YES | Application audit log — stays |

### **Step M5.2 — Remove csv-core dep from csv-store**

\# csv-store imports csv-core for types. After Phase 1:

\# Replace csv_core::Hash → csv_hash::Hash

\# Replace csv_core::ChainId → csv_hash::ChainId

\# Replace csv_core::SanadId → csv_hash::SanadId

\# Then remove csv-core from csv-store/Cargo.toml

\# CI gate: cargo build -p csv-store

### **Step M5.3 — Remove csv-core dep from csv-keys**

\# csv-keys imports csv-core only for Hash types

\# Replace csv_core::Hash → csv_hash::Hash

\# csv-keys/Cargo.toml: remove csv-core, add csv-hash

\# CI gate: cargo build -p csv-keys

### **Step M5.4 — Remove csv-core dep from csv-p2p**

\# csv-p2p uses csv-core for proof transport types

\# Replace imports with csv-protocol equivalents

\# CI gate: cargo build -p csv-p2p

## **Migration Phase 6 — Migrate csv-sdk Off csv-core**

csv-sdk is the public API. It currently imports csv-core as its primary protocol type source. After Phases 1–5, csv-core is a shim and csv-sdk should import directly from new crates.

### **Step M6.1 — Update csv-sdk/Cargo.toml**

\# ADD:

csv-protocol = { path = "../csv-protocol" }

csv-hash = { path = "../csv-hash" }

csv-proof = { path = "../csv-proof" }

\# CHANGE: csv-core dep to optional (for backward compat period only)

csv-core = { path = "../csv-core", optional = true }

Update csv-sdk/src/ imports from csv_core:: to csv_protocol::, csv_hash::, csv_proof:: as applicable.

\# CI gate: cargo build -p csv-sdk --no-default-features

### **Step M6.2 — Add csv-wallet to workspace**

**This resolves the AGENTS.md drift identified in the prior audit.**

- Decision: if csv-wallet is a distinct binary → add it to workspace.members
- Decision: if it was merged into csv-sdk → remove all references from AGENTS.md and CI scripts
- Pick one and make the workspace consistent with the code

\# CI gate: cargo build --workspace # all workspace members must compile

## **Migration Phase 7 — Enforce Clean Dependency Graph in CI**

Once all phases are complete, add a CI gate that prevents regression.

### **Step M7.1 — cargo-deny: ban csv-core imports in new crates**

\# deny.toml

\[bans\]

deny = \[

{ name = "csv-core", wrappers = \[

\# These crates are allowed to still use csv-core (compatibility layer):

"csv-cli", # until Phase 6 migration is complete

\]},

\]

### **Step M7.2 — Add dep-graph CI check**

\# ci/check-dep-graph.sh

cargo tree -p csv-verifier | grep csv-core && exit 1 || true

cargo tree -p csv-storage | grep csv-core && exit 1 || true

cargo tree -p csv-protocol | grep csv-core && exit 1 || true

cargo tree -p csv-hash | grep csv-core && exit 1 || true

cargo tree -p csv-proof | grep csv-core && exit 1 || true

echo 'Dependency graph clean'

# **Part E — Consolidated Migration Tracking Table**

One row per action. Assignable as individual tickets.

| **ID** | **Action** | **From** | **To** | **Blocker** | **Est.** |
| --- | --- | --- | --- | --- | --- |
| M0.1 | csv-verifier: remove csv-core dep | csv-core | csv-protocol+csv-proof | None | 1d  |
| M0.2 | csv-storage: remove csv-core dep | csv-core | csv-protocol+csv-hash | M0.1 types | 1d  |
| M0.3 | csv-testkit: remove csv-core dep | csv-core | csv-protocol+csv-hash | M0.1 | 0.5d |
| M1.1 | Move transfer_stage.rs | csv-core | csv-protocol | M0.x | 1d  |
| M1.2 | Move replay_constitution + registry | csv-core | csv-protocol | M1.1 | 1d  |
| M1.3 | Move signature.rs | csv-core | csv-protocol | M0.1 | 1d  |
| M1.4 | Move finality\*.rs (4 modules) | csv-core | csv-protocol | M1.1 | 2d  |
| M1.5 | Move seal_protocol.rs + backend.rs | csv-core | csv-protocol | M1.3 | 2d  |
| M1.6 | Move failure_domains + recovery | csv-core | csv-protocol | M1.1 | 1d  |
| M1.7 | Move events + canonical_events | csv-core | csv-protocol | M1.1 | 1d  |
| M1.8 | Deduplicate verified.rs | csv-core | csv-protocol | M0.1 | 0.5d |
| M1.9 | Move commitment_chain + zk_proof | csv-core | csv-proof | M0.3 | 2d  |
| M1.10 | Move chain_capabilities + hardening | csv-core | csv-protocol | M1.4 | 1d  |
| M2.1 | Delete dead modules from csv-core | csv-core | archive/delete | M1.x all | 1d  |
| M2.2 | csv-core Cargo.toml: re-export only | csv-core | —   | M2.1 | 0.5d |
| M2.3 | Add #\[deprecated\] to csv-core re-exports | csv-core | —   | M2.2 | 0.5d |
| M3.1 | Update adapter imports | adapters | csv-protocol | M1.5 | 2d  |
| M3.2 | Remove csv-core from adapters | adapters | —   | M3.1 | 0.5d |
| M4.1 | Reconcile runtime/core duplicates | csv-runtime | csv-protocol | M1.6 | 1d  |
| M4.2 | csv-runtime: swap csv-core for csv-protocol | csv-runtime | csv-protocol | M4.1 | 2d  |
| M5.1 | Relocate csv-store protocol ops to csv-storage | csv-store | csv-storage | M0.2 | 2d  |
| M5.2 | csv-store: remove csv-core dep | csv-store | csv-hash | M1.1 | 0.5d |
| M5.3 | csv-keys: remove csv-core dep | csv-keys | csv-hash | M1.1 | 0.5d |
| M5.4 | csv-p2p: remove csv-core dep | csv-p2p | csv-protocol | M1.5 | 1d  |
| M6.1 | csv-sdk: swap csv-core for new crates | csv-sdk | csv-protocol+… | M5.x all | 2d  |
| M6.2 | csv-wallet: resolve workspace drift | csv-sdk or new | workspace | None | 0.5d |
| M7.1 | Add cargo-deny rule for csv-core | CI  | —   | M6.x all | 0.5d |
| M7.2 | Add dep-graph CI check script | CI  | —   | M7.1 | 0.5d |

# **Part F — Execution Schedule**

## **Week 1 — Phase 0 + Phase 1 Foundation (M0.1–M1.5)**

**Goal: csv-verifier, csv-storage, csv-testkit compile without csv-core. Core protocol traits moved.**

| **Day** | **Steps** | **Gate** |
| --- | --- | --- |
| Mon | M0.1 csv-verifier + M0.2 csv-storage | Both build without csv-core |
| Tue | M0.3 csv-testkit + M1.1 transfer_stage | cargo test -p csv-protocol passes |
| Wed | M1.2 replay + M1.3 signature | cargo test --workspace passes |
| Thu | M1.4 finality modules (4) | csv-runtime still compiles |
| Fri | M1.5 seal_protocol + backend | cargo build --workspace --all-features |

## **Week 2 — Phase 1 Tail + Phase 2 Cleanup (M1.6–M2.3)**

**Goal: csv-core is a shim. All real types live in csv-protocol, csv-proof, csv-hash.**

| **Day** | **Steps** | **Gate** |
| --- | --- | --- |
| Mon | M1.6 failure_domains + recovery | csv-runtime reconciled |
| Tue | M1.7 events + M1.8 verified + M1.9 commitment_chain | cargo test --workspace |
| Wed | M1.10 capabilities + hardening + M2.1 delete dead modules | No more real code in csv-core |
| Thu | M2.2 csv-core Cargo.toml cleanup + M2.3 deprecated annotations | cargo build --workspace |
| Fri | Integration test run + regression sweep | All existing tests pass |

## **Week 3 — Phase 3 + 4 Adapter and Runtime Migration (M3.1–M4.2)**

**Goal: All adapters and csv-runtime import from csv-protocol. csv-core is adapter-free.**

| **Day** | **Steps** | **Gate** |
| --- | --- | --- |
| Mon | M3.1 bitcoin + ethereum adapters | Both build against csv-protocol |
| Tue | M3.1 solana + sui + aptos + celestia adapters | All 6 adapters build |
| Wed | M3.2 remove csv-core from adapter Cargo.toml | cargo tree shows no csv-core in adapters |
| Thu | M4.1 reconcile runtime/core duplicates + M4.2 start csv-runtime migration | csv-runtime compiles |
| Fri | M4.2 complete + csv-runtime test suite | cargo test -p csv-runtime |

## **Week 4 — Phase 5 + 6 + 7 Storage, SDK, CI Gates (M5.1–M7.2)**

**Goal: Clean workspace. csv-core is optional/deprecated. New crates are canonical. CI enforces it.**

| **Day** | **Steps** | **Gate** |
| --- | --- | --- |
| Mon | M5.1 relocate csv-store protocol ops + M5.2 csv-store dep update | csv-storage conformance suite passes (T5 from prior plan) |
| Tue | M5.3 csv-keys + M5.4 csv-p2p dep updates | Both build without csv-core |
| Wed | M6.1 csv-sdk migration + M6.2 csv-wallet workspace | cargo build -p csv-sdk |
| Thu | M7.1 cargo-deny rule + M7.2 dep-graph CI check | CI blocks csv-core in new crates |
| Fri | Full workspace test + documentation update | cargo test --workspace; AGENTS.md updated |

## **Final State After Migration**

| **Crate** | **Status** | **csv-core Dependency** |
| --- | --- | --- |
| csv-codec | Leaf crate — no protocol deps | NONE |
| csv-hash | Depends on csv-codec only | NONE |
| csv-proof | Depends on csv-hash, csv-codec | NONE |
| csv-content | Depends on csv-hash | NONE |
| csv-schema | Depends on csv-codec | NONE |
| csv-protocol | Depends on csv-hash, csv-codec, csv-proof | NONE |
| csv-verifier | Depends on csv-protocol, csv-proof, csv-hash | NONE |
| csv-storage | Depends on csv-protocol, csv-hash, csv-proof | NONE |
| csv-testkit | Depends on csv-protocol, csv-proof, csv-hash | NONE |
| csv-runtime | Depends on csv-protocol, csv-verifier, csv-storage | NONE |
| csv-keys | Depends on csv-hash only | NONE |
| csv-p2p | Depends on csv-protocol | NONE |
| csv-observability | No csv deps | NONE |
| All 6 adapters | Depend on csv-protocol, csv-verifier, csv-proof | NONE |
| csv-sdk | Depends on csv-runtime, adapters, csv-keys | NONE |
| csv-store | Depends on csv-hash (wallet/browser state only) | NONE |
| csv-cli | Depends on csv-sdk, csv-schema, csv-keys | NONE (transitively) |
| csv-core | Shim crate: re-exports + #\[deprecated\] annotations | SELF (is csv-core) |
| csv-contract-bindings | No csv deps except csv-hash for hashing | NONE |

Total estimated effort: 4 weeks, 1–2 engineers. Steps are individually mergeable with no breakage to downstream consumers during migration because csv-core re-exports remain in place until the deprecated flag migration is complete.
