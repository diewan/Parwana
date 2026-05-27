
# Commented/Unwired Functionality Summary

## 1. **Archived Code (csv-core/archived/)**

- **atomic_swap.rs.bak** - Hash Time Locked Seal Exchange (HTLSE) implementation for atomic cross-chain swaps
- **stealth.rs.bak** - Stealth address scheme for privacy-preserving seal creation
- **performance.rs.bak** - Performance optimization code with proof caching
- **Why archived**: These features were removed during the Phase 1 restructuring. The atomic swap and stealth address features are not part of the current protocol scope.

## 2. **Commented-Out SQLite Implementation (csv-store/src/lib.rs)**

- Lines 63-89: Complete `SqliteSealStore` implementation commented out
- **Why**: SQLite is no longer acceptable for runtime coordination in production (per csv-runtime/postgres_store.rs comment). PostgreSQL is now the preferred persistent backend.

## 3. **Commented VM Module (csv-core/src/lib.rs)**

- Lines 241-244: VM module re-exports commented out
- **Why**: VM functionality is experimental and gated behind `experimental` feature flag, but the module itself appears to be removed or not yet implemented.

## 4. **TODO: Incomplete Implementations**

### csv-runtime/src/transfer_coordinator.rs

- **Line 1404**: Proof regeneration from LockConfirmed phase not implemented (delegates to full execute)
- **Line 1431**: Proof persistence to skip regeneration not implemented
- **Line 1516**: Proof generation from lock helper not implemented
- **Line 1551**: Mint from proof helper not implemented
- **Why**: The `resume_transfer()` crash recovery logic exists but the optimized phase-specific resumption is not yet implemented. Currently falls back to full re-execution (idempotent due to replay checks).

### csv-content/src/selective_disclosure.rs

- **Lines 72, 97, 124**: Merkle proof verification returns `true` (stub implementation)
- **Why**: Selective disclosure proofs are defined but Merkle proof verification logic is not yet implemented.

### csv-core/src/client.rs & state_store.rs

- **Line 37 & 18**: "Sanad is not available in csv-hash, TODO: find correct location"
- **Why**: Sanad struct was removed during migration, but some code still references it. This is a migration artifact.

### csv-core/src/recovery_engine.rs

- **Line 497**: Reorg detection integration with csv-protocol's ReorgDetector not implemented
- **Why**: Reorg detection was moved to csv-protocol but integration is pending.

### csv-core/tests/chains_load.rs

- **Line 43**: ChainConfigLoader not migrated yet
- **Why**: ChainConfigLoader hasn't been migrated to csv-protocol or csv-runtime during Phase 1 restructuring.

## 5. **Feature-Gated Code (Not Unwired, Just Conditional)**

### Experimental Features

- `experimental` feature gate: Currently empty in most crates (csv-protocol, csv-sdk, csv-core)
- `zk` feature: Pedersen commitments in csv-core/src/zk_proof.rs
- `pq` feature: Post-quantum signatures (ML-DSA-65) in csv-protocol/src/signature.rs
- `secp256k1` feature: ECDSA verification in csv-protocol/src/signature.rs
- `postgres` feature: PostgreSQL backends in csv-runtime
- `persistent` feature: RocksDB backends (incompatible with wasm32)

### Why feature-gated: These are optional features that may not be needed in all deployments or have specific dependencies

## 6. **Ignored Tests (#[ignore])**

### csv-runtime/tests/transfer_coordinator_crash_recovery.rs

- 6 tests ignored: All require full mock adapter implementation
- **Why**: Mock adapter for crash recovery tests is complex and not yet implemented. Core crash recovery logic is tested indirectly through execution_journal tests.

### csv-storage/tests/replay_database_conformance.rs

- PostgreSQL conformance test ignored
- **Why**: Requires running PostgreSQL instance.

## 7. **Dead Code Warnings (#[allow(dead_code)])**

Widespread across the codebase (20+ locations) including:

- csv-runtime/src/adversarial.rs
- csv-p2p/src/proof_delivery.rs, nostr.rs
- csv-cli/src/config.rs, state.rs
- csv-sdk/src/client.rs, transfers.rs, runtime.rs, wallet.rs
- csv-core/src/performance.rs
- csv-verifier/src/verifier.rs
- csv-adapters/csv-ethereum/src/verifier.rs, proofs.rs, ops.rs
- csv-adapters/csv-celestia/src/seal_protocol.rs

**Why**: These are fields and methods that are part of the public API but not yet used by all code paths, or reserved for future use (e.g., LRU cache fields, timestamp constants, helper methods).

## Summary

The main unwired functionality is:

1. **Archived features** (atomic swap, stealth addresses) - removed from scope
2. **SQLite backend** - deprecated in favor of PostgreSQL
3. **Crash recovery optimization** - phase-specific resumption not implemented (falls back to full re-execution)
4. **Selective disclosure verification** - Merkle proof verification stubbed
5. **VM module** - experimental, not yet implemented
6. **Mock adapters** - needed for comprehensive crash recovery testing

Most of this is intentional: either deprecated/archived features, experimental work-in-progress, or infrastructure that's being phased in incrementally.

Critical: runtime proof verification is structurally validating proofs, not cryptographically verifying them.
Normal execution and recovery both call CanonicalVerifierImpl::verify_proof_bundle from transfer_coordinator.rs (line 920) and transfer_coordinator.rs (line 1629). However, the active verifier only checks for non-empty signatures, a non-empty anchor id, and confirmation arithmetic in verifier.rs (line 431), verifier.rs (line 461), and verifier.rs (line 522). A real signature helper exists at verifier.rs (line 941), but this runtime path does not call it. Inclusion and finality are likewise comments-plus-shape checks. This is a mint-authority blocker.

Critical: proof recovery is not bound to the transfer being resumed.
verify_recovery_proof validates proof_bundle.seal_ref.id, but does not compare the proof against the stored transfer’s sanad_id, lock transaction, output index, transition id, or destination in transfer_coordinator.rs (line 1573). VerificationContext does not carry those expected values in verifier.rs (line 355). Consequently, a structurally accepted proof for another available seal can potentially be used while minting the resumed transfer.

Critical: csv-sdk still exposes direct chain minting, including an Aptos success stub.
The SDK prelude exports mint_sanad_on_chain in prelude.rs (line 13), and that function dispatches directly to adapters in cross_chain.rs (line 381), bypassing csv-runtime authority, replay, admission, and journal handling. The Aptos path calls mint.rs (line 11), which builds placeholder proof fields and returns a zero transaction hash as Ok at mint.rs (line 50). The Solana SDK route also supplies a zero state_root at cross_chain.rs (line 425).

Critical: public selective-disclosure verification accepts every proof.
DisclosureProof::verify, RedactedMerkleProof::verify, and EncryptedSubtreeProof::verify return true unconditionally in selective_disclosure.rs (line 54), selective_disclosure.rs (line 79), and selective_disclosure.rs (line 104). These types are publicly re-exported in lib.rs (line 53), despite separate functional content-tree proof types also being exported.

High: execution-journal recovery is not crash-safe in the default runtime wiring.
The journal promises restart survival in execution_journal.rs (line 19), but the default coordinator wires InMemoryJournal in transfer_coordinator.rs (line 217). The only implementation found is in-memory, and it deletes old entries on capacity pressure in execution_journal.rs (line 101). The persistent journal interface exists, but no production implementation is wired.

High: restart recovery fabricates lease authority, and mint recovery skips per-call lease validation.
resume_transfers constructs a synthetic one-hour lease with epoch 1 from journal text in transfer_coordinator.rs (line 2010). execute_from_mint is public and takes no RuntimeExecutionContext; it confirms consumption and completes the transfer after only the optional coordinator assertion in transfer_coordinator.rs (line 1856). Recovery is implemented, but its authority model is not complete.

High: public csv-proof compatibility modules still contain callable protocol stubs.
The crate explicitly publishes stub modules in lib.rs (line 33). ReplayKey::new_with_params discards replay-binding inputs and hash() uses DefaultHasher expanded from one byte in replay_registry.rs (line 26). Event constructors discard their inputs and event emission is a no-op in events.rs (line 19). These should be removed from public API, migrated, or made fail-closed.

Medium: csv-coordinator is exported but not actually performing isolation-domain work.
Its worker accepts a transfer, logs it, and records success without executing anything in cell.rs (line 127). csv-runtime re-exports coordinator types, but TransferCoordinator does not route transfers through them. The stated per-chain failure-domain architecture is presently unwired.

Medium: observability was moved as types, not integrated as runtime behavior.
csv-observability defines RuntimeHealth and PerformanceMetrics in runtime_health.rs (line 5) and performance.rs (line 23), but production runtime still uses its own HealthMonitor in runtime_mode.rs (line 249). No runtime consumer of the new observability types was found.

Cleanup remains around retired csv-core and CLI surfaces.
   csv-core is excluded from the workspace and architecture guards now contain elimination/L7 checks in architecture_guard.rs (line 52) and dep_graph_constitution.rs (line 103). However, the directory still exists, scripts still mention it in dev.sh (line 18) and publish.sh (line 18), and AGENTS.md (line 29) still documents it as active. The CLI plan’s journal/resume/runtime/content/trust wiring and dead chain_management.rs remain open in development-plan.txt (line 8).

Priority Order
Replace the active canonical verifier stubs and bind proofs to the exact transfer.
Remove or disable direct SDK mint helpers until they route through csv-runtime.
Eliminate public accept-all proof APIs in csv-content.
Make journal and recovery authority genuinely durable and lease-safe.
Remove public csv-proof stubs and wire coordinator/observability behavior.
Finish retired-crate/docs/scripts/CLI cleanup.


Here's the gap list of csv-cli :

**Protocol operations with zero CLI surface:**

1. **Replay registry** — `csv-runtime::replay_db` / `csv-protocol::replay::registry` exist. `inspect replay` only decodes hex/CBOR locally. No command to query live registry, list consumed IDs, or check a specific replay ID's status.

2. **Execution journal** — `csv-runtime::execution_journal` records every phase transition per transfer. No command to dump or tail the journal for a given transfer ID.

3. **Crash recovery / resume** — `transfer_coordinator::resume_from_phase()` exists. No command to list stuck transfers by phase, or manually trigger resumption of an incomplete transfer.

4. **Admission control & backpressure** — `csv-admission` and `csv-runtime::backpressure` are fully implemented. No command to inspect queue depth, pressure state, or current admission policy.

5. **Event bus / event store** — `csv-runtime::event_bus`, `event_store`, `event_envelope` exist. No CLI for streaming or querying past protocol events.

6. **Content tree and selective disclosure** — `csv-content` has Merkleized content trees, selective disclosure proofs, encryption envelopes, claims, and participant roles. No commands exist for any of it.

7. **Trust package** — `csv-core::trust_package` handles offline verification bootstrapping. No create/export/import commands.

8. **Runtime health** — `csv-core::runtime_health` and `csv-runtime::deployment_profile` exist. No `runtime status` or `runtime health` command.

**Missing chain:**

9. **Celestia** — `csv-adapters/csv-celestia` is a full adapter. The CLI `Chain` enum has bitcoin/ethereum/sui/aptos/solana only. Celestia is absent from every command including `test run`.

10. **Solana missing from test matrix** — The `test run --all` pair matrix in `commands/tests.rs` covers bitcoin/sui/ethereum/aptos cross-pairs but never includes solana as source or destination.

**Chain management:**

11. **`chain_management.rs` is dead code** — `src/chain_management.rs` defines `ChainCommands` with `discover`, `validate`, and `create-template` subcommands. None are wired into the `Commands` enum in `main.rs`. They are unreachable.

**Schema gaps:**

12. **Schema registry queries missing** — `csv-schema::registry` supports list and versioned lookup. `schema` command has validate/compile/diff but no `list`, `show <name>`, or `history`.

**Proof gaps:**

13. **Live proof DAG query** — `inspect merkle` only reads a local file. No command to query a live transfer's proof DAG from the runtime by transfer ID.

14. **MPC batch** — `csv-bitcoin::mpc_batch` exists. No CLI surface.

**Transfer lifecycle:**

15. **`cross-chain cancel`** — The state machine includes a `Compromised` terminal state. No cancel command exists, leaving no CLI path to abort a transfer that is stuck or adversarial.


| # | Gap | Existing or New subcommand |
|---|-----|---------------------------|
| 1 | Replay registry live query | `csv inspect replay` — extend with `--live` flag querying runtime, add `--check <id>` |
| 2 | Execution journal dump | `csv inspect journal --transfer-id <hex>` — new action under existing `inspect` |
| 3 | Crash recovery / resume | `csv cross-chain resume --transfer-id <hex>` — new action under existing `cross-chain` |
| 4 | Admission control & backpressure | `csv runtime status` — new top-level `runtime` subcommand, `status` action |
| 5 | Event bus / event store | `csv runtime events --transfer-id <hex>` — new action under `runtime` |
| 6 | Content tree & selective disclosure | `csv content` — new top-level subcommand (create, show, disclose, encrypt) |
| 7 | Trust package | `csv validate offline` already exists but only reads a proof file — extend to `csv trust export/import/verify` as new actions under a new `trust` subcommand |
| 8 | Runtime health | `csv runtime health` — new action under `runtime` (same new subcommand as #4 and #5) |
| 9 | Celestia missing from Chain enum | No new subcommand — add `Celestia` variant to the `Chain` enum; surfaces across all existing commands automatically |
| 10 | Solana absent from test matrix | No new subcommand — add solana pairs to the `pairs` vec in `cmd_run` in `commands/tests.rs` |
| 11 | `chain_management.rs` dead code | `csv chain discover`, `csv chain validate`, `csv chain create-template` — wire existing `ChainCommands` variants into the `Commands::Chain` dispatch in `main.rs` |
| 12 | Schema registry list/history | `csv schema list`, `csv schema show <name>`, `csv schema history <name>` — new actions under existing `schema` subcommand |
| 13 | Live proof DAG query | `csv inspect dag --transfer-id <hex>` — new action under existing `inspect` |
| 14 | MPC batch | `csv proof batch` — new action under existing `proof` subcommand |
| 15 | `cross-chain cancel` | `csv cross-chain cancel --transfer-id <hex>` — new action under existing `cross-chain` |

Three new top-level subcommands needed: `runtime` (covers #4, #5, #8), `content` (#6), `trust` (#7). Everything else extends an already-registered subcommand or is a code-only fix with no new commands.
