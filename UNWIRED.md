
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
