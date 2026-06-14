# Remaining Tasks — CSV Protocol

**Generated:** 2026-06-13
**Last Updated:** 2026-06-13 (Technical Debt validation)
**Based on:** PLAN.md + AUDIT.md + codebase validation

---

## Technical Debt Validation: PLAN.md Section "Placeholder and TODO Comments"

**Total "For Now" comments in codebase:** 40 (excluding docs)
**Total TODO comments in codebase:** 17 (excluding docs)
**Entries in PLAN.md Technical Debt table:** 32

### "For Now" Comments — Validation Results (15 entries from PLAN.md)

| # | File | Line | Original Comment | Status | Notes |
|---|------|------|-----------------|--------|-------|
| 1 | csv-wallet/src/wallet.rs | 173 | "For now, return None as we can't clone trait objects" | **STILL PRESENT** | M3 task — needs Arc<dyn Signer> fix |
| 2 | csv-sdk/src/sanads.rs | 336 | "For now, return FeatureNotEnabled error with context" | **STILL PRESENT** | SDK capability gating — acceptable as-is |
| 3 | csv-sdk/src/wallet.rs | 532 | "For now, return the key's signature capability" | **MOVED** | Line shifted, still present (~532) |
| 4 | csv-sdk/src/wallet.rs | 535 | "For now, return fallback signature..." | **MOVED** | Line shifted, still present (~535) |
| 5 | csv-sdk/src/wallet.rs | 822 | "For now, we return a typed error indicating the capability is not enabled" | **STILL PRESENT** | Line shifted (~822), same issue |
| 6 | csv-keys/src/bip44.rs | 186 | "For now, derive directly from seed + path components" | **STILL PRESENT** | Simple derivation — High priority per PLAN.md |
| 7 | csv-cli/src/commands/sanads.rs | 289 | "For now, just log - full implementation would parse policy file" | **STILL PRESENT** | M1 task — disclosure policy parsing |
| 8 | csv-cli/src/commands/sanads.rs | 295 | "For now, just log - full implementation would parse policy file" | **STILL PRESENT** | M1 task — proof policy parsing |
| 9 | csv-cli/src/commands/sanads.rs | 1991 | "For now, skip on-chain validation to avoid RPC dependency" | **STILL PRESENT** | New: also at lines 389, 1119 |
| 10 | csv-cli/src/commands/sanads.rs | 2130 | "For now, return the creation event from local state" | **STILL PRESENT** | Line shifted (~2130) |
| 11 | csv-coordinator/src/cell.rs | 331 | "For now, simulate successful execution" | **RESOLVED** | Comment no longer exists at this line |
| 12 | csv-adapters/csv-aptos/src/seal_protocol.rs | 227 | "Skip on-chain existence check for now" | **STILL PRESENT** | Line shifted (~227) |
| 13 | csv-adapters/csv-aptos/src/seal_protocol.rs | 1024 | "For now, we assume the seal is available if the collection exists" | **STILL PRESENT** | Same line |
| 14 | csv-adapters/csv-aptos/src/seal_protocol.rs | 1422 | "The seal is stored in a SmartTable, but for now we can use the next_nonce - 1" | **STILL PRESENT** | Line shifted (~1422) |
| 15 | csv-adapters/csv-aptos/src/ops.rs | 1041 | "This uses consume_seal entry function as a placeholder since mint_sanad is not yet implemented" | **STILL PRESENT** | Same line |

### "For Production" Comments — Validation Results (11 entries from PLAN.md)

| # | File | Line | Original Comment | Status | Notes |
|---|------|------|-----------------|--------|-------|
| 1 | csv-runtime/src/execution_journal.rs | 219 | "RocksDB-backed append-only execution journal for production recovery" | **STILL PRESENT** | Line shifted (~219) — feature-gated, acceptable |
| 2 | csv-content/src/resource_accounting.rs | 75 | "Create conservative limits for production" | **STILL PRESENT** | Same line |
| 3 | csv-codec/src/canonical.rs | 249 | "For production use, csv-hash provides the full implementation with proper hash types" | **STILL PRESENT** | Same line |
| 4 | csv-sdk/src/client.rs | 182 | "Transfer coordinator for production-grade cross-chain transfer execution" | **STILL PRESENT** | Line shifted (~182) — doc comment, acceptable |
| 5 | csv-sdk/src/transfers.rs | 102 | "Transfer coordinator for production-grade execution (if enabled)" | **STILL PRESENT** | Same line — doc comment |
| 6 | csv-sdk/src/transfers.rs | 129 | "Set the TransferCoordinator for production-grade execution" | **STILL PRESENT** | Same line — doc comment |
| 7 | csv-sdk/src/builder.rs | 185 | "When enabled, the client will initialize a full TransferCoordinator..." | **MOVED** | Line shifted — doc comment, acceptable |
| 8 | csv-keys/src/bip44.rs | 185 | "Simple derivation - in production would use proper BIP-32" | **STILL PRESENT** | Same line — same as "For Now" #6 |
| 9 | csv-adapters/csv-aptos/src/runtime_adapter.rs | 89 | "Use a placeholder owner key ID - in production this would come from wallet" | **STILL PRESENT** | Same line |
| 10 | csv-adapters/csv-aptos/src/runtime_adapter.rs | 119 | "Use a placeholder new owner - in production this would come from wallet" | **STILL PRESENT** | Same line |
| 11 | csv-adapters/csv-aptos/src/ops.rs | 1041 | "Note: This uses consume_seal entry function as a placeholder..." | **STILL PRESENT** | Duplicate of "For Now" #15 |

### "Simplified" Comments — Validation Results (6 entries from PLAN.md)

| # | File | Line | Original Comment | Status | Notes |
|---|------|------|-----------------|--------|-------|
| 1 | csv-codec/src/canonical.rs | 248 | "This is a simplified version that doesn't include the full Hash type" | **STILL PRESENT** | Same line |
| 2 | csv-protocol/src/seal_protocol.rs | 281 | "Simplified DAG representation" | **STILL PRESENT** | Same line — `Vec<u8>` DAG field |
| 3 | csv-protocol/src/version.rs | 300 | "Conversion from a simplified transfer status..." | **MOVED** | Line shifted (~300) — conversion function |
| 4 | csv-adapters/csv-aptos/src/ops.rs | 1186 | "Simplified check: account exists means 'active'" | **STILL PRESENT** | Same line |
| 5 | csv-adapters/csv-aptos/src/ops.rs | 1274 | "This is a simplified implementation" | **STILL PRESENT** | Same line |
| 6 | csv-adapters/csv-sui/src/deploy.rs | 214 | "Extract module names from effects - simplified for now" | **STILL PRESENT** | Same line |

### "TODO" Comments — Validation Results (16 entries from PLAN.md)

| # | File | Line | Original Comment | Status | Notes |
|---|------|------|-----------------|--------|-------|
| 1 | csv-codec/src/encode.rs | 21 | "TODO: Add NFC normalization" | **STILL PRESENT** | Same line — low priority |
| 2 | csv-store/src/lib.rs | 29 | "TODO: Rewrite operations/*.rs to use rusqlite" | **STILL PRESENT** | Same line |
| 3 | csv-cli/src/commands/wallet/mod.rs | 156 | "TODO: track actual index from derivation_path" | **STILL PRESENT** | Same line — low priority |
| 4 | csv-adapters/csv-aptos/src/seal_protocol.rs | 228 | "TODO: Implement create_seal transaction to deploy seal on-chain first" | **STILL PRESENT** | Same line |
| 5 | csv-adapters/csv-aptos/src/anchor.rs | 31 | "TODO: Implement actual BLS aggregate signature verification" | **STILL PRESENT** | Same line |
| 6 | csv-adapters/csv-aptos/src/anchor.rs | 95 | "TODO: Implement actual Merkle proof verification" | **STILL PRESENT** | Same line |
| 7 | csv-adapters/csv-sui/src/runtime_adapter.rs | 216 | "TODO: Implement actual Sui proof validation logic" | **STILL PRESENT** | Same line |
| 8 | csv-adapters/csv-sui/src/runtime_adapter.rs | 223 | "TODO: Implement actual Sui seal registry verification" | **STILL PRESENT** | Same line |
| 9 | csv-adapters/csv-sui/src/runtime_adapter.rs | 230 | "TODO: Implement actual Sui balance query logic" | **STILL PRESENT** | Same line |
| 10 | csv-adapters/csv-solana/src/runtime_adapter.rs | 114 | "TODO: Implement actual Solana mint transaction logic" | **MOVED** | Line shifted (~199) |
| 11 | csv-adapters/csv-solana/src/runtime_adapter.rs | 128 | "TODO: Implement actual Solana inclusion proof logic" | **MOVED** | Line shifted (~199) |
| 12 | csv-adapters/csv-solana/src/runtime_adapter.rs | 139 | "TODO: Implement actual Solana proof validation logic" | **MOVED** | Line shifted (~210) |
| 13 | csv-adapters/csv-solana/src/runtime_adapter.rs | 146 | "TODO: Implement actual Solana seal registry verification" | **MOVED** | Line shifted (~217) |
| 14 | csv-adapters/csv-solana/src/runtime_adapter.rs | 153 | "TODO: Implement actual Solana balance query logic" | **MOVED** | Line shifted (~224) |
| 15 | csv-adapters/csv-ethereum/src/seal_protocol.rs | 453 | "TODO: Implement verify_seal_registry method on EthereumVerifier" | **MOVED** | Line shifted (~454) |
| 16 | csv-cli/src/commands/sanads.rs | 390 | "TODO: Implement proper UTXO validation using Bitcoin adapter" | **NEW LOCATION** | Also at lines 1120, 1992 |

---

## New TODO/"For Now" Comments NOT in PLAN.md Technical Debt Table

The following 8 entries were found during validation but were NOT listed in PLAN.md's Technical Debt section:

| # | File | Line | Comment | Priority |
|---|------|------|---------|----------|
| N1 | csv-sdk/src/wallet.rs | 532 | "For now, return the key's signature capability" | Low |
| N2 | csv-sdk/src/wallet.rs | 535 | "For now, return fallback signature as full Schnorr signing requires transaction context" | Low |
| N3 | csv-protocol/src/reorg/reconciliation.rs | 303 | "For now, we verify block existence and log the result" | Low |
| N4 | csv-protocol/src/reorg/reconciliation.rs | 315 | "For now, we return success if the block exists" | Low |
| N5 | csv-protocol/src/signature.rs | 221 | "For now, we use a simplified derivation - the full ML-DSA key generation" | Medium |
| N6 | csv-protocol/src/signature.rs | 229 | "For now, use the first 32 bytes as a placeholder public key" | Medium |
| N7 | csv-p2p/src/proof_delivery.rs | 76 | "For now, we don't have author info in the proof bundle itself" | Low |
| N8 | csv-adapters/csv-solana/src/seal_protocol.rs | 600 | "For now, we just verify the slot is old enough to be finalized" | Low |

Plus additional "simplified implementation" comments found across adapters:
| # | File | Line | Comment |
|---|------|------|---------|
| N9 | csv-adapters/csv-ethereum/src/ops.rs | 1513 | "This is a simplified implementation - in production, call getSanadState on the contract" |
| N10 | csv-adapters/csv-ethereum/src/ops.rs | 1529 | "This is a simplified implementation" |
| N11 | csv-adapters/csv-bitcoin/src/ops.rs | 2494 | "This is a simplified implementation" |
| N12 | csv-adapters/csv-bitcoin/src/ops.rs | 2510 | "This is a simplified implementation" |
| N13 | csv-adapters/csv-solana/src/ops.rs | 1044 | "This is a simplified implementation" |
| N14 | csv-adapters/csv-sui/src/ops.rs | 1107 | "Simplified since we don't have checkpoint from sign_and_execute" |

---

## Updated Priority Tasks

### P1: High (Blockers for crate freeze)

#### H1: Fix fake encryption in CLI content encrypt

**Files:** `csv-cli/src/commands/content.rs`
**Problem:** `csv-cli content encrypt` uses nonce `[0u8; 12]`, empty ciphertext, empty tag.
**Tasks:**
- [ ] Delete the `content encrypt` command OR implement real AEAD encryption

#### H2: Fix deploy script hash enforcement

**Files:** `csv-contracts/ethereum/scripts/deploy.sh`, `CSVSeal.sol`
**Problem:** deploy.sh computes hashes but does NOT assert against PINNED_* constants. sha3sum vs keccak256 mismatch.
**Tasks:**
- [ ] Replace sha3sum with keccak256
- [ ] Add assertion against PINNED_* constants
- [ ] Clean up Adversarial.t.sol.bak

#### H3: Fix serde stripping violations

**Files:** `csv-protocol/src/proof_validation.rs:15`, `csv-hash/Cargo.toml`
**Problem:** CanonicalProof has serde derives (L1 violation). csv-hash default feature includes serde.
**Tasks:**
- [ ] Remove serde derives from CanonicalProof, add manual CanonicalEncoding
- [ ] Fix csv-hash/Cargo.toml default feature
- [ ] Remove dead serde imports

### P2: Medium (Technical Debt Cleanup)

#### M1: Resolve all "For now" / "TODO" / "Simplified" comments

**Scope:** 40 "For Now" + 17 TODO + 16 Simplified = 73 comments across the codebase
**Approach:** Group by theme rather than fixing individually:

**Theme A: Placeholder implementations in adapters (HIGH impact)**
- [ ] csv-adapters/csv-aptos/src/seal_protocol.rs — Skip on-chain checks, seal availability assumption, SmartTable nonce workaround
- [ ] csv-adapters/csv-aptos/src/anchor.rs — BLS aggregate TODO, Merkle proof TODO, basic reconstruction acceptance
- [ ] csv-adapters/csv-aptos/src/ops.rs — Placeholder mint_sanad, simplified account check, simplified implementation
- [ ] csv-adapters/csv-aptos/src/runtime_adapter.rs — Placeholder owner key ID, placeholder new owner
- [ ] csv-adapters/csv-solana/src/runtime_adapter.rs — 5 TODOs (mint, inclusion, proof validation, seal registry, balance)
- [ ] csv-adapters/csv-solana/src/seal_protocol.rs — Slot finality check placeholder
- [ ] csv-adapters/csv-solana/src/sync_coordinator.rs — RPC connectivity check placeholder
- [ ] csv-adapters/csv-sui/src/runtime_adapter.rs — 3 TODOs (proof validation, seal registry, balance)
- [ ] csv-adapters/csv-sui/src/ops.rs — Simplified checkpoint, simplified sanad_id extraction
- [ ] csv-adapters/csv-sui/src/deploy.rs — Simplified module name extraction
- [ ] csv-adapters/csv-sui/src/ops.rs — Sequence number placeholder, transaction non-empty check
- [ ] csv-adapters/csv-ethereum/src/seal_protocol.rs — Skip on-chain verification, verify_seal_registry TODO
- [ ] csv-adapters/csv-ethereum/src/runtime_adapter.rs — Minimal ProofBundle placeholder
- [ ] csv-adapters/csv-ethereum/src/ops.rs — Simplified implementation (2 instances)
- [ ] csv-adapters/csv-bitcoin/src/ops.rs — Simplified implementation (2 instances), prevout amounts error, keystore error
- [ ] csv-adapters/csv-bitcoin/src/seal_protocol.rs — Block hash only proof placeholder
- [ ] csv-adapters/csv-celestia/src/seal_protocol.rs — Accept rollback without validation

**Theme B: SDK capability stubs (MEDIUM impact)**
- [ ] csv-sdk/src/sanads.rs — FeatureNotEnabled error stub
- [ ] csv-sdk/src/wallet.rs — Signature capability stub, fallback signature stub, capability not enabled error

**Theme C: CLI validation skips (MEDIUM impact)**
- [ ] csv-cli/src/commands/sanads.rs — On-chain validation skips (4 instances), policy file parsing (2 instances), creation event from local state

**Theme D: Protocol-level simplifications (MEDIUM impact)**
- [ ] csv-protocol/src/signature.rs — Simplified ML-DSA derivation, placeholder public key
- [ ] csv-protocol/src/reorg/reconciliation.rs — Block existence verification stubs
- [ ] csv-protocol/src/seal_protocol.rs — Simplified DAG representation (Vec<u8>)
- [ ] csv-protocol/src/version.rs — Simplified transfer status conversion
- [ ] csv-p2p/src/proof_delivery.rs — Missing author info

**Theme E: csv-wallet gaps (MEDIUM impact)**
- [ ] csv-wallet/src/wallet.rs — get_signer() returns None
- [ ] csv-keys/src/bip44.rs — Simple derivation (not proper BIP-32)

**Theme F: csv-codec simplifications (LOW impact)**
- [ ] csv-codec/src/canonical.rs — Simplified version without full Hash type
- [ ] csv-codec/src/encode.rs — NFC normalization TODO

**Theme G: csv-store TODOs (LOW impact)**
- [ ] csv-store/src/lib.rs — rusqlite rewrite TODO
- [ ] csv-cli/src/commands/wallet/mod.rs — Derivation path index TODO

#### M2: Consolidate Bitcoin wallet code

**Files:** `csv-wallet/src/wallet.rs::bitcoin`, `csv-adapters/csv-bitcoin/src/wallet.rs`
**Problem:** Bitcoin wallet code duplicated between simplified and production implementations.

#### M3: Update csv-docs/PROTOCOL_CONSTITUTION.md csv-core references

**Files:** `csv-docs/PROTOCOL_CONSTITUTION.md`
**Problem:** References removed csv-core paths.

### P3: Low (Nice-to-have)

#### L1: Add conformance vectors and adapter template

**Problem:** No third-party conformance vectors or adapter template exist.

#### L2: Add module-level documentation to renamed files

**Problem:** Self-expressive naming reorganization deferred module documentation.

#### L3: Review csv-protocol/src/wire.rs serde placement

**Problem:** Wire types in csv-protocol (not csv-wire) have serde derives.

---

## Summary

| Category | Count | Status |
|----------|-------|--------|
| "For Now" comments in PLAN.md table | 15 | 1 resolved, 14 still present |
| "For Production" comments in PLAN.md table | 11 | 0 resolved, 11 still present (mostly doc comments) |
| "Simplified" comments in PLAN.md table | 6 | 0 resolved, 6 still present |
| "TODO" comments in PLAN.md table | 16 | 0 resolved, 16 still present |
| **New comments NOT in PLAN.md** | 14 | All still present |
| **Total unique comments** | **~73** | **All still present** |

**Key insight:** The Technical Debt section in PLAN.md covered 32 entries but the actual codebase has ~73 placeholder/simplified/TODO comments. The majority are in chain adapters (Solana, Sui, Aptos, Ethereum, Bitcoin runtime adapters and ops files) — these represent the largest remaining engineering effort.

**Estimated effort for Theme A (adapter placeholders):** 40-60 hours
**Estimated effort for Theme B-D (SDK/CLI/Protocol stubs):** 16-24 hours
**Estimated effort for Theme E-F (wallet/codec gaps):** 8-12 hours
**Estimated effort for Theme G (store TODOs):** 4-8 hours
**Total technical debt cleanup:** 68-104 hours
