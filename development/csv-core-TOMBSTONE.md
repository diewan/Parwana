# csv-core — TOMBSTONE

**Removed:** 2025-06-09
**Reason:** Legacy crate excluded from workspace with zero external dependencies. All types migrated to specialized crates.

## Migration Path

All modules that were in `csv-core` have been migrated to the following crates:

### Protocol Types → `csv-protocol`
| csv-core module | New location | Notes |
|-----------------|--------------|-------|
| `signature.rs` | `csv-protocol/src/signature.rs` | SignatureScheme enum, Signature struct |
| `backend.rs` | `csv-protocol/src/backend.rs` | ChainQuery, ChainSigner, ChainBroadcaster traits |
| `verification.rs` | `csv-protocol/src/verification.rs` | Verification levels |
| `verified.rs` | `csv-protocol/src/verified.rs` | Multi-dimensional verification results |
| `proof.rs` | `csv-protocol/src/proof.rs` | Re-exports from csv-proof |
| `proof_types.rs` | `csv-protocol/src/proof_types.rs` | FinalityProof, InclusionProof, ProofBundle |
| `canonical_proof.rs` | `csv-protocol/src/canonical_proof.rs` | Canonical proof validation |
| `consignment.rs` | `csv-protocol/src/consignment.rs` | Consignment wire format |
| `transition.rs` | `csv-protocol/src/transition.rs` | Typed state changes |
| `client.rs` | `csv-protocol/src/client.rs` | Client-side validation engine |
| `validator.rs` | `csv-protocol/src/validator.rs` | Consignment validation pipeline |
| `trust_package.rs` | `csv-protocol/src/trust_package.rs` | Offline verification bootstrapping |
| `compatibility.rs` | `csv-protocol/src/compatibility.rs` | Protocol version compatibility |
| `persisted_transition.rs` | `csv-protocol/src/persisted_transition.rs` | Atomic proof+state coupling |
| `proof_pipeline.rs` | `csv-protocol/src/proof_pipeline.rs` | Chain-specific verification hooks |
| `proof_provenance.rs` | `csv-protocol/src/proof_provenance.rs` | Provenance metadata |
| `data_authority.rs` | `csv-protocol/src/data_authority.rs` | Data authority tags |
| `wallet_types.rs` | `csv-protocol/src/wallet_types.rs` | Wallet capability separation |
| `adapter.rs` | `csv-protocol/src/adapter.rs` | Adapter boundary trait |
| `certification.rs` | `csv-protocol/src/certification.rs` | Proof certification |
| `error.rs` | `csv-protocol/src/error.rs` | ProtocolError types |
| `mcp.rs` | `csv-protocol/src/mcp.rs` | Agent-friendly types (AI) |
| `collections.rs` | `csv-protocol/src/collections.rs` | No-std collections |

### Hash Types → `csv-hash`
| csv-core module | New location | Notes |
|-----------------|--------------|-------|
| `hash.rs` | `csv-hash/src/hash.rs` | Hash, Hash32 types |
| `sanad.rs` | `csv-hash/src/sanad.rs` | SanadId derivation |
| `commitment.rs` | `csv-hash/src/commitment.rs` | Commitment types |
| `nullifier.rs` | `csv-hash/src/nullifier.rs` | SealNullifier, DoubleSpendError |
| `seal.rs` | `csv-hash/src/seal.rs` | CommitAnchor, SealPoint |
| `chain_id.rs` | `csv-hash/src/chain_id.rs` | ChainId type |
| `domain.rs` | `csv-hash/src/domain.rs` | Domain separation types |
| `merkle.rs` | `csv-hash/src/merkle.rs` | MerkleTree, MerkleProof |
| `replay_registry.rs` | `csv-hash/src/replay_registry.rs` | Replay registry types |

### Proof Types → `csv-proof`
| csv-core module | New location | Notes |
|-----------------|--------------|-------|
| `proof.rs` | `csv-proof/src/proof.rs` | Proof type definitions |
| `proof_validation.rs` | `csv-proof/src/proof_validation.rs` | Proof validation logic |
| `commitments_ext.rs` | `csv-proof/src/commitments_ext.rs` | EnhancedCommitment, FinalityProofType |

### Storage → `csv-storage`
| csv-core module | New location | Notes |
|-----------------|--------------|-------|
| `store.rs` | `csv-storage/src/seal_store.rs` | Persistent seal/anchor storage |
| `state_store.rs` | `csv-storage/src/state_store.rs` | State history store |

### Runtime → `csv-runtime`
| csv-core module | New location | Notes |
|-----------------|--------------|-------|
| `recovery_engine.rs` | `csv-runtime/src/recovery_engine.rs` | Crash-safe recovery |

### Observability → `csv-observability`
| csv-core module | New location | Notes |
|-----------------|--------------|-------|
| `runtime_health.rs` | `csv-observability/src/runtime_health.rs` | Runtime health states |

### Experimental → Feature-gated
| csv-core module | Status | Notes |
|-----------------|--------|-------|
| `zk_proof.rs` | REMOVED | ZK proof infrastructure. If needed, re-implement behind `zk` feature gate in `csv-protocol` or a dedicated `csv-zk` crate. |

## Why csv-core Was Removed

1. **Excluded from workspace:** `exclude = ["csv-core"]` in root `Cargo.toml`
2. **Zero external dependencies:** No workspace crate imports `csv_core::`
3. **Architecture tests enforce retirement:** `nothing_new_depends_on_csv_core()` test in `csv-architecture`
4. **All types migrated:** Every module listed above has a destination in the new crate structure
5. **Dead code:** Many test files used `#![cfg(any())]` (never compiled)

## What Was NOT Migrated

- `examples/` — Examples using migrated types are obsolete
- `archived/*.bak` — Backup files, never compiled
- `bin/generate_golden_fixtures.rs` — Binary commented out in Cargo.toml
- `zk_proof.rs` — ZK/quantum proof infrastructure (experimental, feature-gated)

## Golden Fixtures

The 5 CBOR golden fixtures from `csv-core/tests/golden/` were:
- `valid_proof_bundle_v1.cbor`
- `valid_sanad_envelope_v1.cbor`
- `replay_attempt_v1.cbor`
- `malformed_proof_missing_finality.cbor`
- `malformed_proof_wrong_domain.cbor`

If these fixtures are still needed for testing, they should be moved to `csv-protocol/tests/fixtures/` or `csv-testkit/fixtures/`.

## References

- `AGENTS.md` — Repo structure and architecture rules
- `development/AUDIT.md` — Final repository audit
- `development/UNWIRED.md` — Unwired checklist
- `csv-docs/` — Protocol documentation (update any references to csv-core source paths)
